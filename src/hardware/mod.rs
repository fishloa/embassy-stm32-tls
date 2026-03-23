//! Hardware-accelerated crypto implementations using STM32H7 CRYP and HASH peripherals.
//!
//! Call [`init`] once at startup before using the hardware cipher suite.

pub mod cipher;
pub mod hash;
pub mod hkdf;
pub mod hmac;

use core::cell::RefCell;

use critical_section::Mutex;
use embassy_stm32::hash as stm32_hash;
use embassy_stm32::mode::Blocking;
use embassy_stm32::{cryp, peripherals};

/// Stored CRYP peripheral, initialised by [`init`].
static CRYP: Mutex<RefCell<Option<cryp::Cryp<'static, peripherals::CRYP, Blocking>>>> =
    Mutex::new(RefCell::new(None));

/// Stored HASH peripheral, initialised by [`init`].
static HASH: Mutex<RefCell<Option<stm32_hash::Hash<'static, peripherals::HASH, Blocking>>>> =
    Mutex::new(RefCell::new(None));

/// Initialise the hardware crypto peripherals.
///
/// Must be called exactly once before any hardware cipher suite operation.
/// The peripherals are moved into module-level statics and accessed through
/// critical sections.
///
/// # Panics
///
/// Panics if called more than once. This guards against accidental
/// double-initialisation which would silently discard the first peripheral.
///
/// # Important
///
/// On some STM32H7 variants, the RNG peripheral must be initialised before
/// the CRYP and HASH peripherals. Ensure your RNG is set up before calling
/// this function.
pub fn init(
    cryp_peri: cryp::Cryp<'static, peripherals::CRYP, Blocking>,
    hash_peri: stm32_hash::Hash<'static, peripherals::HASH, Blocking>,
) {
    critical_section::with(|cs| {
        let mut cryp_ref = CRYP.borrow_ref_mut(cs);
        assert!(cryp_ref.is_none(), "hardware::init() called more than once");
        cryp_ref.replace(cryp_peri);

        HASH.borrow_ref_mut(cs).replace(hash_peri);
    });
}

/// Access the CRYP peripheral within a critical section.
///
/// # Panics
///
/// Panics if [`init`] has not been called.
pub(crate) fn with_cryp<R>(
    f: impl FnOnce(&cryp::Cryp<'static, peripherals::CRYP, Blocking>) -> R,
) -> R {
    critical_section::with(|cs| {
        let borrow = CRYP.borrow_ref(cs);
        let cryp = borrow
            .as_ref()
            .expect("CRYP not initialised — call hardware::init() first");
        f(cryp)
    })
}

/// Access the HASH peripheral within a critical section.
///
/// # Panics
///
/// Panics if [`init`] has not been called.
pub(crate) fn with_hash<R>(
    f: impl FnOnce(&mut stm32_hash::Hash<'static, peripherals::HASH, Blocking>) -> R,
) -> R {
    critical_section::with(|cs| {
        let mut borrow = HASH.borrow_ref_mut(cs);
        let hash = borrow
            .as_mut()
            .expect("HASH not initialised — call hardware::init() first");
        f(hash)
    })
}
