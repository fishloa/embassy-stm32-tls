use core::marker::PhantomData;

use embassy_stm32::rng::{self, Rng};
use embedded_tls::{Aes128GcmSha256, CryptoProvider, CryptoRngCore, TlsCipherSuite};

/// A [`CryptoProvider`] for `embedded-tls` backed by the STM32H7 hardware RNG.
///
/// The cipher suite is generic -- the default is `Aes128GcmSha256` (software)
/// for backwards compatibility, but you can use any [`TlsCipherSuite`] including
/// the hardware-accelerated ones from this crate.
///
/// # Example
///
/// ```rust,ignore
/// use embassy_stm32::rng::Rng;
/// use embassy_stm32_tls::{Stm32H7Aes128GcmSha256, Stm32H7CryptoProvider};
///
/// let rng = Rng::new(p.RNG, Irqs);
/// // Default (software Aes128GcmSha256):
/// let provider = Stm32H7CryptoProvider::new(rng);
/// // Hardware cipher suite:
/// let provider = Stm32H7CryptoProvider::<_, _, Stm32H7Aes128GcmSha256>::new_with_suite(rng);
/// ```
pub struct Stm32H7CryptoProvider<'d, T: rng::Instance, CS: TlsCipherSuite = Aes128GcmSha256> {
    rng: Rng<'d, T>,
    _cs: PhantomData<CS>,
}

impl<'d, T: rng::Instance> Stm32H7CryptoProvider<'d, T> {
    /// Create a new crypto provider using the default `Aes128GcmSha256` cipher suite.
    #[must_use]
    pub fn new(rng: Rng<'d, T>) -> Self {
        Self {
            rng,
            _cs: PhantomData,
        }
    }
}

impl<'d, T: rng::Instance, CS: TlsCipherSuite> Stm32H7CryptoProvider<'d, T, CS> {
    /// Create a new crypto provider with an explicit cipher suite.
    #[must_use]
    pub fn new_with_suite(rng: Rng<'d, T>) -> Self {
        Self {
            rng,
            _cs: PhantomData,
        }
    }
}

impl<'d, T: rng::Instance, CS: TlsCipherSuite> CryptoProvider for Stm32H7CryptoProvider<'d, T, CS> {
    type CipherSuite = CS;
    type Signature = &'d [u8];

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }
}
