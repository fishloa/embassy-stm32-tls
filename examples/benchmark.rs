//! Hardware vs software crypto benchmark for NUCLEO-H755ZI-Q (Cortex-M7).
//!
//! Measures cycle counts for all TLS crypto operations at multiple payload
//! sizes, comparing hardware (STM32H7 CRYP/HASH) against software (RustCrypto).
//!
//! Run with: cargo run --example benchmark --release --target thumbv7em-none-eabihf

#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use cortex_m::peripheral::DWT;
use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::cryp::{self, Cryp};
use embassy_stm32::hash::{self, Hash};
use embassy_stm32::rng::Rng;
use embassy_stm32::{bind_interrupts, peripherals, rng};
use embedded_tls::{SoftwareCipher, SoftwareHash, SoftwareHkdf, SoftwareHmac};
use embedded_tls::{TlsBuffer, TlsCipher, TlsHash, TlsHkdf, TlsHmac};
use generic_array::GenericArray;
use {defmt_rtt as _, panic_probe as _};

use embassy_stm32_tls::hardware;
use embassy_stm32_tls::hardware::cipher::{HardwareAesGcm128, HardwareAesGcm256};
use embassy_stm32_tls::hardware::hash::HardwareSha256;
use embassy_stm32_tls::hardware::hkdf::HardwareHkdfSha256;
use embassy_stm32_tls::hardware::hmac::HardwareHmacSha256;
use embassy_stm32_tls::TestBuffer;

bind_interrupts!(struct Irqs {
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>,
                hash::InterruptHandler<peripherals::HASH>;
    CRYP =>     cryp::InterruptHandler<peripherals::CRYP>;
});

static SHARED: MaybeUninit<embassy_stm32::SharedData> = MaybeUninit::uninit();

#[inline(always)]
fn cycles() -> u32 {
    DWT::cycle_count()
}

/// Run a closure and return elapsed cycles.
#[inline(never)]
fn measure(f: impl FnOnce()) -> u32 {
    let t0 = cycles();
    f();
    cycles().wrapping_sub(t0)
}

// 4KB buffer for larger payload tests.
static mut BUF_A: [u8; 4112] = [0u8; 4112]; // 4096 + 16 tag

// Stack measurement via a dedicated probe buffer.
// The function under test runs on the main stack; we measure SP delta.
const STACK_SENTINEL: u32 = 0xDEAD_C0DE;
const STACK_PROBE_WORDS: usize = 2048; // 8KB probe zone
static mut STACK_PROBE: [u32; STACK_PROBE_WORDS] = [0; STACK_PROBE_WORDS];

/// Paint the stack probe zone with a sentinel.
fn stack_probe_paint() {
    let ptr = core::ptr::addr_of_mut!(STACK_PROBE) as *mut u32;
    for i in 0..STACK_PROBE_WORDS {
        unsafe { ptr.add(i).write_volatile(STACK_SENTINEL) };
    }
}

/// Measure how many bytes of the probe zone were consumed.
/// Scans from index 0 (lowest address) upward — deepest stack usage
/// overwrites from the top of the array downward.
fn stack_probe_measure() -> usize {
    let ptr = core::ptr::addr_of!(STACK_PROBE) as *const u32;
    for i in 0..STACK_PROBE_WORDS {
        if unsafe { ptr.add(i).read_volatile() } != STACK_SENTINEL {
            return (STACK_PROBE_WORDS - i) * 4;
        }
    }
    0
}

/// Measure peak stack usage of a closure.
///
/// Moves SP into the pre-painted probe zone, runs `f()`, restores SP,
/// then scans for the high-water mark. Interrupts are disabled during
/// measurement since the probe zone becomes the active stack.
#[inline(never)]
fn measure_stack(f: impl FnOnce()) -> usize {
    stack_probe_paint();
    unsafe {
        let probe_top =
            (core::ptr::addr_of!(STACK_PROBE) as *const u32).add(STACK_PROBE_WORDS) as u32;
        let saved_sp: u32;
        core::arch::asm!(
            "mov {saved}, sp",
            "mov sp, {top}",
            saved = out(reg) saved_sp,
            top = in(reg) probe_top,
        );
        cortex_m::interrupt::free(|_| {
            f();
        });
        core::arch::asm!(
            "mov sp, {saved}",
            saved = in(reg) saved_sp,
        );
    }
    stack_probe_measure()
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_stm32::init_primary(Default::default(), &SHARED);

    let mut core = cortex_m::Peripherals::take().unwrap();
    core.DCB.enable_trace();
    core.DWT.enable_cycle_counter();

    let cryp_peri = Cryp::new_blocking(p.CRYP, Irqs);
    let hash_peri = Hash::new_blocking(p.HASH, Irqs);
    hardware::init(cryp_peri, hash_peri);
    let _rng = Rng::new(p.RNG, Irqs);

    let aes128_key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0xABu8; 16]);
    let aes256_key: GenericArray<u8, typenum::U32> = GenericArray::clone_from_slice(&[0xCDu8; 32]);
    let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0xEFu8; 12]);
    let aad = [0x33u8; 13];
    let hmac_key = [0x01u8; 32];
    let hkdf_salt = [0x02u8; 32];
    let hkdf_ikm = [0x03u8; 32];
    let hkdf_info = [0x04u8; 32];

    info!("=== Embassy STM32 TLS Crypto Benchmark ===");
    info!("");

    // ── Memory: type sizes (stack cost per instance) ─────────
    info!("--- Type sizes (bytes) ---");
    info!("  HardwareAesGcm128:    {}", core::mem::size_of::<HardwareAesGcm128>());
    info!("  SoftwareCipher<128>:  {}", core::mem::size_of::<SoftwareCipher<aes_gcm::Aes128Gcm>>());
    info!("  HardwareAesGcm256:    {}", core::mem::size_of::<HardwareAesGcm256>());
    info!("  SoftwareCipher<256>:  {}", core::mem::size_of::<SoftwareCipher<aes_gcm::Aes256Gcm>>());
    info!("  HardwareSha256:       {}", core::mem::size_of::<HardwareSha256>());
    info!("  SoftwareHash<Sha256>: {}", core::mem::size_of::<SoftwareHash<sha2::Sha256>>());
    info!("  HardwareHmacSha256:   {}", core::mem::size_of::<HardwareHmacSha256>());
    info!("  SoftwareHmac<Sha256>: {}", core::mem::size_of::<SoftwareHmac<sha2::Sha256>>());
    info!("  HardwareHkdfSha256:   {}", core::mem::size_of::<HardwareHkdfSha256>());
    info!("  SoftwareHkdf<Sha256>: {}", core::mem::size_of::<SoftwareHkdf<sha2::Sha256>>());
    info!("  TestBuffer<4112>:     {}", core::mem::size_of::<TestBuffer<4112>>());
    info!("");

    // ── SHA-256 (TlsHash) ──────────────────────────────────────
    for &size in &[64u16, 256, 1024, 4096] {
        let sz = size as usize;
        let data = unsafe { &mut BUF_A[..sz] };
        data.fill(0x42);

        let hw = measure(|| {
            let mut h = HardwareSha256::new();
            h.update(data);
            let _ = h.finalize();
        });
        let sw = measure(|| {
            let mut h = <SoftwareHash<sha2::Sha256>>::new();
            h.update(data);
            let _ = h.finalize();
        });
        info!("SHA-256 {}B:  HW={} SW={} ({}x)", sz, hw, sw, sw / hw.max(1));
    }

    // ── HMAC-SHA-256 (TlsHmac) ────────────────────────────────
    info!("");
    for &size in &[64u16, 256, 1024, 4096] {
        let sz = size as usize;
        let data = unsafe { &mut BUF_A[..sz] };
        data.fill(0x77);

        let hw = measure(|| {
            let mut h = HardwareHmacSha256::new_from_slice(&hmac_key).unwrap();
            h.update(data);
            let _ = h.finalize();
        });
        let sw = measure(|| {
            let mut h = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&hmac_key).unwrap();
            h.update(data);
            let _ = h.finalize();
        });
        info!("HMAC-SHA-256 {}B:  HW={} SW={} ({}x)", sz, hw, sw, sw / hw.max(1));
    }

    // ── HKDF-SHA-256 (TlsHkdf) ────────────────────────────────
    info!("");
    for &expand_len in &[32u16, 48, 64, 128] {
        let elen = expand_len as usize;
        let hw = measure(|| {
            let (_, hkdf) = HardwareHkdfSha256::extract(Some(&hkdf_salt), &hkdf_ikm);
            let mut out = [0u8; 128];
            hkdf.expand(&hkdf_info, &mut out[..elen]).unwrap();
        });
        let sw = measure(|| {
            let (_, hkdf) = <SoftwareHkdf<sha2::Sha256>>::extract(Some(&hkdf_salt), &hkdf_ikm);
            let mut out = [0u8; 128];
            hkdf.expand(&hkdf_info, &mut out[..elen]).unwrap();
        });
        info!("HKDF expand {}B:  HW={} SW={} ({}x)", elen, hw, sw, sw / hw.max(1));
    }

    // ── AES-128-GCM encrypt (TlsCipher) ───────────────────────
    info!("");
    for &size in &[64u16, 256, 1024, 4096] {
        let sz = size as usize;

        let hw = measure(|| {
            let cipher = HardwareAesGcm128::new(&aes128_key);
            let mut buf = TestBuffer::<4112>::new(unsafe { &BUF_A[..sz] });
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        let sw = measure(|| {
            let cipher = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&aes128_key);
            let mut buf = TestBuffer::<4112>::new(unsafe { &BUF_A[..sz] });
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        info!("AES-128-GCM enc {}B:  HW={} SW={} ({}x)", sz, hw, sw, sw / hw.max(1));
    }

    // ── AES-128-GCM decrypt ───────────────────────────────────
    info!("");
    for &size in &[64u16, 256, 1024, 4096] {
        let sz = size as usize;

        // Prepare ciphertext with hw encrypt.
        let cipher = HardwareAesGcm128::new(&aes128_key);
        let mut prep = TestBuffer::<4112>::new(unsafe { &BUF_A[..sz] });
        cipher.encrypt_in_place(&nonce, &aad, &mut prep).unwrap();
        let ct = prep.as_slice();

        let hw = measure(|| {
            let cipher = HardwareAesGcm128::new(&aes128_key);
            let mut buf = TestBuffer::<4112>::new(ct);
            cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        let sw = measure(|| {
            let cipher = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&aes128_key);
            let mut buf = TestBuffer::<4112>::new(ct);
            cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        info!("AES-128-GCM dec {}B:  HW={} SW={} ({}x)", sz, hw, sw, sw / hw.max(1));
    }

    // ── AES-256-GCM encrypt ───────────────────────────────────
    info!("");
    for &size in &[64u16, 256, 1024, 4096] {
        let sz = size as usize;

        let hw = measure(|| {
            let cipher = HardwareAesGcm256::new(&aes256_key);
            let mut buf = TestBuffer::<4112>::new(unsafe { &BUF_A[..sz] });
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        let sw = measure(|| {
            let cipher = <SoftwareCipher<aes_gcm::Aes256Gcm>>::new(&aes256_key);
            let mut buf = TestBuffer::<4112>::new(unsafe { &BUF_A[..sz] });
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        info!("AES-256-GCM enc {}B:  HW={} SW={} ({}x)", sz, hw, sw, sw / hw.max(1));
    }

    // ── AES-256-GCM decrypt ───────────────────────────────────
    info!("");
    for &size in &[64u16, 256, 1024, 4096] {
        let sz = size as usize;

        let cipher = HardwareAesGcm256::new(&aes256_key);
        let mut prep = TestBuffer::<4112>::new(unsafe { &BUF_A[..sz] });
        cipher.encrypt_in_place(&nonce, &aad, &mut prep).unwrap();
        let ct = prep.as_slice();

        let hw = measure(|| {
            let cipher = HardwareAesGcm256::new(&aes256_key);
            let mut buf = TestBuffer::<4112>::new(ct);
            cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        let sw = measure(|| {
            let cipher = <SoftwareCipher<aes_gcm::Aes256Gcm>>::new(&aes256_key);
            let mut buf = TestBuffer::<4112>::new(ct);
            cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        info!("AES-256-GCM dec {}B:  HW={} SW={} ({}x)", sz, hw, sw, sw / hw.max(1));
    }

    // ── Stack usage (256B payload) ─────────────────────────────
    info!("");
    info!("--- Peak stack usage (bytes, 256B payload) ---");
    {
        let data = unsafe { &BUF_A[..256] };

        let hw = measure_stack(|| {
            let mut h = HardwareSha256::new();
            h.update(data);
            let _ = h.finalize();
        });
        let sw = measure_stack(|| {
            let mut h = <SoftwareHash<sha2::Sha256>>::new();
            h.update(data);
            let _ = h.finalize();
        });
        info!("  SHA-256:       HW={} SW={}", hw, sw);

        let hw = measure_stack(|| {
            let mut h = HardwareHmacSha256::new_from_slice(&hmac_key).unwrap();
            h.update(data);
            let _ = h.finalize();
        });
        let sw = measure_stack(|| {
            let mut h = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&hmac_key).unwrap();
            h.update(data);
            let _ = h.finalize();
        });
        info!("  HMAC-SHA-256:  HW={} SW={}", hw, sw);

        let hw = measure_stack(|| {
            let (_, hkdf) = HardwareHkdfSha256::extract(Some(&hkdf_salt), &hkdf_ikm);
            let mut out = [0u8; 48];
            hkdf.expand(&hkdf_info, &mut out).unwrap();
        });
        let sw = measure_stack(|| {
            let (_, hkdf) = <SoftwareHkdf<sha2::Sha256>>::extract(Some(&hkdf_salt), &hkdf_ikm);
            let mut out = [0u8; 48];
            hkdf.expand(&hkdf_info, &mut out).unwrap();
        });
        info!("  HKDF:          HW={} SW={}", hw, sw);

        let hw = measure_stack(|| {
            let cipher = HardwareAesGcm128::new(&aes128_key);
            let mut buf = TestBuffer::<1024>::new(data);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        let sw = measure_stack(|| {
            let cipher = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&aes128_key);
            let mut buf = TestBuffer::<1024>::new(data);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        info!("  AES-128-GCM:   HW={} SW={}", hw, sw);

        let hw = measure_stack(|| {
            let cipher = HardwareAesGcm256::new(&aes256_key);
            let mut buf = TestBuffer::<1024>::new(data);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        let sw = measure_stack(|| {
            let cipher = <SoftwareCipher<aes_gcm::Aes256Gcm>>::new(&aes256_key);
            let mut buf = TestBuffer::<1024>::new(data);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        });
        info!("  AES-256-GCM:   HW={} SW={}", hw, sw);
    }

    // ── Flash size note ──────────────────────────────────────
    info!("");
    info!("--- Flash size ---");
    info!("  Compare with: cargo size --example benchmark --release --target thumbv7em-none-eabihf");

    // ── Round-trip correctness ─────────────────────────────────
    info!("");
    {
        let cipher = HardwareAesGcm128::new(&aes128_key);
        let data = [0x42u8; 256];
        let mut buf = TestBuffer::<1024>::new(&data);
        cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        defmt::assert_eq!(buf.as_slice(), &data[..]);
        info!("AES-128-GCM round-trip: OK");
    }
    {
        let cipher = HardwareAesGcm256::new(&aes256_key);
        let data = [0x42u8; 256];
        let mut buf = TestBuffer::<1024>::new(&data);
        cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        defmt::assert_eq!(buf.as_slice(), &data[..]);
        info!("AES-256-GCM round-trip: OK");
    }

    info!("");
    info!("=== Benchmark complete ===");

    loop {
        cortex_m::asm::wfi();
    }
}
