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
