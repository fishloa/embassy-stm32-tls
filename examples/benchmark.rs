//! Hardware vs software crypto benchmark for NUCLEO-H755ZI-Q (Cortex-M7).
//!
//! Measures cycle counts for SHA-256, HMAC-SHA-256, HKDF-SHA-256, and
//! AES-128-GCM encrypt using both hardware and software implementations.
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
use embedded_tls::{TlsBuffer, TlsCipher, TlsHash, TlsHkdf, TlsHmac};
use embedded_tls::{SoftwareCipher, SoftwareHash, SoftwareHkdf, SoftwareHmac, TlsError};
use generic_array::GenericArray;
use {defmt_rtt as _, panic_probe as _};

use embassy_stm32_tls::hardware;
use embassy_stm32_tls::hardware::cipher::HardwareAesGcm128;
use embassy_stm32_tls::hardware::hash::HardwareSha256;
use embassy_stm32_tls::hardware::hkdf::HardwareHkdfSha256;
use embassy_stm32_tls::hardware::hmac::HardwareHmacSha256;

bind_interrupts!(struct Irqs {
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>,
                hash::InterruptHandler<peripherals::HASH>;
    CRYP =>     cryp::InterruptHandler<peripherals::CRYP>;
});

static SHARED: MaybeUninit<embassy_stm32::SharedData> = MaybeUninit::uninit();

/// A simple stack-allocated buffer implementing `TlsBuffer` for benchmarking.
struct BenchBuffer {
    data: [u8; 1024],
    len: usize,
}

impl BenchBuffer {
    fn new(initial: &[u8]) -> Self {
        let mut buf = Self {
            data: [0u8; 1024],
            len: initial.len(),
        };
        buf.data[..initial.len()].copy_from_slice(initial);
        buf
    }
}

impl TlsBuffer for BenchBuffer {
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    fn len(&self) -> usize {
        self.len
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), TlsError> {
        if self.len + other.len() > self.data.len() {
            return Err(TlsError::EncodeError);
        }
        self.data[self.len..self.len + other.len()].copy_from_slice(other);
        self.len += other.len();
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn capacity(&self) -> usize {
        self.data.len()
    }
}

/// Read the DWT cycle counter.
#[inline(always)]
fn cycles() -> u32 {
    DWT::cycle_count()
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_stm32::init_primary(Default::default(), &SHARED);

    // Enable the DWT cycle counter for precise timing.
    let mut core = cortex_m::Peripherals::take().unwrap();
    core.DCB.enable_trace();
    core.DWT.enable_cycle_counter();

    // Initialise hardware crypto peripherals.
    let cryp_peri = Cryp::new_blocking(p.CRYP, Irqs);
    let hash_peri = Hash::new_blocking(p.HASH, Irqs);
    hardware::init(cryp_peri, hash_peri);

    // Initialise RNG (available for future use).
    let _rng = Rng::new(p.RNG, Irqs);

    // --- Test data ---
    let test_data = [0x42u8; 256]; // 256 bytes of payload
    let aes_key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0xABu8; 16]);
    let aes_nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0xCDu8; 12]);
    let aad = [0xEFu8; 13];
    let hmac_key = [0x01u8; 32];
    let hkdf_salt = [0x02u8; 32];
    let hkdf_ikm = [0x03u8; 32];
    let hkdf_info = [0x04u8; 32];

    info!("=== Embassy STM32 TLS Crypto Benchmark ===");
    info!("Payload: {} bytes", test_data.len());
    info!("");

    // -------------------------------------------------------
    // SHA-256
    // -------------------------------------------------------
    info!("--- SHA-256 ({} bytes) ---", test_data.len());

    // Hardware
    let t0 = cycles();
    {
        let mut h = HardwareSha256::new();
        h.update(&test_data);
        let _digest = h.finalize();
    }
    let hw_sha = cycles().wrapping_sub(t0);
    info!("  HW:  {} cycles", hw_sha);

    // Software
    let t0 = cycles();
    {
        let mut h = <SoftwareHash<sha2::Sha256>>::new();
        h.update(&test_data);
        let _digest = h.finalize();
    }
    let sw_sha = cycles().wrapping_sub(t0);
    info!("  SW:  {} cycles", sw_sha);
    info!("  Speedup: {}x", sw_sha / hw_sha.max(1));

    // -------------------------------------------------------
    // HMAC-SHA-256
    // -------------------------------------------------------
    info!("");
    info!("--- HMAC-SHA-256 ({} bytes) ---", test_data.len());

    // Hardware
    let t0 = cycles();
    {
        let mut h = HardwareHmacSha256::new_from_slice(&hmac_key).unwrap();
        h.update(&test_data);
        let _tag = h.finalize();
    }
    let hw_hmac = cycles().wrapping_sub(t0);
    info!("  HW:  {} cycles", hw_hmac);

    // Software
    let t0 = cycles();
    {
        let mut h = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&hmac_key).unwrap();
        h.update(&test_data);
        let _tag = h.finalize();
    }
    let sw_hmac = cycles().wrapping_sub(t0);
    info!("  SW:  {} cycles", sw_hmac);
    info!("  Speedup: {}x", sw_hmac / hw_hmac.max(1));

    // -------------------------------------------------------
    // HKDF-SHA-256
    // -------------------------------------------------------
    info!("");
    info!("--- HKDF-SHA-256 (extract + expand 48 bytes) ---");

    // Hardware
    let t0 = cycles();
    {
        let (_prk, hkdf) = HardwareHkdfSha256::extract(Some(&hkdf_salt), &hkdf_ikm);
        let mut out = [0u8; 48];
        hkdf.expand(&hkdf_info, &mut out).unwrap();
    }
    let hw_hkdf = cycles().wrapping_sub(t0);
    info!("  HW:  {} cycles", hw_hkdf);

    // Software
    let t0 = cycles();
    {
        let (_prk, hkdf) =
            <SoftwareHkdf<sha2::Sha256>>::extract(Some(&hkdf_salt), &hkdf_ikm);
        let mut out = [0u8; 48];
        hkdf.expand(&hkdf_info, &mut out).unwrap();
    }
    let sw_hkdf = cycles().wrapping_sub(t0);
    info!("  SW:  {} cycles", sw_hkdf);
    info!("  Speedup: {}x", sw_hkdf / hw_hkdf.max(1));

    // -------------------------------------------------------
    // AES-128-GCM encrypt
    // -------------------------------------------------------
    info!("");
    info!("--- AES-128-GCM encrypt ({} bytes) ---", test_data.len());

    // Hardware
    let t0 = cycles();
    {
        let cipher = HardwareAesGcm128::new(&aes_key);
        let mut buf = BenchBuffer::new(&test_data);
        cipher.encrypt_in_place(&aes_nonce, &aad, &mut buf).unwrap();
    }
    let hw_aes = cycles().wrapping_sub(t0);
    info!("  HW:  {} cycles", hw_aes);

    // Software
    let t0 = cycles();
    {
        let cipher = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&aes_key);
        let mut buf = BenchBuffer::new(&test_data);
        cipher.encrypt_in_place(&aes_nonce, &aad, &mut buf).unwrap();
    }
    let sw_aes = cycles().wrapping_sub(t0);
    info!("  SW:  {} cycles", sw_aes);
    info!("  Speedup: {}x", sw_aes / hw_aes.max(1));

    // -------------------------------------------------------
    // AES-128-GCM decrypt (round-trip verification)
    // -------------------------------------------------------
    info!("");
    info!("--- AES-128-GCM encrypt+decrypt round-trip ---");
    {
        let cipher = HardwareAesGcm128::new(&aes_key);
        let mut buf = BenchBuffer::new(&test_data);
        cipher.encrypt_in_place(&aes_nonce, &aad, &mut buf).unwrap();
        cipher.decrypt_in_place(&aes_nonce, &aad, &mut buf).unwrap();
        defmt::assert_eq!(&buf.as_slice()[..test_data.len()], &test_data[..]);
        info!("  HW round-trip: OK");
    }

    info!("");
    info!("=== Benchmark complete ===");

    loop {
        cortex_m::asm::wfi();
    }
}
