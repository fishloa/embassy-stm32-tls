//! On-target test: verify hardware crypto against known test vectors and
//! software implementations on NUCLEO-H755ZI-Q.
//!
//! Run with: cargo run --example test_vectors --release --target thumbv7em-none-eabihf

#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::cryp::{self, Cryp};
use embassy_stm32::hash::{self, Hash};
use embassy_stm32::rng::Rng;
use embassy_stm32::{bind_interrupts, peripherals, rng};
use embedded_tls::{SoftwareCipher, SoftwareHash, SoftwareHkdf, SoftwareHmac, TlsError};
use embedded_tls::{TlsBuffer, TlsCipher, TlsHash, TlsHkdf, TlsHmac};
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

/// Compare two byte slices; return true if equal. Log first mismatch via defmt on failure.
fn slices_eq(a: &[u8], b: &[u8], label: &str) -> bool {
    if a.len() != b.len() {
        error!("{}: length mismatch: {} vs {}", label, a.len(), b.len());
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            error!("{}: mismatch at byte {}: 0x{:02x} vs 0x{:02x}", label, i, a[i], b[i]);
            return false;
        }
    }
    true
}

/// Decode a compile-time hex string into a byte array.
macro_rules! hex {
    ($hex:expr) => {{
        const LEN: usize = $hex.len() / 2;
        const fn decode() -> [u8; LEN] {
            let src = $hex.as_bytes();
            let mut out = [0u8; LEN];
            let mut i = 0;
            while i < LEN {
                let hi = match src[i * 2] {
                    b'0'..=b'9' => src[i * 2] - b'0',
                    b'a'..=b'f' => src[i * 2] - b'a' + 10,
                    b'A'..=b'F' => src[i * 2] - b'A' + 10,
                    _ => core::panic!("bad hex"),
                };
                let lo = match src[i * 2 + 1] {
                    b'0'..=b'9' => src[i * 2 + 1] - b'0',
                    b'a'..=b'f' => src[i * 2 + 1] - b'a' + 10,
                    b'A'..=b'F' => src[i * 2 + 1] - b'A' + 10,
                    _ => core::panic!("bad hex"),
                };
                out[i] = hi * 16 + lo;
                i += 1;
            }
            out
        }
        decode()
    }};
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_stm32::init_primary(Default::default(), &SHARED);

    let cryp_peri = Cryp::new_blocking(p.CRYP, Irqs);
    let hash_peri = Hash::new_blocking(p.HASH, Irqs);
    hardware::init(cryp_peri, hash_peri);
    let _rng = Rng::new(p.RNG, Irqs);

    let mut passed = 0u32;
    let mut failed = 0u32;

    macro_rules! check {
        ($ok:expr, $name:expr) => {
            if $ok {
                info!("  PASS: {}", $name);
                passed += 1;
            } else {
                error!("  FAIL: {}", $name);
                failed += 1;
            }
        };
    }

    // ===================================================================
    // 1. SHA-256 Known Answer Tests
    // ===================================================================
    info!("=== 1. SHA-256 Known Answer Tests ===");
    {
        // Empty string
        let expected = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let mut h = HardwareSha256::new();
        h.update(&[]);
        let digest = h.finalize();
        check!(slices_eq(digest.as_slice(), &expected, "sha256-empty"), "SHA-256 empty");
    }
    {
        // "abc"
        let expected = hex!("ba7816bf8f01cfea414140de5dae2223b6ee7ad5cb3b039a9ef2c05e5b17b9a8");
        let mut h = HardwareSha256::new();
        h.update(b"abc");
        let digest = h.finalize();
        check!(slices_eq(digest.as_slice(), &expected, "sha256-abc"), "SHA-256 \"abc\"");
    }
    {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let expected = hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        let mut h = HardwareSha256::new();
        h.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let digest = h.finalize();
        check!(slices_eq(digest.as_slice(), &expected, "sha256-long"), "SHA-256 448-bit msg");
    }

    // ===================================================================
    // 2. HMAC-SHA-256 Known Answer Test (RFC 4231 Test Case 1)
    // ===================================================================
    info!("=== 2. HMAC-SHA-256 Known Answer Test ===");
    {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        let mut hmac = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hmac.update(data);
        let tag = hmac.finalize();
        check!(slices_eq(tag.as_slice(), &expected, "hmac-rfc4231"), "HMAC-SHA-256 RFC 4231 TC1");
    }

    // ===================================================================
    // 3. AES-128-GCM Known Answer Tests
    // ===================================================================
    info!("=== 3. AES-128-GCM Known Answer Tests ===");
    {
        // NIST vector: all-zero key/IV, empty plaintext
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0u8; 16]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0u8; 12]);
        let expected_tag = hex!("58e2fccefa7e3061367f1d57a4e7455a");

        let cipher = HardwareAesGcm128::new(&key);
        let mut buf = BenchBuffer::new(&[]);
        cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
        // Buffer now contains just the 16-byte tag
        check!(slices_eq(buf.as_slice(), &expected_tag, "gcm-zero"), "AES-GCM empty plaintext");
    }
    {
        // NIST vector with data: first 16 bytes of the standard test
        let key_bytes = hex!("feffe9928665731c6d6a8f9467308308");
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&key_bytes);
        let nonce_bytes = hex!("cafebabefacedbaddecaf888");
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&nonce_bytes);
        let plaintext = hex!("d9313225f88406e5a55909c5aff5269a");
        let expected_ct = hex!("42831ec2217774244b7221b784d0d49c");

        let cipher = HardwareAesGcm128::new(&key);
        let mut buf = BenchBuffer::new(&plaintext);
        cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
        // First 16 bytes are ciphertext, last 16 are tag
        let ok_ct = slices_eq(&buf.as_slice()[..16], &expected_ct, "gcm-nist-ct");
        check!(ok_ct, "AES-GCM NIST ciphertext");

        // Verify tag matches software implementation
        let sw_cipher = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&key);
        let mut sw_buf = BenchBuffer::new(&plaintext);
        sw_cipher.encrypt_in_place(&nonce, &[], &mut sw_buf).unwrap();
        let ok_tag = slices_eq(&buf.as_slice()[16..], &sw_buf.as_slice()[16..], "gcm-nist-tag");
        check!(ok_tag, "AES-GCM NIST tag hw==sw");
    }

    // ===================================================================
    // 4. Hardware vs Software Comparison
    // ===================================================================
    info!("=== 4. Hardware vs Software Comparison ===");
    {
        // SHA-256: 512 bytes of 0xAA
        let data = [0xAAu8; 512];
        let mut hw = HardwareSha256::new();
        hw.update(&data);
        let hw_dig = hw.finalize();
        let mut sw = <SoftwareHash<sha2::Sha256>>::new();
        sw.update(&data);
        let sw_dig = sw.finalize();
        check!(slices_eq(hw_dig.as_slice(), sw_dig.as_slice(), "sha256-cmp"), "SHA-256 hw==sw 512B");
    }
    {
        // HMAC-SHA-256: 32-byte key, 128-byte message
        let key = [0x55u8; 32];
        let msg = [0x77u8; 128];
        let mut hw = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hw.update(&msg);
        let hw_tag = hw.finalize();
        let mut sw = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&key).unwrap();
        sw.update(&msg);
        let sw_tag = sw.finalize();
        check!(slices_eq(hw_tag.as_slice(), sw_tag.as_slice(), "hmac-cmp"), "HMAC hw==sw");
    }
    {
        // HKDF: extract + expand to 48 bytes
        let salt = [0x02u8; 32];
        let ikm = [0x03u8; 32];
        let info = [0x04u8; 32];

        let (hw_prk, hw_hkdf) = HardwareHkdfSha256::extract(Some(&salt), &ikm);
        let mut hw_out = [0u8; 48];
        hw_hkdf.expand(&info, &mut hw_out).unwrap();

        let (sw_prk, sw_hkdf) = <SoftwareHkdf<sha2::Sha256>>::extract(Some(&salt), &ikm);
        let mut sw_out = [0u8; 48];
        sw_hkdf.expand(&info, &mut sw_out).unwrap();

        check!(slices_eq(hw_prk.as_slice(), sw_prk.as_slice(), "hkdf-prk"), "HKDF PRK hw==sw");
        check!(slices_eq(&hw_out, &sw_out, "hkdf-expand"), "HKDF expand hw==sw");
    }
    {
        // AES-128-GCM: encrypt 256 bytes, compare ciphertext+tag
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0xABu8; 16]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0xCDu8; 12]);
        let aad = [0xEFu8; 13];
        let data = [0x42u8; 256];

        let hw_cipher = HardwareAesGcm128::new(&key);
        let mut hw_buf = BenchBuffer::new(&data);
        hw_cipher.encrypt_in_place(&nonce, &aad, &mut hw_buf).unwrap();

        let sw_cipher = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&key);
        let mut sw_buf = BenchBuffer::new(&data);
        sw_cipher.encrypt_in_place(&nonce, &aad, &mut sw_buf).unwrap();

        check!(
            slices_eq(hw_buf.as_slice(), sw_buf.as_slice(), "aes-cmp"),
            "AES-GCM encrypt hw==sw 256B"
        );
    }

    // ===================================================================
    // 5. AES-128-GCM Edge Cases: encrypt/decrypt round-trip
    // ===================================================================
    info!("=== 5. AES-128-GCM Edge Cases ===");
    let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0x11u8; 16]);
    let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0x22u8; 12]);
    let aad_data = [0x33u8; 17];
    let sizes: [usize; 9] = [0, 1, 15, 16, 17, 31, 32, 256, 0 /* placeholder for re-use */];
    // We test sizes[0..8] without AAD, then sizes[0..8] with AAD.

    for pass in 0..2u8 {
        let aad: &[u8] = if pass == 0 { &[] } else { &aad_data };
        for &sz in &sizes[..8] {
            // Build plaintext
            let mut plaintext = [0u8; 256];
            for i in 0..sz {
                plaintext[i] = i as u8;
            }

            let cipher = HardwareAesGcm128::new(&key);
            let mut buf = BenchBuffer::new(&plaintext[..sz]);
            cipher.encrypt_in_place(&nonce, aad, &mut buf).unwrap();

            // buf now has ciphertext + 16-byte tag
            if buf.len() != sz + 16 {
                error!("size {}: enc output len {} expected {}", sz, buf.len(), sz + 16);
                failed += 1;
                continue;
            }

            cipher.decrypt_in_place(&nonce, aad, &mut buf).unwrap();

            let ok = slices_eq(buf.as_slice(), &plaintext[..sz], "aes-rt");
            check!(ok, match (sz, pass) {
                (0, 0) => "RT 0B no-aad",
                (1, 0) => "RT 1B no-aad",
                (15, 0) => "RT 15B no-aad",
                (16, 0) => "RT 16B no-aad",
                (17, 0) => "RT 17B no-aad",
                (31, 0) => "RT 31B no-aad",
                (32, 0) => "RT 32B no-aad",
                (256, 0) => "RT 256B no-aad",
                (0, _) => "RT 0B with-aad",
                (1, _) => "RT 1B with-aad",
                (15, _) => "RT 15B with-aad",
                (16, _) => "RT 16B with-aad",
                (17, _) => "RT 17B with-aad",
                (31, _) => "RT 31B with-aad",
                (32, _) => "RT 32B with-aad",
                (256, _) => "RT 256B with-aad",
                _ => "RT unknown",
            });
        }
    }

    // ===================================================================
    // Summary
    // ===================================================================
    info!("");
    info!("=== SUMMARY: {} passed, {} failed ===", passed, failed);
    if failed > 0 {
        defmt::panic!("{} test(s) FAILED", failed);
    } else {
        info!("All tests passed.");
    }

    loop {
        cortex_m::asm::wfi();
    }
}
