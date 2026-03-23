#![no_std]
#![no_main]

use core::mem::MaybeUninit;

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

use embassy_stm32_tls::hardware::cipher::{HardwareAesGcm128, HardwareAesGcm256};
use embassy_stm32_tls::hardware::hash::HardwareSha256;
use embassy_stm32_tls::hardware::hkdf::HardwareHkdfSha256;
use embassy_stm32_tls::hardware::hmac::HardwareHmacSha256;
use embassy_stm32_tls::{hardware, TestBuffer};

bind_interrupts!(struct Irqs {
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>,
                hash::InterruptHandler<peripherals::HASH>;
    CRYP =>     cryp::InterruptHandler<peripherals::CRYP>;
});

static SHARED: MaybeUninit<embassy_stm32::SharedData> = MaybeUninit::uninit();

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

fn fill_pattern(buf: &mut [u8]) {
    for i in 0..buf.len() {
        buf[i] = i as u8;
    }
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

    // =================================================================
    // 1. SHA-256 KATs (NIST FIPS 180-4)
    // =================================================================
    info!("=== 1. SHA-256 KATs ===");
    {
        let expected = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let mut h = HardwareSha256::new();
        h.update(&[]);
        check!(slices_eq(h.finalize().as_slice(), &expected, "sha256"), "SHA-256 empty");
    }
    {
        let expected = hex!("ba7816bf8f01cfea414140de5dae2223b6ee7ad5cb3b039a9ef2c05e5b17b9a8");
        let mut h = HardwareSha256::new();
        h.update(b"abc");
        check!(slices_eq(h.finalize().as_slice(), &expected, "sha256"), "SHA-256 \"abc\"");
    }
    {
        let expected = hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        let mut h = HardwareSha256::new();
        h.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        check!(slices_eq(h.finalize().as_slice(), &expected, "sha256"), "SHA-256 448-bit");
    }
    {
        let expected = hex!("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
        let mut h = HardwareSha256::new();
        h.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        check!(slices_eq(h.finalize().as_slice(), &expected, "sha256"), "SHA-256 896-bit");
    }
    {
        // Multi-update: "abc" split across 3 calls
        let expected = hex!("ba7816bf8f01cfea414140de5dae2223b6ee7ad5cb3b039a9ef2c05e5b17b9a8");
        let mut h = HardwareSha256::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        check!(slices_eq(h.finalize().as_slice(), &expected, "sha256"), "SHA-256 multi-update");
    }

    // =================================================================
    // 2. SHA-256 Clone test
    // =================================================================
    info!("=== 2. SHA-256 Clone ===");
    {
        let mut h1 = HardwareSha256::new();
        h1.update(b"Hello");
        let h2 = h1.clone();

        let mut h1b = h1;
        h1b.update(b" World");
        let dig1 = h1b.finalize();

        let mut h2b = h2;
        h2b.update(b" Rust");
        let dig2 = h2b.finalize();

        let mut sw1 = <SoftwareHash<sha2::Sha256>>::new();
        sw1.update(b"Hello World");
        let sw_dig1 = sw1.finalize();

        let mut sw2 = <SoftwareHash<sha2::Sha256>>::new();
        sw2.update(b"Hello Rust");
        let sw_dig2 = sw2.finalize();

        check!(slices_eq(dig1.as_slice(), sw_dig1.as_slice(), "clone"), "SHA-256 clone orig");
        check!(slices_eq(dig2.as_slice(), sw_dig2.as_slice(), "clone"), "SHA-256 clone fork");
    }

    // =================================================================
    // 3. SHA-256 hw-vs-sw at multiple sizes
    // =================================================================
    info!("=== 3. SHA-256 hw-vs-sw ===");
    {
        let sizes: [usize; 6] = [1, 55, 56, 64, 128, 1024];
        let mut data = [0xAAu8; 1024];
        fill_pattern(&mut data);
        for &sz in &sizes {
            let mut hw = HardwareSha256::new();
            hw.update(&data[..sz]);
            let hw_dig = hw.finalize();
            let mut sw = <SoftwareHash<sha2::Sha256>>::new();
            sw.update(&data[..sz]);
            let sw_dig = sw.finalize();
            check!(slices_eq(hw_dig.as_slice(), sw_dig.as_slice(), "sha256-cmp"), match sz {
                1 => "SHA-256 hw==sw 1B",
                55 => "SHA-256 hw==sw 55B",
                56 => "SHA-256 hw==sw 56B",
                64 => "SHA-256 hw==sw 64B",
                128 => "SHA-256 hw==sw 128B",
                1024 => "SHA-256 hw==sw 1024B",
                _ => "SHA-256 hw==sw ?",
            });
        }
    }

    // =================================================================
    // 4. HMAC-SHA-256 KATs (RFC 4231)
    // =================================================================
    info!("=== 4. HMAC-SHA-256 KATs ===");
    {
        // TC1
        let key = [0x0bu8; 20];
        let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        let mut hmac = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hmac.update(b"Hi There");
        check!(slices_eq(hmac.finalize().as_slice(), &expected, "hmac"), "HMAC TC1");
    }
    {
        // TC2
        let expected = hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let mut hmac = HardwareHmacSha256::new_from_slice(b"Jefe").unwrap();
        hmac.update(b"what do ya want for nothing?");
        check!(slices_eq(hmac.finalize().as_slice(), &expected, "hmac"), "HMAC TC2");
    }
    {
        // TC3
        let key = [0xAAu8; 20];
        let data = [0xDDu8; 50];
        let expected = hex!("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        let mut hmac = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hmac.update(&data);
        check!(slices_eq(hmac.finalize().as_slice(), &expected, "hmac"), "HMAC TC3");
    }
    {
        // TC6: key longer than block size
        let key = [0xAAu8; 131];
        let expected = hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        let mut hmac = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hmac.update(b"Test Using Larger Than Block-Size Key - Hash Key First");
        check!(slices_eq(hmac.finalize().as_slice(), &expected, "hmac"), "HMAC TC6");
    }
    {
        // TC7: key and data longer than block size
        let key = [0xAAu8; 131];
        let expected = hex!("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
        let mut hmac = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hmac.update(b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
        check!(slices_eq(hmac.finalize().as_slice(), &expected, "hmac"), "HMAC TC7");
    }

    // =================================================================
    // 5. HMAC-SHA-256 hw-vs-sw
    // =================================================================
    info!("=== 5. HMAC-SHA-256 hw-vs-sw ===");
    {
        let key_sizes: [usize; 4] = [16, 32, 64, 128];
        let data_sizes: [usize; 6] = [0, 1, 63, 64, 65, 256];
        let mut key_buf = [0x55u8; 128];
        fill_pattern(&mut key_buf);
        let mut data_buf = [0x77u8; 256];
        fill_pattern(&mut data_buf);
        for &ks in &key_sizes {
            for &ds in &data_sizes {
                let mut hw = HardwareHmacSha256::new_from_slice(&key_buf[..ks]).unwrap();
                hw.update(&data_buf[..ds]);
                let hw_tag = hw.finalize();
                let mut sw = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&key_buf[..ks]).unwrap();
                sw.update(&data_buf[..ds]);
                let sw_tag = sw.finalize();
                check!(slices_eq(hw_tag.as_slice(), sw_tag.as_slice(), "hmac-cmp"),
                    "HMAC hw==sw k/d");
            }
        }
    }

    // =================================================================
    // 6. HMAC verify() test
    // =================================================================
    info!("=== 6. HMAC verify() ===");
    {
        let key = [0x42u8; 32];
        let data = b"test message for verify";

        // Compute tag
        let mut hmac = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hmac.update(data);
        let tag = hmac.finalize();

        // Verify correct tag
        let mut hmac2 = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hmac2.update(data);
        let ok = hmac2.verify(&tag).is_ok();
        check!(ok, "HMAC verify correct");

        // Verify tampered tag
        let mut bad_tag = GenericArray::clone_from_slice(tag.as_slice());
        bad_tag[0] ^= 1;
        let mut hmac3 = HardwareHmacSha256::new_from_slice(&key).unwrap();
        hmac3.update(data);
        let ok = hmac3.verify(&bad_tag).is_err();
        check!(ok, "HMAC verify tampered");
    }

    // =================================================================
    // 7. HKDF-SHA-256 KATs (RFC 5869)
    // =================================================================
    info!("=== 7. HKDF-SHA-256 KATs ===");
    {
        // TC1
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected_prk = hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let expected_okm = hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        let (prk, hkdf) = HardwareHkdfSha256::extract(Some(&salt), &ikm);
        check!(slices_eq(prk.as_slice(), &expected_prk, "hkdf-prk"), "HKDF TC1 PRK");
        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).unwrap();
        check!(slices_eq(&okm, &expected_okm, "hkdf-okm"), "HKDF TC1 OKM");
    }
    {
        // TC2
        let ikm = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        let salt = hex!("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info = hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let expected_prk = hex!("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        let expected_okm = hex!("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");

        let (prk, hkdf) = HardwareHkdfSha256::extract(Some(&salt), &ikm);
        check!(slices_eq(prk.as_slice(), &expected_prk, "hkdf-prk"), "HKDF TC2 PRK");
        let mut okm = [0u8; 82];
        hkdf.expand(&info, &mut okm).unwrap();
        check!(slices_eq(&okm, &expected_okm, "hkdf-okm"), "HKDF TC2 OKM");
    }
    {
        // TC3: no salt, no info
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected_prk = hex!("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        let expected_okm = hex!("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

        let (prk, hkdf) = HardwareHkdfSha256::extract(None, &ikm);
        check!(slices_eq(prk.as_slice(), &expected_prk, "hkdf-prk"), "HKDF TC3 PRK");
        let mut okm = [0u8; 42];
        hkdf.expand(&[], &mut okm).unwrap();
        check!(slices_eq(&okm, &expected_okm, "hkdf-okm"), "HKDF TC3 OKM");
    }

    // =================================================================
    // 8. HKDF hw-vs-sw
    // =================================================================
    info!("=== 8. HKDF hw-vs-sw ===");
    {
        let salt = [0x02u8; 32];
        let ikm = [0x03u8; 32];
        let info = [0x04u8; 32];
        let expand_sizes: [usize; 6] = [1, 16, 32, 48, 64, 128];
        for &sz in &expand_sizes {
            let (hw_prk, hw_hkdf) = HardwareHkdfSha256::extract(Some(&salt), &ikm);
            let mut hw_out = [0u8; 128];
            hw_hkdf.expand(&info, &mut hw_out[..sz]).unwrap();

            let (sw_prk, sw_hkdf) = <SoftwareHkdf<sha2::Sha256>>::extract(Some(&salt), &ikm);
            let mut sw_out = [0u8; 128];
            sw_hkdf.expand(&info, &mut sw_out[..sz]).unwrap();

            check!(slices_eq(hw_prk.as_slice(), sw_prk.as_slice(), "hkdf"), "HKDF PRK hw==sw");
            check!(slices_eq(&hw_out[..sz], &sw_out[..sz], "hkdf"), "HKDF expand hw==sw");
        }
    }

    // =================================================================
    // 9. AES-128-GCM KATs
    // =================================================================
    info!("=== 9. AES-128-GCM KATs ===");
    {
        // All-zero key/IV, empty plaintext
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0u8; 16]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0u8; 12]);
        let expected_tag = hex!("58e2fccefa7e3061367f1d57a4e7455a");
        let cipher = HardwareAesGcm128::new(&key);
        let mut buf = TestBuffer::<1024>::new(&[]);
        cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
        check!(slices_eq(buf.as_slice(), &expected_tag, "gcm"), "AES-128-GCM empty KAT");
    }
    {
        // NIST vector with data (first 16 bytes)
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&hex!("feffe9928665731c6d6a8f9467308308"));
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&hex!("cafebabefacedbaddecaf888"));
        let pt = hex!("d9313225f88406e5a55909c5aff5269a");
        let expected_ct = hex!("42831ec2217774244b7221b784d0d49c");

        let cipher = HardwareAesGcm128::new(&key);
        let mut buf = TestBuffer::<1024>::new(&pt);
        cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
        check!(slices_eq(&buf.as_slice()[..16], &expected_ct, "gcm-ct"), "AES-128-GCM NIST ct");

        // Compare tag with software
        let sw = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&key);
        let mut sw_buf = TestBuffer::<1024>::new(&pt);
        sw.encrypt_in_place(&nonce, &[], &mut sw_buf).unwrap();
        check!(slices_eq(&buf.as_slice()[16..], &sw_buf.as_slice()[16..], "gcm-tag"), "AES-128-GCM NIST tag hw==sw");
    }
    {
        // NIST vector with AAD — hw vs sw
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&hex!("feffe9928665731c6d6a8f9467308308"));
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&hex!("cafebabefacedbaddecaf888"));
        let pt = hex!("d9313225f88406e5a55909c5aff5269a");
        let aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        let hw = HardwareAesGcm128::new(&key);
        let mut hw_buf = TestBuffer::<1024>::new(&pt);
        hw.encrypt_in_place(&nonce, &aad, &mut hw_buf).unwrap();

        let sw = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&key);
        let mut sw_buf = TestBuffer::<1024>::new(&pt);
        sw.encrypt_in_place(&nonce, &aad, &mut sw_buf).unwrap();
        check!(slices_eq(hw_buf.as_slice(), sw_buf.as_slice(), "gcm-aad"), "AES-128-GCM NIST+AAD hw==sw");
    }

    // =================================================================
    // 10. AES-128-GCM edge cases
    // =================================================================
    info!("=== 10. AES-128-GCM edge cases ===");
    {
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0x11u8; 16]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0x22u8; 12]);

        // Payload sizes
        let pt_sizes: [usize; 12] = [0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128];
        // AAD sizes
        let aad_sizes: [usize; 6] = [0, 1, 15, 16, 17, 64];

        let mut data = [0u8; 256];
        fill_pattern(&mut data);
        let mut aad_data = [0x33u8; 128];
        fill_pattern(&mut aad_data);

        for &pt_sz in &pt_sizes {
            for &aad_sz in &aad_sizes {
                let cipher = HardwareAesGcm128::new(&key);
                let mut buf = TestBuffer::<1024>::new(&data[..pt_sz]);
                cipher.encrypt_in_place(&nonce, &aad_data[..aad_sz], &mut buf).unwrap();

                if buf.len() != pt_sz + 16 {
                    error!("enc output len {} expected {}", buf.len(), pt_sz + 16);
                    failed += 1;
                    continue;
                }

                cipher.decrypt_in_place(&nonce, &aad_data[..aad_sz], &mut buf).unwrap();
                check!(slices_eq(buf.as_slice(), &data[..pt_sz], "gcm-rt"), "GCM128 RT p/a");
            }
        }

        // Large AAD (128B) with small payload (1B)
        let cipher = HardwareAesGcm128::new(&key);
        let mut buf = TestBuffer::<1024>::new(&[0x42]);
        cipher.encrypt_in_place(&nonce, &aad_data[..128], &mut buf).unwrap();
        cipher.decrypt_in_place(&nonce, &aad_data[..128], &mut buf).unwrap();
        check!(slices_eq(buf.as_slice(), &[0x42], "gcm-lg-aad"), "GCM128 128B-AAD 1B-PT");

        // Size 129
        let mut big = [0u8; 129];
        fill_pattern(&mut big);
        let cipher = HardwareAesGcm128::new(&key);
        let mut buf = TestBuffer::<1024>::new(&big);
        cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
        cipher.decrypt_in_place(&nonce, &[], &mut buf).unwrap();
        check!(slices_eq(buf.as_slice(), &big, "gcm-129"), "GCM128 RT 129B");

        // Size 256
        let cipher = HardwareAesGcm128::new(&key);
        let mut buf = TestBuffer::<1024>::new(&data);
        cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
        cipher.decrypt_in_place(&nonce, &[], &mut buf).unwrap();
        check!(slices_eq(buf.as_slice(), &data, "gcm-256"), "GCM128 RT 256B");
    }

    // =================================================================
    // 11. AES-128-GCM negative tests
    // =================================================================
    info!("=== 11. AES-128-GCM negative tests ===");
    {
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0x11u8; 16]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0x22u8; 12]);
        let aad = [0x33u8; 16];
        let pt = [0x44u8; 32];
        let cipher = HardwareAesGcm128::new(&key);

        // Flip bit in ciphertext
        {
            let mut buf = TestBuffer::<1024>::new(&pt);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            buf.as_mut_slice()[0] ^= 1;
            check!(cipher.decrypt_in_place(&nonce, &aad, &mut buf).is_err(), "GCM128 tampered CT");
        }
        // Flip bit in tag
        {
            let mut buf = TestBuffer::<1024>::new(&pt);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            let last = buf.len() - 1;
            buf.as_mut_slice()[last] ^= 1;
            check!(cipher.decrypt_in_place(&nonce, &aad, &mut buf).is_err(), "GCM128 tampered tag");
        }
        // Wrong AAD
        {
            let mut buf = TestBuffer::<1024>::new(&pt);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            let wrong_aad = [0x34u8; 16];
            check!(cipher.decrypt_in_place(&nonce, &wrong_aad, &mut buf).is_err(), "GCM128 wrong AAD");
        }
        // Wrong nonce
        {
            let mut buf = TestBuffer::<1024>::new(&pt);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            let wrong_nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0x23u8; 12]);
            check!(cipher.decrypt_in_place(&wrong_nonce, &aad, &mut buf).is_err(), "GCM128 wrong nonce");
        }
    }

    // =================================================================
    // 12. AES-256-GCM tests
    // =================================================================
    info!("=== 12. AES-256-GCM tests ===");
    {
        let key: GenericArray<u8, typenum::U32> = GenericArray::clone_from_slice(&[0xABu8; 32]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0xCDu8; 12]);

        // hw-vs-sw at multiple sizes
        let sizes: [usize; 3] = [64, 256, 1024];
        let mut data = [0u8; 1024];
        fill_pattern(&mut data);
        for &sz in &sizes {
            let hw_cipher = HardwareAesGcm256::new(&key);
            let mut hw_buf = TestBuffer::<4112>::new(&data[..sz]);
            hw_cipher.encrypt_in_place(&nonce, &[], &mut hw_buf).unwrap();

            let sw_cipher = <SoftwareCipher<aes_gcm::Aes256Gcm>>::new(&key);
            let mut sw_buf = TestBuffer::<4112>::new(&data[..sz]);
            sw_cipher.encrypt_in_place(&nonce, &[], &mut sw_buf).unwrap();

            check!(slices_eq(hw_buf.as_slice(), sw_buf.as_slice(), "gcm256-cmp"), "GCM256 hw==sw enc");
        }

        // Round-trip edge cases
        let rt_sizes: [usize; 10] = [0, 1, 15, 16, 17, 31, 32, 63, 64, 65];
        for &sz in &rt_sizes {
            let cipher = HardwareAesGcm256::new(&key);
            let mut buf = TestBuffer::<4112>::new(&data[..sz]);
            cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
            cipher.decrypt_in_place(&nonce, &[], &mut buf).unwrap();
            check!(slices_eq(buf.as_slice(), &data[..sz], "gcm256-rt"), "GCM256 RT");
        }

        // Negative: tag tamper
        {
            let cipher = HardwareAesGcm256::new(&key);
            let mut buf = TestBuffer::<4112>::new(&data[..32]);
            cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
            let last = buf.len() - 1;
            buf.as_mut_slice()[last] ^= 1;
            check!(cipher.decrypt_in_place(&nonce, &[], &mut buf).is_err(), "GCM256 tampered tag");
        }
        // Negative: wrong AAD
        {
            let aad = [0xEFu8; 16];
            let cipher = HardwareAesGcm256::new(&key);
            let mut buf = TestBuffer::<4112>::new(&data[..32]);
            cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            let wrong_aad = [0xFEu8; 16];
            check!(cipher.decrypt_in_place(&nonce, &wrong_aad, &mut buf).is_err(), "GCM256 wrong AAD");
        }
    }

    // =================================================================
    // 13. AES-256-GCM KAT (hw vs sw, all-zero)
    // =================================================================
    info!("=== 13. AES-256-GCM KAT ===");
    {
        let key: GenericArray<u8, typenum::U32> = GenericArray::clone_from_slice(&[0u8; 32]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0u8; 12]);

        let hw_cipher = HardwareAesGcm256::new(&key);
        let mut hw_buf = TestBuffer::<4112>::new(&[]);
        hw_cipher.encrypt_in_place(&nonce, &[], &mut hw_buf).unwrap();

        let sw_cipher = <SoftwareCipher<aes_gcm::Aes256Gcm>>::new(&key);
        let mut sw_buf = TestBuffer::<4112>::new(&[]);
        sw_cipher.encrypt_in_place(&nonce, &[], &mut sw_buf).unwrap();

        check!(slices_eq(hw_buf.as_slice(), sw_buf.as_slice(), "gcm256-zero"), "GCM256 all-zero hw==sw");
    }

    // =================================================================
    // 14. Cross-implementation: encrypt SW, decrypt HW (and vice versa)
    // =================================================================
    info!("=== 14. Cross-implementation encrypt/decrypt ===");
    {
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0x55u8; 16]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0x66u8; 12]);
        let aad = [0x77u8; 13];
        let pt = [0x88u8; 128];

        // SW encrypt → HW decrypt
        {
            let sw_cipher = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&key);
            let mut buf = TestBuffer::<1024>::new(&pt);
            sw_cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();

            let hw_cipher = HardwareAesGcm128::new(&key);
            hw_cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            check!(slices_eq(buf.as_slice(), &pt, "cross-sw-hw"), "GCM128 SW-enc HW-dec");
        }
        // HW encrypt → SW decrypt
        {
            let hw_cipher = HardwareAesGcm128::new(&key);
            let mut buf = TestBuffer::<1024>::new(&pt);
            hw_cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();

            let sw_cipher = <SoftwareCipher<aes_gcm::Aes128Gcm>>::new(&key);
            sw_cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            check!(slices_eq(buf.as_slice(), &pt, "cross-hw-sw"), "GCM128 HW-enc SW-dec");
        }
        // Same for AES-256
        {
            let key256: GenericArray<u8, typenum::U32> = GenericArray::clone_from_slice(&[0x55u8; 32]);
            let sw_cipher = <SoftwareCipher<aes_gcm::Aes256Gcm>>::new(&key256);
            let mut buf = TestBuffer::<1024>::new(&pt);
            sw_cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();

            let hw_cipher = HardwareAesGcm256::new(&key256);
            hw_cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            check!(slices_eq(buf.as_slice(), &pt, "cross256-sw-hw"), "GCM256 SW-enc HW-dec");
        }
        {
            let key256: GenericArray<u8, typenum::U32> = GenericArray::clone_from_slice(&[0x55u8; 32]);
            let hw_cipher = HardwareAesGcm256::new(&key256);
            let mut buf = TestBuffer::<1024>::new(&pt);
            hw_cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();

            let sw_cipher = <SoftwareCipher<aes_gcm::Aes256Gcm>>::new(&key256);
            sw_cipher.decrypt_in_place(&nonce, &aad, &mut buf).unwrap();
            check!(slices_eq(buf.as_slice(), &pt, "cross256-hw-sw"), "GCM256 HW-enc SW-dec");
        }
    }

    // =================================================================
    // 15. Interleaved hash contexts (Context save/restore)
    // =================================================================
    info!("=== 15. Interleaved hash contexts ===");
    {
        // Create two HardwareSha256 instances, update them alternately,
        // verify both produce correct results.
        let mut h1 = HardwareSha256::new();
        let mut h2 = HardwareSha256::new();

        // Feed "Hello " to h1, "Goodbye " to h2, interleaved
        h1.update(b"Hel");
        h2.update(b"Good");
        h1.update(b"lo ");
        h2.update(b"bye ");

        // Feed "World" to h1, "Rust" to h2
        h1.update(b"World");
        h2.update(b"Rust");

        let d1 = h1.finalize();
        let d2 = h2.finalize();

        // Compare with software
        let mut sw1 = <SoftwareHash<sha2::Sha256>>::new();
        sw1.update(b"Hello World");
        let sw_d1 = sw1.finalize();

        let mut sw2 = <SoftwareHash<sha2::Sha256>>::new();
        sw2.update(b"Goodbye Rust");
        let sw_d2 = sw2.finalize();

        check!(slices_eq(d1.as_slice(), sw_d1.as_slice(), "interleave-h1"), "Interleaved hash ctx 1");
        check!(slices_eq(d2.as_slice(), sw_d2.as_slice(), "interleave-h2"), "Interleaved hash ctx 2");
    }

    // =================================================================
    // 16. HKDF from_prk + short key error
    // =================================================================
    info!("=== 16. HKDF from_prk tests ===");
    {
        // from_prk with valid 32-byte PRK, then expand
        let prk = [0xAAu8; 32];
        let info = [0xBBu8; 16];
        let hw_hkdf = HardwareHkdfSha256::from_prk(&prk).unwrap();
        let mut hw_out = [0u8; 48];
        hw_hkdf.expand(&info, &mut hw_out).unwrap();

        let sw_hkdf = <SoftwareHkdf<sha2::Sha256>>::from_prk(&prk).unwrap();
        let mut sw_out = [0u8; 48];
        sw_hkdf.expand(&info, &mut sw_out).unwrap();

        check!(slices_eq(&hw_out, &sw_out, "hkdf-from-prk"), "HKDF from_prk expand hw==sw");

        // from_prk with short key (< 32 bytes) should error
        let result = HardwareHkdfSha256::from_prk(&[0u8; 16]);
        check!(result.is_err(), "HKDF from_prk short key → Err");
    }

    // =================================================================
    // 17. HMAC with edge-case key sizes
    // =================================================================
    info!("=== 17. HMAC edge-case keys ===");
    {
        let msg = b"test message";

        // Empty key
        let mut hw = HardwareHmacSha256::new_from_slice(&[]).unwrap();
        hw.update(msg);
        let hw_tag = hw.finalize();
        let mut sw = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&[]).unwrap();
        sw.update(msg);
        let sw_tag = sw.finalize();
        check!(slices_eq(hw_tag.as_slice(), sw_tag.as_slice(), "hmac-empty-key"), "HMAC empty key hw==sw");

        // Exactly 64-byte key (= SHA-256 block size boundary)
        let key64 = [0x42u8; 64];
        let mut hw = HardwareHmacSha256::new_from_slice(&key64).unwrap();
        hw.update(msg);
        let hw_tag = hw.finalize();
        let mut sw = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&key64).unwrap();
        sw.update(msg);
        let sw_tag = sw.finalize();
        check!(slices_eq(hw_tag.as_slice(), sw_tag.as_slice(), "hmac-64b-key"), "HMAC 64B key hw==sw");

        // 65-byte key (one over block size, triggers different pad path)
        let key65 = [0x43u8; 65];
        let mut hw = HardwareHmacSha256::new_from_slice(&key65).unwrap();
        hw.update(msg);
        let hw_tag = hw.finalize();
        let mut sw = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&key65).unwrap();
        sw.update(msg);
        let sw_tag = sw.finalize();
        check!(slices_eq(hw_tag.as_slice(), sw_tag.as_slice(), "hmac-65b-key"), "HMAC 65B key hw==sw");

        // 1-byte key
        let mut hw = HardwareHmacSha256::new_from_slice(&[0x01]).unwrap();
        hw.update(msg);
        let hw_tag = hw.finalize();
        let mut sw = <SoftwareHmac<sha2::Sha256>>::new_from_slice(&[0x01]).unwrap();
        sw.update(msg);
        let sw_tag = sw.finalize();
        check!(slices_eq(hw_tag.as_slice(), sw_tag.as_slice(), "hmac-1b-key"), "HMAC 1B key hw==sw");
    }

    // =================================================================
    // 18. Interrupt-disabled duration documentation test
    // =================================================================
    // Note: this is not a correctness test but verifies that large
    // operations complete without hanging (no watchdog/peripheral issues).
    info!("=== 18. Large payload smoke test ===");
    {
        // 4KB SHA-256
        let data = [0xFFu8; 4096];
        let mut h = HardwareSha256::new();
        h.update(&data);
        let hw_dig = h.finalize();
        let mut sw = <SoftwareHash<sha2::Sha256>>::new();
        sw.update(&data);
        let sw_dig = sw.finalize();
        check!(slices_eq(hw_dig.as_slice(), sw_dig.as_slice(), "large-sha"), "SHA-256 4KB hw==sw");

        // 4KB AES-128-GCM round-trip
        let key: GenericArray<u8, typenum::U16> = GenericArray::clone_from_slice(&[0xAAu8; 16]);
        let nonce: GenericArray<u8, typenum::U12> = GenericArray::clone_from_slice(&[0xBBu8; 12]);
        let cipher = HardwareAesGcm128::new(&key);
        let mut buf = TestBuffer::<4112>::new(&data);
        cipher.encrypt_in_place(&nonce, &[], &mut buf).unwrap();
        cipher.decrypt_in_place(&nonce, &[], &mut buf).unwrap();
        check!(slices_eq(buf.as_slice(), &data, "large-gcm"), "AES-128-GCM 4KB RT");
    }

    // =================================================================
    // Summary
    // =================================================================
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
