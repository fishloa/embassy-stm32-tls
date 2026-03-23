//! Hardware HKDF-SHA-256 using the hardware HMAC-SHA-256 implementation.
//!
//! HKDF (RFC 5869) is built entirely from HMAC operations, so this
//! implementation inherits the hardware SHA-256 acceleration from
//! [`super::hmac::HardwareHmacSha256`].

use core::cmp;

use embedded_tls::{TlsError, TlsHkdf, TlsHmac};
use generic_array::GenericArray;
use typenum::U32;
use zeroize::Zeroize;

use super::hmac::HardwareHmacSha256;

/// HKDF-SHA-256 using the STM32H7 hardware HMAC-SHA-256.
pub struct HardwareHkdfSha256 {
    /// The pseudo-random key from the extract step.
    prk: [u8; 32],
}

impl Drop for HardwareHkdfSha256 {
    fn drop(&mut self) {
        self.prk.zeroize();
    }
}

impl TlsHkdf for HardwareHkdfSha256 {
    type OutputSize = U32;

    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> (GenericArray<u8, U32>, Self) {
        // HKDF-Extract: PRK = HMAC-SHA-256(salt, IKM)
        // If no salt, use a zero-filled key of hash length.
        let default_salt = [0u8; 32];
        let salt = salt.unwrap_or(&default_salt);

        let mut hmac =
            HardwareHmacSha256::new_from_slice(salt).expect("HMAC key creation should not fail");
        hmac.update(ikm);
        let prk_ga = hmac.finalize();

        let mut prk = [0u8; 32];
        prk.copy_from_slice(prk_ga.as_slice());

        (prk_ga, Self { prk })
    }

    fn from_prk(prk: &[u8]) -> Result<Self, TlsError> {
        if prk.len() < 32 {
            return Err(TlsError::InternalError);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&prk[..32]);
        Ok(Self { prk: key })
    }

    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), TlsError> {
        // HKDF-Expand: T(0) = empty, T(i) = HMAC(PRK, T(i-1) || info || i)
        // Output is T(1) || T(2) || ... truncated to the requested length.
        let hash_len = 32usize;
        let n = output.len().div_ceil(hash_len);
        if n > 255 {
            return Err(TlsError::CryptoError);
        }

        let mut t = [0u8; 32];
        let mut offset = 0;

        for i in 1..=n {
            let mut hmac = HardwareHmacSha256::new_from_slice(&self.prk)
                .map_err(|_| TlsError::CryptoError)?;

            if i > 1 {
                hmac.update(&t);
            }
            hmac.update(info);
            hmac.update(&[i as u8]);

            let result = hmac.finalize();
            t.copy_from_slice(result.as_slice());

            let copy_len = cmp::min(hash_len, output.len() - offset);
            output[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
            offset += copy_len;
        }

        Ok(())
    }
}
