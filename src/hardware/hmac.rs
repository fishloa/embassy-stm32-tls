//! Hardware HMAC-SHA-256 using the STM32H7 HASH peripheral's SHA-256.
//!
//! Implements the standard HMAC construction (RFC 2104) on top of the
//! hardware SHA-256 engine, avoiding self-referential lifetime issues
//! that would arise from the HASH peripheral's native HMAC mode.

use embedded_tls::{TlsHmac, TlsError};
use generic_array::GenericArray;
use typenum::U32;

use embassy_stm32::hash::{Algorithm, Context, DataType};

use super::with_hash;

const SHA256_BLOCK_SIZE: usize = 64;

/// HMAC-SHA-256 built on top of the STM32H7 hardware SHA-256 engine.
///
/// Uses the standard HMAC construction:
/// `HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))`
///
/// where K' is the key zero-padded (or hashed) to the block size.
pub struct HardwareHmacSha256 {
    /// Inner hash context, already seeded with `K' XOR ipad`.
    inner_ctx: Context<'static>,
    /// `K' XOR opad`, stored for the outer pass in [`finalize`].
    outer_key_pad: [u8; SHA256_BLOCK_SIZE],
}

impl TlsHmac for HardwareHmacSha256 {
    type OutputSize = U32;

    fn new_from_slice(key: &[u8]) -> Result<Self, TlsError> {
        // Derive K' — hash if longer than block size, else zero-pad.
        let mut key_block = [0u8; SHA256_BLOCK_SIZE];
        if key.len() > SHA256_BLOCK_SIZE {
            // Hash the key down to 32 bytes.
            let digest = with_hash(|hash| {
                let ctx = hash.start(Algorithm::SHA256, DataType::Width8, None);
                let mut ctx = ctx;
                hash.update_blocking(&mut ctx, key);
                let mut buf = [0u8; 32];
                hash.finish_blocking(ctx, &mut buf);
                buf
            });
            key_block[..32].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // Compute ipad and opad key blocks.
        let mut inner_key_pad = [0u8; SHA256_BLOCK_SIZE];
        let mut outer_key_pad = [0u8; SHA256_BLOCK_SIZE];
        for i in 0..SHA256_BLOCK_SIZE {
            inner_key_pad[i] = key_block[i] ^ 0x36;
            outer_key_pad[i] = key_block[i] ^ 0x5C;
        }

        // Start the inner hash and feed the ipad-XORed key.
        let inner_ctx = with_hash(|hash| {
            let mut ctx = hash.start(Algorithm::SHA256, DataType::Width8, None);
            hash.update_blocking(&mut ctx, &inner_key_pad);
            ctx
        });

        Ok(Self {
            inner_ctx,
            outer_key_pad,
        })
    }

    fn update(&mut self, data: &[u8]) {
        with_hash(|hash| {
            hash.update_blocking(&mut self.inner_ctx, data);
        });
    }

    fn finalize(self) -> GenericArray<u8, U32> {
        // Finish the inner hash: H(K' XOR ipad || message)
        let mut inner_digest = [0u8; 32];
        with_hash(|hash| {
            hash.finish_blocking(self.inner_ctx, &mut inner_digest);
        });

        // Compute the outer hash: H(K' XOR opad || inner_digest)
        let mut result = [0u8; 32];
        with_hash(|hash| {
            let mut ctx = hash.start(Algorithm::SHA256, DataType::Width8, None);
            hash.update_blocking(&mut ctx, &self.outer_key_pad);
            hash.update_blocking(&mut ctx, &inner_digest);
            hash.finish_blocking(ctx, &mut result);
        });

        GenericArray::clone_from_slice(&result)
    }

    fn verify(self, tag: &GenericArray<u8, U32>) -> Result<(), TlsError> {
        let computed = self.finalize();
        // Constant-time comparison.
        let mut diff = 0u8;
        for (a, b) in computed.iter().zip(tag.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            Err(TlsError::CryptoError)
        } else {
            Ok(())
        }
    }
}
