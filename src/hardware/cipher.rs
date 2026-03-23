//! Hardware AES-128-GCM cipher using the STM32H7 CRYP peripheral.

use embedded_tls::{TlsBuffer, TlsCipher, TlsError};
use generic_array::GenericArray;
use typenum::{U12, U16};

use embassy_stm32::cryp::{AesGcm, Direction};

use super::with_cryp;

const AES_BLOCK: usize = 16;

/// AES-128-GCM cipher backed by the STM32H7 CRYP hardware accelerator.
pub struct HardwareAesGcm128 {
    key: [u8; 16],
}

impl TlsCipher for HardwareAesGcm128 {
    type KeySize = U16;
    type NonceSize = U12;
    type TagSize = U16;

    fn new(key: &GenericArray<u8, U16>) -> Self {
        let mut k = [0u8; 16];
        k.copy_from_slice(key.as_slice());
        Self { key: k }
    }

    fn encrypt_in_place<B: TlsBuffer>(
        &self,
        nonce: &GenericArray<u8, U12>,
        aad: &[u8],
        buffer: &mut B,
    ) -> Result<(), TlsError> {
        let iv: &[u8; 12] = nonce.as_slice().try_into().unwrap();
        let key = &self.key;

        let cipher = AesGcm::<16>::new(key, iv);

        let tag = with_cryp(|cryp| {
            let mut ctx = cryp.start_blocking(&cipher, Direction::Encrypt);

            // Feed AAD (pass all at once as the last block).
            cryp.aad_blocking::<16, _>(&mut ctx, aad, true);

            // Process payload block-by-block in place.
            let payload_len = buffer.len();
            let full_blocks = payload_len / AES_BLOCK;
            let remainder = payload_len % AES_BLOCK;

            for i in 0..full_blocks {
                let offset = i * AES_BLOCK;
                let last = remainder == 0 && i == full_blocks - 1;
                let mut temp = [0u8; AES_BLOCK];
                temp.copy_from_slice(&buffer.as_slice()[offset..offset + AES_BLOCK]);
                cryp.payload_blocking(
                    &mut ctx,
                    &temp,
                    &mut buffer.as_mut_slice()[offset..offset + AES_BLOCK],
                    last,
                );
            }

            if remainder > 0 {
                let offset = full_blocks * AES_BLOCK;
                let mut temp = [0u8; AES_BLOCK];
                temp[..remainder].copy_from_slice(&buffer.as_slice()[offset..offset + remainder]);
                let mut out = [0u8; AES_BLOCK];
                cryp.payload_blocking(&mut ctx, &temp[..remainder], &mut out[..remainder], true);
                buffer.as_mut_slice()[offset..offset + remainder]
                    .copy_from_slice(&out[..remainder]);
            }

            // Empty payload edge case: if payload_len == 0, still need to finish.
            if payload_len == 0 {
                cryp.payload_blocking(&mut ctx, &[], &mut [], true);
            }

            cryp.finish_blocking::<16, _>(ctx)
        });

        // Append the authentication tag.
        buffer
            .extend_from_slice(&tag)
            .map_err(|_| TlsError::EncodeError)
    }

    fn decrypt_in_place<B: TlsBuffer>(
        &self,
        nonce: &GenericArray<u8, U12>,
        aad: &[u8],
        buffer: &mut B,
    ) -> Result<(), TlsError> {
        let total_len = buffer.len();
        if total_len < 16 {
            return Err(TlsError::CryptoError);
        }
        let ciphertext_len = total_len - 16;

        // Extract the received tag from the end of the buffer.
        let mut received_tag = [0u8; 16];
        received_tag.copy_from_slice(&buffer.as_slice()[ciphertext_len..total_len]);

        // Truncate buffer to ciphertext only.
        buffer.truncate(ciphertext_len);

        let iv: &[u8; 12] = nonce.as_slice().try_into().unwrap();
        let key = &self.key;

        let cipher = AesGcm::<16>::new(key, iv);

        let computed_tag = with_cryp(|cryp| {
            let mut ctx = cryp.start_blocking(&cipher, Direction::Decrypt);

            // Feed AAD.
            cryp.aad_blocking::<16, _>(&mut ctx, aad, true);

            // Process payload block-by-block in place.
            let payload_len = buffer.len();
            let full_blocks = payload_len / AES_BLOCK;
            let remainder = payload_len % AES_BLOCK;

            for i in 0..full_blocks {
                let offset = i * AES_BLOCK;
                let last = remainder == 0 && i == full_blocks - 1;
                let mut temp = [0u8; AES_BLOCK];
                temp.copy_from_slice(&buffer.as_slice()[offset..offset + AES_BLOCK]);
                cryp.payload_blocking(
                    &mut ctx,
                    &temp,
                    &mut buffer.as_mut_slice()[offset..offset + AES_BLOCK],
                    last,
                );
            }

            if remainder > 0 {
                let offset = full_blocks * AES_BLOCK;
                let mut temp = [0u8; AES_BLOCK];
                temp[..remainder].copy_from_slice(&buffer.as_slice()[offset..offset + remainder]);
                let mut out = [0u8; AES_BLOCK];
                cryp.payload_blocking(&mut ctx, &temp[..remainder], &mut out[..remainder], true);
                buffer.as_mut_slice()[offset..offset + remainder]
                    .copy_from_slice(&out[..remainder]);
            }

            if payload_len == 0 {
                cryp.payload_blocking(&mut ctx, &[], &mut [], true);
            }

            cryp.finish_blocking::<16, _>(ctx)
        });

        // Verify the tag in constant-ish time (good enough for embedded).
        let mut diff = 0u8;
        for (a, b) in computed_tag.iter().zip(received_tag.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(TlsError::CryptoError);
        }

        Ok(())
    }
}
