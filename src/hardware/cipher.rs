//! Hardware AES-GCM ciphers using the STM32H7 CRYP peripheral.

use embedded_tls::{TlsBuffer, TlsCipher, TlsError};
use generic_array::GenericArray;
use typenum::{U12, U16, U32};

use embassy_stm32::cryp::{AesGcm, Direction};

use super::with_cryp;

const AES_BLOCK: usize = 16;

/// Process payload block-by-block through the CRYP peripheral,
/// reading from and writing back to the same buffer via a temp copy.
fn process_payload_in_place<'c, C>(
    cryp: &embassy_stm32::cryp::Cryp<'_, impl embassy_stm32::cryp::Instance, impl embassy_stm32::mode::Mode>,
    ctx: &mut embassy_stm32::cryp::Context<'c, C>,
    buffer: &mut impl TlsBuffer,
) where
    C: embassy_stm32::cryp::Cipher<'c>
        + embassy_stm32::cryp::CipherSized
        + embassy_stm32::cryp::IVSized,
{
    let payload_len = buffer.len();
    let full_blocks = payload_len / AES_BLOCK;
    let remainder = payload_len % AES_BLOCK;

    for i in 0..full_blocks {
        let offset = i * AES_BLOCK;
        let last = remainder == 0 && i == full_blocks - 1;
        let mut temp = [0u8; AES_BLOCK];
        temp.copy_from_slice(&buffer.as_slice()[offset..offset + AES_BLOCK]);
        cryp.payload_blocking(
            ctx,
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
        cryp.payload_blocking(ctx, &temp[..remainder], &mut out[..remainder], true);
        buffer.as_mut_slice()[offset..offset + remainder].copy_from_slice(&out[..remainder]);
    }

    if payload_len == 0 {
        cryp.payload_blocking(ctx, &[], &mut [], true);
    }
}

/// Constant-time tag comparison.
fn verify_tag(computed: &[u8; 16], received: &[u8; 16]) -> Result<(), TlsError> {
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(received.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 { Err(TlsError::CryptoError) } else { Ok(()) }
}

macro_rules! impl_hardware_aes_gcm {
    ($name:ident, $key_size:literal, $key_typenum:ty) => {
        pub struct $name {
            key: [u8; $key_size],
        }

        impl TlsCipher for $name {
            type KeySize = $key_typenum;
            type NonceSize = U12;
            type TagSize = U16;

            fn new(key: &GenericArray<u8, $key_typenum>) -> Self {
                let mut k = [0u8; $key_size];
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
                let cipher = AesGcm::<$key_size>::new(&self.key, iv);

                let tag = with_cryp(|cryp| {
                    let mut ctx = cryp.start_blocking(&cipher, Direction::Encrypt);
                    cryp.aad_blocking::<16, _>(&mut ctx, aad, true);
                    process_payload_in_place(cryp, &mut ctx, buffer);
                    cryp.finish_blocking::<16, _>(ctx)
                });

                buffer.extend_from_slice(&tag).map_err(|_| TlsError::EncodeError)
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

                let mut received_tag = [0u8; 16];
                received_tag.copy_from_slice(&buffer.as_slice()[ciphertext_len..total_len]);
                buffer.truncate(ciphertext_len);

                let iv: &[u8; 12] = nonce.as_slice().try_into().unwrap();
                let cipher = AesGcm::<$key_size>::new(&self.key, iv);

                let computed_tag = with_cryp(|cryp| {
                    let mut ctx = cryp.start_blocking(&cipher, Direction::Decrypt);
                    cryp.aad_blocking::<16, _>(&mut ctx, aad, true);
                    process_payload_in_place(cryp, &mut ctx, buffer);
                    cryp.finish_blocking::<16, _>(ctx)
                });

                verify_tag(&computed_tag, &received_tag)
            }
        }
    };
}

impl_hardware_aes_gcm!(HardwareAesGcm128, 16, U16);
impl_hardware_aes_gcm!(HardwareAesGcm256, 32, U32);
