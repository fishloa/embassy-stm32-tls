//! Hardware SHA-256 hash using the STM32H7 HASH peripheral.

use embassy_stm32::hash::{Algorithm, Context, DataType};
use embedded_tls::TlsHash;
use generic_array::GenericArray;
use typenum::U32;

use super::with_hash;

/// SHA-256 hash backed by the STM32H7 HASH hardware accelerator.
///
/// The HASH peripheral's [`Context`] supports Clone, allowing the TLS stack
/// to snapshot and restore transcript hash state as required.
#[derive(Clone)]
pub struct HardwareSha256 {
    ctx: Context<'static>,
}

impl TlsHash for HardwareSha256 {
    type OutputSize = U32;

    fn new() -> Self {
        let ctx = with_hash(|hash| hash.start(Algorithm::SHA256, DataType::Width8, None));
        Self { ctx }
    }

    fn update(&mut self, data: &[u8]) {
        with_hash(|hash| {
            hash.update_blocking(&mut self.ctx, data);
        });
    }

    fn finalize(self) -> GenericArray<u8, U32> {
        let mut buf = [0u8; 32];
        with_hash(|hash| {
            hash.finish_blocking(self.ctx, &mut buf);
        });
        GenericArray::clone_from_slice(&buf)
    }
}
