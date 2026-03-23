#![no_std]

pub mod hardware;
mod cipher_suite;
mod provider;
mod test_buffer;

pub use cipher_suite::{Stm32H7Aes128GcmSha256, Stm32H7Aes256GcmSha384};
pub use provider::Stm32H7CryptoProvider;
pub use test_buffer::TestBuffer;
