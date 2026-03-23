#![no_std]

pub mod hardware;
mod cipher_suite;
mod provider;

pub use cipher_suite::Stm32H7Aes128GcmSha256;
pub use provider::Stm32H7CryptoProvider;
