#![no_std]
//! Hardware-accelerated TLS 1.3 crypto for STM32H7 via Embassy.
//!
//! This crate provides hardware-backed implementations of the `embedded-tls`
//! crypto traits using the STM32H7's CRYP and HASH peripherals.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use embassy_stm32_tls::{hardware, Stm32H7Aes128GcmSha256, Stm32H7CryptoProvider};
//!
//! // Initialize hardware peripherals (once, at startup)
//! hardware::init(cryp, hash);
//!
//! // Create provider with hardware cipher suite
//! let provider = Stm32H7CryptoProvider::<_, _, Stm32H7Aes128GcmSha256>::new_with_suite(rng);
//! ```

pub mod hardware;
mod cipher_suite;
mod provider;
mod test_buffer;

pub use cipher_suite::{Stm32H7Aes128GcmSha256, Stm32H7Aes256GcmSha384};
pub use provider::Stm32H7CryptoProvider;
pub use test_buffer::TestBuffer;
