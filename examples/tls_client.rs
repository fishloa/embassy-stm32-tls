//! Minimal TLS client example for NUCLEO-H755ZI-Q (Cortex-M7 core).
//!
//! Demonstrates how to construct a `Stm32H7CryptoProvider` and use it with
//! `embedded-tls` to perform a TLS 1.3 handshake.
//!
//! NOTE: This is a build-check skeleton. A real application needs a working
//! network stack (Ethernet driver, DHCP, etc.) and compatible `embedded-io-async`
//! versions between embassy-net and embedded-tls.

#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::rng::Rng;
use embassy_stm32::{bind_interrupts, peripherals, rng};
use embassy_stm32_tls::Stm32H7CryptoProvider;
use embedded_tls::TlsConfig;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

static SHARED: MaybeUninit<embassy_stm32::SharedData> = MaybeUninit::uninit();

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_stm32::init_primary(Default::default(), &SHARED);

    // --- Hardware RNG ---
    let rng = Rng::new(p.RNG, Irqs);
    let provider = Stm32H7CryptoProvider::new(rng);

    info!("Crypto provider ready.");

    // --- TLS usage (illustrative) ---
    // In a real application, `socket` would be a TCP socket from embassy-net
    // that implements `embedded_io_async::{Read, Write}` (version 0.6, matching
    // embedded-tls 0.18). The provider is passed to TlsContext::new:
    //
    //   let tls_config = TlsConfig::new().with_server_name("example.com");
    //   let mut tls: TlsConnection<'_, _, Aes128GcmSha256> =
    //       TlsConnection::new(socket, &mut read_buf, &mut write_buf);
    //   tls.open(TlsContext::new(&tls_config, provider)).await.unwrap();

    // Demonstrate that the provider compiles with the TLS types.
    let _config = TlsConfig::new().with_server_name("example.com");
    let _ = provider;

    info!("Done. Wire up a network stack to perform a real handshake.");
}
