//! Full TLS 1.3 handshake test over Ethernet on NUCLEO-H755ZI-Q.
//!
//! Connects to a public HTTPS server, performs a TLS 1.3 handshake using
//! hardware-accelerated crypto, sends an HTTP GET, and prints the response.
//!
//! Run with: cargo run --example tls_handshake --release --target thumbv7em-none-eabihf
//!
//! Prerequisites:
//! - NUCLEO-H755ZI-Q with Ethernet cable connected to a network with DHCP + internet
//! - probe-rs configured for STM32H755ZITx

#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use defmt::*;
use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::{Ipv4Address, StackResources};
use embassy_stm32::cryp::{self, Cryp};
use embassy_stm32::eth::{Ethernet, GenericPhy, PacketQueue, Sma};
use embassy_stm32::hash::{self, Hash};
use embassy_stm32::rng::Rng;
use embassy_stm32::{bind_interrupts, eth, peripherals, rng};
use embassy_time::Timer;
use embedded_tls::{TlsConfig, TlsConnection, TlsContext, UnsecureProvider};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use embassy_stm32_tls::{Stm32H7Aes128GcmSha256, hardware};

bind_interrupts!(struct Irqs {
    ETH =>      eth::InterruptHandler;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>,
                hash::InterruptHandler<peripherals::HASH>;
    CRYP =>     cryp::InterruptHandler<peripherals::CRYP>;
});

static SHARED: MaybeUninit<embassy_stm32::SharedData> = MaybeUninit::uninit();

type EthDev = Ethernet<'static, peripherals::ETH, GenericPhy<Sma<'static, peripherals::ETH_SMA>>>;

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, EthDev>) -> ! {
    runner.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init_primary(Default::default(), &SHARED);

    // --- Hardware crypto ---
    let cryp_peri = Cryp::new_blocking(p.CRYP, Irqs);
    let hash_peri = Hash::new_blocking(p.HASH, Irqs);
    let mut rng = Rng::new(p.RNG, Irqs);
    hardware::init(cryp_peri, hash_peri);
    info!("Crypto initialised.");

    // --- Ethernet (NUCLEO-H755ZI-Q RMII pinout) ---
    static PACKET_QUEUE: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
    let queue = PACKET_QUEUE.init(PacketQueue::new());

    let mut mac_addr = [0u8; 6];
    let _ = rng.async_fill_bytes(&mut mac_addr).await;
    mac_addr[0] = (mac_addr[0] & 0xFC) | 0x02; // locally administered unicast

    let eth = Ethernet::new(
        queue,
        p.ETH,
        Irqs,
        p.PA1,   // REF_CLK
        p.PA7,   // CRS_DV
        p.PC4,   // RXD0
        p.PC5,   // RXD1
        p.PG13,  // TXD0
        p.PB13,  // TXD1
        p.PG11,  // TX_EN
        mac_addr,
        p.ETH_SMA, // SMI
        p.PA2,  // MDIO
        p.PC1,  // MDC
    );
    info!("Ethernet created.");

    // --- Network stack ---
    static RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    let mut seed_bytes = [0u8; 8];
    let _ = rng.async_fill_bytes(&mut seed_bytes).await;
    let seed = u64::from_le_bytes(seed_bytes);

    let (stack, runner) = embassy_net::new(
        eth,
        embassy_net::Config::dhcpv4(Default::default()),
        RESOURCES.init(StackResources::new()),
        seed,
    );
    spawner.spawn(net_task(runner).unwrap());

    // --- Wait for link + DHCP ---
    info!("Waiting for link...");
    loop {
        if stack.is_link_up() { break; }
        Timer::after_millis(100).await;
    }
    info!("Link up. Waiting for DHCP...");
    loop {
        if let Some(cfg) = stack.config_v4() {
            info!("IP: {}", cfg.address);
            break;
        }
        Timer::after_millis(100).await;
    }

    // --- TCP connect ---
    let mut rx_buf = [0u8; 4096];
    let mut tx_buf = [0u8; 4096];
    let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);
    socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));

    let remote = (Ipv4Address::new(93, 184, 216, 34), 443); // example.com
    info!("Connecting to {:?}...", remote);
    if let Err(_e) = socket.connect(remote).await {
        error!("TCP connect failed");
        loop { cortex_m::asm::wfi(); }
    }
    info!("TCP connected.");

    // --- TLS handshake (hardware crypto) ---
    let mut tls_rx = [0u8; 16640];
    let mut tls_tx = [0u8; 16640];
    let tls_config = TlsConfig::new().with_server_name("example.com");

    let mut tls: TlsConnection<'_, _, Stm32H7Aes128GcmSha256> =
        TlsConnection::new(socket, &mut tls_rx, &mut tls_tx);

    let mut provider = UnsecureProvider::new::<Stm32H7Aes128GcmSha256>(rng);

    info!("Starting TLS 1.3 handshake...");
    match tls.open(TlsContext::new(&tls_config, &mut provider)).await {
        Ok(()) => info!("TLS handshake SUCCESS!"),
        Err(_e) => {
            error!("TLS handshake FAILED");
            loop { cortex_m::asm::wfi(); }
        }
    }

    // --- HTTP GET ---
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    if let Err(_e) = tls.write(req).await {
        error!("TLS write failed");
        loop { cortex_m::asm::wfi(); }
    }

    let mut buf = [0u8; 1024];
    match tls.read(&mut buf).await {
        Ok(n) => {
            info!("Received {} bytes", n);
            let show = core::cmp::min(n, 200);
            if let Ok(s) = core::str::from_utf8(&buf[..show]) {
                info!("{}", s);
            }
        }
        Err(_e) => error!("TLS read failed"),
    }

    tls.close().await.ok();
    info!("TLS handshake test PASSED.");

    loop { cortex_m::asm::wfi(); }
}
