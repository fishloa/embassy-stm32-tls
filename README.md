# embassy-stm32-tls

Hardware-accelerated TLS 1.3 crypto for STM32H7 via [Embassy](https://embassy.dev)
and [embedded-tls](https://crates.io/crates/embedded-tls).

## What this crate does

Provides hardware-accelerated implementations of the TLS 1.3 cryptographic
operations for STM32H7 microcontrollers, using the CRYP (AES-GCM) and HASH
(SHA-256) peripherals via `embassy-stm32`.

### Cipher suites

| Cipher Suite | Cipher | Hash | HMAC | HKDF |
|---|---|---|---|---|
| `Stm32H7Aes128GcmSha256` | HW CRYP | HW HASH | HW (via SHA-256) | HW (via HMAC) |
| `Stm32H7Aes256GcmSha384` | HW CRYP | SW RustCrypto | SW | SW |

The AES-256 suite is hybrid because the STM32H755 HASH peripheral (v2) only
supports up to SHA-256. On chips with HASH v3+ (e.g. STM32H5), SHA-384 could
also be hardware-accelerated.

### Hardware implementations

- **`HardwareAesGcm128` / `HardwareAesGcm256`** — AES-GCM via CRYP peripheral.
  Processes data block-by-block with a 16-byte temp buffer to work around the
  peripheral's separate input/output buffer requirement. Constant-time tag
  verification via `subtle::ConstantTimeEq`. Key material zeroed on drop.

- **`HardwareSha256`** — SHA-256 via HASH peripheral. The peripheral's `Context`
  supports Clone (register save/restore), enabling transcript hash snapshots
  as required by TLS 1.3.

- **`HardwareHmacSha256`** — HMAC-SHA-256 via RFC 2104 standard construction on
  top of hardware SHA-256. Key material zeroed on drop.

- **`HardwareHkdfSha256`** — HKDF-SHA-256 built entirely on `HardwareHmacSha256`.
  PRK zeroed on drop.

### Security

- Constant-time tag comparison using `subtle::ConstantTimeEq`
- Key material zeroed on drop using `zeroize`
- Double-initialization guard on `hardware::init()`
- RNG initialization documented as prerequisite for CRYP/HASH

## Usage

```rust
use embassy_stm32::cryp::Cryp;
use embassy_stm32::hash::Hash;
use embassy_stm32::rng::Rng;
use embassy_stm32_tls::{Stm32H7Aes128GcmSha256, Stm32H7CryptoProvider, hardware};
use embedded_tls::{TlsConfig, TlsConnection, TlsContext, UnsecureProvider};

// Initialize hardware crypto (once, at startup — after RNG!)
let rng = Rng::new(p.RNG, Irqs);
let cryp = Cryp::new_blocking(p.CRYP, Irqs);
let hash = Hash::new_blocking(p.HASH, Irqs);
hardware::init(cryp, hash);

// Create provider with hardware cipher suite
let mut provider = UnsecureProvider::new::<Stm32H7Aes128GcmSha256>(rng);

// TLS handshake
let mut tls: TlsConnection<'_, _, Stm32H7Aes128GcmSha256> =
    TlsConnection::new(socket, &mut read_buf, &mut write_buf);
tls.open(TlsContext::new(&config, &mut provider)).await.unwrap();
```

## Examples

### TLS handshake (end-to-end test)

Full TLS 1.3 connection to example.com:443 over Ethernet with hardware crypto:

```
cargo run --example tls_handshake --release --target thumbv7em-none-eabihf
```

### Benchmark (hardware vs software)

Measures cycle counts and memory for all crypto operations at 64/256/1024/4096B:

```
cargo run --example benchmark --release --target thumbv7em-none-eabihf
```

### Test vectors

~180 tests: NIST KATs, RFC 4231/5869, hw-vs-sw comparison, edge cases,
negative tests, cross-implementation decrypt, interleaved hash contexts:

```
cargo run --example test_vectors --release --target thumbv7em-none-eabihf
```

## Interrupt latency

All operations run in blocking mode inside critical sections. For large
payloads (e.g. 4 KB AES-GCM), interrupts may be disabled for hundreds of
microseconds. See the `hardware` module documentation for details.

## Dependencies

This crate depends on a fork of `embedded-tls` that adds abstraction traits
for hardware crypto extensibility. The fork is at
[fishloa/embedded-tls](https://github.com/fishloa/embedded-tls/tree/hw-crypto-extensibility).
An upstream PR to [drogue-iot/embedded-tls](https://github.com/drogue-iot/embedded-tls)
is planned after on-target validation.

## Target hardware

- **Board:** NUCLEO-H755ZI-Q (Cortex-M7 core)
- **Peripherals:** CRYP (cryp_v4), HASH (hash_v2), RNG
- **Target:** `thumbv7em-none-eabihf`

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
