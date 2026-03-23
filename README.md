# embassy-stm32-tls

Hardware RNG-backed TLS for STM32H7 via [Embassy](https://embassy.dev) and
[embedded-tls](https://crates.io/crates/embedded-tls).

## What this crate does

Provides a thin `CryptoProvider` implementation for `embedded-tls` that uses
the STM32H7's hardware RNG peripheral (via `embassy-stm32`). The TLS cipher
suite (`Aes128GcmSha256`) runs in software — only the random number generation
is hardware-accelerated.

## Usage

```rust
use embassy_stm32::rng::Rng;
use embassy_stm32_tls::Stm32H7CryptoProvider;

// Construct the hardware RNG (caller owns the peripheral + interrupt binding)
let rng = Rng::new(p.RNG, Irqs);
let mut provider = Stm32H7CryptoProvider::new(rng);

// Use with embedded-tls
let mut tls = TlsConnection::new(socket, &mut read_buf, &mut write_buf);
tls.open::<_, Aes128GcmSha256>(TlsContext::new(&config, &mut provider))
    .await
    .unwrap();
```

## Scope and future work

This crate deliberately keeps a minimal scope: it only wraps the RNG.
`embedded-tls` currently hardcodes its AES-GCM and SHA-256 implementations to
software RustCrypto crates — there is no trait abstraction to swap in hardware
crypto yet.

A future effort could fork `embedded-tls` to abstract the cipher and hash
operations through `CryptoProvider`, enabling STM32 CRYP and HASH peripheral
acceleration. See `embedded-tls-hw-crypto-prompt.md` in this repo for a
detailed task prompt.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
