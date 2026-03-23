# Claude Code Prompt: `embassy-stm32-tls`

**Model: Claude Opus 4.6**

---

You are an expert embedded Rust engineer. You are working in a new empty repository. Your task is to build a standalone crate called `embassy-stm32-tls` from scratch, published as an independent crate on crates.io, that implements the `CryptoProvider` trait from `embedded-tls` using the hardware CRYP and HASH peripherals available in `embassy-stm32` on STM32H7 devices.

## Context

The STM32H755ZIT6 has hardware AES-GCM (via the CRYP peripheral) and hardware SHA-256 (via the HASH peripheral). Both are already implemented as safe Rust drivers in `embassy-stm32` as `embassy_stm32::cryp` and `embassy_stm32::hash`. The `embedded-tls` crate has a `CryptoProvider` trait that allows hardware backends for TLS 1.3 crypto operations. No one has wired these two together yet. This crate does exactly that.

The long-term intention is to upstream this crate into the embassy-rs/embassy monorepo as `embassy-stm32-tls`. Build it to that standard from day one — code quality, documentation, test coverage, and CI should all be production grade.

## Goal

Implement `CryptoProvider` from `embedded-tls` using `embassy_stm32::cryp` for AES-GCM-256 and `embassy_stm32::hash` for SHA-256, targeting STM32H7 devices. The result is that any Embassy firmware using `embedded-tls` on an STM32H755 can replace the software crypto backend with this hardware-accelerated one by swapping a single type.

## Repository Structure

Initialise a complete standalone Rust crate repository with the following layout:

```
embassy-stm32-tls/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── CHANGELOG.md
├── LICENSE-MIT
├── LICENSE-APACHE
├── .gitignore
├── .cargo/
│   └── config.toml        — target = thumbv7em-none-eabihf, runner = probe-rs
├── .github/
│   └── workflows/
│       ├── ci.yml         — cargo check, cargo test, cargo clippy
│       └── publish.yml    — publishes to crates.io on tag v*
├── src/
│   ├── lib.rs
│   ├── provider.rs        — CryptoProvider impl
│   ├── aes_gcm.rs         — AES-GCM-256 using embassy_stm32::cryp
│   ├── sha256.rs          — SHA-256 using embassy_stm32::hash
│   └── rng.rs             — RNG wrapper using embassy_stm32::rng
└── examples/
    └── tls_client.rs      — minimal TLS client on NUCLEO-H755ZI-Q
```

## Cargo.toml Requirements

```toml
[package]
name = "embassy-stm32-tls"
version = "0.1.0"
edition = "2021"
description = "Hardware-accelerated TLS for STM32H7 via Embassy and embedded-tls"
license = "MIT OR Apache-2.0"
repository = "https://github.com/fishloa/embassy-stm32-tls"
keywords = ["embedded", "stm32", "tls", "embassy", "crypto"]
categories = ["embedded", "no-std", "cryptography"]

[dependencies]
embassy-stm32 = { version = "*", features = ["stm32h755zi"] }
embedded-tls = { version = "*" }
embassy-sync = { version = "*" }
heapless = { version = "0.8" }
defmt = { version = "0.3", optional = true }

[dev-dependencies]
aes-gcm = "0.10"
sha2 = "0.10"

[features]
default = []
defmt = ["dep:defmt", "embassy-stm32/defmt", "embedded-tls/defmt"]

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
```

## Implementation Requirements

Read the embedded-tls source and documentation before writing any code. Specifically examine the `CryptoProvider` trait definition, `TlsCipherSuite`, and how the existing `UnsecureProvider` software implementation works — model your implementation on that pattern.

The `Stm32H7CryptoProvider` struct must:
- Hold owned instances of the CRYP peripheral, HASH peripheral, and RNG peripheral from embassy-stm32
- Implement `CryptoProvider` with `CipherSuite = Aes128GcmSha256` initially (TLS 1.3 mandatory cipher suite)
- Use `embassy_stm32::cryp::AesGcm` for the AEAD encrypt/decrypt operations
- Use `embassy_stm32::hash` for SHA-256 HMAC and transcript hashing
- Use `embassy_stm32::rng::Rng` for the secure random number generator
- Be `Send` safe for use across Embassy tasks

The struct should be constructable like this:

```rust
let provider = Stm32H7CryptoProvider::new(
    p.CRYP,
    p.HASH,
    p.RNG,
    &mut p.DMA2_CH0,
);
```

And used like this:

```rust
let tls_config = TlsConfig::new()
    .with_server_name("example.com");
let mut tls = TlsConnection::new(tcp_socket, &mut tls_record_buf, &mut tls_plaintext_buf);
tls.open(TlsContext::new(&tls_config, &mut provider)).await?;
```

## Error Handling

Define a `Stm32TlsError` enum covering: `CrypPeripheralBusy`, `HashPeripheralBusy`, `RngError`, `InvalidKeySize`, `InvalidNonceSize`. Implement conversion to `embedded_tls::TlsError`.

## Peripheral Mock for Tests

Since the CRYP and HASH peripherals cannot be instantiated in a host-side `cargo test` run, create a `mock` module behind `#[cfg(test)]` that provides software implementations of the same operations using the `aes-gcm` and `sha2` RustCrypto crates. The NIST test vectors run against the mock on the host. This validates algorithmic correctness independently of hardware availability.

## NIST Test Vectors

Include a `#[cfg(test)]` module in `aes_gcm.rs` and `sha256.rs` with NIST test vectors running against the mock. These must pass before the crate is considered complete.

Use the NIST CAVS AES-GCM test vectors (at minimum: 128-bit key, 256-bit key, empty AAD, non-empty AAD cases). Use NIST SHA-256 test vectors (at minimum: empty input, `"abc"`, 448-bit message cases).

## CI Requirements

`.github/workflows/ci.yml` must run on every push and PR:
- `cargo check --target thumbv7em-none-eabihf`
- `cargo clippy --target thumbv7em-none-eabihf -- -D warnings`
- `cargo test` (host, runs mock-backed NIST vectors)
- `cargo build --example tls_client --target thumbv7em-none-eabihf`

`.github/workflows/publish.yml` must trigger on tag `v*` and publish to crates.io using `CARGO_REGISTRY_TOKEN` secret.

## README Requirements

Write a complete README.md covering:
- What this crate does
- Hardware requirements (STM32H755 or any STM32H7 with CRYP peripheral)
- How to add to Cargo.toml
- A minimal usage example
- A note that the long-term plan is to upstream into embassy-rs/embassy
- Performance comparison table (hw vs sw AES-GCM throughput — placeholder values, note these should be measured on real hardware)
- Contributing section pointing to the Matrix room at `https://matrix.to/#/#embassy-rs:matrix.org`

## CHANGELOG.md

Follow the Keep a Changelog format. Initial entry is `[0.1.0] - unreleased` with the initial feature list.

## Example

Write `examples/tls_client.rs` targeting NUCLEO-H755ZI-Q. It should establish a TLS 1.3 connection to `httpbin.org/get` over the board's Ethernet port using embassy-net and embassy-stm32 Ethernet MAC, make an HTTPS GET request, and print the response via defmt RTT.

## Validation Checklist

Before declaring the implementation complete, verify every item:

- [ ] `cargo check --target thumbv7em-none-eabihf` passes with no errors or warnings
- [ ] `cargo test` passes all NIST test vectors
- [ ] The `CryptoProvider` impl satisfies all trait bounds including `Send`
- [ ] `cargo build --example tls_client --target thumbv7em-none-eabihf` succeeds
- [ ] All public types and functions have rustdoc comments
- [ ] `#![no_std]` is set in `lib.rs`
- [ ] No `unwrap()` or `expect()` in library code — all errors propagated via `Result`
- [ ] `cargo clippy` passes with no warnings
- [ ] Both licence files (`LICENSE-MIT`, `LICENSE-APACHE`) are present
- [ ] `.gitignore` excludes `/target`
- [ ] `Cargo.lock` is committed
