# Task: Hardware Crypto Acceleration for embedded-tls

## Goal

Fork `embedded-tls` to abstract cipher and hash operations through `CryptoProvider`, then implement STM32H7 hardware-accelerated AES-GCM (via CRYP peripheral) and SHA-256/HMAC-SHA-256 (via HASH peripheral) in this crate.

Currently `embedded-tls` hardcodes software RustCrypto crates (`aes-gcm`, `sha2`, `hmac`) internally — the `CryptoProvider` trait only abstracts the RNG and certificate signature type. This task extends the trait to also abstract the cipher suite operations.

## Context from research (embedded-tls 0.18, embassy-stm32 0.6)

### Current CryptoProvider trait (embedded-tls 0.18)

```rust
// embedded-tls/src/crypto_provider.rs
pub trait CryptoProvider {
    type CipherSuite: TlsCipherSuite;
    type Signature: AsRef<[u8]>;
    fn rng(&mut self) -> impl CryptoRngCore;  // re-exported from rand_core 0.6
}
```

The `TlsCipherSuite` trait defines associated types for the cipher and hash, but they're consumed directly by `embedded-tls` internals using concrete RustCrypto types. The trait itself is:

```rust
pub trait TlsCipherSuite {
    const CODE_POINT: CipherSuite;
    type Cipher: KeySizeUser + ...;  // aes_gcm::AesGcm types
    type KeyLen: ArrayLength<u8>;
    type IvLen: ArrayLength<u8>;
    // etc.
}
```

### Where software crypto is called in embedded-tls

Key files to modify in the fork:
- `src/handshake/mod.rs` — HMAC-SHA-256 for key derivation (HKDF)
- `src/record.rs` — AES-GCM encrypt/decrypt for record protection
- `src/key_schedule.rs` — SHA-256 transcript hash, HKDF-Expand-Label

These currently import and use `sha2::Sha256`, `hmac::Hmac`, `aes_gcm::AesGcm` directly.

### embassy-stm32 CRYP API (0.6)

```rust
// embassy_stm32::cryp
pub struct Cryp<'d, T: Instance, D = NoDma> { ... }

impl<'d, T: Instance> Cryp<'d, T, NoDma> {
    pub fn new(peri: Peri<'d, T>) -> Self;

    pub fn start_blocking<C: Cipher<'_> + CipherSized + IVSized>(
        &self, key: &[u8], iv: &[u8], aad: &[u8], cipher: C,
    ) -> Context<'_, C>;

    pub fn aad_blocking<C: Cipher<'_> + CipherSized + IVSized>(
        &self, ctx: &mut Context<'_, C>, aad: &[u8], last_aad_block: bool,
    );

    pub fn payload_blocking<C: Cipher<'_> + CipherSized + IVSized>(
        &self, ctx: &mut Context<'_, C>, input: &[u8], output: &mut [u8], last_block: bool,
    );

    pub fn finish_blocking<C: Cipher<'_> + CipherSized + IVSized>(
        &self, ctx: Context<'_, C>,
    ) -> [u8; 16]; // GCM tag
}

// Cipher types available:
pub struct AesGcm128; // implements Cipher trait for AES-128-GCM
pub struct AesGcm256;
```

Note: The CRYP API is **synchronous** (blocking). This is fine because RustCrypto traits are also sync, so the replacement is 1:1. DMA variants exist but aren't needed.

### embassy-stm32 HASH API (0.6)

```rust
// embassy_stm32::hash
pub struct Hash<'d, T: Instance, D = NoDma> { ... }

impl<'d, T: Instance> Hash<'d, T, NoDma> {
    pub fn new(peri: Peri<'d, T>, _irq: impl Binding<T::Interrupt, InterruptHandler<T>>) -> Self;
    pub fn blocking_start(&mut self, algorithm: Algorithm, format: DataType);
    pub fn blocking_update(&mut self, data: &[u8]);
    pub fn blocking_finish(&mut self, output: &mut [u8; 32]); // for SHA-256
}

pub enum Algorithm {
    SHA256,
    // others...
}
```

HMAC-SHA-256 would need manual implementation on top of the HASH peripheral (apply HMAC construction: H(K⊕opad ∥ H(K⊕ipad ∥ message))).

### embassy-stm32 RNG API (0.6)

Already wrapped in this crate. `Rng<'d, T>` implements `rand_core_06::{RngCore, CryptoRng}`.

## Implementation plan

### Step 1: Fork embedded-tls

Fork `embedded-tls` and extend `CryptoProvider` to abstract crypto operations:

```rust
pub trait CryptoProvider {
    type CipherSuite: TlsCipherSuite;
    type Signature: AsRef<[u8]>;

    fn rng(&mut self) -> impl CryptoRngCore;

    // New: cipher operations
    fn encrypt_aead(
        &mut self, key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8], tag: &mut [u8], ciphertext: &mut [u8],
    ) -> Result<(), TlsError>;

    fn decrypt_aead(
        &mut self, key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8], plaintext: &mut [u8],
    ) -> Result<(), TlsError>;

    // New: hash operations
    fn hash_sha256(&mut self, data: &[&[u8]], output: &mut [u8; 32]);
    fn hmac_sha256(&mut self, key: &[u8], data: &[&[u8]], output: &mut [u8; 32]);
    fn hkdf_expand_label(
        &mut self, secret: &[u8], label: &[u8], context: &[u8], output: &mut [u8],
    ) -> Result<(), TlsError>;
}
```

Provide a default impl using software RustCrypto (so existing users don't break).

### Step 2: Implement hardware provider in this crate

```
src/
  lib.rs
  provider.rs       — CryptoProvider impl, delegates to sub-modules
  aes_gcm.rs        — wraps embassy_stm32::cryp for AES-128-GCM
  sha256.rs          — wraps embassy_stm32::hash for SHA-256 + HMAC-SHA-256
```

The provider struct would hold all three peripherals:

```rust
pub struct Stm32H7CryptoProvider<'d, R: rng::Instance, C: cryp::Instance, H: hash::Instance> {
    rng: Rng<'d, R>,
    cryp: Cryp<'d, C>,
    hash: Hash<'d, H>,
}
```

### Step 3: Test

- Implement known-answer tests (KAT) for AES-GCM and SHA-256 that run on-target
- Compare hardware output against software RustCrypto output for the same inputs
- Test full TLS handshake against a test server (e.g., `openssl s_server`)

## Version information

- `embedded-tls`: 0.18.0 (crates.io)
- `embassy-stm32`: 0.6.0 (crates.io)
- `stm32-metapac`: 21.0.0 (pulled by embassy-stm32)
- `rand_core`: 0.6.x (re-exported by embedded-tls as `CryptoRngCore`)
- `embedded-io-async`: 0.6.1 (used by embedded-tls 0.18)
- Target: `thumbv7em-none-eabihf` (Cortex-M7)

## Notes

- The CRYP and HASH peripherals use blocking APIs — this is fine since the crypto operations in embedded-tls's handshake/record processing are synchronous.
- HMAC-SHA-256 is not directly supported by the HASH peripheral on all STM32H7 variants. Check the reference manual for your specific chip. If HMAC mode is available in hardware, use it; otherwise, implement the HMAC construction manually using two SHA-256 passes.
- The `embedded-io-async` version (0.6 vs 0.7) ecosystem split between embassy-net and embedded-tls will likely resolve in a future embedded-tls release. Check compatibility before starting.
