# Changelog

## 0.1.0 — 2026-03-23

- Initial release
- `Stm32H7CryptoProvider`: hardware RNG-backed `CryptoProvider` for `embedded-tls`
- `Stm32H7Aes128GcmSha256`: fully hardware-accelerated cipher suite (CRYP + HASH)
- `Stm32H7Aes256GcmSha384`: hybrid cipher suite (hardware AES-256-GCM, software SHA-384)
- Hardware implementations: `HardwareAesGcm128`, `HardwareAesGcm256`, `HardwareSha256`, `HardwareHmacSha256`, `HardwareHkdfSha256`
- `TestBuffer<N>`: generic `TlsBuffer` implementation for tests and examples
- Benchmark example: hw vs sw comparison across all operations and payload sizes
- Test vectors example: NIST KATs, RFC 4231, hw/sw comparison, AES-GCM edge cases
