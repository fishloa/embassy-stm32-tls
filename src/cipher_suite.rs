//! Hardware-accelerated TLS 1.3 cipher suites for STM32H7.

use embedded_tls::{SoftwareHkdf, SoftwareHmac, TlsCipherSuite};
use sha2::Sha384;
use typenum::{U12, U16, U22, U32, U48};

use crate::hardware::cipher::{HardwareAesGcm128, HardwareAesGcm256};
use crate::hardware::hash::HardwareSha256;
use crate::hardware::hkdf::HardwareHkdfSha256;
use crate::hardware::hmac::HardwareHmacSha256;

// LabelBuffer = HashOutput + LongestLabel(12) + LabelOverhead(10)
// SHA-256: 32 + 22 = 54
type U54 = typenum::Sum<U32, U22>;
// SHA-384: 48 + 22 = 70
type U70 = typenum::Sum<U48, U22>;

/// AES-128-GCM + SHA-256 cipher suite — fully hardware-accelerated.
///
/// All four crypto operations (cipher, hash, HMAC, HKDF) use the STM32H7
/// CRYP and HASH peripherals.
pub struct Stm32H7Aes128GcmSha256;

impl TlsCipherSuite for Stm32H7Aes128GcmSha256 {
    const CODE_POINT: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

    type Cipher = HardwareAesGcm128;
    type KeyLen = U16;
    type IvLen = U12;

    type Hash = HardwareSha256;
    type LabelBufferSize = U54;

    type Hmac = HardwareHmacSha256;
    type Hkdf = HardwareHkdfSha256;
}

/// AES-256-GCM + SHA-384 cipher suite — hardware cipher, software hash.
///
/// The AES-256-GCM cipher uses the STM32H7 CRYP peripheral. SHA-384, HMAC,
/// and HKDF use software (RustCrypto) because the STM32H755 HASH peripheral
/// (v2) only supports up to SHA-256.
pub struct Stm32H7Aes256GcmSha384;

impl TlsCipherSuite for Stm32H7Aes256GcmSha384 {
    const CODE_POINT: u16 = 0x1302; // TLS_AES_256_GCM_SHA384

    type Cipher = HardwareAesGcm256;
    type KeyLen = U32;
    type IvLen = U12;

    type Hash = embedded_tls::SoftwareHash<Sha384>;
    type LabelBufferSize = U70;

    type Hmac = SoftwareHmac<Sha384>;
    type Hkdf = SoftwareHkdf<Sha384>;
}
