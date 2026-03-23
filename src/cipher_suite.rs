//! Hardware-accelerated TLS 1.3 cipher suite for AES-128-GCM with SHA-256.

use embedded_tls::TlsCipherSuite;
use typenum::{U12, U16, U22, U32};

use crate::hardware::cipher::HardwareAesGcm128;
use crate::hardware::hash::HardwareSha256;
use crate::hardware::hkdf::HardwareHkdfSha256;
use crate::hardware::hmac::HardwareHmacSha256;

/// AES-128-GCM + SHA-256 cipher suite using STM32H7 hardware acceleration.
///
/// Drop-in replacement for the software `Aes128GcmSha256` — just change
/// the type parameter on your [`CryptoProvider`](embedded_tls::CryptoProvider).
pub struct Stm32H7Aes128GcmSha256;

// LabelBuffer = HashOutput(32) + LongestLabel(12) + LabelOverhead(10) = 54
// But the trait uses typenum Sum<OutputSize, Sum<U12, U10>>.
// U32 + U12 + U10 = U54. We need to express this properly.
// Actually, looking at config.rs the LabelBuffer type is:
//   Sum<<<CipherSuite as TlsCipherSuite>::Hash as TlsHash>::OutputSize, Sum<LongestLabel, LabelOverhead>>
// where LongestLabel = U12, LabelOverhead = U10.
// So for SHA-256 (OutputSize = U32): U32 + U22 = U54.
// But the existing Aes128GcmSha256 uses `LabelBuffer<Self>` which computes this.
// We need to provide a concrete type. typenum::U54 should work.
// Since we can't use the type alias from embedded-tls's config module,
// we compute it manually: U32 + U12 + U10 = U54.
type U54 = typenum::Sum<U32, U22>;

impl TlsCipherSuite for Stm32H7Aes128GcmSha256 {
    // TLS_AES_128_GCM_SHA256 = 0x1301
    const CODE_POINT: u16 = 0x1301;

    type Cipher = HardwareAesGcm128;
    type KeyLen = U16;
    type IvLen = U12;

    type Hash = HardwareSha256;
    type LabelBufferSize = U54;

    type Hmac = HardwareHmacSha256;
    type Hkdf = HardwareHkdfSha256;
}
