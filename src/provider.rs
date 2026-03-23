use embassy_stm32::rng::{self, Rng};
use embedded_tls::{Aes128GcmSha256, CryptoProvider, CryptoRngCore};

/// A [`CryptoProvider`] for `embedded-tls` backed by the STM32H7 hardware RNG.
///
/// This provider uses the existing software `Aes128GcmSha256` cipher suite
/// but supplies cryptographically secure random numbers from the STM32's
/// hardware RNG peripheral.
///
/// # Example
///
/// ```rust,no_run
/// use embassy_stm32::rng::Rng;
/// use embassy_stm32_tls::Stm32H7CryptoProvider;
///
/// let rng = Rng::new(p.RNG, Irqs);
/// let mut provider = Stm32H7CryptoProvider::new(rng);
/// ```
pub struct Stm32H7CryptoProvider<'d, T: rng::Instance> {
    rng: Rng<'d, T>,
}

impl<'d, T: rng::Instance> Stm32H7CryptoProvider<'d, T> {
    /// Create a new crypto provider from an already-constructed [`Rng`].
    pub fn new(rng: Rng<'d, T>) -> Self {
        Self { rng }
    }
}

impl<'d, T: rng::Instance> CryptoProvider for Stm32H7CryptoProvider<'d, T> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = &'d [u8];

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }
}
