//! Fixed-size buffer implementing [`TlsBuffer`] for tests and examples.

use embedded_tls::{TlsBuffer, TlsError};

/// A stack-allocated buffer of `N` bytes implementing [`TlsBuffer`].
///
/// Useful for benchmarks, tests, and examples where heap allocation
/// is unavailable.
pub struct TestBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> TestBuffer<N> {
    /// Create a buffer pre-filled with `initial` data.
    pub fn new(initial: &[u8]) -> Self {
        assert!(initial.len() <= N);
        let mut buf = Self {
            data: [0u8; N],
            len: initial.len(),
        };
        buf.data[..initial.len()].copy_from_slice(initial);
        buf
    }

    /// Create an empty buffer.
    pub fn empty() -> Self {
        Self {
            data: [0u8; N],
            len: 0,
        }
    }
}

impl<const N: usize> TlsBuffer for TestBuffer<N> {
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    fn len(&self) -> usize {
        self.len
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), TlsError> {
        if self.len + other.len() > N {
            return Err(TlsError::EncodeError);
        }
        self.data[self.len..self.len + other.len()].copy_from_slice(other);
        self.len += other.len();
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn capacity(&self) -> usize {
        N
    }
}
