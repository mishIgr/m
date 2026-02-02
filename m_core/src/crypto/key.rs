use crate::crypto::{CryptoError, CryptoResult};

use super::CryptoKey;

#[derive(Clone)]
pub struct Key<const N: usize> {
    data: Vec<u8>,
}

impl<const N: usize> CryptoKey for Key<N> {
    fn key_bytes(&self) -> usize {
        N
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != N {
            return Err(CryptoError::SizeMismatch {
                context: "key",
                expected: N,
                actual: bytes.len(),
            });
        }
        Ok(Key {
            data: bytes.to_vec()
        })
    }
}

impl<const N: usize> PartialEq for Key<N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<const N: usize> Eq for Key<N> {}
