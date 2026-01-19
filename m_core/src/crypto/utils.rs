use std::error::Error;
use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct CryptoError {
    message: String,
}

impl CryptoError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Crypto error: {}", self.message)
    }
}

impl Error for CryptoError {}

impl From<String> for CryptoError {
    fn from(s: String) -> Self {
        CryptoError::new(s)
    }
}

impl From<&str> for CryptoError {
    fn from(s: &str) -> Self {
        CryptoError::new(s)
    }
}

pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<const N: usize>(Box<[u8; N]>);

impl<const N: usize> SecretKey<N> {
    pub fn new(data: &[u8]) -> CryptoResult<Self> {
        let boxed_array: Box<[u8; N]> = data
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| format!("Expected {} bytes, got {}", N, data.len()))?;
        Ok(Self(boxed_array))
    }
    
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<const N: usize> AsMut<[u8]> for SecretKey<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl<const N: usize> std::ops::Deref for SecretKey<N> {
    type Target = [u8; N];
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> std::ops::DerefMut for SecretKey<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for SecretKey<N> {
    fn from(data: [u8; N]) -> Self {
        Self(Box::new(data))
    }
}

impl<const N: usize> PartialEq for SecretKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl<const N: usize> Eq for SecretKey<N> {}

#[derive(Clone)]
pub struct PublicKey<const N: usize>(Box<[u8; N]>);

impl<const N: usize> PublicKey<N> {
    pub fn new(data: &[u8]) -> CryptoResult<Self> {
        let boxed_array: Box<[u8; N]> = data
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| format!("Expected {} bytes, got {}", N, data.len()))?;
        Ok(Self(boxed_array))
    }
    
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for PublicKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<const N: usize> AsMut<[u8]> for PublicKey<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl<const N: usize> std::ops::Deref for PublicKey<N> {
    type Target = [u8; N];
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> std::ops::DerefMut for PublicKey<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for PublicKey<N> {
    fn from(data: [u8; N]) -> Self {
        Self(Box::new(data))
    }
}

impl<const N: usize> PartialEq for PublicKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl<const N: usize> Eq for PublicKey<N> {}

#[derive(Clone)]
pub struct KeyPair<const S: usize, const P: usize> {
    pub secret: SecretKey<S>,
    pub public: PublicKey<P>,
}

impl<const S: usize, const P: usize> KeyPair<S, P> {
    pub fn new(secret: &[u8], public: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            secret: SecretKey::new(secret)?,
            public: PublicKey::new(public)?,
        })
    }
}

impl<const S: usize, const P: usize> From<([u8; S], [u8; P])> for KeyPair<S, P> {
    fn from(data: ([u8; S], [u8; P])) -> Self {
        Self {
            secret: SecretKey::from(data.0),
            public: PublicKey::from(data.1),
        }
    }
}

impl<const S: usize, const P: usize> PartialEq for KeyPair<S, P> {
    fn eq(&self, other: &Self) -> bool {
        self.public.as_bytes().ct_eq(other.public.as_bytes()).into() 
            && self.secret.as_bytes().ct_eq(other.secret.as_bytes()).into()
    }
}

impl<const S: usize, const P: usize> Eq for KeyPair<S, P> {}
