use std::error::Error;
use std::fmt;

pub type Key<const N: usize> = [u8; N];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPair<const S: usize, const P: usize> {
    pub secret: Key<S>,
    pub public: Key<P>,
}

impl<const S: usize, const P: usize> KeyPair<S, P> {
    pub fn new(secret: Key<S>, public: Key<P>) -> Self {
        Self { secret, public }
    }

    pub fn into_keys(self) -> (Key<S>, Key<P>) {
        (self.secret, self.public)
    }
}

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

pub type Result<T> = std::result::Result<T, CryptoError>;
