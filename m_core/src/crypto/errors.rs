use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid {0}: {1}")]
    InvalidInput(&'static str, String),
    
    #[error("{0} failed: {1}")]
    OperationFailed(&'static str, String),
    
    #[error("{context} size mismatch: expected {expected}, got {actual}")]
    SizeMismatch {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
}
