use thiserror::Error;

#[derive(Error, Debug)]
pub enum CodecError {
    #[error("CompressionError: {0}")]
    CompressionError(String),

    #[error("DecompressionError {0}")]
    DecompressionError(String),
}
