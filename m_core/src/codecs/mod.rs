mod errors;
pub mod algorithms;

pub use errors::CodecError;
pub type CodecResult<T> = std::result::Result<T, CodecError>;

pub trait Compressor {
    fn compress(&self, data: &[u8]) -> CodecResult<Vec<u8>>;
    fn decompress(&self, data: &[u8]) -> CodecResult<Vec<u8>>;
}
