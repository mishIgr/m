use crate::codecs::{CodecResult, CodecError, Compressor};
use zstd;

pub struct ZstdCompressor {
    compression_level: i32,
}

impl ZstdCompressor {
    pub fn new() -> Self {
        Self {
            compression_level: 10,
        }
    }

    pub fn with_level(compression_level: i32) -> Self {
        Self {
            compression_level: compression_level.clamp(1, 22),
        }
    }
}

impl Compressor for ZstdCompressor {
    fn compress(&self, data: &[u8]) -> CodecResult<Vec<u8>> {
        zstd::encode_all(data, self.compression_level)
            .map_err(|e| CodecError::CompressionError(e.to_string()))
    }

    fn decompress(&self, data: &[u8]) -> CodecResult<Vec<u8>> {
        zstd::decode_all(data)
            .map_err(|e| CodecError::DecompressionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_basic() {
        let compressor = ZstdCompressor::new();
        let data = b"Hello, World!";
        
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(data.to_vec(), decompressed);
    }

    #[test]
    fn test_binary_data() {
        let compressor = ZstdCompressor::new();
        let data: Vec<u8> = vec![0xFF, 0x00, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03];
        
        let compressed = compressor.compress(&data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_utf8_text() {
        let compressor = ZstdCompressor::new();
        let text = "Привет, мир! 🌍 Hello, World! 你好世界";
        let data = text.as_bytes();
        
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(data, decompressed.as_slice());
        assert_eq!(text, String::from_utf8(decompressed).unwrap());
    }

    #[test]
    fn test_compression_ratio() {
        let compressor = ZstdCompressor::new();
        let data = b"This is a test string with repetitions. ".repeat(100);
        
        let compressed = compressor.compress(&data).unwrap();
        let ratio = data.len() as f64 / compressed.len() as f64;
        
        assert!(ratio > 2.0, "Compression ratio: {:.2}", ratio);
    }

    #[test]
    fn test_invalid_compressed_data() {
        let compressor = ZstdCompressor::new();
        let invalid_data = vec![0xFF, 0xAA, 0xBB, 0xCC];
        
        let result = compressor.decompress(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_data() {
        let compressor = ZstdCompressor::new();
        let data = b"Original data";
        
        let mut compressed = compressor.compress(data).unwrap();
        
        if compressed.len() > 10 {
            compressed[5] ^= 0xFF;
        }
        
        let result = compressor.decompress(&compressed);
        assert!(result.is_err());
    }
}
