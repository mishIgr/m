use crate::crypto::{CryptoResult, CryptoError, CryptoAlgorithm, Hash};

pub struct Blake3Hash;

impl CryptoAlgorithm for Blake3Hash {
    const NAME: &'static str = "BLAKE3";
}

impl Hash for Blake3Hash {

    fn hash(data: &[u8], output_size: usize) -> CryptoResult<Vec<u8>> {
        if output_size == 0 {
            return Err(CryptoError::InvalidInput(
                "hash output size",
                "must be greater than 0".to_string()
            ));
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        
        let mut output = vec![0u8; output_size];
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut output);
        
        Ok(output)
    }

    fn hash_to(data: &[u8], output: &mut [u8]) -> CryptoResult<()> {
        if output.is_empty() {
            return Err(CryptoError::InvalidInput(
                "hash output size",
                "must be greater than 0".to_string()
            ));
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(output);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_variable_sizes() {
        let data = b"BLAKE3 variable test";
        
        for size in [16, 32, 64, 128, 256, 512, 1024] {
            let crypto_result = Blake3Hash::hash(data, size).unwrap();
            assert_eq!(crypto_result.len(), size);
        }
    }

    #[test]
    fn test_blake3_deterministic() {
        let data = b"Test data";
        let crypto_result1 = Blake3Hash::hash(data, 64).unwrap();
        let crypto_result2 = Blake3Hash::hash(data, 64).unwrap();
        assert_eq!(crypto_result1, crypto_result2);
    }

    #[test]
    fn test_blake3_hash_to() {
        let data = b"Test data";
        let mut buffer = vec![0u8; 100];
        Blake3Hash::hash_to(data, &mut buffer).unwrap();
        
        let direct = Blake3Hash::hash(data, 100).unwrap();
        assert_eq!(buffer, direct);
    }

    #[test]
    fn test_blake3_zero_size() {
        let data = b"Test data";
        let result = Blake3Hash::hash(data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_blake3_empty_buffer() {
        let data = b"Test data";
        let mut buffer = [];
        let result = Blake3Hash::hash_to(data, &mut buffer);
        assert!(result.is_err());
    }
}
