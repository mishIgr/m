use crate::crypto::utils::{Result, CryptoError};
use crate::crypto::traits::{CryptoAlgorithm, Hash};

pub struct Blake3Hash {
    output_size: usize,
}

impl CryptoAlgorithm for Blake3Hash {
    const NAME: &'static str = "BLAKE3";
}

impl Hash for Blake3Hash {
    fn new(output_size: usize) -> Result<Self> {
        if output_size == 0 {
            return Err(CryptoError::new("BLAKE3 output size must be greater than 0"));
        }

        Ok(Self { output_size })
    }

    fn output_size(&self) -> usize {
        self.output_size
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        
        let mut output = vec![0u8; self.output_size];
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut output);
        
        Ok(output)
    }

    fn hash_to(&self, data: &[u8], output: &mut [u8]) -> Result<()> {
        if output.len() != self.output_size {
            return Err(CryptoError::new(format!(
                "Output buffer size mismatch: expected {}, got {}",
                self.output_size,
                output.len()
            )));
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(output);
        
        Ok(())
    }
}

impl Default for Blake3Hash {
    fn default() -> Self {
        Self::new(32).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_variable_sizes() {
        for size in [16, 32, 64, 128, 256, 512, 1024] {
            let hash = Blake3Hash::new(size).unwrap();
            let data = b"BLAKE3 variable test";
            let result = hash.hash(data).unwrap();
            assert_eq!(result.len(), size);
        }
    }

    #[test]
    fn test_blake3_deterministic() {
        let hash = Blake3Hash::new(64).unwrap();
        let data = b"Test data";
        let result1 = hash.hash(data).unwrap();
        let result2 = hash.hash(data).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_blake3_hash_to() {
        let hash = Blake3Hash::new(100).unwrap();
        let data = b"Test data";
        let mut buffer = vec![0u8; 100];
        hash.hash_to(data, &mut buffer).unwrap();
        
        let direct = hash.hash(data).unwrap();
        assert_eq!(buffer, direct);
    }
}
