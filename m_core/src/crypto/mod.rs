mod errors;
pub mod key;
pub mod algorithms;

pub use errors::CryptoError;
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

pub trait CryptoKey {
    fn key_bytes(&self) -> usize;
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> CryptoResult<Self>
    where
        Self: Sized + Clone;
}

pub trait CryptoAlgorithm {
    const NAME: &'static str;
}

pub trait Hash: CryptoAlgorithm {
    fn hash(data: &[u8], output_size: usize) -> CryptoResult<Vec<u8>>;
    fn hash_to(data: &[u8], output: &mut [u8]) -> CryptoResult<()>;
}

pub trait Mac: CryptoAlgorithm {
    const TAG_SIZE: usize;
    const KEY_SIZE: usize;

    type SecretKey: CryptoKey;

    fn regenerate_key(&mut self);
    fn set_key(&mut self, key: Self::SecretKey);
    fn get_key(&self) -> Self::SecretKey;

    fn compute(&self, data: &[u8]) -> CryptoResult<Vec<u8>>;
    fn verify(&self, data: &[u8], tag: &[u8]) -> CryptoResult<bool>;
}

pub trait SymmetricCipher: CryptoAlgorithm {
    const KEY_SIZE: usize;

    type SecretKey: CryptoKey;
    
    fn regenerate_key(&mut self);
    fn set_key(&mut self, key: Self::SecretKey);
    fn get_key(&self) -> &Self::SecretKey;
}

pub trait SymmetricEncryption: SymmetricCipher {
    const NONCE_SIZE: usize;
    const TAG_SIZE: usize;

    fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> CryptoResult<Vec<u8>>;
    
    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

pub trait AsymmetricCipher: CryptoAlgorithm {
    const PUBLIC_KEY_SIZE: usize;
    const SECRET_KEY_SIZE: usize;

    type SecretKey: CryptoKey;
    type PublicKey: CryptoKey;
    
    fn regenerate_keypair(&mut self);
    fn set_secret(&mut self, keypair: Self::SecretKey);
    fn set_public(&mut self, keypair: Self::PublicKey);
    fn get_secret(&self) -> &Self::SecretKey;
    fn get_public(&self) -> &Self::PublicKey;
}

pub trait Signature: AsymmetricCipher {
    const SIGNATURE_SIZE: usize;
    
    fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>>;
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &[u8]) -> CryptoResult<bool>;
}

pub trait Kem: AsymmetricCipher {
    const CIPHERTEXT_SIZE: usize;
    const SHARED_SECRET_SIZE: usize;
    
    type SharedSecret: CryptoKey;
    
    fn encapsulate(public_key: &Self::PublicKey) -> CryptoResult<(Self::SharedSecret, Vec<u8>)>;
    fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Self::SharedSecret>;
}
