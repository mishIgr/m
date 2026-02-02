use crate::crypto::{CryptoResult, CryptoError, CryptoKey, SymmetricCipher, CryptoAlgorithm, SymmetricEncryption};
use crate::crypto::key::Key;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm as Aes128GcmImpl, Aes256Gcm as Aes256GcmImpl,
    Nonce,
};
use rand::RngCore;

macro_rules! impl_aes_gcm {
    ($name:ident, $impl_type:ty, $key_size:expr, $display_name:expr) => {
        pub struct $name {
            key: Key<$key_size>,
        }

        impl CryptoAlgorithm for $name {
            const NAME: &'static str = $display_name;
        }

        impl SymmetricCipher for $name {
            const KEY_SIZE: usize = $key_size;
            type SecretKey = Key<$key_size>;

            fn regenerate_key(&mut self) {
                let mut rng = rand::rng();
                let mut buf = [0u8; Self::KEY_SIZE];
                rng.fill_bytes(&mut buf);
                self.key = CryptoKey::from_bytes(&buf).expect("Failed to generate key");
            }


            fn set_key(&mut self, key: Self::SecretKey) {
                self.key = key;
            }

            fn get_key(&self) -> &Self::SecretKey {
                &self.key
            }
        }

        impl SymmetricEncryption for $name {
            const NONCE_SIZE: usize = 12;
            const TAG_SIZE: usize = 16;

            fn encrypt(
                &self,
                nonce: &[u8],
                plaintext: &[u8],
                associated_data: &[u8],
            ) -> CryptoResult<Vec<u8>> {
                if nonce.len() != Self::NONCE_SIZE {
                    return Err(CryptoError::SizeMismatch {
                        context: "nonce",
                        expected: Self::NONCE_SIZE,
                        actual: nonce.len(),
                    });
                }

                let cipher = <$impl_type>::new_from_slice(self.key.as_bytes())
                    .map_err(|e| CryptoError::OperationFailed(
                        "Cipher initialization",
                        format!("failed to create cipher: {:?}", e)
                    ))?;

                let nonce_array = Nonce::from_slice(nonce);

                let payload = Payload {
                    msg: plaintext,
                    aad: associated_data,
                };

                cipher
                    .encrypt(nonce_array, payload)
                    .map_err(|e| CryptoError::OperationFailed(
                        "Encryption",
                        format!("{:?}", e)
                    ))
            }

            fn decrypt(
                &self,
                nonce: &[u8],
                ciphertext: &[u8],
                associated_data: &[u8],
            ) -> CryptoResult<Vec<u8>> {
                if nonce.len() != Self::NONCE_SIZE {
                    return Err(CryptoError::SizeMismatch {
                        context: "nonce",
                        expected: Self::NONCE_SIZE,
                        actual: nonce.len(),
                    });
                }

                if ciphertext.len() < Self::TAG_SIZE {
                    return Err(CryptoError::SizeMismatch {
                        context: "ciphertext",
                        expected: Self::TAG_SIZE,
                        actual: ciphertext.len(),
                    });
                }

                let cipher = <$impl_type>::new_from_slice(self.key.as_bytes())
                    .map_err(|e| CryptoError::OperationFailed(
                        "Cipher initialization",
                        format!("failed to create cipher: {:?}", e)
                    ))?;

                let nonce_array = Nonce::from_slice(nonce);

                let payload = Payload {
                    msg: ciphertext,
                    aad: associated_data,
                };

                cipher
                    .decrypt(nonce_array, payload)
                    .map_err(|e| CryptoError::OperationFailed(
                        "Decryption",
                        format!("{:?}", e)
                    ))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            pub fn new() -> Self {
                let mut rng = rand::rng();
                let mut buf = [0u8; Self::KEY_SIZE];
                rng.fill_bytes(&mut buf);
                Self{ key: CryptoKey::from_bytes(&buf).expect("Failed to generate key") }
            }

            pub fn from_key(key: Key<$key_size>) -> Self {
                Self { key }
            }

            pub fn generate_nonce() -> [u8; Self::NONCE_SIZE] {
                let mut nonce = [0u8; Self::NONCE_SIZE];
                let mut rng = rand::rng();
                rng.fill_bytes(&mut nonce);
                nonce
            }
        }
    };
}

impl_aes_gcm!(Aes128Gcm, Aes128GcmImpl, 16, "AES-128-GCM");
impl_aes_gcm!(Aes256Gcm, Aes256GcmImpl, 32, "AES-256-GCM");

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_aes_gcm_variant {
        ($variant:ident) => {
            paste::paste! {
                #[test]
                fn [<test_ $variant:lower _basic>]() {
                    let cipher = $variant::new();
                    let nonce = $variant::generate_nonce();
                    let plaintext = b"Hello, World!";
                    let aad = b"additional data";

                    let ciphertext = cipher
                        .encrypt(&nonce, plaintext, aad)
                        .expect("Encryption failed");

                    assert_eq!(
                        ciphertext.len(),
                        plaintext.len() + $variant::TAG_SIZE
                    );

                    let decrypted = cipher
                        .decrypt(&nonce, &ciphertext, aad)
                        .expect("Decryption failed");

                    assert_eq!(plaintext, decrypted.as_slice());
                }

                #[test]
                fn [<test_ $variant:lower _empty_plaintext>]() {
                    let cipher = $variant::new();
                    let nonce = $variant::generate_nonce();
                    let plaintext = b"";
                    let aad = b"";

                    let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
                    let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

                    assert_eq!(plaintext, decrypted.as_slice());
                }

                #[test]
                fn [<test_ $variant:lower _wrong_nonce>]() {
                    let cipher = $variant::new();
                    let nonce1 = $variant::generate_nonce();
                    let nonce2 = $variant::generate_nonce();
                    let plaintext = b"Secret message";
                    let aad = b"";

                    let ciphertext = cipher.encrypt(&nonce1, plaintext, aad).unwrap();
                    let crypto_result = cipher.decrypt(&nonce2, &ciphertext, aad);

                    assert!(crypto_result.is_err());
                }

                #[test]
                fn [<test_ $variant:lower _wrong_aad>]() {
                    let cipher = $variant::new();
                    let nonce = $variant::generate_nonce();
                    let plaintext = b"Secret message";
                    let aad1 = b"correct aad";
                    let aad2 = b"wrong aad";

                    let ciphertext = cipher.encrypt(&nonce, plaintext, aad1).unwrap();
                    let crypto_result = cipher.decrypt(&nonce, &ciphertext, aad2);

                    assert!(crypto_result.is_err());
                }

                #[test]
                fn [<test_ $variant:lower _modified_ciphertext>]() {
                    let cipher = $variant::new();
                    let nonce = $variant::generate_nonce();
                    let plaintext = b"Secret message";
                    let aad = b"";

                    let mut ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
                    ciphertext[0] ^= 1;

                    let crypto_result = cipher.decrypt(&nonce, &ciphertext, aad);
                    assert!(crypto_result.is_err());
                }

                #[test]
                fn [<test_ $variant:lower _invalid_nonce_size>]() {
                    let cipher = $variant::new();
                    let invalid_nonce = vec![0u8; 8];
                    let plaintext = b"test";
                    let aad = b"";

                    let crypto_result = cipher.encrypt(&invalid_nonce, plaintext, aad);
                    assert!(crypto_result.is_err());
                }

                #[test]
                fn [<test_ $variant:lower _key_operations>]() {
                    let cipher1 = $variant::new();
                    let key = cipher1.get_key().clone();

                    let mut cipher2 = $variant::new();
                    cipher2.set_key(key);

                    let nonce = $variant::generate_nonce();
                    let plaintext = b"Test message";
                    let aad = b"";

                    let ciphertext = cipher1.encrypt(&nonce, plaintext, aad).unwrap();
                    let decrypted = cipher2.decrypt(&nonce, &ciphertext, aad).unwrap();

                    assert_eq!(plaintext, decrypted.as_slice());
                }

                #[test]
                fn [<test_ $variant:lower _regenerate_key>]() {
                    let mut cipher = $variant::new();
                    let old_key = cipher.get_key().clone();

                    cipher.regenerate_key();
                    let new_key = cipher.get_key().clone();

                    assert!(!old_key.eq(&new_key));
                }

                #[test]
                fn [<test_ $variant:lower _large_plaintext>]() {
                    let cipher = $variant::new();
                    let nonce = $variant::generate_nonce();
                    let plaintext = vec![0x42u8; 10_000];
                    let aad = b"large data";

                    let ciphertext = cipher.encrypt(&nonce, &plaintext, aad).unwrap();
                    let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

                    assert_eq!(plaintext, decrypted);
                }

                #[test]
                fn [<test_ $variant:lower _from_key>]() {
                    let key_bytes = [0x42u8; $variant::KEY_SIZE];
                    let key = CryptoKey::from_bytes(&key_bytes).unwrap();
                    let cipher = $variant::from_key(key);

                    assert_eq!(cipher.get_key().as_bytes(), &key_bytes);

                    let nonce = $variant::generate_nonce();
                    let plaintext = b"test";
                    let aad = b"";

                    let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
                    let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

                    assert_eq!(plaintext, decrypted.as_slice());
                }
            }
        };
    }

    test_aes_gcm_variant!(Aes128Gcm);
    test_aes_gcm_variant!(Aes256Gcm);
}
