use crate::crypto::{CryptoResult, CryptoKey, AsymmetricCipher, CryptoAlgorithm, Kem};
use crate::crypto::key::Key;
use crate::crypto::errors::CryptoError;
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{Ciphertext, PublicKey as PQPublicKey, SecretKey as PQSecretKey, SharedSecret};

macro_rules! impl_kyber {
    ($name:ident, $module:ident, $display_name:expr) => {
        pub struct $name {
            secret_key: Key<{ Self::SECRET_KEY_SIZE }>,
            public_key: Key<{ Self::PUBLIC_KEY_SIZE }>,
        }

        impl CryptoAlgorithm for $name {
            const NAME: &'static str = $display_name;
        }

        impl AsymmetricCipher for $name {
            const PUBLIC_KEY_SIZE: usize = $module::public_key_bytes();
            const SECRET_KEY_SIZE: usize = $module::secret_key_bytes();

            type SecretKey = Key<{ Self::SECRET_KEY_SIZE }>;
            type PublicKey = Key<{ Self::PUBLIC_KEY_SIZE }>;

            fn regenerate_keypair(&mut self) {
                let (pk, sk) = $module::keypair();
                
                self.secret_key = CryptoKey::from_bytes(sk.as_bytes())
                    .expect("keypair generation should always produce valid secret key");
                self.public_key = CryptoKey::from_bytes(pk.as_bytes())
                    .expect("keypair generation should always produce valid public key");
            }

            fn set_secret(&mut self, secret_key: Self::SecretKey) {
                self.secret_key = secret_key;
            }

            fn set_public(&mut self, public_key: Self::PublicKey) {
                self.public_key = public_key;
            }

            fn get_secret(&self) -> &Self::SecretKey {
                &self.secret_key
            }

            fn get_public(&self) -> &Self::PublicKey {
                &self.public_key
            }
        }

        impl Kem for $name {
            const CIPHERTEXT_SIZE: usize = $module::ciphertext_bytes();
            const SHARED_SECRET_SIZE: usize = $module::shared_secret_bytes();

            type SharedSecret = Key<{ Self::SHARED_SECRET_SIZE }>;

            fn encapsulate(public_key: &Self::PublicKey) -> CryptoResult<(Self::SharedSecret, Vec<u8>)> {
                let pk = $module::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|e| CryptoError::InvalidInput(
                        "public key", 
                        format!("failed to parse: {:?}", e)
                    ))?;
                
                let (ss, ct) = $module::encapsulate(&pk);
                
                let shared_secret = Key::from_bytes(ss.as_bytes())?;
                
                Ok((shared_secret, ct.as_bytes().to_vec()))
            }

            fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Self::SharedSecret> {
                if ciphertext.len() != Self::CIPHERTEXT_SIZE {
                    return Err(CryptoError::SizeMismatch {
                        context: "ciphertext",
                        expected: Self::CIPHERTEXT_SIZE,
                        actual: ciphertext.len(),
                    });
                }

                let sk = $module::SecretKey::from_bytes(self.secret_key.as_bytes())
                    .map_err(|e| CryptoError::InvalidInput(
                        "secret key",
                        format!("failed to parse: {:?}", e)
                    ))?;
                
                let ct = $module::Ciphertext::from_bytes(ciphertext)
                    .map_err(|e| CryptoError::InvalidInput(
                        "ciphertext",
                        format!("failed to parse: {:?}", e)
                    ))?;
                
                let ss = $module::decapsulate(&ct, &sk);
                
                Self::SharedSecret::from_bytes(ss.as_bytes())
            }
        }


        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            pub fn new() -> Self {
                let (pk, sk) = $module::keypair();
                
                Self {
                    secret_key: CryptoKey::from_bytes(sk.as_bytes())
                        .expect("Key generation should succeed"),
                    public_key: CryptoKey::from_bytes(pk.as_bytes())
                        .expect("Key generation should succeed"),
                }
            }
        }
    };
}

impl_kyber!(Kyber512, kyber512, "Kyber512");
impl_kyber!(Kyber768, kyber768, "Kyber768");
impl_kyber!(Kyber1024, kyber1024, "Kyber1024");

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_kyber_variant {
        ($variant:ident) => {
            paste::paste! {
                #[test]
                fn [<test_ $variant:lower>]() {
                    let kyber = $variant::new();
                    let public_key = kyber.get_public();
                    let (ss_sender, ciphertext) = $variant::encapsulate(public_key).unwrap();
                    let ss_receiver = kyber.decapsulate(&ciphertext).unwrap();
                    
                    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
                    assert_eq!(ciphertext.len(), $variant::CIPHERTEXT_SIZE);
                }

                #[test]
                fn [<test_ $variant:lower _keypair_transfer>]() {
                    let kyber1 = $variant::new();
                    let secret_key = kyber1.get_secret().clone();
                    let public_key = kyber1.get_public().clone();
                    
                    let mut kyber2 = $variant::new();
                    kyber2.set_secret(secret_key);
                    kyber2.set_public(public_key.clone());
                    
                    let (ss1, ciphertext) = $variant::encapsulate(&public_key).unwrap();
                    let ss2 = kyber2.decapsulate(&ciphertext).unwrap();
                    
                    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
                }

                #[test]
                fn [<test_ $variant:lower _multiple_encapsulations>]() {
                    let kyber = $variant::new();
                    let public_key = kyber.get_public();

                    let (ss1, ct1) = $variant::encapsulate(public_key).unwrap();
                    let (ss2, ct2) = $variant::encapsulate(public_key).unwrap();

                    assert_ne!(ss1.as_bytes(), ss2.as_bytes());
                    assert_ne!(ct1, ct2);

                    let ss1_dec = kyber.decapsulate(&ct1).unwrap();
                    let ss2_dec = kyber.decapsulate(&ct2).unwrap();

                    assert_eq!(ss1.as_bytes(), ss1_dec.as_bytes());
                    assert_eq!(ss2.as_bytes(), ss2_dec.as_bytes());
                }

                #[test]
                fn [<test_ $variant:lower _regenerate_keypair>]() {
                    let mut kyber = $variant::new();
                    let old_public_key = kyber.get_public().clone();
                    
                    kyber.regenerate_keypair();
                    let new_public_key = kyber.get_public();
                    
                    assert_ne!(old_public_key.as_bytes(), new_public_key.as_bytes());
                }

                #[test]
                fn [<test_ $variant:lower _invalid_ciphertext_size>]() {
                    let kyber = $variant::new();
                    let invalid_ct = vec![0u8; $variant::CIPHERTEXT_SIZE - 1];
                    
                    let result = kyber.decapsulate(&invalid_ct);
                    assert!(result.is_err());
                    
                    if let Err(CryptoError::SizeMismatch { context, expected, actual }) = result {
                        assert_eq!(context, "ciphertext");
                        assert_eq!(expected, $variant::CIPHERTEXT_SIZE);
                        assert_eq!(actual, invalid_ct.len());
                    } else {
                        panic!("Expected SizeMismatch error");
                    }
                }
            }
        };
    }

    test_kyber_variant!(Kyber512);
    test_kyber_variant!(Kyber768);
    test_kyber_variant!(Kyber1024);
}
