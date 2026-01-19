use crate::crypto::utils::{CryptoResult, CryptoError, KeyPair, PublicKey, SecretKey};
use crate::crypto::traits::{AsymmetricCipher, CryptoAlgorithm, Kem};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{Ciphertext, PublicKey as PQPublicKey, SecretKey as PQSecretKey, SharedSecret};

macro_rules! impl_kyber {
    ($name:ident, $module:ident, $display_name:expr) => {
        pub struct $name {
            keypair: KeyPair<{ Self::SECRET_KEY_SIZE }, { Self::PUBLIC_KEY_SIZE }>,
        }

        impl CryptoAlgorithm for $name {
            const NAME: &'static str = $display_name;
        }

        impl AsymmetricCipher for $name {
            const PUBLIC_KEY_SIZE: usize = $module::public_key_bytes();
            const SECRET_KEY_SIZE: usize = $module::secret_key_bytes();

            type KeyPair = KeyPair<{ Self::SECRET_KEY_SIZE }, { Self::PUBLIC_KEY_SIZE }>;

            fn regenerate_keypair(&mut self) {
                let (pk, sk) = $module::keypair();
                
                self.keypair = KeyPair::new(sk.as_bytes(), pk.as_bytes())
                    .expect("keypair generation should always produce valid keys");
            }

            fn set_keypair(&mut self, keypair: Self::KeyPair) {
                self.keypair = keypair;
            }

            fn get_keypair(&self) -> &Self::KeyPair {
                &self.keypair
            }
        }

        impl Kem for $name {
            const CIPHERTEXT_SIZE: usize = $module::ciphertext_bytes();
            const SHARED_SECRET_SIZE: usize = $module::shared_secret_bytes();

            type PublicKey = PublicKey<{ Self::PUBLIC_KEY_SIZE }>;
            type SharedSecret = SecretKey<{ Self::SHARED_SECRET_SIZE }>;

            fn encapsulate(public_key: &Self::PublicKey) -> CryptoResult<(Self::SharedSecret, Vec<u8>)> {
                let pk = $module::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|e| CryptoError::new(format!("Invalid public key: {:?}", e)))?;
                
                let (ss, ct) = $module::encapsulate(&pk);
                
                let shared_secret = Self::SharedSecret::new(ss.as_bytes())
                    .map_err(|e| CryptoError::new(format!("Invalid shared secret: {}", e)))?;
                
                Ok((shared_secret, ct.as_bytes().to_vec()))
            }

            fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Self::SharedSecret> {
                if ciphertext.len() != Self::CIPHERTEXT_SIZE {
                    return Err(CryptoError::new(format!(
                        "Invalid ciphertext size: expected {}, got {}",
                        Self::CIPHERTEXT_SIZE,
                        ciphertext.len()
                    )));
                }

                let sk = $module::SecretKey::from_bytes(self.keypair.secret.as_bytes())
                    .map_err(|e| CryptoError::new(format!("Invalid secret key: {:?}", e)))?;
                
                let ct = $module::Ciphertext::from_bytes(ciphertext)
                    .map_err(|e| CryptoError::new(format!("Invalid ciphertext: {:?}", e)))?;
                
                let ss = $module::decapsulate(&ct, &sk);
                
                Self::SharedSecret::new(ss.as_bytes())
                    .map_err(|e| CryptoError::new(format!("Failed to create shared secret: {}", e)))
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
                    keypair: KeyPair::new(sk.as_bytes(), pk.as_bytes())
                        .expect("Failed to create keypair from generated keys"),
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
                    let public_key = &kyber.get_keypair().public;
                    let (ss_sender, ciphertext) = $variant::encapsulate(public_key).unwrap();
                    let ss_receiver = kyber.decapsulate(&ciphertext).unwrap();
                    
                    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
                    assert_eq!(ciphertext.len(), $variant::CIPHERTEXT_SIZE);
                }

                #[test]
                fn [<test_ $variant:lower _keypair_transfer>]() {
                    let kyber1 = $variant::new();
                    let keypair = kyber1.get_keypair();
                    
                    let mut kyber2 = $variant::new();
                    kyber2.set_keypair(keypair.clone());
                    
                    let public_key = &kyber1.get_keypair().public;
                    let (ss1, ciphertext) = $variant::encapsulate(public_key).unwrap();
                    let ss2 = kyber2.decapsulate(&ciphertext).unwrap();
                    
                    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
                }

                #[test]
                fn [<test_ $variant:lower _multiple_encapsulations>]() {
                    let kyber = $variant::new();
                    let public_key = &kyber.get_keypair().public;

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
                    let old_public_key = kyber.get_keypair().public.clone();
                    
                    kyber.regenerate_keypair();
                    let new_public_key = &kyber.get_keypair().public;
                    
                    assert_ne!(old_public_key.as_bytes(), new_public_key.as_bytes());
                }

                #[test]
                fn [<test_ $variant:lower _zeroize>]() {
                    use std::ptr;
                    
                    let kyber = $variant::new();
                    let secret_ptr = ptr::addr_of!(*kyber.get_keypair().secret.as_bytes()) as usize;
                    
                    drop(kyber);

                    println!("Secret key memory location was at: 0x{:x}", secret_ptr);
                }
            }
        };
    }

    test_kyber_variant!(Kyber512);
    test_kyber_variant!(Kyber768);
    test_kyber_variant!(Kyber1024);
}
