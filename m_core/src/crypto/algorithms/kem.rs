use crate::crypto::utils::{Result, CryptoError, Key, KeyPair};
use crate::crypto::traits::{AsymmetricCipher, CryptoAlgorithm, Kem};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

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
                
                let mut public_key = [0u8; Self::PUBLIC_KEY_SIZE];
                let mut secret_key = [0u8; Self::SECRET_KEY_SIZE];
                
                public_key.copy_from_slice(pk.as_bytes());
                secret_key.copy_from_slice(sk.as_bytes());
                
                self.keypair = KeyPair::new(secret_key, public_key);
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

            type PublicKey = Key<{ Self::PUBLIC_KEY_SIZE }>;
            type SharedSecret = Key<{ Self::SHARED_SECRET_SIZE }>;

            fn encapsulate(public_key: &Self::PublicKey) -> Result<(Self::SharedSecret, Vec<u8>)> {
                let pk = $module::PublicKey::from_bytes(public_key)
                    .map_err(|e| CryptoError::new(format!("Invalid public key: {:?}", e)))?;
                
                let (ss, ct) = $module::encapsulate(&pk);

                let mut shared_secret = [0u8; Self::SHARED_SECRET_SIZE];
                shared_secret.copy_from_slice(ss.as_bytes());
                
                Ok((shared_secret, ct.as_bytes().to_vec()))
            }

            fn decapsulate(&self, ciphertext: &[u8]) -> Result<Self::SharedSecret> {
                if ciphertext.len() != Self::CIPHERTEXT_SIZE {
                    return Err(CryptoError::new(format!(
                        "Invalid ciphertext size: expected {}, got {}",
                        Self::CIPHERTEXT_SIZE,
                        ciphertext.len()
                    )));
                }

                let secret_key = &self.keypair.secret;
                
                let sk = $module::SecretKey::from_bytes(secret_key)
                    .map_err(|e| CryptoError::new(format!("Invalid secret key: {:?}", e)))?;
                
                let ct = $module::Ciphertext::from_bytes(ciphertext)
                    .map_err(|e| CryptoError::new(format!("Invalid ciphertext: {:?}", e)))?;
                
                let ss = $module::decapsulate(&ct, &sk);

                let mut shared_secret = [0u8; Self::SHARED_SECRET_SIZE];
                shared_secret.copy_from_slice(ss.as_bytes());
                
                Ok(shared_secret)
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
                
                let mut public_key = [0u8; Self::PUBLIC_KEY_SIZE];
                let mut secret_key = [0u8; Self::SECRET_KEY_SIZE];
                
                public_key.copy_from_slice(pk.as_bytes());
                secret_key.copy_from_slice(sk.as_bytes());
                
                Self {
                    keypair: KeyPair::new(secret_key, public_key),
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
                    
                    assert_eq!(ss_sender, ss_receiver);
                    assert_eq!(ciphertext.len(), $variant::CIPHERTEXT_SIZE);
                    assert_eq!(ss_sender.len(), $variant::SHARED_SECRET_SIZE);
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
                    
                    assert_eq!(ss1, ss2);
                }

                #[test]
                fn [<test_ $variant:lower _multiple_encapsulations>]() {
                    let kyber = $variant::new();
                    let public_key = &kyber.get_keypair().public;

                    let (ss1, ct1) = $variant::encapsulate(public_key).unwrap();
                    let (ss2, ct2) = $variant::encapsulate(public_key).unwrap();

                    assert_ne!(ss1, ss2);
                    assert_ne!(ct1, ct2);

                    let ss1_dec = kyber.decapsulate(&ct1).unwrap();
                    let ss2_dec = kyber.decapsulate(&ct2).unwrap();

                    assert_eq!(ss1, ss1_dec);
                    assert_eq!(ss2, ss2_dec);
                }

                #[test]
                fn [<test_ $variant:lower _regenerate_keypair>]() {
                    let mut kyber = $variant::new();
                    let old_public_key = kyber.get_keypair().public;
                    
                    kyber.regenerate_keypair();
                    let new_public_key = kyber.get_keypair().public;
                    
                    assert_ne!(old_public_key, new_public_key);
                }
            }
        };
    }

    test_kyber_variant!(Kyber512);
    test_kyber_variant!(Kyber768);
    test_kyber_variant!(Kyber1024);
}
