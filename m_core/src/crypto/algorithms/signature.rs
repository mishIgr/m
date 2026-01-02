use crate::crypto::{CryptoResult, CryptoKey, AsymmetricCipher, CryptoAlgorithm, Signature, CryptoError};
use crate::crypto::key::Key;
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey, SignedMessage, DetachedSignature};

macro_rules! impl_dilithium {
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
                    .expect("Failed to create secret key from bytes");
                self.public_key = CryptoKey::from_bytes(pk.as_bytes())
                    .expect("Failed to create public key from bytes");
            }

            fn set_secret(&mut self, key: Self::SecretKey) {
                self.secret_key = key;
            }

            fn set_public(&mut self, key: Self::PublicKey) {
                self.public_key = key;
            }

            fn get_secret(&self) -> &Self::SecretKey {
                &self.secret_key
            }

            fn get_public(&self) -> &Self::PublicKey {
                &self.public_key
            }
        }

        impl Signature for $name {
            const SIGNATURE_SIZE: usize = $module::signature_bytes();

            fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
                let sk = $module::SecretKey::from_bytes(self.secret_key.as_bytes())
                    .map_err(|e| CryptoError::InvalidInput(
                        "secret key",
                        format!("{:?}", e)
                    ))?;

                let signed_msg = $module::sign(message, &sk);
                Ok(signed_msg.as_bytes().to_vec())
            }

            fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
                let pk = $module::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|e| CryptoError::InvalidInput(
                        "public key",
                        format!("{:?}", e)
                    ))?;

                let signed_msg = $module::SignedMessage::from_bytes(signature)
                    .map_err(|e| CryptoError::InvalidInput(
                        "signature",
                        format!("{:?}", e)
                    ))?;

                match $module::open(&signed_msg, &pk) {
                    Ok(opened_msg) => Ok(opened_msg == message),
                    Err(_) => Ok(false),
                }
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
                        .expect("Failed to create secret key from bytes"),
                    public_key: CryptoKey::from_bytes(pk.as_bytes())
                        .expect("Failed to create public key from bytes"),
                }
            }

            pub fn sign_detached(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
                let sk = $module::SecretKey::from_bytes(self.secret_key.as_bytes())
                    .map_err(|e| CryptoError::InvalidInput(
                        "secret key",
                        format!("{:?}", e)
                    ))?;

                let sig = $module::detached_sign(message, &sk);
                Ok(sig.as_bytes().to_vec())
            }

            pub fn verify_detached(
                public_key: &Key<{ Self::PUBLIC_KEY_SIZE }>,
                message: &[u8],
                signature: &[u8],
            ) -> CryptoResult<bool> {
                if signature.len() != Self::SIGNATURE_SIZE {
                    return Err(CryptoError::SizeMismatch {
                        context: "signature",
                        expected: Self::SIGNATURE_SIZE,
                        actual: signature.len(),
                    });
                }

                let pk = $module::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|e| CryptoError::InvalidInput(
                        "public key",
                        format!("{:?}", e)
                    ))?;

                let sig = $module::DetachedSignature::from_bytes(signature)
                    .map_err(|e| CryptoError::InvalidInput(
                        "signature",
                        format!("{:?}", e)
                    ))?;

                match $module::verify_detached_signature(&sig, message, &pk) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }

    };
}

impl_dilithium!(Dilithium2, dilithium2, "Dilithium2");
impl_dilithium!(Dilithium3, dilithium3, "Dilithium3");
impl_dilithium!(Dilithium5, dilithium5, "Dilithium5");

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_dilithium_variant {
        ($variant:ident) => {
            paste::paste! {
                #[test]
                fn [<test_ $variant:lower _sign_verify>]() {
                    let dilithium = $variant::new();
                    let message = b"Hello, Dilithium!";

                    let signature = dilithium.sign(message).expect("Signing failed");

                    let public_key = dilithium.get_public();
                    let original_msg = b"Hello, Dilithium!";
                    
                    let is_valid = $variant::verify(public_key, original_msg, &signature)
                        .expect("Verification failed");

                    assert!(is_valid);
                }

                #[test]
                fn [<test_ $variant:lower _sign_detached>]() {
                    let dilithium = $variant::new();
                    let message = b"Test message for detached signature";

                    let signature = dilithium
                        .sign_detached(message)
                        .expect("Detached signing failed");

                    assert_eq!(signature.len(), $variant::SIGNATURE_SIZE);

                    let public_key = dilithium.get_public();
                    let is_valid = $variant::verify_detached(public_key, message, &signature)
                        .expect("Detached verification failed");

                    assert!(is_valid);
                }

                #[test]
                fn [<test_ $variant:lower _verify_wrong_message>]() {
                    let dilithium = $variant::new();
                    let message = b"Original message";
                    let wrong_message = b"Wrong message";

                    let signature = dilithium.sign_detached(message).unwrap();

                    let public_key = dilithium.get_public();
                    let is_valid = $variant::verify_detached(public_key, wrong_message, &signature)
                        .unwrap();

                    assert!(!is_valid);
                }

                #[test]
                fn [<test_ $variant:lower _verify_modified_signature>]() {
                    let dilithium = $variant::new();
                    let message = b"Test message";

                    let mut signature = dilithium.sign_detached(message).unwrap();
                    signature[0] ^= 1;

                    let public_key = dilithium.get_public();
                    let is_valid = $variant::verify_detached(public_key, message, &signature)
                        .unwrap();

                    assert!(!is_valid);
                }

                #[test]
                fn [<test_ $variant:lower _verify_wrong_public_key>]() {
                    let dilithium1 = $variant::new();
                    let dilithium2 = $variant::new();
                    let message = b"Test message";

                    let signature = dilithium1.sign_detached(message).unwrap();

                    let wrong_public_key = dilithium2.get_public();
                    let is_valid = $variant::verify_detached(wrong_public_key, message, &signature)
                        .unwrap();

                    assert!(!is_valid);
                }

                #[test]
                fn [<test_ $variant:lower _empty_message>]() {
                    let dilithium = $variant::new();
                    let message = b"";

                    let signature = dilithium.sign_detached(message).unwrap();

                    let public_key = dilithium.get_public();
                    let is_valid = $variant::verify_detached(public_key, message, &signature)
                        .unwrap();

                    assert!(is_valid);
                }

                #[test]
                fn [<test_ $variant:lower _large_message>]() {
                    let dilithium = $variant::new();
                    let message = vec![0x42u8; 10_000];

                    let signature = dilithium.sign_detached(&message).unwrap();

                    let public_key = dilithium.get_public();
                    let is_valid = $variant::verify_detached(public_key, &message, &signature)
                        .unwrap();

                    assert!(is_valid);
                }

                #[test]
                fn [<test_ $variant:lower _key_transfer>]() {
                    let dilithium1 = $variant::new();
                    let secret_key = dilithium1.get_secret().clone();
                    let public_key = dilithium1.get_public().clone();

                    let mut dilithium2 = $variant::new();
                    dilithium2.set_secret(secret_key);
                    dilithium2.set_public(public_key);

                    let message = b"Test message";
                    let signature = dilithium1.sign_detached(message).unwrap();

                    let public_key2 = dilithium2.get_public();
                    let is_valid = $variant::verify_detached(public_key2, message, &signature)
                        .unwrap();

                    assert!(is_valid);
                }

                #[test]
                fn [<test_ $variant:lower _regenerate_keypair>]() {
                    let mut dilithium = $variant::new();
                    let old_public_key = dilithium.get_public().clone();

                    dilithium.regenerate_keypair();
                    let new_public_key = dilithium.get_public().clone();

                    assert!(!old_public_key.eq(&new_public_key));
                }

                #[test]
                fn [<test_ $variant:lower _multiple_signatures>]() {
                    let dilithium = $variant::new();
                    let message = b"Test message";

                    let sig1 = dilithium.sign_detached(message).unwrap();
                    let sig2 = dilithium.sign_detached(message).unwrap();

                    assert_eq!(sig1.len(), sig2.len());

                    let public_key = dilithium.get_public();
                    let is_valid1 = $variant::verify_detached(public_key, message, &sig1).unwrap();
                    let is_valid2 = $variant::verify_detached(public_key, message, &sig2).unwrap();

                    assert!(is_valid1);
                    assert!(is_valid2);
                }

                #[test]
                fn [<test_ $variant:lower _invalid_signature_size>]() {
                    let dilithium = $variant::new();
                    let message = b"Test";
                    let invalid_sig = vec![0u8; 100];

                    let public_key = dilithium.get_public();
                    let crypto_result = $variant::verify_detached(public_key, message, &invalid_sig);

                    assert!(crypto_result.is_err());
                }
            }
        };
    }

    test_dilithium_variant!(Dilithium2);
    test_dilithium_variant!(Dilithium3);
    test_dilithium_variant!(Dilithium5);
}
