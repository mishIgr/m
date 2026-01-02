use serde::{Serialize, Deserialize};
use torut::onion::TorSecretKeyV3;

use m_core::crypto::{CryptoKey, AsymmetricCipher, Hash};
use m_core::crypto::algorithms::hash::Blake3Hash;
use m_core::crypto::algorithms::signature::Dilithium2;

pub struct Identity {
    pub signing: Dilithium2,
    pub tor_sk: TorSecretKeyV3,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ContactCard {
    pub signing_pk: Vec<u8>,
    pub tor_pk: Vec<u8>,
    pub onion_address: String,
}

pub fn contact_id(signing_pk: &[u8], tor_pk: &[u8]) -> String {
    let data = [signing_pk, tor_pk].concat();
    let hash = Blake3Hash::hash(&data, 16).expect("blake3 hash failed");
    hex::encode(&hash[..8])
}

impl Identity {
    pub fn generate() -> Self {
        let signing = Dilithium2::new();
        let tor_sk = TorSecretKeyV3::generate();
        Self { signing, tor_sk }
    }

    pub fn id(&self) -> String {
        let signing_pk = self.signing.get_public().as_bytes();
        let tor_pk = self.tor_sk.public().to_bytes();
        contact_id(signing_pk, &tor_pk)
    }

    pub fn onion_address(&self) -> String {
        self.tor_sk.public().get_onion_address().to_string()
    }

    pub fn tor_pk_bytes(&self) -> [u8; 32] {
        self.tor_sk.public().to_bytes()
    }

    pub fn tor_sk_bytes(&self) -> [u8; 64] {
        self.tor_sk.clone().into()
    }

    pub fn to_contact_card(&self) -> ContactCard {
        ContactCard {
            signing_pk: self.signing.get_public().as_bytes().to_vec(),
            tor_pk: self.tor_pk_bytes().to_vec(),
            onion_address: self.onion_address(),
        }
    }
}

impl ContactCard {
    pub fn id(&self) -> String {
        contact_id(&self.signing_pk, &self.tor_pk)
    }

    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let identity = Identity::generate();
        let id = identity.id();
        assert_eq!(id.len(), 16);
        let onion = identity.onion_address();
        assert!(onion.ends_with(".onion"));
    }

    #[test]
    fn test_contact_card_roundtrip() {
        let identity = Identity::generate();
        let card = identity.to_contact_card();
        let bytes = card.to_bytes().unwrap();
        let restored = ContactCard::from_bytes(&bytes).unwrap();
        assert_eq!(card.signing_pk, restored.signing_pk);
        assert_eq!(card.tor_pk, restored.tor_pk);
        assert_eq!(card.onion_address, restored.onion_address);
    }

    #[test]
    fn test_contact_card_id_matches_identity_id() {
        let identity = Identity::generate();
        let card = identity.to_contact_card();
        assert_eq!(identity.id(), card.id());
    }

    #[test]
    fn test_different_identities_different_ids() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        assert_ne!(id1.id(), id2.id());
    }
}
