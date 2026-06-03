use anyhow::Result;
use m_core::crypto::{AsymmetricCipher, CryptoKey};
use m_core::crypto::algorithms::signature::Dilithium2;
use m_core::crypto::key::Key;
use rand::RngExt;

use crate::store::{Store, VerificationStatus};

const RS: char = '\x1e';

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPayload {
    pub sender_id: String,
    pub sender_name: String,
    pub text: String,
    pub client_message_id: String,
    pub message_seq: u128,
    pub signature: Option<Vec<u8>>,
}

pub fn generate_client_message_id() -> String {
    format!("{:032x}", rand::rng().random::<u128>())
}

pub fn sign_material(
    chat_id: u128,
    sender_id: &str,
    text: &str,
    client_message_id: &str,
    message_seq: u128,
) -> String {
    format!(
        "{chat_id:032x}{RS}{sender_id}{RS}{text}{RS}{client_message_id}{RS}{message_seq:032x}"
    )
}

fn is_valid_hex_u128_field(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_hex_u128(s: &str) -> Option<u128> {
    u128::from_str_radix(s, 16).ok()
}

/// Parses `sender_id ‖ sender_name ‖ text ‖ client_message_id ‖ message_seq [‖ hex(sig)]`.
pub fn parse_payload(raw: &str) -> Option<ParsedPayload> {
    let parts: Vec<&str> = raw.split(RS).collect();
    let (sender_id, sender_name, text, client_message_id, message_seq, signature) =
        match parts.as_slice() {
            [a, b, c, id, seq_hex, sig_hex]
                if is_valid_hex_u128_field(id) && is_valid_hex_u128_field(seq_hex) =>
            {
                (a, b, c, *id, parse_hex_u128(seq_hex)?, hex::decode(sig_hex).ok())
            }
            [a, b, c, id, seq_hex]
                if is_valid_hex_u128_field(id) && is_valid_hex_u128_field(seq_hex) =>
            {
                (a, b, c, *id, parse_hex_u128(seq_hex)?, None)
            }
            _ => return None,
        };
    Some(ParsedPayload {
        sender_id: sender_id.to_string(),
        sender_name: sender_name.to_string(),
        text: text.to_string(),
        client_message_id: client_message_id.to_string(),
        message_seq,
        signature,
    })
}

pub fn build_payload(
    my_id: &str,
    my_name: &str,
    text: &str,
    chat_id: u128,
    verification_mode: bool,
    store: &Store,
) -> Result<String> {
    let client_message_id = generate_client_message_id();
    let message_seq = store.allocate_outgoing_seq(chat_id)?;
    let base = format!(
        "{my_id}{RS}{my_name}{RS}{text}{RS}{client_message_id}{RS}{message_seq:032x}",
    );

    if !verification_mode {
        return Ok(base);
    }

    let Ok(Some(identity)) = store.load_identity() else {
        return Ok(base);
    };
    let (Ok(sk), Ok(pk)) = (
        CryptoKey::from_bytes(&identity.signing_sk_bytes),
        CryptoKey::from_bytes(&identity.signing_pk_bytes),
    ) else {
        return Ok(base);
    };

    let mut signer = Dilithium2::new();
    signer.set_secret(sk);
    signer.set_public(pk);

    let material = sign_material(chat_id, my_id, text, &client_message_id, message_seq);
    match signer.sign_detached(material.as_bytes()) {
        Ok(sig) => Ok(format!("{base}{RS}{}", hex::encode(&sig))),
        Err(_) => Ok(base),
    }
}

pub fn verify_message_sig(
    store: &Store,
    sender_id: &str,
    chat_id: u128,
    text: &str,
    client_message_id: &str,
    message_seq: u128,
    sig: &[u8],
) -> VerificationStatus {
    let material = sign_material(chat_id, sender_id, text, client_message_id, message_seq);

    match store.load_contact(sender_id) {
        Ok(contact) => {
            let pk: Key<{ Dilithium2::PUBLIC_KEY_SIZE }> =
                match CryptoKey::from_bytes(&contact.signing_pk_bytes) {
                    Ok(k) => k,
                    Err(_) => return VerificationStatus::CannotVerify,
                };
            match Dilithium2::verify_detached(&pk, material.as_bytes(), sig) {
                Ok(true) => VerificationStatus::Verified,
                _ => VerificationStatus::Tampered,
            }
        }
        Err(_) => VerificationStatus::CannotVerify,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_five_fields() {
        let id = "a".repeat(32);
        let seq = "b".repeat(32);
        let raw = format!("alice\x1ebob\x1ehello\x1e{id}\x1e{seq}");
        let p = parse_payload(&raw).unwrap();
        assert_eq!(p.sender_id, "alice");
        assert_eq!(p.client_message_id, id);
        assert_eq!(p.message_seq, u128::from_str_radix(&"b".repeat(32), 16).unwrap());
        assert!(p.signature.is_none());
    }

    #[test]
    fn parse_signed_six_fields() {
        let id = "f".repeat(32);
        let seq = "1".repeat(32);
        let sig_hex = "cd".repeat(100);
        let raw = format!("alice\x1ebob\x1ehello\x1e{id}\x1e{seq}\x1e{sig_hex}");
        let p = parse_payload(&raw).unwrap();
        assert_eq!(p.client_message_id, id);
        assert!(p.signature.is_some());
    }

    #[test]
    fn parse_rejects_legacy_four_fields() {
        let id = "a".repeat(32);
        assert!(parse_payload(&format!("alice\x1ebob\x1ehello\x1e{id}")).is_none());
    }

    #[test]
    fn parse_rejects_legacy_three_fields() {
        assert!(parse_payload("alice\x1ebob\x1ehello").is_none());
    }
}
