/// Manual (file-based) share exchange — no transport involved.
///
/// Flow:
///   B calls `generate_kem_offer` → saves ephemeral KEM sk to DB keyed by A's contact_id → returns bytes for B's init file
///   A calls `create_share_response` with B's init file bytes + data → returns bytes for A's response file
///   B calls `load_share_response` with A's response file bytes → decrypts and returns ShareData
use anyhow::Result;

use m_core::crypto::{CryptoKey, AsymmetricCipher, Hash, Kem, Signature, SymmetricEncryption};
use m_core::crypto::algorithms::hash::Blake3Hash;
use m_core::crypto::algorithms::kem::Kyber512;
use m_core::crypto::algorithms::signature::Dilithium2;
use m_core::crypto::algorithms::symmetric::Aes256Gcm;
use m_core::crypto::key::Key;

use crate::sharing::{KemOffer, SharePacket, ShareData, encode_frame, decode_frame};
use crate::store::{Store, IdentityRecord, ContactRecord};

fn derive_aes_key(shared_secret: &[u8]) -> Result<Aes256Gcm> {
    let key_bytes = Blake3Hash::hash(shared_secret, 32)
        .map_err(|e| anyhow::anyhow!("key derivation: {e}"))?;
    let key: Key<32> = CryptoKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("bad derived key: {e}"))?;
    Ok(Aes256Gcm::from_key(key))
}

fn build_signer(identity: &IdentityRecord) -> Result<Dilithium2> {
    let sk = CryptoKey::from_bytes(&identity.signing_sk_bytes)
        .map_err(|e| anyhow::anyhow!("bad signing sk: {e}"))?;
    let pk = CryptoKey::from_bytes(&identity.signing_pk_bytes)
        .map_err(|e| anyhow::anyhow!("bad signing pk: {e}"))?;
    let mut signer = Dilithium2::new();
    signer.set_secret(sk);
    signer.set_public(pk);
    Ok(signer)
}

fn build_verifier(contact: &ContactRecord) -> Result<Key<{ Dilithium2::PUBLIC_KEY_SIZE }>> {
    CryptoKey::from_bytes(&contact.signing_pk_bytes)
        .map_err(|e| anyhow::anyhow!("bad contact signing pk: {e}"))
}

fn concat_for_sign(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|s| s.iter().copied()).collect()
}

/// B: Generate an init file to send to A.
///
/// Saves the ephemeral KEM secret key to the store keyed by `target_contact.id`
/// so it can be retrieved when B later calls `load_share_response`.
///
/// Returns the raw bytes to write to the init file.
pub fn generate_kem_offer(
    identity: &IdentityRecord,
    target_contact: &ContactRecord,
    store: &Store,
) -> Result<Vec<u8>> {
    let kyber = Kyber512::new();
    let kem_pk_bytes = kyber.get_public().as_bytes().to_vec();
    let kem_sk_bytes = kyber.get_secret().as_bytes().to_vec();

    let signer = build_signer(identity)?;
    let signature = signer.sign(&kem_pk_bytes)
        .map_err(|e| anyhow::anyhow!("sign offer: {e}"))?;

    store.save_pending_kem_offer(&target_contact.id, &kem_sk_bytes)?;

    let offer = KemOffer {
        user_id: identity.id.clone(),
        kem_pk: kem_pk_bytes,
        signature,
    };
    encode_frame(&offer)
}

/// A: Process B's init file, produce response bytes, and save share data locally.
///
/// Returns the raw bytes for A's response file (to deliver to B).
pub fn create_share_response(
    offer_bytes: &[u8],
    data: ShareData,
    identity: &IdentityRecord,
    contact: &ContactRecord,
    store: &Store,
) -> Result<Vec<u8>> {
    let kem_offer: KemOffer = decode_frame(offer_bytes)?;

    let contact_pk = build_verifier(contact)?;
    let valid = Dilithium2::verify(&contact_pk, &kem_offer.kem_pk, &kem_offer.signature)
        .map_err(|e| anyhow::anyhow!("verify offer: {e}"))?;
    if !valid {
        anyhow::bail!("invalid KemOffer signature from {}", kem_offer.user_id);
    }

    let kem_pk: Key<{ Kyber512::PUBLIC_KEY_SIZE }> = CryptoKey::from_bytes(&kem_offer.kem_pk)
        .map_err(|e| anyhow::anyhow!("bad KEM pk: {e}"))?;
    let (shared_secret, kem_ct) = Kyber512::encapsulate(&kem_pk)
        .map_err(|e| anyhow::anyhow!("encapsulate: {e}"))?;

    let plaintext = data.to_bytes()?;
    let cipher = derive_aes_key(shared_secret.as_bytes())?;
    let nonce = Aes256Gcm::generate_nonce();
    let ciphertext = cipher.encrypt(&nonce, &plaintext, b"share")
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;

    let signer = build_signer(identity)?;
    let packet_sign_msg = concat_for_sign(&[&kem_ct, &ciphertext, &nonce]);
    let signature = signer.sign(&packet_sign_msg)
        .map_err(|e| anyhow::anyhow!("sign packet: {e}"))?;

    // Save data locally
    store.merge_share_data(&data)?;

    let packet = SharePacket {
        user_id: identity.id.clone(),
        kem_ct,
        ciphertext,
        nonce,
        signature,
    };
    encode_frame(&packet)
}

/// B: Load A's response file and return the decrypted ShareData.
///
/// The ephemeral KEM secret key is retrieved from the store (saved during `generate_kem_offer`)
/// keyed by A's contact_id, and deleted after use.
pub fn load_share_response(
    response_bytes: &[u8],
    identity: &IdentityRecord,
    contact: &ContactRecord,
    store: &Store,
) -> Result<ShareData> {
    let _ = identity; // identity not needed for decapsulation, but kept for API symmetry
    let packet: SharePacket = decode_frame(response_bytes)?;

    let contact_pk = build_verifier(contact)?;
    let packet_sign_msg = concat_for_sign(&[&packet.kem_ct, &packet.ciphertext, &packet.nonce]);
    let valid = Dilithium2::verify(&contact_pk, &packet_sign_msg, &packet.signature)
        .map_err(|e| anyhow::anyhow!("verify packet: {e}"))?;
    if !valid {
        anyhow::bail!("invalid SharePacket signature from {}", packet.user_id);
    }

    let kem_sk_bytes = store.take_pending_kem_offer(&contact.id)?;
    let kem_sk: Key<{ Kyber512::SECRET_KEY_SIZE }> = CryptoKey::from_bytes(&kem_sk_bytes)
        .map_err(|e| anyhow::anyhow!("bad KEM sk: {e}"))?;

    let mut kyber = Kyber512::new();
    kyber.set_secret(kem_sk);

    let shared_secret = kyber.decapsulate(&packet.kem_ct)
        .map_err(|e| anyhow::anyhow!("decapsulate: {e}"))?;

    let cipher = derive_aes_key(shared_secret.as_bytes())?;
    let plaintext = cipher.decrypt(&packet.nonce, &packet.ciphertext, b"share")
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;

    ShareData::from_bytes(&plaintext)
}
