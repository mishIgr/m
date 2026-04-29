use anyhow::{Context, Result};
use prost::Message;
use tonic::Request;

use m_core::crypto::{CryptoKey, SymmetricEncryption};
use m_core::crypto::algorithms::symmetric::Aes256Gcm;
use m_core::crypto::key::Key;
use m_core::proto::*;
use m_core::proto::messenger_client::MessengerClient;

pub struct Transport {
    client: MessengerClient<tonic::transport::Channel>,
    cipher: Aes256Gcm,
}

fn encrypt_envelope<M: Message>(cipher: &Aes256Gcm, msg: &M) -> Result<Envelope> {
    let plaintext = msg.encode_to_vec();
    let nonce = Aes256Gcm::generate_nonce();
    let ciphertext = cipher.encrypt(&nonce, &plaintext, b"grpc")
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
    let mut data = Vec::with_capacity(nonce.len() + ciphertext.len());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&ciphertext);
    Ok(Envelope { data })
}

fn decrypt_envelope<M: Message + Default>(cipher: &Aes256Gcm, envelope: &Envelope) -> Result<M> {
    let raw = &envelope.data;
    let nonce_size = <Aes256Gcm as SymmetricEncryption>::NONCE_SIZE;
    if raw.len() < nonce_size {
        anyhow::bail!("payload too short");
    }
    let (nonce, ciphertext) = raw.split_at(nonce_size);
    let plaintext = cipher.decrypt(nonce, ciphertext, b"grpc")
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
    M::decode(plaintext.as_slice())
        .context("failed to decode protobuf")
}

pub fn encrypt_payload(text: &str, key_bytes: &[u8], chat_id: &str) -> Result<Vec<u8>> {
    let key: Key<32> = CryptoKey::from_bytes(key_bytes)
        .map_err(|e| anyhow::anyhow!("bad chat key: {e}"))?;
    let cipher = Aes256Gcm::from_key(key);
    let nonce = Aes256Gcm::generate_nonce();
    let ciphertext = cipher.encrypt(&nonce, text.as_bytes(), chat_id.as_bytes())
        .map_err(|e| anyhow::anyhow!("payload encrypt: {e}"))?;
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_payload(encrypted: &[u8], key_bytes: &[u8], chat_id: &str) -> Result<String> {
    let key: Key<32> = CryptoKey::from_bytes(key_bytes)
        .map_err(|e| anyhow::anyhow!("bad chat key: {e}"))?;
    let cipher = Aes256Gcm::from_key(key);
    let nonce_size = <Aes256Gcm as SymmetricEncryption>::NONCE_SIZE;
    if encrypted.len() < nonce_size {
        anyhow::bail!("encrypted payload too short");
    }
    let (nonce, ciphertext) = encrypted.split_at(nonce_size);
    let plaintext = cipher.decrypt(nonce, ciphertext, chat_id.as_bytes())
        .map_err(|e| anyhow::anyhow!("payload decrypt: {e}"))?;
    String::from_utf8(plaintext).context("payload is not valid UTF-8")
}

impl Transport {
    pub async fn connect(address: &str, shared_key_bytes: &[u8]) -> Result<Self> {
        m_core::log_info!("transport: connecting to {}", address);
        let key: Key<32> = CryptoKey::from_bytes(shared_key_bytes)
            .map_err(|e| anyhow::anyhow!("bad shared key: {e}"))?;
        let cipher = Aes256Gcm::from_key(key);
        let client = MessengerClient::connect(address.to_string()).await
            .map_err(|e| {
                m_core::log_error!("transport: failed to connect to {}: {}", address, e);
                anyhow::anyhow!("failed to connect to server: {e}")
            })?;
        m_core::log_info!("transport: connected to {}", address);
        Ok(Self { client, cipher })
    }

    pub fn cipher(&self) -> &Aes256Gcm {
        &self.cipher
    }

    pub async fn create_chat(
        &mut self,
        admin_key: &[u8],
        chat_id: &str,
        max_messages: u32,
        max_bytes: u64,
    ) -> Result<CreateChatResponse> {
        let req = CreateChatRequest {
            admin_key: admin_key.to_vec(),
            chat_id: chat_id.to_string(),
            max_messages,
            max_bytes,
        };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        m_core::log_info!("transport: create_chat rpc chat_id={}", chat_id);
        let resp = self.client.create_chat(Request::new(envelope)).await
            .map_err(|e| {
                m_core::log_error!("transport: create_chat rpc failed: {}", e);
                anyhow::anyhow!("create_chat RPC failed: {e}")
            })?;
        decrypt_envelope(&self.cipher, &resp.into_inner())
    }

    pub async fn delete_chat(
        &mut self,
        admin_key: &[u8],
        chat_id: &str,
    ) -> Result<DeleteChatResponse> {
        let req = DeleteChatRequest {
            admin_key: admin_key.to_vec(),
            chat_id: chat_id.to_string(),
        };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        let resp = self.client.delete_chat(Request::new(envelope)).await
            .context("delete_chat RPC failed")?;
        decrypt_envelope(&self.cipher, &resp.into_inner())
    }

    pub async fn list_chats(&mut self, admin_key: &[u8]) -> Result<ListChatsResponse> {
        let req = ListChatsRequest { admin_key: admin_key.to_vec() };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        let resp = self.client.list_chats(Request::new(envelope)).await
            .context("list_chats RPC failed")?;
        decrypt_envelope(&self.cipher, &resp.into_inner())
    }

    pub async fn send_message(
        &mut self,
        chat_id: &str,
        text: &str,
        chat_key_bytes: &[u8],
    ) -> Result<SendMessageResponse> {
        let encrypted_payload = encrypt_payload(text, chat_key_bytes, chat_id)?;
        let req = SendMessageRequest {
            chat_id: chat_id.to_string(),
            message_id: uuid::Uuid::new_v4().to_string(),
            encrypted_payload,
        };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        let resp = self.client.send_message(Request::new(envelope)).await
            .context("send_message RPC failed")?;
        decrypt_envelope(&self.cipher, &resp.into_inner())
    }

    pub async fn get_history(
        &mut self,
        chat_id: &str,
        from_ts: u64,
        to_ts: u64,
        limit: u32,
    ) -> Result<GetHistoryResponse> {
        let req = GetHistoryRequest {
            chat_id: chat_id.to_string(),
            from_timestamp_ms: from_ts,
            to_timestamp_ms: to_ts,
            limit,
        };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        let resp = self.client.get_history(Request::new(envelope)).await
            .context("get_history RPC failed")?;
        decrypt_envelope(&self.cipher, &resp.into_inner())
    }

    pub async fn open_channel(
        &mut self,
    ) -> Result<(
        tokio::sync::mpsc::Sender<Envelope>,
        tonic::codec::Streaming<Envelope>,
    )> {
        let (tx, rx) = tokio::sync::mpsc::channel::<Envelope>(128);
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let response = self.client.channel(stream).await
            .context("channel RPC failed")?;
        Ok((tx, response.into_inner()))
    }
}

pub fn make_envelope(cipher: &Aes256Gcm, msg: &impl Message) -> Result<Envelope> {
    encrypt_envelope(cipher, msg)
}

pub fn parse_server_event(cipher: &Aes256Gcm, envelope: &Envelope) -> Result<ServerEvent> {
    decrypt_envelope(cipher, envelope)
}
