use anyhow::Result;
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
        .map_err(|e| {
            m_core::log_warn!("transport: encrypt_envelope failed: {}", e);
            anyhow::anyhow!("encrypt: {e}")
        })?;
    let mut data = Vec::with_capacity(nonce.len() + ciphertext.len());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&ciphertext);
    Ok(Envelope { data })
}

fn decrypt_envelope<M: Message + Default>(cipher: &Aes256Gcm, envelope: &Envelope) -> Result<M> {
    let raw = &envelope.data;
    let nonce_size = <Aes256Gcm as SymmetricEncryption>::NONCE_SIZE;
    if raw.len() < nonce_size {
        m_core::log_warn!("transport: decrypt_envelope payload too short: got {} bytes, need {}", raw.len(), nonce_size);
        anyhow::bail!("payload too short");
    }
    let (nonce, ciphertext) = raw.split_at(nonce_size);
    let plaintext = cipher.decrypt(nonce, ciphertext, b"grpc")
        .map_err(|e| {
            m_core::log_warn!("transport: decrypt_envelope AES decrypt failed: {}", e);
            anyhow::anyhow!("decrypt: {e}")
        })?;
    M::decode(plaintext.as_slice())
        .map_err(|e| {
            m_core::log_warn!("transport: decrypt_envelope protobuf decode failed: {}", e);
            anyhow::anyhow!("failed to decode protobuf: {e}")
        })
}

/// Encode u128 chat_id as 16-byte big-endian for proto bytes field.
pub fn chat_id_bytes(id: u128) -> Vec<u8> {
    id.to_be_bytes().to_vec()
}

/// Decode proto bytes field to u128 chat_id.
pub fn chat_id_from_bytes(b: &[u8]) -> Result<u128> {
    let arr: [u8; 16] = b.try_into()
        .map_err(|_| anyhow::anyhow!("chat_id must be 16 bytes, got {}", b.len()))?;
    Ok(u128::from_be_bytes(arr))
}

pub fn encrypt_payload(text: &str, key_bytes: &[u8], chat_id: u128) -> Result<Vec<u8>> {
    let key: Key<32> = CryptoKey::from_bytes(key_bytes)
        .map_err(|e| {
            m_core::log_warn!("transport: encrypt_payload bad chat key chat={:032x}: {}", chat_id, e);
            anyhow::anyhow!("bad chat key: {e}")
        })?;
    let cipher = Aes256Gcm::from_key(key);
    let nonce = Aes256Gcm::generate_nonce();
    let aad = chat_id.to_be_bytes();
    let ciphertext = cipher.encrypt(&nonce, text.as_bytes(), &aad)
        .map_err(|e| {
            m_core::log_warn!("transport: encrypt_payload AES failed chat={:032x}: {}", chat_id, e);
            anyhow::anyhow!("payload encrypt: {e}")
        })?;
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_payload(encrypted: &[u8], key_bytes: &[u8], chat_id: u128) -> Result<String> {
    let key: Key<32> = CryptoKey::from_bytes(key_bytes)
        .map_err(|e| {
            m_core::log_warn!("transport: decrypt_payload bad chat key chat={:032x}: {}", chat_id, e);
            anyhow::anyhow!("bad chat key: {e}")
        })?;
    let cipher = Aes256Gcm::from_key(key);
    let nonce_size = <Aes256Gcm as SymmetricEncryption>::NONCE_SIZE;
    if encrypted.len() < nonce_size {
        m_core::log_warn!("transport: decrypt_payload payload too short chat={:032x}: got {} need {}", chat_id, encrypted.len(), nonce_size);
        anyhow::bail!("encrypted payload too short");
    }
    let (nonce, ciphertext) = encrypted.split_at(nonce_size);
    let aad = chat_id.to_be_bytes();
    let plaintext = cipher.decrypt(nonce, ciphertext, &aad)
        .map_err(|e| {
            m_core::log_warn!("transport: decrypt_payload AES failed chat={:032x}: {}", chat_id, e);
            anyhow::anyhow!("payload decrypt: {e}")
        })?;
    String::from_utf8(plaintext).map_err(|e| {
        m_core::log_warn!("transport: decrypt_payload UTF-8 failed chat={:032x}: {}", chat_id, e);
        anyhow::anyhow!("payload is not valid UTF-8: {e}")
    })
}

impl Transport {
    pub async fn connect(address: &str, shared_key_bytes: &[u8]) -> Result<Self> {
        m_core::log_info!("transport: connecting to {}", address);
        let key: Key<32> = CryptoKey::from_bytes(shared_key_bytes)
            .map_err(|e| anyhow::anyhow!("bad shared key: {e}"))?;
        let cipher = Aes256Gcm::from_key(key);
        let uri = if address.contains("://") {
            address.to_string()
        } else {
            format!("http://{}", address)
        };
        let client = MessengerClient::connect(uri).await
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

    /// Create a chat on the server and return the server-generated u128 chat ID.
    pub async fn create_chat(
        &mut self,
        admin_key: &[u8],
        name: &str,
        max_messages: u32,
        max_bytes: u64,
    ) -> Result<u128> {
        let req = CreateChatRequest {
            admin_key: admin_key.to_vec(),
            name: name.to_string(),
            max_messages,
            max_bytes,
        };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        m_core::log_info!("transport: create_chat rpc name={}", name);
        let resp = self.client.create_chat(Request::new(envelope)).await
            .map_err(|e| {
                m_core::log_error!("transport: create_chat rpc failed: {}", e);
                anyhow::anyhow!("create_chat RPC failed: {e}")
            })?;
        let response: CreateChatResponse = decrypt_envelope(&self.cipher, &resp.into_inner())?;
        if !response.success {
            anyhow::bail!("create_chat rejected: {}", response.error);
        }
        chat_id_from_bytes(&response.chat_id)
    }

    pub async fn delete_chat(
        &mut self,
        admin_key: &[u8],
        chat_id: u128,
    ) -> Result<DeleteChatResponse> {
        let req = DeleteChatRequest {
            admin_key: admin_key.to_vec(),
            chat_id: chat_id_bytes(chat_id),
        };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        m_core::log_info!("transport: delete_chat rpc chat_id={:032x}", chat_id);
        let resp = self.client.delete_chat(Request::new(envelope)).await
            .map_err(|e| {
                m_core::log_error!("transport: delete_chat rpc failed: {}", e);
                anyhow::anyhow!("delete_chat RPC failed: {e}")
            })?;
        decrypt_envelope(&self.cipher, &resp.into_inner())
    }

    pub async fn list_chats(&mut self, admin_key: &[u8]) -> Result<ListChatsResponse> {
        let req = ListChatsRequest { admin_key: admin_key.to_vec() };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        m_core::log_info!("transport: list_chats rpc");
        let resp = self.client.list_chats(Request::new(envelope)).await
            .map_err(|e| {
                m_core::log_error!("transport: list_chats rpc failed: {}", e);
                anyhow::anyhow!("list_chats RPC failed: {e}")
            })?;
        let result: ListChatsResponse = decrypt_envelope(&self.cipher, &resp.into_inner())?;
        m_core::log_debug!("transport: list_chats returned {} chats", result.chats.len());
        Ok(result)
    }

    pub async fn send_message(
        &mut self,
        chat_id: u128,
        text: &str,
        chat_key_bytes: &[u8],
    ) -> Result<SendMessageResponse> {
        let encrypted_payload = encrypt_payload(text, chat_key_bytes, chat_id)?;
        let req = SendMessageRequest {
            chat_id: chat_id_bytes(chat_id),
            encrypted_payload,
        };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        m_core::log_info!("transport: send_message rpc chat_id={:032x}", chat_id);
        let resp = self.client.send_message(Request::new(envelope)).await
            .map_err(|e| {
                m_core::log_error!("transport: send_message rpc failed chat_id={:032x}: {}", chat_id, e);
                anyhow::anyhow!("send_message RPC failed: {e}")
            })?;
        let result: SendMessageResponse = decrypt_envelope(&self.cipher, &resp.into_inner())?;
        if !result.accepted {
            m_core::log_warn!("transport: send_message rejected chat_id={:032x} reason={}", chat_id, result.error);
        } else {
            m_core::log_debug!("transport: send_message accepted chat_id={:032x} message_id={}", chat_id, result.message_id);
        }
        Ok(result)
    }

    pub async fn get_history(
        &mut self,
        chat_id: u128,
        from_ts: u64,
        to_ts: u64,
        limit: u32,
    ) -> Result<GetHistoryResponse> {
        let req = GetHistoryRequest {
            chat_id: chat_id_bytes(chat_id),
            from_timestamp_ms: from_ts,
            to_timestamp_ms: to_ts,
            limit,
        };
        let envelope = encrypt_envelope(&self.cipher, &req)?;
        m_core::log_info!("transport: get_history rpc chat_id={:032x} from={} to={} limit={}", chat_id, from_ts, to_ts, limit);
        let resp = self.client.get_history(Request::new(envelope)).await
            .map_err(|e| {
                m_core::log_error!("transport: get_history rpc failed chat_id={:032x}: {}", chat_id, e);
                anyhow::anyhow!("get_history RPC failed: {e}")
            })?;
        let result: GetHistoryResponse = decrypt_envelope(&self.cipher, &resp.into_inner())?;
        m_core::log_debug!("transport: get_history returned {} messages chat_id={:032x}", result.messages.len(), chat_id);
        Ok(result)
    }

    pub async fn open_channel(
        &mut self,
    ) -> Result<(
        tokio::sync::mpsc::Sender<Envelope>,
        tonic::codec::Streaming<Envelope>,
    )> {
        m_core::log_info!("transport: open_channel rpc");
        let (tx, rx) = tokio::sync::mpsc::channel::<Envelope>(128);
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let response = self.client.channel(stream).await
            .map_err(|e| {
                m_core::log_error!("transport: open_channel rpc failed: {}", e);
                anyhow::anyhow!("channel RPC failed: {e}")
            })?;
        m_core::log_debug!("transport: open_channel established");
        Ok((tx, response.into_inner()))
    }
}

pub fn make_envelope(cipher: &Aes256Gcm, msg: &impl Message) -> Result<Envelope> {
    encrypt_envelope(cipher, msg)
}

pub fn parse_server_event(cipher: &Aes256Gcm, envelope: &Envelope) -> Result<ServerEvent> {
    decrypt_envelope(cipher, envelope)
}
