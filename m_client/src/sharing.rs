use serde::{Serialize, Deserialize};

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InviteMsg {
    pub contact_id: String,
    pub kem_pk: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InviteAck {
    pub contact_id: String,
    pub kem_ct: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SharePayload {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ShareData {
    Server(ServerShareData),
    Chat(ChatShareData),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerShareData {
    pub id: String,
    pub host: String,
    pub shared_key: Vec<u8>,
    pub admin_key: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatShareData {
    pub server_id: String,
    pub chat_id: String,
    pub name: String,
    pub encryption_key: Vec<u8>,
    pub server_admin_key: Option<Vec<u8>>,
}

impl ShareData {
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(data)?)
    }
}

/// Serialize `msg` via bincode and prepend a 4-byte big-endian length header.
pub fn encode_frame<T: Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
    let body = bincode::serialize(msg)?;
    if body.len() > MAX_FRAME_SIZE {
        anyhow::bail!("frame too large: {} bytes", body.len());
    }
    let len = body.len() as u32;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Deserialize a bincode body (without the length prefix).
pub fn decode_frame<T: for<'de> Deserialize<'de>>(data: &[u8]) -> anyhow::Result<T> {
    Ok(bincode::deserialize(data)?)
}
