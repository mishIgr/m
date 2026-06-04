use serde::{Serialize, Deserialize};

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Step 1 (Tor only): A → B — proves A's intent to share
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InviteMsg {
    pub user_id: String,
    pub random_bytes: Vec<u8>, // 32 random bytes
    pub signature: Vec<u8>,    // sign(random_bytes)
}

/// Step 2 (Tor) / init file (manual): B → A — B's ephemeral KEM public key
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KemOffer {
    pub user_id: String,
    pub kem_pk: Vec<u8>,    // ephemeral Kyber512 public key
    pub signature: Vec<u8>, // sign(kem_pk)
}

/// Step 3 (Tor) / response file (manual): A → B — encrypted share data
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SharePacket {
    pub user_id: String,
    pub kem_ct: Vec<u8>,     // Kyber512 ciphertext from encapsulate(B.kem_pk)
    pub ciphertext: Vec<u8>, // AES-256-GCM(ShareData)
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,  // sign(kem_ct || ciphertext || nonce)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ShareData {
    Server(ServerShareData),
    Chat(ChatShareData), // always includes full server data
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerShareData {
    pub id: u128,
    pub name: String,
    pub host: String,
    pub shared_key: Vec<u8>,
    pub admin_key: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatShareData {
    pub id: u128,
    pub name: String,
    pub server: ServerShareData, // full server data always included
    pub encryption_key: Vec<u8>,
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
///
/// Used on the streaming path, where `read_frame` has already consumed and
/// stripped the 4-byte length header. For a whole buffer that still carries the
/// header (e.g. a file written by `encode_frame`), use `decode_framed` instead.
pub fn decode_frame<T: for<'de> Deserialize<'de>>(data: &[u8]) -> anyhow::Result<T> {
    Ok(bincode::deserialize(data)?)
}

/// Deserialize a complete frame produced by `encode_frame`: validate and strip
/// the 4-byte big-endian length header, then bincode-decode the body.
///
/// Use this when you hold the entire frame in memory (e.g. file contents),
/// rather than reading it off a stream via `read_frame`.
pub fn decode_framed<T: for<'de> Deserialize<'de>>(data: &[u8]) -> anyhow::Result<T> {
    if data.len() < 4 {
        anyhow::bail!("frame too short: {} bytes", data.len());
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let body = &data[4..];
    if body.len() != len {
        anyhow::bail!("frame length mismatch: header says {len}, got {}", body.len());
    }
    decode_frame(body)
}
