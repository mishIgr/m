use std::fmt;
use std::path::Path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use m_core::db::{RedbStore, KvStore, Table};

use crate::identity::ContactCard;
use crate::sharing::{ServerShareData, ChatShareData};
use crate::config::{ServerCard, ChatCard};

const SERVER_TABLE: &str = "servers";
const CHATS_TABLE: &str = "chats";
const MESSAGES_TABLE_PREFIX: &str = "messages:";
const IDENTITY_TABLE: &str = "identity";
const CONTACTS_TABLE: &str = "contacts";
const PENDING_KEM_TABLE: &str = "pending_kem_offers";

fn id_key(id: u128) -> String {
    format!("{:032x}", id)
}

fn chat_key(server_id: u128, chat_id: u128) -> String {
    format!("{:032x}:{:032x}", server_id, chat_id)
}

fn msg_table_name(chat_id: u128) -> String {
    format!("{}{:032x}", MESSAGES_TABLE_PREFIX, chat_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeState {
    Enabled,
    Disabled,
    Unavailable,
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeState::Enabled => write!(f, "enabled"),
            NodeState::Disabled => write!(f, "disabled"),
            NodeState::Unavailable => write!(f, "unavailable"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub enum VerificationStatus {
    #[default]
    NoSignature,
    Verified,
    CannotVerify,
    Tampered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRecord {
    pub id: u128,
    pub name: String,
    pub address: String,
    pub shared_key_bytes: Vec<u8>,
    pub admin_key_bytes: Option<Vec<u8>>,
    pub state: NodeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRecord {
    pub server_id: u128,
    pub chat_id: u128,
    pub name: String,
    pub encryption_key_bytes: Vec<u8>,
    pub last_synced_ts: i64,
    pub state: NodeState,
    #[serde(default)]
    pub verification_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub chat_id: u128,
    pub message_id: String,
    pub timestamp_ms: i64,
    pub text: String,
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub verification: VerificationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub id: String,
    pub signing_sk_bytes: Vec<u8>,
    pub signing_pk_bytes: Vec<u8>,
    pub tor_sk_bytes: Vec<u8>,
    pub tor_pk_bytes: Vec<u8>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactRecord {
    pub id: String,
    pub name: String,
    pub signing_pk_bytes: Vec<u8>,
    pub tor_pk_bytes: Vec<u8>,
    pub onion_address: String,
}

#[derive(Clone)]
pub struct Store {
    db: RedbStore,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = RedbStore::open(path)
            .with_context(|| format!("Failed to open DB: {}", path.display()))?;
        Ok(Self { db })
    }

    // ── Server ────────────────────────────────────────────────────────────────

    pub fn save_server_card(&self, card: &ServerCard) -> Result<()> {
        let record = ServerRecord {
            id: card.id,
            name: card.name.clone(),
            address: card.address.clone(),
            shared_key_bytes: card.shared_key.clone(),
            admin_key_bytes: card.admin_key.clone(),
            state: NodeState::Disabled,
        };
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        table.put(&id_key(card.id), &record)?;
        Ok(())
    }

    pub fn export_server_card(&self, id: u128) -> Result<ServerCard> {
        let r = self.load_server(id)?;
        Ok(ServerCard {
            id: r.id,
            name: r.name,
            address: r.address,
            shared_key: r.shared_key_bytes,
            admin_key: r.admin_key_bytes,
        })
    }

    pub fn load_server(&self, id: u128) -> Result<ServerRecord> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        table.get(&id_key(id))?
            .ok_or_else(|| anyhow::anyhow!("Server '{:032x}' not found", id))
    }

    pub fn list_servers(&self) -> Result<Vec<ServerRecord>> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        Ok(table.iter()?.into_iter().map(|(_, v)| v).collect())
    }

    pub fn list_enabled_servers(&self) -> Result<Vec<ServerRecord>> {
        Ok(self.list_servers()?.into_iter()
            .filter(|s| s.state == NodeState::Enabled)
            .collect())
    }

    pub fn set_server_state(&self, id: u128, state: NodeState) -> Result<()> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        let mut record = self.load_server(id)?;
        record.state = state;
        table.put(&id_key(id), &record)?;
        Ok(())
    }

    pub fn rename_server(&self, id: u128, name: &str) -> Result<()> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        let mut record = self.load_server(id)?;
        record.name = name.to_string();
        table.put(&id_key(id), &record)?;
        Ok(())
    }

    pub fn delete_server(&self, id: u128) -> Result<()> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        table.delete(&id_key(id))?;
        Ok(())
    }

    // ── Chat ──────────────────────────────────────────────────────────────────

    pub fn save_chat_card(&self, card: &ChatCard) -> Result<()> {
        let key = chat_key(card.server_id, card.chat_id);
        let record = ChatRecord {
            server_id: card.server_id,
            chat_id: card.chat_id,
            name: card.name.clone(),
            encryption_key_bytes: card.encryption_key.clone(),
            last_synced_ts: 0,
            state: NodeState::Disabled,
            verification_mode: false,
        };
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        table.put(&key, &record)?;
        Ok(())
    }

    pub fn export_chat_card(&self, server_id: u128, chat_id: u128) -> Result<ChatCard> {
        let r = self.load_chat(server_id, chat_id)?;
        Ok(ChatCard {
            server_id: r.server_id,
            chat_id: r.chat_id,
            name: r.name,
            encryption_key: r.encryption_key_bytes,
        })
    }

    pub fn load_chat(&self, server_id: u128, chat_id: u128) -> Result<ChatRecord> {
        let key = chat_key(server_id, chat_id);
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        table.get(&key)?
            .ok_or_else(|| anyhow::anyhow!(
                "Chat '{:032x}' not found on server '{:032x}'", chat_id, server_id
            ))
    }

    pub fn list_chats_for_server(&self, server_id: u128) -> Result<Vec<ChatRecord>> {
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        Ok(table.iter()?.into_iter()
            .filter(|(_, c)| c.server_id == server_id)
            .map(|(_, v)| v)
            .collect())
    }

    pub fn list_enabled_chats_for_server(&self, server_id: u128) -> Result<Vec<ChatRecord>> {
        Ok(self.list_chats_for_server(server_id)?.into_iter()
            .filter(|c| c.state == NodeState::Enabled)
            .collect())
    }

    pub fn set_chat_state(&self, server_id: u128, chat_id: u128, state: NodeState) -> Result<()> {
        let key = chat_key(server_id, chat_id);
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        let mut record = self.load_chat(server_id, chat_id)?;
        record.state = state;
        table.put(&key, &record)?;
        Ok(())
    }

    pub fn rename_chat(&self, server_id: u128, chat_id: u128, name: &str) -> Result<()> {
        let key = chat_key(server_id, chat_id);
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        let mut record = self.load_chat(server_id, chat_id)?;
        record.name = name.to_string();
        table.put(&key, &record)?;
        Ok(())
    }

    pub fn delete_chat(&self, server_id: u128, chat_id: u128) -> Result<()> {
        let key = chat_key(server_id, chat_id);
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        table.delete(&key)?;
        Ok(())
    }

    pub fn update_chat_sync_ts(&self, server_id: u128, chat_id: u128, ts: i64) -> Result<()> {
        let key = chat_key(server_id, chat_id);
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        let mut record = self.load_chat(server_id, chat_id)?;
        record.last_synced_ts = ts;
        table.put(&key, &record)?;
        Ok(())
    }

    pub fn set_chat_verification_mode(&self, server_id: u128, chat_id: u128, enabled: bool) -> Result<()> {
        let key = chat_key(server_id, chat_id);
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        let mut record = self.load_chat(server_id, chat_id)?;
        record.verification_mode = enabled;
        table.put(&key, &record)?;
        Ok(())
    }

    // ── Messages ──────────────────────────────────────────────────────────────

    pub fn save_message(&self, msg: &StoredMessage) -> Result<()> {
        let table_name = msg_table_name(msg.chat_id);
        let table = self.db.table::<i64, StoredMessage>(&table_name)?;
        table.put(&msg.timestamp_ms, msg)?;
        Ok(())
    }

    pub fn get_messages(&self, chat_id: u128, limit: usize) -> Result<Vec<StoredMessage>> {
        let table_name = msg_table_name(chat_id);
        let table = self.db.table::<i64, StoredMessage>(&table_name)?;
        let all: Vec<StoredMessage> = table.iter()?.into_iter().map(|(_, v)| v).collect();
        let start = all.len().saturating_sub(limit);
        Ok(all[start..].to_vec())
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    pub fn set_identity_name(&self, name: &str) -> Result<()> {
        let table = self.db.table::<String, IdentityRecord>(IDENTITY_TABLE)?;
        let mut record = table.get(&"self".to_string())?
            .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;
        record.name = Some(name.to_string());
        table.put(&"self".to_string(), &record)?;
        Ok(())
    }

    pub fn save_identity(&self, record: &IdentityRecord) -> Result<()> {
        let table = self.db.table::<String, IdentityRecord>(IDENTITY_TABLE)?;
        table.put(&"self".to_string(), record)?;
        Ok(())
    }

    pub fn load_identity(&self) -> Result<Option<IdentityRecord>> {
        let table = self.db.table::<String, IdentityRecord>(IDENTITY_TABLE)?;
        Ok(table.get(&"self".to_string())?)
    }

    // ── Contacts ──────────────────────────────────────────────────────────────

    pub fn save_contact(&self, card: &ContactCard, name: Option<&str>) -> Result<()> {
        let id = card.id();
        let record = ContactRecord {
            id: id.clone(),
            name: name.unwrap_or(&id).to_string(),
            signing_pk_bytes: card.signing_pk.clone(),
            tor_pk_bytes: card.tor_pk.clone(),
            onion_address: card.onion_address.clone(),
        };
        let table = self.db.table::<String, ContactRecord>(CONTACTS_TABLE)?;
        table.put(&id, &record)?;
        Ok(())
    }

    pub fn load_contact(&self, id: &str) -> Result<ContactRecord> {
        let table = self.db.table::<String, ContactRecord>(CONTACTS_TABLE)?;
        table.get(&id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", id))
    }

    pub fn list_contacts(&self) -> Result<Vec<ContactRecord>> {
        let table = self.db.table::<String, ContactRecord>(CONTACTS_TABLE)?;
        Ok(table.iter()?.into_iter().map(|(_, v)| v).collect())
    }

    pub fn rename_contact(&self, id: &str, name: &str) -> Result<()> {
        let table = self.db.table::<String, ContactRecord>(CONTACTS_TABLE)?;
        let mut record = self.load_contact(id)?;
        record.name = name.to_string();
        table.put(&id.to_string(), &record)?;
        Ok(())
    }

    pub fn delete_contact(&self, id: &str) -> Result<()> {
        let table = self.db.table::<String, ContactRecord>(CONTACTS_TABLE)?;
        table.delete(&id.to_string())?;
        Ok(())
    }

    // ── Pending KEM offers (for manual share) ────────────────────────────────

    pub fn save_pending_kem_offer(&self, contact_id: &str, kem_sk_bytes: &[u8]) -> Result<()> {
        let table = self.db.table::<String, Vec<u8>>(PENDING_KEM_TABLE)?;
        table.put(&contact_id.to_string(), &kem_sk_bytes.to_vec())?;
        Ok(())
    }

    pub fn take_pending_kem_offer(&self, contact_id: &str) -> Result<Vec<u8>> {
        let table = self.db.table::<String, Vec<u8>>(PENDING_KEM_TABLE)?;
        let sk = table.get(&contact_id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("No pending KEM offer for contact={}", contact_id))?;
        table.delete(&contact_id.to_string())?;
        Ok(sk)
    }

    // ── Share merge ───────────────────────────────────────────────────────────

    /// Merge received server data: update admin_key if new, save if not present.
    pub fn merge_server_share(&self, s: &ServerShareData) -> Result<String> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;

        if let Some(existing) = table.get(&id_key(s.id))? {
            if existing.address != s.host || existing.shared_key_bytes != s.shared_key {
                anyhow::bail!(
                    "Server {:032x} already exists but data mismatch (host or shared_key differs)",
                    s.id
                );
            }
            // Update admin_key only if we receive one and don't already have one
            if s.admin_key.is_some() && existing.admin_key_bytes.is_none() {
                let mut updated = existing.clone();
                updated.admin_key_bytes = s.admin_key.clone();
                table.put(&id_key(s.id), &updated)?;
                return Ok(format!("Server '{:032x}' admin_key updated", s.id));
            }
            return Ok(format!("Server '{:032x}' already up to date", s.id));
        }

        let record = ServerRecord {
            id: s.id,
            name: s.name.clone(),
            address: s.host.clone(),
            shared_key_bytes: s.shared_key.clone(),
            admin_key_bytes: s.admin_key.clone(),
            state: NodeState::Disabled,
        };
        table.put(&id_key(s.id), &record)?;
        Ok(format!("Server '{:032x}' saved", s.id))
    }

    pub fn merge_chat_share(&self, c: &ChatShareData) -> Result<String> {
        // Always process server data first
        self.merge_server_share(&c.server)?;

        let key = chat_key(c.server.id, c.id);
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        let existing = table.get(&key)?;

        let record = ChatRecord {
            server_id: c.server.id,
            chat_id: c.id,
            name: c.name.clone(),
            encryption_key_bytes: c.encryption_key.clone(),
            last_synced_ts: existing.as_ref().map(|e| e.last_synced_ts).unwrap_or(0),
            state: existing.as_ref().map(|e| e.state).unwrap_or(NodeState::Disabled),
            verification_mode: existing.as_ref().map(|e| e.verification_mode).unwrap_or(false),
        };
        table.put(&key, &record)?;

        let action = if existing.is_some() { "updated" } else { "saved" };
        Ok(format!("Chat '{:032x}/{:032x}' {action}", c.server.id, c.id))
    }

    pub fn merge_share_data(&self, data: &crate::sharing::ShareData) -> Result<String> {
        match data {
            crate::sharing::ShareData::Server(s) => self.merge_server_share(s),
            crate::sharing::ShareData::Chat(c) => self.merge_chat_share(c),
        }
    }
}
