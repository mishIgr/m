use std::fmt;
use std::path::Path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use m_core::crypto::Hash;
use m_core::crypto::algorithms::hash::Blake3Hash;
use m_core::db::{RedbStore, KvStore, Table};

use crate::identity::ContactCard;
use crate::sharing::{ServerShareData, ChatShareData};
use crate::config::{ServerImport, ChatImport};

const SERVER_TABLE: &str = "servers";
const CHATS_TABLE: &str = "chats";
const MESSAGES_TABLE_PREFIX: &str = "messages:";
const IDENTITY_TABLE: &str = "identity";
const CONTACTS_TABLE: &str = "contacts";

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

fn address_hash(address: &str) -> String {
    let hash_bytes = Blake3Hash::hash(address.as_bytes(), 16)
        .expect("blake3 hash failed");
    hex::encode(&hash_bytes[..4])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRecord {
    pub id: String,
    pub name: String,
    pub address: String,
    pub shared_key_bytes: Vec<u8>,
    pub admin_key_bytes: Option<Vec<u8>>,
    pub state: NodeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRecord {
    pub server_id: String,
    pub chat_id: String,
    pub name: String,
    pub encryption_key_bytes: Vec<u8>,
    pub last_synced_ts: i64,
    pub state: NodeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub chat_id: String,
    pub message_id: String,
    pub timestamp_ms: i64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub id: String,
    pub signing_sk_bytes: Vec<u8>,
    pub signing_pk_bytes: Vec<u8>,
    pub tor_sk_bytes: Vec<u8>,
    pub tor_pk_bytes: Vec<u8>,
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

    pub fn save_server(&self, import: &ServerImport) -> Result<()> {
        let shared_key_bytes = hex::decode(&import.auth.shared_key)
            .context("Failed to decode shared_key hex")?;
        let admin_key_bytes = import.auth.admin_key.as_ref()
            .map(|k| hex::decode(k))
            .transpose()
            .context("Failed to decode admin_key hex")?;

        let id = import.connection.id.clone();
        let name = format!("{}-{}", id, address_hash(&import.connection.server_address));

        let record = ServerRecord {
            id: id.clone(),
            name,
            address: import.connection.server_address.clone(),
            shared_key_bytes,
            admin_key_bytes,
            state: NodeState::Disabled,
        };

        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        table.put(&id, &record)?;
        Ok(())
    }

    pub fn load_server(&self, id: &str) -> Result<ServerRecord> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        table.get(&id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("Server '{}' not found. Run: import-server <path.toml>", id))
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

    pub fn set_server_state(&self, id: &str, state: NodeState) -> Result<()> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
        let mut record = self.load_server(id)?;
        record.state = state;
        table.put(&id.to_string(), &record)?;
        Ok(())
    }

    pub fn save_chat(&self, import: &ChatImport) -> Result<()> {
        let encryption_key_bytes = hex::decode(&import.encryption_key)
            .context("Failed to decode encryption_key hex")?;

        let key = format!("{}:{}", import.server_id, import.chat_id);

        let record = ChatRecord {
            server_id: import.server_id.clone(),
            chat_id: import.chat_id.clone(),
            name: import.name.clone(),
            encryption_key_bytes,
            last_synced_ts: 0,
            state: NodeState::Disabled,
        };

        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        table.put(&key, &record)?;
        Ok(())
    }

    pub fn load_chat(&self, server_id: &str, chat_id: &str) -> Result<ChatRecord> {
        let key = format!("{server_id}:{chat_id}");
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        table.get(&key)?
            .ok_or_else(|| anyhow::anyhow!(
                "Chat '{chat_id}' not found on server '{server_id}'. Run: import-chat <path.toml>"
            ))
    }

    pub fn list_chats_for_server(&self, server_id: &str) -> Result<Vec<ChatRecord>> {
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        Ok(table.iter()?.into_iter()
            .filter(|(_, c)| c.server_id == server_id)
            .map(|(_, v)| v)
            .collect())
    }

    pub fn list_enabled_chats_for_server(&self, server_id: &str) -> Result<Vec<ChatRecord>> {
        Ok(self.list_chats_for_server(server_id)?.into_iter()
            .filter(|c| c.state == NodeState::Enabled)
            .collect())
    }

    pub fn set_chat_state(&self, server_id: &str, chat_id: &str, state: NodeState) -> Result<()> {
        let key = format!("{server_id}:{chat_id}");
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        let mut record = self.load_chat(server_id, chat_id)?;
        record.state = state;
        table.put(&key, &record)?;
        Ok(())
    }

    pub fn update_chat_sync_ts(&self, server_id: &str, chat_id: &str, ts: i64) -> Result<()> {
        let key = format!("{server_id}:{chat_id}");
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        let mut record = self.load_chat(server_id, chat_id)?;
        record.last_synced_ts = ts;
        table.put(&key, &record)?;
        Ok(())
    }

    pub fn save_message(&self, msg: &StoredMessage) -> Result<()> {
        let table_name = format!("{}{}", MESSAGES_TABLE_PREFIX, msg.chat_id);
        let table = self.db.table::<i64, StoredMessage>(&table_name)?;
        table.put(&msg.timestamp_ms, msg)?;
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

    pub fn upsert_shared_server(&self, data: &ServerShareData) -> Result<String> {
        let table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;

        let existing = table.get(&data.id)?.or_else(|| {
            table.iter().ok().and_then(|all| {
                all.into_iter()
                    .find(|(_, r)| r.address == data.host)
                    .map(|(_, r)| r)
            })
        });

        if let Some(existing) = existing {
            let admin_key = match (&existing.admin_key_bytes, &data.admin_key) {
                (Some(ak), None) => Some(ak.clone()),
                (_, incoming) => incoming.clone(),
            };

            let record = ServerRecord {
                id: data.id.clone(),
                name: existing.name.clone(),
                address: data.host.clone(),
                shared_key_bytes: data.shared_key.clone(),
                admin_key_bytes: admin_key,
                state: existing.state,
            };

            if existing.id != data.id {
                table.delete(&existing.id)?;
            }

            table.put(&data.id, &record)?;
            Ok(format!("Server '{}' updated", data.id))
        } else {
            let name = format!("{}-{}", data.id, address_hash(&data.host));
            let record = ServerRecord {
                id: data.id.clone(),
                name,
                address: data.host.clone(),
                shared_key_bytes: data.shared_key.clone(),
                admin_key_bytes: data.admin_key.clone(),
                state: NodeState::Disabled,
            };
            table.put(&data.id, &record)?;
            Ok(format!("Server '{}' saved", data.id))
        }
    }

    pub fn upsert_shared_chat(&self, data: &ChatShareData) -> Result<String> {
        let key = format!("{}:{}", data.server_id, data.chat_id);
        let table = self.db.table::<String, ChatRecord>(CHATS_TABLE)?;
        let existing = table.get(&key)?;

        let record = ChatRecord {
            server_id: data.server_id.clone(),
            chat_id: data.chat_id.clone(),
            name: data.name.clone(),
            encryption_key_bytes: data.encryption_key.clone(),
            last_synced_ts: existing.as_ref().map(|e| e.last_synced_ts).unwrap_or(0),
            state: existing.as_ref().map(|e| e.state).unwrap_or(NodeState::Disabled),
        };
        table.put(&key, &record)?;

        if let Some(admin_key) = &data.server_admin_key {
            let server_table = self.db.table::<String, ServerRecord>(SERVER_TABLE)?;
            if let Ok(Some(mut server)) = server_table.get(&data.server_id) {
                if server.admin_key_bytes.is_none() {
                    server.admin_key_bytes = Some(admin_key.clone());
                    server_table.put(&data.server_id, &server)?;
                }
            }
        }

        let action = if existing.is_some() { "updated" } else { "saved" };
        Ok(format!("Chat '{}/{}' {action}", data.server_id, data.chat_id))
    }
}
