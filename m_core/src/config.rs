use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub server: ServerSettings,
    pub auth: ServerAuthSettings,
    pub storage: StorageSettings,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    pub bind_address: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerAuthSettings {
    pub user_key: String,
    pub admin_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageSettings {
    pub default_max_messages: u32,
    pub default_max_bytes: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientConfig {
    pub connection: ConnectionSettings,
    pub auth: ClientAuthSettings,
    pub chats: ChatSettings,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConnectionSettings {
    pub server_address: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientAuthSettings {
    pub role: String,
    pub shared_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChatSettings {
    #[serde(default)]
    pub keys: HashMap<String, String>,
}

pub fn load_server_config(path: &Path) -> Result<ServerConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read: {}", path.display()))?;
    toml::from_str(&content).with_context(|| "Failed to parse server config")
}

pub fn load_client_config(path: &Path) -> Result<ClientConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read: {}", path.display()))?;
    toml::from_str(&content).with_context(|| "Failed to parse client config")
}
