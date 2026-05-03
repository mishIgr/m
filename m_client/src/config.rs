use std::path::Path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use m_core::LoggerConfig;

fn expand(s: &str) -> String {
    shellexpand::tilde(s).into_owned()
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientConfig {
    pub storage: StorageConfig,
    pub logging: LoggerConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub db_path: String,
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let mut cfg: Self = toml::from_str(&content)
            .with_context(|| "Failed to parse client config")?;
        cfg.storage.db_path = expand(&cfg.storage.db_path);
        cfg.logging.log_dir = expand(&cfg.logging.log_dir);
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCard {
    pub id: u128,
    pub name: String,
    pub address: String,
    pub shared_key: Vec<u8>,
    pub admin_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCard {
    pub server_id: u128,
    pub chat_id: u128,
    pub name: String,
    pub encryption_key: Vec<u8>,
}
