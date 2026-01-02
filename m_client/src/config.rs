use std::path::Path;
use anyhow::{Context, Result};
use serde::Deserialize;
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

#[derive(Debug, Deserialize)]
pub struct ServerImport {
    pub connection: ServerConnection,
    pub auth: ServerAuth,
}

#[derive(Debug, Deserialize)]
pub struct ServerConnection {
    pub id: String,
    pub server_address: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerAuth {
    pub shared_key: String,
    pub admin_key: Option<String>,
}

impl ServerImport {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read server file: {}", path.display()))?;
        let cfg: Self = toml::from_str(&content)
            .with_context(|| "Failed to parse server import TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        validate_hex(&self.auth.shared_key, "shared_key")?;
        if let Some(ref ak) = self.auth.admin_key {
            validate_hex(ak, "admin_key")?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct ChatImport {
    pub server_id: String,
    pub chat_id: String,
    pub name: String,
    pub encryption_key: String,
}

impl ChatImport {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read chat file: {}", path.display()))?;
        let cfg: Self = toml::from_str(&content)
            .with_context(|| "Failed to parse chat import TOML")?;
        validate_hex(&cfg.encryption_key, "encryption_key")?;
        Ok(cfg)
    }
}

fn validate_hex(key: &str, name: &str) -> Result<()> {
    if key.is_empty() {
        anyhow::bail!("{} cannot be empty", name);
    }
    if key.len() % 2 != 0 {
        anyhow::bail!("{} must have even length", name);
    }
    if !key.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("{} contains invalid hex characters", name);
    }
    Ok(())
}
