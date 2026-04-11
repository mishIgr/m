use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: HostConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub encryption: EncryptionConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostConfig {
    pub bind_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub user_key: String,
    pub admin_key: String,
}

impl ServerConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        let config_content = std::fs::read_to_string(path)
            .context(format!("Failed to read configuration file: {}", path))?;
        
        let config: ServerConfig = toml::from_str(&config_content)
            .context("Failed to parse TOML configuration")?;
        
        Ok(config)
    }
    
    pub fn validate(&self) -> Result<()> {
        self.validate_hex_key(&self.encryption.user_key, "user_key")?;
        self.validate_hex_key(&self.encryption.admin_key, "admin_key")?;
        
        Ok(())
    }
    
    fn validate_hex_key(&self, key: &str, key_name: &str) -> Result<()> {
        if key.is_empty() {
            anyhow::bail!("Key {} cannot be empty", key_name);
        }
        
        if key.len() % 2 != 0 {
            anyhow::bail!("Key {} must have even length", key_name);
        }
        
        if !key.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("Key {} contains invalid characters", key_name);
        }
        
        Ok(())
    }
    
    pub fn user_key_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.encryption.user_key)
            .context("Failed to decode user_key from hex")
    }
    
    pub fn admin_key_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.encryption.admin_key)
            .context("Failed to decode admin_key from hex")
    }
}
