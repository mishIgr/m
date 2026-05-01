use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use m_core::LoggerConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: HostConfig,
    pub database: DatabaseConfig,
    pub logging: LoggerConfig,
    pub delivery: DeliveryConfig,
    pub performance: PerformanceConfig,
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
pub struct DeliveryConfig {
    pub ack_timeout_secs: u64,
    pub max_retries: u32,
    pub retry_interval_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub channel_buffer_size: usize,
    pub dedup_cache_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub user_key: String,
    pub admin_key: String,
    #[serde(default)]
    pub server_id: String,
}

pub fn expand_tilde_path(s: &str) -> String {
    shellexpand::tilde(s).into_owned()
}

impl ServerConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        let config_content = std::fs::read_to_string(path)
            .context(format!("Failed to read configuration file: {}", path))?;

        let mut config: ServerConfig = toml::from_str(&config_content)
            .context("Failed to parse TOML configuration")?;

        config.database.path = expand_tilde_path(&config.database.path);
        config.logging.log_dir = expand_tilde_path(&config.logging.log_dir);

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        self.logging.validate().map_err(|e| anyhow::anyhow!(e))?;

        self.validate_hex_key(&self.encryption.user_key, "user_key")?;
        self.validate_hex_key(&self.encryption.admin_key, "admin_key")?;

        if self.delivery.ack_timeout_secs == 0 {
            anyhow::bail!("delivery.ack_timeout_secs must be > 0");
        }
        if self.delivery.retry_interval_secs == 0 {
            anyhow::bail!("delivery.retry_interval_secs must be > 0");
        }
        if self.performance.channel_buffer_size == 0 {
            anyhow::bail!("performance.channel_buffer_size must be > 0");
        }
        if self.performance.dedup_cache_size == 0 {
            anyhow::bail!("performance.dedup_cache_size must be > 0");
        }

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

    pub fn server_id_u128(&self) -> u128 {
        if self.encryption.server_id.is_empty() {
            let id: u128 = rand::random();
            eprintln!(
                "WARNING: server_id not set in config. Generated: {:032x}. Set encryption.server_id in config.",
                id
            );
            id
        } else {
            u128::from_str_radix(&self.encryption.server_id, 16)
                .unwrap_or_else(|_| panic!("Invalid server_id in config: must be 32-char hex"))
        }
    }
}
