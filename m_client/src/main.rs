mod config;
mod connection_manager;
mod message_payload;
mod message_seq;
mod store;
mod transport;
mod live;
mod sharing;
mod identity;
mod share;
mod manual_share;
mod setup_server;
mod tui;

use std::path::PathBuf;
use clap::Parser;
use anyhow::Result;

use m_core::crypto::{CryptoKey, AsymmetricCipher};

use identity::Identity;
use config::ClientConfig;
use store::{Store, IdentityRecord};

#[derive(Parser)]
#[command(name = "m_client", about = "Encrypted messenger TUI client")]
struct Cli {
    #[arg(long, default_value = "~/.config/m/client.toml")]
    config: String,
}

fn expand_tilde(path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(path).as_ref())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = expand_tilde(&cli.config);
    let config = ClientConfig::load(&config_path)?;

    let db_path = PathBuf::from(&config.storage.db_path);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let store = Store::open(&db_path)?;

    if store.load_identity()?.is_none() {
        let identity = Identity::generate();
        let record = IdentityRecord {
            id: identity.id(),
            signing_sk_bytes: identity.signing.get_secret().as_bytes().to_vec(),
            signing_pk_bytes: identity.signing.get_public().as_bytes().to_vec(),
            tor_sk_bytes: identity.tor_sk_bytes().to_vec(),
            tor_pk_bytes: identity.tor_pk_bytes().to_vec(),
            name: None,
        };
        store.save_identity(&record)?;
        println!("Identity generated.");
        println!("  ID:    {}", record.id);
        println!("  Onion: {}", identity.onion_address());
    }

    if let Err(err) = m_core::init_logger(config.logging) {
        panic!("Error init logger, error: {}", err);
    }

    tui::run(store, config.messages).await
}
