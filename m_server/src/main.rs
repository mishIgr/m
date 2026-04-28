mod config;
mod chat_buffer;
mod dispatcher;
mod service;

use tonic::transport::Server;

use m_core::{crypto::{CryptoKey, algorithms::symmetric::Aes256Gcm}};
use m_core::db::{RedbStore, KvStore};
use m_core::proto::messenger_server;

use dispatcher::Dispatcher;
use service::MessengerService;
use config::ServerConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let config_path = config::expand_tilde_path(
        &std::env::args()
            .nth(1)
            .unwrap_or_else(|| "~/.config/m/server.toml".to_string()),
    );

    let config = ServerConfig::from_file(&config_path)?;

    if let Err(err) = config.validate() {
        panic!("Error configurationr: {}", err);
    };

    // Extract via methods before any field moves
    let user_key_bytes = config.user_key_bytes().unwrap();
    let admin_key = config.admin_key_bytes()?;
    let db_path = config.database.path.clone();
    let retry_interval_secs = config.delivery.retry_interval_secs;
    let dedup_cache_size = config.performance.dedup_cache_size;
    let channel_buffer_size = config.performance.channel_buffer_size;
    let bind_address = config.host.bind_address.clone().unwrap_or("0.0.0.0:50051".to_string());

    if let Err(err) = m_core::init_logger(config.logging) {
        panic!("Error init logger, error: {}", err);
    }

    let store = RedbStore::open(&db_path)?;
    let chats_table = store.table("chats")?;

    let dispatcher = Dispatcher::new(config.delivery, dedup_cache_size, chats_table)?;

    let user_key: Result<_, m_core::crypto::CryptoError> = CryptoKey::from_vec(user_key_bytes);
    let cipher = match user_key {
        Ok(key) => Aes256Gcm::from_key(key),
        Err(err) => {
            panic!("Error user_key on config {}, error: {}", config_path, err);
        }
    };

    let service = MessengerService::new(dispatcher, cipher, admin_key, channel_buffer_size);
    service.spawn_retry_loop(std::time::Duration::from_secs(retry_interval_secs));

    Server::builder()
        .add_service(messenger_server::MessengerServer::new(service))
        .serve(bind_address.parse()?)
        .await?;

    Ok(())
}
