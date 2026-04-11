mod config;
mod chat_buffer;
mod dispatcher;
mod service;

use tonic::transport::Server;

use m_core::{LoggerConfig, crypto::{CryptoKey, algorithms::symmetric::Aes256Gcm}};
use dispatcher::{DeliverySettings, Dispatcher};
use service::MessengerService;
use config::ServerConfig;
use m_core::proto::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "~/.config/m/client.yaml".to_string());

    let config = ServerConfig::from_file(&config_path)?;

    if let Err(err) = config.validate() {
        panic!("Error configurationr: {}", err);
    };

    let log_config = LoggerConfig::default().set_log_dir(&config.logging.path);

    if let Err(err) = m_core::init_logger(log_config) {
        panic!("Error init logger, error: {}", err);
    }

    let dispatcher = Dispatcher::new(DeliverySettings{ack_timeout_secs: 10, max_retries: 10});

    let user_key: Result<_, m_core::crypto::CryptoError> = CryptoKey::from_vec(config.user_key_bytes().unwrap());
    let cipher = match user_key {
        Ok(key) => Aes256Gcm::from_key(key),
        Err(err) => {
            panic!("Error user_key on config {}, error: {}", config_path, err);
        }
    };
    let admin_key = config.admin_key_bytes()?;

    let service = MessengerService::new(dispatcher, cipher, admin_key);
    let bind_address = config.host.bind_address.unwrap_or("0.0.0.0:50051".to_string());

    Server::builder()
        .add_service(messenger_server::MessengerServer::new(service))
        .serve(bind_address.parse()?)
        .await?;

    Ok(())
}
