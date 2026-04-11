use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Request, Streaming};

use m_core::proto::messenger::*;
use m_core::proto::messenger_client::MessengerClient;

pub struct Connection {
    client: MessengerClient<Channel>,
    auth_key: String,
}

impl Connection {
    pub async fn connect(server_address: &str, auth_key: String) -> Result<Self> {
        let client = MessengerClient::connect(server_address.to_string())
            .await
            .context("Failed to connect")?;
        Ok(Self { client, auth_key })
    }

    fn auth_request<T>(&self, inner: T) -> Result<Request<T>> {
        let mut req = Request::new(inner);
        req.metadata_mut().insert(
            "x-auth-key",
            MetadataValue::try_from(self.auth_key.as_str())?,
        );
        Ok(req)
    }

    pub async fn create_chat(&mut self, chat_id: &str) -> Result<CreateChatResponse> {
        let req = self.auth_request(CreateChatRequest {
            chat_id: chat_id.to_string(),
            max_messages: 0,
            max_bytes: 0,
        })?;
        Ok(self.client.create_chat(req).await?.into_inner())
    }

    pub async fn delete_chat(&mut self, chat_id: &str) -> Result<DeleteChatResponse> {
        let req = self.auth_request(DeleteChatRequest {
            chat_id: chat_id.to_string(),
        })?;
        Ok(self.client.delete_chat(req).await?.into_inner())
    }

    pub async fn list_chats(&mut self) -> Result<Vec<ChatInfo>> {
        let req = self.auth_request(ListChatsRequest {})?;
        Ok(self.client.list_chats(req).await?.into_inner().chats)
    }

    pub async fn send_message(&mut self, chat_id: &str, encrypted_payload: Vec<u8>) -> Result<SendMessageResponse> {
        let req = self.auth_request(SendMessageRequest {
            chat_id: chat_id.to_string(),
            message_id: uuid::Uuid::new_v4().to_string(),
            encrypted_payload,
        })?;
        Ok(self.client.send_message(req).await?.into_inner())
    }

    pub async fn get_history(&mut self, chat_id: &str, from_ms: u64, to_ms: u64, limit: u32) -> Result<GetHistoryResponse> {
        let req = self.auth_request(GetHistoryRequest {
            chat_id: chat_id.to_string(),
            from_timestamp_ms: from_ms,
            to_timestamp_ms: to_ms,
            limit,
        })?;
        Ok(self.client.get_history(req).await?.into_inner())
    }

    pub async fn open_channel(&mut self) -> Result<(mpsc::Sender<ClientEvent>, Streaming<ServerEvent>)> {
        let (tx, rx) = mpsc::channel::<ClientEvent>(256);
        let rx_stream = ReceiverStream::new(rx);

        let mut req = Request::new(rx_stream);
        req.metadata_mut().insert(
            "x-auth-key",
            MetadataValue::try_from(self.auth_key.as_str())?,
        );

        let response = self.client.channel(req).await?;
        Ok((tx, response.into_inner()))
    }
}
