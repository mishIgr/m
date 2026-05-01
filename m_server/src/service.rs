use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use prost::Message;
use subtle::ConstantTimeEq;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};

use m_core::crypto::SymmetricEncryption;
use m_core::proto::*;

use crate::dispatcher::{Dispatcher, bytes_to_u128};

fn encrypt_raw<C: SymmetricEncryption, M: Message>(
    cipher: &C,
    message: &M,
) -> Result<Vec<u8>, Status> {
    let plaintext = message.encode_to_vec();

    let nonce = C::generate_nonce();

    let ciphertext = cipher
        .encrypt(&nonce, &plaintext, b"grpc")
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut data = Vec::with_capacity(C::NONCE_SIZE + ciphertext.len());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&ciphertext);
    Ok(data)
}

fn decrypt_raw<C: SymmetricEncryption, M: Message + Default>(
    cipher: &C,
    raw: &[u8],
) -> Result<M, Status> {
    if raw.len() < C::NONCE_SIZE {
        return Err(Status::invalid_argument("payload too short"));
    }

    let nonce = &raw[..C::NONCE_SIZE];
    let ciphertext = &raw[C::NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext, b"grpc")
        .map_err(|e| Status::unauthenticated(format!("decrypt: {e}")))?;

    M::decode(plaintext.as_slice())
        .map_err(|e| Status::internal(format!("decode: {e}")))
}

pub struct MessengerService<C: SymmetricEncryption> {
    dispatcher: Arc<Mutex<Dispatcher>>,
    cipher: C,
    admin_key: Vec<u8>,
    channel_buffer_size: usize,
}

impl<C: SymmetricEncryption> MessengerService<C> {
    pub fn new(dispatcher: Dispatcher, cipher: C, admin_key: Vec<u8>, channel_buffer_size: usize) -> Self {
        Self { dispatcher: Arc::new(Mutex::new(dispatcher)), cipher, admin_key, channel_buffer_size }
    }

    pub fn spawn_retry_loop(&self, interval: Duration) {
        let dispatcher = self.dispatcher.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                dispatcher.lock().await.retry_pending().await;
            }
        });
    }

    fn verify_admin(&self, key: &[u8]) -> Result<(), Status> {
        let eq: bool = self.admin_key
            .ct_eq(key)
            .into();

        if eq {
            Ok(())
        } else {
            Err(Status::permission_denied("invalid admin key"))
        }
    }

    fn encrypt<M: Message>(&self, message: &M) -> Result<Vec<u8>, Status> {
        encrypt_raw::<C, M>(&self.cipher, message)
    }

    fn decrypt<M: Message + Default>(&self, raw: &[u8]) -> Result<M, Status> {
        decrypt_raw::<C, M>(&self.cipher, raw)
    }

    fn decrypt_request<M: Message + Default>(
        &self,
        request: Request<Envelope>,
    ) -> Result<M, Status> {
        self.decrypt(&request.into_inner().data)
    }

    fn encrypt_response<M: Message>(
        &self,
        message: &M,
    ) -> Result<Response<Envelope>, Status> {
        let data = self.encrypt(message)?;
        Ok(Response::new(Envelope { data }))
    }
}

#[tonic::async_trait]
impl<C> messenger_server::Messenger for MessengerService<C>
where
    C: SymmetricEncryption + Clone + Send + Sync + 'static,
{
    async fn create_chat(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        m_core::log_info!("service: create_chat request received");
        let req: CreateChatRequest = self.decrypt_request(request)
            .map_err(|e| { m_core::log_error!("service: create_chat decrypt failed: {}", e); e })?;
        self.verify_admin(&req.admin_key)
            .map_err(|e| { m_core::log_error!("service: create_chat admin key invalid"); e })?;

        let chat_id: u128 = rand::random();
        m_core::log_info!("service: create_chat name={} generated id={:032x}", req.name, chat_id);
        let mut d = self.dispatcher.lock().await;
        let success = d
            .create_chat(chat_id, &req.name, req.max_messages, req.max_bytes)
            .map_err(|e| { m_core::log_error!("service: create_chat dispatcher error: {}", e); Status::internal(e.to_string()) })?;

        m_core::log_info!("service: create_chat success={} id={:032x}", success, chat_id);
        self.encrypt_response(&CreateChatResponse {
            success,
            error: if success { String::new() } else { "chat already exists".into() },
            chat_id: chat_id.to_be_bytes().to_vec(),
        })
    }

    async fn delete_chat(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        let req: DeleteChatRequest = self.decrypt_request(request)?;
        self.verify_admin(&req.admin_key)?;

        let chat_id = bytes_to_u128(&req.chat_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let mut d = self.dispatcher.lock().await;
        let success = d
            .delete_chat(chat_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        self.encrypt_response(&DeleteChatResponse {
            success,
            error: if success { String::new() } else { "chat not found".into() },
        })
    }

    async fn list_chats(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        let req: ListChatsRequest = self.decrypt_request(request)?;
        self.verify_admin(&req.admin_key)?;

        let d = self.dispatcher.lock().await;
        let chats = d.list_chats();

        self.encrypt_response(&ListChatsResponse { chats })
    }

    async fn send_message(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        let req: SendMessageRequest = self.decrypt_request(request)?;

        let chat_id = bytes_to_u128(&req.chat_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let mut d = self.dispatcher.lock().await;
        let buffer = d.chat_buffers.get_mut(&chat_id)
            .ok_or_else(|| {
                m_core::log_warn!("service: send_message chat not found chat_id={:032x}", chat_id);
                Status::not_found("chat not found")
            })?;

        let message_id = format!("{:032x}", rand::random::<u128>());
        let (timestamp_ms, accepted) = buffer.push(message_id.clone(), req.encrypted_payload.clone());
        m_core::log_debug!("service: send_message chat_id={:032x} message_id={} accepted={} ts={}", chat_id, message_id, accepted, timestamp_ms);

        if accepted {
            let msg = ChatMessage {
                chat_id: req.chat_id.clone(),
                message_id: message_id.clone(),
                timestamp_ms,
                encrypted_payload: req.encrypted_payload,
            };
            d.fanout(chat_id, &msg).await;
        }

        self.encrypt_response(&SendMessageResponse {
            accepted,
            timestamp_ms: timestamp_ms as u64,
            error: String::new(),
            message_id,
        })
    }

    async fn get_history(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        let req: GetHistoryRequest = self.decrypt_request(request)?;

        let chat_id = bytes_to_u128(&req.chat_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let d = self.dispatcher.lock().await;
        let buffer = d.chat_buffers.get(&chat_id)
            .ok_or_else(|| Status::not_found("chat not found"))?;

        let stored = buffer.get_range(req.from_timestamp_ms as i64, req.to_timestamp_ms as i64);
        let chat_id_bytes = chat_id.to_be_bytes().to_vec();
        let messages: Vec<ChatMessage> = stored
            .into_iter()
            .take(req.limit as usize)
            .map(|m| ChatMessage {
                chat_id: chat_id_bytes.clone(),
                message_id: m.message_id.clone(),
                timestamp_ms: m.timestamp_ms,
                encrypted_payload: m.encrypted_payload.clone(),
            })
            .collect();

        self.encrypt_response(&GetHistoryResponse { messages })
    }

    type ChannelStream = ReceiverStream<Result<Envelope, Status>>;

    async fn channel(
        &self,
        request: Request<tonic::Streaming<Envelope>>,
    ) -> Result<Response<Self::ChannelStream>, Status> {
        let mut inbound = request.into_inner();
        let cipher = self.cipher.clone();
        let dispatcher = self.dispatcher.clone();

        let buf = self.channel_buffer_size;
        let (inner_tx, mut inner_rx) = tokio::sync::mpsc::channel::<ServerEvent>(buf);
        let (outer_tx, outer_rx) = tokio::sync::mpsc::channel::<Result<Envelope, Status>>(buf);

        let conn_id = {
            let mut d = dispatcher.lock().await;
            d.register_connection(inner_tx)
        };
        m_core::log_info!("service: channel opened conn_id={}", conn_id);

        let fwd_cipher = cipher.clone();
        let fwd_tx = outer_tx.clone();
        tokio::spawn(async move {
            while let Some(server_event) = inner_rx.recv().await {
                let data = match encrypt_raw::<C, _>(&fwd_cipher, &server_event) {
                    Ok(d) => d,
                    Err(e) => {
                        m_core::log_error!("service: channel fwd_task encrypt failed conn={}: {}", conn_id, e);
                        let _ = fwd_tx.send(Err(e)).await;
                        return;
                    }
                };
                if fwd_tx.send(Ok(Envelope { data })).await.is_err() {
                    return;
                }
            }
            m_core::log_debug!("service: channel fwd_task exited conn={}", conn_id);
        });

        tokio::spawn(async move {
            while let Some(result) = inbound.next().await {
                let envelope = match result {
                    Ok(e) => e,
                    Err(e) => {
                        m_core::log_warn!("service: channel inbound stream error conn={}: {}", conn_id, e);
                        let _ = outer_tx.send(Err(e)).await;
                        break;
                    }
                };

                let event: ClientEvent = match decrypt_raw::<C, _>(&cipher, &envelope.data) {
                    Ok(e) => e,
                    Err(e) => {
                        m_core::log_error!("service: channel inbound decrypt failed conn={}: {}", conn_id, e);
                        let _ = outer_tx.send(Err(e)).await;
                        break;
                    }
                };

                match event.event {
                    Some(client_event::Event::Subscribe(sub)) => {
                        m_core::log_debug!("service: channel inbound Subscribe conn={} chat_count={}", conn_id, sub.chats.len());
                        let mut d = dispatcher.lock().await;
                        d.subscribe(conn_id, sub.chats).await;
                    }

                    Some(client_event::Event::Ack(ack)) => {
                        m_core::log_debug!("service: channel inbound Ack conn={} ts={}", conn_id, ack.timestamp_ms);
                        let mut d = dispatcher.lock().await;
                        d.handle_ack(conn_id, &ack);
                    }

                    None => {
                        m_core::log_warn!("service: channel inbound empty client event conn={}", conn_id);
                        let error_event = ServerEvent {
                            event: Some(server_event::Event::Error(ErrorEvent {
                                code: "EMPTY_EVENT".to_string(),
                                message: "empty client event".to_string(),
                            })),
                        };

                        let data = match encrypt_raw::<C, _>(&cipher, &error_event) {
                            Ok(d) => d,
                            Err(e) => {
                                let _ = outer_tx.send(Err(e)).await;
                                return;
                            }
                        };

                        let _ = outer_tx.send(Ok(Envelope { data })).await;
                    }
                }
            }

            let mut d = dispatcher.lock().await;
            d.remove_connection(conn_id);
            m_core::log_info!("service: channel closed conn_id={}", conn_id);
        });

        Ok(Response::new(ReceiverStream::new(outer_rx)))
    }
}
