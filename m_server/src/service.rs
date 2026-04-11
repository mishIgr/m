use prost::Message;
use subtle::ConstantTimeEq;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};

use m_core::crypto::SymmetricEncryption;
use m_core::proto::*;

use crate::dispatcher::Dispatcher;

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
    dispatcher: Dispatcher,
    cipher: C,
    admin_key: Vec<u8>,
}

impl<C: SymmetricEncryption> MessengerService<C> {
    pub fn new(dispatcher: Dispatcher, cipher: C, admin_key: Vec<u8>) -> Self {
        Self { dispatcher, cipher, admin_key }
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
        let req: CreateChatRequest = self.decrypt_request(request)?;
        self.verify_admin(&req.admin_key)?;

        // TODO: бизнес-логика

        self.encrypt_response(&CreateChatResponse {
            success: true,
            error: String::new(),
        })
    }

    async fn delete_chat(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        let req: DeleteChatRequest = self.decrypt_request(request)?;
        self.verify_admin(&req.admin_key)?;

        // TODO: бизнес-логика

        self.encrypt_response(&DeleteChatResponse {
            success: true,
            error: String::new(),
        })
    }

    async fn list_chats(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        let req: ListChatsRequest = self.decrypt_request(request)?;
        self.verify_admin(&req.admin_key)?;

        // TODO: бизнес-логика

        self.encrypt_response(&ListChatsResponse {
            chats: vec![],
        })
    }

    async fn send_message(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        let req: SendMessageRequest = self.decrypt_request(request)?;

        // TODO: бизнес-логика

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        self.encrypt_response(&SendMessageResponse {
            accepted: true,
            timestamp_ms,
            error: String::new(),
        })
    }

    async fn get_history(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        let _req: GetHistoryRequest = self.decrypt_request(request)?;

        // TODO: бизнес-логика

        self.encrypt_response(&GetHistoryResponse {
            messages: vec![],
        })
    }

    type ChannelStream = ReceiverStream<Result<Envelope, Status>>;

    async fn channel(
        &self,
        request: Request<tonic::Streaming<Envelope>>,
    ) -> Result<Response<Self::ChannelStream>, Status> {
        let mut inbound = request.into_inner();
        let cipher = self.cipher.clone();

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Envelope, Status>>(128);

        tokio::spawn(async move {
            while let Some(result) = inbound.next().await {
                let envelope = match result {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                };

                // Расшифровываем вручную (нет доступа к self)
                let event: ClientEvent = match decrypt_raw::<C, _>(&cipher, &envelope.data) {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                };

                match event.event {
                    Some(client_event::Event::Subscribe(sub)) => {
                        // TODO: подписка на чаты

                        for chat in &sub.chats {
                            let server_event = ServerEvent {
                                event: Some(server_event::Event::SyncComplete(SyncComplete {
                                    chat_id: chat.chat_id.clone(),
                                    synced_up_timestamp_ms: chat.latest_timestamp_ms,
                                })),
                            };

                            let data = match encrypt_raw::<C, _>(&cipher, &server_event) {
                                Ok(d) => d,
                                Err(e) => {
                                    let _ = tx.send(Err(e)).await;
                                    return;
                                }
                            };

                            if tx.send(Ok(Envelope { data })).await.is_err() {
                                return;
                            }
                        }
                    }

                    Some(client_event::Event::Ack(_ack)) => {
                        // TODO: подтверждение доставки
                    }

                    None => {
                        let error_event = ServerEvent {
                            event: Some(server_event::Event::Error(ErrorEvent {
                                code: "EMPTY_EVENT".to_string(),
                                message: "empty client event".to_string(),
                            })),
                        };

                        let data = match encrypt_raw::<C, _>(&cipher, &error_event) {
                            Ok(d) => d,
                            Err(e) => {
                                let _ = tx.send(Err(e)).await;
                                return;
                            }
                        };

                        let _ = tx.send(Ok(Envelope { data })).await;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
