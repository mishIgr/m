use std::collections::HashMap;
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use m_core::proto::*;

use crate::sharing::ShareData;
use crate::store::{ChatRecord, Store, StoredMessage};
use crate::transport::{self, decrypt_payload, make_envelope, parse_server_event};

pub struct LiveMessage {
    pub server_id: String,
    pub chat_id: String,
    pub chat_name: String,
    pub text: String,
    pub timestamp: String,
}

pub enum LiveEvent {
    Message(LiveMessage),
    SyncComplete { _server_id: String, _chat_name: String },
    Error { server_id: String, message: String },
    ServerUnavailable(String),
    Disconnected(String),
    ShareReceived(ShareData),
    TorBootstrap(u8),
}

pub async fn subscribe(
    server_id: &str,
    address: &str,
    shared_key_bytes: &[u8],
    chats: &[(String, ChatRecord)],
    store: Store,
    cancel: CancellationToken,
    event_tx: mpsc::UnboundedSender<LiveEvent>,
) -> Result<()> {
    let sid = server_id.to_string();

    m_core::log_info!("live: connecting to server={} address={} chats={}", sid, address, chats.len());
    for (id, rec) in chats {
        m_core::log_debug!("live: subscribe chat={} last_synced_ts={}", id, rec.last_synced_ts);
    }

    let mut channel_transport = match transport::Transport::connect(address, shared_key_bytes).await {
        Ok(t) => t,
        Err(e) => {
            m_core::log_error!("live: connect failed server={} error={}", sid, e);
            let _ = event_tx.send(LiveEvent::ServerUnavailable(sid.clone()));
            return Err(e);
        }
    };
    let cipher = channel_transport.cipher().clone();
    m_core::log_info!("live: transport connected server={}", sid);

    let (tx, mut inbound) = match channel_transport.open_channel().await {
        Ok(pair) => pair,
        Err(e) => {
            m_core::log_error!("live: open_channel failed server={} error={}", sid, e);
            let _ = event_tx.send(LiveEvent::ServerUnavailable(sid.clone()));
            return Err(e);
        }
    };
    m_core::log_info!("live: channel opened server={}", sid);

    let chat_keys: HashMap<String, Vec<u8>> = chats.iter()
        .map(|(id, rec)| (id.clone(), rec.encryption_key_bytes.clone()))
        .collect();

    let subscriptions: Vec<ChatSubscription> = chats.iter()
        .map(|(id, rec)| ChatSubscription {
            chat_id: id.clone(),
            latest_timestamp_ms: if rec.last_synced_ts > 0 { rec.last_synced_ts as u64 } else { 0 },
        })
        .collect();

    let subscribe_event = ClientEvent {
        event: Some(client_event::Event::Subscribe(SubscribeRequest {
            chats: subscriptions,
        })),
    };
    let envelope = make_envelope(&cipher, &subscribe_event)?;
    tx.send(envelope).await.context("failed to send subscribe")?;
    m_core::log_info!("live: subscribe sent server={} chats={}", sid, subscriptions.len());

    let chat_names: HashMap<String, String> = chats.iter()
        .map(|(id, rec)| (id.clone(), rec.name.clone()))
        .collect();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            item = inbound.next() => {
                let Some(result) = item else {
                    m_core::log_info!("live: inbound stream closed server={}", sid);
                    break;
                };
                let envelope = match result {
                    Ok(e) => e,
                    Err(e) => {
                        m_core::log_error!("live: stream error server={} error={}", sid, e);
                        let _ = event_tx.send(LiveEvent::Error {
                            server_id: sid.clone(),
                            message: format!("Stream error: {e}"),
                        });
                        break;
                    }
                };

                let server_event: ServerEvent = match parse_server_event(&cipher, &envelope) {
                    Ok(e) => e,
                    Err(e) => {
                        m_core::log_error!("live: parse_server_event failed server={} error={}", sid, e);
                        let _ = event_tx.send(LiveEvent::Error {
                            server_id: sid.clone(),
                            message: format!("Decrypt error: {e}"),
                        });
                        continue;
                    }
                };

                match server_event.event {
                    Some(server_event::Event::Message(msg)) => {
                        m_core::log_debug!("live: message received server={} chat={} ts={} id={}", sid, msg.chat_id, msg.timestamp_ms, msg.message_id);
                        if !chat_keys.contains_key(&msg.chat_id) {
                            m_core::log_warn!("live: message for unknown chat={} server={}, skipping", msg.chat_id, sid);
                            continue;
                        }

                        let chat_name = chat_names.get(&msg.chat_id)
                            .cloned()
                            .unwrap_or_else(|| msg.chat_id.clone());

                        let text = match chat_keys.get(&msg.chat_id) {
                            Some(key) => match decrypt_payload(&msg.encrypted_payload, key, &msg.chat_id) {
                                Ok(t) => t,
                                Err(e) => {
                                    m_core::log_warn!("live: decrypt_payload failed server={} chat={} ts={} error={}", sid, msg.chat_id, msg.timestamp_ms, e);
                                    "<decryption failed>".to_string()
                                }
                            },
                            None => continue,
                        };

                        let ts = match chrono::DateTime::from_timestamp_millis(msg.timestamp_ms) {
                            Some(dt) => dt.format("%H:%M:%S").to_string(),
                            None => {
                                m_core::log_warn!("live: invalid timestamp_ms={} server={} chat={}, using raw value", msg.timestamp_ms, sid, msg.chat_id);
                                msg.timestamp_ms.to_string()
                            }
                        };

                        if let Err(e) = store.save_message(&StoredMessage {
                            chat_id: msg.chat_id.clone(),
                            message_id: msg.message_id.clone(),
                            timestamp_ms: msg.timestamp_ms,
                            text: text.clone(),
                        }) {
                            m_core::log_warn!("live: save_message failed server={} chat={} ts={} error={}", sid, msg.chat_id, msg.timestamp_ms, e);
                        }

                        let _ = event_tx.send(LiveEvent::Message(LiveMessage {
                            server_id: sid.clone(),
                            chat_id: msg.chat_id.clone(),
                            chat_name,
                            text,
                            timestamp: ts,
                        }));

                        let ack = ClientEvent {
                            event: Some(client_event::Event::Ack(MessageAck {
                                chat_id: msg.chat_id.clone(),
                                timestamp_ms: msg.timestamp_ms as u64,
                            })),
                        };
                        match make_envelope(&cipher, &ack) {
                            Ok(env) => {
                                if let Err(e) = tx.send(env).await {
                                    m_core::log_warn!("live: ack send failed server={} chat={} ts={} error={}", sid, msg.chat_id, msg.timestamp_ms, e);
                                }
                            }
                            Err(e) => {
                                m_core::log_warn!("live: ack envelope build failed server={} chat={} error={}", sid, msg.chat_id, e);
                            }
                        }
                    }
                    Some(server_event::Event::SyncComplete(sync)) => {
                        m_core::log_debug!("live: SyncComplete server={} chat={} synced_up_ts={}", sid, sync.chat_id, sync.synced_up_timestamp_ms);
                        if let Err(e) = store.update_chat_sync_ts(&sid, &sync.chat_id, sync.synced_up_timestamp_ms as i64) {
                            m_core::log_error!("live: update_chat_sync_ts failed server={} chat={} ts={}: {}", sid, sync.chat_id, sync.synced_up_timestamp_ms, e);
                        }
                        let chat_name = chat_names.get(&sync.chat_id)
                            .cloned()
                            .unwrap_or_else(|| sync.chat_id.clone());
                        let _ = event_tx.send(LiveEvent::SyncComplete {
                            _server_id: sid.clone(),
                            _chat_name: chat_name,
                        });
                    }
                    Some(server_event::Event::Error(err)) => {
                        m_core::log_error!("live: server error server={} code={} message={}", sid, err.code, err.message);
                        let _ = event_tx.send(LiveEvent::Error {
                            server_id: sid.clone(),
                            message: format!("Server error [{}]: {}", err.code, err.message),
                        });
                    }
                    None => {
                        m_core::log_warn!("live: received event with no payload server={}", sid);
                    }
                }
            }
        }
    }

    m_core::log_info!("live: subscribe loop exited server={}, sending Disconnected", sid);
    let _ = event_tx.send(LiveEvent::Disconnected(sid));
    Ok(())
}
