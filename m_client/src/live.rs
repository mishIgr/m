use std::collections::HashMap;
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use m_core::proto::*;
use m_core::crypto::{CryptoKey, AsymmetricCipher};
use m_core::crypto::algorithms::signature::Dilithium2;
use m_core::crypto::key::Key;

use crate::sharing::ShareData;
use crate::store::{ChatRecord, Store, StoredMessage, VerificationStatus};
use crate::transport::{self, chat_id_bytes, chat_id_from_bytes, decrypt_payload, make_envelope, parse_server_event};

pub struct LiveMessage {
    pub server_id: u128,
    pub chat_id: u128,
    pub chat_name: String,
    pub sender_id: String,
    pub sender_name: String,
    pub text: String,
    pub timestamp: String,
    pub timestamp_ms: i64,
    pub verification: VerificationStatus,
}

fn parse_payload(raw: &str) -> (String, String, String, Option<Vec<u8>>) {
    let parts: Vec<&str> = raw.splitn(4, '\x1e').collect();
    if parts.len() == 4 {
        let sig = hex::decode(parts[3]).ok();
        (parts[0].to_string(), parts[1].to_string(), parts[2].to_string(), sig)
    } else if parts.len() == 3 {
        (parts[0].to_string(), parts[1].to_string(), parts[2].to_string(), None)
    } else {
        (String::new(), String::new(), raw.to_string(), None)
    }
}

fn verify_message_sig(store: &Store, sender_id: &str, chat_id: u128, text: &str, sig: &[u8]) -> VerificationStatus {
    let sign_material = format!("{:032x}\x1e{}\x1e{}", chat_id, sender_id, text);
    match store.load_contact(sender_id) {
        Ok(contact) => {
            let pk: Key<{ Dilithium2::PUBLIC_KEY_SIZE }> =
                match CryptoKey::from_bytes(&contact.signing_pk_bytes) {
                    Ok(k) => k,
                    Err(_) => return VerificationStatus::CannotVerify,
                };
            match Dilithium2::verify_detached(&pk, sign_material.as_bytes(), sig) {
                Ok(true) => VerificationStatus::Verified,
                _ => VerificationStatus::Tampered,
            }
        }
        Err(_) => VerificationStatus::CannotVerify,
    }
}

pub enum LiveEvent {
    Message(LiveMessage),
    SyncComplete { _server_id: u128, _chat_name: String },
    Error { server_id: u128, message: String },
    ServerUnavailable(u128),
    Disconnected(u128),
    ShareReceived(ShareData),
    TorBootstrap(u8),
}

pub async fn subscribe(
    server_id: u128,
    address: &str,
    shared_key_bytes: &[u8],
    chats: &[(u128, ChatRecord)],
    store: Store,
    cancel: CancellationToken,
    event_tx: mpsc::UnboundedSender<LiveEvent>,
) -> Result<()> {
    m_core::log_info!("live: connecting to server={:032x} address={} chats={}", server_id, address, chats.len());
    for (id, rec) in chats {
        m_core::log_debug!("live: subscribe chat={:032x} last_synced_ts={}", id, rec.last_synced_ts);
    }

    let mut channel_transport = match transport::Transport::connect(address, shared_key_bytes).await {
        Ok(t) => t,
        Err(e) => {
            m_core::log_error!("live: connect failed server={:032x} error={}", server_id, e);
            let _ = event_tx.send(LiveEvent::ServerUnavailable(server_id));
            return Err(e);
        }
    };
    let cipher = channel_transport.cipher().clone();
    m_core::log_info!("live: transport connected server={:032x}", server_id);

    let (tx, mut inbound) = match channel_transport.open_channel().await {
        Ok(pair) => pair,
        Err(e) => {
            m_core::log_error!("live: open_channel failed server={:032x} error={}", server_id, e);
            let _ = event_tx.send(LiveEvent::ServerUnavailable(server_id));
            return Err(e);
        }
    };
    m_core::log_info!("live: channel opened server={:032x}", server_id);

    let chat_keys: HashMap<u128, Vec<u8>> = chats.iter()
        .map(|(id, rec)| (*id, rec.encryption_key_bytes.clone()))
        .collect();

    let subscriptions: Vec<ChatSubscription> = chats.iter()
        .map(|(id, rec)| ChatSubscription {
            chat_id: chat_id_bytes(*id),
            latest_timestamp_ms: if rec.last_synced_ts > 0 { rec.last_synced_ts as u64 } else { 0 },
        })
        .collect();
    let subscriptions_count = subscriptions.len();

    let subscribe_event = ClientEvent {
        event: Some(client_event::Event::Subscribe(SubscribeRequest {
            chats: subscriptions,
        })),
    };
    let envelope = make_envelope(&cipher, &subscribe_event)?;
    tx.send(envelope).await.context("failed to send subscribe")?;
    m_core::log_info!("live: subscribe sent server={:032x} chats={}", server_id, subscriptions_count);

    let chat_names: HashMap<u128, String> = chats.iter()
        .map(|(id, rec)| (*id, rec.name.clone()))
        .collect();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            item = inbound.next() => {
                let Some(result) = item else {
                    m_core::log_info!("live: inbound stream closed server={:032x}", server_id);
                    break;
                };
                let envelope = match result {
                    Ok(e) => e,
                    Err(e) => {
                        m_core::log_error!("live: stream error server={:032x} error={}", server_id, e);
                        let _ = event_tx.send(LiveEvent::Error {
                            server_id,
                            message: format!("Stream error: {e}"),
                        });
                        break;
                    }
                };

                let server_event: ServerEvent = match parse_server_event(&cipher, &envelope) {
                    Ok(e) => e,
                    Err(e) => {
                        m_core::log_error!("live: parse_server_event failed server={:032x} error={}", server_id, e);
                        let _ = event_tx.send(LiveEvent::Error {
                            server_id,
                            message: format!("Decrypt error: {e}"),
                        });
                        continue;
                    }
                };

                match server_event.event {
                    Some(server_event::Event::Message(msg)) => {
                        let chat_id = match chat_id_from_bytes(&msg.chat_id) {
                            Ok(id) => id,
                            Err(e) => {
                                m_core::log_warn!("live: invalid chat_id in message server={:032x}: {}", server_id, e);
                                continue;
                            }
                        };
                        m_core::log_debug!("live: message received server={:032x} chat={:032x} ts={} id={}", server_id, chat_id, msg.timestamp_ms, msg.message_id);
                        if !chat_keys.contains_key(&chat_id) {
                            m_core::log_warn!("live: message for unknown chat={:032x} server={:032x}, skipping", chat_id, server_id);
                            continue;
                        }

                        let chat_name = chat_names.get(&chat_id)
                            .cloned()
                            .unwrap_or_else(|| format!("{:08x}", chat_id));

                        let raw = match chat_keys.get(&chat_id) {
                            Some(key) => match decrypt_payload(&msg.encrypted_payload, key, chat_id) {
                                Ok(t) => t,
                                Err(e) => {
                                    m_core::log_warn!("live: decrypt_payload failed server={:032x} chat={:032x} ts={} error={}", server_id, chat_id, msg.timestamp_ms, e);
                                    "<decryption failed>".to_string()
                                }
                            },
                            None => continue,
                        };

                        let (sender_id, sender_name, text, sig_opt) = parse_payload(&raw);

                        let verification = match &sig_opt {
                            Some(sig) => verify_message_sig(&store, &sender_id, chat_id, &text, sig),
                            None => VerificationStatus::NoSignature,
                        };

                        let ts = match chrono::DateTime::from_timestamp_millis(msg.timestamp_ms) {
                            Some(dt) => dt.format("%H:%M").to_string(),
                            None => {
                                m_core::log_warn!("live: invalid timestamp_ms={} server={:032x} chat={:032x}, using raw value", msg.timestamp_ms, server_id, chat_id);
                                msg.timestamp_ms.to_string()
                            }
                        };

                        if let Err(e) = store.save_message(&StoredMessage {
                            chat_id,
                            message_id: msg.message_id.clone(),
                            timestamp_ms: msg.timestamp_ms,
                            text: text.clone(),
                            sender: Some(format!("{}\x1e{}", sender_id, sender_name)),
                            verification: verification.clone(),
                        }) {
                            m_core::log_warn!("live: save_message failed server={:032x} chat={:032x} ts={} error={}", server_id, chat_id, msg.timestamp_ms, e);
                        }

                        let _ = event_tx.send(LiveEvent::Message(LiveMessage {
                            server_id,
                            chat_id,
                            chat_name,
                            sender_id,
                            sender_name,
                            text,
                            timestamp: ts,
                            timestamp_ms: msg.timestamp_ms,
                            verification,
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
                                    m_core::log_warn!("live: ack send failed server={:032x} chat={:032x} ts={} error={}", server_id, chat_id, msg.timestamp_ms, e);
                                }
                            }
                            Err(e) => {
                                m_core::log_warn!("live: ack envelope build failed server={:032x} chat={:032x} error={}", server_id, chat_id, e);
                            }
                        }
                    }
                    Some(server_event::Event::SyncComplete(sync)) => {
                        let chat_id = match chat_id_from_bytes(&sync.chat_id) {
                            Ok(id) => id,
                            Err(e) => {
                                m_core::log_warn!("live: invalid chat_id in SyncComplete server={:032x}: {}", server_id, e);
                                continue;
                            }
                        };
                        m_core::log_debug!("live: SyncComplete server={:032x} chat={:032x} synced_up_ts={}", server_id, chat_id, sync.synced_up_timestamp_ms);
                        if let Err(e) = store.update_chat_sync_ts(server_id, chat_id, sync.synced_up_timestamp_ms as i64) {
                            m_core::log_error!("live: update_chat_sync_ts failed server={:032x} chat={:032x} ts={}: {}", server_id, chat_id, sync.synced_up_timestamp_ms, e);
                        }
                        let chat_name = chat_names.get(&chat_id)
                            .cloned()
                            .unwrap_or_else(|| format!("{:08x}", chat_id));
                        let _ = event_tx.send(LiveEvent::SyncComplete {
                            _server_id: server_id,
                            _chat_name: chat_name,
                        });
                    }
                    Some(server_event::Event::Error(err)) => {
                        m_core::log_error!("live: server error server={:032x} code={} message={}", server_id, err.code, err.message);
                        let _ = event_tx.send(LiveEvent::Error {
                            server_id,
                            message: format!("Server error [{}]: {}", err.code, err.message),
                        });
                    }
                    None => {
                        m_core::log_warn!("live: received event with no payload server={:032x}", server_id);
                    }
                }
            }
        }
    }

    m_core::log_info!("live: subscribe loop exited server={:032x}, sending Disconnected", server_id);
    let _ = event_tx.send(LiveEvent::Disconnected(server_id));
    Ok(())
}
