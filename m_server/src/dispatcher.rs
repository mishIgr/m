use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use m_core::proto::*;
use crate::chat_buffer::ChatBuffer;

#[derive(Debug, Clone)]
pub struct DeliverySettings {
    pub ack_timeout_secs: u64,
    pub max_retries: u32,
}

pub struct PendingAck {
    pub message: ChatMessage,
    pub attempts: u32,
    pub next_retry_at: Instant,
}

pub struct ConnectionState {
    pub stream_tx: mpsc::Sender<ServerEvent>,
    pub subscribed_chats: HashSet<String>,
    pub pending_acks: HashMap<(String, i64), PendingAck>,
}

pub struct Dispatcher {
    pub chat_buffers: HashMap<String, ChatBuffer>,
    pub subscriptions: HashMap<String, HashSet<u64>>,
    pub connections: HashMap<u64, ConnectionState>,
    next_conn_id: u64,
    delivery_config: DeliverySettings,
}

impl Dispatcher {
    pub fn new(delivery_config: DeliverySettings) -> Self {
        Self {
            chat_buffers: HashMap::new(),
            subscriptions: HashMap::new(),
            connections: HashMap::new(),
            next_conn_id: 1,
            delivery_config,
        }
    }

    pub fn register_connection(&mut self, tx: mpsc::Sender<ServerEvent>) -> u64 {
        let id = self.next_conn_id;
        self.next_conn_id += 1;
        self.connections.insert(id, ConnectionState {
            stream_tx: tx,
            subscribed_chats: HashSet::new(),
            pending_acks: HashMap::new(),
        });
        m_core::log_info!("Connection registered: {}", id);
        id
    }

    pub fn remove_connection(&mut self, conn_id: u64) {
        if let Some(conn) = self.connections.remove(&conn_id) {
            for chat_id in &conn.subscribed_chats {
                if let Some(subs) = self.subscriptions.get_mut(chat_id) {
                    subs.remove(&conn_id);
                }
            }
        }
        m_core::log_info!("Connection removed: {}", conn_id);
    }

    pub async fn subscribe(&mut self, conn_id: u64, chats: Vec<ChatSubscription>) {
        for chat in chats {
            self.add_subscription(conn_id, &chat.chat_id, chat.latest_timestamp_ms as i64).await;
        }
    }

    async fn add_subscription(&mut self, conn_id: u64, chat_id: &str, last_ts: i64) {
        let Some(buffer) = self.chat_buffers.get(chat_id) else { return };

        let messages: Vec<_> = buffer.get_after(last_ts).into_iter().cloned().collect();
        let latest = buffer.latest_timestamp_ms();

        self.subscriptions
            .entry(chat_id.to_string())
            .or_default()
            .insert(conn_id);

        let Some(conn) = self.connections.get_mut(&conn_id) else { return };
        conn.subscribed_chats.insert(chat_id.to_string());

        let timeout = Duration::from_secs(self.delivery_config.ack_timeout_secs);

        for msg in messages {
            let chat_msg = ChatMessage {
                chat_id: chat_id.to_string(),
                message_id: msg.message_id.clone(),
                timestamp_ms: msg.timestamp_ms,
                encrypted_payload: msg.encrypted_payload.clone(),
            };

            conn.pending_acks.insert(
                (chat_id.to_string(), msg.timestamp_ms),
                PendingAck {
                    message: chat_msg.clone(),
                    attempts: 1,
                    next_retry_at: Instant::now() + timeout,
                },
            );

            let _ = conn.stream_tx.send(ServerEvent {
                event: Some(server_event::Event::Message(chat_msg)),
            }).await;
        }

        let _ = conn.stream_tx.send(ServerEvent {
            event: Some(server_event::Event::SyncComplete(SyncComplete {
                chat_id: chat_id.to_string(),
                synced_up_timestamp_ms: latest,
            })),
        }).await;
    }

    pub async fn fanout(&mut self, chat_id: &str, message: &ChatMessage) {
        let conn_ids: Vec<u64> = self.subscriptions
            .get(chat_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();

        let timeout = Duration::from_secs(self.delivery_config.ack_timeout_secs);

        for conn_id in conn_ids {
            let Some(conn) = self.connections.get_mut(&conn_id) else { continue };

            conn.pending_acks.insert(
                (chat_id.to_string(), message.timestamp_ms),
                PendingAck {
                    message: message.clone(),
                    attempts: 1,
                    next_retry_at: Instant::now() + timeout,
                },
            );

            let _ = conn.stream_tx.send(ServerEvent {
                event: Some(server_event::Event::Message(message.clone())),
            }).await;
        }
    }

    pub fn handle_ack(&mut self, conn_id: u64, ack: &MessageAck) {
        if let Some(conn) = self.connections.get_mut(&conn_id) {
            conn.pending_acks.remove(&(ack.chat_id.clone(), ack.timestamp_ms as i64));
            m_core::log_debug!("Ack: conn={} chat={} ts={}", conn_id, ack.chat_id, ack.timestamp_ms);
        }
    }

    pub async fn retry_pending(&mut self) {
        let max_retries = self.delivery_config.max_retries;
        let timeout = Duration::from_secs(self.delivery_config.ack_timeout_secs);
        let now = Instant::now();

        let conn_ids: Vec<u64> = self.connections.keys().cloned().collect();

        for conn_id in conn_ids {
            let Some(conn) = self.connections.get_mut(&conn_id) else { continue };
            let tx = conn.stream_tx.clone();
            let mut to_remove = Vec::new();

            for (key, pending) in conn.pending_acks.iter_mut() {
                if now < pending.next_retry_at { continue; }

                if pending.attempts >= max_retries {
                    m_core::log_warn!("Max retries: conn={} chat={} ts={}", conn_id, key.0, key.1);
                    to_remove.push(key.clone());
                    continue;
                }

                pending.attempts += 1;
                pending.next_retry_at = now + timeout * pending.attempts;

                let _ = tx.send(ServerEvent {
                    event: Some(server_event::Event::Message(pending.message.clone())),
                }).await;

                m_core::log_debug!("Retry #{}: conn={} chat={} ts={}", pending.attempts, conn_id, key.0, key.1);
            }

            for key in to_remove {
                conn.pending_acks.remove(&key);
            }
        }
    }
}
