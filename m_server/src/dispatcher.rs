use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use m_core::db::{RedbTable, Table};
use m_core::proto::*;
use crate::chat_buffer::ChatBuffer;
use crate::config::DeliveryConfig;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatMeta {
    pub name: String,
    pub max_messages: u32,
    pub max_bytes: u64,
}

pub struct PendingAck {
    pub message: ChatMessage,
    pub attempts: u32,
    pub next_retry_at: Instant,
}

pub struct ConnectionState {
    pub stream_tx: mpsc::Sender<ServerEvent>,
    pub subscribed_chats: HashSet<u128>,
    pub pending_acks: HashMap<(u128, i64), PendingAck>,
}

pub struct Dispatcher {
    pub chat_buffers: HashMap<u128, ChatBuffer>,
    pub subscriptions: HashMap<u128, HashSet<u64>>,
    pub connections: HashMap<u64, ConnectionState>,
    next_conn_id: u64,
    delivery_config: DeliveryConfig,
    dedup_cache_size: usize,
    chats_table: RedbTable<String, ChatMeta>,
}

fn u128_key(id: u128) -> String {
    format!("{:032x}", id)
}

pub fn bytes_to_u128(b: &[u8]) -> anyhow::Result<u128> {
    let arr: [u8; 16] = b.try_into()
        .map_err(|_| anyhow::anyhow!("chat_id must be 16 bytes, got {}", b.len()))?;
    Ok(u128::from_be_bytes(arr))
}

impl Dispatcher {
    pub fn new(
        delivery_config: DeliveryConfig,
        dedup_cache_size: usize,
        chats_table: RedbTable<String, ChatMeta>,
    ) -> Result<Self, m_core::db::KvError> {
        let mut chat_buffers = HashMap::new();
        for (key, meta) in chats_table.iter()? {
            let chat_id = u128::from_str_radix(&key, 16).unwrap_or(0);
            m_core::log_info!("Restored chat: {:032x} name={}", chat_id, meta.name);
            chat_buffers.insert(
                chat_id,
                ChatBuffer::new(chat_id, meta.name.clone(), meta.max_messages, meta.max_bytes, dedup_cache_size),
            );
        }
        Ok(Self {
            chat_buffers,
            subscriptions: HashMap::new(),
            connections: HashMap::new(),
            next_conn_id: 1,
            delivery_config,
            dedup_cache_size,
            chats_table,
        })
    }

    pub fn create_chat(
        &mut self,
        chat_id: u128,
        name: &str,
        max_messages: u32,
        max_bytes: u64,
    ) -> Result<bool, m_core::db::KvError> {
        if self.chat_buffers.contains_key(&chat_id) {
            return Ok(false);
        }
        let meta = ChatMeta { name: name.to_string(), max_messages, max_bytes };
        self.chats_table.put(&u128_key(chat_id), &meta)?;
        self.chat_buffers.insert(
            chat_id,
            ChatBuffer::new(chat_id, name.to_string(), max_messages, max_bytes, self.dedup_cache_size),
        );
        m_core::log_info!("Chat created: {:032x} name={}", chat_id, name);
        Ok(true)
    }

    pub fn delete_chat(&mut self, chat_id: u128) -> Result<bool, m_core::db::KvError> {
        if self.chat_buffers.remove(&chat_id).is_none() {
            return Ok(false);
        }
        self.chats_table.delete(&u128_key(chat_id))?;
        self.subscriptions.remove(&chat_id);
        m_core::log_info!("Chat deleted: {:032x}", chat_id);
        Ok(true)
    }

    pub fn list_chats(&self) -> Vec<ChatInfo> {
        self.chat_buffers
            .values()
            .map(|buf| ChatInfo {
                chat_id: buf.chat_id.to_be_bytes().to_vec(),
                name: buf.name.clone(),
                latest_timestamp_ms: buf.latest_timestamp_ms(),
                earliest_timestamp_ms: buf.earliest_timestamp_ms(),
            })
            .collect()
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
            let pending_count = conn.pending_acks.len();
            let subscribed = conn.subscribed_chats.len();
            for chat_id in &conn.subscribed_chats {
                if let Some(subs) = self.subscriptions.get_mut(chat_id) {
                    subs.remove(&conn_id);
                }
            }
            m_core::log_info!("dispatcher: remove_connection conn={} subscribed_chats={} abandoned_pending_acks={}", conn_id, subscribed, pending_count);
        } else {
            m_core::log_warn!("dispatcher: remove_connection conn={} not found (already removed?)", conn_id);
        }
    }

    pub async fn subscribe(&mut self, conn_id: u64, chats: Vec<ChatSubscription>) {
        for chat in chats {
            let chat_id = match bytes_to_u128(&chat.chat_id) {
                Ok(id) => id,
                Err(e) => {
                    m_core::log_warn!("dispatcher: subscribe invalid chat_id conn={}: {}", conn_id, e);
                    continue;
                }
            };
            self.add_subscription(conn_id, chat_id, chat.latest_timestamp_ms as i64).await;
        }
    }

    async fn add_subscription(&mut self, conn_id: u64, chat_id: u128, last_ts: i64) {
        let Some(buffer) = self.chat_buffers.get(&chat_id) else {
            m_core::log_warn!("dispatcher: add_subscription chat not found conn={} chat={:032x}", conn_id, chat_id);
            return;
        };

        let messages: Vec<_> = buffer.get_after(last_ts).into_iter().cloned().collect();
        let latest = buffer.latest_timestamp_ms();
        let chat_id_bytes = chat_id.to_be_bytes().to_vec();
        m_core::log_debug!("dispatcher: add_subscription conn={} chat={:032x} last_ts={} catchup_count={} latest_ts={}", conn_id, chat_id, last_ts, messages.len(), latest);

        self.subscriptions
            .entry(chat_id)
            .or_default()
            .insert(conn_id);

        let Some(conn) = self.connections.get_mut(&conn_id) else { return };
        conn.subscribed_chats.insert(chat_id);

        let timeout = Duration::from_secs(self.delivery_config.ack_timeout_secs);

        for msg in messages {
            let chat_msg = ChatMessage {
                chat_id: chat_id_bytes.clone(),
                message_id: msg.message_id.clone(),
                timestamp_ms: msg.timestamp_ms,
                encrypted_payload: msg.encrypted_payload.clone(),
            };

            conn.pending_acks.insert(
                (chat_id, msg.timestamp_ms),
                PendingAck {
                    message: chat_msg.clone(),
                    attempts: 1,
                    next_retry_at: Instant::now() + timeout,
                },
            );

            if let Err(e) = conn.stream_tx.send(ServerEvent {
                event: Some(server_event::Event::Message(chat_msg)),
            }).await {
                m_core::log_warn!("dispatcher: add_subscription send failed conn={} chat={:032x} ts={}: {}", conn_id, chat_id, msg.timestamp_ms, e);
            }
        }

        if let Err(e) = conn.stream_tx.send(ServerEvent {
            event: Some(server_event::Event::SyncComplete(SyncComplete {
                chat_id: chat_id_bytes,
                synced_up_timestamp_ms: latest,
            })),
        }).await {
            m_core::log_warn!("dispatcher: add_subscription SyncComplete send failed conn={} chat={:032x}: {}", conn_id, chat_id, e);
        } else {
            m_core::log_debug!("dispatcher: add_subscription SyncComplete sent conn={} chat={:032x} latest_ts={}", conn_id, chat_id, latest);
        }
    }

    pub async fn fanout(&mut self, chat_id: u128, message: &ChatMessage) {
        let conn_ids: Vec<u64> = self.subscriptions
            .get(&chat_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        m_core::log_debug!("dispatcher: fanout chat={:032x} subscriber_count={} msg_ts={} msg_id={}", chat_id, conn_ids.len(), message.timestamp_ms, message.message_id);

        let timeout = Duration::from_secs(self.delivery_config.ack_timeout_secs);

        for conn_id in conn_ids {
            let Some(conn) = self.connections.get_mut(&conn_id) else { continue };

            conn.pending_acks.insert(
                (chat_id, message.timestamp_ms),
                PendingAck {
                    message: message.clone(),
                    attempts: 1,
                    next_retry_at: Instant::now() + timeout,
                },
            );

            if let Err(e) = conn.stream_tx.send(ServerEvent {
                event: Some(server_event::Event::Message(message.clone())),
            }).await {
                m_core::log_warn!("dispatcher: fanout send failed conn={} chat={:032x} ts={}: {}", conn_id, chat_id, message.timestamp_ms, e);
            }
        }
    }

    pub fn handle_ack(&mut self, conn_id: u64, ack: &MessageAck) {
        let chat_id = match bytes_to_u128(&ack.chat_id) {
            Ok(id) => id,
            Err(e) => {
                m_core::log_warn!("dispatcher: handle_ack invalid chat_id conn={}: {}", conn_id, e);
                return;
            }
        };
        if let Some(conn) = self.connections.get_mut(&conn_id) {
            let key = (chat_id, ack.timestamp_ms as i64);
            if conn.pending_acks.remove(&key).is_some() {
                m_core::log_debug!("dispatcher: handle_ack matched conn={} chat={:032x} ts={}", conn_id, chat_id, ack.timestamp_ms);
            } else {
                m_core::log_warn!("dispatcher: handle_ack NOT FOUND conn={} chat={:032x} ts={} (duplicate or mismatch)", conn_id, chat_id, ack.timestamp_ms);
            }
        } else {
            m_core::log_warn!("dispatcher: handle_ack unknown conn={} chat={:032x} ts={}", conn_id, chat_id, ack.timestamp_ms);
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
                    m_core::log_warn!("Max retries: conn={} chat={:032x} ts={}", conn_id, key.0, key.1);
                    to_remove.push(key.clone());
                    continue;
                }

                pending.attempts += 1;
                pending.next_retry_at = now + timeout * pending.attempts;

                if let Err(e) = tx.send(ServerEvent {
                    event: Some(server_event::Event::Message(pending.message.clone())),
                }).await {
                    m_core::log_warn!("dispatcher: retry_pending send failed conn={} chat={:032x} ts={} attempt={}: {}", conn_id, key.0, key.1, pending.attempts, e);
                } else {
                    m_core::log_debug!("dispatcher: retry_pending sent conn={} chat={:032x} ts={} attempt={}", conn_id, key.0, key.1, pending.attempts);
                }
            }

            for key in to_remove {
                conn.pending_acks.remove(&key);
            }
        }
    }
}
