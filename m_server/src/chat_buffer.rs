use std::collections::VecDeque;
use std::num::NonZeroUsize;
use lru::LruCache;

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub message_id: String,
    pub timestamp_ms: i64,
    pub encrypted_payload: Vec<u8>,
}

pub struct ChatBuffer {
    pub chat_id: String,
    pub max_messages: u32,
    pub max_bytes: u64,
    messages: VecDeque<StoredMessage>,
    current_bytes: u64,
    seen_ids: LruCache<String, i64>,
}

impl ChatBuffer {
    pub fn new(chat_id: String, max_messages: u32, max_bytes: u64, dedup_cache_size: usize) -> Self {
        Self {
            chat_id,
            max_messages,
            max_bytes,
            messages: VecDeque::new(),
            current_bytes: 0,
            seen_ids: LruCache::new(NonZeroUsize::new(dedup_cache_size).unwrap()),
        }
    }

    /// Возвращает (timestamp_ms, is_new)
    pub fn push(&mut self, message_id: String, encrypted_payload: Vec<u8>) -> (i64, bool) {
        if let Some(&existing_ts) = self.seen_ids.get(&message_id) {
            m_core::log_debug!("chat_buffer: push dedup hit chat={} message_id={} original_ts={}", self.chat_id, message_id, existing_ts);
            return (existing_ts, false);
        }

        let ts = chrono::Utc::now().timestamp_millis();
        let size = encrypted_payload.len() as u64;

        self.messages.push_back(StoredMessage {
            message_id: message_id.clone(),
            timestamp_ms: ts,
            encrypted_payload,
        });

        self.current_bytes += size;
        self.seen_ids.put(message_id.clone(), ts);
        m_core::log_debug!("chat_buffer: push accepted chat={} message_id={} ts={} payload_bytes={} count={}", self.chat_id, message_id, ts, size, self.messages.len());
        self.evict();

        (ts, true)
    }

    fn evict(&mut self) {
        let before_count = self.messages.len();
        let before_bytes = self.current_bytes;
        while self.messages.len() > self.max_messages as usize || self.current_bytes > self.max_bytes {
            match self.messages.pop_front() {
                Some(old) => self.current_bytes -= old.encrypted_payload.len() as u64,
                None => break,
            }
        }
        let evicted = before_count - self.messages.len();
        if evicted > 0 {
            m_core::log_warn!("chat_buffer: evict chat={} evicted_count={} freed_bytes={} remaining_count={} remaining_bytes={}", self.chat_id, evicted, before_bytes - self.current_bytes, self.messages.len(), self.current_bytes);
        }
    }

    pub fn get_range(&self, from_ms: i64, to_ms: i64) -> Vec<&StoredMessage> {
        self.messages
            .iter()
            .filter(|m| m.timestamp_ms >= from_ms && (to_ms == 0 || m.timestamp_ms <= to_ms))
            .collect()
    }

    pub fn get_after(&self, after_ms: i64) -> Vec<&StoredMessage> {
        self.messages
            .iter()
            .filter(|m| m.timestamp_ms > after_ms)
            .collect()
    }

    pub fn earliest_timestamp_ms(&self) -> u64 {
        self.messages.front().map(|m| m.timestamp_ms as u64).unwrap_or(0)
    }

    pub fn latest_timestamp_ms(&self) -> u64 {
        self.messages.back().map(|m| m.timestamp_ms as u64).unwrap_or(0)
    }
}
