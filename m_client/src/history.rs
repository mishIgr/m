use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AppMessage {
    #[serde(rename = "message")]
    Text { text: String },

    #[serde(rename = "history_request")]
    HistoryRequest {
        request_id: String,
        from_timestamp_ms: u64,
        to_timestamp_ms: u64,
    },

    #[serde(rename = "history_response")]
    HistoryResponse {
        request_id: String,
        messages: Vec<HistoryEntry>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HistoryEntry {
    pub message_id: String,
    pub timestamp_ms: i64,
    pub encrypted_payload_b64: String,
}
