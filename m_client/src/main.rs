use std::collections::HashMap;
use std::path::Path;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

use m_core::proto::messenger::*;
use m_core::config::load_client_config;

mod connection;
mod crypto;
mod history;

use connection::Connection;
use history::AppMessage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config/client.toml".to_string());

    let config = load_client_config(Path::new(&config_path))?;

    let mut chat_keys: HashMap<String, Vec<u8>> = HashMap::new();
    for (chat_id, hex_key) in &config.chats.keys {
        chat_keys.insert(chat_id.clone(), hex::decode(hex_key)?);
    }

    let mut conn = Connection::connect(
        &config.connection.server_address,
        config.auth.shared_key.clone(),
    ).await?;
    info!("Connected to {}", config.connection.server_address);

    let (tx, mut rx) = conn.open_channel().await?;
    info!("Channel opened");

    let subs: Vec<ChatSubscription> = chat_keys.keys().map(|id| ChatSubscription {
        chat_id: id.clone(),
        latest_timestamp_ms: 0,
    }).collect();

    if !subs.is_empty() {
        tx.send(ClientEvent {
            event: Some(client_event::Event::Subscribe(SubscribeRequest { chats: subs })),
        }).await?;
        info!("Subscribed to {} chats", chat_keys.len());
    }

    let tx_recv = tx.clone();
    let chat_keys_recv = chat_keys.clone();

    let recv_handle = tokio::spawn(async move {
        while let Some(Ok(server_event)) = rx.next().await {
            let Some(event) = server_event.event else { continue };

            match event {
                server_event::Event::Message(msg) => {
                    if let Some(key) = chat_keys_recv.get(&msg.chat_id) {
                        match crypto::decrypt(key, &msg.encrypted_payload) {
                            Ok(plaintext) => match serde_json::from_slice::<AppMessage>(&plaintext) {
                                Ok(AppMessage::Text { text }) => {
                                    println!("[{}@{}] {}", msg.chat_id, msg.timestamp_ms, text);
                                }
                                Ok(AppMessage::HistoryRequest { request_id, from_timestamp_ms, to_timestamp_ms }) => {
                                    info!("History request: {} ts {}..{}", request_id, from_timestamp_ms, to_timestamp_ms);
                                }
                                Ok(AppMessage::HistoryResponse { request_id, messages }) => {
                                    info!("History response: {} ({} msgs)", request_id, messages.len());
                                }
                                Err(e) => warn!("Parse error: {}", e),
                            },
                            Err(e) => warn!("Decrypt failed [{}]: {}", msg.chat_id, e),
                        }
                    } else {
                        warn!("No key for chat: {}", msg.chat_id);
                    }

                    let _ = tx_recv.send(ClientEvent {
                        event: Some(client_event::Event::Ack(MessageAck {
                            chat_id: msg.chat_id,
                            timestamp_ms: msg.timestamp_ms as u64,
                        })),
                    }).await;
                }

                server_event::Event::SyncComplete(s) => {
                    info!("Sync complete: {} up to ts {}", s.chat_id, s.synced_up_timestamp_ms);
                }

                server_event::Event::Error(e) => {
                    error!("Server error: [{}] {}", e.code, e.message);
                }
            }
        }
    });

    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    println!("Commands:");
    println!("  /send <chat> <text>");
    println!("  /sub <chat> [last_ts]");
    println!("  /create <chat>");
    println!("  /delete <chat>");
    println!("  /list");
    println!("  /history <chat> <from_ts> <to_ts>");
    println!("  /addkey <chat> <hex_key>");
    println!("  /quit");

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() { continue; }

        let parts: Vec<&str> = line.splitn(3, ' ').collect();

        match parts[0] {
            "/send" => {
                if parts.len() < 3 { println!("Usage: /send <chat> <text>"); continue; }
                let (chat_id, text) = (parts[1], parts[2]);

                if let Some(key) = chat_keys.get(chat_id) {
                    let app_msg = AppMessage::Text { text: text.to_string() };
                    let json = serde_json::to_vec(&app_msg).unwrap();
                    match crypto::encrypt(key, &json) {
                        Ok(enc) => match conn.send_message(chat_id, enc).await {
                            Ok(r) if r.accepted => println!("Sent: ts={}", r.timestamp_ms),
                            Ok(r) => println!("Rejected: {}", r.error),
                            Err(e) => println!("Error: {}", e),
                        },
                        Err(e) => println!("Encrypt error: {}", e),
                    }
                } else {
                    println!("No key for chat: {}", chat_id);
                }
            }

            "/sub" => {
                if parts.len() < 2 { println!("Usage: /sub <chat> [last_ts]"); continue; }
                let chat_id = parts[1];
                let last_ts: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

                let _ = tx.send(ClientEvent {
                    event: Some(client_event::Event::Subscribe(SubscribeRequest {
                        chats: vec![ChatSubscription {
                            chat_id: chat_id.to_string(),
                            latest_timestamp_ms: last_ts,
                        }],
                    })),
                }).await;
            }

            "/create" => {
                if parts.len() < 2 { println!("Usage: /create <chat>"); continue; }
                match conn.create_chat(parts[1]).await {
                    Ok(r) if r.success => println!("Created: {}", parts[1]),
                    Ok(r) => println!("Failed: {}", r.error),
                    Err(e) => println!("Error: {}", e),
                }
            }

            "/delete" => {
                if parts.len() < 2 { println!("Usage: /delete <chat>"); continue; }
                match conn.delete_chat(parts[1]).await {
                    Ok(r) if r.success => println!("Deleted: {}", parts[1]),
                    Ok(r) => println!("Failed: {}", r.error),
                    Err(e) => println!("Error: {}", e),
                }
            }

            "/list" => match conn.list_chats().await {
                Ok(chats) => {
                    if chats.is_empty() { println!("No chats"); }
                    for c in chats {
                        println!("  {} | ts:{}..{}", c.chat_id, c.earliest_timestamp_ms, c.latest_timestamp_ms);
                    }
                }
                Err(e) => println!("Error: {}", e),
            },

            "/history" => {
                let args: Vec<&str> = line.splitn(4, ' ').collect();
                if args.len() < 4 { println!("Usage: /history <chat> <from_ts> <to_ts>"); continue; }
                let chat_id = args[1];
                let from: u64 = args[2].parse().unwrap_or(0);
                let to: u64 = args[3].parse().unwrap_or(0);

                match conn.get_history(chat_id, from, to, 100).await {
                    Ok(r) => {
                        println!("History ({} msgs):", r.messages.len());
                        for m in r.messages {
                            if let Some(key) = chat_keys.get(chat_id) {
                                match crypto::decrypt(key, &m.encrypted_payload) {
                                    Ok(pt) => println!("  [@{}] {}", m.timestamp_ms, String::from_utf8_lossy(&pt)),
                                    Err(_) => println!("  [@{}] <decrypt failed>", m.timestamp_ms),
                                }
                            }
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }

            "/addkey" => {
                let args: Vec<&str> = line.splitn(3, ' ').collect();
                if args.len() < 3 { println!("Usage: /addkey <chat> <hex_key>"); continue; }
                match hex::decode(args[2]) {
                    Ok(key) => { chat_keys.insert(args[1].to_string(), key); println!("Key added: {}", args[1]); }
                    Err(e) => println!("Invalid hex: {}", e),
                }
            }

            "/quit" => { println!("Bye!"); break; }

            _ => println!("Unknown command"),
        }
    }

    recv_handle.abort();
    Ok(())
}
