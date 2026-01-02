use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers, EnableBracketedPaste, DisableBracketedPaste};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::identity::ContactCard;
use crate::sharing::{ShareData, ServerShareData, ChatShareData};
use crate::config::ClientConfig;
use crate::connection_manager::ConnectionManager;
use crate::live::LiveEvent;
use crate::store::{NodeState, Store};
use crate::transport::Transport;

const MAX_LINES: usize = 2000;

struct App {
    left_lines: VecDeque<String>,
    right_lines: VecDeque<String>,
    input: String,
    cursor_pos: usize,
    live_on: bool,
    left_scroll: u16,
    right_scroll: u16,
}

impl App {
    fn new() -> Self {
        Self {
            left_lines: VecDeque::new(),
            right_lines: VecDeque::new(),
            input: String::new(),
            cursor_pos: 0,
            live_on: false,
            left_scroll: 0,
            right_scroll: 0,
        }
    }

    fn push_left(&mut self, line: String) {
        self.left_lines.push_back(line);
        if self.left_lines.len() > MAX_LINES {
            self.left_lines.pop_front();
        }
        self.left_scroll = self.left_lines.len().saturating_sub(1) as u16;
    }

    fn push_right(&mut self, line: String) {
        self.right_lines.push_back(line);
        if self.right_lines.len() > MAX_LINES {
            self.right_lines.pop_front();
        }
        self.right_scroll = self.right_lines.len().saturating_sub(1) as u16;
    }
}

enum CmdResult {
    Output,
    Quit,
    Clear,
}

fn parse_command(input: &str) -> CmdResult {
    let input = input.trim();
    if input.is_empty() {
        return CmdResult::Output;
    }

    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        "quit" | "exit" | "q" => CmdResult::Quit,
        "clear" | "cls" => CmdResult::Clear,
        _ => CmdResult::Output,
    }
}

async fn execute_command(
    input: &str,
    store: &Store,
    manager: &mut ConnectionManager,
    event_tx: &mpsc::UnboundedSender<LiveEvent>,
    share_state: &mut Option<(CancellationToken, Option<tokio::process::Child>)>,
) -> Vec<String> {
    let input = input.trim();
    let words: Vec<&str> = input.split_whitespace().collect();
    if words.is_empty() {
        return vec![];
    }
    let cmd = words[0].to_lowercase();

    match cmd.as_str() {
        "help" | "?" => vec![
            "Commands:".into(),
            "  whoami                                            Show own identity".into(),
            "  export-contact <path>                             Export contact card to binary file".into(),
            "  import-contact <path> [name]                      Import contact from binary file".into(),
            "  list contacts                                     List contacts".into(),
            "  rename-contact <id> <new_name>                    Rename a contact".into(),
            "  remove-contact <id>                               Remove a contact".into(),
            "  import-server <path>                              Import server config".into(),
            "  import-chat <path>                                Import chat config".into(),
            "  enable server <id>                                Enable server".into(),
            "  disable server <id>                               Disable server".into(),
            "  enable chat <server_id> <chat_id>                 Enable chat".into(),
            "  disable chat <server_id> <chat_id>                Disable chat".into(),
            "  list servers                                      List servers".into(),
            "  list chats [server_id]                            List chats".into(),
            "  send <server_id> <chat_id> <message>              Send a message".into(),
            "  history <server_id> <chat_id> [--limit N]         Fetch history".into(),
            "  share-listen [port]                               Start Tor share listener".into(),
            "  share-stop                                        Stop share listener".into(),
            "  share server <server_id> <contact_id>             Share server with contact".into(),
            "  share chat <server_id> <chat_id> <contact_id>     Share chat with contact".into(),
            "  admin <server_id> create-chat <id>                Create chat".into(),
            "  admin <server_id> delete-chat <id>                Delete chat".into(),
            "  admin <server_id> list-chats                      List chats on server".into(),
            "  deploy-server <user> <ip> <pass> <server_id>       Deploy server via SSH (keys auto-generated)".into(),
            "  remove-server <user> <ip> <pass> <server_id>      Remove server via SSH and disable locally".into(),
            "  clear                                             Clear output panel".into(),
            "  quit                                              Exit".into(),
        ],
        "whoami" => {
            match store.load_identity() {
                Ok(Some(identity)) => {
                    vec![
                        format!("  ID:         {}", identity.id),
                        format!("  Onion:      {}", {
                            let tor_pk_arr: [u8; 32] = identity.tor_pk_bytes.clone().try_into()
                                .unwrap_or([0u8; 32]);
                            match torut::onion::TorPublicKeyV3::from_bytes(&tor_pk_arr) {
                                Ok(pk) => pk.get_onion_address().to_string(),
                                Err(_) => "<invalid tor key>".into(),
                            }
                        }),
                        format!("  Signing PK: {}", hex::encode(&identity.signing_pk_bytes)),
                    ]
                }
                Ok(None) => vec!["No identity found. Restart the client to generate one.".into()],
                Err(e) => vec![format!("Error: {e}")],
            }
        }
        "export-contact" => {
            if words.len() < 2 {
                return vec!["Usage: export-contact <path>".into()];
            }
            let path = shellexpand::tilde(words[1]);
            match store.load_identity() {
                Ok(Some(identity)) => {
                    let tor_pk_arr: [u8; 32] = match identity.tor_pk_bytes.clone().try_into() {
                        Ok(arr) => arr,
                        Err(_) => return vec!["Error: invalid tor public key length".into()],
                    };
                    let onion_address = match torut::onion::TorPublicKeyV3::from_bytes(&tor_pk_arr) {
                        Ok(pk) => pk.get_onion_address().to_string(),
                        Err(_) => return vec!["Error: invalid tor public key".into()],
                    };
                    let card = ContactCard {
                        signing_pk: identity.signing_pk_bytes.clone(),
                        tor_pk: identity.tor_pk_bytes.clone(),
                        onion_address,
                    };
                    match card.to_bytes() {
                        Ok(bytes) => {
                            match std::fs::write(path.as_ref(), &bytes) {
                                Ok(()) => vec![format!("Contact card exported to {}", path)],
                                Err(e) => vec![format!("Error writing file: {e}")],
                            }
                        }
                        Err(e) => vec![format!("Error serializing: {e}")],
                    }
                }
                Ok(None) => vec!["No identity found. Restart the client to generate one.".into()],
                Err(e) => vec![format!("Error: {e}")],
            }
        }
        "import-contact" => {
            if words.len() < 2 {
                return vec!["Usage: import-contact <path> [name]".into()];
            }
            let path = shellexpand::tilde(words[1]);
            let name = if words.len() >= 3 {
                Some(words[2..].join(" "))
            } else {
                None
            };
            match std::fs::read(path.as_ref()) {
                Ok(bytes) => {
                    match ContactCard::from_bytes(&bytes) {
                        Ok(card) => {
                            let id = card.id();
                            match store.save_contact(&card, name.as_deref()) {
                                Ok(()) => {
                                    let display_name = name.as_deref().unwrap_or(&id);
                                    vec![format!("Contact '{}' ({}) imported", display_name, id)]
                                }
                                Err(e) => vec![format!("Error saving contact: {e}")],
                            }
                        }
                        Err(e) => vec![format!("Error reading contact file: {e}")],
                    }
                }
                Err(e) => vec![format!("Error reading file: {e}")],
            }
        }
        "rename-contact" => {
            if words.len() < 3 {
                return vec!["Usage: rename-contact <id> <new_name>".into()];
            }
            let id = words[1];
            let new_name = words[2..].join(" ");
            match store.rename_contact(id, &new_name) {
                Ok(()) => vec![format!("Contact '{}' renamed to '{}'", id, new_name)],
                Err(e) => vec![format!("Error: {e}")],
            }
        }
        "remove-contact" => {
            if words.len() < 2 {
                return vec!["Usage: remove-contact <id>".into()];
            }
            let id = words[1];
            match store.delete_contact(id) {
                Ok(()) => vec![format!("Contact '{}' removed", id)],
                Err(e) => vec![format!("Error: {e}")],
            }
        }
        "import-server" => {
            if words.len() < 2 {
                return vec!["Usage: import-server <path>".into()];
            }
            let path = shellexpand::tilde(words[1]);
            match crate::config::ServerImport::load(std::path::Path::new(path.as_ref())) {
                Ok(server_toml) => {
                    let id = server_toml.connection.id.clone();
                    match store.save_server(&server_toml) {
                        Ok(()) => vec![format!("Server '{}' imported: {}", id, server_toml.connection.server_address)],
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                Err(e) => vec![format!("Error: {e}")],
            }
        }
        "import-chat" => {
            if words.len() < 2 {
                return vec!["Usage: import-chat <path>".into()];
            }
            let path = shellexpand::tilde(words[1]);
            match crate::config::ChatImport::load(std::path::Path::new(path.as_ref())) {
                Ok(chat_toml) => {
                    match store.save_chat(&chat_toml) {
                        Ok(()) => vec![format!(
                            "Chat imported: {}/{} ({})",
                            chat_toml.server_id, chat_toml.chat_id, chat_toml.name
                        )],
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                Err(e) => vec![format!("Error: {e}")],
            }
        }
        "enable" => {
            if words.len() < 3 {
                return vec!["Usage: enable server <id> | enable chat <server_id> <chat_id>".into()];
            }
            let target = words[1].to_lowercase();
            match target.as_str() {
                "server" => {
                    let id = words[2];
                    match store.set_server_state(id, NodeState::Enabled) {
                        Ok(()) => {
                            if let Err(e) = manager.start_server(id) {
                                vec![
                                    format!("Server '{id}' enabled."),
                                    format!("Warning: could not start connection: {e}"),
                                ]
                            } else {
                                vec![format!("Server '{id}' enabled and connected.")]
                            }
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                "chat" => {
                    if words.len() < 4 {
                        return vec!["Usage: enable chat <server_id> <chat_id>".into()];
                    }
                    let server_id = words[2];
                    let chat_id = words[3];
                    match store.set_chat_state(server_id, chat_id, NodeState::Enabled) {
                        Ok(()) => {
                            let _ = manager.restart_server(server_id);
                            vec![format!("Chat '{server_id}/{chat_id}' enabled.")]
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                _ => vec!["Usage: enable server <id> | enable chat <server_id> <chat_id>".into()],
            }
        }
        "disable" => {
            if words.len() < 3 {
                return vec!["Usage: disable server <id> | disable chat <server_id> <chat_id>".into()];
            }
            let target = words[1].to_lowercase();
            match target.as_str() {
                "server" => {
                    let id = words[2];
                    manager.stop_server(id);
                    match store.set_server_state(id, NodeState::Disabled) {
                        Ok(()) => vec![format!("Server '{id}' disabled.")],
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                "chat" => {
                    if words.len() < 4 {
                        return vec!["Usage: disable chat <server_id> <chat_id>".into()];
                    }
                    let server_id = words[2];
                    let chat_id = words[3];
                    match store.set_chat_state(server_id, chat_id, NodeState::Disabled) {
                        Ok(()) => {
                            let _ = manager.restart_server(server_id);
                            vec![format!("Chat '{server_id}/{chat_id}' disabled.")]
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                _ => vec!["Usage: disable server <id> | disable chat <server_id> <chat_id>".into()],
            }
        }
        "list" => {
            if words.len() < 2 {
                return vec!["Usage: list servers | list chats [server_id] | list contacts".into()];
            }
            let target = words[1].to_lowercase();
            match target.as_str() {
                "contacts" => {
                    match store.list_contacts() {
                        Ok(contacts) => {
                            if contacts.is_empty() {
                                vec!["No contacts.".into()]
                            } else {
                                contacts.iter()
                                    .map(|c| format!("  {} ({}) {}", c.name, c.id, c.onion_address))
                                    .collect()
                            }
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                "servers" => {
                    match store.list_servers() {
                        Ok(servers) => {
                            if servers.is_empty() {
                                vec!["No servers configured.".into()]
                            } else {
                                servers.iter()
                                    .map(|s| {
                                        let running = if manager.is_running(&s.id) { " [live]" } else { "" };
                                        format!("  {} ({}) [{}]{}", s.name, s.address, s.state, running)
                                    })
                                    .collect()
                            }
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                "chats" => {
                    let server_id = words.get(2).copied();
                    match server_id {
                        Some(sid) => {
                            match store.list_chats_for_server(sid) {
                                Ok(chats) => {
                                    if chats.is_empty() {
                                        vec![format!("No chats for server '{sid}'.")]
                                    } else {
                                        chats.iter()
                                            .map(|c| format!("  {}/{} ({}) [{}]", c.server_id, c.chat_id, c.name, c.state))
                                            .collect()
                                    }
                                }
                                Err(e) => vec![format!("Error: {e}")],
                            }
                        }
                        None => {
                            match store.list_servers() {
                                Ok(servers) => {
                                    let mut lines = Vec::new();
                                    for s in &servers {
                                        match store.list_chats_for_server(&s.id) {
                                            Ok(chats) => {
                                                for c in &chats {
                                                    lines.push(format!(
                                                        "  {}/{} ({}) [{}]",
                                                        c.server_id, c.chat_id, c.name, c.state,
                                                    ));
                                                }
                                            }
                                            Err(e) => lines.push(format!("  Error listing chats for '{}': {e}", s.id)),
                                        }
                                    }
                                    if lines.is_empty() {
                                        vec!["No chats configured.".into()]
                                    } else {
                                        lines
                                    }
                                }
                                Err(e) => vec![format!("Error: {e}")],
                            }
                        }
                    }
                }
                _ => vec!["Usage: list servers | list chats [server_id] | list contacts".into()],
            }
        }
        "send" => {
            // send <server_id> <chat_id> <message...>
            let parts: Vec<&str> = input.splitn(4, ' ').collect();
            if parts.len() < 4 {
                return vec!["Usage: send <server_id> <chat_id> <message>".into()];
            }
            let server_id = parts[1];
            let chat_id = parts[2];
            let message = parts[3];

            let server = match store.load_server(server_id) {
                Ok(s) => s,
                Err(e) => return vec![format!("Error: {e}")],
            };
            let chat = match store.load_chat(server_id, chat_id) {
                Ok(c) => c,
                Err(e) => return vec![format!("Error: {e}")],
            };
            match Transport::connect(&server.address, &server.shared_key_bytes).await {
                Ok(mut transport) => {
                    match transport.send_message(chat_id, message, &chat.encryption_key_bytes).await {
                        Ok(resp) => {
                            if resp.accepted {
                                vec![]
                            } else {
                                vec![format!("Rejected: {}", resp.error)]
                            }
                        }
                        Err(e) => vec![format!("Send error: {e}")],
                    }
                }
                Err(e) => vec![format!("Connection error: {e}")],
            }
        }
        "history" => {
            // history <server_id> <chat_id> [--limit N]
            if words.len() < 3 {
                return vec!["Usage: history <server_id> <chat_id> [--limit N]".into()];
            }
            let server_id = words[1];
            let chat_id = words[2];

            let mut limit = 50u32;
            for i in 3..words.len() {
                if words[i] == "--limit" {
                    if let Some(n) = words.get(i + 1) {
                        limit = n.parse().unwrap_or(50);
                    }
                }
            }
            let server = match store.load_server(server_id) {
                Ok(s) => s,
                Err(e) => return vec![format!("Error: {e}")],
            };
            let chat = match store.load_chat(server_id, chat_id) {
                Ok(c) => c,
                Err(e) => return vec![format!("Error: {e}")],
            };
            match Transport::connect(&server.address, &server.shared_key_bytes).await {
                Ok(mut transport) => {
                    match transport.get_history(chat_id, 0, 0, limit).await {
                        Ok(resp) => {
                            let mut lines = Vec::new();
                            for msg in &resp.messages {
                                let text = crate::transport::decrypt_payload(
                                    &msg.encrypted_payload,
                                    &chat.encryption_key_bytes,
                                    &msg.chat_id,
                                ).unwrap_or_else(|_| "<decryption failed>".into());
                                let ts = chrono::DateTime::from_timestamp_millis(msg.timestamp_ms)
                                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                    .unwrap_or_else(|| msg.timestamp_ms.to_string());
                                lines.push(format!("[{ts}] {text}"));
                            }
                            if lines.is_empty() {
                                lines.push("No messages.".into());
                            }
                            lines
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                Err(e) => vec![format!("Connection error: {e}")],
            }
        }
        "admin" => {
            // admin <server_id> <subcommand> [arg]
            if words.len() < 3 {
                return vec!["Usage: admin <server_id> <create-chat|delete-chat|list-chats> [args]".into()];
            }
            let server_id = words[1];
            let sub = words[2].to_lowercase();
            let sub_arg = words.get(3).copied();

            let server = match store.load_server(server_id) {
                Ok(s) => s,
                Err(e) => return vec![format!("Error: {e}")],
            };
            let admin_key = match server.admin_key_bytes {
                Some(k) => k,
                None => return vec!["No admin key configured for this server.".into()],
            };
            let mut transport = match Transport::connect(&server.address, &server.shared_key_bytes).await {
                Ok(t) => t,
                Err(e) => return vec![format!("Connection error: {e}")],
            };
            match sub.as_str() {
                "create-chat" => {
                    let id = match sub_arg {
                        Some(id) if !id.is_empty() => id,
                        _ => return vec!["Usage: admin <server_id> create-chat <chat_id>".into()],
                    };
                    match transport.create_chat(&admin_key, id, 1000, 10_485_760).await {
                        Ok(resp) => {
                            if resp.success {
                                vec![format!("Chat '{id}' created on '{server_id}'")]
                            } else {
                                vec![format!("Failed: {}", resp.error)]
                            }
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                "delete-chat" => {
                    let id = match sub_arg {
                        Some(id) if !id.is_empty() => id,
                        _ => return vec!["Usage: admin <server_id> delete-chat <chat_id>".into()],
                    };
                    match transport.delete_chat(&admin_key, id).await {
                        Ok(resp) => {
                            if resp.success {
                                vec![format!("Chat '{id}' deleted from '{server_id}'")]
                            } else {
                                vec![format!("Failed: {}", resp.error)]
                            }
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                "list-chats" => {
                    match transport.list_chats(&admin_key).await {
                        Ok(resp) => {
                            if resp.chats.is_empty() {
                                vec!["No chats.".into()]
                            } else {
                                resp.chats.iter()
                                    .map(|c| format!("  {} (earliest: {}, latest: {})", c.chat_id, c.earliest_timestamp_ms, c.latest_timestamp_ms))
                                    .collect()
                            }
                        }
                        Err(e) => vec![format!("Error: {e}")],
                    }
                }
                _ => vec![format!("Unknown admin command: {sub}")],
            }
        }
        "share-listen" => {
            if share_state.is_some() {
                return vec!["Share listener already running. Use 'share-stop' first.".into()];
            }
            let port: u16 = words.get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(17777);
            let cancel = CancellationToken::new();
            match crate::share::listen(port, store.clone(), event_tx.clone(), cancel.clone()).await {
                Ok((addr, tor_child)) => {
                    *share_state = Some((cancel, tor_child));
                    vec![format!("Share listener started: {addr}")]
                }
                Err(e) => vec![format!("Error: {e}")],
            }
        }
        "share-stop" => {
            match share_state.take() {
                Some((cancel, mut tor_child)) => {
                    cancel.cancel();
                    if let Some(ref mut child) = tor_child {
                        let _ = child.kill().await;
                    }
                    vec!["Share listener stopped.".into()]
                }
                None => vec!["No share listener running.".into()],
            }
        }
        "share" => {
            if words.len() < 2 {
                return vec!["Usage: share server <server_id> <contact_id> | share chat <server_id> <chat_id> <contact_id>".into()];
            }
            let target = words[1].to_lowercase();
            match target.as_str() {
                "server" => {
                    if words.len() < 4 {
                        return vec!["Usage: share server <server_id> <contact_id>".into()];
                    }
                    let server_id = words[2];
                    let contact_id = words[3];

                    let server = match store.load_server(server_id) {
                        Ok(s) => s,
                        Err(e) => return vec![format!("Error: {e}")],
                    };
                    let contact = match store.load_contact(contact_id) {
                        Ok(c) => c,
                        Err(e) => return vec![format!("Error: {e}")],
                    };
                    let identity = match store.load_identity() {
                        Ok(Some(id)) => id,
                        Ok(None) => return vec!["No identity found.".into()],
                        Err(e) => return vec![format!("Error: {e}")],
                    };

                    let data = ShareData::Server(ServerShareData {
                        id: server.id.clone(),
                        host: server.address.clone(),
                        shared_key: server.shared_key_bytes.clone(),
                        admin_key: server.admin_key_bytes.clone(),
                    });

                    match crate::share::send_share(data, &contact, &identity, 17777).await {
                        Ok(()) => vec![format!("Shared server '{}' with {}", server_id, contact_id)],
                        Err(e) => vec![format!("Share error: {e}")],
                    }
                }
                "chat" => {
                    if words.len() < 5 {
                        return vec!["Usage: share chat <server_id> <chat_id> <contact_id>".into()];
                    }
                    let server_id = words[2];
                    let chat_id = words[3];
                    let contact_id = words[4];

                    let server = match store.load_server(server_id) {
                        Ok(s) => s,
                        Err(e) => return vec![format!("Error: {e}")],
                    };
                    let chat = match store.load_chat(server_id, chat_id) {
                        Ok(c) => c,
                        Err(e) => return vec![format!("Error: {e}")],
                    };
                    let contact = match store.load_contact(contact_id) {
                        Ok(c) => c,
                        Err(e) => return vec![format!("Error: {e}")],
                    };
                    let identity = match store.load_identity() {
                        Ok(Some(id)) => id,
                        Ok(None) => return vec!["No identity found.".into()],
                        Err(e) => return vec![format!("Error: {e}")],
                    };

                    let data = ShareData::Chat(ChatShareData {
                        server_id: server_id.to_string(),
                        chat_id: chat_id.to_string(),
                        name: chat.name.clone(),
                        encryption_key: chat.encryption_key_bytes.clone(),
                        server_admin_key: server.admin_key_bytes.clone(),
                    });

                    match crate::share::send_share(data, &contact, &identity, 17777).await {
                        Ok(()) => vec![format!("Shared chat '{}/{}' with {}", server_id, chat_id, contact_id)],
                        Err(e) => vec![format!("Share error: {e}")],
                    }
                }
                _ => vec!["Usage: share server <server_id> <contact_id> | share chat <server_id> <chat_id> <contact_id>".into()],
            }
        }
        "deploy-server" => {
            if words.len() < 5 {
                return vec!["Usage: deploy-server <ssh_user> <ssh_ip> <ssh_pass> <server_id>".into()];
            }
            let ssh_user = words[1];
            let ssh_ip = words[2];
            let ssh_pass = words[3];
            let server_id = words[4];

            let creds = crate::setup_server::SshCredentials::new(
                ssh_user.to_string(),
                ssh_ip.to_string(),
                ssh_pass.to_string(),
            );

            let user_key = {
                use m_core::crypto::algorithms::symmetric::Aes256Gcm;
                use m_core::crypto::{CryptoKey, SymmetricCipher};
                hex::encode(Aes256Gcm::new().get_key().as_bytes())
            };
            let admin_key = {
                use m_core::crypto::algorithms::symmetric::Aes256Gcm;
                use m_core::crypto::{CryptoKey, SymmetricCipher};
                hex::encode(Aes256Gcm::new().get_key().as_bytes())
            };
            let server_address = format!("http://{}:50051", ssh_ip);

            manager.stop_server(server_id);

            if let Err(e) = crate::setup_server::setup_server(&creds, &user_key, &admin_key).await {
                return vec![format!("Deploy failed: {e}")];
            }

            let import = crate::config::ServerImport {
                connection: crate::config::ServerConnection {
                    id: server_id.to_string(),
                    server_address: server_address.clone(),
                },
                auth: crate::config::ServerAuth {
                    shared_key: user_key.clone(),
                    admin_key: Some(admin_key.clone()),
                },
            };
            if let Err(e) = store.save_server(&import) {
                return vec![format!("Server deployed but DB save failed: {e}")];
            }
            if let Err(e) = store.set_server_state(server_id, NodeState::Enabled) {
                return vec![format!("Server deployed but could not enable: {e}")];
            }

            let mut out = vec![
                format!("Server '{}' deployed at {}", server_id, server_address),
                format!("  user_key:  {}", user_key),
                format!("  admin_key: {}", admin_key),
            ];
            if let Err(e) = manager.start_server(server_id) {
                out.push(format!("Warning: could not start connection: {e}"));
            } else {
                out.push(format!("Connection started."));
            }
            out
        }
        "remove-server" => {
            if words.len() < 5 {
                return vec!["Usage: remove-server <ssh_user> <ssh_ip> <ssh_pass> <server_id>".into()];
            }
            let creds = crate::setup_server::SshCredentials::new(
                words[1].to_string(),
                words[2].to_string(),
                words[3].to_string(),
            );
            let server_id = words[4];

            manager.stop_server(server_id);

            if let Err(e) = crate::setup_server::remove_server(&creds).await {
                return vec![format!("Remote removal failed: {e}")];
            }

            match store.set_server_state(server_id, NodeState::Disabled) {
                Ok(()) => vec![format!("Server '{}' removed and disabled.", server_id)],
                Err(_) => vec![format!("Remote server removed. No local record found for '{}'.", server_id)],
            }
        }
        _ => vec![format!("Unknown command: {cmd}. Type 'help' for list.")],
    }
}

pub async fn run(_config: ClientConfig, store: Store) -> Result<()> {
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_inner(&mut terminal, store).await;

    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), DisableBracketedPaste, LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_inner(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    store: Store,
) -> Result<()> {
    let mut app = App::new();
    app.push_left("m client TUI. Type 'help' for commands.".into());

    let (live_event_tx, mut live_event_rx) = mpsc::unbounded_channel::<LiveEvent>();
    let mut manager = ConnectionManager::new(store.clone(), live_event_tx.clone());
    let mut share_state: Option<(CancellationToken, Option<tokio::process::Child>)> = None;

    match manager.start_all_enabled() {
        Ok(()) => {
            let enabled = store.list_enabled_servers().unwrap_or_default();
            if !enabled.is_empty() {
                app.live_on = true;
                let names: Vec<_> = enabled.iter().map(|s| s.name.clone()).collect();
                app.push_left(format!("Auto-connected to: {}", names.join(", ")));
            }
        }
        Err(e) => {
            app.push_left(format!("Warning: auto-connect failed: {e}"));
        }
    }

    loop {
        draw(terminal, &app)?;

        let has_terminal_event = event::poll(Duration::from_millis(16))?;

        if has_terminal_event {
            match event::read()? {
                Event::Key(key) => {
                    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                        if let Some((c, mut tor_child)) = share_state.take() {
                            c.cancel();
                            if let Some(ref mut child) = tor_child {
                                let _ = child.kill().await;
                            }
                        }
                        manager.stop_all();
                        break;
                    }
                    match key.code {
                        KeyCode::Enter => {
                            let input = app.input.clone();
                            app.input.clear();
                            app.cursor_pos = 0;

                            if input.trim().is_empty() {
                                continue;
                            }

                            app.push_left(format!("> {input}"));

                            match parse_command(&input) {
                                CmdResult::Quit => {
                                    if let Some((c, mut tor_child)) = share_state.take() {
                                        c.cancel();
                                        if let Some(ref mut child) = tor_child {
                                            let _ = child.kill().await;
                                        }
                                    }
                                    manager.stop_all();
                                    break;
                                }
                                CmdResult::Clear => {
                                    app.left_lines.clear();
                                    app.left_scroll = 0;
                                }
                                CmdResult::Output => {
                                    if !input.trim().is_empty() {
                                        let lines = execute_command(
                                            &input, &store, &mut manager,
                                            &live_event_tx, &mut share_state,
                                        ).await;
                                        for line in lines {
                                            app.push_left(line);
                                        }
                                        let has_enabled = store.list_enabled_servers()
                                            .map(|s| !s.is_empty())
                                            .unwrap_or(false);
                                        app.live_on = has_enabled;
                                    }
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            app.input.insert(app.cursor_pos, c);
                            app.cursor_pos += 1;
                        }
                        KeyCode::Backspace => {
                            if app.cursor_pos > 0 {
                                app.cursor_pos -= 1;
                                app.input.remove(app.cursor_pos);
                            }
                        }
                        KeyCode::Delete => {
                            if app.cursor_pos < app.input.len() {
                                app.input.remove(app.cursor_pos);
                            }
                        }
                        KeyCode::Left => {
                            if app.cursor_pos > 0 {
                                app.cursor_pos -= 1;
                            }
                        }
                        KeyCode::Right => {
                            if app.cursor_pos < app.input.len() {
                                app.cursor_pos += 1;
                            }
                        }
                        KeyCode::Home => {
                            app.cursor_pos = 0;
                        }
                        KeyCode::End => {
                            app.cursor_pos = app.input.len();
                        }
                        _ => {}
                    }
                }
                Event::Paste(text) => {
                    for ch in text.chars() {
                        app.input.insert(app.cursor_pos, ch);
                        app.cursor_pos += 1;
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }

        while let Ok(event) = live_event_rx.try_recv() {
            match event {
                LiveEvent::Message(msg) => {
                    app.push_right(format!(
                        "[{}] [{}/{}] {}",
                        msg.timestamp, msg.server_id, msg.chat_name, msg.text,
                    ));
                }
                LiveEvent::SyncComplete { server_id, chat_name } => {
                    app.push_right(format!("--- sync: {server_id}/{chat_name} ---"));
                }
                LiveEvent::Error { server_id, message } => {
                    app.push_right(format!("! [{server_id}] {message}"));
                }
                LiveEvent::ServerUnavailable(sid) => {
                    manager.handle_unavailable_server(&sid);
                    app.push_right(format!("--- {sid}: unavailable ---"));
                    let has_enabled = store.list_enabled_servers()
                        .map(|s| !s.is_empty())
                        .unwrap_or(false);
                    app.live_on = has_enabled || !app.right_lines.is_empty();
                }
                LiveEvent::Disconnected(sid) => {
                    manager.handle_disconnected(&sid);
                    app.push_right(format!("--- {sid}: disconnected ---"));
                }
                LiveEvent::ShareReceived(data) => {
                    let msg = match &data {
                        ShareData::Server(s) => store.upsert_shared_server(s),
                        ShareData::Chat(c) => store.upsert_shared_chat(c),
                    };
                    app.push_right(format!(
                        "--- share: {} ---",
                        msg.unwrap_or_else(|e| e.to_string()),
                    ));
                }
                LiveEvent::TorBootstrap(pct) => {
                    app.push_left(format!("  Tor bootstrap: {pct}%"));
                }
            }
        }

    }

    Ok(())
}

fn draw(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &App,
) -> Result<()> {
    terminal.draw(|f| {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(f.area());

        let input_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Input ");
        let input_text = Paragraph::new(Line::from(vec![
            Span::styled("> ", Style::default().fg(Color::Green)),
            Span::raw(&app.input),
        ]))
        .block(input_block);
        f.render_widget(input_text, outer[1]);

        let cursor_x = outer[1].x + 1 + 2 + app.cursor_pos as u16;
        let cursor_y = outer[1].y + 1;
        f.set_cursor_position((cursor_x, cursor_y));

        if app.live_on {
            let top = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ])
                .split(outer[0]);

            let left_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::White))
                .title(" Output ");
            let left_lines: Vec<Line> = app.left_lines.iter()
                .map(|s| Line::from(s.as_str()))
                .collect();
            let left_height = top[0].height.saturating_sub(2) as usize;
            let left_scroll = app.left_lines.len().saturating_sub(left_height) as u16;
            let left_para = Paragraph::new(left_lines)
                .block(left_block)
                .wrap(Wrap { trim: false })
                .scroll((left_scroll, 0));
            f.render_widget(left_para, top[0]);

            let right_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" Live ")
                .title_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow));
            let right_lines: Vec<Line> = app.right_lines.iter()
                .map(|s| Line::from(s.as_str()))
                .collect();
            let right_height = top[1].height.saturating_sub(2) as usize;
            let right_scroll = app.right_lines.len().saturating_sub(right_height) as u16;
            let right_para = Paragraph::new(right_lines)
                .block(right_block)
                .wrap(Wrap { trim: false })
                .scroll((right_scroll, 0));
            f.render_widget(right_para, top[1]);
        } else {
            let left_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::White))
                .title(" Output ");
            let left_lines: Vec<Line> = app.left_lines.iter()
                .map(|s| Line::from(s.as_str()))
                .collect();
            let left_height = outer[0].height.saturating_sub(2) as usize;
            let left_scroll = app.left_lines.len().saturating_sub(left_height) as u16;
            let left_para = Paragraph::new(left_lines)
                .block(left_block)
                .wrap(Wrap { trim: false })
                .scroll((left_scroll, 0));
            f.render_widget(left_para, outer[0]);
        }
    })?;
    Ok(())
}
