use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Terminal;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::{ServerCard, ChatCard};
use crate::connection_manager::ConnectionManager;
use crate::identity::ContactCard;
use crate::live::LiveEvent;
use crate::sharing::{ShareData, ChatShareData};
use crate::store::{ContactRecord, ChatRecord, NodeState, ServerRecord, Store};
use crate::transport::Transport;

const MAX_MESSAGES: usize = 2000;
const MAX_RECEIVING_LINES: usize = 500;

// ── Screen state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Contacts,
    Servers,
    Chats { server_id: String },
    Share,
}

// ── Overlay ───────────────────────────────────────────────────────────────────

enum Overlay {
    None,
    Info(Vec<String>),
    Error(String),
    ShareData(ShareStep),
}

enum ShareStep {
    SelectContact { contacts: Vec<ContactRecord>, cursor: usize },
    SelectServer  { contact: ContactRecord, servers: Vec<ServerRecord>, cursor: usize },
    SelectChat    { contact: ContactRecord, server: ServerRecord, chats: Vec<ChatRecord>, cursor: usize },
}

// ── Live chat mode ────────────────────────────────────────────────────────────

enum LiveMode {
    Off,
    On {
        server_id: String,
        chat_id: String,
        messages: VecDeque<String>,
        scroll: u16,
    },
}

// ── Tor ───────────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum TorStatus {
    Off,
    Starting(u8),
    Running,
}

// ── App ───────────────────────────────────────────────────────────────────────

struct App {
    screen: Screen,
    overlay: Overlay,
    live_mode: LiveMode,
    tor_status: TorStatus,
    receiving_locked: bool,
    receiving_lines: VecDeque<String>,

    contacts: Vec<ContactRecord>,
    servers: Vec<ServerRecord>,
    servers_last_ts: Vec<Option<i64>>, // max last_synced_ts across all chats per server
    chats: Vec<ChatRecord>,

    contacts_cursor: usize,
    servers_cursor: usize,
    chats_cursor: usize,

    input: String,
    cursor_pos: usize,
    info_scroll: u16,
}

impl App {
    fn new() -> Self {
        Self {
            screen: Screen::Contacts,
            overlay: Overlay::None,
            live_mode: LiveMode::Off,
            tor_status: TorStatus::Off,
            receiving_locked: false,
            receiving_lines: VecDeque::new(),
            contacts: vec![],
            servers: vec![],
            servers_last_ts: vec![],
            chats: vec![],
            contacts_cursor: 0,
            servers_cursor: 0,
            chats_cursor: 0,
            input: String::new(),
            cursor_pos: 0,
            info_scroll: 0,
        }
    }

    fn input_prompt(&self) -> &'static str {
        if matches!(self.live_mode, LiveMode::On { .. }) {
            return "message";
        }
        match &self.screen {
            Screen::Contacts => "contacts",
            Screen::Servers => "servers",
            Screen::Chats { .. } => "servers/chats",
            Screen::Share => "share",
        }
    }

    fn is_input_locked(&self) -> bool {
        self.receiving_locked || matches!(self.tor_status, TorStatus::Starting(_))
    }

    fn set_error(&mut self, msg: impl Into<String>) {
        self.overlay = Overlay::Error(msg.into());
    }

    fn set_info(&mut self, lines: Vec<String>) {
        self.info_scroll = 0;
        self.overlay = Overlay::Info(lines);
    }
}

// ── Refresh helpers ───────────────────────────────────────────────────────────

fn refresh_contacts(app: &mut App, store: &Store) {
    app.contacts = store.list_contacts().unwrap_or_default();
    app.contacts_cursor = app.contacts_cursor.min(app.contacts.len().saturating_sub(1));
}

fn refresh_servers(app: &mut App, store: &Store) {
    app.servers = store.list_servers().unwrap_or_default();
    app.servers_cursor = app.servers_cursor.min(app.servers.len().saturating_sub(1));
    app.servers_last_ts = app.servers.iter().map(|s| {
        store.list_chats_for_server(&s.id).ok()
            .and_then(|chats| {
                chats.iter()
                    .filter(|c| c.state == NodeState::Enabled && c.last_synced_ts > 0)
                    .map(|c| c.last_synced_ts)
                    .max()
            })
    }).collect();
}

fn refresh_chats(app: &mut App, store: &Store) {
    if let Screen::Chats { server_id } = &app.screen.clone() {
        app.chats = store.list_chats_for_server(server_id).unwrap_or_default();
        app.chats_cursor = app.chats_cursor.min(app.chats.len().saturating_sub(1));
    }
}

// ── Command execution ─────────────────────────────────────────────────────────

async fn execute_command(
    input: &str,
    app: &mut App,
    store: &Store,
    manager: &mut ConnectionManager,
    event_tx: &mpsc::UnboundedSender<LiveEvent>,
    share_state: &mut Option<(CancellationToken, Option<tokio::process::Child>)>,
) -> bool /* quit */ {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return false;
    }

    let words: Vec<&str> = trimmed.split_whitespace().collect();
    let cmd = words[0].to_lowercase();

    // ── Global navigation ────────────────────────────────────────────────────
    match cmd.as_str() {
        "quit" | "exit" | "q" => return true,
        "contacts" => {
            app.screen = Screen::Contacts;
            refresh_contacts(app, store);
            return false;
        }
        "servers" => {
            app.screen = Screen::Servers;
            refresh_servers(app, store);
            return false;
        }
        "share" => {
            app.screen = Screen::Share;
            return false;
        }
        _ => {}
    }

    // ── Screen-specific commands ─────────────────────────────────────────────
    match &app.screen.clone() {
        Screen::Contacts => exec_contacts(trimmed, &words, app, store).await,
        Screen::Servers  => exec_servers(trimmed, &words, app, store, manager, event_tx, share_state).await,
        Screen::Chats { server_id } => {
            let sid = server_id.clone();
            exec_chats(trimmed, &words, &sid, app, store, manager).await
        }
        Screen::Share => exec_share(trimmed, &words, app, store, event_tx, share_state).await,
    }

    false
}

// ── Contacts commands ─────────────────────────────────────────────────────────

async fn exec_contacts(_input: &str, words: &[&str], app: &mut App, store: &Store) {
    let cmd = words[0].to_lowercase();
    match cmd.as_str() {
        "help" | "?" => {
            app.set_info(vec![
                "contacts commands:".into(),
                "  export-self <path>     Export own identity card (binary)".into(),
                "  export <path>          Export selected contact (binary)".into(),
                "  load <path> <name>     Import contact from binary file".into(),
                "  del                    Delete selected contact".into(),
                "  rename <new_name>      Rename selected contact".into(),
                "  whoami                 Show own identity info".into(),
                "  servers / share        Switch screen".into(),
            ]);
        }
        "whoami" => {
            match store.load_identity() {
                Ok(Some(id)) => {
                    let onion = {
                        let arr: [u8; 32] = id.tor_pk_bytes.clone().try_into().unwrap_or([0u8; 32]);
                        match torut::onion::TorPublicKeyV3::from_bytes(&arr) {
                            Ok(pk) => pk.get_onion_address().to_string(),
                            Err(_) => "<invalid tor key>".into(),
                        }
                    };
                    app.set_info(vec![
                        format!("ID:         {}", id.id),
                        format!("Onion:      {}", onion),
                        format!("Signing PK: {}", hex::encode(&id.signing_pk_bytes)),
                    ]);
                }
                Ok(None) => app.set_error("No identity found"),
                Err(e) => app.set_error(format!("Error: {e}")),
            }
        }
        "export-self" => {
            if words.len() < 2 {
                app.set_error("Usage: export-self <path>"); return;
            }
            let path = shellexpand::tilde(words[1]);
            match store.load_identity() {
                Ok(Some(id)) => {
                    let arr: [u8; 32] = match id.tor_pk_bytes.clone().try_into() {
                        Ok(a) => a,
                        Err(_) => { app.set_error("Invalid tor public key length"); return; }
                    };
                    let onion = match torut::onion::TorPublicKeyV3::from_bytes(&arr) {
                        Ok(pk) => pk.get_onion_address().to_string(),
                        Err(_) => { app.set_error("Invalid tor public key"); return; }
                    };
                    let card = ContactCard {
                        signing_pk: id.signing_pk_bytes,
                        tor_pk: id.tor_pk_bytes,
                        onion_address: onion,
                    };
                    match card.to_bytes() {
                        Ok(bytes) => match std::fs::write(path.as_ref(), &bytes) {
                            Ok(()) => app.set_info(vec![format!("Exported to {}", path)]),
                            Err(e) => app.set_error(format!("Write error: {e}")),
                        },
                        Err(e) => app.set_error(format!("Serialize error: {e}")),
                    }
                }
                Ok(None) => app.set_error("No identity found"),
                Err(e) => app.set_error(format!("Error: {e}")),
            }
        }
        "export" => {
            if words.len() < 2 {
                app.set_error("Usage: export <path>"); return;
            }
            if app.contacts.is_empty() {
                app.set_error("No contacts"); return;
            }
            let contact = &app.contacts[app.contacts_cursor];
            let path = shellexpand::tilde(words[1]);
            let card = ContactCard {
                signing_pk: contact.signing_pk_bytes.clone(),
                tor_pk: contact.tor_pk_bytes.clone(),
                onion_address: contact.onion_address.clone(),
            };
            match card.to_bytes() {
                Ok(bytes) => match std::fs::write(path.as_ref(), &bytes) {
                    Ok(()) => app.set_info(vec![format!("Exported '{}' to {}", contact.name, path)]),
                    Err(e) => app.set_error(format!("Write error: {e}")),
                },
                Err(e) => app.set_error(format!("Serialize error: {e}")),
            }
        }
        "load" => {
            if words.len() < 3 {
                app.set_error("Usage: load <path> <name>"); return;
            }
            let path = shellexpand::tilde(words[1]);
            let name = words[2..].join(" ");
            match std::fs::read(path.as_ref()) {
                Ok(bytes) => match ContactCard::from_bytes(&bytes) {
                    Ok(card) => match store.save_contact(&card, Some(&name)) {
                        Ok(()) => {
                            refresh_contacts(app, store);
                            app.set_info(vec![format!("Contact '{}' imported", name)]);
                        }
                        Err(e) => app.set_error(format!("Save error: {e}")),
                    },
                    Err(e) => app.set_error(format!("Parse error: {e}")),
                },
                Err(e) => app.set_error(format!("Read error: {e}")),
            }
        }
        "del" => {
            if app.contacts.is_empty() {
                app.set_error("No contacts"); return;
            }
            let id = app.contacts[app.contacts_cursor].id.clone();
            match store.delete_contact(&id) {
                Ok(()) => { refresh_contacts(app, store); }
                Err(e) => app.set_error(format!("Error: {e}")),
            }
        }
        "rename" => {
            if words.len() < 2 {
                app.set_error("Usage: rename <new_name>"); return;
            }
            if app.contacts.is_empty() {
                app.set_error("No contacts"); return;
            }
            let id = app.contacts[app.contacts_cursor].id.clone();
            let new_name = words[1..].join(" ");
            match store.rename_contact(&id, &new_name) {
                Ok(()) => { refresh_contacts(app, store); }
                Err(e) => app.set_error(format!("Error: {e}")),
            }
        }
        _ => app.set_error(format!("Unknown command: {}. Type 'help'.", words[0])),
    }
}

// ── Servers commands ──────────────────────────────────────────────────────────

async fn exec_servers(
    _input: &str,
    words: &[&str],
    app: &mut App,
    store: &Store,
    manager: &mut ConnectionManager,
    _event_tx: &mpsc::UnboundedSender<LiveEvent>,
    _share_state: &mut Option<(CancellationToken, Option<tokio::process::Child>)>,
) {
    let cmd = words[0].to_lowercase();
    match cmd.as_str() {
        "help" | "?" => {
            app.set_info(vec![
                "servers commands:".into(),
                "  enable                 Enable selected server".into(),
                "  disable                Disable selected server".into(),
                "  rename <name>          Rename selected server".into(),
                "  del                    Delete selected server".into(),
                "  chats                  Go to chats of selected server".into(),
                "  import <path>          Import server from binary file".into(),
                "  export <path>          Export selected server to binary file".into(),
                "  deploy <user> <ip> <pass>  Deploy server via SSH".into(),
                "  remove <user> <ip> <pass>  Remove server via SSH".into(),
                "  admin create-chat <id> Create chat on server, generate key, save locally".into(),
                "  admin delete-chat <id> Delete chat on selected server".into(),
                "  admin list-chats       List chats on selected server".into(),
                "  contacts / share       Switch screen".into(),
            ]);
        }
        "chats" => {
            if app.servers.is_empty() {
                app.set_error("No servers"); return;
            }
            let sid = app.servers[app.servers_cursor].id.clone();
            app.screen = Screen::Chats { server_id: sid };
            app.chats_cursor = 0;
            refresh_chats(app, store);
        }
        "enable" => {
            if app.servers.is_empty() {
                app.set_error("No servers"); return;
            }
            let id = app.servers[app.servers_cursor].id.clone();
            if let Err(e) = store.set_server_state(&id, NodeState::Enabled) {
                app.set_error(format!("Error: {e}")); return;
            }
            if let Err(e) = manager.start_server(&id) {
                app.set_error(format!("Enabled but connect failed: {e}"));
            }
            refresh_servers(app, store);
        }
        "disable" => {
            if app.servers.is_empty() {
                app.set_error("No servers"); return;
            }
            let id = app.servers[app.servers_cursor].id.clone();
            manager.stop_server(&id);
            if let Err(e) = store.set_server_state(&id, NodeState::Disabled) {
                app.set_error(format!("Error: {e}")); return;
            }
            refresh_servers(app, store);
        }
        "rename" => {
            if words.len() < 2 {
                app.set_error("Usage: rename <new_name>"); return;
            }
            if app.servers.is_empty() {
                app.set_error("No servers"); return;
            }
            let id = app.servers[app.servers_cursor].id.clone();
            let name = words[1..].join(" ");
            if let Err(e) = store.rename_server(&id, &name) {
                app.set_error(format!("Error: {e}")); return;
            }
            refresh_servers(app, store);
        }
        "del" => {
            if app.servers.is_empty() {
                app.set_error("No servers"); return;
            }
            let id = app.servers[app.servers_cursor].id.clone();
            manager.stop_server(&id);
            if let Err(e) = store.delete_server(&id) {
                app.set_error(format!("Error: {e}")); return;
            }
            refresh_servers(app, store);
        }
        "import" => {
            if words.len() < 2 {
                app.set_error("Usage: import <path>"); return;
            }
            let path_str = shellexpand::tilde(words[1]);
            match ServerCard::load(std::path::Path::new(path_str.as_ref())) {
                Ok(card) => {
                    let id = card.id.clone();
                    match store.save_server_card(&card) {
                        Ok(()) => {
                            refresh_servers(app, store);
                            app.set_info(vec![format!("Server '{}' imported", id)]);
                        }
                        Err(e) => app.set_error(format!("Save error: {e}")),
                    }
                }
                Err(e) => app.set_error(format!("Load error: {e}")),
            }
        }
        "export" => {
            if words.len() < 2 {
                app.set_error("Usage: export <path>"); return;
            }
            if app.servers.is_empty() {
                app.set_error("No servers"); return;
            }
            let id = app.servers[app.servers_cursor].id.clone();
            let path_str = shellexpand::tilde(words[1]);
            match store.export_server_card(&id) {
                Ok(card) => match card.save(std::path::Path::new(path_str.as_ref())) {
                    Ok(()) => app.set_info(vec![format!("Exported server '{}' to {}", id, path_str)]),
                    Err(e) => app.set_error(format!("Write error: {e}")),
                },
                Err(e) => app.set_error(format!("Error: {e}")),
            }
        }
        "deploy" => {
            if words.len() < 4 {
                app.set_error("Usage: deploy <ssh_user> <ssh_ip> <ssh_pass>"); return;
            }
            let ssh_user = words[1];
            let ssh_ip = words[2];
            let ssh_pass = words[3];
            let server_id = format!("srv-{}", address_short(ssh_ip));

            let creds = crate::setup_server::SshCredentials::new(
                ssh_user.to_string(),
                ssh_ip.to_string(),
                ssh_pass.to_string(),
            );
            let user_key = new_aes_key_hex();
            let admin_key = new_aes_key_hex();
            let address = format!("http://{}:50051", ssh_ip);

            manager.stop_server(&server_id);
            if let Err(e) = crate::setup_server::setup_server(&creds, &user_key, &admin_key).await {
                app.set_error(format!("Deploy failed: {e}")); return;
            }
            let card = ServerCard {
                id: server_id.clone(),
                address,
                shared_key: hex::decode(&user_key).unwrap_or_default(),
                admin_key: Some(hex::decode(&admin_key).unwrap_or_default()),
            };
            if let Err(e) = store.save_server_card(&card) {
                app.set_error(format!("Deployed but DB save failed: {e}")); return;
            }
            let _ = store.set_server_state(&server_id, NodeState::Enabled);
            let _ = manager.start_server(&server_id);
            refresh_servers(app, store);
            app.set_info(vec![
                format!("Server '{}' deployed", server_id),
                format!("  user_key:  {}", user_key),
                format!("  admin_key: {}", admin_key),
            ]);
        }
        "remove" => {
            if words.len() < 4 {
                app.set_error("Usage: remove <ssh_user> <ssh_ip> <ssh_pass>"); return;
            }
            if app.servers.is_empty() {
                app.set_error("No servers"); return;
            }
            let creds = crate::setup_server::SshCredentials::new(
                words[1].to_string(),
                words[2].to_string(),
                words[3].to_string(),
            );
            let id = app.servers[app.servers_cursor].id.clone();
            manager.stop_server(&id);
            if let Err(e) = crate::setup_server::remove_server(&creds).await {
                app.set_error(format!("Remote removal failed: {e}")); return;
            }
            let _ = store.delete_server(&id);
            refresh_servers(app, store);
        }
        "admin" => {
            if words.len() < 2 {
                app.set_error("Usage: admin <create-chat|delete-chat|list-chats> [args]"); return;
            }
            if app.servers.is_empty() {
                app.set_error("No servers"); return;
            }
            let server = app.servers[app.servers_cursor].clone();
            let admin_key = match server.admin_key_bytes.clone() {
                Some(k) => k,
                None => { app.set_error("No admin key for this server"); return; }
            };
            let mut transport = match Transport::connect(&server.address, &server.shared_key_bytes).await {
                Ok(t) => t,
                Err(e) => { app.set_error(format!("Connection error: {e}")); return; }
            };
            let sub = words[1].to_lowercase();
            match sub.as_str() {
                "create-chat" => {
                    let id = match words.get(2) {
                        Some(s) if !s.is_empty() => *s,
                        _ => { app.set_error("Usage: admin create-chat <chat_id>"); return; }
                    };
                    let encryption_key = new_aes_key_bytes();
                    match transport.create_chat(&admin_key, id, 1000, 10_485_760).await {
                        Ok(r) if r.success => {
                            let card = crate::config::ChatCard {
                                server_id: server.id.clone(),
                                chat_id: id.to_string(),
                                name: id.to_string(),
                                encryption_key: encryption_key.clone(),
                            };
                            match store.save_chat_card(&card) {
                                Ok(()) => {
                                    refresh_chats(app, store);
                                    app.set_info(vec![
                                        format!("Chat '{}' created", id),
                                        format!("Key: {}", hex::encode(&encryption_key)),
                                    ]);
                                }
                                Err(e) => app.set_error(format!("Chat created on server but local save failed: {e}")),
                            }
                        }
                        Ok(r) => app.set_error(format!("Server rejected: {}", r.error)),
                        Err(e) => app.set_error(format!("Error: {e}")),
                    }
                }
                "delete-chat" => {
                    let id = match words.get(2) {
                        Some(s) if !s.is_empty() => *s,
                        _ => { app.set_error("Usage: admin delete-chat <chat_id>"); return; }
                    };
                    match transport.delete_chat(&admin_key, id).await {
                        Ok(r) if r.success => app.set_info(vec![format!("Chat '{}' deleted", id)]),
                        Ok(r) => app.set_error(format!("Failed: {}", r.error)),
                        Err(e) => app.set_error(format!("Error: {e}")),
                    }
                }
                "list-chats" => {
                    match transport.list_chats(&admin_key).await {
                        Ok(r) => {
                            if r.chats.is_empty() {
                                app.set_info(vec!["No chats on server".into()]);
                            } else {
                                app.set_info(r.chats.iter().map(|c| {
                                    format!("  {} ({}..{})", c.chat_id, c.earliest_timestamp_ms, c.latest_timestamp_ms)
                                }).collect());
                            }
                        }
                        Err(e) => app.set_error(format!("Error: {e}")),
                    }
                }
                _ => app.set_error(format!("Unknown admin command: {sub}")),
            }
        }
        _ => app.set_error(format!("Unknown command: {}. Type 'help'.", words[0])),
    }
}

// ── Chats commands ────────────────────────────────────────────────────────────

async fn exec_chats(
    input: &str,
    words: &[&str],
    server_id: &str,
    app: &mut App,
    store: &Store,
    manager: &mut ConnectionManager,
) {
    let cmd = words[0].to_lowercase();
    match cmd.as_str() {
        "help" | "?" => {
            app.set_info(vec![
                "servers/chats commands:".into(),
                "  enable                 Enable selected chat".into(),
                "  disable                Disable selected chat".into(),
                "  rename <name>          Rename selected chat".into(),
                "  del                    Delete selected chat".into(),
                "  live                   Enter live mode for selected chat".into(),
                "  send <message>         Send message to selected chat".into(),
                "  history [--limit N]    Fetch chat history".into(),
                "  import <path>          Import chat from binary file".into(),
                "  export <path>          Export selected chat to binary file".into(),
                "  admin create-chat <id> Create chat on server, generate key, save locally".into(),
                "  admin delete-chat <id> Delete chat on server".into(),
                "  admin list-chats       List chats on server".into(),
                "  servers                Back to server list".into(),
            ]);
        }
        "live" => {
            if app.chats.is_empty() {
                app.set_error("No chats"); return;
            }
            let chat = &app.chats[app.chats_cursor];
            app.live_mode = LiveMode::On {
                server_id: server_id.to_string(),
                chat_id: chat.chat_id.clone(),
                messages: VecDeque::new(),
                scroll: 0,
            };
        }
        "enable" => {
            if app.chats.is_empty() {
                app.set_error("No chats"); return;
            }
            let chat = app.chats[app.chats_cursor].chat_id.clone();
            if let Err(e) = store.set_chat_state(server_id, &chat, NodeState::Enabled) {
                app.set_error(format!("Error: {e}")); return;
            }
            let _ = manager.restart_server(server_id);
            refresh_chats(app, store);
        }
        "disable" => {
            if app.chats.is_empty() {
                app.set_error("No chats"); return;
            }
            let chat = app.chats[app.chats_cursor].chat_id.clone();
            if let Err(e) = store.set_chat_state(server_id, &chat, NodeState::Disabled) {
                app.set_error(format!("Error: {e}")); return;
            }
            let _ = manager.restart_server(server_id);
            refresh_chats(app, store);
        }
        "rename" => {
            if words.len() < 2 {
                app.set_error("Usage: rename <new_name>"); return;
            }
            if app.chats.is_empty() {
                app.set_error("No chats"); return;
            }
            let chat_id = app.chats[app.chats_cursor].chat_id.clone();
            let name = words[1..].join(" ");
            if let Err(e) = store.rename_chat(server_id, &chat_id, &name) {
                app.set_error(format!("Error: {e}")); return;
            }
            refresh_chats(app, store);
        }
        "del" => {
            if app.chats.is_empty() {
                app.set_error("No chats"); return;
            }
            let chat_id = app.chats[app.chats_cursor].chat_id.clone();
            if let Err(e) = store.delete_chat(server_id, &chat_id) {
                app.set_error(format!("Error: {e}")); return;
            }
            if let LiveMode::On { chat_id: live_cid, .. } = &app.live_mode {
                if *live_cid == chat_id {
                    app.live_mode = LiveMode::Off;
                }
            }
            refresh_chats(app, store);
        }
        "import" => {
            if words.len() < 2 {
                app.set_error("Usage: import <path>"); return;
            }
            let path_str = shellexpand::tilde(words[1]);
            match ChatCard::load(std::path::Path::new(path_str.as_ref())) {
                Ok(card) => {
                    let display = format!("{}/{}", card.server_id, card.chat_id);
                    match store.save_chat_card(&card) {
                        Ok(()) => {
                            refresh_chats(app, store);
                            app.set_info(vec![format!("Chat '{}' imported", display)]);
                        }
                        Err(e) => app.set_error(format!("Save error: {e}")),
                    }
                }
                Err(e) => app.set_error(format!("Load error: {e}")),
            }
        }
        "export" => {
            if words.len() < 2 {
                app.set_error("Usage: export <path>"); return;
            }
            if app.chats.is_empty() {
                app.set_error("No chats"); return;
            }
            let chat_id = app.chats[app.chats_cursor].chat_id.clone();
            let path_str = shellexpand::tilde(words[1]);
            match store.export_chat_card(server_id, &chat_id) {
                Ok(card) => match card.save(std::path::Path::new(path_str.as_ref())) {
                    Ok(()) => app.set_info(vec![format!("Exported chat '{}/{}' to {}", server_id, chat_id, path_str)]),
                    Err(e) => app.set_error(format!("Write error: {e}")),
                },
                Err(e) => app.set_error(format!("Error: {e}")),
            }
        }
        "send" => {
            let parts: Vec<&str> = input.splitn(2, ' ').collect();
            if parts.len() < 2 {
                app.set_error("Usage: send <message>"); return;
            }
            let message = parts[1];
            let chat_id = match active_chat_id(app) {
                Some(id) => id,
                None => {
                    if app.chats.is_empty() { app.set_error("No chat selected"); return; }
                    app.chats[app.chats_cursor].chat_id.clone()
                }
            };
            let server = match store.load_server(server_id) {
                Ok(s) => s,
                Err(e) => { app.set_error(format!("Error: {e}")); return; }
            };
            let chat = match store.load_chat(server_id, &chat_id) {
                Ok(c) => c,
                Err(e) => { app.set_error(format!("Error: {e}")); return; }
            };
            match Transport::connect(&server.address, &server.shared_key_bytes).await {
                Ok(mut t) => match t.send_message(&chat_id, message, &chat.encryption_key_bytes).await {
                    Ok(r) if r.accepted => {}
                    Ok(r) => app.set_error(format!("Rejected: {}", r.error)),
                    Err(e) => app.set_error(format!("Send error: {e}")),
                },
                Err(e) => app.set_error(format!("Connection error: {e}")),
            }
        }
        "history" => {
            let chat_id = match active_chat_id(app) {
                Some(id) => id,
                None => {
                    if app.chats.is_empty() { app.set_error("No chat selected"); return; }
                    app.chats[app.chats_cursor].chat_id.clone()
                }
            };
            let mut limit = 50u32;
            for i in 1..words.len() {
                if words[i] == "--limit" {
                    if let Some(n) = words.get(i + 1) { limit = n.parse().unwrap_or(50); }
                }
            }
            let server = match store.load_server(server_id) {
                Ok(s) => s,
                Err(e) => { app.set_error(format!("Error: {e}")); return; }
            };
            let chat = match store.load_chat(server_id, &chat_id) {
                Ok(c) => c,
                Err(e) => { app.set_error(format!("Error: {e}")); return; }
            };
            match Transport::connect(&server.address, &server.shared_key_bytes).await {
                Ok(mut t) => match t.get_history(&chat_id, 0, 0, limit).await {
                    Ok(resp) => {
                        let lines: Vec<String> = resp.messages.iter().map(|msg| {
                            let text = crate::transport::decrypt_payload(
                                &msg.encrypted_payload,
                                &chat.encryption_key_bytes,
                                &msg.chat_id,
                            ).unwrap_or_else(|_| "<decryption failed>".into());
                            let ts = chrono::DateTime::from_timestamp_millis(msg.timestamp_ms)
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                .unwrap_or_else(|| msg.timestamp_ms.to_string());
                            format!("[{ts}] {text}")
                        }).collect();
                        if lines.is_empty() {
                            app.set_info(vec!["No messages".into()]);
                        } else {
                            // Inject into live panel
                            if let LiveMode::On { messages, .. } = &mut app.live_mode {
                                for l in &lines { messages.push_back(l.clone()); }
                            } else {
                                app.set_info(lines);
                            }
                        }
                    }
                    Err(e) => app.set_error(format!("Error: {e}")),
                },
                Err(e) => app.set_error(format!("Connection error: {e}")),
            }
        }
        "admin" => {
            if words.len() < 2 {
                app.set_error("Usage: admin <create-chat|delete-chat|list-chats> [args]"); return;
            }
            let server = match store.load_server(server_id) {
                Ok(s) => s,
                Err(e) => { app.set_error(format!("Error loading server: {e}")); return; }
            };
            let admin_key = match server.admin_key_bytes.clone() {
                Some(k) => k,
                None => { app.set_error("No admin key for this server"); return; }
            };
            let mut transport = match Transport::connect(&server.address, &server.shared_key_bytes).await {
                Ok(t) => t,
                Err(e) => { app.set_error(format!("Connection error: {e}")); return; }
            };
            let sub = words[1].to_lowercase();
            match sub.as_str() {
                "create-chat" => {
                    let id = match words.get(2) {
                        Some(s) if !s.is_empty() => *s,
                        _ => { app.set_error("Usage: admin create-chat <chat_id>"); return; }
                    };
                    let encryption_key = new_aes_key_bytes();
                    match transport.create_chat(&admin_key, id, 1000, 10_485_760).await {
                        Ok(r) if r.success => {
                            let card = crate::config::ChatCard {
                                server_id: server_id.to_string(),
                                chat_id: id.to_string(),
                                name: id.to_string(),
                                encryption_key: encryption_key.clone(),
                            };
                            match store.save_chat_card(&card) {
                                Ok(()) => {
                                    refresh_chats(app, store);
                                    app.set_info(vec![
                                        format!("Chat '{}' created", id),
                                        format!("Key: {}", hex::encode(&encryption_key)),
                                    ]);
                                }
                                Err(e) => app.set_error(format!("Chat created on server but local save failed: {e}")),
                            }
                        }
                        Ok(r) => app.set_error(format!("Server rejected: {}", r.error)),
                        Err(e) => app.set_error(format!("Error: {e}")),
                    }
                }
                "delete-chat" => {
                    let id = match words.get(2) {
                        Some(s) if !s.is_empty() => *s,
                        _ => { app.set_error("Usage: admin delete-chat <chat_id>"); return; }
                    };
                    match transport.delete_chat(&admin_key, id).await {
                        Ok(r) if r.success => app.set_info(vec![format!("Chat '{}' deleted", id)]),
                        Ok(r) => app.set_error(format!("Failed: {}", r.error)),
                        Err(e) => app.set_error(format!("Error: {e}")),
                    }
                }
                "list-chats" => {
                    match transport.list_chats(&admin_key).await {
                        Ok(r) => {
                            if r.chats.is_empty() {
                                app.set_info(vec!["No chats on server".into()]);
                            } else {
                                app.set_info(r.chats.iter().map(|c| {
                                    format!("  {} ({}..{})", c.chat_id, c.earliest_timestamp_ms, c.latest_timestamp_ms)
                                }).collect());
                            }
                        }
                        Err(e) => app.set_error(format!("Error: {e}")),
                    }
                }
                _ => app.set_error(format!("Unknown admin command: {sub}")),
            }
        }
        _ => app.set_error(format!("Unknown command: {}. Type 'help'.", words[0])),
    }
}

fn active_chat_id(app: &App) -> Option<String> {
    if let LiveMode::On { chat_id, .. } = &app.live_mode {
        Some(chat_id.clone())
    } else {
        None
    }
}

// ── Share commands ────────────────────────────────────────────────────────────

async fn exec_share(
    _input: &str,
    words: &[&str],
    app: &mut App,
    store: &Store,
    event_tx: &mpsc::UnboundedSender<LiveEvent>,
    share_state: &mut Option<(CancellationToken, Option<tokio::process::Child>)>,
) {
    let cmd = words[0].to_lowercase();
    match cmd.as_str() {
        "help" | "?" => {
            app.set_info(vec![
                "share commands:".into(),
                "  run-tor                Start Tor daemon (ESC to cancel)".into(),
                "  stop-tor               Stop Tor daemon".into(),
                "  receiving-data         Start onion share listener (ESC to stop)".into(),
                "  share-data             Interactive share wizard".into(),
                "  contacts / servers     Switch screen".into(),
            ]);
        }
        "run-tor" => {
            if share_state.is_some() {
                app.set_error("Share listener already running. Use stop-tor or close receiving-data first."); return;
            }
            let port: u16 = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(17777);
            let cancel = CancellationToken::new();
            app.tor_status = TorStatus::Starting(0);
            match crate::share::listen(port, store.clone(), event_tx.clone(), cancel.clone()).await {
                Ok((_addr, tor_child)) => {
                    *share_state = Some((cancel, tor_child));
                }
                Err(e) => {
                    app.tor_status = TorStatus::Off;
                    app.set_error(format!("Error: {e}"));
                }
            }
        }
        "stop-tor" => {
            match share_state.take() {
                Some((cancel, mut tor_child)) => {
                    cancel.cancel();
                    if let Some(ref mut child) = tor_child { let _ = child.kill().await; }
                    app.tor_status = TorStatus::Off;
                    app.receiving_locked = false;
                }
                None => app.set_error("No active Tor session"),
            }
        }
        "receiving-data" => {
            if share_state.is_some() {
                app.set_error("Already listening. Use stop-tor first."); return;
            }
            let port: u16 = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(17777);
            let cancel = CancellationToken::new();
            app.tor_status = TorStatus::Starting(0);
            app.receiving_locked = true;
            app.receiving_lines.clear();
            match crate::share::listen(port, store.clone(), event_tx.clone(), cancel.clone()).await {
                Ok((addr, tor_child)) => {
                    *share_state = Some((cancel, tor_child));
                    let addr_line = format!("Listening on {}", addr);
                    app.receiving_lines.push_back(addr_line);
                }
                Err(e) => {
                    app.tor_status = TorStatus::Off;
                    app.receiving_locked = false;
                    app.set_error(format!("Error: {e}"));
                }
            }
        }
        "share-data" => {
            let contacts = store.list_contacts().unwrap_or_default();
            if contacts.is_empty() {
                app.set_error("No contacts to share with"); return;
            }
            app.overlay = Overlay::ShareData(ShareStep::SelectContact { contacts, cursor: 0 });
        }
        _ => app.set_error(format!("Unknown command: {}. Type 'help'.", words[0])),
    }
}

// ── Share wizard confirmation ─────────────────────────────────────────────────

async fn confirm_share_step(app: &mut App, store: &Store) {
    let current = match &app.overlay {
        Overlay::ShareData(step) => step,
        _ => return,
    };

    match current {
        ShareStep::SelectContact { contacts, cursor } => {
            let contact = contacts[*cursor].clone();
            let servers = store.list_servers().unwrap_or_default();
            if servers.is_empty() {
                app.overlay = Overlay::Error("No servers configured".into());
                return;
            }
            app.overlay = Overlay::ShareData(ShareStep::SelectServer {
                contact,
                servers,
                cursor: 0,
            });
        }
        ShareStep::SelectServer { contact, servers, cursor } => {
            let server = servers[*cursor].clone();
            let contact = contact.clone();
            let chats = store.list_chats_for_server(&server.id).unwrap_or_default();
            if chats.is_empty() {
                app.overlay = Overlay::Error("No chats on this server".into());
                return;
            }
            app.overlay = Overlay::ShareData(ShareStep::SelectChat {
                contact,
                server,
                chats,
                cursor: 0,
            });
        }
        ShareStep::SelectChat { contact, server, chats, cursor } => {
            let chat = chats[*cursor].clone();
            let contact = contact.clone();
            let server = server.clone();
            app.overlay = Overlay::None;

            let identity = match store.load_identity() {
                Ok(Some(id)) => id,
                Ok(None) => { app.set_error("No identity found"); return; }
                Err(e) => { app.set_error(format!("Error: {e}")); return; }
            };

            let contact_record = match store.load_contact(&contact.id) {
                Ok(c) => c,
                Err(e) => { app.set_error(format!("Error: {e}")); return; }
            };

            let data = ShareData::Chat(ChatShareData {
                server_id: server.id.clone(),
                chat_id: chat.chat_id.clone(),
                name: chat.name.clone(),
                encryption_key: chat.encryption_key_bytes.clone(),
                server_admin_key: server.admin_key_bytes.clone(),
            });

            match crate::share::send_share(data, &contact_record, &identity, 17777).await {
                Ok(()) => app.set_info(vec![format!(
                    "Shared {}/{} with {}",
                    server.id, chat.chat_id, contact.name
                )]),
                Err(e) => app.set_error(format!("Share error: {e}")),
            }
        }
    }
}

fn overlay_cursor_up(app: &mut App) {
    match &mut app.overlay {
        Overlay::ShareData(ShareStep::SelectContact { cursor, .. }) => {
            *cursor = cursor.saturating_sub(1);
        }
        Overlay::ShareData(ShareStep::SelectServer { cursor, .. }) => {
            *cursor = cursor.saturating_sub(1);
        }
        Overlay::ShareData(ShareStep::SelectChat { cursor, .. }) => {
            *cursor = cursor.saturating_sub(1);
        }
        _ => {}
    }
}

fn overlay_cursor_down(app: &mut App) {
    match &mut app.overlay {
        Overlay::ShareData(ShareStep::SelectContact { contacts, cursor }) => {
            *cursor = (*cursor + 1).min(contacts.len().saturating_sub(1));
        }
        Overlay::ShareData(ShareStep::SelectServer { servers, cursor, .. }) => {
            *cursor = (*cursor + 1).min(servers.len().saturating_sub(1));
        }
        Overlay::ShareData(ShareStep::SelectChat { chats, cursor, .. }) => {
            *cursor = (*cursor + 1).min(chats.len().saturating_sub(1));
        }
        _ => {}
    }
}

fn overlay_back(app: &mut App, store: &Store) {
    match &app.overlay {
        Overlay::ShareData(ShareStep::SelectContact { .. }) => {
            app.overlay = Overlay::None;
        }
        Overlay::ShareData(ShareStep::SelectServer { .. }) => {
            let contacts = store.list_contacts().unwrap_or_default();
            app.overlay = Overlay::ShareData(ShareStep::SelectContact { contacts, cursor: 0 });
        }
        Overlay::ShareData(ShareStep::SelectChat { contact, .. }) => {
            let contact = contact.clone();
            let servers = store.list_servers().unwrap_or_default();
            app.overlay = Overlay::ShareData(ShareStep::SelectServer { contact, servers, cursor: 0 });
        }
        _ => app.overlay = Overlay::None,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fmt_ts(ts_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ts_ms)
        .map(|dt| dt.format("%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

fn new_aes_key_hex() -> String {
    use m_core::crypto::algorithms::symmetric::Aes256Gcm;
    use m_core::crypto::{CryptoKey, SymmetricCipher};
    hex::encode(Aes256Gcm::new().get_key().as_bytes())
}

fn new_aes_key_bytes() -> Vec<u8> {
    use m_core::crypto::algorithms::symmetric::Aes256Gcm;
    use m_core::crypto::{CryptoKey, SymmetricCipher};
    Aes256Gcm::new().get_key().as_bytes().to_vec()
}

fn address_short(addr: &str) -> String {
    use m_core::crypto::Hash;
    use m_core::crypto::algorithms::hash::Blake3Hash;
    let bytes = Blake3Hash::hash(addr.as_bytes(), 16).unwrap_or_default();
    hex::encode(&bytes[..4])
}

// ── Public entry point ────────────────────────────────────────────────────────

pub async fn run(store: Store) -> Result<()> {
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
    refresh_contacts(&mut app, &store);

    let (live_event_tx, mut live_event_rx) = mpsc::unbounded_channel::<LiveEvent>();
    let mut manager = ConnectionManager::new(store.clone(), live_event_tx.clone());
    let mut share_state: Option<(CancellationToken, Option<tokio::process::Child>)> = None;

    let _ = manager.start_all_enabled();

    loop {
        draw(terminal, &app)?;

        let has_event = event::poll(Duration::from_millis(16))?;

        if has_event {
            match event::read()? {
                Event::Key(key) => {
                    // Ctrl+C always quits
                    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                        cleanup_and_quit(&mut app, &mut manager, &mut share_state).await;
                        break;
                    }

                    // ESC handling
                    if key.code == KeyCode::Esc {
                        match &app.overlay {
                            Overlay::None => {
                                // Exit live mode
                                if matches!(app.live_mode, LiveMode::On { .. }) {
                                    app.live_mode = LiveMode::Off;
                                } else if app.receiving_locked || matches!(app.tor_status, TorStatus::Starting(_)) {
                                    // Cancel run-tor / receiving-data
                                    if let Some((cancel, mut tor_child)) = share_state.take() {
                                        cancel.cancel();
                                        if let Some(ref mut child) = tor_child { let _ = child.kill().await; }
                                    }
                                    app.tor_status = TorStatus::Off;
                                    app.receiving_locked = false;
                                }
                            }
                            Overlay::Error(_) | Overlay::Info(_) => {
                                app.overlay = Overlay::None;
                            }
                            Overlay::ShareData(_) => {
                                overlay_back(&mut app, &store);
                            }
                        }
                        continue;
                    }

                    // Arrow keys for list navigation and overlay navigation
                    if key.code == KeyCode::Up {
                        match &app.overlay {
                            Overlay::ShareData(_) => overlay_cursor_up(&mut app),
                            Overlay::Info(_) => { app.info_scroll = app.info_scroll.saturating_sub(1); }
                            _ => cursor_up(&mut app),
                        }
                        continue;
                    }
                    if key.code == KeyCode::Down {
                        if let Overlay::Info(ref lines) = app.overlay {
                            let max = lines.len().saturating_sub(1) as u16;
                            app.info_scroll = (app.info_scroll + 1).min(max);
                        } else {
                            match &app.overlay {
                                Overlay::ShareData(_) => overlay_cursor_down(&mut app),
                                _ => cursor_down(&mut app),
                            }
                        }
                        continue;
                    }

                    // Scroll live messages panel
                    if let LiveMode::On { scroll, messages, .. } = &mut app.live_mode {
                        if key.code == KeyCode::PageUp {
                            *scroll = scroll.saturating_sub(5);
                            continue;
                        }
                        if key.code == KeyCode::PageDown {
                            *scroll = (*scroll + 5).min(messages.len().saturating_sub(1) as u16);
                            continue;
                        }
                    }

                    // Enter
                    if key.code == KeyCode::Enter {
                        match &app.overlay {
                            Overlay::ShareData(_) => {
                                confirm_share_step(&mut app, &store).await;
                                continue;
                            }
                            Overlay::Error(_) | Overlay::Info(_) => {
                                app.overlay = Overlay::None;
                                continue;
                            }
                            Overlay::None => {}
                        }

                        if app.is_input_locked() { continue; }

                        let input = app.input.clone();
                        app.input.clear();
                        app.cursor_pos = 0;

                        if input.trim().is_empty() { continue; }

                        // In live mode send message directly, no commands
                        if let LiveMode::On { server_id, chat_id, .. } = &app.live_mode {
                            let sid = server_id.clone();
                            let cid = chat_id.clone();
                            match store.load_server(&sid) {
                                Ok(server) => match store.load_chat(&sid, &cid) {
                                    Ok(chat) => match Transport::connect(&server.address, &server.shared_key_bytes).await {
                                        Ok(mut t) => match t.send_message(&cid, &input, &chat.encryption_key_bytes).await {
                                            Ok(r) if r.accepted => {}
                                            Ok(r) => app.set_error(format!("Rejected: {}", r.error)),
                                            Err(e) => app.set_error(format!("Send error: {e}")),
                                        },
                                        Err(e) => app.set_error(format!("Connection error: {e}")),
                                    },
                                    Err(e) => app.set_error(format!("Error loading chat: {e}")),
                                },
                                Err(e) => app.set_error(format!("Error loading server: {e}")),
                            }
                            continue;
                        }

                        let quit = execute_command(
                            &input, &mut app, &store, &mut manager,
                            &live_event_tx, &mut share_state,
                        ).await;
                        if quit {
                            cleanup_and_quit(&mut app, &mut manager, &mut share_state).await;
                            break;
                        }
                        continue;
                    }

                    if app.is_input_locked() { continue; }
                    if matches!(app.overlay, Overlay::Error(_) | Overlay::Info(_) | Overlay::ShareData(_)) {
                        continue;
                    }

                    // Text editing
                    match key.code {
                        KeyCode::Char(c) => {
                            app.input.insert(app.cursor_pos, c);
                            app.cursor_pos += c.len_utf8();
                        }
                        KeyCode::Backspace => {
                            if app.cursor_pos > 0 {
                                let prev = app.input[..app.cursor_pos]
                                    .char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
                                app.input.remove(prev);
                                app.cursor_pos = prev;
                            }
                        }
                        KeyCode::Delete => {
                            if app.cursor_pos < app.input.len() {
                                app.input.remove(app.cursor_pos);
                            }
                        }
                        KeyCode::Left => {
                            if app.cursor_pos > 0 {
                                app.cursor_pos = app.input[..app.cursor_pos]
                                    .char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
                            }
                        }
                        KeyCode::Right => {
                            if app.cursor_pos < app.input.len() {
                                let c = app.input[app.cursor_pos..].chars().next().unwrap();
                                app.cursor_pos += c.len_utf8();
                            }
                        }
                        KeyCode::Home => { app.cursor_pos = 0; }
                        KeyCode::End => { app.cursor_pos = app.input.len(); }
                        _ => {}
                    }
                }
                Event::Paste(text) => {
                    if !app.is_input_locked() {
                        for ch in text.chars() {
                            app.input.insert(app.cursor_pos, ch);
                            app.cursor_pos += ch.len_utf8();
                        }
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }

        // Process live events
        while let Ok(event) = live_event_rx.try_recv() {
            handle_live_event(event, &mut app, &mut manager, &store);
        }
    }

    Ok(())
}

fn cursor_up(app: &mut App) {
    match &app.screen {
        Screen::Contacts => {
            app.contacts_cursor = app.contacts_cursor.saturating_sub(1);
        }
        Screen::Servers => {
            app.servers_cursor = app.servers_cursor.saturating_sub(1);
        }
        Screen::Chats { .. } => {
            app.chats_cursor = app.chats_cursor.saturating_sub(1);
        }
        Screen::Share => {}
    }
}

fn cursor_down(app: &mut App) {
    match &app.screen {
        Screen::Contacts => {
            if !app.contacts.is_empty() {
                app.contacts_cursor = (app.contacts_cursor + 1).min(app.contacts.len() - 1);
            }
        }
        Screen::Servers => {
            if !app.servers.is_empty() {
                app.servers_cursor = (app.servers_cursor + 1).min(app.servers.len() - 1);
            }
        }
        Screen::Chats { .. } => {
            if !app.chats.is_empty() {
                app.chats_cursor = (app.chats_cursor + 1).min(app.chats.len() - 1);
            }
        }
        Screen::Share => {}
    }
}

fn handle_live_event(event: LiveEvent, app: &mut App, manager: &mut ConnectionManager, store: &Store) {
    match event {
        LiveEvent::Message(msg) => {
            if let LiveMode::On { server_id, chat_id, messages, scroll } = &mut app.live_mode {
                if *server_id == msg.server_id && *chat_id == msg.chat_name {
                    let line = format!("[{}] {}", msg.timestamp, msg.text);
                    messages.push_back(line);
                    if messages.len() > MAX_MESSAGES { messages.pop_front(); }
                    // Auto-scroll to bottom
                    *scroll = messages.len().saturating_sub(1) as u16;
                }
            }
        }
        LiveEvent::SyncComplete { .. } => {
            refresh_chats(app, store);
            refresh_servers(app, store);
        }
        LiveEvent::Error { server_id, message } => {
            if let Screen::Chats { server_id: sid } = &app.screen {
                if *sid == server_id {
                    app.set_error(format!("[{server_id}] {message}"));
                }
            }
        }
        LiveEvent::ServerUnavailable(sid) => {
            manager.handle_unavailable_server(&sid);
            refresh_servers(app, store);
        }
        LiveEvent::Disconnected(sid) => {
            manager.handle_disconnected(&sid);
            refresh_servers(app, store);
        }
        LiveEvent::ShareReceived(data) => {
            let result = match &data {
                ShareData::Server(s) => store.upsert_shared_server(s),
                ShareData::Chat(c) => store.upsert_shared_chat(c),
            };
            let line = match result {
                Ok(msg) => format!("Received: {}", msg),
                Err(e) => format!("Receive error: {e}"),
            };
            if app.receiving_lines.len() >= MAX_RECEIVING_LINES {
                app.receiving_lines.pop_front();
            }
            app.receiving_lines.push_back(line);
            refresh_servers(app, store);
        }
        LiveEvent::TorBootstrap(pct) => {
            if pct >= 100 {
                app.tor_status = TorStatus::Running;
            } else {
                app.tor_status = TorStatus::Starting(pct);
            }
        }
    }
}

async fn cleanup_and_quit(
    _app: &mut App,
    manager: &mut ConnectionManager,
    share_state: &mut Option<(CancellationToken, Option<tokio::process::Child>)>,
) {
    if let Some((cancel, mut tor_child)) = share_state.take() {
        cancel.cancel();
        if let Some(ref mut child) = tor_child { let _ = child.kill().await; }
    }
    manager.stop_all();
}

// ── Drawing ───────────────────────────────────────────────────────────────────

fn draw(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &App) -> Result<()> {
    terminal.draw(|f| {
        let full = f.area();

        // Outer layout: main area + input bar
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(full);

        let main_area = outer[0];
        let input_area = outer[1];

        // Draw screen content
        match &app.screen {
            Screen::Contacts => draw_contacts(f, main_area, app),
            Screen::Servers  => draw_servers(f, main_area, app),
            Screen::Chats { .. } => draw_chats(f, main_area, app),
            Screen::Share    => draw_share(f, main_area, app),
        }

        // Draw input bar
        draw_input(f, input_area, app);

        // Draw overlay last (on top)
        if !matches!(app.overlay, Overlay::None) {
            draw_overlay(f, full, app);
        }
    })?;
    Ok(())
}

fn item_style(is_cursor: bool) -> Style {
    if is_cursor {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    }
}

fn item_border_style(is_cursor: bool) -> Style {
    if is_cursor {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn draw_contacts(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Contacts ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.contacts.is_empty() {
        let hint = Paragraph::new("No contacts. Use 'load <path> <name>' to import.")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint, inner);
        return;
    }

    // Each contact gets a 3-line item block (border top + 1 line + border bottom)
    let item_h = 3u16;
    let visible = (inner.height / item_h) as usize;
    let total = app.contacts.len();
    let start = if app.contacts_cursor >= visible {
        app.contacts_cursor - visible + 1
    } else {
        0
    }.min(total.saturating_sub(visible));

    let mut y = inner.y;
    for (i, contact) in app.contacts.iter().enumerate().skip(start).take(visible) {
        if y + item_h > inner.y + inner.height { break; }
        let is_cur = i == app.contacts_cursor;
        let item_area = Rect { x: inner.x, y, width: inner.width, height: item_h };
        let b = Block::default()
            .borders(Borders::ALL)
            .border_style(item_border_style(is_cur));
        let bi = b.inner(item_area);
        f.render_widget(b, item_area);
        let line = Line::from(vec![
            Span::styled(format!("  {}", contact.name), item_style(is_cur)),
            Span::styled(format!("  ID: {}", contact.id), Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(line), bi);
        y += item_h;
    }
}

fn draw_servers(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Servers ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.servers.is_empty() {
        let hint = Paragraph::new("No servers. Use 'import <path>' or 'deploy <user> <ip> <pass>'.")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint, inner);
        return;
    }

    let item_h = 3u16;
    let visible = (inner.height / item_h) as usize;
    let total = app.servers.len();
    let start = if app.servers_cursor >= visible {
        app.servers_cursor - visible + 1
    } else {
        0
    }.min(total.saturating_sub(visible));

    let mut y = inner.y;
    for (i, server) in app.servers.iter().enumerate().skip(start).take(visible) {
        if y + item_h > inner.y + inner.height { break; }
        let is_cur = i == app.servers_cursor;
        let item_area = Rect { x: inner.x, y, width: inner.width, height: item_h };
        let b = Block::default()
            .borders(Borders::ALL)
            .border_style(item_border_style(is_cur));
        let bi = b.inner(item_area);
        f.render_widget(b, item_area);

        let state_color = match server.state {
            NodeState::Enabled => Color::Green,
            NodeState::Disabled => Color::DarkGray,
            NodeState::Unavailable => Color::Red,
        };
        let last_ts = app.servers_last_ts.get(i).and_then(|t| *t);
        let ts_span = match last_ts {
            Some(ts) => Span::styled(format!("  {}", fmt_ts(ts)), Style::default().fg(Color::DarkGray)),
            None => Span::raw(""),
        };
        let line = Line::from(vec![
            Span::styled(format!("  {}", server.name), item_style(is_cur)),
            Span::styled(format!("  ID: {}", server.id), Style::default().fg(Color::DarkGray)),
            ts_span,
            Span::styled(format!("  [{}]", server.state), Style::default().fg(state_color)),
        ]);
        f.render_widget(Paragraph::new(line), bi);
        y += item_h;
    }
}

fn draw_chats(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let server_id = if let Screen::Chats { server_id } = &app.screen {
        server_id.as_str()
    } else {
        ""
    };

    // Split: left ~30% for chat list, right ~70% for live messages
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    // Left: chat list
    let left_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(format!(" {} ", server_id));
    let left_inner = left_block.inner(cols[0]);
    f.render_widget(left_block, cols[0]);

    if app.chats.is_empty() {
        let hint = Paragraph::new("No chats.\n'import <path>'")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint, left_inner);
    } else {
        let item_h = 3u16;
        let visible = (left_inner.height / item_h) as usize;
        let total = app.chats.len();
        let start = if app.chats_cursor >= visible {
            app.chats_cursor - visible + 1
        } else {
            0
        }.min(total.saturating_sub(visible));

        let mut y = left_inner.y;
        for (i, chat) in app.chats.iter().enumerate().skip(start).take(visible) {
            if y + item_h > left_inner.y + left_inner.height { break; }
            let is_cur = i == app.chats_cursor;

            // Highlight active live chat
            let is_live = match &app.live_mode {
                LiveMode::On { chat_id, .. } => chat_id == &chat.chat_id,
                _ => false,
            };

            let item_area = Rect { x: left_inner.x, y, width: left_inner.width, height: item_h };
            let b = Block::default()
                .borders(Borders::ALL)
                .border_style(if is_live {
                    Style::default().fg(Color::Yellow)
                } else {
                    item_border_style(is_cur)
                });
            let bi = b.inner(item_area);
            f.render_widget(b, item_area);

            let state_color = match chat.state {
                NodeState::Enabled => Color::Green,
                NodeState::Disabled => Color::DarkGray,
                NodeState::Unavailable => Color::Red,
            };
            let text_style = if is_cur {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let ts_span = if chat.state == NodeState::Enabled && chat.last_synced_ts > 0 {
                Span::styled(format!(" {}", fmt_ts(chat.last_synced_ts)), Style::default().fg(Color::DarkGray))
            } else {
                Span::raw("")
            };
            let line = Line::from(vec![
                Span::styled(format!(" {}", chat.name), text_style),
                ts_span,
                Span::styled(format!(" [{}]", chat.state), Style::default().fg(state_color)),
            ]);
            f.render_widget(Paragraph::new(line), bi);
            y += item_h;
        }
    }

    // Right: live messages or hint
    match &app.live_mode {
        LiveMode::On { chat_id, messages, scroll, .. } => {
            let right_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(format!(" {} — live ", chat_id))
                .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
            let right_inner = right_block.inner(cols[1]);
            f.render_widget(right_block, cols[1]);

            let lines: Vec<Line> = messages.iter().map(|s| Line::from(s.as_str())).collect();
            let height = right_inner.height as usize;
            let auto_scroll = messages.len().saturating_sub(height) as u16;
            let actual_scroll = (*scroll).max(auto_scroll.saturating_sub(0));
            let para = Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((actual_scroll, 0));
            f.render_widget(para, right_inner);
        }
        LiveMode::Off => {
            let right_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" messages ");
            let right_inner = right_block.inner(cols[1]);
            f.render_widget(right_block, cols[1]);
            let hint = Paragraph::new("Use 'live' to enter live mode for selected chat.")
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center);
            // Center vertically
            let y_offset = right_inner.height / 2;
            let hint_area = Rect { y: right_inner.y + y_offset, ..right_inner };
            f.render_widget(hint, hint_area);
        }
    }
}

fn draw_share(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Share / Tor ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let tor_line = match &app.tor_status {
        TorStatus::Off => Line::from(vec![
            Span::raw("Tor: "),
            Span::styled("off", Style::default().fg(Color::DarkGray)),
        ]),
        TorStatus::Starting(pct) => Line::from(vec![
            Span::raw("Tor: "),
            Span::styled(format!("starting {}%", pct), Style::default().fg(Color::Yellow)),
            Span::styled(" (ESC to cancel)", Style::default().fg(Color::DarkGray)),
        ]),
        TorStatus::Running => Line::from(vec![
            Span::raw("Tor: "),
            Span::styled("running", Style::default().fg(Color::Green)),
        ]),
    };

    let recv_indicator = if app.receiving_locked {
        Line::from(vec![
            Span::styled("Receiving data... ", Style::default().fg(Color::Yellow)),
            Span::styled("(ESC to stop)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from("")
    };

    let mut all_lines: Vec<Line> = vec![tor_line, recv_indicator, Line::from("")];

    for line in &app.receiving_lines {
        all_lines.push(Line::from(line.as_str()));
    }

    let height = inner.height as usize;
    let scroll = all_lines.len().saturating_sub(height) as u16;
    let para = Paragraph::new(all_lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(para, inner);
}

fn draw_input(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let prompt = app.input_prompt();

    let (border_style, content) = if app.is_input_locked() {
        (
            Style::default().fg(Color::DarkGray),
            Line::from(vec![
                Span::styled(format!(" {}> ", prompt), Style::default().fg(Color::DarkGray)),
                Span::styled("[locked — ESC to stop]", Style::default().fg(Color::Red)),
            ]),
        )
    } else if matches!(app.live_mode, LiveMode::On { .. }) {
        (
            Style::default().fg(Color::Yellow),
            Line::from(vec![
                Span::styled(format!(" {}> ", prompt), Style::default().fg(Color::Yellow)),
                Span::styled(&app.input, Style::default().fg(Color::White)),
            ]),
        )
    } else {
        (
            Style::default().fg(Color::Cyan),
            Line::from(vec![
                Span::styled(format!(" {}> ", prompt), Style::default().fg(Color::Green)),
                Span::styled(&app.input, Style::default().fg(Color::White)),
            ]),
        )
    };

    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = input_block.inner(area);
    f.render_widget(input_block, area);
    f.render_widget(Paragraph::new(content), inner);

    if !app.is_input_locked() {
        let prompt_len = (prompt.len() + 3) as u16; // " > " prefix
        let cursor_x = inner.x + prompt_len + app.input[..app.cursor_pos].chars().count() as u16;
        let cursor_y = inner.y;
        f.set_cursor_position((cursor_x, cursor_y));
    }
}

fn draw_overlay(f: &mut ratatui::Frame, area: Rect, app: &App) {
    match &app.overlay {
        Overlay::None => {}
        Overlay::Error(msg) => {
            let lines: Vec<Line> = std::iter::once(Line::from(vec![
                Span::styled("Error: ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::raw(msg.as_str()),
            ]))
            .chain(std::iter::once(Line::from(
                Span::styled("  [ESC or Enter to close]", Style::default().fg(Color::DarkGray))
            )))
            .collect();
            render_overlay_box(f, area, " Error ", &lines, Color::Red, 0);
        }
        Overlay::Info(lines) => {
            let mut ls: Vec<Line> = lines.iter()
                .map(|s| Line::from(s.as_str()))
                .collect();
            let popup_h = (ls.len() as u16 + 3).min(area.height.saturating_sub(4));
            let visible = popup_h.saturating_sub(2) as usize;
            let hint = if ls.len() > visible {
                "  [↑/↓ scroll  ESC close]"
            } else {
                "  [ESC or Enter to close]"
            };
            ls.push(Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray))));
            render_overlay_box(f, area, " Info ", &ls, Color::Cyan, app.info_scroll);
        }
        Overlay::ShareData(step) => {
            draw_share_wizard(f, area, step);
        }
    }
}

fn render_overlay_box(f: &mut ratatui::Frame, area: Rect, title: &str, lines: &[Line], color: Color, scroll: u16) {
    let max_w = area.width.saturating_sub(8).min(80);
    let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(max_w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup = Rect { x, y, width: max_w, height: h };

    f.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(title);
    let inner = block.inner(popup);
    f.render_widget(block, popup);
    let para = Paragraph::new(lines.to_vec())
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(para, inner);
}

fn draw_share_wizard(f: &mut ratatui::Frame, area: Rect, step: &ShareStep) {
    let (title, items, cursor, hint): (&str, Vec<String>, usize, &str) = match step {
        ShareStep::SelectContact { contacts, cursor } => (
            " Share — Select Contact ",
            contacts.iter().map(|c| format!("  {} ({})", c.name, c.id)).collect(),
            *cursor,
            "↑/↓ navigate  Enter select  ESC cancel",
        ),
        ShareStep::SelectServer { servers, cursor, .. } => (
            " Share — Select Server ",
            servers.iter().map(|s| format!("  {} [{}]", s.name, s.state)).collect(),
            *cursor,
            "↑/↓ navigate  Enter select  ESC back",
        ),
        ShareStep::SelectChat { chats, cursor, .. } => (
            " Share — Select Chat ",
            chats.iter().map(|c| format!("  {} [{}]", c.name, c.state)).collect(),
            *cursor,
            "↑/↓ navigate  Enter confirm  ESC back",
        ),
    };

    let max_w = area.width.saturating_sub(8).min(70);
    let h = ((items.len() + 4) as u16).min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(max_w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup = Rect { x, y, width: max_w, height: h };

    f.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .title(title);
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let mut lines: Vec<Line> = items.iter().enumerate().map(|(i, item)| {
        if i == cursor {
            Line::from(Span::styled(item.as_str(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
        } else {
            Line::from(item.as_str())
        }
    }).collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray))));

    let visible_h = inner.height as usize;
    let scroll = if cursor >= visible_h { (cursor - visible_h + 1) as u16 } else { 0 };
    let para = Paragraph::new(lines).scroll((scroll, 0));
    f.render_widget(para, inner);
}
