use std::collections::HashMap;
use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::live::{self, LiveEvent};
use crate::store::{NodeState, Store};

pub struct ConnectionManager {
    store: Store,
    event_tx: mpsc::UnboundedSender<LiveEvent>,
    cancels: HashMap<u128, CancellationToken>,
    max_forward_seq: u128,
}

impl ConnectionManager {
    pub fn new(store: Store, event_tx: mpsc::UnboundedSender<LiveEvent>, max_forward_seq: u128) -> Self {
        Self {
            store,
            event_tx,
            cancels: HashMap::new(),
            max_forward_seq,
        }
    }

    pub fn start_all_enabled(&mut self) -> Result<()> {
        let servers = self.store.list_enabled_servers()?;
        m_core::log_info!("connection_manager: start_all_enabled found {} enabled servers", servers.len());
        for server in servers {
            self.start_server_inner(server.id, &server.address, &server.shared_key_bytes);
        }
        Ok(())
    }

    pub fn start_server(&mut self, server_id: u128) -> Result<()> {
        m_core::log_info!("connection_manager: start_server server={:032x}", server_id);
        let server = self.store.load_server(server_id)?;
        if server.state != NodeState::Enabled {
            m_core::log_warn!("connection_manager: start_server server={:032x} not enabled state={}", server_id, server.state);
            anyhow::bail!("Server '{:032x}' is not enabled (state: {})", server_id, server.state);
        }
        self.start_server_inner(server.id, &server.address, &server.shared_key_bytes);
        Ok(())
    }

    fn start_server_inner(&mut self, server_id: u128, address: &str, shared_key_bytes: &[u8]) {
        if let Some(old) = self.cancels.remove(&server_id) {
            m_core::log_debug!("connection_manager: cancelling old task for server={:032x}", server_id);
            old.cancel();
        }

        let cancel = CancellationToken::new();
        self.cancels.insert(server_id, cancel.clone());

        let chats = match self.store.list_enabled_chats_for_server(server_id) {
            Ok(c) => c,
            Err(e) => {
                m_core::log_warn!("connection_manager: list_enabled_chats_for_server failed server={:032x}: {}", server_id, e);
                vec![]
            }
        };

        m_core::log_info!("connection_manager: spawning live task server={:032x} address={} chats={}", server_id, address, chats.len());

        let chat_pairs: Vec<_> = chats.iter()
            .map(|c| (c.chat_id, c.clone()))
            .collect();

        let addr = address.to_string();
        let key = shared_key_bytes.to_vec();
        let store = self.store.clone();
        let event_tx = self.event_tx.clone();
        let max_forward_seq = self.max_forward_seq;

        tokio::spawn(async move {
            m_core::log_debug!("connection_manager: live task started server={:032x}", server_id);
            match live::subscribe(server_id, &addr, &key, &chat_pairs, store, cancel, event_tx, max_forward_seq).await {
                Ok(()) => { m_core::log_debug!("connection_manager: live task exited cleanly server={:032x}", server_id) }
                Err(e) => m_core::log_error!("connection_manager: live task exited with error server={:032x}: {}", server_id, e),
            }
        });
    }

    pub fn stop_server(&mut self, server_id: u128) {
        if let Some(cancel) = self.cancels.remove(&server_id) {
            m_core::log_info!("connection_manager: stop_server server={:032x}", server_id);
            cancel.cancel();
        } else {
            m_core::log_debug!("connection_manager: stop_server server={:032x} was not running", server_id);
        }
    }

    pub fn stop_all(&mut self) {
        let count = self.cancels.len();
        m_core::log_info!("connection_manager: stop_all stopping {} servers", count);
        for (_, cancel) in self.cancels.drain() {
            cancel.cancel();
        }
    }

    pub fn restart_server(&mut self, server_id: u128) -> Result<()> {
        m_core::log_info!("connection_manager: restart_server server={:032x}", server_id);
        self.stop_server(server_id);
        self.start_server(server_id)
    }

    #[allow(dead_code)]
    pub fn is_running(&self, server_id: u128) -> bool {
        self.cancels.contains_key(&server_id)
    }

    pub fn handle_unavailable_server(&mut self, server_id: u128) {
        m_core::log_error!("connection_manager: server unavailable server={:032x}", server_id);
        self.cancels.remove(&server_id);
        if let Err(e) = self.store.set_server_state(server_id, NodeState::Unavailable) {
            m_core::log_error!("connection_manager: handle_unavailable_server persist failed server={:032x}: {}", server_id, e);
        }
    }

    pub fn handle_disconnected(&mut self, server_id: u128) {
        m_core::log_info!("connection_manager: server disconnected server={:032x}", server_id);
        self.cancels.remove(&server_id);
        if let Err(e) = self.store.set_server_state(server_id, NodeState::Unavailable) {
            m_core::log_error!("connection_manager: handle_disconnected persist failed server={:032x}: {}", server_id, e);
        }
    }
}
