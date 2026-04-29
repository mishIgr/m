use std::collections::HashMap;
use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::live::{self, LiveEvent};
use crate::store::{NodeState, Store};

pub struct ConnectionManager {
    store: Store,
    event_tx: mpsc::UnboundedSender<LiveEvent>,
    cancels: HashMap<String, CancellationToken>,
}

impl ConnectionManager {
    pub fn new(store: Store, event_tx: mpsc::UnboundedSender<LiveEvent>) -> Self {
        Self {
            store,
            event_tx,
            cancels: HashMap::new(),
        }
    }

    pub fn start_all_enabled(&mut self) -> Result<()> {
        let servers = self.store.list_enabled_servers()?;
        for server in servers {
            self.start_server_inner(&server.id, &server.address, &server.shared_key_bytes);
        }
        Ok(())
    }

    pub fn start_server(&mut self, server_id: &str) -> Result<()> {
        let server = self.store.load_server(server_id)?;
        if server.state != NodeState::Enabled {
            anyhow::bail!("Server '{}' is not enabled (state: {})", server_id, server.state);
        }
        self.start_server_inner(&server.id, &server.address, &server.shared_key_bytes);
        Ok(())
    }

    fn start_server_inner(&mut self, server_id: &str, address: &str, shared_key_bytes: &[u8]) {
        if let Some(old) = self.cancels.remove(server_id) {
            old.cancel();
        }

        let cancel = CancellationToken::new();
        self.cancels.insert(server_id.to_string(), cancel.clone());

        let chats = self.store.list_enabled_chats_for_server(server_id)
            .unwrap_or_default();

        let chat_pairs: Vec<_> = chats.iter()
            .map(|c| (c.chat_id.clone(), c.clone()))
            .collect();

        let sid = server_id.to_string();
        let addr = address.to_string();
        let key = shared_key_bytes.to_vec();
        let store = self.store.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let _ = live::subscribe(
                &sid, &addr, &key, &chat_pairs, store, cancel, event_tx,
            ).await;
        });
    }

    pub fn stop_server(&mut self, server_id: &str) {
        if let Some(cancel) = self.cancels.remove(server_id) {
            cancel.cancel();
        }
    }

    pub fn stop_all(&mut self) {
        for (_, cancel) in self.cancels.drain() {
            cancel.cancel();
        }
    }

    pub fn restart_server(&mut self, server_id: &str) -> Result<()> {
        self.stop_server(server_id);
        self.start_server(server_id)
    }

    #[allow(dead_code)]
    pub fn is_running(&self, server_id: &str) -> bool {
        self.cancels.contains_key(server_id)
    }

    pub fn handle_unavailable_server(&mut self, server_id: &str) {
        self.cancels.remove(server_id);
        let _ = self.store.set_server_state(server_id, NodeState::Unavailable);
    }

    pub fn handle_disconnected(&mut self, server_id: &str) {
        self.cancels.remove(server_id);
        let _ = self.store.set_server_state(server_id, NodeState::Unavailable);
    }
}
