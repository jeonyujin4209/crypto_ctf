use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use tracing::info;

#[derive(Default, Debug)]
pub struct AliveConnections {
    connections: Arc<RwLock<HashSet<usize>>>,
}

pub struct BorrowedConnection {
    user_id: usize,
    peer_addr: SocketAddr,
    connections: Arc<RwLock<HashSet<usize>>>,
}

impl AliveConnections {
    pub fn connect(&mut self, peer_addr: SocketAddr, uid: usize) -> BorrowedConnection {
        let mut connections = self.connections.write().unwrap();
        connections.insert(uid);
        BorrowedConnection {
            user_id: uid,
            peer_addr,
            connections: self.connections.clone(),
        }
    }

    pub fn is_connected(&self, uid: usize) -> bool {
        let connections = self.connections.read().unwrap();
        connections.contains(&uid)
    }
}

impl BorrowedConnection {
    pub fn disconnect(self) {
        info!(peer_addr=%self.peer_addr, "Closed connection");
    }
}

impl Drop for BorrowedConnection {
    fn drop(&mut self) {
        let mut connections = self.connections.write().unwrap();
        connections.remove(&self.user_id);
    }
}
