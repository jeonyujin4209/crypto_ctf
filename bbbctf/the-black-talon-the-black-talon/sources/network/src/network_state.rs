use crate::{
    alive_connections::AliveConnections,
    broadcast::{Broadcast, BroadcastedMessage},
    user::User,
};

use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Default, Debug)]
pub struct NetworkStateX {
    pub users: Vec<Option<User>>,
    pub channels: HashMap<String, Channel>,
    pub broadcast: Broadcast<BroadcastedMessage>,
    pub active_connections: AliveConnections,
}
pub type NetworkState = Arc<RwLock<NetworkStateX>>;

#[derive(Default, Debug)]
pub struct Channel {
    pub users: Vec<usize>,
}
