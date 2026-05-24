#[derive(Clone, Default, Debug)]
pub struct BroadcastedMessage {
    pub from: String,
    pub channel: String,
    pub message: String,
}

#[derive(Debug)]
pub struct Broadcast<T> {
    tx: tokio::sync::broadcast::Sender<T>,
}

impl<T> Broadcast<T> {
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<T> {
        self.tx.subscribe()
    }
    pub fn send(&self, value: T) {
        let _ = self.tx.send(value);
    }
}

impl<T: Clone> Default for Broadcast<T> {
    fn default() -> Self {
        // We drop the immediate receiver to allow for consistently getting subscribers later on
        let (tx, _rx) = tokio::sync::broadcast::channel(1024);
        Self { tx }
    }
}
