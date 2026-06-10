//! **Realtime WebSocket hub** (PRODUCT.md Phase 5): a `tokio::broadcast` channel
//! fanned out to every `/ws/*` subscriber. Producers (scan progress, new
//! findings, remediation events) call [`Hub::publish`]; each connection gets its
//! own forwarding task. One-way fan-out - inbound client frames are ignored.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use tokio::sync::broadcast;

use crate::state::AppState;

/// Default fan-out ring capacity (lagging clients drop oldest messages).
pub const HUB_CAPACITY: usize = 1024;

/// Cloneable realtime fan-out handle. Cheap to clone - wraps a broadcast sender.
#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<String>,
}

impl Hub {
    /// Fresh hub with [`HUB_CAPACITY`].
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(HUB_CAPACITY);
        Self { tx }
    }

    /// Publish a message to all subscribers; returns how many received it.
    pub fn publish(&self, msg: impl Into<String>) -> usize {
        self.tx.send(msg.into()).unwrap_or(0)
    }

    /// Subscribe a new consumer.
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

/// Axum handler: upgrade to WebSocket and stream hub messages to the client.
pub async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    let rx = state.hub.subscribe();
    ws.on_upgrade(move |socket| forward(socket, rx))
}

async fn forward(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Ok(msg) => {
                    if socket.send(Message::Text(msg.into())).await.is_err() {
                        break; // client gone
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(_)) => {} // ignore client → server frames
                _ => break,       // closed / error
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_reaches_subscribers() {
        let hub = Hub::new();
        let mut a = hub.subscribe();
        let mut b = hub.subscribe();
        let n = hub.publish("hello");
        assert_eq!(n, 2);
        assert_eq!(a.recv().await.unwrap(), "hello");
        assert_eq!(b.recv().await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_zero() {
        let hub = Hub::new();
        assert_eq!(hub.publish("noone"), 0);
    }
}
