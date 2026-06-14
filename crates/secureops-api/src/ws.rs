//! **Realtime WebSocket hub** (PRODUCT.md Phase 5): a `tokio::broadcast` channel
//! fanned out to `/ws/*` subscribers. Producers (scan progress, new findings,
//! remediation events) call [`Hub::publish_tenant`]; each connection gets its
//! own forwarding task. One-way fan-out - inbound client frames are ignored.
//!
//! Security (beta blockers fixed):
//! - **Authentication required.** The upgrade is rejected with `401` unless the
//!   request carries a valid session JWT (`Authorization: Bearer` or
//!   `?access_token=`) or `X-API-Key`. Previously any anonymous client could
//!   subscribe.
//! - **Per-tenant isolation.** Each message is tagged with its owning tenant and
//!   delivered only to subscribers of that tenant (plus untagged/global events).
//!   Previously every subscriber received every tenant's events.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::auth::{hash_api_key, verify_jwt, Claims};
use crate::state::AppState;

/// Default fan-out ring capacity (lagging clients drop oldest messages).
pub const HUB_CAPACITY: usize = 1024;

/// A fan-out message tagged with the tenant it belongs to. `tenant == None`
/// marks a global/system event delivered to every authenticated subscriber.
#[derive(Clone, Debug)]
pub struct HubMsg {
    pub tenant: Option<String>,
    pub payload: String,
}

/// Cloneable realtime fan-out handle. Cheap to clone - wraps a broadcast sender.
#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<HubMsg>,
}

impl Hub {
    /// Fresh hub with [`HUB_CAPACITY`].
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(HUB_CAPACITY);
        Self { tx }
    }

    /// Publish a tenant-scoped message; returns how many receivers got it.
    pub fn publish_tenant(&self, tenant: impl Into<String>, msg: impl Into<String>) -> usize {
        self.tx
            .send(HubMsg {
                tenant: Some(tenant.into()),
                payload: msg.into(),
            })
            .unwrap_or(0)
    }

    /// Publish a global (non-tenant) message to every subscriber.
    pub fn publish_global(&self, msg: impl Into<String>) -> usize {
        self.tx
            .send(HubMsg {
                tenant: None,
                payload: msg.into(),
            })
            .unwrap_or(0)
    }

    /// Subscribe a new consumer.
    pub fn subscribe(&self) -> broadcast::Receiver<HubMsg> {
        self.tx.subscribe()
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
pub struct WsQuery {
    /// Browser-friendly auth: clients that cannot set an `Authorization` header
    /// on a WebSocket pass `?access_token=<jwt>`.
    pub access_token: Option<String>,
}

/// Resolve the principal for a WS upgrade from a Bearer header, `X-API-Key`, or
/// a `?access_token=` query parameter. Returns `None` if unauthenticated.
async fn resolve_ws_principal(
    state: &AppState,
    headers: &HeaderMap,
    access_token: Option<&str>,
) -> Option<Claims> {
    if let Some(tok) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        if let Ok(c) = verify_jwt(&state.jwt_secret, tok) {
            return Some(c);
        }
    }
    if let Some(tok) = access_token {
        if let Ok(c) = verify_jwt(&state.jwt_secret, tok) {
            return Some(c);
        }
    }
    if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        let hashed = hash_api_key(&state.api_key_pepper, key);
        if let Ok(Some(c)) = state.store.lookup_api_key(&hashed).await {
            return Some(c);
        }
    }
    None
}

/// Axum handler: authenticate, then upgrade and stream this tenant's hub
/// messages to the client. Unauthenticated upgrades get `401`.
pub async fn ws_handler(
    State(state): State<AppState>,
    Query(q): Query<WsQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(claims) = resolve_ws_principal(&state, &headers, q.access_token.as_deref()).await
    else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "unauthorized",
        )
            .into_response();
    };
    let tenant = claims.tenant;
    let rx = state.hub.subscribe();
    ws.on_upgrade(move |socket| forward(socket, rx, tenant))
}

async fn forward(mut socket: WebSocket, mut rx: broadcast::Receiver<HubMsg>, tenant: String) {
    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Ok(msg) => {
                    // Deliver only this tenant's events (and untagged globals).
                    let deliver = match &msg.tenant {
                        None => true,
                        Some(t) => t == &tenant,
                    };
                    if deliver
                        && socket.send(Message::Text(msg.payload.into())).await.is_err()
                    {
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
    async fn tenant_messages_reach_all_subscribers_of_the_channel() {
        let hub = Hub::new();
        let mut a = hub.subscribe();
        let mut b = hub.subscribe();
        let n = hub.publish_tenant("t1", "hello");
        assert_eq!(n, 2);
        let ma = a.recv().await.unwrap();
        assert_eq!(ma.payload, "hello");
        assert_eq!(ma.tenant.as_deref(), Some("t1"));
        assert_eq!(b.recv().await.unwrap().payload, "hello");
    }

    #[tokio::test]
    async fn global_messages_are_untagged() {
        let hub = Hub::new();
        let mut a = hub.subscribe();
        hub.publish_global("sys");
        let m = a.recv().await.unwrap();
        assert_eq!(m.payload, "sys");
        assert!(m.tenant.is_none());
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_zero() {
        let hub = Hub::new();
        assert_eq!(hub.publish_tenant("t", "noone"), 0);
    }
}
