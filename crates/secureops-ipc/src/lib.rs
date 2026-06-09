
//! # secureops-ipc
//!
//! Unix-domain-socket JSON-RPC protocol and peer-credential authentication for
//! the SecureOps control plane.
//!
//! ## Why this crate exists (PRODUCT.md A.3, A.4)
//!
//! The privileged daemon (`secureops-daemon`) and the unprivileged clients
//! (`secureops-cli`, the `secureops-napi` shim) talk over a **unix domain
//! socket**. Per PRODUCT.md A.3 ("Process & privilege model"), the daemon does
//! **not** trust a bearer token the agent could leak — instead it authenticates
//! the connecting process's `uid`/`pid` directly from the kernel via
//! `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS). This module is the single
//! shared definition of:
//!
//! * the request/response wire enums ([`IpcRequest`] / [`IpcResponse`]),
//! * the peer-credential type ([`PeerCred`]) and its OS-specific reader
//!   ([`peer_cred`]),
//! * the server ([`serve`]) and client ([`connect`]) skeletons.
//!
//! Because both Ring 1 (napi) and Ring 2 (daemon) speak this protocol over the
//! same socket, the wire format is a frozen contract (PRODUCT.md A.5): all enums
//! derive `serde` with `rename_all = "camelCase"` / `snake_case` tags so the
//! bytes are stable across the migration window.
//!
//! All transport bodies are fully implemented (peer_cred, serve, connect, request).

use std::path::Path;

use serde::{Deserialize, Serialize};

// Re-export the frozen core contract carried across the wire so callers of this
// crate (daemon, cli, napi) get one consistent set of types.
pub use secureops_core::{AuditOptions, AuditReport, MonitorAlert, MonitorStatus};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised while framing, transporting, or authenticating IPC messages.
///
/// PRODUCT.md A.3/A.4: transport + peer-credential failures are distinct from
/// application-level failures (which travel in-band as [`IpcResponse::Err`]).
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Underlying socket / framing I/O failed.
    #[error("ipc transport i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A frame could not be (de)serialized to/from JSON.
    #[error("ipc codec error: {0}")]
    Codec(#[from] serde_json::Error),

    /// The connecting peer failed the `SO_PEERCRED`/`LOCAL_PEERCRED` check
    /// (PRODUCT.md A.3 — uid/pid not in the allowed set).
    #[error("ipc peer authentication denied: {0}")]
    Unauthorized(String),

    /// Peer-credential introspection is not implemented for this OS.
    #[error("ipc peer-cred not supported on this platform")]
    UnsupportedPlatform,
}

/// Convenience result alias for IPC transport operations.
pub type IpcResult<T> = std::result::Result<T, IpcError>;

// ---------------------------------------------------------------------------
// Wire protocol — request enum (PRODUCT.md A.4)
// ---------------------------------------------------------------------------

/// A request sent from a client (cli / napi) to the daemon over the socket.
///
/// Internally tagged so the JSON stays self-describing and stable across the
/// TS↔Rust migration window (PRODUCT.md A.5). Variant tags are `camelCase`.
///
/// PRODUCT.md A.4: this is the control-plane verb set shared by every Ring-1/2
/// process. Variants map onto the daemon workflows in PRODUCT.md Part B.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum IpcRequest {
    /// Run a (read-only) audit and return the [`AuditReport`] (PRODUCT.md B.2).
    ///
    /// `AuditOptions` (core) is `Default + Copy` but does not derive serde, so
    /// the wire form carries the three knobs flatly; the daemon rebuilds an
    /// `AuditOptions` from them before invoking `run_audit`.
    Audit {
        /// Deep-scan toggle forwarded from the caller.
        #[serde(default)]
        deep: bool,
        /// Auto-fix toggle forwarded from the caller.
        #[serde(default)]
        fix: bool,
        /// JSON-output toggle forwarded from the caller.
        #[serde(default)]
        json: bool,
    },

    /// Query daemon liveness + monitor status (PRODUCT.md B.4).
    Status,

    /// Trip the kill switch / request enforcement shutdown (PRODUCT.md A.3,
    /// B.4). The optional human-readable `reason` is recorded in the audit log.
    Kill {
        /// Why the kill switch was tripped (for the signed log).
        reason: Option<String>,
    },

    /// Subscribe to the live [`MonitorAlert`] stream from the AlertBus
    /// (PRODUCT.md B.4). The server keeps the connection open and pushes
    /// [`IpcResponse::Alert`] frames until the client disconnects.
    Subscribe,

    /// Fetch the most recent monitor alerts (bounded by `limit`).
    Alerts {
        /// Maximum number of alerts to return.
        limit: Option<u32>,
    },

    /// Ask the daemon to reload its policy bundle from disk
    /// (PRODUCT.md B.4 hot-reload). The PDP lives in `secureops-policy`.
    ReloadPolicy,

    /// Liveness ping; the daemon answers with [`IpcResponse::Ok`].
    Ping,
}

// ---------------------------------------------------------------------------
// Wire protocol — response enum (PRODUCT.md A.4)
// ---------------------------------------------------------------------------

/// A response (or pushed event) sent from the daemon back to a client.
///
/// Application-level failures travel **in-band** as [`IpcResponse::Err`] so a
/// failing check never tears down the transport (mirrors the audit "run never
/// aborts" rule, PRODUCT.md B.2). Transport/auth failures use [`IpcError`].
///
/// `serde` internally tagged, `camelCase` — frozen wire contract (A.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum IpcResponse {
    /// Success carrying an arbitrary JSON payload (e.g. a serialized
    /// [`AuditReport`] or [`MonitorStatus`]).
    Ok(serde_json::Value),

    /// In-band application error with a human-readable message.
    Err(String),

    /// A pushed alert frame delivered on a [`IpcRequest::Subscribe`] stream
    /// (PRODUCT.md B.4).
    Alert(MonitorAlert),
}

impl IpcResponse {
    /// Build an [`IpcResponse::Ok`] from any serializable value.
    ///
    /// PRODUCT.md A.4 — convenience used by the daemon's request handler to wrap
    /// typed results (reports, status) into the generic `Ok(Value)` frame.
    pub fn ok<T: Serialize>(value: &T) -> IpcResult<Self> {
        Ok(IpcResponse::Ok(serde_json::to_value(value)?))
    }

    /// Build an [`IpcResponse::Err`] from any displayable error.
    pub fn err(msg: impl std::fmt::Display) -> Self {
        IpcResponse::Err(msg.to_string())
    }
}

// ---------------------------------------------------------------------------
// Peer credentials (PRODUCT.md A.3)
// ---------------------------------------------------------------------------

/// Kernel-reported identity of the process on the other end of the socket.
///
/// PRODUCT.md A.3: the daemon authenticates the connecting process's `uid`/`pid`
/// via `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) rather than trusting a
/// token the agent could leak. This is the value those calls populate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCred {
    /// Effective user id of the connecting process.
    pub uid: u32,
    /// Process id of the connecting process.
    pub pid: i32,
}

impl PeerCred {
    /// Authorization predicate: is this peer the expected service/owner uid?
    ///
    /// PRODUCT.md A.3 — the daemon runs as the dedicated `secureops` user and
    /// accepts connections from the owning operator uid. Real policy is wired by
    /// the daemon; this is the building block.
    pub fn is_authorized(&self, allowed_uid: u32) -> bool {
        self.uid == allowed_uid
    }
}

/// Read the peer credentials of a connected unix-socket stream (PRODUCT.md A.3).
///
/// Uses tokio's built-in `peer_cred()` which calls `SO_PEERCRED` (Linux) or
/// `getpeereid` (macOS) through the kernel. `pid` is `-1` on platforms where
/// it is not available in a single call.
#[cfg(unix)]
pub fn peer_cred(stream: &tokio::net::UnixStream) -> std::io::Result<PeerCred> {
    let ucred = stream.peer_cred()?;
    Ok(PeerCred {
        uid: ucred.uid(),
        pid: ucred.pid().unwrap_or(-1),
    })
}

// ---------------------------------------------------------------------------
// Handler trait — the daemon-side request dispatcher
// ---------------------------------------------------------------------------

/// Server-side request handler implemented by `secureops-daemon`.
///
/// PRODUCT.md A.4/B.4 — [`serve`] accepts a connection, authenticates the peer
/// ([`peer_cred`]), then routes each decoded [`IpcRequest`] through this trait.
/// Keeping the handler abstract lets the daemon inject its PDP/PEP/AlertBus
/// wiring while this crate owns only the transport.
#[async_trait::async_trait]
pub trait IpcHandler: Send + Sync {
    /// Handle one request from an authenticated peer, producing one response.
    ///
    /// The `peer` argument carries the kernel-verified [`PeerCred`] so handlers
    /// can apply per-uid authorization (PRODUCT.md A.3).
    async fn handle(&self, peer: PeerCred, request: IpcRequest) -> IpcResponse;
}

// ---------------------------------------------------------------------------
// Server skeleton (PRODUCT.md A.4, B.4)
// ---------------------------------------------------------------------------

/// Bind a `UnixListener` at `path` and serve newline-delimited JSON-RPC until
/// the listener is dropped. Each connection is authenticated via [`peer_cred`]
/// and dispatched through `handler` (PRODUCT.md A.3/A.4/B.4).
#[cfg(unix)]
pub async fn serve<H, P>(path: P, handler: H) -> IpcResult<()>
where
    H: IpcHandler + 'static,
    P: AsRef<Path>,
{
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    let listener = UnixListener::bind(path.as_ref())?;
    let handler = Arc::new(handler);

    loop {
        let (stream, _) = listener.accept().await?;
        let peer = peer_cred(&stream).unwrap_or(PeerCred {
            uid: u32::MAX,
            pid: -1,
        });
        let handler = handler.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut lines = BufReader::new(read_half).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let request: IpcRequest = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(e) => {
                        let resp = IpcResponse::err(e);
                        let _ = write_half
                            .write_all(
                                format!("{}\n", serde_json::to_string(&resp).unwrap_or_default())
                                    .as_bytes(),
                            )
                            .await;
                        continue;
                    }
                };
                let response = handler.handle(peer, request).await;
                let _ = write_half
                    .write_all(
                        format!("{}\n", serde_json::to_string(&response).unwrap_or_default())
                            .as_bytes(),
                    )
                    .await;
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Client skeleton (PRODUCT.md A.4)
// ---------------------------------------------------------------------------

/// A connected client handle to the daemon's control socket.
///
/// PRODUCT.md A.4 — used by `secureops-cli` and `secureops-napi` to send
/// [`IpcRequest`]s and read [`IpcResponse`]s over the unix socket.
#[cfg(unix)]
pub struct IpcClient {
    stream: tokio::net::UnixStream,
}

#[cfg(unix)]
impl IpcClient {
    /// Write a newline-delimited JSON [`IpcRequest`], read one [`IpcResponse`].
    pub async fn request(&mut self, request: IpcRequest) -> IpcResult<IpcResponse> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let json = serde_json::to_string(&request)?;
        let (read_half, mut write_half) = self.stream.split();
        write_half
            .write_all(format!("{}\n", json).as_bytes())
            .await?;

        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let response: IpcResponse = serde_json::from_str(line.trim())?;
        Ok(response)
    }
}

/// Connect to the daemon control socket at `path` (PRODUCT.md A.4).
#[cfg(unix)]
pub async fn connect<P: AsRef<Path>>(path: P) -> IpcResult<IpcClient> {
    use tokio::net::UnixStream;
    let stream = UnixStream::connect(path.as_ref()).await?;
    Ok(IpcClient { stream })
}

// ---------------------------------------------------------------------------
// Tests — wire-contract round-trips only (no I/O, compile-time safety net)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_json() {
        let req = IpcRequest::Kill {
            reason: Some("manual trip".to_string()),
        };
        let bytes = serde_json::to_vec(&req).expect("serialize");
        let back: IpcRequest = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(req, back);
    }

    #[test]
    fn response_ok_wraps_value() {
        let resp = IpcResponse::ok(&"pong").expect("ok wrap");
        match resp {
            IpcResponse::Ok(v) => assert_eq!(v, serde_json::json!("pong")),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn peer_cred_authorization() {
        let pc = PeerCred {
            uid: 501,
            pid: 4242,
        };
        assert!(pc.is_authorized(501));
        assert!(!pc.is_authorized(0));
    }
}
