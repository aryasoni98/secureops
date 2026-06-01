//! SecureOps runtime monitors — `secureops-monitors`.
//!
//! Implements the Phase-2 "monitors daemon" surface from **PRODUCT.md B.4
//! (Daemon runtime loop)** and PRODUCT.md §A architecture diagram
//! (`AlertBus → SQLite`):
//!
//! 1. `init_db` migrates the SQLite store (alerts + audit-log tables).
//! 2. An [`AlertBus`] (`tokio::sync::broadcast`) fans [`MonitorAlert`]s out to
//!    every consumer (SQLite persistence, ratatui TUI, axum/SSE dashboard,
//!    OpenTelemetry export — see PRODUCT.md §"Observability surfaces").
//! 3. Each [`Monitor`] is spawned *by value* into a `JoinSet`, holding a clone
//!    of the bus sender and a [`CancellationToken`]; `token.cancel()` fans a
//!    clean shutdown to every monitor (PRODUCT.md B.4 steps 3 & 5).
//! 4. The cost circuit breaker is published over a `tokio::sync::watch`
//!    [`CircuitState`] channel; the gateway hook refuses new sessions while it
//!    reads [`CircuitState::Tripped`] (PRODUCT.md B.9 step 2).
//!
//! SQLite persistence is live (rusqlite bundled): `init_db` + `run_alert_persistence`.
//! All 4 monitor implementations and AlertBus are fully operational.

#![allow(dead_code, unused_variables)]

pub mod cost;
pub mod credential;
pub mod memory_integrity;
pub mod skill_scanner;

pub use cost::CostMonitor;
pub use credential::CredentialMonitor;
pub use memory_integrity::MemoryIntegrityMonitor;
pub use skill_scanner::SkillScanner;

use std::sync::Arc;

use async_trait::async_trait;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::{broadcast, watch};

/// Current UTC time as an RFC3339 string (`new Date().toISOString()`), shared by
/// the monitor run loops for alert timestamps.
pub fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

// Re-export the runtime wire types this crate produces/consumes so downstream
// crates (daemon, ipc) can depend on us without also reaching into core.
pub use secureops_core::{
    BehavioralBaseline, CostEntry, CostProjection, CostReport, MonitorAlert, MonitorStatus,
    Severity, SkillScanResult,
};

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// Cooperative cancellation handle handed to every [`Monitor::run`].
///
/// To avoid pulling in the `tokio-util` dependency for its
/// `CancellationToken`, we model it ourselves over a `tokio::sync::watch<bool>`
/// receiver (PRODUCT.md B.4 step 5: `token.cancel()` fans a clean shutdown to
/// every monitor). `true` on the channel means "shut down now".
#[derive(Clone, Debug)]
pub struct CancellationToken {
    rx: watch::Receiver<bool>,
}

/// The producer side of a [`CancellationToken`]; the daemon holds this and
/// calls [`CancellationSource::cancel`] on signal.
#[derive(Debug)]
pub struct CancellationSource {
    tx: watch::Sender<bool>,
}

impl CancellationToken {
    /// Create a linked (`source`, `token`) pair. Clone the token for each
    /// monitor; dropping/cancelling the source fans out to all clones.
    pub fn new() -> (CancellationSource, CancellationToken) {
        let (tx, rx) = watch::channel(false);
        (CancellationSource { tx }, CancellationToken { rx })
    }

    /// `true` once cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves when cancellation is requested. Monitors `tokio::select!` this
    /// against their work loop for prompt, clean shutdown.
    pub async fn cancelled(&mut self) {
        // Wait until the watched value becomes `true` (or the sender drops).
        let _ = self.rx.wait_for(|cancelled| *cancelled).await;
    }
}

impl CancellationSource {
    /// Request shutdown of every linked [`CancellationToken`].
    pub fn cancel(&self) {
        let _ = self.tx.send(true);
    }
}

// ---------------------------------------------------------------------------
// AlertBus
// ---------------------------------------------------------------------------

/// Default capacity for the broadcast ring buffer (lagging consumers drop
/// oldest alerts rather than blocking producers).
pub const ALERT_BUS_CAPACITY: usize = 1024;

/// The in-process alert fan-out (PRODUCT.md §A: `AlertBus → SQLite`).
///
/// Wraps a `tokio::sync::broadcast::Sender<MonitorAlert>`; every monitor holds
/// a clone of the inner sender, and each consumer (SQLite writer, TUI, web
/// dashboard, OTel exporter) subscribes its own receiver.
#[derive(Clone, Debug)]
pub struct AlertBus(pub broadcast::Sender<MonitorAlert>);

impl AlertBus {
    /// Create a fresh bus with [`ALERT_BUS_CAPACITY`].
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(ALERT_BUS_CAPACITY);
        AlertBus(tx)
    }

    /// Create a bus with an explicit ring-buffer capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        AlertBus(tx)
    }

    /// Publish an alert to all current subscribers. Returns the number of
    /// receivers it reached (`Err` only when there are none).
    pub fn publish(
        &self,
        alert: MonitorAlert,
    ) -> Result<usize, broadcast::error::SendError<MonitorAlert>> {
        self.0.send(alert)
    }

    /// Subscribe a new consumer (e.g. the SQLite persistence task).
    pub fn subscribe(&self) -> broadcast::Receiver<MonitorAlert> {
        self.0.subscribe()
    }
}

impl Default for AlertBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Monitor trait
// ---------------------------------------------------------------------------

/// A long-running runtime monitor (PRODUCT.md B.4 step 3).
///
/// Implementations are spawned *by value* into the daemon's `JoinSet`, each
/// holding a clone of the [`AlertBus`] sender and a [`CancellationToken`].
/// `run` should loop until cancellation, publishing [`MonitorAlert`]s onto the
/// bus, and return promptly once `cancel.cancelled()` resolves.
#[async_trait]
pub trait Monitor: Send + Sync {
    /// Stable identifier used in [`MonitorAlert::monitor`] and status output.
    fn name(&self) -> &'static str;

    /// Run the monitor loop until cancelled. Takes the bus and a cancellation
    /// token by value so the daemon can spawn the monitor onto a `JoinSet`.
    async fn run(&self, bus: AlertBus, cancel: CancellationToken);
}

// The four monitor implementations live in their own modules
// (`cost`, `credential`, `memory_integrity`, `skill_scanner`) and are
// re-exported at the crate root above.

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

/// The cost / kill-switch circuit-breaker state (PRODUCT.md B.9).
///
/// Published over a `tokio::sync::watch` channel by [`circuit_channel`]; the
/// gateway hook reads `*rx.borrow()` and refuses new sessions while it is
/// [`CircuitState::Tripped`] (PRODUCT.md B.9 step 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — new sessions allowed.
    #[default]
    Armed,
    /// Tripped (cost breaker, eBPF chain match, canary read, or operator
    /// `kill`) — the gateway refuses new sessions.
    Tripped,
}

/// Create the circuit-breaker `watch` channel, starting [`CircuitState::Armed`].
///
/// The daemon keeps the [`watch::Sender`] (handing a clone to [`CostMonitor`]),
/// and clones the [`watch::Receiver`] into the gateway hook (PRODUCT.md B.4
/// step 4 / B.9 step 2).
pub fn circuit_channel() -> (watch::Sender<CircuitState>, watch::Receiver<CircuitState>) {
    watch::channel(CircuitState::Armed)
}

// ---------------------------------------------------------------------------
// SQLite persistence
// ---------------------------------------------------------------------------

/// Open/migrate the SQLite store — `alerts` + `audit_log` tables (PRODUCT.md B.4 step 2).
pub async fn init_db(path: &str) -> anyhow::Result<()> {
    use rusqlite::Connection;
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS alerts (
             id        INTEGER PRIMARY KEY AUTOINCREMENT,
             timestamp TEXT    NOT NULL,
             severity  TEXT    NOT NULL,
             monitor   TEXT    NOT NULL,
             message   TEXT    NOT NULL,
             details   TEXT
         );
         CREATE TABLE IF NOT EXISTS audit_log (
             seq        INTEGER PRIMARY KEY,
             timestamp  TEXT NOT NULL,
             prev_hash  TEXT NOT NULL,
             hash       TEXT NOT NULL,
             entry_json TEXT NOT NULL
         );",
    )?;
    Ok(())
}

/// Drain the [`AlertBus`] into the SQLite `alerts` table (PRODUCT.md §A `AlertBus → SQLite`).
///
/// Runs until the bus sender is dropped or the subscription lags and errors.
pub async fn run_alert_persistence(bus: AlertBus, db_path: Arc<str>) -> anyhow::Result<()> {
    use rusqlite::Connection;

    let conn = Connection::open(db_path.as_ref())?;
    let mut rx = bus.subscribe();
    loop {
        match rx.recv().await {
            Ok(alert) => {
                let details = alert.details.as_deref();
                conn.execute(
                    "INSERT INTO alerts (timestamp, severity, monitor, message, details) VALUES (?1,?2,?3,?4,?5)",
                    rusqlite::params![
                        alert.timestamp,
                        format!("{:?}", alert.severity),
                        alert.monitor,
                        alert.message,
                        details,
                    ],
                )?;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("alert_persistence lagged by {n} — some alerts not persisted");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn alert_bus_fans_out_to_subscribers() {
        let bus = AlertBus::new();
        let mut rx = bus.subscribe();
        let alert = MonitorAlert {
            timestamp: "2026-05-29T00:00:00Z".into(),
            severity: Severity::Info,
            monitor: "test".into(),
            message: "hello".into(),
            details: None,
        };
        bus.publish(alert.clone()).expect("at least one subscriber");
        assert_eq!(rx.recv().await.expect("alert delivered"), alert);
    }

    #[tokio::test]
    async fn cancellation_token_propagates() {
        let (src, token) = CancellationToken::new();
        assert!(!token.is_cancelled());
        src.cancel();
        let mut token = token;
        token.cancelled().await;
        assert!(token.is_cancelled());
    }

    #[test]
    fn circuit_channel_starts_armed() {
        let (_tx, rx) = circuit_channel();
        assert_eq!(*rx.borrow(), CircuitState::Armed);
    }
}
