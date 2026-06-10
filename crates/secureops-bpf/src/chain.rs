//! Per-PID **exfil-chain correlation** — the kernel-free userspace half of the
//! kernel PEP (PRODUCT.md B.6 step 2).
//!
//! The dangerous, kernel-observable pattern is an `openat` of a secret-shaped
//! path followed, **on the same PID within a short window**, by a `connect`:
//!
//! ```text
//!   openat("/path/.env")  ──(≤ TTL ms, same pid)──▶  connect(unknown host)
//! ```
//!
//! [`ChainCorrelator`] consumes the [`SyscallEvent`] stream (from the eBPF ring
//! buffer on Linux, or any source elsewhere) and emits an [`ExfilChain`] the
//! instant the second half lands inside the window. It contains **no `unsafe`,
//! no kernel calls, and no I/O**, so it unit-tests on every platform.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use secureops_core::{now_iso, MonitorAlert, Severity};

use crate::{SyscallEvent, SyscallKind};

/// Default correlation window: an `openat(secret)` chains with a later
/// `connect` only if they occur within this many milliseconds on the same PID
/// (PRODUCT.md B.6 — "within a short per-PID time window").
pub const DEFAULT_TTL_MS: u64 = 500;

/// A confirmed `openat(secret) → connect(unknown)` exfil chain on one PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfilChain {
    /// Originating process id.
    pub pid: i32,
    /// Process command name at the time of the read.
    pub comm: String,
    /// The credential/secret path that was read (first half of the chain).
    pub cred_path: String,
    /// The outbound destination dialed (second half).
    pub dest: String,
    /// Milliseconds between the secret read and the dial-out.
    pub gap_ms: u64,
}

impl ExfilChain {
    /// Render as a `Critical` [`MonitorAlert`] for the AlertBus. The daemon's
    /// `bpf_wire` publishes this and trips the circuit breaker (PRODUCT.md B.6
    /// step 4). `details` is a JSON object kept camelCase for wire-format
    /// consistency with the rest of the tool.
    pub fn to_alert(&self) -> MonitorAlert {
        MonitorAlert {
            timestamp: now_iso(),
            severity: Severity::Critical,
            monitor: "ebpf-chain".into(),
            message: format!(
                "exfil chain: pid {} ({}) read {} then dialed {} ({}ms apart)",
                self.pid, self.comm, self.cred_path, self.dest, self.gap_ms
            ),
            details: Some(format!(
                "{{\"pid\":{},\"comm\":{:?},\"credPath\":{:?},\"dest\":{:?},\"gapMs\":{}}}",
                self.pid, self.comm, self.cred_path, self.dest, self.gap_ms
            )),
        }
    }
}

/// First-half state remembered for a PID after it reads a secret.
#[derive(Debug, Clone)]
struct PidState {
    cred_path: String,
    comm: String,
    opened_at_ms: u64,
}

/// Correlates `openat(secret)` with a later `connect` on the same PID inside a
/// TTL window (PRODUCT.md B.6 step 2).
///
/// Interior-mutable via a `Mutex<HashMap>` so a single shared correlator can be
/// fed from the daemon's event-drain task; the map is keyed by PID. (A
/// lock-free `DashMap` is an option, but the drain is single-consumer, so a
/// `Mutex` keeps the dependency surface — and `#![forbid(unsafe_code)]` — clean.)
#[derive(Debug)]
pub struct ChainCorrelator {
    ttl_ms: u64,
    states: Mutex<HashMap<i32, PidState>>,
    base: Instant,
}

impl ChainCorrelator {
    /// Correlator with an explicit window in milliseconds.
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            ttl_ms,
            states: Mutex::new(HashMap::new()),
            base: Instant::now(),
        }
    }

    /// Correlator with the [`DEFAULT_TTL_MS`] window.
    pub fn with_default_ttl() -> Self {
        Self::new(DEFAULT_TTL_MS)
    }

    /// Monotonic millis since this correlator was created (used by [`observe`]).
    ///
    /// [`observe`]: ChainCorrelator::observe
    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    /// Observe an event using the internal monotonic clock. Returns the matched
    /// [`ExfilChain`] when this event completes a chain.
    pub fn observe(&self, ev: &SyscallEvent) -> Option<ExfilChain> {
        let now = self.now_ms();
        self.observe_at(ev, now)
    }

    /// Observe with an explicit timestamp — deterministic, for tests and replay.
    pub fn observe_at(&self, ev: &SyscallEvent, now_ms: u64) -> Option<ExfilChain> {
        let mut states = self.states.lock().expect("chain state mutex poisoned");
        match ev.kind {
            // First half: a secret-shaped open. Remember it for this PID.
            SyscallKind::Openat if ev.is_secret_read() => {
                states.insert(
                    ev.pid,
                    PidState {
                        cred_path: ev.path_or_host.clone(),
                        comm: ev.comm.clone(),
                        opened_at_ms: now_ms,
                    },
                );
                None
            }
            // Second half: a dial-out. Chain only if a fresh secret-read is on
            // record for this PID.
            SyscallKind::Connect => {
                let st = states.remove(&ev.pid)?;
                let gap = now_ms.saturating_sub(st.opened_at_ms);
                if gap <= self.ttl_ms {
                    Some(ExfilChain {
                        pid: ev.pid,
                        comm: st.comm,
                        cred_path: st.cred_path,
                        dest: ev.path_or_host.clone(),
                        gap_ms: gap,
                    })
                } else {
                    None // window expired — not a chain
                }
            }
            // Keep process identity fresh for an in-window PID.
            SyscallKind::Execve => {
                if let Some(st) = states.get_mut(&ev.pid) {
                    st.comm = ev.comm.clone();
                }
                None
            }
            // Non-credential opens (and anything else) never start a chain.
            SyscallKind::Openat => None,
        }
    }

    /// Drop PID states older than the TTL relative to `now_ms`, so long-lived
    /// idle PIDs don't accumulate. The daemon can call this periodically.
    pub fn prune(&self, now_ms: u64) {
        let mut states = self.states.lock().expect("chain state mutex poisoned");
        states.retain(|_, st| now_ms.saturating_sub(st.opened_at_ms) <= self.ttl_ms);
    }

    /// Number of PIDs currently inside the secret-read window (status/tests).
    pub fn tracked(&self) -> usize {
        self.states
            .lock()
            .expect("chain state mutex poisoned")
            .len()
    }
}

/// Whether the kernel PEP only watches (alert + escalate) or also denies the
/// exfil `connect` inline in-kernel via LSM-BPF (PRODUCT.md B.6 step 3).
///
/// Inline deny is only real on Linux with the `ebpf` feature and an LSM-BPF
/// hook; on macOS / kernel-free builds `Enforce` still alerts and trips the
/// circuit breaker but cannot block the syscall — the egress proxy PEP enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Detect + escalate only.
    #[default]
    Observe,
    /// Detect + escalate **and** request an in-kernel `connect` deny.
    Enforce,
}

/// The action the PEP takes on a matched chain, derived from [`EnforcementMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainAction {
    /// Publish an alert and trip the circuit breaker (observe-only platforms).
    AlertEscalate,
    /// Additionally deny the `connect` syscall in-kernel (Linux LSM-BPF).
    DenyConnect,
}

/// Map an [`EnforcementMode`] to the [`ChainAction`] for a matched chain.
pub fn decide(mode: EnforcementMode, _chain: &ExfilChain) -> ChainAction {
    match mode {
        EnforcementMode::Observe => ChainAction::AlertEscalate,
        EnforcementMode::Enforce => ChainAction::DenyConnect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(pid: i32, path: &str) -> SyscallEvent {
        SyscallEvent::new(pid, "agent", SyscallKind::Openat, path)
    }
    fn connect(pid: i32, host: &str) -> SyscallEvent {
        SyscallEvent::new(pid, "agent", SyscallKind::Connect, host)
    }

    #[test]
    fn secret_read_then_connect_within_ttl_is_a_chain() {
        let c = ChainCorrelator::with_default_ttl();
        assert_eq!(c.observe_at(&open(7, "/root/.env"), 1_000), None);
        let chain = c
            .observe_at(&connect(7, "1.2.3.4:443"), 1_400)
            .expect("chain fires within TTL");
        assert_eq!(chain.pid, 7);
        assert_eq!(chain.cred_path, "/root/.env");
        assert_eq!(chain.dest, "1.2.3.4:443");
        assert_eq!(chain.gap_ms, 400);
        // State is consumed on match.
        assert_eq!(c.tracked(), 0);
    }

    #[test]
    fn non_credential_open_then_connect_is_not_a_chain() {
        let c = ChainCorrelator::with_default_ttl();
        assert_eq!(c.observe_at(&open(7, "/tmp/readme.txt"), 1_000), None);
        assert_eq!(c.observe_at(&connect(7, "1.2.3.4:443"), 1_100), None);
    }

    #[test]
    fn connect_after_ttl_expiry_is_not_a_chain() {
        let c = ChainCorrelator::new(500);
        assert_eq!(c.observe_at(&open(7, "/root/.env"), 1_000), None);
        // 501ms later — window expired.
        assert_eq!(c.observe_at(&connect(7, "1.2.3.4:443"), 1_501), None);
    }

    #[test]
    fn connect_without_prior_read_is_not_a_chain() {
        let c = ChainCorrelator::with_default_ttl();
        assert_eq!(c.observe_at(&connect(7, "1.2.3.4:443"), 1_000), None);
    }

    #[test]
    fn chains_are_per_pid() {
        let c = ChainCorrelator::with_default_ttl();
        c.observe_at(&open(7, "/root/.env"), 1_000);
        // A different PID's connect must not consume PID 7's pending read.
        assert_eq!(c.observe_at(&connect(8, "1.2.3.4:443"), 1_050), None);
        assert!(c.observe_at(&connect(7, "1.2.3.4:443"), 1_100).is_some());
    }

    #[test]
    fn prune_drops_expired_states() {
        let c = ChainCorrelator::new(500);
        c.observe_at(&open(7, "/root/.env"), 1_000);
        assert_eq!(c.tracked(), 1);
        c.prune(2_000);
        assert_eq!(c.tracked(), 0);
    }

    #[test]
    fn decide_maps_mode_to_action() {
        let chain = ExfilChain {
            pid: 7,
            comm: "agent".into(),
            cred_path: "/root/.env".into(),
            dest: "1.2.3.4:443".into(),
            gap_ms: 10,
        };
        assert_eq!(
            decide(EnforcementMode::Observe, &chain),
            ChainAction::AlertEscalate
        );
        assert_eq!(
            decide(EnforcementMode::Enforce, &chain),
            ChainAction::DenyConnect
        );
    }

    #[test]
    fn alert_is_critical_and_tagged() {
        let chain = ExfilChain {
            pid: 7,
            comm: "agent".into(),
            cred_path: "/root/.env".into(),
            dest: "1.2.3.4:443".into(),
            gap_ms: 10,
        };
        let a = chain.to_alert();
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.monitor, "ebpf-chain");
        assert!(a.message.contains("/root/.env"));
        assert!(a.details.unwrap().contains("\"credPath\""));
    }
}
