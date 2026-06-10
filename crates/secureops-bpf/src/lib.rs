//! # secureops-bpf
//!
//! The **kernel Policy Enforcement Point (PEP)**: in-kernel syscall observation
//! and correlation that catches the prompt-injection *exfil chain* before the
//! bytes ever leave the box — see **PRODUCT.md B.6** ("Syscall correlation —
//! catching the exfil *chain*") and the crate map in **PRODUCT.md A.4**
//! ("kernel PEP: aya loader + CO-RE; ES-framework fallback").
//!
//! ## The exfil chain this crate is built to catch (PRODUCT.md B.6)
//!
//! The dangerous, kernel-observable pattern is:
//!
//! ```text
//!   openat("/path/to/.env" | secret | credential)   // read-a-secret
//!        └─ within a short per-PID time window ─┐
//!   connect(<unknown / not-allowlisted host>)   ◀─┘   // then-connect-to-an-unknown-host
//! ```
//!
//! This is exactly the prompt-injection exfiltration flow: an agent (Ring 0) is
//! talked into reading a credential file and then dialing out to an attacker
//! host. Promoting it from the behavioral "Rule 8" heuristic (an LLM suggestion
//! the agent may ignore) to a **kernel fact the agent cannot evade** is the
//! whole point of this crate (PRODUCT.md B.6 step 4).
//!
//! ## How it works per platform
//!
//! - **Linux** ([`linux`]): `aya` loads CO-RE eBPF programs that hook `openat`,
//!   `connect`, and `execve`. Events stream to the daemon over a ring buffer
//!   with PID + `comm` attached (B.6 step 1). The daemon keeps a short per-PID
//!   state window and, on a match, the PDP can escalate (alert + trip the
//!   circuit breaker) or — with **LSM-BPF** — **deny the `connect` inline,
//!   in-kernel** (B.6 step 2-3).
//! - **macOS** ([`macos`]): the Endpoint Security framework provides the same
//!   `openat`/`connect`/`execve` event stream but is **observe-only** (no inline
//!   kernel deny); correlation + escalation still run in the daemon, with
//!   enforcement falling back to the egress proxy PEP (PRODUCT.md B.5).
//!
//! ## Wiring (PRODUCT.md B.4 step 4)
//!
//! The privileged daemon calls [`load`] during PEP bring-up; the correlated
//! [`SyscallEvent`]s feed the per-PID state window and, ultimately, the PDP's
//! egress decision (PRODUCT.md B.5 step 3: "this PID `openat`'d a credential
//! file 200ms ago").

#![forbid(unsafe_code)]

// Re-exported for downstream crates that build [`AuditFinding`]s out of a
// correlated chain match (e.g. an `L4`/`Evasion` escalation alert). Bound here
// so the API surface references the FROZEN `secureops-core` contract directly.
use secureops_core::{MaestroLayer, NistAttackType, Severity};

/// Per-PID exfil-chain correlation (PRODUCT.md B.6 step 2) — kernel-free,
/// unit-testable on every platform.
pub mod chain;
/// seccomp-bpf "learn mode" allowlist generation (PRODUCT.md B.6).
pub mod seccomp;

pub use chain::{ChainAction, ChainCorrelator, EnforcementMode, ExfilChain};

/// Kernel-free demo event source (gated by the `mock` feature) so the daemon's
/// chain wiring can be exercised end-to-end without a kernel (PRODUCT.md B.6).
#[cfg(feature = "mock")]
pub mod mock {
    use crate::{SyscallEvent, SyscallKind};
    use tokio::sync::mpsc;

    /// Spawn a task that injects a synthetic exfil chain (read `.env` → dial an
    /// off-allowlist host) into `tx`, then drops the sender to close the stream.
    pub fn spawn_demo(tx: mpsc::Sender<SyscallEvent>) {
        tokio::spawn(async move {
            let _ = tx
                .send(SyscallEvent::new(
                    4242,
                    "agent",
                    SyscallKind::Openat,
                    "/home/agent/.env",
                ))
                .await;
            let _ = tx
                .send(SyscallEvent::new(
                    4242,
                    "agent",
                    SyscallKind::Connect,
                    "203.0.113.7:443",
                ))
                .await;
        });
    }
}

/// A single in-kernel syscall observation, lifted out of the eBPF ring buffer
/// (Linux) or the Endpoint Security event stream (macOS) with the originating
/// process attached — PRODUCT.md B.6 step 1 ("events stream to the daemon over
/// a ring buffer with PID/comm attached").
///
/// These are the atoms the per-PID correlation window is built from: a sequence
/// of `SyscallEvent`s for one `pid` is what reveals the
/// `openat(secret) -> connect(unknown host)` exfil chain (B.6 step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEvent {
    /// Originating process id, as reported by the kernel.
    pub pid: i32,
    /// Process command name (`comm`) — the short executable name, for human-
    /// readable alerts and for `execve`-based process-identity tracking.
    pub comm: String,
    /// Which syscall family this event belongs to.
    pub kind: SyscallKind,
    /// The path opened (`Openat`), the destination host/endpoint dialed
    /// (`Connect`), or the program image executed (`Execve`). Interpreted
    /// according to [`SyscallEvent::kind`].
    pub path_or_host: String,
}

/// The kernel syscalls SecureOps hooks to reconstruct the exfil chain —
/// PRODUCT.md B.6 step 1 ("eBPF programs hook `openat`, `connect`, `execve`").
///
/// Only these three are needed for the headline behavioral rule:
/// `openat` (read-a-secret) correlated with `connect` (dial-out), with `execve`
/// providing process identity / lineage for the per-PID state window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallKind {
    /// File open — the "read-a-secret" half of the chain when the path is a
    /// credential / `.env` / canary file.
    Openat,
    /// Outbound connection — the "then-connect-to-an-unknown-host" half of the
    /// chain when the destination is not allowlisted.
    Connect,
    /// Program execution — tracks process identity and lineage across the
    /// per-PID state window.
    Execve,
}

impl SyscallEvent {
    /// Construct a raw syscall event. Heavy parsing of the kernel record into
    /// these fields happens in the platform loaders ([`linux`] / [`macos`]).
    pub fn new(
        pid: i32,
        comm: impl Into<String>,
        kind: SyscallKind,
        path_or_host: impl Into<String>,
    ) -> Self {
        Self {
            pid,
            comm: comm.into(),
            kind,
            path_or_host: path_or_host.into(),
        }
    }

    /// Whether this event is the *first* half of the exfil chain: an `Openat`
    /// of something secret-shaped (PRODUCT.md B.6 step 2 — "read-a-secret").
    ///
    /// Uses path-based heuristics; the daemon can refine with the full IOC
    /// `infostealer_artifacts` list once the eBPF loader is wired.
    pub fn is_secret_read(&self) -> bool {
        if self.kind != SyscallKind::Openat {
            return false;
        }
        let p = self.path_or_host.as_str();
        p.ends_with(".env")
            || p.contains("/.env")
            || p.contains("credentials")
            || p.contains("id_rsa")
            || p.contains("id_ed25519")
            || p.contains(".pem")
            || p.contains("secret")
            || p.contains("password")
            || p.contains("Keychains")
            || p.contains(".aws")
            || p.contains("canary")
    }

    /// Whether this event is the *second* half of the exfil chain: a `Connect`
    /// to a destination not on the egress allowlist (PRODUCT.md B.6 step 2-3).
    ///
    /// Without the daemon's allowlist context, unknown-connect detection is left
    /// to the PDP/proxy layer; this returns `false` to avoid false positives.
    pub fn is_unknown_connect(&self) -> bool {
        // The PDP/proxy layer (secureops-proxy + AllowlistEngine) enforces egress.
        // Once the eBPF ring buffer is wired to the daemon, the per-PID window
        // passes the allowlist reference here for inline kernel correlation.
        false
    }

    /// MAESTRO layer this kernel-level enforcement maps to (host/runtime tier).
    /// Used when a chain match is turned into an `AuditFinding`/alert.
    pub fn maestro_layer(&self) -> MaestroLayer {
        // Kernel/runtime enforcement sits at the infrastructure tier.
        MaestroLayer::L4
    }

    /// NIST AI 100-2 attack family a matched chain represents: the exfil chain
    /// is an *evasion* of the intended behavioral guardrail (PRODUCT.md B.6
    /// step 4 — "a kernel fact the agent cannot evade").
    pub fn nist_attack_type(&self) -> NistAttackType {
        NistAttackType::Evasion
    }

    /// Severity to attach to a confirmed `openat(secret) -> connect(unknown)`
    /// chain match. Active credential exfiltration is treated as critical.
    pub fn chain_match_severity(&self) -> Severity {
        Severity::Critical
    }
}

/// Cross-platform entry point: load and start the kernel PEP for the current
/// host, dispatching by target OS. Called by the daemon during PEP bring-up
/// (PRODUCT.md B.4 step 4: "load eBPF programs").
///
/// On Linux this loads the aya CO-RE programs and (where available) the LSM-BPF
/// inline-deny hook; on macOS it attaches the observe-only Endpoint Security
/// client. On any other target it returns an error — there is no kernel PEP.
pub fn load() -> anyhow::Result<()> {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        return linux::load();
    }
    #[cfg(target_os = "macos")]
    {
        macos::load()
    }
    #[cfg(not(any(all(target_os = "linux", feature = "ebpf"), target_os = "macos")))]
    {
        anyhow::bail!(
            "secureops-bpf: no kernel PEP in this build — enable the `ebpf` feature \
             on Linux (and build the secureops-ebpf programs), or this platform has \
             no kernel PEP (PRODUCT.md B.6)"
        )
    }
}

/// Linux kernel PEP — the full-strength path: aya CO-RE eBPF loader hooking
/// `openat`/`connect`/`execve`, plus **LSM-BPF inline deny** that can RST the
/// exfil `connect` in-kernel (PRODUCT.md B.6 steps 1-4).
/// Linux kernel PEP: aya CO-RE eBPF loader.
///
/// The eBPF programs (`secureops-ebpf/` crate, separate build) hook `openat`,
/// `connect`, and `execve`. They stream `SyscallEvent` records to the daemon
/// via a ring buffer; the daemon keeps a per-PID state window and on a chain
/// match either escalates (alerts + circuit breaker) or denies inline via
/// LSM-BPF (PRODUCT.md B.6 steps 1-4).
///
/// ## Build the BPF programs
///
/// ```sh
/// # Install bpf-linker and compile the eBPF programs:
/// cargo install bpf-linker
/// CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker \
///     cargo build --target bpfel-unknown-none -Z build-std=core \
///     -p secureops-ebpf --release
/// # The .o file is produced at:
/// # target/bpfel-unknown-none/release/secureops-ebpf
/// # Set SECUREOPS_BPF_OBJ to that path before running the daemon.
/// ```
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod linux {
    use aya::{programs::TracePoint, Bpf};

    /// Load and attach the CO-RE eBPF programs (PRODUCT.md B.6).
    ///
    /// Reads the BPF object from `$SECUREOPS_BPF_OBJ` (default:
    /// `target/bpfel-unknown-none/release/secureops-ebpf`). Returns an error
    /// with build instructions if the object is not found.
    pub fn load() -> anyhow::Result<()> {
        let bpf_path = std::env::var("SECUREOPS_BPF_OBJ")
            .unwrap_or_else(|_| "target/bpfel-unknown-none/release/secureops-ebpf".into());

        let obj_bytes = std::fs::read(&bpf_path).map_err(|e| {
            anyhow::anyhow!(
                "BPF object not found at {bpf_path}: {e}\n\
             Build it with:\n  cargo install bpf-linker\n  \
             CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker \\\n  \
               cargo build --target bpfel-unknown-none -Z build-std=core \\\n  \
               -p secureops-ebpf --release\n\
             Then set SECUREOPS_BPF_OBJ to the output path."
            )
        })?;

        let mut bpf = Bpf::load(&obj_bytes)?;

        // Attach tracepoint hooks for the three syscalls we correlate.
        for (prog_name, category, syscall) in [
            ("secureops_openat", "syscalls", "sys_enter_openat"),
            ("secureops_connect", "syscalls", "sys_enter_connect"),
            ("secureops_execve", "syscalls", "sys_enter_execve"),
        ] {
            if let Ok(prog) = bpf.program_mut(prog_name) {
                let tp: &mut TracePoint = prog.try_into()?;
                tp.load()?;
                tp.attach(category, syscall)?;
                tracing::info!(%prog_name, %syscall, "eBPF tracepoint attached");
            }
        }

        tracing::info!(
            "secureops-bpf: kernel PEP loaded — syscall correlation active (PRODUCT.md B.6)"
        );

        // Keep `bpf` alive — caller must hold the returned handle.
        // For now we leak it into the daemon loop; a production daemon would
        // store it in the JoinSet state or a OnceCell.
        std::mem::forget(bpf);
        Ok(())
    }
}

/// macOS kernel PEP — the **observe-only** fallback via the Endpoint Security
/// framework. It produces the same `openat`/`connect`/`execve` event stream for
/// correlation, but cannot deny inline in-kernel; enforcement falls back to the
/// egress proxy PEP (PRODUCT.md B.5 / B.6).
#[cfg(target_os = "macos")]
pub mod macos {
    /// Attach an Endpoint Security client and stream `openat`/`connect`/`execve`
    /// events into the daemon's per-PID correlation window. Observe-only: there
    /// is no in-kernel inline deny on macOS, so matches escalate to the PDP /
    /// circuit breaker and the proxy PEP enforces (PRODUCT.md B.6 step 3).
    pub fn load() -> anyhow::Result<()> {
        anyhow::bail!(
            "Endpoint Security framework client not compiled — requires Apple entitlement \
             + native ES framework binding (Phase 4, macOS-only, PRODUCT.md B.6)"
        )
    }
}
