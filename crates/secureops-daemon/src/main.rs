//! # secureops-daemon - Ring-2 root-of-trust daemon
//!
//! The privileged, out-of-band process (PRODUCT.md A.1/A.3) that survives agent
//! compromise. This binary implements the **Phase-2** slice of the B.4 runtime
//! loop end-to-end:
//!
//! 1. **Kill switch first** - if `<stateDir>/.secureops/killswitch` exists,
//!    refuse to bring anything up and exit (B.4 step 1 / B.9).
//! 2. Open the persisted hash-chain audit log, then open the **AlertBus** and
//!    spawn its consumer (prints + appends alerts).
//! 3. Spawn every [`Monitor`] *by value* into a [`JoinSet`], each holding a
//!    clone of the bus and a [`CancellationToken`]; publish the circuit-breaker
//!    `watch` channel and log on trip (B.4 steps 3–4 / B.9 step 2).
//! 4. Run until SIGINT; `cancel()` fans a clean shutdown to every task (step 5).
//!
//! The **PEPs** (egress proxy + DNS sinkhole, eBPF/LSM, WASM sandbox) and the
//! **PDP** wiring are **Phase 4** - this daemon logs that enforcement is
//! disabled rather than pretending to enforce (PRODUCT.md W0: never over-trust a
//! weaker tier).

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde_json::{json, Value};
use tokio::task::JoinSet;

use secureops_auditlog::{AuditLog, InMemorySigner};
use secureops_bpf::chain::EnforcementMode;
use secureops_monitors::{
    circuit_channel, AlertBus, CancellationToken, CircuitState, CostMonitor, CredentialMonitor,
    MemoryIntegrityMonitor, Monitor, SkillScanner,
};

mod bpf_wire;

/// Resolve the state dir: `OPENCLAW_STATE_DIR` → `~/.openclaw` (same contract as
/// the CLI and the TS tool).
fn resolve_state_dir() -> String {
    if let Ok(dir) = std::env::var("OPENCLAW_STATE_DIR") {
        return dir;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/.openclaw")
}

/// Load `<stateDir>/openclaw.json`, or the default config if absent/invalid.
fn load_config(state_dir: &str) -> secureops_core::OpenClawConfig {
    let content = std::fs::read_to_string(format!("{state_dir}/openclaw.json")).unwrap_or_default();
    secureops_core::OpenClawConfig::from_json_or_default(&content)
}

fn open_audit_log(state_dir: &str) -> Result<Arc<Mutex<AuditLog>>> {
    let secureops_dir = Path::new(state_dir).join(".secureops");
    std::fs::create_dir_all(&secureops_dir)?;
    let path = secureops_dir.join("audit.jsonl");
    let log = AuditLog::open(path, Box::new(InMemorySigner::generate()))?;
    Ok(Arc::new(Mutex::new(log)))
}

/// Bring up the egress proxy (PRODUCT.md B.5) iff the operator enabled the
/// allowlist in `openclaw.json`. Fail-closed: any host not in `egressAllowlist`
/// is denied. No-op (just logs) when the allowlist is disabled or unset.
fn spawn_egress_proxy(tasks: &mut JoinSet<()>, config: &secureops_core::OpenClawConfig) {
    let net = config
        .secureops
        .as_ref()
        .and_then(|s| s.network.as_ref())
        .filter(|n| n.egress_allowlist_enabled == Some(true));
    let Some(net) = net else {
        println!(
            "  egress proxy: off (set secureops.network.egressAllowlistEnabled=true to enforce)"
        );
        return;
    };
    let hosts = net.egress_allowlist.clone().unwrap_or_default();
    let pdp: Arc<dyn secureops_proxy::PolicyDecisionPoint> =
        Arc::new(secureops_proxy::AllowlistPdp::new(hosts.clone()));
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8889));
    println!(
        "  egress proxy: ON at {addr} (set agent HTTPS_PROXY) - {} allowlisted host(s), fail-closed",
        hosts.len()
    );
    tasks.spawn(async move {
        let proxy = secureops_proxy::EgressProxy::new();
        if let Err(e) = proxy.start(addr, pdp).await {
            eprintln!("[egress] proxy stopped: {e}");
        }
    });
}

fn append_audit(audit: &Arc<Mutex<AuditLog>>, payload: Value) {
    let Ok(mut log) = audit.lock() else {
        eprintln!("[audit] failed to acquire audit-log lock");
        return;
    };
    if let Err(e) = log.append(payload, secureops_core::now_iso()) {
        eprintln!("[audit] append failed: {e}");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let state_dir = resolve_state_dir();

    println!("SecureOps daemon - Ring-2 root of trust (PRODUCT.md A.1)");
    println!("  state dir: {state_dir}");

    let audit = open_audit_log(&state_dir)?;
    append_audit(
        &audit,
        json!({
            "event": "daemon_start",
            "stateDir": state_dir,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    );

    // Step 1 - kill switch first (B.4 step 1 / B.9).
    if secureops_fs::killswitch::is_kill_switch_active(&state_dir).await {
        append_audit(
            &audit,
            json!({
                "event": "killswitch_active",
                "action": "daemon_refused_start",
            }),
        );
        println!(
            "  kill switch ACTIVE - refusing to bring up monitors/enforcement.\n  \
             Run `secureops kill --deactivate` to resume."
        );
        return Ok(());
    }

    // Step 2 - AlertBus + consumer. Alerts print to stdout and append to the
    // persisted hash-chain audit log. Production keychain/TPM signing remains a
    // follow-up; the current signer is process-local.
    let bus = AlertBus::new();
    let mut rx = bus.subscribe();
    let audit_for_alerts = audit.clone();
    let consumer = tokio::spawn(async move {
        while let Ok(a) = rx.recv().await {
            let severity = format!("{:?}", a.severity);
            let monitor = a.monitor.clone();
            let message = a.message.clone();
            append_audit(
                &audit_for_alerts,
                json!({
                    "event": "monitor_alert",
                    "timestamp": a.timestamp,
                    "severity": severity,
                    "monitor": monitor,
                    "message": message,
                    "details": a.details,
                }),
            );
            let details = a.details.map(|d| format!(" - {d}")).unwrap_or_default();
            println!(
                "[{:?}] {} :: {}{}",
                a.severity, a.monitor, a.message, details
            );
        }
    });

    // IOC database: empty for now (Phase 3 loads the signed feed). Dangerous-
    // pattern skill detection still works; typosquat/hash need a populated db.
    let ioc = Arc::new(secureops_intel::empty_database());

    let (circuit_tx, mut circuit_rx) = circuit_channel();
    // The kernel-PEP chain agent also trips the breaker on an exfil-chain match,
    // so it needs its own sender clone (the original is moved into CostMonitor).
    let circuit_tx_bpf = circuit_tx.clone();
    let (cancel_src, cancel) = CancellationToken::new();

    // Steps 3–4 - spawn monitors by value into the JoinSet.
    let monitors: Vec<Box<dyn Monitor>> = vec![
        Box::new(CostMonitor::new(circuit_tx).with_state_dir(state_dir.clone())),
        Box::new(CredentialMonitor::new().with_state_dir(state_dir.clone())),
        Box::new(MemoryIntegrityMonitor::new().with_state_dir(state_dir.clone())),
        Box::new(SkillScanner::new(ioc).with_state_dir(state_dir.clone())),
    ];
    let mut tasks: JoinSet<()> = JoinSet::new();
    for m in monitors {
        let bus = bus.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move { m.run(bus, cancel).await });
    }

    // Circuit-breaker watch: log on trip (Phase 4 PEPs will hard-refuse here).
    let audit_for_circuit = audit.clone();
    tasks.spawn(async move {
        while circuit_rx.changed().await.is_ok() {
            if *circuit_rx.borrow() == CircuitState::Tripped {
                append_audit(
                    &audit_for_circuit,
                    json!({
                        "event": "circuit_tripped",
                        "action": "new_agent_sessions_refused",
                    }),
                );
                eprintln!(
                    "[circuit] TRIPPED - new agent sessions would be refused (PRODUCT.md B.9 step 2)"
                );
            }
        }
    });

    // PEP: egress proxy (PRODUCT.md B.5, the P0 enforcement lever). Brought up
    // only when the operator enables the egress allowlist - fail-closed.
    let config = load_config(&state_dir);
    spawn_egress_proxy(&mut tasks, &config);

    // PEP: kernel exfil-chain correlator (PRODUCT.md B.6). Enforce mode (inline
    // LSM-BPF deny) is opt-in via SECUREOPS_BPF_ENFORCE=1 and only real on
    // Linux+ebpf; elsewhere it escalates and the egress proxy enforces.
    let bpf_mode = if std::env::var("SECUREOPS_BPF_ENFORCE").as_deref() == Ok("1") {
        EnforcementMode::Enforce
    } else {
        EnforcementMode::Observe
    };
    bpf_wire::spawn(
        &mut tasks,
        bus.clone(),
        circuit_tx_bpf,
        cancel.clone(),
        bpf_mode,
    );

    println!(
        "  {} tasks running. WASM-sandbox PEP DISABLED - Phase 4.",
        tasks.len()
    );
    println!("  Ctrl-C to stop.");

    // Step 5 - run until SIGINT or SIGTERM, then fan a clean shutdown.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;

    println!("\nshutdown signal - cancelling monitors...");
    cancel_src.cancel();
    while tasks.join_next().await.is_some() {}
    consumer.abort();
    println!("daemon stopped.");
    Ok(())
}
