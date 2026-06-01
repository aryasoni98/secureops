//! # secureops-daemon — Ring-2 root-of-trust daemon
//!
//! The privileged, out-of-band process (PRODUCT.md A.1/A.3) that survives agent
//! compromise. This binary implements the **Phase-2** slice of the B.4 runtime
//! loop end-to-end:
//!
//! 1. **Kill switch first** — if `<stateDir>/.secureops/killswitch` exists,
//!    refuse to bring anything up and exit (B.4 step 1 / B.9).
//! 2. Open the **AlertBus** and spawn its consumer (print now; SQLite + signed
//!    audit log are Phase-2-finish / Phase-4 TODO).
//! 3. Spawn every [`Monitor`] *by value* into a [`JoinSet`], each holding a
//!    clone of the bus and a [`CancellationToken`]; publish the circuit-breaker
//!    `watch` channel and log on trip (B.4 steps 3–4 / B.9 step 2).
//! 4. Run until SIGINT; `cancel()` fans a clean shutdown to every task (step 5).
//!
//! The **PEPs** (egress proxy + DNS sinkhole, eBPF/LSM, WASM sandbox) and the
//! **PDP** wiring are **Phase 4** — this daemon logs that enforcement is
//! disabled rather than pretending to enforce (PRODUCT.md W0: never over-trust a
//! weaker tier).

#![forbid(unsafe_code)]

use std::sync::Arc;

use anyhow::Result;
use tokio::task::JoinSet;

use secureops_monitors::{
    circuit_channel, AlertBus, CancellationToken, CircuitState, CostMonitor, CredentialMonitor,
    MemoryIntegrityMonitor, Monitor, SkillScanner,
};

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
    match std::fs::read_to_string(format!("{state_dir}/openclaw.json")) {
        Ok(c) => serde_json::from_str(&c).unwrap_or_default(),
        Err(_) => secureops_core::OpenClawConfig::default(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let state_dir = resolve_state_dir();

    println!("SecureOps daemon — Ring-2 root of trust (PRODUCT.md A.1)");
    println!("  state dir: {state_dir}");

    // Step 1 — kill switch first (B.4 step 1 / B.9).
    if secureops_fs::killswitch::is_kill_switch_active(&state_dir).await {
        println!(
            "  kill switch ACTIVE — refusing to bring up monitors/enforcement.\n  \
             Run `secureops kill --deactivate` to resume."
        );
        return Ok(());
    }

    // Step 2 — AlertBus + consumer. SQLite persistence (init_db) + signed audit
    // log are TODO; for now alerts print to stdout.
    let bus = AlertBus::new();
    let mut rx = bus.subscribe();
    let consumer = tokio::spawn(async move {
        while let Ok(a) = rx.recv().await {
            let details = a.details.map(|d| format!(" — {d}")).unwrap_or_default();
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
    let (cancel_src, cancel) = CancellationToken::new();

    // Steps 3–4 — spawn monitors by value into the JoinSet.
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
    tasks.spawn(async move {
        while circuit_rx.changed().await.is_ok() {
            if *circuit_rx.borrow() == CircuitState::Tripped {
                eprintln!(
                    "[circuit] TRIPPED — new agent sessions would be refused (PRODUCT.md B.9 step 2)"
                );
            }
        }
    });

    // PEP: egress proxy (PRODUCT.md B.5, the P0 enforcement lever). Brought up
    // only when the operator enables the egress allowlist — fail-closed.
    let config = load_config(&state_dir);
    let egress = config
        .secureops
        .as_ref()
        .and_then(|s| s.network.as_ref())
        .filter(|n| n.egress_allowlist_enabled == Some(true));
    match egress {
        Some(net) => {
            let hosts = net.egress_allowlist.clone().unwrap_or_default();
            let pdp: std::sync::Arc<dyn secureops_proxy::PolicyDecisionPoint> =
                std::sync::Arc::new(secureops_proxy::AllowlistPdp::new(hosts.clone()));
            let addr: std::net::SocketAddr = "127.0.0.1:8889".parse().unwrap();
            println!(
                "  egress proxy: ON at {addr} (set agent HTTPS_PROXY) — {} allowlisted host(s), fail-closed",
                hosts.len()
            );
            tasks.spawn(async move {
                let proxy = secureops_proxy::EgressProxy::new();
                if let Err(e) = proxy.start(addr, pdp).await {
                    eprintln!("[egress] proxy stopped: {e}");
                }
            });
        }
        None => println!(
            "  egress proxy: off (set secureops.network.egressAllowlistEnabled=true to enforce)"
        ),
    }

    println!(
        "  {} tasks running. eBPF / WASM-sandbox PEPs DISABLED — Phase 4.",
        tasks.len()
    );
    println!("  Ctrl-C to stop.");

    // Step 5 — run until SIGINT or SIGTERM, then fan a clean shutdown.
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

    println!("\nshutdown signal — cancelling monitors...");
    cancel_src.cancel();
    while tasks.join_next().await.is_some() {}
    consumer.abort();
    println!("daemon stopped.");
    Ok(())
}
