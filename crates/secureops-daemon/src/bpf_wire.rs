//! Wires the kernel-PEP **chain correlator** ([`secureops_bpf::chain`]) into the
//! daemon runtime loop (PRODUCT.md B.6 step 4).
//!
//! A platform event source produces [`SyscallEvent`]s; [`run_chain_agent`]
//! drains them through a [`ChainCorrelator`] and, on a matched [`ExfilChain`],
//! publishes a `Critical` alert on the [`AlertBus`] and trips the circuit
//! breaker. Under [`EnforcementMode::Enforce`] on Linux+LSM-BPF the `connect` is
//! additionally denied in-kernel; on observe-only builds the egress proxy PEP
//! remains the enforcing layer (honest disclosure - never over-trust a weaker
//! tier, PRODUCT.md W0).
//!
//! ## Event source by build
//!
//! | build | source |
//! |---|---|
//! | Linux + `ebpf` feature | aya CO-RE hooks attached via [`secureops_bpf::load`]; the ring-buffer → correlator pump requires the built `secureops-ebpf` programs |
//! | `mock` feature (any OS) | [`secureops_bpf::mock::spawn_demo`] injects a synthetic chain |
//! | otherwise | no source - the correlator idles; the egress proxy PEP enforces |

use secureops_bpf::chain::{ChainAction, ChainCorrelator, EnforcementMode};
use secureops_bpf::SyscallEvent;
use secureops_monitors::{AlertBus, CancellationToken, CircuitState};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

/// Capacity of the kernel→userspace event channel (mirrors the alert bus).
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Drain a [`SyscallEvent`] stream through the correlator until the source
/// closes or cancellation fires. On every matched [`ExfilChain`]: publish a
/// `Critical` alert and trip the circuit breaker; log whether the connect was
/// (or would be) denied in-kernel per `mode`.
pub async fn run_chain_agent(
    mut events: mpsc::Receiver<SyscallEvent>,
    correlator: ChainCorrelator,
    bus: AlertBus,
    circuit: watch::Sender<CircuitState>,
    mode: EnforcementMode,
    mut cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            maybe = events.recv() => {
                let Some(ev) = maybe else { break }; // source closed
                if let Some(chain) = correlator.observe(&ev) {
                    // Escalate on every match, regardless of mode.
                    let _ = bus.publish(chain.to_alert());
                    let _ = circuit.send(CircuitState::Tripped);
                    match secureops_bpf::chain::decide(mode, &chain) {
                        ChainAction::DenyConnect => eprintln!(
                            "[bpf] exfil chain DENIED in-kernel (LSM-BPF) - pid {} dest {}",
                            chain.pid, chain.dest
                        ),
                        ChainAction::AlertEscalate => eprintln!(
                            "[bpf] exfil chain detected (observe-only) - pid {} dest {} - egress proxy enforces",
                            chain.pid, chain.dest
                        ),
                    }
                }
            }
        }
    }
}

/// Spawn the chain-correlation agent into the daemon `JoinSet`, wiring the event
/// source appropriate for this build. Returns immediately; the agent runs until
/// `cancel` fires (or, on a build with no event source, until it drains the
/// closed channel).
pub fn spawn(
    tasks: &mut JoinSet<()>,
    bus: AlertBus,
    circuit: watch::Sender<CircuitState>,
    cancel: CancellationToken,
    mode: EnforcementMode,
) {
    let (tx, rx) = mpsc::channel::<SyscallEvent>(EVENT_CHANNEL_CAPACITY);
    let correlator = ChainCorrelator::with_default_ttl();

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        match secureops_bpf::load() {
            Ok(()) => println!(
                "  kernel PEP: eBPF hooks attached ({mode:?}); ring-buffer→correlator \
                 forwarding requires the built secureops-ebpf programs"
            ),
            Err(e) => eprintln!("  kernel PEP: eBPF load failed: {e}"),
        }
        // No synthetic source on a real kernel build: the ring-buffer pump (part
        // of the secureops-ebpf program build) feeds `tx`. Until then, close it
        // so the agent idles rather than blocking forever.
        drop(tx);
    }

    #[cfg(feature = "mock")]
    {
        println!(
            "  kernel PEP: mock event source active ({mode:?}) - injecting a demo exfil chain"
        );
        secureops_bpf::mock::spawn_demo(tx);
    }

    #[cfg(not(any(all(target_os = "linux", feature = "ebpf"), feature = "mock")))]
    {
        println!(
            "  kernel PEP: unavailable on this build - chain correlator idle (egress proxy enforces)"
        );
        drop(tx); // no source: agent drains the closed channel and exits
    }

    tasks.spawn(run_chain_agent(rx, correlator, bus, circuit, mode, cancel));
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureops_bpf::SyscallKind;
    use secureops_monitors::{circuit_channel, Severity};
    use std::time::Duration;

    #[tokio::test]
    async fn mock_chain_fires_critical_alert_and_trips_circuit() {
        let bus = AlertBus::new();
        let mut alerts = bus.subscribe();
        let (circuit_tx, circuit_rx) = circuit_channel();
        let (ev_tx, ev_rx) = mpsc::channel(16);
        let (_cancel_src, cancel) = CancellationToken::new();

        let agent = tokio::spawn(run_chain_agent(
            ev_rx,
            ChainCorrelator::with_default_ttl(),
            bus.clone(),
            circuit_tx,
            EnforcementMode::Observe,
            cancel,
        ));

        ev_tx
            .send(SyscallEvent::new(
                7,
                "agent",
                SyscallKind::Openat,
                "/app/.env",
            ))
            .await
            .unwrap();
        ev_tx
            .send(SyscallEvent::new(
                7,
                "agent",
                SyscallKind::Connect,
                "1.2.3.4:443",
            ))
            .await
            .unwrap();
        drop(ev_tx); // close source → agent drains then returns

        let alert = tokio::time::timeout(Duration::from_secs(1), alerts.recv())
            .await
            .expect("alert delivered within 1s")
            .expect("alert received");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.monitor, "ebpf-chain");

        agent.await.unwrap();
        assert_eq!(*circuit_rx.borrow(), CircuitState::Tripped);
    }

    #[tokio::test]
    async fn non_credential_traffic_does_not_alert_or_trip() {
        let bus = AlertBus::new();
        let mut alerts = bus.subscribe();
        let (circuit_tx, circuit_rx) = circuit_channel();
        let (ev_tx, ev_rx) = mpsc::channel(16);
        let (_cancel_src, cancel) = CancellationToken::new();

        let agent = tokio::spawn(run_chain_agent(
            ev_rx,
            ChainCorrelator::with_default_ttl(),
            bus.clone(),
            circuit_tx,
            EnforcementMode::Observe,
            cancel,
        ));

        ev_tx
            .send(SyscallEvent::new(
                7,
                "agent",
                SyscallKind::Openat,
                "/tmp/readme.txt",
            ))
            .await
            .unwrap();
        ev_tx
            .send(SyscallEvent::new(
                7,
                "agent",
                SyscallKind::Connect,
                "1.2.3.4:443",
            ))
            .await
            .unwrap();
        drop(ev_tx);
        agent.await.unwrap();

        assert!(
            matches!(
                alerts.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "no alert expected for non-credential traffic"
        );
        assert_eq!(*circuit_rx.borrow(), CircuitState::Armed);
    }

    #[tokio::test]
    async fn cancellation_stops_the_agent() {
        let bus = AlertBus::new();
        let (circuit_tx, _circuit_rx) = circuit_channel();
        let (_ev_tx, ev_rx) = mpsc::channel(16);
        let (cancel_src, cancel) = CancellationToken::new();

        let agent = tokio::spawn(run_chain_agent(
            ev_rx,
            ChainCorrelator::with_default_ttl(),
            bus,
            circuit_tx,
            EnforcementMode::Enforce,
            cancel,
        ));
        cancel_src.cancel();
        tokio::time::timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent stops promptly on cancel")
            .unwrap();
    }
}
