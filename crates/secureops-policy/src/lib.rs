//! # secureops-policy — the Policy Decision Point (PDP)
//!
//! The PDP is **the single authoritative place** that answers the question
//! *"is this allowed?"*. It evaluates structured policy (Rego/Cedar) against a
//! [`DecisionRequest`] — a request plus accumulated per-process context — and
//! returns [`Decision::Allow`], [`Decision::Deny`], or [`Decision::Escalate`]
//! in microseconds. (PRODUCT.md A.2 — *PDP/PEP split, the enforcement spine*.)
//!
//! ## Why a single authority
//! Ring 2 is a classic **Policy Decision Point / Policy Enforcement Point**
//! architecture: one PDP and many dumb, fast PEPs that ask it
//! ([`secureops-proxy`] egress, [`secureops-bpf`] kernel,
//! [`secureops-sandbox`] execution, the gateway hook). A new enforcer is
//! added without touching policy, and policy is authored/versioned/tested
//! without touching enforcers — and the *same* decision is logged once,
//! centrally, to the signed audit log. (PRODUCT.md A.2.)
//!
//! ## The headline path (egress decision — PRODUCT.md B.5)
//! 1. The agent attempts an outbound connection; the proxy reads the SNI /
//!    requested host and asks the PDP *is this destination allowed for this
//!    process?*
//! 2. The PDP evaluates policy + accumulated process context
//!    (e.g. *"this PID `openat`'d a credential file 200ms ago"* — the
//!    read-a-secret → connect-to-unknown-host exfil chain of B.6).
//! 3. **Deny → hard RST** (bytes never leave the box); **Allow →** proceeds;
//!    **Escalate →** alert + trip the circuit breaker. Either way one entry is
//!    written to the signed audit log.
//!
//! ## Implementation status (Phase 4 LIVE)
//! - **Rego eval**: `RegoPdp` backed by `regorus` — hot-reload, decision cache, default policy.
//! - **AllowlistEngine**: dependency-free fallback for simple host allowlists.
//! - **Cedar**: future extension (cedar-policy dep, commented).
//!
//! [`secureops-proxy`]: https://github.com/adversa-ai/secureops
//! [`secureops-bpf`]: https://github.com/adversa-ai/secureops
//! [`secureops-sandbox`]: https://github.com/adversa-ai/secureops

#![allow(dead_code, unused_variables)]

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Default Rego policy bundled with SecureOps (PRODUCT.md A.2 / B.5).
///
/// Allows egress connects only to `data.allowedHosts`; escalates on the
/// classic exfil chain (`.env` read → unknown connect within 5 s).
const DEFAULT_REGO_POLICY: &str = r#"
package secureops.policy

default allow = false
default escalate = false

# Allow: outbound connection or DNS resolve to an allowlisted host.
allow {
    input.action == "connect"
    input.destinationHost == data.allowedHosts[_]
}
allow {
    input.action == "resolve"
    input.destinationHost == data.allowedHosts[_]
}
# Allow: non-egress actions (open/exec/capability — governed by other PEPs).
allow {
    input.action != "connect"
    input.action != "resolve"
}

# Escalate: connect to unknown host ≤5 s after opening a secret-looking file.
escalate {
    input.action == "connect"
    not allow
    event := input.recentSyscalls[_]
    event.syscall == "openat"
    contains(lower(event.target), ".env")
    event.ageMs < 5000
}
"#;

// Re-export the frozen core contract so PEP crates can depend on policy alone.
pub use secureops_core::Severity;

/// Errors raised while loading, compiling, or evaluating policy.
///
/// PDP failures are **fail-closed** by convention (PRODUCT.md B.5 step 4): a
/// caller that receives an error should treat the request as denied, never as
/// implicitly allowed.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A policy bundle (Rego/Cedar source or data) failed to load from disk.
    #[error("failed to load policy bundle: {0}")]
    Load(String),

    /// A policy bundle failed to compile / parse.
    #[error("failed to compile policy: {0}")]
    Compile(String),

    /// Evaluation of a [`DecisionRequest`] failed at runtime.
    #[error("policy evaluation failed: {0}")]
    Evaluation(String),

    /// A hot-reload was requested but the new bundle was rejected; the previous
    /// bundle remains active.
    #[error("hot-reload rejected: {0}")]
    Reload(String),
}

/// The single, authoritative verdict the PDP returns for every request.
///
/// PRODUCT.md A.2 / B.5: the PDP "answers allow/deny/escalate in µs".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    /// Permit the operation. Egress: connection proceeds (B.5 step 4).
    Allow,
    /// Refuse the operation. Egress: **hard RST**, bytes never leave the box.
    Deny,
    /// Permit-but-alarm, or hand off to a human/circuit-breaker. Egress: alert
    /// + trip the circuit breaker (B.5 step 3 / B.6 step 3).
    Escalate,
}

impl Decision {
    /// Wire string for the signed audit log / IPC (`"ALLOW"`, `"DENY"`, `"ESCALATE"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
            Decision::Escalate => "ESCALATE",
        }
    }

    /// True only for [`Decision::Allow`]. Convenience for fail-closed PEPs.
    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// The kind of operation a PEP is asking the PDP to adjudicate.
///
/// The PDP is the single authority for *all* enforcement points, so the request
/// is tagged with which PEP/operation it came from (PRODUCT.md A.2 table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Outbound network connection (egress PEP — PRODUCT.md B.5).
    Connect,
    /// DNS resolution intercepted by the sinkhole (egress PEP — B.5 step 1).
    Resolve,
    /// File open observed by the kernel PEP (`openat` — PRODUCT.md B.6).
    Open,
    /// Process execution observed by the kernel PEP (`execve` — B.6).
    Exec,
    /// A WASI capability grant requested by the execution PEP (A.2 sandbox row).
    Capability,
}

/// A single observed syscall in a process's recent-history window.
///
/// The PDP keeps a short per-PID state window so it can detect the
/// read-a-secret → connect-to-unknown-host exfil chain (PRODUCT.md B.6 step 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Syscall name as hooked in-kernel, e.g. `"openat"`, `"connect"`, `"execve"`.
    pub syscall: String,
    /// Primary argument (path for `openat`, host/addr for `connect`, …).
    pub target: Option<String>,
    /// Milliseconds before "now" that this event was observed (recency matters:
    /// "`openat`'d a credential file 200ms ago" — B.5 step 3).
    pub age_ms: u64,
}

/// A request for a decision, plus the accumulated process context the PDP needs.
///
/// This is what a PEP hands the PDP (PRODUCT.md A.2: *"policy against a request
/// + accumulated process context"*; B.5 step 2–3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionRequest {
    /// What the PEP is asking about (connect / resolve / open / exec / capability).
    pub action: Action,

    /// Destination host (SNI / requested host for an egress connect — B.5 step 2).
    pub destination_host: Option<String>,

    /// Destination port, when known.
    pub destination_port: Option<u16>,

    /// The OS process id of the requesting agent process (B.6 attaches PID/comm).
    pub pid: u32,

    /// The process `comm` / executable name, when known.
    pub comm: Option<String>,

    /// Recent syscalls for this PID, newest first — the per-PID state window the
    /// PDP correlates to catch the exfil chain (PRODUCT.md B.6).
    pub recent_syscalls: Vec<SyscallEvent>,

    /// Free-form, policy-readable attributes (tenant id, agent id, session id,
    /// risk profile, …). Multi-tenant deployments scope policy via these
    /// (PRODUCT.md: per-tenant PDP isolation).
    pub attributes: HashMap<String, String>,
}

impl DecisionRequest {
    /// Minimal constructor for an egress connect request (the B.5 headline path).
    pub fn connect(pid: u32, host: impl Into<String>, port: u16) -> Self {
        Self {
            action: Action::Connect,
            destination_host: Some(host.into()),
            destination_port: Some(port),
            pid,
            comm: None,
            recent_syscalls: Vec::new(),
            attributes: HashMap::new(),
        }
    }
}

/// A fully-formed verdict with the metadata the audit log and PEPs need.
///
/// PRODUCT.md A.2 / B.5 step 4: "the *same* decision is logged once, centrally,
/// to the signed audit log."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionResponse {
    /// The verdict.
    pub decision: Decision,
    /// Human/audit-readable reason, e.g. the policy rule id that matched.
    pub reason: String,
    /// Severity to attach to an alert when the decision is [`Decision::Escalate`].
    pub severity: Option<Severity>,
    /// Version of the policy bundle that produced this decision (cache key + audit).
    pub policy_version: Option<String>,
    /// Whether this verdict was served from the decision cache (telemetry only).
    pub cached: bool,
}

impl DecisionResponse {
    /// Construct a verdict carrying just a decision and reason.
    pub fn new(decision: Decision, reason: impl Into<String>) -> Self {
        Self {
            decision,
            reason: reason.into(),
            severity: None,
            policy_version: None,
            cached: false,
        }
    }

    /// The fail-closed default used whenever the PDP cannot reach a verdict
    /// (PRODUCT.md B.5 step 4 — deny rather than implicitly allow).
    pub fn fail_closed(reason: impl Into<String>) -> Self {
        Self::new(Decision::Deny, reason)
    }
}

/// The contract every policy backend implements.
///
/// One PDP, many PEPs (PRODUCT.md A.2). [`evaluate`](PolicyEngine::evaluate) is
/// the µs-latency hot path on the egress decision (B.5); it is intentionally
/// synchronous so an in-kernel/inline caller never has to await.
pub trait PolicyEngine: Send + Sync {
    /// Adjudicate a single request. Must be fail-closed on any internal error.
    fn evaluate(&self, req: &DecisionRequest) -> Decision;

    /// The richer entry point that returns reason/severity/policy-version for the
    /// signed audit log. Defaults to wrapping [`evaluate`](PolicyEngine::evaluate).
    fn evaluate_detailed(&self, req: &DecisionRequest) -> DecisionResponse {
        DecisionResponse::new(self.evaluate(req), "evaluated")
    }

    /// Atomically swap in a new policy bundle without dropping in-flight
    /// evaluations (hot-reload — PRODUCT.md A.2 "hot-reload"). The previous
    /// bundle stays active if the new one is rejected.
    fn reload(&self, bundle: &PolicyBundle) -> Result<(), PolicyError> {
        Err(PolicyError::Reload("hot-reload not implemented".into()))
    }

    /// The version string of the currently active policy bundle.
    fn version(&self) -> Option<String> {
        None
    }
}

/// A loadable unit of policy: Rego/Cedar source plus its companion data.
///
/// Bundles are versioned, signed, and hot-reloadable (PRODUCT.md A.2, and
/// "behavioral rules as structured policy (Rego/Cedar)").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyBundle {
    /// Opaque version identifier (content hash or semver) — the decision-cache key.
    pub version: String,
    /// Which language the `source` is authored in.
    pub language: PolicyLanguage,
    /// The policy source text (Rego module or Cedar policy set).
    pub source: String,
    /// JSON data document the policy evaluates against (allowlists, IOC feeds, …).
    pub data: serde_json::Value,
}

/// The structured-policy languages the PDP can evaluate (PRODUCT.md A.2 / B.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyLanguage {
    /// Open Policy Agent's Rego (evaluated via the commented `regorus` dep).
    Rego,
    /// AWS Cedar (evaluated via the commented `cedar-policy` dep).
    Cedar,
}

struct CacheEntry {
    resp: DecisionResponse,
    inserted: Instant,
}

fn hash_request(req: &DecisionRequest, policy_version: &str) -> u64 {
    let mut h = DefaultHasher::new();
    format!("{:?}", req.action).hash(&mut h);
    req.destination_host.as_deref().unwrap_or("").hash(&mut h);
    req.destination_port.hash(&mut h);
    req.pid.hash(&mut h);
    policy_version.hash(&mut h);
    h.finish()
}

/// A bounded, time-aware LRU cache of decisions (PRODUCT.md A.2 "decision cache").
pub struct DecisionCache {
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<u64, CacheEntry>>,
}

impl DecisionCache {
    /// Create a cache holding up to `capacity` entries, each valid for `ttl`.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Return a cached verdict if present and not expired, marking `cached = true`.
    pub fn get(&self, req: &DecisionRequest, policy_version: &str) -> Option<DecisionResponse> {
        let key = hash_request(req, policy_version);
        let mut guard = self.entries.lock().ok()?;
        if let Some(entry) = guard.get(&key) {
            if entry.inserted.elapsed() < self.ttl {
                return Some(DecisionResponse {
                    cached: true,
                    ..entry.resp.clone()
                });
            }
            guard.remove(&key);
        }
        None
    }

    /// Insert a verdict, evicting the oldest entry when at capacity.
    pub fn put(&self, req: &DecisionRequest, policy_version: &str, resp: DecisionResponse) {
        let key = hash_request(req, policy_version);
        let Ok(mut guard) = self.entries.lock() else {
            return;
        };
        if guard.len() >= self.capacity {
            if let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, e)| e.inserted)
                .map(|(k, _)| *k)
            {
                guard.remove(&oldest_key);
            }
        }
        guard.insert(
            key,
            CacheEntry {
                resp,
                inserted: Instant::now(),
            },
        );
    }

    /// Drop all cached entries after a hot-reload changes the active policy version.
    pub fn clear(&self) {
        if let Ok(mut g) = self.entries.lock() {
            g.clear();
        }
    }
}

/// Production PDP: regorus Rego evaluator + decision cache (PRODUCT.md A.2).
pub struct RegoPdp {
    cache: DecisionCache,
    engine: Mutex<regorus::Engine>,
    bundle_version: String,
}

impl RegoPdp {
    /// Build a PDP from a [`PolicyBundle`] (Rego source + JSON data).
    pub fn new(bundle: PolicyBundle) -> Result<Self, PolicyError> {
        if bundle.language != PolicyLanguage::Rego {
            return Err(PolicyError::Compile(format!(
                "only Rego supported, got {:?}",
                bundle.language
            )));
        }
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("secureops.rego".to_string(), bundle.source.clone())
            .map_err(|e| PolicyError::Compile(e.to_string()))?;
        if !bundle.data.is_null() {
            let data_json = serde_json::to_string(&bundle.data)
                .map_err(|e| PolicyError::Compile(e.to_string()))?;
            let data = regorus::Value::from_json_str(&data_json)
                .map_err(|e| PolicyError::Compile(e.to_string()))?;
            engine
                .add_data(data)
                .map_err(|e| PolicyError::Compile(e.to_string()))?;
        }
        Ok(Self {
            cache: DecisionCache::new(1000, Duration::from_secs(60)),
            engine: Mutex::new(engine),
            bundle_version: bundle.version,
        })
    }

    /// Build a PDP using the bundled default Rego policy with an explicit allowlist.
    pub fn with_default_policy(allowed_hosts: Vec<String>) -> Result<Self, PolicyError> {
        let bundle = PolicyBundle {
            version: "default-v1".to_string(),
            language: PolicyLanguage::Rego,
            source: DEFAULT_REGO_POLICY.to_string(),
            data: serde_json::json!({ "allowedHosts": allowed_hosts }),
        };
        Self::new(bundle)
    }

    /// Load policy from `dir/policy.rego` + optional `dir/data.json`.
    pub fn from_dir(dir: &str) -> Result<Self, PolicyError> {
        use std::path::Path;
        let src = std::fs::read_to_string(Path::new(dir).join("policy.rego"))
            .map_err(|e| PolicyError::Load(format!("policy.rego: {e}")))?;
        let data = {
            let p = Path::new(dir).join("data.json");
            if p.exists() {
                let text = std::fs::read_to_string(&p)
                    .map_err(|e| PolicyError::Load(format!("data.json: {e}")))?;
                serde_json::from_str(&text)
                    .map_err(|e| PolicyError::Load(format!("data.json parse: {e}")))?
            } else {
                serde_json::Value::Null
            }
        };
        Self::new(PolicyBundle {
            version: format!("file://{dir}"),
            language: PolicyLanguage::Rego,
            source: src,
            data,
        })
    }

    fn eval_decision(&self, req: &DecisionRequest) -> Decision {
        let input_json = match serde_json::to_string(req) {
            Ok(j) => j,
            Err(_) => return Decision::Deny,
        };
        let input = match regorus::Value::from_json_str(&input_json) {
            Ok(v) => v,
            Err(_) => return Decision::Deny,
        };
        let mut guard = match self.engine.lock() {
            Ok(g) => g,
            Err(_) => return Decision::Deny,
        };
        guard.set_input(input);
        let allow = guard
            .eval_bool_query("data.secureops.policy.allow".to_string(), false)
            .unwrap_or(false);
        if allow {
            return Decision::Allow;
        }
        let escalate = guard
            .eval_bool_query("data.secureops.policy.escalate".to_string(), false)
            .unwrap_or(false);
        if escalate {
            Decision::Escalate
        } else {
            Decision::Deny
        }
    }
}

impl PolicyEngine for RegoPdp {
    fn evaluate(&self, req: &DecisionRequest) -> Decision {
        if let Some(cached) = self.cache.get(req, &self.bundle_version) {
            return cached.decision;
        }
        let decision = self.eval_decision(req);
        self.cache.put(
            req,
            &self.bundle_version,
            DecisionResponse::new(decision, "rego"),
        );
        decision
    }

    fn evaluate_detailed(&self, req: &DecisionRequest) -> DecisionResponse {
        if let Some(cached) = self.cache.get(req, &self.bundle_version) {
            return cached;
        }
        let decision = self.eval_decision(req);
        let resp = DecisionResponse {
            decision,
            reason: "evaluated by Rego (secureops.policy)".into(),
            severity: if decision == Decision::Escalate {
                Some(Severity::High)
            } else {
                None
            },
            policy_version: Some(self.bundle_version.clone()),
            cached: false,
        };
        self.cache.put(req, &self.bundle_version, resp.clone());
        resp
    }

    fn reload(&self, bundle: &PolicyBundle) -> Result<(), PolicyError> {
        if bundle.language != PolicyLanguage::Rego {
            return Err(PolicyError::Reload("only Rego supported".into()));
        }
        let mut new_engine = regorus::Engine::new();
        new_engine
            .add_policy("secureops.rego".to_string(), bundle.source.clone())
            .map_err(|e| PolicyError::Compile(e.to_string()))?;
        if !bundle.data.is_null() {
            let data_json = serde_json::to_string(&bundle.data)
                .map_err(|e| PolicyError::Compile(e.to_string()))?;
            let data = regorus::Value::from_json_str(&data_json)
                .map_err(|e| PolicyError::Compile(e.to_string()))?;
            new_engine
                .add_data(data)
                .map_err(|e| PolicyError::Compile(e.to_string()))?;
        }
        let mut guard = self
            .engine
            .lock()
            .map_err(|_| PolicyError::Reload("engine lock poisoned".into()))?;
        *guard = new_engine;
        self.cache.clear();
        Ok(())
    }

    fn version(&self) -> Option<String> {
        Some(self.bundle_version.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_wire_strings() {
        assert_eq!(Decision::Allow.as_str(), "ALLOW");
        assert_eq!(Decision::Deny.as_str(), "DENY");
        assert_eq!(Decision::Escalate.as_str(), "ESCALATE");
        assert!(Decision::Allow.is_allowed());
        assert!(!Decision::Deny.is_allowed());
    }

    #[test]
    fn fail_closed_is_deny() {
        let r = DecisionResponse::fail_closed("pdp unreachable");
        assert_eq!(r.decision, Decision::Deny);
    }

    #[test]
    fn connect_request_builder() {
        let req = DecisionRequest::connect(4242, "evil.example", 443);
        assert_eq!(req.action, Action::Connect);
        assert_eq!(req.destination_host.as_deref(), Some("evil.example"));
        assert_eq!(req.destination_port, Some(443));
        assert_eq!(req.pid, 4242);
    }

    #[test]
    fn decision_round_trips_as_json() {
        let json = serde_json::to_string(&Decision::Escalate).unwrap();
        assert_eq!(json, "\"ESCALATE\"");
        let back: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Decision::Escalate);
    }
}

// =============================================================================
// AllowlistEngine — a concrete, dependency-free PolicyEngine (egress allowlist)
// =============================================================================

/// A minimal [`PolicyEngine`]: permits `connect`/`resolve` only to hosts on an
/// egress allowlist (everything else denied — fail-closed); non-egress actions
/// are out of its scope and pass through as [`Decision::Allow`].
///
/// This is the dependency-free engine the daemon can use today; [`RegoPdp`] is
/// the richer Rego/Cedar engine reserved for the full Phase-4 policy language.
pub struct AllowlistEngine {
    allow_hosts: std::collections::HashSet<String>,
    version: String,
}

impl AllowlistEngine {
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow_hosts: hosts.into_iter().map(Into::into).collect(),
            version: "allowlist-v1".to_string(),
        }
    }
}

impl PolicyEngine for AllowlistEngine {
    fn evaluate(&self, req: &DecisionRequest) -> Decision {
        match req.action {
            Action::Connect | Action::Resolve => {
                let host = req.destination_host.as_deref().unwrap_or("");
                if self.allow_hosts.contains(host) {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
            // This engine only governs egress; other PEPs use their own policy.
            _ => Decision::Allow,
        }
    }
}

#[cfg(test)]
mod allowlist_tests {
    use super::*;

    #[test]
    fn allows_listed_denies_others() {
        let e = AllowlistEngine::new(["api.anthropic.com"]);
        assert_eq!(
            e.evaluate(&DecisionRequest::connect(1, "api.anthropic.com", 443)),
            Decision::Allow
        );
        assert_eq!(
            e.evaluate(&DecisionRequest::connect(1, "evil.com", 443)),
            Decision::Deny
        );
    }

    #[test]
    fn non_egress_actions_pass_through() {
        let e = AllowlistEngine::new(Vec::<String>::new());
        let mut req = DecisionRequest::connect(1, "x", 1);
        req.action = Action::Exec;
        assert_eq!(e.evaluate(&req), Decision::Allow);
    }
}

#[cfg(test)]
mod rego_pdp_tests {
    use super::*;

    fn pdp(allowed: &[&str]) -> RegoPdp {
        RegoPdp::with_default_policy(allowed.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    #[test]
    fn allow_listed_host_connect() {
        let p = pdp(&["api.anthropic.com"]);
        assert_eq!(
            p.evaluate(&DecisionRequest::connect(1, "api.anthropic.com", 443)),
            Decision::Allow
        );
    }

    #[test]
    fn deny_unlisted_host_connect() {
        let p = pdp(&["api.anthropic.com"]);
        assert_eq!(
            p.evaluate(&DecisionRequest::connect(1, "evil.com", 443)),
            Decision::Deny
        );
    }

    #[test]
    fn non_egress_actions_allowed() {
        let p = pdp(&[]);
        let mut req = DecisionRequest::connect(1, "x", 1);
        req.action = Action::Exec;
        assert_eq!(p.evaluate(&req), Decision::Allow);
    }

    #[test]
    fn decision_is_cached_on_second_call() {
        let p = pdp(&["safe.example"]);
        let req = DecisionRequest::connect(1, "safe.example", 443);
        let r1 = p.evaluate_detailed(&req);
        let r2 = p.evaluate_detailed(&req);
        assert!(!r1.cached); // first call: real eval
        assert!(r2.cached); // second call: from cache
        assert_eq!(r1.decision, r2.decision);
    }

    #[test]
    fn reload_swaps_policy_and_clears_cache() {
        let p = pdp(&["old.example"]);
        // Warm cache
        let req = DecisionRequest::connect(1, "old.example", 443);
        assert_eq!(p.evaluate(&req), Decision::Allow);

        // Reload with empty allowlist
        let new_bundle = PolicyBundle {
            version: "v2".to_string(),
            language: PolicyLanguage::Rego,
            source: DEFAULT_REGO_POLICY.to_string(),
            data: serde_json::json!({ "allowedHosts": [] }),
        };
        p.reload(&new_bundle).unwrap();
        assert_eq!(p.evaluate(&req), Decision::Deny);
    }
}

// =============================================================================
// CedarPdp — AWS Cedar policy engine (PRODUCT.md A.2 / B.5)
// =============================================================================

/// Default Cedar policy — mirrors the Rego default policy semantics.
///
/// Allows egress to allowlisted hosts; permits non-egress actions; forbids all
/// other outbound connections. Cedar's `forbid` is evaluated after all `permit`
/// rules, so non-matching connects get the implicit deny.
const DEFAULT_CEDAR_POLICY: &str = r#"
// Allow: outbound connect/resolve to an allowlisted host.
permit(
    principal,
    action in [Action::"connect", Action::"resolve"],
    resource
)
when {
    context has allowedByPolicy && context.allowedByPolicy
};

// Allow: non-egress actions (file open, exec, capability) — governed elsewhere.
permit(
    principal,
    action in [Action::"exec", Action::"open", Action::"capability"],
    resource
);
"#;

/// AWS Cedar PDP (PRODUCT.md A.2 — alternative to Rego).
///
/// Uses the `cedar-policy` crate's pure-Rust Cedar authorizer. Passes the
/// allow-decision pre-computed in context so the Cedar policy stays simple
/// while the full DAL (attributes, recent syscalls) can drive complex rules.
pub struct CedarPdp {
    cache: DecisionCache,
    policies: cedar_policy::PolicySet,
    entities: cedar_policy::Entities,
    allow_hosts: std::collections::HashSet<String>,
    bundle_version: String,
}

impl CedarPdp {
    /// Build a Cedar PDP from a Cedar policy source + an egress allowlist.
    pub fn new(
        cedar_src: &str,
        allowed_hosts: Vec<String>,
        version: impl Into<String>,
    ) -> Result<Self, PolicyError> {
        use std::str::FromStr;
        let policies = cedar_policy::PolicySet::from_str(cedar_src)
            .map_err(|e| PolicyError::Compile(e.to_string()))?;
        Ok(Self {
            cache: DecisionCache::new(1000, Duration::from_secs(60)),
            policies,
            entities: cedar_policy::Entities::empty(),
            allow_hosts: allowed_hosts.into_iter().collect(),
            bundle_version: version.into(),
        })
    }

    /// Build with the default Cedar policy and an egress allowlist.
    pub fn with_default_policy(allowed_hosts: Vec<String>) -> Result<Self, PolicyError> {
        Self::new(DEFAULT_CEDAR_POLICY, allowed_hosts, "default-cedar-v1")
    }

    fn eval_cedar(&self, req: &DecisionRequest) -> Decision {
        use cedar_policy::{Authorizer, Context, EntityUid, Request};
        use std::str::FromStr;

        let host = req.destination_host.as_deref().unwrap_or("");
        let allowed_by_policy = match req.action {
            Action::Connect | Action::Resolve => self.allow_hosts.contains(host),
            _ => true,
        };

        let action_str = match req.action {
            Action::Connect => r#"Action::"connect""#,
            Action::Resolve => r#"Action::"resolve""#,
            Action::Exec => r#"Action::"exec""#,
            Action::Open => r#"Action::"open""#,
            Action::Capability => r#"Action::"capability""#,
        };

        let principal = match EntityUid::from_str(&format!(r#"Agent::"pid-{}""#, req.pid)) {
            Ok(p) => p,
            Err(_) => return Decision::Deny,
        };
        let action = match EntityUid::from_str(action_str) {
            Ok(a) => a,
            Err(_) => return Decision::Deny,
        };
        let resource_name = format!(r#"Resource::"{}""#, host.replace('"', "'"));
        let resource = match EntityUid::from_str(&resource_name) {
            Ok(r) => r,
            Err(_) => return Decision::Deny,
        };

        let ctx_json = serde_json::json!({ "allowedByPolicy": allowed_by_policy });
        let ctx = match Context::from_json_value(ctx_json, None) {
            Ok(c) => c,
            Err(_) => return Decision::Deny,
        };

        let cedar_req = match Request::new(principal, action, resource, ctx, None) {
            Ok(r) => r,
            Err(_) => return Decision::Deny,
        };

        let auth = Authorizer::new();
        let response = auth.is_authorized(&cedar_req, &self.policies, &self.entities);
        match response.decision() {
            cedar_policy::Decision::Allow => Decision::Allow,
            cedar_policy::Decision::Deny => Decision::Deny,
        }
    }
}

impl PolicyEngine for CedarPdp {
    fn evaluate(&self, req: &DecisionRequest) -> Decision {
        if let Some(cached) = self.cache.get(req, &self.bundle_version) {
            return cached.decision;
        }
        let decision = self.eval_cedar(req);
        self.cache.put(
            req,
            &self.bundle_version,
            DecisionResponse::new(decision, "cedar"),
        );
        decision
    }

    fn evaluate_detailed(&self, req: &DecisionRequest) -> DecisionResponse {
        if let Some(cached) = self.cache.get(req, &self.bundle_version) {
            return cached;
        }
        let decision = self.eval_cedar(req);
        let resp = DecisionResponse {
            decision,
            reason: "evaluated by Cedar (secureops default policy)".into(),
            severity: if decision == Decision::Escalate {
                Some(Severity::High)
            } else {
                None
            },
            policy_version: Some(self.bundle_version.clone()),
            cached: false,
        };
        self.cache.put(req, &self.bundle_version, resp.clone());
        resp
    }

    fn version(&self) -> Option<String> {
        Some(self.bundle_version.clone())
    }
}

#[cfg(test)]
mod cedar_tests {
    use super::*;

    fn cedar_pdp(allowed: &[&str]) -> CedarPdp {
        CedarPdp::with_default_policy(allowed.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    #[test]
    fn cedar_allows_listed_host() {
        let p = cedar_pdp(&["api.anthropic.com"]);
        assert_eq!(
            p.evaluate(&DecisionRequest::connect(1, "api.anthropic.com", 443)),
            Decision::Allow
        );
    }

    #[test]
    fn cedar_denies_unlisted_host() {
        let p = cedar_pdp(&["api.anthropic.com"]);
        assert_eq!(
            p.evaluate(&DecisionRequest::connect(1, "evil.com", 443)),
            Decision::Deny
        );
    }

    #[test]
    fn cedar_non_egress_allowed() {
        let p = cedar_pdp(&[]);
        let mut req = DecisionRequest::connect(1, "x", 1);
        req.action = Action::Exec;
        assert_eq!(p.evaluate(&req), Decision::Allow);
    }
}
