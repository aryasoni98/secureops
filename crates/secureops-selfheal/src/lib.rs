//! # secureops-selfheal
//!
//! YAML-defined **self-healing playbooks** (PRODUCT.md §19 + Phase 7). Each
//! playbook declares a remediation class that fixes the execution path:
//!
//! - **Safe** - `dry_run → execute → audit`.
//! - **Reversible** - `snapshot → execute → health_check`; on failure
//!   `rollback(snapshot) → audit(RolledBack)`.
//! - **Destructive** - requires human approval first; without an `Approved`
//!   decision the cloud is **never touched** (`Aborted`).
//!
//! A per-class **circuit breaker** halts a class once its 5-minute error rate
//! exceeds 20%. Every cloud mutation goes through the [`CloudBackend`] trait, so
//! the whole engine tests against a mock with **zero live cloud calls**. Audit
//! records are emitted to an append-only [`AuditSink`].

#![forbid(unsafe_code)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

/// Remediation risk class (drives the execution path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookClass {
    /// Idempotent, no data loss - apply directly.
    Safe,
    /// Mutating but undoable - snapshot first, roll back on failure.
    Reversible,
    /// Irreversible / high-impact - requires human approval.
    Destructive,
}

/// A remediation playbook (parsed from YAML).
#[derive(Debug, Clone, Deserialize)]
pub struct Playbook {
    pub id: String,
    /// Finding rule ids this playbook remediates.
    #[serde(default)]
    pub matches: Vec<String>,
    pub class: PlaybookClass,
    #[serde(default)]
    pub dry_run: Option<String>,
    #[serde(default)]
    pub snapshot: Option<String>,
    pub execute: String,
    #[serde(default)]
    pub health_check: Option<String>,
    #[serde(default)]
    pub rollback: Option<String>,
    #[serde(default = "default_true")]
    pub audit_required: bool,
}

fn default_true() -> bool {
    true
}

impl Playbook {
    /// Parse a playbook from YAML.
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        Ok(serde_yaml::from_str(yaml)?)
    }
}

/// The cloud mutation surface - implemented for real providers (AWS/GCP/Azure)
/// or a mock. All steps are opaque command strings the backend interprets.
#[async_trait]
pub trait CloudBackend: Send + Sync {
    async fn dry_run(&self, step: &str) -> anyhow::Result<String>;
    /// Capture restore state; returns an opaque snapshot handle.
    async fn snapshot(&self, step: &str) -> anyhow::Result<String>;
    async fn execute(&self, step: &str) -> anyhow::Result<String>;
    /// `true` if the post-execute health check passes.
    async fn health_check(&self, step: &str) -> anyhow::Result<bool>;
    async fn rollback(&self, step: &str, snapshot: &str) -> anyhow::Result<()>;
}

/// A human decision on a destructive playbook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    Approved {
        by: String,
    },
    Denied {
        reason: String,
    },
    /// No decision within the approval window.
    Timeout,
}

/// Terminal state of a playbook run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecState {
    Completed,
    RolledBack,
    Aborted,
    Failed,
}

/// One append-only audit record (mirrors the daemon's signed log).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub playbook_id: String,
    pub action: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub state: ExecState,
    pub actor: Option<String>,
}

/// Append-only audit sink (no update/delete by contract).
pub trait AuditSink: Send + Sync {
    fn record(&self, entry: AuditRecord);
}

/// In-memory append-only collector (tests / single-node).
#[derive(Default)]
pub struct VecAudit {
    entries: Mutex<Vec<AuditRecord>>,
}
impl VecAudit {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn entries(&self) -> Vec<AuditRecord> {
        self.entries.lock().expect("audit lock").clone()
    }
}
impl AuditSink for VecAudit {
    fn record(&self, entry: AuditRecord) {
        self.entries.lock().expect("audit lock").push(entry);
    }
}

/// The outcome of [`PlaybookEngine::run`].
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub state: ExecState,
    /// Whether the backend's `execute` was actually invoked (false for an
    /// aborted destructive run - the key safety guarantee).
    pub executed: bool,
}

/// Per-class sliding-window error-rate breaker (PRODUCT.md §19).
pub struct CircuitBreaker {
    window_ms: u64,
    threshold: f32,
    min_samples: usize,
    base: Instant,
    samples: Mutex<HashMap<PlaybookClass, VecDeque<(bool, u64)>>>,
    halted: Mutex<HashMap<PlaybookClass, bool>>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(300_000, 0.2, 3)
    }
}

impl CircuitBreaker {
    pub fn new(window_ms: u64, threshold: f32, min_samples: usize) -> Self {
        Self {
            window_ms,
            threshold,
            min_samples,
            base: Instant::now(),
            samples: Mutex::new(HashMap::new()),
            halted: Mutex::new(HashMap::new()),
        }
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    /// Record a result for a class at an explicit time (deterministic tests).
    pub fn record_at(&self, class: PlaybookClass, ok: bool, now_ms: u64) {
        let mut s = self.samples.lock().expect("breaker lock");
        let dq = s.entry(class).or_default();
        dq.push_back((ok, now_ms));
        while let Some(&(_, t)) = dq.front() {
            if now_ms.saturating_sub(t) > self.window_ms {
                dq.pop_front();
            } else {
                break;
            }
        }
        let total = dq.len();
        let errors = dq.iter().filter(|(ok, _)| !*ok).count();
        if total >= self.min_samples && (errors as f32 / total as f32) > self.threshold {
            self.halted
                .lock()
                .expect("breaker lock")
                .insert(class, true);
        }
    }

    /// Record a result now.
    pub fn record(&self, class: PlaybookClass, ok: bool) {
        let now = self.now_ms();
        self.record_at(class, ok, now);
    }

    /// Whether a class is currently halted.
    pub fn is_open(&self, class: PlaybookClass) -> bool {
        *self
            .halted
            .lock()
            .expect("breaker lock")
            .get(&class)
            .unwrap_or(&false)
    }

    /// Manually reset a halted class (operator action via the API).
    pub fn reset(&self, class: PlaybookClass) {
        self.halted
            .lock()
            .expect("breaker lock")
            .insert(class, false);
        self.samples.lock().expect("breaker lock").remove(&class);
    }
}

/// Executes playbooks along their class-specific paths.
#[derive(Default)]
pub struct PlaybookEngine {
    pub breaker: CircuitBreaker,
}

impl PlaybookEngine {
    pub fn new() -> Self {
        Self::default()
    }

    fn audit(
        &self,
        sink: &dyn AuditSink,
        pb: &Playbook,
        action: &str,
        after: Option<String>,
        state: ExecState,
        actor: Option<String>,
    ) {
        if pb.audit_required {
            sink.record(AuditRecord {
                playbook_id: pb.id.clone(),
                action: action.into(),
                before: None,
                after,
                state,
                actor,
            });
        }
    }

    /// Common terminal handling for an `execute` call: trip the breaker, emit an
    /// audit record, and return the matching [`ExecOutcome`].
    fn finalize_execute(
        &self,
        pb: &Playbook,
        audit: &dyn AuditSink,
        result: anyhow::Result<String>,
        actor: Option<String>,
    ) -> ExecOutcome {
        let (state, after) = match result {
            Ok(after) => (ExecState::Completed, Some(after)),
            Err(e) => (ExecState::Failed, Some(e.to_string())),
        };
        self.breaker.record(pb.class, state == ExecState::Completed);
        self.audit(audit, pb, "execute", after, state, actor);
        ExecOutcome {
            state,
            executed: true,
        }
    }

    /// Run a playbook. `approval` is consulted only for destructive playbooks.
    pub async fn run(
        &self,
        pb: &Playbook,
        cloud: &dyn CloudBackend,
        approval: Option<Approval>,
        audit: &dyn AuditSink,
    ) -> ExecOutcome {
        if self.breaker.is_open(pb.class) {
            self.audit(audit, pb, "blocked", None, ExecState::Aborted, None);
            return ExecOutcome {
                state: ExecState::Aborted,
                executed: false,
            };
        }

        match pb.class {
            PlaybookClass::Safe => {
                if let Some(dr) = &pb.dry_run {
                    let _ = cloud.dry_run(dr).await;
                }
                self.finalize_execute(pb, audit, cloud.execute(&pb.execute).await, None)
            }

            PlaybookClass::Reversible => {
                let snap = match &pb.snapshot {
                    Some(s) => cloud.snapshot(s).await.ok(),
                    None => None,
                };
                let exec = cloud.execute(&pb.execute).await;
                let healthy = match &exec {
                    Ok(_) => match &pb.health_check {
                        Some(hc) => cloud.health_check(hc).await.unwrap_or(false),
                        None => true,
                    },
                    Err(_) => false,
                };
                if exec.is_ok() && healthy {
                    self.breaker.record(pb.class, true);
                    self.audit(audit, pb, "execute", exec.ok(), ExecState::Completed, None);
                    ExecOutcome {
                        state: ExecState::Completed,
                        executed: true,
                    }
                } else {
                    if let (Some(rb), Some(s)) = (&pb.rollback, &snap) {
                        let _ = cloud.rollback(rb, s).await;
                    }
                    self.breaker.record(pb.class, false);
                    self.audit(audit, pb, "rollback", None, ExecState::RolledBack, None);
                    ExecOutcome {
                        state: ExecState::RolledBack,
                        executed: exec.is_ok(),
                    }
                }
            }

            PlaybookClass::Destructive => match approval {
                Some(Approval::Approved { by }) => {
                    self.finalize_execute(pb, audit, cloud.execute(&pb.execute).await, Some(by))
                }
                _ => {
                    // Denied / Timeout / no decision → never touch the cloud.
                    self.audit(audit, pb, "await_approval", None, ExecState::Aborted, None);
                    ExecOutcome {
                        state: ExecState::Aborted,
                        executed: false,
                    }
                }
            },
        }
    }
}

/// The six sample playbooks shipped with SecureOps (PRODUCT.md §19).
pub fn sample_playbooks() -> Vec<Playbook> {
    [
        S3_PUBLIC_ACL,
        SG_OPEN_SSH_WORLD,
        GCS_PUBLIC_BUCKET,
        K8S_PRIVILEGED_POD,
        ENABLE_CLOUDTRAIL,
        AZURE_NSG_OPEN_RDP,
    ]
    .iter()
    .map(|y| Playbook::from_yaml(y).expect("embedded playbook parses"))
    .collect()
}

/// Load every `*.yaml`/`*.yml` playbook under `dir`. Returns the parsed set
/// alphabetically. Errors are propagated for the first invalid playbook so
/// operators see a clear failure at startup.
pub fn load_dir(dir: impl AsRef<std::path::Path>) -> anyhow::Result<Vec<Playbook>> {
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir.as_ref())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            matches!(
                p.extension().and_then(|s| s.to_str()),
                Some("yaml") | Some("yml")
            )
        })
        .collect();
    entries.sort();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let yaml = std::fs::read_to_string(&path)?;
        let pb = Playbook::from_yaml(&yaml)
            .map_err(|e| anyhow::anyhow!("playbook {} failed to parse: {e}", path.display()))?;
        out.push(pb);
    }
    Ok(out)
}

pub const S3_PUBLIC_ACL: &str = r#"
id: s3-public-acl
matches: [SC-S3-001]
class: reversible
dry_run: "aws s3api get-bucket-acl --bucket {bucket}"
snapshot: "capture current bucket acl"
execute: "s3.put_bucket_acl bucket={bucket} acl=private"
health_check: "aws s3api get-bucket-acl --bucket {bucket} | assert not public"
rollback: "restore bucket acl from snapshot"
audit_required: true
"#;

pub const SG_OPEN_SSH_WORLD: &str = r#"
id: sg-open-ssh-world
matches: [SC-SG-022]
class: reversible
snapshot: "capture security group ingress rules"
execute: "ec2.revoke_ingress sg={sg} cidr=0.0.0.0/0 port=22"
health_check: "assert no 0.0.0.0/0 on port 22"
rollback: "re-add captured ingress rules"
"#;

pub const GCS_PUBLIC_BUCKET: &str = r#"
id: gcs-public-bucket
matches: [SC-GCS-003]
class: reversible
snapshot: "capture iam policy on {bucket}"
execute: "gcs.remove_iam_member bucket={bucket} member=allUsers"
health_check: "assert allUsers not present"
rollback: "restore iam policy from snapshot"
"#;

pub const K8S_PRIVILEGED_POD: &str = r#"
id: k8s-privileged-pod
matches: [SC-K8S-011]
class: destructive
execute: "k8s.delete_pod namespace={namespace} pod={pod}"
audit_required: true
"#;

pub const ENABLE_CLOUDTRAIL: &str = r#"
id: enable-cloudtrail
matches: [SC-AWS-CT-001]
class: safe
dry_run: "aws cloudtrail get-trail-status --name {trail}"
execute: "cloudtrail.start_logging name={trail}"
"#;

pub const AZURE_NSG_OPEN_RDP: &str = r#"
id: azure-nsg-open-rdp
matches: [SC-AZ-NSG-014]
class: reversible
snapshot: "capture nsg inbound rules"
execute: "azure.nsg_revoke_rule nsg={nsg} cidr=0.0.0.0/0 port=3389"
health_check: "assert no 0.0.0.0/0 on port 3389"
rollback: "re-add captured nsg rules"
audit_required: true
"#;

/// A typed cloud remediation action parsed from a playbook step. Lets a real
/// provider backend (e.g. [`aws::AwsCloud`]) execute structured operations
/// instead of interpreting opaque strings. Step format: `service.op k=v k=v`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudAction {
    PutBucketAcl {
        bucket: String,
        acl: String,
    },
    RevokeSecurityGroupIngress {
        sg: String,
        cidr: String,
        port: String,
    },
    StartCloudTrail {
        name: String,
    },
    GcsRemoveIamMember {
        bucket: String,
        member: String,
    },
    DeleteK8sPod {
        namespace: String,
        pod: String,
    },
    AzureNsgRevokeRule {
        nsg: String,
        cidr: String,
        port: String,
    },
    GcpFirewallRevoke {
        firewall: String,
        cidr: String,
    },
    /// Unrecognized op - carries the raw step (a backend may log/skip it).
    Unknown(String),
}

/// Parse a structured playbook step (`"service.op key=value ..."`) into a
/// [`CloudAction`]. Unrecognized ops map to [`CloudAction::Unknown`].
pub fn parse_step(step: &str) -> CloudAction {
    let mut parts = step.split_whitespace();
    let op = parts.next().unwrap_or("");
    let kv: std::collections::HashMap<&str, &str> =
        parts.filter_map(|p| p.split_once('=')).collect();
    let g = |k: &str| kv.get(k).copied().unwrap_or("").to_string();
    match op {
        "s3.put_bucket_acl" => CloudAction::PutBucketAcl {
            bucket: g("bucket"),
            acl: g("acl"),
        },
        "ec2.revoke_ingress" => CloudAction::RevokeSecurityGroupIngress {
            sg: g("sg"),
            cidr: g("cidr"),
            port: g("port"),
        },
        "cloudtrail.start_logging" => CloudAction::StartCloudTrail { name: g("name") },
        "gcs.remove_iam_member" => CloudAction::GcsRemoveIamMember {
            bucket: g("bucket"),
            member: g("member"),
        },
        "k8s.delete_pod" => CloudAction::DeleteK8sPod {
            namespace: g("namespace"),
            pod: g("pod"),
        },
        "azure.nsg_revoke_rule" => CloudAction::AzureNsgRevokeRule {
            nsg: g("nsg"),
            cidr: g("cidr"),
            port: g("port"),
        },
        "gcp.firewall_revoke" => CloudAction::GcpFirewallRevoke {
            firewall: g("firewall"),
            cidr: g("cidr"),
        },
        _ => CloudAction::Unknown(step.to_string()),
    }
}

/// Live AWS backend (gated `aws` feature): executes parsed [`CloudAction`]s via
/// the AWS SDK. Unblocked by the tree-sitter bump (cc≥1.1). Gated so the default
/// build stays light; non-AWS actions (GCP/K8s) return an unsupported error.
#[cfg(feature = "aws")]
pub mod aws;

pub mod azure;
pub mod gcp;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct MockCloud {
        execute_calls: AtomicUsize,
        rollback_calls: AtomicUsize,
        fail_execute: bool,
        health_ok: bool,
    }
    impl MockCloud {
        fn healthy() -> Self {
            Self {
                health_ok: true,
                ..Default::default()
            }
        }
        fn unhealthy() -> Self {
            Self {
                health_ok: false,
                ..Default::default()
            }
        }
        fn failing() -> Self {
            Self {
                fail_execute: true,
                health_ok: true,
                ..Default::default()
            }
        }
    }
    #[async_trait]
    impl CloudBackend for MockCloud {
        async fn dry_run(&self, _s: &str) -> anyhow::Result<String> {
            Ok("dry".into())
        }
        async fn snapshot(&self, _s: &str) -> anyhow::Result<String> {
            Ok("snap-1".into())
        }
        async fn execute(&self, _s: &str) -> anyhow::Result<String> {
            self.execute_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_execute {
                anyhow::bail!("execute failed")
            }
            Ok("done".into())
        }
        async fn health_check(&self, _s: &str) -> anyhow::Result<bool> {
            Ok(self.health_ok)
        }
        async fn rollback(&self, _s: &str, _snap: &str) -> anyhow::Result<()> {
            self.rollback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn pb(id: &str) -> Playbook {
        sample_playbooks().into_iter().find(|p| p.id == id).unwrap()
    }

    #[test]
    fn samples_classify_correctly() {
        assert_eq!(pb("s3-public-acl").class, PlaybookClass::Reversible);
        assert_eq!(pb("k8s-privileged-pod").class, PlaybookClass::Destructive);
        assert_eq!(pb("enable-cloudtrail").class, PlaybookClass::Safe);
        assert_eq!(sample_playbooks().len(), 6);
        assert_eq!(pb("azure-nsg-open-rdp").class, PlaybookClass::Reversible);
    }

    #[tokio::test]
    async fn safe_executes_and_audits() {
        let eng = PlaybookEngine::new();
        let cloud = MockCloud::healthy();
        let audit = VecAudit::new();
        let out = eng
            .run(&pb("enable-cloudtrail"), &cloud, None, &audit)
            .await;
        assert_eq!(out.state, ExecState::Completed);
        assert_eq!(cloud.execute_calls.load(Ordering::SeqCst), 1);
        assert_eq!(audit.entries().len(), 1);
    }

    #[tokio::test]
    async fn reversible_rolls_back_on_unhealthy() {
        let eng = PlaybookEngine::new();
        let cloud = MockCloud::unhealthy();
        let audit = VecAudit::new();
        let out = eng.run(&pb("s3-public-acl"), &cloud, None, &audit).await;
        assert_eq!(out.state, ExecState::RolledBack);
        assert_eq!(cloud.rollback_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reversible_rolls_back_on_execute_error() {
        let eng = PlaybookEngine::new();
        let cloud = MockCloud::failing();
        let audit = VecAudit::new();
        let out = eng
            .run(&pb("sg-open-ssh-world"), &cloud, None, &audit)
            .await;
        assert_eq!(out.state, ExecState::RolledBack);
        assert_eq!(cloud.rollback_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn destructive_aborts_without_approval() {
        let eng = PlaybookEngine::new();
        let cloud = MockCloud::healthy();
        let audit = VecAudit::new();
        let out = eng
            .run(&pb("k8s-privileged-pod"), &cloud, None, &audit)
            .await;
        assert_eq!(out.state, ExecState::Aborted);
        assert!(!out.executed);
        assert_eq!(
            cloud.execute_calls.load(Ordering::SeqCst),
            0,
            "cloud must never be touched"
        );
    }

    #[tokio::test]
    async fn destructive_denied_does_not_execute() {
        let eng = PlaybookEngine::new();
        let cloud = MockCloud::healthy();
        let audit = VecAudit::new();
        let out = eng
            .run(
                &pb("k8s-privileged-pod"),
                &cloud,
                Some(Approval::Denied {
                    reason: "no".into(),
                }),
                &audit,
            )
            .await;
        assert_eq!(out.state, ExecState::Aborted);
        assert_eq!(cloud.execute_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn destructive_approved_executes_once() {
        let eng = PlaybookEngine::new();
        let cloud = MockCloud::healthy();
        let audit = VecAudit::new();
        let out = eng
            .run(
                &pb("k8s-privileged-pod"),
                &cloud,
                Some(Approval::Approved { by: "alice".into() }),
                &audit,
            )
            .await;
        assert_eq!(out.state, ExecState::Completed);
        assert_eq!(cloud.execute_calls.load(Ordering::SeqCst), 1);
        assert_eq!(audit.entries()[0].actor.as_deref(), Some("alice"));
    }

    #[test]
    fn breaker_halts_class_above_error_rate() {
        let cb = CircuitBreaker::new(300_000, 0.2, 3);
        // 3 errors in window → error rate 1.0 > 0.2 → halted.
        cb.record_at(PlaybookClass::Reversible, false, 0);
        cb.record_at(PlaybookClass::Reversible, false, 100);
        cb.record_at(PlaybookClass::Reversible, false, 200);
        assert!(cb.is_open(PlaybookClass::Reversible));
        assert!(!cb.is_open(PlaybookClass::Safe));
        cb.reset(PlaybookClass::Reversible);
        assert!(!cb.is_open(PlaybookClass::Reversible));
    }

    #[tokio::test]
    async fn open_breaker_aborts_run() {
        let eng = PlaybookEngine::new();
        eng.breaker.record_at(PlaybookClass::Reversible, false, 0);
        eng.breaker.record_at(PlaybookClass::Reversible, false, 1);
        eng.breaker.record_at(PlaybookClass::Reversible, false, 2);
        let cloud = MockCloud::healthy();
        let audit = VecAudit::new();
        let out = eng.run(&pb("s3-public-acl"), &cloud, None, &audit).await;
        assert_eq!(out.state, ExecState::Aborted);
        assert_eq!(cloud.execute_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn parse_step_maps_sample_playbook_actions() {
        assert_eq!(
            parse_step("s3.put_bucket_acl bucket=b1 acl=private"),
            CloudAction::PutBucketAcl {
                bucket: "b1".into(),
                acl: "private".into()
            }
        );
        assert_eq!(
            parse_step("ec2.revoke_ingress sg=sg-1 cidr=0.0.0.0/0 port=22"),
            CloudAction::RevokeSecurityGroupIngress {
                sg: "sg-1".into(),
                cidr: "0.0.0.0/0".into(),
                port: "22".into()
            }
        );
        assert_eq!(
            parse_step("cloudtrail.start_logging name=trail-1"),
            CloudAction::StartCloudTrail {
                name: "trail-1".into()
            }
        );
        assert!(matches!(
            parse_step("totally unknown step"),
            CloudAction::Unknown(_)
        ));
    }

    #[test]
    fn load_dir_reads_yaml_playbooks_from_disk() {
        let dir = std::env::temp_dir().join(format!("secureops-selfheal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.yaml"), S3_PUBLIC_ACL).unwrap();
        std::fs::write(dir.join("b.yml"), ENABLE_CLOUDTRAIL).unwrap();
        std::fs::write(dir.join("ignored.txt"), "not a playbook").unwrap();
        let pbs = load_dir(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(pbs.len(), 2);
        assert!(pbs.iter().any(|p| p.id == "s3-public-acl"));
        assert!(pbs.iter().any(|p| p.id == "enable-cloudtrail"));
    }

    #[test]
    fn every_sample_playbook_step_parses_to_a_known_action() {
        // The shipped playbooks must use the structured format AwsCloud expects.
        for pb in sample_playbooks() {
            assert!(
                !matches!(parse_step(&pb.execute), CloudAction::Unknown(_)),
                "playbook {} has an unparseable execute step: {}",
                pb.id,
                pb.execute
            );
        }
    }
}
