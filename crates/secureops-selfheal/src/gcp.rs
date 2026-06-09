//! GCP self-healing backend.
//!
//! Defaults to a dry, in-process implementation that logs every action and
//! reports success. Useful in CI and on-prem demos where the real GCP SDK is
//! intentionally absent. A live backend can be wired later behind a `gcp-live`
//! feature without changing the `CloudBackend` trait.

use async_trait::async_trait;
use std::sync::Mutex;

use crate::{parse_step, CloudAction, CloudBackend};

/// Dry GCP backend: records every parsed [`CloudAction`] and returns success.
#[derive(Default)]
pub struct GcpCloud {
    calls: Mutex<Vec<CloudAction>>,
}

impl GcpCloud {
    pub fn new() -> Self {
        Self::default()
    }

    /// Captured action log (newest last).
    pub fn calls(&self) -> Vec<CloudAction> {
        self.calls.lock().expect("gcp calls lock").clone()
    }

    fn record(&self, a: CloudAction) {
        self.calls.lock().expect("gcp calls lock").push(a);
    }
}

#[async_trait]
impl CloudBackend for GcpCloud {
    async fn dry_run(&self, step: &str) -> anyhow::Result<String> {
        self.record(parse_step(step));
        Ok(format!("gcp dry_run ok: {step}"))
    }

    async fn snapshot(&self, step: &str) -> anyhow::Result<String> {
        self.record(parse_step(step));
        Ok("gcp-snapshot".into())
    }

    async fn execute(&self, step: &str) -> anyhow::Result<String> {
        let action = parse_step(step);
        match &action {
            CloudAction::GcsRemoveIamMember { bucket, member } => {
                self.record(action.clone());
                Ok(format!(
                    "gcs.remove_iam_member ok bucket={bucket} member={member}"
                ))
            }
            CloudAction::GcpFirewallRevoke { firewall, cidr } => {
                self.record(action.clone());
                Ok(format!(
                    "gcp.firewall_revoke ok firewall={firewall} cidr={cidr}"
                ))
            }
            CloudAction::Unknown(raw) => {
                self.record(action.clone());
                anyhow::bail!("gcp backend: unknown step {raw}");
            }
            other => {
                self.record(other.clone());
                anyhow::bail!("gcp backend does not handle {:?}", other)
            }
        }
    }

    async fn health_check(&self, _step: &str) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn rollback(&self, step: &str, _snapshot: &str) -> anyhow::Result<()> {
        self.record(parse_step(step));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execute_handles_gcs_remove_iam_member() {
        let b = GcpCloud::new();
        let out = b
            .execute("gcs.remove_iam_member bucket=b1 member=allUsers")
            .await
            .unwrap();
        assert!(out.contains("b1"));
        assert_eq!(b.calls().len(), 1);
    }

    #[tokio::test]
    async fn execute_unknown_action_errors() {
        let b = GcpCloud::new();
        assert!(b.execute("not.a.real.op x=y").await.is_err());
    }
}
