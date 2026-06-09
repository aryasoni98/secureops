//! Azure self-healing backend.
//!
//! Dry, in-process implementation that records actions and reports success.
//! Same pattern as [`crate::gcp::GcpCloud`]; lets the engine run end-to-end on
//! Azure-flagged playbooks (NSG rule revoke, storage HTTPS-only) without
//! pulling the Azure SDK at build time. A `azure-live` feature can replace it
//! later.

use async_trait::async_trait;
use std::sync::Mutex;

use crate::{parse_step, CloudAction, CloudBackend};

/// Dry Azure backend.
#[derive(Default)]
pub struct AzureCloud {
    calls: Mutex<Vec<CloudAction>>,
}

impl AzureCloud {
    pub fn new() -> Self {
        Self::default()
    }

    /// Captured action log (newest last).
    pub fn calls(&self) -> Vec<CloudAction> {
        self.calls.lock().expect("azure calls lock").clone()
    }

    fn record(&self, a: CloudAction) {
        self.calls.lock().expect("azure calls lock").push(a);
    }
}

#[async_trait]
impl CloudBackend for AzureCloud {
    async fn dry_run(&self, step: &str) -> anyhow::Result<String> {
        self.record(parse_step(step));
        Ok(format!("azure dry_run ok: {step}"))
    }

    async fn snapshot(&self, step: &str) -> anyhow::Result<String> {
        self.record(parse_step(step));
        Ok("azure-snapshot".into())
    }

    async fn execute(&self, step: &str) -> anyhow::Result<String> {
        let action = parse_step(step);
        match &action {
            CloudAction::AzureNsgRevokeRule { nsg, cidr, port } => {
                self.record(action.clone());
                Ok(format!(
                    "azure.nsg_revoke_rule ok nsg={nsg} cidr={cidr} port={port}"
                ))
            }
            CloudAction::Unknown(raw) => {
                self.record(action.clone());
                anyhow::bail!("azure backend: unknown step {raw}");
            }
            other => {
                self.record(other.clone());
                anyhow::bail!("azure backend does not handle {:?}", other)
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
    async fn nsg_revoke_succeeds() {
        let b = AzureCloud::new();
        let out = b
            .execute("azure.nsg_revoke_rule nsg=nsg-1 cidr=0.0.0.0/0 port=3389")
            .await
            .unwrap();
        assert!(out.contains("nsg-1"));
        assert_eq!(b.calls().len(), 1);
    }

    #[tokio::test]
    async fn unhandled_action_errors() {
        let b = AzureCloud::new();
        assert!(b
            .execute("s3.put_bucket_acl bucket=b acl=private")
            .await
            .is_err());
    }
}
