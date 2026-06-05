//! Storage abstraction (PRODUCT.md Phase 5).
//!
//! Handlers depend only on the [`Store`] trait, so the entire API surface
//! unit-tests against [`InMemoryStore`] with no external infrastructure. The
//! Postgres-backed implementation ([`pg::PgStore`]) is wired in 5b; both satisfy
//! the same contract.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use uuid::Uuid;

use crate::auth::Claims;
use crate::license::License;
use crate::models::{Finding, Scan};

/// Postgres-backed [`Store`] (PRODUCT.md Phase 5b).
pub mod pg;

/// Filter for `GET /findings`.
#[derive(Debug, Default, Clone)]
pub struct FindingFilter {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

/// The persistence contract every backend implements.
#[async_trait]
pub trait Store: Send + Sync {
    /// Readiness probe — `true` when the backend is reachable.
    async fn health(&self) -> bool;
    /// Resolve a hashed API key to its principal claims.
    async fn lookup_api_key(&self, hashed: &str) -> anyhow::Result<Option<Claims>>;
    /// Upsert the active license for a tenant.
    async fn put_license(&self, lic: &License) -> anyhow::Result<()>;
    /// Fetch a tenant's active license.
    async fn get_license(&self, tenant: &str) -> anyhow::Result<Option<License>>;
    /// Persist a newly-queued scan job.
    async fn create_scan(&self, scan: &Scan) -> anyhow::Result<()>;
    /// Fetch one scan scoped to a tenant.
    async fn get_scan(&self, tenant: &str, id: Uuid) -> anyhow::Result<Option<Scan>>;
    /// List a tenant's findings with filtering + pagination.
    async fn list_findings(&self, tenant: &str, f: &FindingFilter) -> anyhow::Result<Vec<Finding>>;
    /// Set a finding's status (confirm/dismiss/escalate). `false` if not found.
    async fn set_finding_status(
        &self,
        tenant: &str,
        id: Uuid,
        status: &str,
    ) -> anyhow::Result<bool>;
    /// Insert a finding (used by scanners and tests).
    async fn insert_finding(&self, finding: &Finding) -> anyhow::Result<()>;
}

#[derive(Default)]
struct Mem {
    licenses: HashMap<String, License>,
    api_keys: HashMap<String, Claims>,
    scans: HashMap<Uuid, Scan>,
    findings: Vec<Finding>,
}

/// In-memory [`Store`] for tests / single-node dev (no external infra).
pub struct InMemoryStore {
    inner: Mutex<Mem>,
}

impl InMemoryStore {
    /// Empty store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Mem::default()),
        }
    }

    /// Builder: pre-register a hashed API key → claims mapping.
    pub fn with_api_key(self, hashed: impl Into<String>, claims: Claims) -> Self {
        self.inner
            .lock()
            .expect("mem lock")
            .api_keys
            .insert(hashed.into(), claims);
        self
    }

    /// Builder: seed a finding.
    pub fn seed_finding(self, f: Finding) -> Self {
        self.inner.lock().expect("mem lock").findings.push(f);
        self
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn health(&self) -> bool {
        true
    }

    async fn lookup_api_key(&self, hashed: &str) -> anyhow::Result<Option<Claims>> {
        Ok(self
            .inner
            .lock()
            .expect("mem lock")
            .api_keys
            .get(hashed)
            .cloned())
    }

    async fn put_license(&self, lic: &License) -> anyhow::Result<()> {
        self.inner
            .lock()
            .expect("mem lock")
            .licenses
            .insert(lic.tenant_id.clone(), lic.clone());
        Ok(())
    }

    async fn get_license(&self, tenant: &str) -> anyhow::Result<Option<License>> {
        Ok(self
            .inner
            .lock()
            .expect("mem lock")
            .licenses
            .get(tenant)
            .cloned())
    }

    async fn create_scan(&self, scan: &Scan) -> anyhow::Result<()> {
        self.inner
            .lock()
            .expect("mem lock")
            .scans
            .insert(scan.id, scan.clone());
        Ok(())
    }

    async fn get_scan(&self, tenant: &str, id: Uuid) -> anyhow::Result<Option<Scan>> {
        Ok(self
            .inner
            .lock()
            .expect("mem lock")
            .scans
            .get(&id)
            .filter(|s| s.tenant_id == tenant)
            .cloned())
    }

    async fn list_findings(&self, tenant: &str, f: &FindingFilter) -> anyhow::Result<Vec<Finding>> {
        let mem = self.inner.lock().expect("mem lock");
        let offset = f.offset.max(0) as usize;
        let limit = if f.limit <= 0 { 50 } else { f.limit as usize };
        let out = mem
            .findings
            .iter()
            .filter(|x| x.tenant_id == tenant)
            .filter(|x| {
                f.severity
                    .as_deref()
                    .is_none_or(|s| format!("{:?}", x.severity).to_lowercase() == s)
            })
            .filter(|x| f.status.as_deref().is_none_or(|s| x.status == s))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        Ok(out)
    }

    async fn set_finding_status(
        &self,
        tenant: &str,
        id: Uuid,
        status: &str,
    ) -> anyhow::Result<bool> {
        let mut mem = self.inner.lock().expect("mem lock");
        for x in mem.findings.iter_mut() {
            if x.id == id && x.tenant_id == tenant {
                x.status = status.to_string();
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn insert_finding(&self, finding: &Finding) -> anyhow::Result<()> {
        self.inner
            .lock()
            .expect("mem lock")
            .findings
            .push(finding.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::Tier;
    use crate::models::Severity;

    fn finding(tenant: &str, status: &str, sev: Severity) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            tenant_id: tenant.into(),
            scan_id: None,
            title: "t".into(),
            severity: sev,
            status: status.into(),
            cloud: Some("aws".into()),
            blast_radius: 0,
        }
    }

    #[tokio::test]
    async fn license_round_trips_by_tenant() {
        let s = InMemoryStore::new();
        let lic = License {
            lic_id: "l".into(),
            tenant_id: "t1".into(),
            tier: Tier::Pro,
            seats: 1,
            features: vec![],
            issued: 0,
            expiry: 1,
            mode: "online".into(),
            grace_days: 0,
        };
        s.put_license(&lic).await.unwrap();
        assert!(s.get_license("t1").await.unwrap().is_some());
        assert!(s.get_license("other").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn findings_are_tenant_scoped_and_filtered() {
        let s = InMemoryStore::new()
            .seed_finding(finding("t1", "open", Severity::High))
            .seed_finding(finding("t1", "confirmed", Severity::Low))
            .seed_finding(finding("t2", "open", Severity::High));

        let all = s
            .list_findings("t1", &FindingFilter::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 2, "tenant isolation");

        let high = s
            .list_findings(
                "t1",
                &FindingFilter {
                    severity: Some("high".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(high.len(), 1);
    }

    #[tokio::test]
    async fn set_status_only_affects_owning_tenant() {
        let f = finding("t1", "open", Severity::High);
        let id = f.id;
        let s = InMemoryStore::new().seed_finding(f);
        assert!(!s.set_finding_status("t2", id, "confirmed").await.unwrap());
        assert!(s.set_finding_status("t1", id, "confirmed").await.unwrap());
    }
}
