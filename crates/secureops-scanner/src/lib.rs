//! # secureops-scanner
//!
//! Scan-job consumer (PRODUCT.md Phase 5b). Pulls scan jobs off the Redis
//! `SCAN_QUEUE`, dispatches them to a [`Collector`] implementation (mock or
//! cloud-specific), and writes [`Finding`](secureops_api::models::Finding) rows
//! into the platform [`Store`](secureops_api::store::Store).
//!
//! The collector layer is a thin trait so unit tests and chaos drills can run
//! with `MockCollector` while the production binary slots in real read-only
//! cloud collectors (AWS/GCP/Azure).

#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::Pool;
use secureops_api::models::{Finding, Severity};
use secureops_api::store::Store;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One job payload from Redis (`LPUSH` by the API, `BRPOP` by the worker).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    #[serde(rename = "scanId")]
    pub scan_id: Uuid,
    pub scope: String,
    pub kind: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// One audit result the collector wants persisted as a Finding.
#[derive(Debug, Clone)]
pub struct CollectorFinding {
    pub title: String,
    pub severity: Severity,
    pub cloud: Option<String>,
    pub blast_radius: i64,
}

/// A pluggable scan executor. Implementations are stateless and `Send + Sync`.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Run the configured checks for `job` and return everything that needs to
    /// become a [`Finding`].
    async fn collect(&self, job: &ScanJob) -> anyhow::Result<Vec<CollectorFinding>>;
}

/// Deterministic mock collector: emits one finding per scope keyword.
///
/// `scope = "aws"`  → one critical AWS finding.
/// `scope = "all"`  → one finding per cloud (aws/gcp/azure).
/// Anything else    → one info finding.
pub struct MockCollector;

#[async_trait]
impl Collector for MockCollector {
    async fn collect(&self, job: &ScanJob) -> anyhow::Result<Vec<CollectorFinding>> {
        let mk = |cloud: &str, sev: Severity, blast: i64, title: &str| CollectorFinding {
            title: title.into(),
            severity: sev,
            cloud: Some(cloud.into()),
            blast_radius: blast,
        };
        Ok(match job.scope.as_str() {
            "aws" => vec![mk(
                "aws",
                Severity::Critical,
                90,
                "S3 bucket world-readable",
            )],
            "gcp" => vec![mk("gcp", Severity::High, 70, "GCS bucket allUsers reader")],
            "azure" => vec![mk(
                "azure",
                Severity::High,
                65,
                "NSG opens RDP to 0.0.0.0/0",
            )],
            "all" => vec![
                mk("aws", Severity::Critical, 90, "S3 bucket world-readable"),
                mk("gcp", Severity::High, 70, "GCS bucket allUsers reader"),
                mk("azure", Severity::High, 65, "NSG opens RDP to 0.0.0.0/0"),
            ],
            _ => vec![mk(
                "n/a",
                Severity::Info,
                0,
                "no rules matched for the requested scope",
            )],
        })
    }
}

/// Scanner-worker process wiring: a Redis-backed queue + a [`Collector`] + a
/// destination [`Store`]. Drives the BRPOP→collect→persist loop until canceled.
pub struct Worker {
    pool: Pool,
    queue: String,
    collector: Arc<dyn Collector>,
    store: Arc<dyn Store>,
    /// Default tenant assigned to jobs that don't carry `tenant_id` (CI/dev).
    pub default_tenant: String,
    /// BRPOP timeout (seconds). `0` blocks forever; any non-zero is a heartbeat.
    pub poll_secs: u64,
}

impl Worker {
    pub fn new(
        pool: Pool,
        queue: impl Into<String>,
        collector: Arc<dyn Collector>,
        store: Arc<dyn Store>,
    ) -> Self {
        Self {
            pool,
            queue: queue.into(),
            collector,
            store,
            default_tenant: "default".into(),
            poll_secs: 5,
        }
    }

    /// Build from a `redis://` URL (production entry point).
    pub fn from_url(
        url: &str,
        queue: impl Into<String>,
        collector: Arc<dyn Collector>,
        store: Arc<dyn Store>,
    ) -> anyhow::Result<Self> {
        let cfg = deadpool_redis::Config::from_url(url);
        let pool = cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
        Ok(Self::new(pool, queue, collector, store))
    }

    /// Pop one job, process it, persist findings, mark the scan done. Returns
    /// `Ok(true)` when a job was processed, `Ok(false)` on poll timeout.
    pub async fn process_one(&self) -> anyhow::Result<bool> {
        let mut conn = self.pool.get().await?;
        let popped: Option<(String, String)> =
            conn.brpop(&self.queue, self.poll_secs as f64).await?;
        let Some((_, payload)) = popped else {
            return Ok(false);
        };
        self.handle_payload(&payload).await?;
        Ok(true)
    }

    /// Process one payload string (used by tests + `process_one`). Persists
    /// findings even when the upstream scan row has not been created - useful
    /// for ad-hoc collector runs.
    pub async fn handle_payload(&self, payload: &str) -> anyhow::Result<()> {
        let job: ScanJob = serde_json::from_str(payload)?;
        tracing::info!(scan_id=%job.scan_id, scope=%job.scope, "scanner: starting job");
        let tenant = job
            .tenant_id
            .clone()
            .unwrap_or_else(|| self.default_tenant.clone());

        let collected = self.collector.collect(&job).await?;
        for c in &collected {
            let finding = Finding {
                id: Uuid::new_v4(),
                tenant_id: tenant.clone(),
                scan_id: Some(job.scan_id),
                title: c.title.clone(),
                severity: c.severity,
                status: "open".into(),
                cloud: c.cloud.clone(),
                blast_radius: c.blast_radius,
            };
            if let Err(e) = self.store.insert_finding(&finding).await {
                tracing::warn!(error=%e, "scanner: insert_finding failed (degraded)");
            }
        }
        tracing::info!(scan_id=%job.scan_id, count=collected.len(), "scanner: job done");
        Ok(())
    }

    /// Run forever (until `cancel` resolves). `process_one` errors are logged
    /// but never crash the worker - Phase 9 chaos requires graceful degradation.
    pub async fn run_until(self, cancel: impl std::future::Future<Output = ()>) {
        tokio::pin!(cancel);
        loop {
            tokio::select! {
                _ = &mut cancel => {
                    tracing::info!("scanner: shutdown requested");
                    return;
                }
                res = self.process_one() => {
                    if let Err(e) = res {
                        tracing::warn!(error=%e, "scanner: process_one failed (will retry)");
                        tokio::time::sleep(std::time::Duration::from_secs(self.poll_secs.max(1))).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureops_api::store::InMemoryStore;

    #[tokio::test]
    async fn mock_collector_emits_one_per_cloud_for_all_scope() {
        let job = ScanJob {
            scan_id: Uuid::new_v4(),
            scope: "all".into(),
            kind: "scan".into(),
            tenant_id: None,
        };
        let out = MockCollector.collect(&job).await.unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().any(|f| f.cloud.as_deref() == Some("aws")));
        assert!(out.iter().any(|f| f.cloud.as_deref() == Some("gcp")));
        assert!(out.iter().any(|f| f.cloud.as_deref() == Some("azure")));
    }

    #[tokio::test]
    async fn handle_payload_persists_findings_to_store() {
        let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
        // Build a worker without a live Redis pool - `handle_payload` doesn't touch it.
        let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1");
        let pool = cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let worker = Worker::new(pool, "q", Arc::new(MockCollector), store.clone());
        let scan_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "scanId": scan_id,
            "scope": "aws",
            "kind": "scan",
            "tenant_id": "acme",
        })
        .to_string();
        worker.handle_payload(&payload).await.unwrap();

        let findings = store
            .list_findings("acme", &secureops_api::store::FindingFilter::default())
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].scan_id, Some(scan_id));
        assert_eq!(findings[0].cloud.as_deref(), Some("aws"));
    }
}
