//! Postgres-backed [`Store`] (PRODUCT.md Phase 5b), via deadpool-postgres +
//! tokio-postgres (no sqlx → no sqlite/cc clash). Runtime-parameterised queries
//! (no `query!` macro), so it builds without a live database. The embedded
//! [`PgStore::migrate`] runner applies `migrations/00{1..6}_*.sql` idempotently.

use async_trait::async_trait;
use deadpool_postgres::Pool;
use serde_json::Value;
use uuid::Uuid;

use crate::auth::Claims;
use crate::license::{License, Tier};
use crate::models::{Finding, Remediation, Scan, ScanStatus, Severity};
use crate::store::{FindingFilter, Store};

/// Embedded migrations, applied in order (PRODUCT.md Phase 5).
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "001_licenses",
        include_str!("../../migrations/001_licenses.sql"),
    ),
    (
        "002_clouds",
        include_str!("../../migrations/002_clouds.sql"),
    ),
    (
        "003_assets_identities",
        include_str!("../../migrations/003_assets_identities.sql"),
    ),
    (
        "004_findings",
        include_str!("../../migrations/004_findings.sql"),
    ),
    (
        "005_remediations_feedback",
        include_str!("../../migrations/005_remediations_feedback.sql"),
    ),
    (
        "006_usage_audit",
        include_str!("../../migrations/006_usage_audit.sql"),
    ),
];

/// A far-future session expiry used for API-key-derived principals.
const SESSION_EXP: usize = 4_102_444_800; // ~year 2100

fn sev_to_str(s: Severity) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "info".into())
}
fn sev_from_str(s: &str) -> Severity {
    serde_json::from_value(Value::String(s.to_string())).unwrap_or(Severity::Info)
}
fn status_to_str(s: ScanStatus) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "queued".into())
}
fn status_from_str(s: &str) -> ScanStatus {
    serde_json::from_value(Value::String(s.to_string())).unwrap_or(ScanStatus::Queued)
}
fn tier_from_str(s: &str) -> Tier {
    serde_json::from_value(Value::String(s.to_string())).unwrap_or(Tier::Community)
}
fn tier_to_str(t: Tier) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "community".into())
}
fn features_to_json(features: &[String]) -> Value {
    Value::Array(features.iter().cloned().map(Value::String).collect())
}
fn features_from_json(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Postgres-backed store.
pub struct PgStore {
    pool: Pool,
}

impl PgStore {
    /// Wrap a connection pool.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// Build a `PgStore` from a Postgres DSN (NoTls; front with a TLS terminator
    /// for encrypted transit). Keeps the pool types internal so callers/tests
    /// only depend on this crate.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        use std::str::FromStr;
        let pg_config = tokio_postgres::Config::from_str(url)?;
        let mgr_config = deadpool_postgres::ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        };
        let mgr =
            deadpool_postgres::Manager::from_config(pg_config, tokio_postgres::NoTls, mgr_config);
        let pool = deadpool_postgres::Pool::builder(mgr)
            .max_size(16)
            .build()
            .map_err(|e| anyhow::anyhow!("pg pool: {e}"))?;
        Ok(Self::new(pool))
    }

    /// Apply all embedded migrations in a tracked, idempotent way. Running twice
    /// is a no-op (each migration is recorded in `_migrations`).
    pub async fn migrate(&self) -> anyhow::Result<()> {
        let mut client = self.pool.get().await?;
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS _migrations (
                     name TEXT PRIMARY KEY,
                     applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                 );",
            )
            .await?;
        for (name, sql) in MIGRATIONS {
            let already = client
                .query_opt("SELECT 1 FROM _migrations WHERE name = $1", &[name])
                .await?;
            if already.is_some() {
                continue;
            }
            let tx = client.transaction().await?;
            tx.batch_execute(sql).await?;
            tx.execute("INSERT INTO _migrations (name) VALUES ($1)", &[name])
                .await?;
            tx.commit().await?;
            tracing::info!(migration = name, "applied");
        }
        Ok(())
    }
}

#[async_trait]
impl Store for PgStore {
    async fn health(&self) -> bool {
        match self.pool.get().await {
            Ok(client) => client.query_one("SELECT 1", &[]).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn lookup_api_key(&self, hashed: &str) -> anyhow::Result<Option<Claims>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT tenant_id, sub, tier, features FROM api_keys \
                 WHERE key_hash = $1 AND revoked = false",
                &[&hashed],
            )
            .await?;
        Ok(row.map(|r| Claims {
            sub: r.get("sub"),
            tenant: r.get("tenant_id"),
            tier: r.get("tier"),
            features: features_from_json(&r.get::<_, Value>("features")),
            exp: SESSION_EXP,
        }))
    }

    async fn put_license(&self, lic: &License) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO licenses \
                   (lic_id, tenant_id, tier, seats, features, issued, expiry, mode, grace_days) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
                 ON CONFLICT (lic_id) DO UPDATE SET \
                   tenant_id = EXCLUDED.tenant_id, tier = EXCLUDED.tier, seats = EXCLUDED.seats, \
                   features = EXCLUDED.features, issued = EXCLUDED.issued, expiry = EXCLUDED.expiry, \
                   mode = EXCLUDED.mode, grace_days = EXCLUDED.grace_days",
                &[
                    &lic.lic_id,
                    &lic.tenant_id,
                    &tier_to_str(lic.tier),
                    &(lic.seats as i32),
                    &features_to_json(&lic.features),
                    &lic.issued,
                    &lic.expiry,
                    &lic.mode,
                    &(lic.grace_days as i32),
                ],
            )
            .await?;
        Ok(())
    }

    async fn get_license(&self, tenant: &str) -> anyhow::Result<Option<License>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT lic_id, tenant_id, tier, seats, features, issued, expiry, mode, grace_days \
                 FROM licenses WHERE tenant_id = $1 ORDER BY expiry DESC LIMIT 1",
                &[&tenant],
            )
            .await?;
        Ok(row.map(|r| License {
            lic_id: r.get("lic_id"),
            tenant_id: r.get("tenant_id"),
            tier: tier_from_str(&r.get::<_, String>("tier")),
            seats: r.get::<_, i32>("seats") as u32,
            features: features_from_json(&r.get::<_, Value>("features")),
            issued: r.get("issued"),
            expiry: r.get("expiry"),
            mode: r.get("mode"),
            grace_days: r.get::<_, i32>("grace_days") as u32,
        }))
    }

    async fn create_scan(&self, scan: &Scan) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO scans (id, tenant_id, scope, kind, status, created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
                &[
                    &scan.id,
                    &scan.tenant_id,
                    &scan.scope,
                    &scan.kind,
                    &status_to_str(scan.status),
                    &scan.created_at,
                ],
            )
            .await?;
        Ok(())
    }

    async fn get_scan(&self, tenant: &str, id: Uuid) -> anyhow::Result<Option<Scan>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, tenant_id, scope, kind, status, created_at \
                 FROM scans WHERE id = $1 AND tenant_id = $2",
                &[&id, &tenant],
            )
            .await?;
        Ok(row.map(|r| Scan {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            scope: r.get("scope"),
            kind: r.get("kind"),
            status: status_from_str(&r.get::<_, String>("status")),
            created_at: r.get("created_at"),
        }))
    }

    async fn list_findings(&self, tenant: &str, f: &FindingFilter) -> anyhow::Result<Vec<Finding>> {
        let client = self.pool.get().await?;
        let limit = if f.limit <= 0 { 50 } else { f.limit };
        let offset = f.offset.max(0);
        let rows = client
            .query(
                "SELECT id, tenant_id, scan_id, title, severity, status, cloud, blast_radius \
                 FROM findings \
                 WHERE tenant_id = $1 \
                   AND ($2::text IS NULL OR severity = $2) \
                   AND ($3::text IS NULL OR status = $3) \
                 ORDER BY created_at DESC LIMIT $4 OFFSET $5",
                &[&tenant, &f.severity, &f.status, &limit, &offset],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| Finding {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                scan_id: r.get("scan_id"),
                title: r.get("title"),
                severity: sev_from_str(&r.get::<_, String>("severity")),
                status: r.get("status"),
                cloud: r.get("cloud"),
                blast_radius: r.get("blast_radius"),
            })
            .collect())
    }

    async fn set_finding_status(
        &self,
        tenant: &str,
        id: Uuid,
        status: &str,
    ) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;
        let n = client
            .execute(
                "UPDATE findings SET status = $3 WHERE id = $1 AND tenant_id = $2",
                &[&id, &tenant, &status],
            )
            .await?;
        Ok(n > 0)
    }

    async fn insert_finding(&self, finding: &Finding) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO findings \
                   (id, tenant_id, scan_id, title, severity, status, cloud, blast_radius) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                &[
                    &finding.id,
                    &finding.tenant_id,
                    &finding.scan_id,
                    &finding.title,
                    &sev_to_str(finding.severity),
                    &finding.status,
                    &finding.cloud,
                    &finding.blast_radius,
                ],
            )
            .await?;
        Ok(())
    }

    async fn insert_remediation(&self, tenant: &str, r: &Remediation) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO remediations (id, tenant_id, finding_id, playbook, class, state) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
                &[
                    &r.id,
                    &tenant,
                    &r.finding_id,
                    &r.playbook_id,
                    &r.class,
                    &r.state,
                ],
            )
            .await?;
        Ok(())
    }

    async fn list_remediations(&self, tenant: &str) -> anyhow::Result<Vec<Remediation>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT id, finding_id, playbook, class, state FROM remediations \
                 WHERE tenant_id = $1 ORDER BY created_at DESC",
                &[&tenant],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| Remediation {
                id: r.get("id"),
                finding_id: r.get("finding_id"),
                playbook_id: r.get("playbook"),
                class: r.get("class"),
                state: r.get("state"),
            })
            .collect())
    }

    async fn set_remediation_state(
        &self,
        tenant: &str,
        id: Uuid,
        state: &str,
    ) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;
        let n = client
            .execute(
                "UPDATE remediations SET state = $3, updated_at = now() \
                 WHERE id = $1 AND tenant_id = $2",
                &[&id, &tenant, &state],
            )
            .await?;
        Ok(n > 0)
    }

    async fn record_rl_feedback(
        &self,
        tenant: &str,
        finding_id: &str,
        action: &str,
        reward: f64,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO rl_feedback (tenant_id, finding_id, action, reward) \
                 VALUES ($1,$2,$3,$4)",
                &[&tenant, &finding_id, &action, &reward],
            )
            .await?;
        Ok(())
    }
}
