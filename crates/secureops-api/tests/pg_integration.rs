//! Live-Postgres integration tests (PRODUCT.md Phase 5b).
//!
//! `#[ignore]` by default — they need a real database. Run with:
//! ```sh
//! DATABASE_URL=postgres://secureops_app:pw@localhost/secureops \
//!   cargo test -p secureops-api --test pg_integration -- --ignored
//! ```
//! CI provides a `postgres:16` service. These compile unconditionally, so the
//! PgStore query surface is type-checked on every build.

use secureops_api::license::{License, Tier};
use secureops_api::models::{Finding, Scan, ScanStatus, Severity};
use secureops_api::store::pg::PgStore;
use secureops_api::store::{FindingFilter, Store};
use uuid::Uuid;

const FAR_FUTURE: i64 = 4_102_444_800;

async fn store() -> PgStore {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for --ignored pg tests");
    let s = PgStore::connect(&url).await.expect("connect to postgres");
    s.migrate().await.expect("apply migrations");
    s
}

#[tokio::test]
#[ignore = "needs live Postgres (set DATABASE_URL, run with --ignored)"]
async fn migrations_run_twice_idempotently() {
    let s = store().await;
    // Already migrated in store(); a second run must be a no-op, not an error.
    s.migrate().await.expect("second migrate is idempotent");
    assert!(s.health().await);
}

#[tokio::test]
#[ignore = "needs live Postgres (set DATABASE_URL, run with --ignored)"]
async fn license_scan_finding_round_trip() {
    let s = store().await;
    let tenant = format!("t-{}", Uuid::new_v4());

    let lic = License {
        lic_id: format!("lic-{}", Uuid::new_v4()),
        tenant_id: tenant.clone(),
        tier: Tier::Pro,
        seats: 3,
        features: vec!["bughunt".into(), "scans".into()],
        issued: 0,
        expiry: FAR_FUTURE,
        mode: "online".into(),
        grace_days: 7,
    };
    s.put_license(&lic).await.unwrap();
    // Upsert path: putting again must not error.
    s.put_license(&lic).await.unwrap();
    let got = s
        .get_license(&tenant)
        .await
        .unwrap()
        .expect("license present");
    assert_eq!(got.tier, Tier::Pro);
    assert!(got.features.contains(&"bughunt".to_string()));

    let scan = Scan {
        id: Uuid::new_v4(),
        tenant_id: tenant.clone(),
        scope: "all".into(),
        kind: "scan".into(),
        status: ScanStatus::Queued,
        created_at: 1,
    };
    s.create_scan(&scan).await.unwrap();
    let fetched = s
        .get_scan(&tenant, scan.id)
        .await
        .unwrap()
        .expect("scan present");
    assert_eq!(fetched.scope, "all");
    // Tenant isolation: another tenant can't read it.
    assert!(s.get_scan("someone-else", scan.id).await.unwrap().is_none());

    let f = Finding {
        id: Uuid::new_v4(),
        tenant_id: tenant.clone(),
        scan_id: Some(scan.id),
        title: "ssh open to world".into(),
        severity: Severity::High,
        status: "open".into(),
        cloud: Some("aws".into()),
        blast_radius: 5,
    };
    s.insert_finding(&f).await.unwrap();

    let high = s
        .list_findings(
            &tenant,
            &FindingFilter {
                severity: Some("high".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(high.len(), 1);

    assert!(s
        .set_finding_status(&tenant, f.id, "confirmed")
        .await
        .unwrap());
    assert!(!s
        .set_finding_status("other", f.id, "dismissed")
        .await
        .unwrap());

    let confirmed = s
        .list_findings(
            &tenant,
            &FindingFilter {
                status: Some("confirmed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(confirmed.len(), 1);
}
