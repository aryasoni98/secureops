//! Entry point for the SecureOps scan-job worker. Reads `REDIS_URL`,
//! `SECUREOPS_SCAN_QUEUE` (defaults to `secureops:scans`), a collector choice
//! via `SECUREOPS_COLLECTOR` (`mock` default, `aws` when built with
//! `--features aws`), and a backing store choice via `DATABASE_URL`
//! (Postgres) or falls back to a process-local in-memory store for CI/dev.

use std::sync::Arc;

use secureops_api::redis_queue::SCAN_QUEUE;
use secureops_api::store::pg::PgStore;
use secureops_api::store::{InMemoryStore, Store};
use secureops_scanner::{Collector, MockCollector, Worker};
use tracing::Level;
use tracing_subscriber::EnvFilter;

/// Pick the collector from `SECUREOPS_COLLECTOR`.
async fn collector_from_env() -> anyhow::Result<Arc<dyn Collector>> {
    let which = std::env::var("SECUREOPS_COLLECTOR").unwrap_or_else(|_| "mock".into());
    match which.as_str() {
        "mock" => Ok(Arc::new(MockCollector)),
        #[cfg(feature = "aws")]
        "aws" => Ok(Arc::new(
            secureops_scanner::aws::AwsCollector::from_env().await,
        )),
        #[cfg(not(feature = "aws"))]
        "aws" => anyhow::bail!(
            "SECUREOPS_COLLECTOR=aws but this binary was built without the `aws` feature; \
             rebuild with `cargo build -p secureops-scanner --features aws`"
        ),
        other => anyhow::bail!("unknown SECUREOPS_COLLECTOR '{other}' (expected mock|aws)"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_max_level(Level::INFO)
        .init();

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let queue = std::env::var("SECUREOPS_SCAN_QUEUE").unwrap_or_else(|_| SCAN_QUEUE.to_string());

    let store: Arc<dyn Store> = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => {
            tracing::info!("connecting Postgres store");
            let pg = PgStore::connect(&url).await?;
            Arc::new(pg)
        }
        _ => {
            tracing::warn!("DATABASE_URL not set - using in-memory store (CI/dev mode)");
            Arc::new(InMemoryStore::new())
        }
    };

    let collector = collector_from_env().await?;
    let worker = Worker::from_url(&redis_url, &queue, collector, store)?;
    tracing::info!(%redis_url, %queue, "scanner worker starting");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    worker.run_until(shutdown).await;
    Ok(())
}
