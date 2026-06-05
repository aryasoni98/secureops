//! Redis-backed scan job queue + readiness (PRODUCT.md Phase 5), via
//! deadpool-redis. Callers degrade gracefully when Redis is down (P9 chaos:
//! "Redis down → scan job completes in degraded mode, warning logged").

use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::Pool;

/// Default queue key scan jobs are pushed onto.
pub const SCAN_QUEUE: &str = "secureops:scans";

/// Scan job queue over a Redis connection pool.
#[derive(Clone)]
pub struct RedisQueue {
    pool: Pool,
}

impl RedisQueue {
    /// Wrap an existing pool.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// Build a pool from a `redis://host:port` URL.
    pub fn from_url(url: &str) -> anyhow::Result<Self> {
        let cfg = deadpool_redis::Config::from_url(url);
        let pool = cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
        Ok(Self::new(pool))
    }

    /// `LPUSH` a job payload onto a queue (worker `BRPOP`s the other end).
    pub async fn enqueue(&self, queue: &str, payload: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let _: i64 = conn.lpush(queue, payload).await?;
        Ok(())
    }

    /// `true` if the server answers `PING`.
    pub async fn health(&self) -> bool {
        match self.pool.get().await {
            Ok(mut conn) => deadpool_redis::redis::cmd("PING")
                .query_async::<String>(&mut conn)
                .await
                .map(|r| r == "PONG")
                .unwrap_or(false),
            Err(_) => false,
        }
    }
}
