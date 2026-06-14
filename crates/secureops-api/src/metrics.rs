//! **Process metrics** (beta blocker: "no `/metrics` endpoint, nothing scrapes
//! telemetry"). A dependency-free counter/histogram registry rendered in the
//! Prometheus text exposition format at `GET /metrics`.
//!
//! This closes the "observability is configured but never wired" gap: the
//! collector / scraper now has a real endpoint to read, and every HTTP request
//! flows through [`track`] via the router middleware. Distributed tracing
//! (OTLP spans) is layered separately via `tower_http::trace::TraceLayer`; this
//! module owns the numeric surface (request counts, latency, auth failures).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// Fixed latency buckets (seconds) for the request-duration histogram.
const BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

/// Process-wide metric counters. Cheap to clone via `Arc`.
#[derive(Default)]
pub struct Metrics {
    requests_total: AtomicU64,
    requests_4xx: AtomicU64,
    requests_5xx: AtomicU64,
    auth_failures_total: AtomicU64,
    authz_denials_total: AtomicU64,
    rate_limited_total: AtomicU64,
    /// Cumulative request duration in microseconds (for an avg + sum gauge).
    duration_micros_total: AtomicU64,
    /// Histogram bucket counters (`le` upper bounds in [`BUCKETS`]) + `+Inf`.
    hist: Mutex<[u64; 11]>,
}

impl Metrics {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed request with its status and wall-clock duration.
    pub fn observe(&self, status: u16, secs: f64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if (400..500).contains(&status) {
            self.requests_4xx.fetch_add(1, Ordering::Relaxed);
        } else if status >= 500 {
            self.requests_5xx.fetch_add(1, Ordering::Relaxed);
        }
        if status == 401 {
            self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
        }
        if status == 403 {
            self.authz_denials_total.fetch_add(1, Ordering::Relaxed);
        }
        if status == 429 {
            self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
        }
        self.duration_micros_total
            .fetch_add((secs * 1_000_000.0) as u64, Ordering::Relaxed);
        let mut h = self.hist.lock().unwrap_or_else(|e| e.into_inner());
        let mut placed = false;
        for (i, le) in BUCKETS.iter().enumerate() {
            if secs <= *le {
                h[i] += 1;
                placed = true;
                break;
            }
        }
        if !placed {
            h[BUCKETS.len()] += 1; // +Inf bucket
        }
    }

    /// Increment the rate-limit rejection counter directly (the limiter rejects
    /// before the request reaches [`observe`]).
    pub fn inc_rate_limited(&self) {
        self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the registry in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let total = self.requests_total.load(Ordering::Relaxed);
        let dur_us = self.duration_micros_total.load(Ordering::Relaxed);
        let h = self.hist.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::new();

        out.push_str("# HELP secureops_http_requests_total Total HTTP requests served.\n");
        out.push_str("# TYPE secureops_http_requests_total counter\n");
        out.push_str(&format!("secureops_http_requests_total {total}\n"));

        for (name, help, v) in [
            (
                "secureops_http_requests_4xx_total",
                "HTTP 4xx responses.",
                self.requests_4xx.load(Ordering::Relaxed),
            ),
            (
                "secureops_http_requests_5xx_total",
                "HTTP 5xx responses.",
                self.requests_5xx.load(Ordering::Relaxed),
            ),
            (
                "secureops_auth_failures_total",
                "401 unauthorized responses.",
                self.auth_failures_total.load(Ordering::Relaxed),
            ),
            (
                "secureops_authz_denials_total",
                "403 forbidden responses (Cedar/RBAC deny).",
                self.authz_denials_total.load(Ordering::Relaxed),
            ),
            (
                "secureops_rate_limited_total",
                "429 rate-limited responses.",
                self.rate_limited_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}\n"
            ));
        }

        // Latency histogram (cumulative buckets).
        out.push_str(
            "# HELP secureops_http_request_duration_seconds Request latency.\n\
             # TYPE secureops_http_request_duration_seconds histogram\n",
        );
        let mut cumulative = 0u64;
        for (i, le) in BUCKETS.iter().enumerate() {
            cumulative += h[i];
            out.push_str(&format!(
                "secureops_http_request_duration_seconds_bucket{{le=\"{le}\"}} {cumulative}\n"
            ));
        }
        cumulative += h[BUCKETS.len()];
        out.push_str(&format!(
            "secureops_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}\n"
        ));
        out.push_str(&format!(
            "secureops_http_request_duration_seconds_sum {}\n",
            dur_us as f64 / 1_000_000.0
        ));
        out.push_str(&format!(
            "secureops_http_request_duration_seconds_count {cumulative}\n"
        ));
        out
    }
}

/// `GET /metrics` - Prometheus scrape endpoint. Unauthenticated by design (it
/// exposes only aggregate counters, no tenant data); restrict via NetworkPolicy
/// so only the in-cluster scraper can reach it.
pub async fn metrics_handler(State(s): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        s.metrics.render(),
    )
}

/// Router middleware: time each request and record its status.
pub async fn track(State(s): State<AppState>, req: axum::extract::Request, next: Next) -> Response {
    let start = std::time::Instant::now();
    let resp = next.run(req).await;
    let secs = start.elapsed().as_secs_f64();
    s.metrics.observe(resp.status().as_u16(), secs);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_counters_and_histogram() {
        let m = Metrics::new();
        m.observe(200, 0.003);
        m.observe(401, 0.02);
        m.observe(500, 3.0);
        let text = m.render();
        assert!(text.contains("secureops_http_requests_total 3"));
        assert!(text.contains("secureops_auth_failures_total 1"));
        assert!(text.contains("secureops_http_requests_5xx_total 1"));
        assert!(text.contains("le=\"+Inf\""));
    }
}
