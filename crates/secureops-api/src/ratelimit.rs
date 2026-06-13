//! **HTTP rate limiting** (beta blocker: "no rate limiting / lockout on any
//! auth endpoint → brute-force open"). A dependency-free fixed-window limiter
//! keyed by client IP, with a stricter window for the unauthenticated auth
//! endpoints (`/license/activate`, `/auth/oidc/callback`) than for the rest of
//! the API.
//!
//! Client IP is resolved from `X-Forwarded-For` / `X-Real-IP` (set by the
//! ingress/reverse proxy); deployments must run behind a proxy that sets these,
//! or in front of `into_make_service_with_connect_info`. Requests with no
//! resolvable IP share a single bucket (fail-safe: they are still limited).

use std::collections::HashMap;
use std::sync::Mutex;

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::state::AppState;

fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Fixed-window counter limiter. Two windows: a generous global one and a
/// tighter one for credential-presenting auth endpoints.
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (i64, u32)>>,
    window_secs: i64,
    global_limit: u32,
    auth_limit: u32,
}

impl RateLimiter {
    /// Build with explicit limits (requests per `window_secs`).
    pub fn new(window_secs: i64, global_limit: u32, auth_limit: u32) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            window_secs,
            global_limit,
            auth_limit,
        }
    }

    /// Sensible defaults for unit/integration tests and local dev: 600 req/min
    /// overall, 30 req/min for auth endpoints.
    pub fn default_limits() -> Self {
        Self::new(60, 600, 30)
    }

    /// Read limits from env (`SECUREOPS_RL_WINDOW_SECS`, `SECUREOPS_RL_GLOBAL`,
    /// `SECUREOPS_RL_AUTH`); falls back to [`RateLimiter::default_limits`].
    pub fn from_env() -> Self {
        let g = std::env::var("SECUREOPS_RL_GLOBAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(600);
        let a = std::env::var("SECUREOPS_RL_AUTH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let w = std::env::var("SECUREOPS_RL_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        Self::new(w, g, a)
    }

    /// `true` if this (key) is within its window budget; records the hit.
    fn allow(&self, key: &str, limit: u32) -> bool {
        let now = now_secs();
        let mut map = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        // Opportunistic cleanup so the map can't grow without bound.
        if map.len() > 100_000 {
            map.retain(|_, (start, _)| now - *start < self.window_secs);
        }
        let entry = map.entry(key.to_string()).or_insert((now, 0));
        if now - entry.0 >= self.window_secs {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::default_limits()
    }
}

/// Is this an unauthenticated credential-submission endpoint (stricter window)?
fn is_auth_path(path: &str) -> bool {
    path.ends_with("/license/activate") || path.ends_with("/auth/oidc/callback")
}

/// Extract the client IP from proxy headers, falling back to a shared bucket.
fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Router middleware: reject with `429 + Retry-After` once a client exceeds its
/// window budget. The auth endpoints get the tighter `auth_limit`.
pub async fn enforce(
    State(s): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let ip = client_ip(req.headers());
    let (limit, class) = if is_auth_path(&path) {
        (s.limiter.auth_limit, "auth")
    } else {
        (s.limiter.global_limit, "global")
    };
    let key = format!("{class}:{ip}");
    if !s.limiter.allow(&key, limit) {
        s.metrics.inc_rate_limited();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "60")],
            axum::Json(json!({ "error": "rate_limited", "message": "too many requests" })),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_budget_enforced_then_resets_per_key() {
        let rl = RateLimiter::new(60, 3, 2);
        assert!(rl.allow("global:1.1.1.1", 3));
        assert!(rl.allow("global:1.1.1.1", 3));
        assert!(rl.allow("global:1.1.1.1", 3));
        assert!(!rl.allow("global:1.1.1.1", 3)); // 4th exceeds
                                                 // Different key is independent.
        assert!(rl.allow("global:2.2.2.2", 3));
    }

    #[test]
    fn auth_path_classification() {
        assert!(is_auth_path("/api/v1/license/activate"));
        assert!(is_auth_path("/api/v1/auth/oidc/callback"));
        assert!(!is_auth_path("/api/v1/findings"));
    }
}
