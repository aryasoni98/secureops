//! API error type → HTTP response mapping (PRODUCT.md Phase 5).
//!
//! Every handler returns [`ApiResult`]; [`ApiError`] renders a stable JSON body
//! `{ "error": <code>, "message": <detail> }` with the right status. `401`s
//! carry a `WWW-Authenticate` header (P5 test asserts this).

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Result alias used by every handler.
pub type ApiResult<T> = Result<T, ApiError>;

/// All ways a request can fail. The `&'static str` payloads are the stable
/// machine-readable `error` codes returned to clients.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Missing/invalid credentials → `401` + `WWW-Authenticate`.
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    /// Authenticated but not permitted (Cedar deny / tier gate) → `403`.
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// License verification failed → `403` (code = `invalid_signature`,
    /// `license_expired`, `malformed_key`, …).
    #[error("license: {0}")]
    License(&'static str),
    /// Malformed input → `400`.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// Resource not found → `404`.
    #[error("not found")]
    NotFound,
    /// Backing store unreachable/failed → `503` (degraded, retryable).
    #[error("storage error: {0}")]
    Store(String),
    /// Unexpected internal failure → `500`.
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, with_www_auth) = match &self {
            ApiError::Unauthorized(c) => (StatusCode::UNAUTHORIZED, *c, true),
            ApiError::Forbidden(c) => (StatusCode::FORBIDDEN, *c, false),
            ApiError::License(c) => (StatusCode::FORBIDDEN, *c, false),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", false),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", false),
            ApiError::Store(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                false,
            ),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", false),
        };
        let body = Json(json!({ "error": code, "message": self.to_string() }));
        if with_www_auth {
            (status, [(header::WWW_AUTHENTICATE, "Bearer")], body).into_response()
        } else {
            (status, body).into_response()
        }
    }
}
