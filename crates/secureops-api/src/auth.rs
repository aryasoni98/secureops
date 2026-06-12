//! **Dual authentication** (PRODUCT.md Phase 5): a session JWT (HMAC-SHA256) or
//! a per-tenant API key (SHA-256 hashed at rest). The [`Authenticated`]
//! extractor resolves either into [`Claims`] or rejects with `401`
//! (`WWW-Authenticate: Bearer`).
//!
//! `alg=none` and any non-HS256 token are rejected by `jsonwebtoken`'s
//! [`Validation`] algorithm allowlist (P9 pen-test: `alg:none → 401`).

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::state::AppState;

/// Authenticated principal carried in the session JWT / minted from an API key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Subject - user id.
    pub sub: String,
    /// Tenant id (multi-tenancy boundary).
    pub tenant: String,
    /// License tier (`community` | `pro` | `enterprise`).
    pub tier: String,
    /// Granted feature flags (Cedar authorization input).
    pub features: Vec<String>,
    /// Expiry, unix seconds.
    pub exp: usize,
}

impl Claims {
    /// Whether the principal holds a feature (used by the Cedar gate).
    pub fn has_feature(&self, f: &str) -> bool {
        self.features.iter().any(|x| x == f)
    }
}

/// Mint a session JWT (HS256).
pub fn issue_jwt(secret: &str, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Verify and decode a session JWT. Only HS256 is accepted.
pub fn verify_jwt(secret: &str, token: &str) -> Result<Claims, &'static str> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|d| d.claims)
    .map_err(|_| "invalid_token")
}

/// SHA-256 hex of an API key, as stored in the DB (never the raw key).
pub fn hash_api_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Axum extractor: authenticate via `Authorization: Bearer <jwt>` first, then
/// `X-API-Key: <key>` (looked up by hash in the store). Missing/invalid → `401`.
pub struct Authenticated(pub Claims);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1) Bearer JWT.
        if let Some(value) = parts.headers.get(AUTHORIZATION) {
            let raw = value
                .to_str()
                .map_err(|_| ApiError::Unauthorized("invalid_token"))?;
            if let Some(token) = raw.strip_prefix("Bearer ") {
                let claims =
                    verify_jwt(&state.jwt_secret, token).map_err(ApiError::Unauthorized)?;
                return Ok(Authenticated(claims));
            }
        }
        // 2) API key.
        if let Some(value) = parts.headers.get("x-api-key") {
            let key = value
                .to_str()
                .map_err(|_| ApiError::Unauthorized("invalid_token"))?;
            let hashed = hash_api_key(key);
            match state
                .store
                .lookup_api_key(&hashed)
                .await
                .map_err(|e| ApiError::Store(e.to_string()))?
            {
                Some(claims) => return Ok(Authenticated(claims)),
                None => return Err(ApiError::Unauthorized("invalid_api_key")),
            }
        }
        Err(ApiError::Unauthorized("missing_credentials"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn claims() -> Claims {
        Claims {
            sub: "u1".into(),
            tenant: "t1".into(),
            tier: "pro".into(),
            features: vec!["scans".into()],
            exp: 9_999_999_999,
        }
    }

    #[test]
    fn jwt_round_trips() {
        let tok = issue_jwt("secret", &claims()).unwrap();
        let got = verify_jwt("secret", &tok).unwrap();
        assert_eq!(got, claims());
    }

    #[test]
    fn jwt_wrong_secret_rejected() {
        let tok = issue_jwt("secret", &claims()).unwrap();
        assert_eq!(verify_jwt("other", &tok), Err("invalid_token"));
    }

    #[test]
    fn jwt_alg_none_rejected() {
        // A hand-built `alg:none` token must not validate under HS256.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"sub":"admin","tenant":"t","tier":"enterprise","features":[],"exp":9999999999}"#,
        );
        let forged = format!("{header}.{payload}.");
        assert_eq!(verify_jwt("secret", &forged), Err("invalid_token"));
    }

    #[test]
    fn api_key_hash_is_stable_and_not_plaintext() {
        let h = hash_api_key("sk_live_abc");
        assert_eq!(h, hash_api_key("sk_live_abc"));
        assert_ne!(h, "sk_live_abc");
        assert_eq!(h.len(), 64);
    }
}
