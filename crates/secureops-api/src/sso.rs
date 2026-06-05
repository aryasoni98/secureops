//! **OIDC SSO** (PRODUCT.md Phase 8). The metadata endpoint is Cedar-gated on
//! the `sso` feature (Enterprise); the callback verifies an IdP token through a
//! pluggable [`OidcVerifier`] and mints a SecureOps session JWT.
//!
//! Real IdP integration (Okta/Azure AD/Google: JWKS fetch + token-endpoint
//! exchange via reqwest) plugs in behind the [`OidcVerifier`] trait. A mock
//! verifier keeps the login flow testable offline.

use async_trait::async_trait;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{issue_jwt, Claims};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Identity returned by the IdP after verification.
#[derive(Debug, Clone)]
pub struct OidcClaims {
    pub sub: String,
    pub email: String,
    pub tenant: String,
    pub tier: String,
    pub features: Vec<String>,
}

/// Verifies an IdP token (id_token / code) and resolves it to [`OidcClaims`].
#[async_trait]
pub trait OidcVerifier: Send + Sync {
    async fn verify(&self, token: &str) -> Option<OidcClaims>;
}

/// `GET /api/v1/auth/oidc/metadata` — SP metadata. Gated on the `sso` feature.
pub async fn oidc_metadata(
    State(s): State<AppState>,
    crate::auth::Authenticated(claims): crate::auth::Authenticated,
) -> ApiResult<Json<Value>> {
    if !s.authz.allows(&claims.features, "sso") {
        return Err(ApiError::Forbidden("sso"));
    }
    Ok(Json(json!({
        "issuer": "secureops",
        "callback": "/api/v1/auth/oidc/callback",
        "responseTypes": ["code", "id_token"],
        "idps": ["okta", "azure_ad", "google"],
        "ssoConfigured": s.oidc.is_some(),
    })))
}

#[derive(Deserialize)]
pub struct CallbackReq {
    pub token: String,
}

/// `POST /api/v1/auth/oidc/callback` — exchange an IdP token for a session JWT.
/// Public (this *is* the login): `404` if SSO isn't configured, `401` if the
/// token doesn't verify.
pub async fn oidc_callback(
    State(s): State<AppState>,
    Json(req): Json<CallbackReq>,
) -> ApiResult<Json<Value>> {
    let verifier = s.oidc.as_ref().ok_or(ApiError::NotFound)?;
    let claims = verifier
        .verify(&req.token)
        .await
        .ok_or(ApiError::Unauthorized("invalid_oidc_token"))?;

    let exp = (time::OffsetDateTime::now_utc().unix_timestamp() + 3600) as usize;
    let session = Claims {
        sub: claims.sub,
        tenant: claims.tenant,
        tier: claims.tier,
        features: claims.features,
        exp,
    };
    let token =
        issue_jwt(&s.jwt_secret, &session).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(json!({ "token": token, "email": claims.email })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts the token `"valid"` for an Enterprise-with-sso principal.
    pub struct MockVerifier;
    #[async_trait]
    impl OidcVerifier for MockVerifier {
        async fn verify(&self, token: &str) -> Option<OidcClaims> {
            (token == "valid").then(|| OidcClaims {
                sub: "okta|user1".into(),
                email: "user1@corp.example".into(),
                tenant: "tenant_1".into(),
                tier: "enterprise".into(),
                features: vec!["sso".into()],
            })
        }
    }

    #[tokio::test]
    async fn mock_verifier_accepts_only_valid() {
        let v = MockVerifier;
        assert!(v.verify("valid").await.is_some());
        assert!(v.verify("nope").await.is_none());
    }
}
