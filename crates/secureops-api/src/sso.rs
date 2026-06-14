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
    /// Coarse RBAC role (`admin` | `member`); defaults to `member`.
    pub role: String,
    pub features: Vec<String>,
}

/// Verifies an IdP token (id_token / code) and resolves it to [`OidcClaims`].
#[async_trait]
pub trait OidcVerifier: Send + Sync {
    async fn verify(&self, token: &str) -> Option<OidcClaims>;
}

/// `GET /api/v1/auth/oidc/metadata` - SP metadata. Gated on the `sso` feature.
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

/// `POST /api/v1/auth/oidc/callback` - exchange an IdP token for a session JWT.
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
        role: claims.role,
        features: claims.features,
        iss: crate::auth::ISSUER.into(),
        exp,
    };
    let token =
        issue_jwt(&s.jwt_secret, &session).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(json!({ "token": token, "email": claims.email })))
}

/// Map a validated IdP id_token payload to [`OidcClaims`] (pure). `tenant`/
/// `tier` come from custom claims when present, else defaults; `sub`/`email` are
/// standard OIDC claims; `features` from a `features` array claim.
pub fn map_oidc_claims(payload: &serde_json::Value, default_tenant: &str) -> OidcClaims {
    let features = payload["features"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    OidcClaims {
        sub: payload["sub"].as_str().unwrap_or("").to_string(),
        email: payload["email"].as_str().unwrap_or("").to_string(),
        tenant: payload["tenant"]
            .as_str()
            .unwrap_or(default_tenant)
            .to_string(),
        tier: payload["tier"].as_str().unwrap_or("community").to_string(),
        role: payload["role"].as_str().unwrap_or("member").to_string(),
        features,
    }
}

/// Real OIDC verifier (gated `live-oidc`): fetches the IdP JWKS, validates the
/// id_token (RS256 + audience) with `jsonwebtoken`, then maps the claims. Reuses
/// the workspace-locked reqwest + jsonwebtoken (no cc-cap bump).
#[cfg(feature = "live-oidc")]
pub struct HttpOidcVerifier {
    pub jwks_uri: String,
    pub audience: String,
    /// Expected `iss` claim - pin to your IdP's issuer URL so tokens minted by
    /// any other issuer (even with a matching `kid`/audience) are rejected.
    pub issuer: String,
    pub default_tenant: String,
}

#[cfg(feature = "live-oidc")]
#[async_trait]
impl OidcVerifier for HttpOidcVerifier {
    async fn verify(&self, token: &str) -> Option<OidcClaims> {
        let kid = jsonwebtoken::decode_header(token).ok()?.kid?;
        let jwks: serde_json::Value = reqwest::get(&self.jwks_uri).await.ok()?.json().await.ok()?;
        let key = jwks["keys"]
            .as_array()?
            .iter()
            .find(|k| k["kid"].as_str() == Some(&kid))?;
        let dk =
            jsonwebtoken::DecodingKey::from_rsa_components(key["n"].as_str()?, key["e"].as_str()?)
                .ok()?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);
        let data = jsonwebtoken::decode::<serde_json::Value>(token, &dk, &validation).ok()?;
        Some(map_oidc_claims(&data.claims, &self.default_tenant))
    }
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
                role: "member".into(),
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

    #[test]
    fn map_oidc_claims_reads_custom_then_defaults() {
        let full = json!({
            "sub": "okta|u", "email": "u@corp.example", "tenant": "acme",
            "tier": "pro", "features": ["sso", "bughunt"]
        });
        let c = map_oidc_claims(&full, "fallback");
        assert_eq!(c.sub, "okta|u");
        assert_eq!(c.tenant, "acme");
        assert_eq!(c.tier, "pro");
        assert!(c.features.contains(&"sso".to_string()));

        // Missing custom claims → defaults.
        let bare = json!({ "sub": "u", "email": "e@x" });
        let c = map_oidc_claims(&bare, "fallback");
        assert_eq!(c.tenant, "fallback");
        assert_eq!(c.tier, "community");
        assert!(c.features.is_empty());
    }
}
