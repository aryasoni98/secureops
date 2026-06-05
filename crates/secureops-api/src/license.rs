//! **Ed25519 license keys** (PRODUCT.md §8 license-key system).
//!
//! A key is `base64url(payload_json) "." base64url(ed25519_sig)`. The payload is
//! the [`License`] claims; the signature is over the exact payload bytes, made
//! by the vendor signing key. [`verify`] checks the signature against the
//! embedded vendor public key, then enforces expiry — so a tampered key fails
//! with `invalid_signature` and a stale key with `license_expired`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Commercial tier a license unlocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Community,
    Pro,
    Enterprise,
}

/// Decoded, verified license claims (PRODUCT.md §8 fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct License {
    pub lic_id: String,
    pub tenant_id: String,
    pub tier: Tier,
    pub seats: u32,
    pub features: Vec<String>,
    /// Issued-at, unix seconds.
    pub issued: i64,
    /// Hard expiry, unix seconds.
    pub expiry: i64,
    /// `"online" | "offline"` enforcement mode.
    pub mode: String,
    /// Grace period after `expiry` before features hard-lock.
    pub grace_days: u32,
}

impl License {
    /// `true` once `now_unix` is past `expiry`.
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix > self.expiry
    }

    /// Whether the license grants a named feature (Cedar gate input).
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

fn engine() -> base64::engine::general_purpose::GeneralPurpose {
    URL_SAFE_NO_PAD
}

/// Verify a license key against the vendor public key and check expiry.
///
/// Error codes (returned to clients as the `error` field): `malformed_key`,
/// `bad_pubkey`, `invalid_signature`, `malformed_payload`, `license_expired`.
pub fn verify(key: &str, pubkey: &[u8; 32], now_unix: i64) -> Result<License, &'static str> {
    let (payload_b64, sig_b64) = key.split_once('.').ok_or("malformed_key")?;
    let payload = engine().decode(payload_b64).map_err(|_| "malformed_key")?;
    let sig_bytes = engine().decode(sig_b64).map_err(|_| "malformed_key")?;

    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| "bad_pubkey")?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "invalid_signature")?;
    vk.verify(&payload, &sig).map_err(|_| "invalid_signature")?;

    let lic: License = serde_json::from_slice(&payload).map_err(|_| "malformed_payload")?;
    if lic.is_expired_at(now_unix) {
        return Err("license_expired");
    }
    Ok(lic)
}

/// Sign a license into a key string (vendor/license-server side; used in tests).
pub fn sign(lic: &License, signing_key: &SigningKey) -> String {
    let payload = serde_json::to_vec(lic).expect("license serializes");
    let sig = signing_key.sign(&payload);
    format!(
        "{}.{}",
        engine().encode(&payload),
        engine().encode(sig.to_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pair() -> (SigningKey, [u8; 32]) {
        // Deterministic test seed — no RNG dependency.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sample(expiry: i64) -> License {
        License {
            lic_id: "lic_1".into(),
            tenant_id: "tenant_1".into(),
            tier: Tier::Pro,
            seats: 5,
            features: vec!["bughunt".into(), "scans".into()],
            issued: 1_000,
            expiry,
            mode: "online".into(),
            grace_days: 7,
        }
    }

    #[test]
    fn valid_key_verifies_and_decodes() {
        let (sk, pk) = key_pair();
        let key = sign(&sample(10_000), &sk);
        let lic = verify(&key, &pk, 5_000).expect("valid");
        assert_eq!(lic.tenant_id, "tenant_1");
        assert_eq!(lic.tier, Tier::Pro);
        assert!(lic.has_feature("bughunt"));
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let (sk, pk) = key_pair();
        let key = sign(&sample(10_000), &sk);
        // Flip a byte in the payload segment.
        let (payload, sig) = key.split_once('.').unwrap();
        let mut p = payload.to_string();
        p.push('A'); // corrupt
        let tampered = format!("{p}.{sig}");
        assert_eq!(verify(&tampered, &pk, 5_000), Err("invalid_signature"));
    }

    #[test]
    fn expired_key_is_rejected() {
        let (sk, pk) = key_pair();
        let key = sign(&sample(1_000), &sk);
        assert_eq!(verify(&key, &pk, 5_000), Err("license_expired"));
    }

    #[test]
    fn wrong_pubkey_fails_signature() {
        let (sk, _pk) = key_pair();
        let other = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let key = sign(&sample(10_000), &sk);
        assert_eq!(verify(&key, &other, 5_000), Err("invalid_signature"));
    }
}
