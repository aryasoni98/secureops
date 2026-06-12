//! **S3/MinIO evidence presigning** (PRODUCT.md Phase 5: presigned PUT for
//! evidence upload, GET for snapshot restore).
//!
//! Implements AWS Signature V4 *query-string* presigning in pure Rust (HMAC-
//! SHA256) - no `aws-sdk` (which would drag `aws-lc-sys`/`cc >=1.1` and clash
//! with the workspace `cc <1.1` cap). Works against AWS S3 and MinIO (path-style).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// RFC3986 percent-encoding as required by SigV4. `encode_slash=false` keeps
/// `/` literal (used for the canonical URI path).
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// SigV4 presigner for an S3-compatible endpoint.
#[derive(Debug, Clone)]
pub struct S3Presigner {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    /// Endpoint host[:port] for path-style URLs (e.g. `minio:9000`).
    pub host: String,
    /// `https` or `http`.
    pub scheme: String,
}

impl S3Presigner {
    /// Presigner for a MinIO/S3 endpoint (path-style).
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        region: impl Into<String>,
        host: impl Into<String>,
        scheme: impl Into<String>,
    ) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            region: region.into(),
            host: host.into(),
            scheme: scheme.into(),
        }
    }

    /// Low-level presign for an explicit `host` + `canonical_uri` (path). `method`
    /// is `GET`/`PUT`; `amz_date` is `YYYYMMDDTHHMMSSZ` (caller supplies UTC now,
    /// or a fixed value for tests). Returns the full presigned URL.
    pub fn presign(
        &self,
        method: &str,
        host: &str,
        canonical_uri: &str,
        expires_secs: u32,
        amz_date: &str,
    ) -> String {
        let date = &amz_date[..8]; // YYYYMMDD
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let credential = format!("{}/{scope}", self.access_key);

        // Canonical (and final) query string: params sorted by key, encoded.
        let mut params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
            ("X-Amz-Credential", credential),
            ("X-Amz-Date", amz_date.to_string()),
            ("X-Amz-Expires", expires_secs.to_string()),
            ("X-Amz-SignedHeaders", "host".to_string()),
        ];
        params.sort_by(|a, b| a.0.cmp(b.0));
        let canonical_query = params
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
            .collect::<Vec<_>>()
            .join("&");

        let encoded_uri = uri_encode(canonical_uri, false);
        let canonical_request = format!(
            "{method}\n{encoded_uri}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let k_date = hmac(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

        format!(
            "{}://{host}{encoded_uri}?{canonical_query}&X-Amz-Signature={signature}",
            self.scheme
        )
    }

    /// Presign a path-style object URL on the configured endpoint:
    /// `{scheme}://{host}/{bucket}/{key}?...`.
    pub fn presign_path_style(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        expires_secs: u32,
        amz_date: &str,
    ) -> String {
        let uri = format!("/{bucket}/{key}");
        let host = self.host.clone();
        self.presign(method, &host, &uri, expires_secs, amz_date)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical AWS SigV4 example - "GET Object (using query parameters)" from
    /// the AWS docs. Verifies our signature byte-for-byte against AWS's published
    /// expected value, proving the algorithm is correct (not just deterministic).
    #[test]
    fn matches_aws_published_get_vector() {
        let p = S3Presigner::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "examplebucket.s3.amazonaws.com",
            "https",
        );
        let url = p.presign(
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            86400,
            "20130524T000000Z",
        );
        assert!(
            url.contains(
                "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "SigV4 signature mismatch vs AWS published vector: {url}"
        );
    }

    #[test]
    fn presigned_url_carries_all_required_params() {
        let p = S3Presigner::new("ak", "sk", "us-east-1", "minio:9000", "http");
        let url = p.presign_path_style("PUT", "secureops-t1", "ev/1.json", 900, "20260605T120000Z");
        assert!(url.starts_with("http://minio:9000/secureops-t1/ev/1.json?"));
        for must in [
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Credential=ak%2F20260605%2Fus-east-1%2Fs3%2Faws4_request",
            "X-Amz-Date=20260605T120000Z",
            "X-Amz-Expires=900",
            "X-Amz-SignedHeaders=host",
            "X-Amz-Signature=",
        ] {
            assert!(url.contains(must), "missing {must} in {url}");
        }
    }

    #[test]
    fn signature_is_deterministic_and_key_sensitive() {
        let a = S3Presigner::new("ak", "sk", "us-east-1", "minio:9000", "http");
        let b = S3Presigner::new("ak", "different", "us-east-1", "minio:9000", "http");
        let u1 = a.presign_path_style("GET", "b", "k", 60, "20260605T000000Z");
        let u2 = a.presign_path_style("GET", "b", "k", 60, "20260605T000000Z");
        let u3 = b.presign_path_style("GET", "b", "k", 60, "20260605T000000Z");
        assert_eq!(u1, u2, "same inputs must produce same URL");
        assert_ne!(u1, u3, "different secret must change the signature");
    }
}
