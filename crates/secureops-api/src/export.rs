//! **Signed incident-report export** (PRODUCT.md Phase 8): bundle findings + a
//! manifest into a ZIP and **Ed25519-sign** the contents, so a regulator can
//! verify the package is intact and authentic with the embedded vendor public
//! key. Uses stored (uncompressed) ZIP entries — no compression C deps.
//!
//! Bundle layout: `findings.json`, `manifest.json`, `signature.hex` (sig over
//! `findings.json ‖ manifest.json`), `pubkey.hex`.

use std::io::{Cursor, Read, Write};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn from_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("odd-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("hex: {e}")))
        .collect()
}

/// The signed bytes: `findings.json ‖ manifest.json`.
fn payload(findings_json: &str, manifest_json: &str) -> Vec<u8> {
    let mut v = findings_json.as_bytes().to_vec();
    v.extend_from_slice(manifest_json.as_bytes());
    v
}

/// Holds the server's Ed25519 signing key for incident-report exports.
pub struct IncidentExport {
    signing: SigningKey,
}

impl IncidentExport {
    /// Build from a 32-byte seed (production: from a Secret/keystore; dev: fixed).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The public key clients verify exports against.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Produce a signed ZIP bundle for the given findings + manifest JSON.
    pub fn build(&self, findings_json: &str, manifest_json: &str) -> anyhow::Result<Vec<u8>> {
        let sig = self.signing.sign(&payload(findings_json, manifest_json));
        let mut buf = Vec::new();
        {
            let mut zw = ZipWriter::new(Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zw.start_file("findings.json", opts)?;
            zw.write_all(findings_json.as_bytes())?;
            zw.start_file("manifest.json", opts)?;
            zw.write_all(manifest_json.as_bytes())?;
            zw.start_file("signature.hex", opts)?;
            zw.write_all(to_hex(&sig.to_bytes()).as_bytes())?;
            zw.start_file("pubkey.hex", opts)?;
            zw.write_all(to_hex(&self.public_key()).as_bytes())?;
            zw.finish()?;
        }
        Ok(buf)
    }

    /// Verify a bundle's signature against `expected_pubkey`. Returns `true` only
    /// if the signature over `findings.json ‖ manifest.json` checks out.
    pub fn verify(bytes: &[u8], expected_pubkey: &[u8; 32]) -> anyhow::Result<bool> {
        let mut zip = ZipArchive::new(Cursor::new(bytes))?;
        let findings = read_entry(&mut zip, "findings.json")?;
        let manifest = read_entry(&mut zip, "manifest.json")?;
        let sig_hex = read_entry(&mut zip, "signature.hex")?;
        let sig = Signature::from_slice(&from_hex(sig_hex.trim())?)?;
        let vk = VerifyingKey::from_bytes(expected_pubkey)?;
        Ok(vk.verify(&payload(&findings, &manifest), &sig).is_ok())
    }
}

fn read_entry(zip: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> anyhow::Result<String> {
    let mut f = zip.by_name(name)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_bundle_verifies() {
        let ex = IncidentExport::from_seed([9u8; 32]);
        let zip = ex
            .build(
                r#"[{"id":"f1","severity":"high"}]"#,
                r#"{"framework":"cis"}"#,
            )
            .unwrap();
        assert!(IncidentExport::verify(&zip, &ex.public_key()).unwrap());
    }

    #[test]
    fn wrong_pubkey_fails() {
        let ex = IncidentExport::from_seed([9u8; 32]);
        let other = IncidentExport::from_seed([1u8; 32]).public_key();
        let zip = ex.build("[]", "{}").unwrap();
        assert!(!IncidentExport::verify(&zip, &other).unwrap());
    }

    #[test]
    fn tampered_bundle_fails() {
        let ex = IncidentExport::from_seed([9u8; 32]);
        let zip = ex
            .build(r#"[{"id":"f1"}]"#, r#"{"framework":"cis"}"#)
            .unwrap();
        // Rebuild a bundle with different findings but the original signature.
        let mut archive = ZipArchive::new(Cursor::new(zip.as_slice())).unwrap();
        let sig = read_entry(&mut archive, "signature.hex").unwrap();
        let pk = read_entry(&mut archive, "pubkey.hex").unwrap();
        let mut buf = Vec::new();
        {
            let mut zw = ZipWriter::new(Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zw.start_file("findings.json", opts).unwrap();
            zw.write_all(br#"[{"id":"TAMPERED"}]"#).unwrap();
            zw.start_file("manifest.json", opts).unwrap();
            zw.write_all(br#"{"framework":"cis"}"#).unwrap();
            zw.start_file("signature.hex", opts).unwrap();
            zw.write_all(sig.as_bytes()).unwrap();
            zw.start_file("pubkey.hex", opts).unwrap();
            zw.write_all(pk.as_bytes()).unwrap();
            zw.finish().unwrap();
        }
        assert!(!IncidentExport::verify(&buf, &ex.public_key()).unwrap());
    }
}
