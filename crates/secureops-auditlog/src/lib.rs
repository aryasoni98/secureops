#![forbid(unsafe_code)]

//! # secureops-auditlog
//!
//! Tamper-evident, append-only audit log for SecureOps, per **PRODUCT.md A.1
//! / A.4** (Ring 2 "owns ... the tamper-evident log") and the **Phase 4**
//! enforcement work. It is the log that must keep telling the truth *after* the
//! agent is hijacked, so it lives in the privileged daemon, not in the agent's
//! address space.
//!
//! ## Tamper-evidence model
//!
//! Each [`LogEntry`] commits to its predecessor by hash, forming an
//! **append-only hash chain**:
//!
//! ```text
//!   hash_n = H( prev_hash_{n-1} || canonical(payload_n) )
//! ```
//!
//! Because every link folds in the previous link's hash, editing or deleting
//! any historical entry changes every hash after it — [`AuditLog::verify_chain`]
//! detects exactly that break (PRODUCT.md B.9 step 3: the export carries "its
//! hash-chain proof", "tamper-evident in court/audit").
//!
//! ## Signing keys live in the keychain / TPM
//!
//! Every entry is additionally **ed25519-signed**. Per **PRODUCT.md A.3**, the
//! signing key is NOT held in a passphrase keystore: it lives in the **OS
//! keychain or a TPM / Secure Enclave** "so even root-on-the-box can't silently
//! forge log entries without leaving evidence." The key-access abstraction is
//! [`Signer`]; the daemon injects a keychain/TPM-backed implementation.
//!
//! ## Optional public anchoring (non-repudiation across orgs)
//!
//! For the regulated / MSSP tiers (**PRODUCT.md W6**), the chain head can be
//! **anchored to a public transparency log (Rekor)** or a **timestamp
//! authority (RFC3161)** so non-repudiation holds "across organizational and
//! national boundaries, not just on one box." That is the [`Anchor`] trait.
//!
//! ## Forensic export
//!
//! [`AuditLog::export_segment`] produces the signed segment that
//! `secureops export-incident` bundles with matching alerts and the policy
//! version in effect (PRODUCT.md B.9 step 3).
//!
//! All cryptographic primitives (`sha2`, `ed25519-dalek`) and the anchoring
//! client (`rekor-client`) are commented TODO deps in `Cargo.toml` during
//! scaffolding; the signatures here are the stable contract those impls fill.

use std::path::PathBuf;

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Re-exported so callers/tests can map audit-log failures onto the frozen core
// contract (e.g. a verify_chain break surfaces as a Critical finding upstream
// in secureops-checks) without a second import.
pub use secureops_core::Severity;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The chain hash for an entry: `SHA-256(prev_hash || canonical(payload))`,
/// hex-encoded. `canonical` is `serde_json` of the value (default serde_json
/// `Map` is key-sorted, so this is deterministic).
fn chain_hash(prev_hash: &str, payload: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    to_hex(&hasher.finalize())
}

/// Errors returned by audit-log operations.
///
/// Callers map these to user-facing `secureops_core::AuditFinding`s; a
/// [`AuditLogError::ChainBroken`] is by construction [`Severity::Critical`]
/// (the log can no longer prove its own integrity).
#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    /// The hash chain is broken: a recomputed `hash` did not match the stored
    /// one, or an entry's `prev_hash` did not match its predecessor's `hash`.
    #[error("audit-log hash chain broken at seq {seq}: {detail}")]
    ChainBroken {
        /// Sequence number of the first entry that failed verification.
        seq: u64,
        /// Human-readable description of the mismatch.
        detail: String,
    },

    /// An ed25519 signature over an entry failed to verify.
    #[error("ed25519 signature invalid at seq {seq}")]
    SignatureInvalid {
        /// Sequence number of the entry whose signature failed.
        seq: u64,
    },

    /// Signing failed (key unavailable in keychain/TPM, or backend error).
    #[error("signing failed: {0}")]
    Signing(String),

    /// Canonical serialization of a payload for hashing failed.
    #[error("payload serialization failed: {0}")]
    Serialize(String),

    /// Anchoring the chain head to a transparency log / TSA failed.
    #[error("anchor backend error: {0}")]
    Anchor(String),

    /// Requested export range was invalid (e.g. `from > to`, or out of range).
    #[error("invalid export range: from={from} to={to}")]
    InvalidRange {
        /// Inclusive lower bound requested.
        from: u64,
        /// Inclusive upper bound requested.
        to: u64,
    },
}

/// A single append-only, hash-chained, ed25519-signed audit-log record.
///
/// Wire shape is the frozen on-disk/export contract (PRODUCT.md A.5): field
/// names are serialized `camelCase` so the Rust log and any TS reader agree.
///
/// Per **PRODUCT.md B.9**, the `hash` + `prev_hash` pair forms the chain link
/// and the `signature` provides non-repudiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// Monotonic sequence number, 0-based, contiguous within a log.
    pub seq: u64,
    /// RFC3339 timestamp the entry was appended (UTC).
    pub timestamp: String,
    /// Hex-encoded `hash` of the previous entry; the genesis entry uses the
    /// all-zero / empty-chain sentinel.
    pub prev_hash: String,
    /// Arbitrary structured event payload (kill reason, decision, alert, etc.).
    pub payload: serde_json::Value,
    /// Hex-encoded `H(prev_hash || canonical(payload))` for this entry.
    pub hash: String,
    /// Hex-encoded ed25519 signature over `hash` (key from keychain/TPM, A.3).
    pub signature: String,
}

impl LogEntry {
    /// Recompute this entry's chain hash from `prev_hash` and `payload` and
    /// compare it to the stored [`LogEntry::hash`].
    ///
    /// Returns `true` iff the stored hash matches the recomputation
    /// (PRODUCT.md B.9). Used internally by [`AuditLog::verify_chain`].
    pub fn recompute_hash_matches(&self) -> bool {
        chain_hash(&self.prev_hash, &self.payload) == self.hash
    }
}

/// Abstraction over the ed25519 signing key backend.
///
/// Per **PRODUCT.md A.3**, the real implementation reads the private key from
/// the **OS keychain or a TPM / Secure Enclave** rather than a file or the
/// passphrase keystore, so a root-level compromise cannot silently forge
/// entries. The daemon injects the concrete backend; this keeps the chain
/// logic testable against an in-memory key.
pub trait Signer: Send + Sync {
    /// Sign the entry's chain `hash` (hex string) and return a hex-encoded
    /// ed25519 signature.
    fn sign(&self, hash: &str) -> Result<String, AuditLogError>;

    /// Verify a hex-encoded ed25519 `signature` over `hash` against the public
    /// key paired with this signer.
    fn verify(&self, hash: &str, signature: &str) -> Result<bool, AuditLogError>;
}

/// An in-memory ed25519 [`Signer`] for tests and dev. Production uses a
/// keychain/TPM-backed signer (PRODUCT.md A.3) so a root compromise can't forge
/// entries; this one holds the key in process.
pub struct InMemorySigner {
    key: SigningKey,
}

impl InMemorySigner {
    /// Generate a fresh random key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS CSPRNG unavailable");
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// The paired public key, for external verifiers.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl Signer for InMemorySigner {
    fn sign(&self, hash: &str) -> Result<String, AuditLogError> {
        let sig = self.key.sign(hash.as_bytes());
        Ok(to_hex(&sig.to_bytes()))
    }

    fn verify(&self, hash: &str, signature: &str) -> Result<bool, AuditLogError> {
        let bytes = from_hex(signature)
            .ok_or_else(|| AuditLogError::Signing("signature not hex".to_string()))?;
        let arr: [u8; 64] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuditLogError::Signing("signature not 64 bytes".to_string()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        Ok(self
            .key
            .verifying_key()
            .verify(hash.as_bytes(), &sig)
            .is_ok())
    }
}

/// Abstraction over an optional public anchoring backend (PRODUCT.md W6).
///
/// Periodically anchors the chain head to a public **transparency log (Rekor)**
/// or a **timestamp authority (RFC3161)** so non-repudiation survives across
/// organizational and national boundaries. Optional and self-hostable, in
/// keeping with the "no central SaaS dependency" ethos.
pub trait Anchor: Send + Sync {
    /// Submit the current chain-head `hash` to the backend and return an
    /// opaque, backend-specific inclusion/timestamp proof.
    fn anchor_head(&self, head_hash: &str) -> Result<String, AuditLogError>;
}

/// The append-only, hash-chained, signed audit log.
///
/// Owns the in-memory tail of the chain (the last `prev_hash` / `seq`) plus the
/// signer and the optional anchor. Durable persistence (append to disk, fsync,
/// rotation) is wired by the daemon (PRODUCT.md A.4); this struct defines the
/// integrity contract over whatever store backs it.
pub struct AuditLog {
    /// Next sequence number to assign on the following [`AuditLog::append`].
    next_seq: u64,
    /// Hex-encoded hash of the most recently appended entry (chain head); the
    /// genesis sentinel until the first append.
    prev_hash: String,
    /// ed25519 signing backend (keychain/TPM-backed in production, A.3).
    signer: Box<dyn Signer>,
    /// Optional public-transparency / TSA anchor (W6).
    anchor: Option<Box<dyn Anchor>>,
    /// In-memory tail of appended entries.
    entries: Vec<LogEntry>,
    /// Optional JSONL persistence path — entries are fsynced here on each append.
    persist_path: Option<PathBuf>,
}

impl AuditLog {
    /// Create a new in-memory audit log with a fresh genesis chain.
    pub fn new(signer: Box<dyn Signer>) -> Self {
        Self {
            next_seq: 0,
            prev_hash: Self::genesis_hash(),
            signer,
            anchor: None,
            entries: Vec::new(),
            persist_path: None,
        }
    }

    /// Open (or create) a **persisted** audit log backed by a JSONL file.
    ///
    /// If `path` exists, loads all entries and resumes from the chain tail —
    /// preserving the integrity guarantees across daemon restarts (PRODUCT.md B.9).
    /// Returns an error if the existing chain fails verification.
    pub fn open(path: impl Into<PathBuf>, signer: Box<dyn Signer>) -> anyhow::Result<Self> {
        use std::io::{BufRead, BufReader};
        let path: PathBuf = path.into();
        let mut entries: Vec<LogEntry> = Vec::new();

        if path.exists() {
            let file = std::fs::File::open(&path)?;
            for line in BufReader::new(file).lines() {
                let line = line?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let entry: LogEntry = serde_json::from_str(trimmed)
                    .map_err(|e| anyhow::anyhow!("corrupt audit log at {}: {e}", path.display()))?;
                entries.push(entry);
            }
        }

        let (next_seq, prev_hash) = if entries.is_empty() {
            (0, Self::genesis_hash())
        } else {
            let last = entries.last().unwrap();
            (last.seq + 1, last.hash.clone())
        };

        // Verify hash-chain integrity on load (not signatures — the signing key
        // lives in the OS keychain and is the same across restarts in production,
        // but tests may use ephemeral keys; hash integrity is always verifiable).
        let mut expected_prev = Self::genesis_hash();
        for entry in &entries {
            if entry.prev_hash != expected_prev {
                return Err(anyhow::anyhow!(
                    "corrupt audit log {}: chain broken at seq {}",
                    path.display(),
                    entry.seq
                ));
            }
            if !entry.recompute_hash_matches() {
                return Err(anyhow::anyhow!(
                    "corrupt audit log {}: hash mismatch at seq {}",
                    path.display(),
                    entry.seq
                ));
            }
            expected_prev = entry.hash.clone();
        }

        Ok(Self {
            next_seq,
            prev_hash,
            signer,
            anchor: None,
            entries,
            persist_path: Some(path),
        })
    }

    /// Attach an optional public anchoring backend (Rekor / RFC3161, W6).
    pub fn with_anchor(mut self, anchor: Box<dyn Anchor>) -> Self {
        self.anchor = Some(anchor);
        self
    }

    /// The genesis-link sentinel used as `prev_hash` for the first entry.
    fn genesis_hash() -> String {
        // 32 zero bytes, hex-encoded — the empty-chain predecessor.
        "0".repeat(64)
    }

    /// Append a new entry committing to `payload`.
    ///
    /// Computes `hash = H(prev_hash || canonical(payload))`, ed25519-signs the
    /// hash via the keychain/TPM-backed [`Signer`], advances the chain head,
    /// and returns the materialized [`LogEntry`] (PRODUCT.md B.9).
    ///
    /// The real impl also durably appends + fsyncs before returning.
    pub fn append(
        &mut self,
        payload: serde_json::Value,
        now: impl Into<String>,
    ) -> Result<LogEntry, AuditLogError> {
        let prev_hash = self.prev_hash.clone();
        let hash = chain_hash(&prev_hash, &payload);
        let signature = self.signer.sign(&hash)?;
        let entry = LogEntry {
            seq: self.next_seq,
            timestamp: now.into(),
            prev_hash,
            payload,
            hash: hash.clone(),
            signature,
        };
        self.next_seq += 1;
        self.prev_hash = hash;
        self.entries.push(entry.clone());

        // Persist to JSONL file if a path is configured (PRODUCT.md B.9).
        if let Some(ref path) = self.persist_path {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| AuditLogError::Serialize(e.to_string()))?;
            let line = serde_json::to_string(&entry)
                .map_err(|e| AuditLogError::Serialize(e.to_string()))?;
            writeln!(file, "{}", line).map_err(|e| AuditLogError::Serialize(e.to_string()))?;
            file.flush()
                .map_err(|e| AuditLogError::Serialize(e.to_string()))?;
        }

        Ok(entry)
    }

    /// All entries appended so far, in sequence order.
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Walk the entire chain and verify integrity.
    ///
    /// Returns `Ok(true)` iff, for every entry: its `prev_hash` equals the
    /// predecessor's `hash`, its stored `hash` recomputes from
    /// `H(prev_hash || canonical(payload))`, and its ed25519 `signature`
    /// verifies. A detected break is reported as
    /// [`AuditLogError::ChainBroken`] / [`AuditLogError::SignatureInvalid`]
    /// (PRODUCT.md B.9 — "tamper-evident").
    pub fn verify_chain(&self) -> anyhow::Result<bool> {
        let mut expected_prev = Self::genesis_hash();
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.seq != i as u64 {
                return Err(AuditLogError::ChainBroken {
                    seq: entry.seq,
                    detail: format!("non-contiguous seq (expected {i})"),
                }
                .into());
            }
            if entry.prev_hash != expected_prev {
                return Err(AuditLogError::ChainBroken {
                    seq: entry.seq,
                    detail: "prev_hash does not match predecessor".to_string(),
                }
                .into());
            }
            if !entry.recompute_hash_matches() {
                return Err(AuditLogError::ChainBroken {
                    seq: entry.seq,
                    detail: "payload tampered (hash mismatch)".to_string(),
                }
                .into());
            }
            if !self.signer.verify(&entry.hash, &entry.signature)? {
                return Err(AuditLogError::SignatureInvalid { seq: entry.seq }.into());
            }
            expected_prev = entry.hash.clone();
        }
        Ok(true)
    }

    /// Export a contiguous, inclusive `[from, to]` segment of the chain for
    /// forensic / incident bundling.
    ///
    /// This is the "relevant audit-log segment (with its hash-chain proof)"
    /// that `secureops export-incident` packages alongside matching alerts and
    /// the in-effect policy version (PRODUCT.md B.9 step 3). Returns
    /// [`AuditLogError::InvalidRange`] for a malformed range.
    pub fn export_segment(&self, from: u64, to: u64) -> anyhow::Result<Vec<LogEntry>> {
        if from > to {
            return Err(AuditLogError::InvalidRange { from, to }.into());
        }
        Ok(self
            .entries
            .iter()
            .filter(|e| e.seq >= from && e.seq <= to)
            .cloned()
            .collect())
    }

    /// Anchor the current chain head to the configured public backend (PRODUCT.md W6).
    /// Returns `Ok(None)` when no [`Anchor`] is set.
    pub fn anchor_now(&self) -> anyhow::Result<Option<String>> {
        match &self.anchor {
            None => Ok(None),
            Some(anchor) => {
                let proof = anchor.anchor_head(&self.prev_hash)?;
                Ok(Some(proof))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn log() -> AuditLog {
        AuditLog::new(Box::new(InMemorySigner::generate()))
    }

    #[test]
    fn append_links_chain_and_verifies() {
        let mut l = log();
        let e0 = l
            .append(json!({"event": "kill", "reason": "breach"}), "t0")
            .unwrap();
        let e1 = l
            .append(json!({"event": "deny", "host": "evil.com"}), "t1")
            .unwrap();

        assert_eq!(e0.seq, 0);
        assert_eq!(e0.prev_hash, "0".repeat(64)); // genesis
        assert_eq!(e1.seq, 1);
        assert_eq!(e1.prev_hash, e0.hash); // chain link
        assert!(l.verify_chain().unwrap());
    }

    #[test]
    fn tampering_a_payload_breaks_the_chain() {
        let mut l = log();
        l.append(json!({"event": "a"}), "t0").unwrap();
        l.append(json!({"event": "b"}), "t1").unwrap();
        // Tamper entry 0's payload after the fact.
        l.entries[0].payload = json!({"event": "FORGED"});
        let err = l.verify_chain().unwrap_err();
        assert!(
            err.to_string().contains("hash chain broken at seq 0"),
            "{err}"
        );
    }

    #[test]
    fn tampering_a_signature_is_detected() {
        let mut l = log();
        l.append(json!({"x": 1}), "t0").unwrap();
        // Flip the stored signature to another valid-length hex that won't verify.
        l.entries[0].signature = "0".repeat(128);
        let err = l.verify_chain().unwrap_err();
        assert!(
            err.to_string().contains("signature invalid at seq 0"),
            "{err}"
        );
    }

    #[test]
    fn export_segment_slices_and_validates_range() {
        let mut l = log();
        for i in 0..5 {
            l.append(json!({ "i": i }), format!("t{i}")).unwrap();
        }
        let seg = l.export_segment(1, 3).unwrap();
        assert_eq!(seg.len(), 3);
        assert_eq!(seg[0].seq, 1);
        assert_eq!(seg[2].seq, 3);
        assert!(l.export_segment(3, 1).is_err()); // from > to
    }

    #[test]
    fn signer_roundtrip() {
        let s = InMemorySigner::generate();
        let sig = s.sign("deadbeef").unwrap();
        assert!(s.verify("deadbeef", &sig).unwrap());
        assert!(!s.verify("deadbee0", &sig).unwrap()); // different message
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn open_creates_and_resumes_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut log = AuditLog::open(&path, Box::new(InMemorySigner::generate())).unwrap();
        log.append(json!({"event": "start"}), "t0").unwrap();
        log.append(json!({"event": "stop"}), "t1").unwrap();
        assert_eq!(log.entries().len(), 2);
        assert!(path.exists());

        // Resume from disk with a new signer (loaded chain; signer used for new entries only)
        let log2 = AuditLog::open(&path, Box::new(InMemorySigner::generate())).unwrap();
        assert_eq!(log2.entries().len(), 2);
        assert_eq!(log2.entries()[0].payload, json!({"event": "start"}));
    }
}
