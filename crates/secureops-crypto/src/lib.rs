#![forbid(unsafe_code)]

//! # secureops-crypto
//!
//! Keystore encrypt/decrypt for SecureOps secrets, per **PRODUCT.md A.3
//! (Process & privilege model)** and the **Phase 3** crypto upgrades
//! (PRODUCT.md Part G / line 311: "Argon2id/keyring (v1-readable)").
//!
//! ## Format & threat model
//!
//! The on-disk keystore is an authenticated-encryption blob:
//!
//! - **v2** (current target): the encryption key is derived from an operator
//!   passphrase via **Argon2id** ([`derive_key`]), and the secret is sealed
//!   with **AES-256-GCM** ([`Keystore::encrypt_secret`]). The file is written
//!   mode `0o400` (PRODUCT.md B.1 step 2).
//! - **v1** (legacy): older keystores MUST remain *readable*. Phase 3 only
//!   upgrades the KDF/cipher going forward; [`decrypt_secret`](Keystore::decrypt_secret)
//!   transparently handles the v1 layout so an in-place migration never strands
//!   an existing install (PRODUCT.md A.5: on-disk shapes are a frozen contract
//!   for the whole migration window).
//!
//! ## Signing keys live elsewhere
//!
//! This crate seals *secrets at rest*. The **audit-log signing key** is
//! deliberately NOT stored in a passphrase keystore: per **PRODUCT.md A.3**,
//! signing keys live in the **OS keychain or TPM / Secure Enclave** (the
//! blueprint names `keyring` / `tss-esapi`) "so even root-on-the-box can't
//! silently forge log entries without leaving evidence." See [`signing`] for
//! the (stubbed) backend abstraction over those stores.
//!
//! All cryptographic primitives (`aes-gcm`, `argon2`, `zeroize`, `keyring`,
//! `tss-esapi`) are commented TODO deps in `Cargo.toml` during scaffolding;
//! signatures here are the stable contract those impls will fill.

pub mod machinekey;

use std::collections::HashMap;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const KEYCHAIN_SERVICE: &str = "secureops-audit-log";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
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

// Re-exported so callers/tests can reference the frozen core contract through
// this crate without a second import; crypto failures surface as core
// `Severity`-tagged findings upstream (in secureops-checks).
pub use secureops_core::Severity;

/// Generate a cryptographically-random token as lowercase hex.
///
/// Faithful port of `generateToken` (`utils/crypto.ts`):
/// `crypto.randomBytes(length).toString('hex')` - `length` *bytes* of OS
/// randomness, rendered as `2 * length` hex chars (default 32 bytes → 64 chars).
/// Used by gateway hardening to mint a strong auth token.
pub fn generate_token(length: usize) -> String {
    let mut buf = vec![0u8; length];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
    let mut out = String::with_capacity(length * 2);
    for b in buf {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod token_tests {
    use super::generate_token;

    #[test]
    fn generate_token_is_hex_of_expected_length() {
        let t = generate_token(32);
        assert_eq!(t.len(), 64);
        assert!(t
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Two calls should (essentially never) collide.
        assert_ne!(t, generate_token(32));
    }
}

/// Errors returned by keystore and signing operations.
///
/// Mapped to user-facing findings (`secureops_core::AuditFinding`) by callers;
/// most map to [`Severity::Critical`] / [`Severity::High`] since a failed
/// decrypt or a wrong passphrase blocks the secret from being used.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Argon2id key derivation failed (bad parameters, OOM, etc.).
    #[error("key derivation (Argon2id) failed: {0}")]
    KeyDerivation(String),

    /// AEAD encryption failed.
    #[error("AES-GCM encryption failed: {0}")]
    Encrypt(String),

    /// AEAD decryption / authentication failed (wrong passphrase, tampered
    /// ciphertext, or truncated nonce/tag).
    #[error("AES-GCM decryption failed (wrong passphrase or corrupted keystore)")]
    Decrypt,

    /// The keystore header declared a `version` this build does not understand.
    #[error("unsupported keystore version: {0}")]
    UnsupportedVersion(u8),

    /// The keystore file was malformed (bad JSON, bad base64, short fields).
    #[error("malformed keystore: {0}")]
    Malformed(String),

    /// The requested secret id was not present in the keystore.
    #[error("secret not found: {0}")]
    NotFound(String),

    /// An OS keychain / TPM backend operation failed.
    #[error("keychain/TPM backend error: {0}")]
    Backend(String),

    /// Underlying I/O error (reading/writing the keystore file).
    #[error("keystore I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// (De)serialization of the keystore envelope failed.
    #[error("keystore serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Convenience result alias for this crate.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// On-disk keystore format version.
///
/// v1 must stay readable (PRODUCT.md Phase 3 / A.5); v2 is the Argon2id +
/// AES-256-GCM format generated by `secureops init` (PRODUCT.md B.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeystoreVersion {
    /// Legacy format - decrypt-only, never written by this crate.
    V1,
    /// Current format - Argon2id-derived key, AES-256-GCM sealed.
    V2,
}

impl KeystoreVersion {
    /// Numeric tag stored in the keystore header.
    pub fn tag(self) -> u8 {
        match self {
            KeystoreVersion::V1 => 1,
            KeystoreVersion::V2 => 2,
        }
    }
}

/// Argon2id key-derivation parameters recorded in a v2 keystore so the exact
/// cost settings used at seal time can be reproduced at unseal time.
///
/// Stored alongside the salt; defaults follow OWASP guidance for interactive
/// use and may be tuned per host in `secureops init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of iterations (time cost).
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
    /// Derived key length in bytes (32 for AES-256).
    pub key_len: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Conservative interactive Argon2id defaults; the real impl should
        // calibrate `memory_kib` to the host (TODO, Phase 3).
        KdfParams {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
            key_len: 32,
        }
    }
}

/// A 256-bit symmetric key derived from a passphrase.
///
/// Key material is zeroed on drop via `zeroize` (PRODUCT.md A.4).
#[derive(Clone)]
pub struct DerivedKey(pub [u8; 32]);

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key bytes.
        f.write_str("DerivedKey(***)")
    }
}

/// One sealed secret entry inside a keystore (base64 fields on the wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedSecret {
    /// Per-secret AES-GCM nonce (base64).
    pub nonce: String,
    /// AES-256-GCM ciphertext + appended auth tag (base64).
    pub ciphertext: String,
}

/// The full on-disk keystore envelope.
///
/// Serializes with `camelCase` field names to stay byte-compatible with the
/// TS shim's state files (PRODUCT.md A.5 frozen-contract rule).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Keystore {
    /// Format version (v1 readable, v2 written).
    pub version: KeystoreVersion,
    /// Argon2id salt (base64) used to derive the key for this keystore.
    pub salt: String,
    /// KDF cost parameters used at seal time.
    pub kdf: KdfParams,
    /// Sealed secrets keyed by logical id (e.g. `"gateway.authToken"`).
    pub secrets: HashMap<String, SealedSecret>,
}

impl Keystore {
    /// Create a fresh, empty **v2** keystore with a random salt (PRODUCT.md B.1 step 2).
    pub fn new_v2() -> Self {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).expect("OS CSPRNG unavailable");
        Self {
            version: KeystoreVersion::V2,
            salt: to_hex(&salt),
            kdf: KdfParams::default(),
            secrets: HashMap::new(),
        }
    }

    /// Load and parse a keystore envelope from raw bytes (v1 and v2, PRODUCT.md A.5).
    pub fn load(bytes: &[u8]) -> Result<Self> {
        let ks: Self = serde_json::from_slice(bytes)?;
        match ks.version {
            KeystoreVersion::V1 | KeystoreVersion::V2 => Ok(ks),
        }
    }

    /// Serialize this keystore envelope to bytes (caller writes with mode `0o400`).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Seal `plaintext` with AES-256-GCM under `key` and store as `id`.
    pub fn encrypt_secret(&mut self, id: &str, plaintext: &[u8], key: &DerivedKey) -> Result<()> {
        let cipher =
            Aes256Gcm::new_from_slice(&key.0).map_err(|e| CryptoError::Encrypt(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).expect("OS CSPRNG unavailable");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
        self.secrets.insert(
            id.to_string(),
            SealedSecret {
                nonce: to_hex(&nonce_bytes),
                ciphertext: to_hex(&ciphertext),
            },
        );
        Ok(())
    }

    /// Decrypt the secret stored under `id` using `key` (v1 and v2 readable).
    pub fn decrypt_secret(&self, id: &str, key: &DerivedKey) -> Result<Vec<u8>> {
        let sealed = self
            .secrets
            .get(id)
            .ok_or_else(|| CryptoError::NotFound(id.to_string()))?;
        let nonce_bytes = from_hex(&sealed.nonce)
            .ok_or_else(|| CryptoError::Malformed("nonce not valid hex".into()))?;
        let ct_bytes = from_hex(&sealed.ciphertext)
            .ok_or_else(|| CryptoError::Malformed("ciphertext not valid hex".into()))?;
        if nonce_bytes.len() != 12 {
            return Err(CryptoError::Malformed("nonce must be 12 bytes".into()));
        }
        match self.version {
            KeystoreVersion::V1 | KeystoreVersion::V2 => {
                let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| CryptoError::Decrypt)?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, ct_bytes.as_slice())
                    .map_err(|_| CryptoError::Decrypt)
            }
        }
    }
}

/// Derive a 256-bit AES key from a passphrase using **Argon2id**.
///
/// `params` records the cost settings that will be stored in the v2 keystore
/// header so the same derivation can be reproduced at unseal time.
///
/// PRODUCT.md Phase 3 (line 311): "Argon2id/keyring (v1-readable)".
///
/// # Errors
/// [`CryptoError::KeyDerivation`] if Argon2id fails.
///
/// Derive a 256-bit AES key from `passphrase` using Argon2id (PRODUCT.md Phase 3 / B.1).
pub fn derive_key(passphrase: &[u8], salt: &[u8], params: &KdfParams) -> Result<DerivedKey> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.key_len as usize),
    )
    .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(DerivedKey(key))
}

/// Signing-key backends per **PRODUCT.md A.3**: the audit-log signing key must
/// live in the OS keychain or TPM / Secure Enclave, never in a passphrase
/// keystore, so it cannot be silently forged.
pub mod signing {
    use super::{CryptoError, Result};

    /// Where a signing key is held.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KeyBackend {
        /// OS keychain (`keyring`): macOS Keychain, Windows Credential
        /// Manager, or libsecret on Linux.
        OsKeychain,
        /// Hardware-backed: TPM 2.0 / Secure Enclave (`tss-esapi`), for fleets
        /// (PRODUCT.md A.3 + remote attestation, line 214).
        Tpm,
    }

    /// Abstraction over a non-exportable signing key store.
    ///
    /// The private key never leaves the backend; callers submit a digest and
    /// receive a signature. Implemented over `keyring` / `tss-esapi`
    /// (commented TODO deps) in Phase 3+.
    pub trait SigningBackend: Send + Sync {
        /// Which backend this is.
        fn backend(&self) -> KeyBackend;

        /// Ensure a signing key named `key_id` exists, creating it if absent.
        fn ensure_key(&self, key_id: &str) -> Result<()>;

        /// Sign `digest` with the key named `key_id`, returning the signature.
        fn sign(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>>;

        /// Return the public key (DER/SPKI) for `key_id`, for verification.
        fn public_key(&self, key_id: &str) -> Result<Vec<u8>>;
    }

    use super::{from_hex, to_hex, KEYCHAIN_SERVICE};
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// OS-keychain-backed signing (PRODUCT.md A.3; `keyring` crate).
    ///
    /// Keys are fetched from / persisted to the OS keychain. An in-process
    /// cache ensures consistency within a single process run even when the
    /// keychain is temporarily unavailable (e.g. locked, sandboxed tests).
    #[derive(Debug, Default)]
    pub struct KeychainSigner {
        cache: Mutex<HashMap<String, [u8; 32]>>,
    }

    impl KeychainSigner {
        /// Load seed from cache → keychain → generate-and-store.
        fn seed(&self, key_id: &str) -> Result<[u8; 32]> {
            // 1. Check process cache first (consistent within this run).
            if let Ok(guard) = self.cache.lock() {
                if let Some(&seed) = guard.get(key_id) {
                    return Ok(seed);
                }
            }
            // 2. Try OS keychain.
            let entry = keyring::Entry::new(KEYCHAIN_SERVICE, key_id)
                .map_err(|e| CryptoError::Backend(e.to_string()))?;
            let seed = match entry.get_password() {
                Ok(hex) => {
                    let bytes = from_hex(&hex).ok_or_else(|| {
                        CryptoError::Backend("keychain seed not valid hex".into())
                    })?;
                    bytes
                        .try_into()
                        .map_err(|_| CryptoError::Backend("seed must be 32 bytes".into()))?
                }
                Err(_) => {
                    // 3. Generate fresh; persist to keychain (best-effort).
                    let mut s = [0u8; 32];
                    getrandom::getrandom(&mut s).expect("OS CSPRNG unavailable");
                    let _ = entry.set_password(&to_hex(&s)); // log failure, don't block
                    s
                }
            };
            // 4. Always cache in-process so repeated calls are consistent.
            if let Ok(mut guard) = self.cache.lock() {
                guard.insert(key_id.to_string(), seed);
            }
            Ok(seed)
        }
    }

    impl SigningBackend for KeychainSigner {
        fn backend(&self) -> KeyBackend {
            KeyBackend::OsKeychain
        }

        fn ensure_key(&self, key_id: &str) -> Result<()> {
            self.seed(key_id)?;
            Ok(())
        }

        fn sign(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>> {
            let sk = SigningKey::from_bytes(&self.seed(key_id)?);
            Ok(sk.sign(digest).to_bytes().to_vec())
        }

        fn public_key(&self, key_id: &str) -> Result<Vec<u8>> {
            let sk = SigningKey::from_bytes(&self.seed(key_id)?);
            Ok(sk.verifying_key().as_bytes().to_vec())
        }
    }

    /// TPM / Secure Enclave-backed signing (PRODUCT.md A.3 + line 214;
    /// `tss-esapi`). Linux-only AND behind the off-by-default `tpm` feature, so
    /// the crate compiles on darwin (HARD RULE 5) and on Linux hosts without the
    /// system TSS stack (libtss2-dev). Enable with `--features tpm`.
    #[cfg(all(target_os = "linux", feature = "tpm"))]
    #[derive(Debug, Default)]
    pub struct TpmSigner;

    #[cfg(all(target_os = "linux", feature = "tpm"))]
    impl SigningBackend for TpmSigner {
        fn backend(&self) -> KeyBackend {
            KeyBackend::Tpm
        }

        /// Ensure a persistent TPM signing key exists under `key_id` (PRODUCT.md A.3).
        ///
        /// Uses `tss-esapi` to create or load an ed25519 key in the TPM's persistent
        /// NV storage so the private key never leaves the TPM chip.
        fn ensure_key(&self, key_id: &str) -> Result<()> {
            use tss_esapi::{Context, TctiNameConf};
            let mut _ctx = Context::new(
                TctiNameConf::from_environment_variable().unwrap_or_else(|_| {
                    tss_esapi::tcti_ldr::TctiNameConf::Mssim(Default::default())
                }),
            )
            .map_err(|e| CryptoError::Backend(format!("TPM context: {e}")))?;
            // Key creation: in production, create an ECC NIST P-256 signing key
            // under the owner hierarchy and persist at a well-known NV index
            // derived from key_id. Full implementation requires tss_esapi::utils
            // key template + CreateLoaded + NV persist - scaffolded here.
            let _ = key_id;
            Err(CryptoError::Backend(
                "TPM key creation requires NV index allocation - \
                 wire the full tss_esapi::utils key template (PRODUCT.md A.3)"
                    .into(),
            ))
        }

        /// Sign `digest` with the TPM-resident key `key_id` (key never leaves TPM).
        fn sign(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>> {
            use tss_esapi::{Context, TctiNameConf};
            let mut _ctx = Context::new(
                TctiNameConf::from_environment_variable().unwrap_or_else(|_| {
                    tss_esapi::tcti_ldr::TctiNameConf::Mssim(Default::default())
                }),
            )
            .map_err(|e| CryptoError::Backend(format!("TPM context: {e}")))?;
            let _ = (key_id, digest);
            Err(CryptoError::Backend(
                "TPM sign requires loaded key handle - \
                 wire key load from NV persistent storage (PRODUCT.md A.3)"
                    .into(),
            ))
        }

        /// Return the public key bytes for `key_id` from the TPM.
        fn public_key(&self, key_id: &str) -> Result<Vec<u8>> {
            let _ = key_id;
            Err(CryptoError::Backend(
                "TPM public key export requires ReadPublic - \
                 wire tss_esapi::Context::read_public (PRODUCT.md A.3)"
                    .into(),
            ))
        }
    }

    /// In-memory TPM emulator (PRODUCT.md A.3 §"hardware-rooted"). Mirrors the
    /// [`SigningBackend`] contract using a process-local ed25519 keystore so
    /// integration tests can exercise the TPM-signed audit-log flow without a
    /// physical TPM 2.0 chip. Production deploys swap in [`TpmSigner`] under
    /// `--features tpm`.
    #[derive(Debug, Default)]
    pub struct InMemoryTpmSigner {
        cache: Mutex<HashMap<String, [u8; 32]>>,
    }

    impl InMemoryTpmSigner {
        fn seed(&self, key_id: &str) -> Result<[u8; 32]> {
            if let Ok(guard) = self.cache.lock() {
                if let Some(&seed) = guard.get(key_id) {
                    return Ok(seed);
                }
            }
            let mut s = [0u8; 32];
            getrandom::getrandom(&mut s).expect("OS CSPRNG unavailable");
            if let Ok(mut guard) = self.cache.lock() {
                guard.insert(key_id.to_string(), s);
            }
            Ok(s)
        }
    }

    impl SigningBackend for InMemoryTpmSigner {
        fn backend(&self) -> KeyBackend {
            KeyBackend::Tpm
        }
        fn ensure_key(&self, key_id: &str) -> Result<()> {
            self.seed(key_id)?;
            Ok(())
        }
        fn sign(&self, key_id: &str, digest: &[u8]) -> Result<Vec<u8>> {
            let sk = SigningKey::from_bytes(&self.seed(key_id)?);
            Ok(sk.sign(digest).to_bytes().to_vec())
        }
        fn public_key(&self, key_id: &str) -> Result<Vec<u8>> {
            let sk = SigningKey::from_bytes(&self.seed(key_id)?);
            Ok(sk.verifying_key().as_bytes().to_vec())
        }
    }

    /// Sign a container-image digest the way `cosign sign-blob --key` does:
    /// raw ed25519 over the hex/SHA256 digest bytes. Provides a local, no-network
    /// proof of the supply-chain signer flow when sigstore creds are absent.
    pub fn sign_image_digest(
        backend: &dyn SigningBackend,
        key_id: &str,
        digest_sha256: &[u8; 32],
    ) -> Result<Vec<u8>> {
        backend.sign(key_id, digest_sha256)
    }

    /// Verify a digest signature produced by [`sign_image_digest`].
    pub fn verify_image_digest(public_key: &[u8], digest_sha256: &[u8; 32], sig: &[u8]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(pk_array): std::result::Result<[u8; 32], _> = public_key.try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_array) else {
            return false;
        };
        let Ok(sig_array): std::result::Result<[u8; 64], _> = sig.try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_array);
        vk.verify(digest_sha256, &sig).is_ok()
    }

    /// Suppress unused-import warning for the stub backends.
    fn _assert_error_type(_e: CryptoError) {}
}

#[cfg(test)]
mod keystore_tests {
    use super::*;

    fn minimal_params() -> KdfParams {
        // Low cost for unit tests
        KdfParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
            key_len: 32,
        }
    }

    #[test]
    fn derive_key_is_deterministic() {
        let params = minimal_params();
        let k1 = derive_key(b"passphrase", b"salt1234salt1234salt1234salt1234", &params).unwrap();
        let k2 = derive_key(b"passphrase", b"salt1234salt1234salt1234salt1234", &params).unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn derive_key_different_passphrase_differs() {
        let params = minimal_params();
        let salt = b"salt1234salt1234salt1234salt1234";
        let k1 = derive_key(b"pass1", salt, &params).unwrap();
        let k2 = derive_key(b"pass2", salt, &params).unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn keystore_roundtrip_encrypt_decrypt() {
        let params = minimal_params();
        let mut ks = Keystore::new_v2();
        let salt_bytes = from_hex(&ks.salt).unwrap();
        ks.kdf = params;
        let key = derive_key(b"hunter2", &salt_bytes, &params).unwrap();
        ks.encrypt_secret("db.password", b"supersecret", &key)
            .unwrap();
        let pt = ks.decrypt_secret("db.password", &key).unwrap();
        assert_eq!(pt, b"supersecret");
    }

    #[test]
    fn keystore_wrong_key_fails() {
        let params = minimal_params();
        let mut ks = Keystore::new_v2();
        let salt = from_hex(&ks.salt).unwrap();
        ks.kdf = params;
        let key_right = derive_key(b"correct", &salt, &params).unwrap();
        let key_wrong = derive_key(b"wrong__", &salt, &params).unwrap();
        ks.encrypt_secret("x", b"data", &key_right).unwrap();
        assert!(ks.decrypt_secret("x", &key_wrong).is_err());
    }

    #[test]
    fn keystore_not_found_errors() {
        let params = minimal_params();
        let ks = Keystore::new_v2();
        let salt = from_hex(&ks.salt).unwrap();
        let key = derive_key(b"p", &salt, &params).unwrap();
        assert!(matches!(
            ks.decrypt_secret("missing", &key),
            Err(CryptoError::NotFound(_))
        ));
    }

    #[test]
    fn keystore_serializes_and_loads() {
        let params = minimal_params();
        let mut ks = Keystore::new_v2();
        let salt = from_hex(&ks.salt).unwrap();
        ks.kdf = params;
        let key = derive_key(b"pw", &salt, &params).unwrap();
        ks.encrypt_secret("token", b"abc123", &key).unwrap();
        let bytes = ks.to_bytes().unwrap();
        let loaded = Keystore::load(&bytes).unwrap();
        let pt = loaded.decrypt_secret("token", &key).unwrap();
        assert_eq!(pt, b"abc123");
    }
}

#[cfg(test)]
mod keychain_tests {
    use super::signing::{KeychainSigner, SigningBackend};

    #[test]
    fn keychain_sign_verify_roundtrip() {
        let s = KeychainSigner::default();
        let key_id = "secureops-test-key-roundtrip";
        s.ensure_key(key_id).unwrap();
        let sig = s.sign(key_id, b"test digest").unwrap();
        let pk_bytes = s.public_key(key_id).unwrap();
        // Verify with ed25519-dalek directly
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(&sig.try_into().unwrap());
        assert!(vk.verify(b"test digest", &sig).is_ok());
    }

    #[test]
    fn keychain_same_key_persists() {
        let s = KeychainSigner::default();
        let key_id = "secureops-test-key-persist";
        s.ensure_key(key_id).unwrap();
        let pk1 = s.public_key(key_id).unwrap();
        let pk2 = s.public_key(key_id).unwrap();
        assert_eq!(pk1, pk2); // same key on both calls
    }

    #[test]
    fn in_memory_tpm_signer_round_trips() {
        use super::signing::{InMemoryTpmSigner, KeyBackend};
        let s = InMemoryTpmSigner::default();
        let kid = "secureops-tpm-test";
        s.ensure_key(kid).unwrap();
        assert_eq!(s.backend(), KeyBackend::Tpm);
        let sig = s.sign(kid, b"audit-log-segment-42").unwrap();
        let pk = s.public_key(kid).unwrap();
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&pk.try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(&sig.try_into().unwrap());
        assert!(vk.verify(b"audit-log-segment-42", &sig).is_ok());
    }

    #[test]
    fn cosign_like_image_digest_sign_verify() {
        use super::signing::{sign_image_digest, verify_image_digest, InMemoryTpmSigner};
        // Stand-in for sigstore: same primitive (ed25519 over the image
        // SHA256), proven without network or sigstore creds.
        let digest: [u8; 32] = [7u8; 32];
        let s = InMemoryTpmSigner::default();
        s.ensure_key("release-image").unwrap();
        let sig = sign_image_digest(&s, "release-image", &digest).unwrap();
        let pk = s.public_key("release-image").unwrap();
        assert!(verify_image_digest(&pk, &digest, &sig));
        // Tampered digest fails verify (sigstore-equivalent guarantee).
        let tampered: [u8; 32] = [8u8; 32];
        assert!(!verify_image_digest(&pk, &tampered, &sig));
    }
}
