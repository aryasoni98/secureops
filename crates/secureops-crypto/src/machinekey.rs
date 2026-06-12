//! Machine-keyed AES-256-GCM encryption - faithful port of `utils/crypto.ts`.
//!
//! Keys are derived from a machine id + state-dir path via PBKDF2-HMAC-SHA512
//! (100k iters). The on-disk byte layout is **identical to the TS tool** -
//! `salt(32) || iv(16) || authTag(16) || ciphertext` - so `.enc` files written
//! by either tool decrypt with the other (PRODUCT.md A.5 frozen on-disk shapes).

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use anyhow::{anyhow, Result};
use sha2::Sha512;
use std::path::{Path, PathBuf};

/// AES-256-GCM with a 16-byte nonce + 16-byte tag (matches node's `aes-256-gcm`
/// with `authTagLength: 16` and the TS 16-byte IV).
type Aes256Gcm16 = AesGcm<Aes256, U16>;

const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;
const AUTH_TAG_LENGTH: usize = 16;
const SALT_LENGTH: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
    buf
}

/// Machine-specific id for key derivation (port of `getMachineId`):
/// `/etc/machine-id` (Linux) → IOPlatformUUID (macOS) → hostname fallback.
pub fn get_machine_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/etc/machine-id") {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(uuid) = parse_io_platform_uuid(&s) {
                return uuid;
            }
        }
    }
    hostname_fallback()
}

#[cfg(target_os = "macos")]
fn parse_io_platform_uuid(s: &str) -> Option<String> {
    // Match `"IOPlatformUUID" = "<uuid>"`.
    let key = "\"IOPlatformUUID\"";
    let idx = s.find(key)?;
    let after = &s[idx + key.len()..];
    let eq = after.find('=')?;
    let rest = &after[eq + 1..];
    let q1 = rest.find('"')?;
    let rest2 = &rest[q1 + 1..];
    let q2 = rest2.find('"')?;
    Some(rest2[..q2].to_string())
}

fn hostname_fallback() -> String {
    if let Ok(out) = std::process::Command::new("hostname").output() {
        let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    "unknown-host".to_string()
}

/// Derive a 32-byte key from `{machineId}:{stateDir}` + salt via
/// PBKDF2-HMAC-SHA512, 100k iterations (port of `deriveKey`).
pub fn derive_key(machine_id: &str, state_dir: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let material = format!("{machine_id}:{state_dir}");
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::pbkdf2_hmac::<Sha512>(material.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt with AES-256-GCM. Output: `salt(32) || iv(16) || authTag(16) || ct`
/// (port of `encrypt`).
pub fn encrypt(plaintext: &str, machine_id: &str, state_dir: &str) -> Vec<u8> {
    let salt = random_bytes(SALT_LENGTH);
    let iv = random_bytes(IV_LENGTH);
    let key = derive_key(machine_id, state_dir, &salt);

    let cipher = Aes256Gcm16::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&iv);
    // aes-gcm returns ciphertext || tag(16).
    let mut sealed = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("AES-GCM encryption");
    let tag = sealed.split_off(sealed.len() - AUTH_TAG_LENGTH);
    let ciphertext = sealed;

    let mut out = Vec::with_capacity(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt data produced by [`encrypt`] (port of `decrypt`). Fails on tamper
/// (GCM tag mismatch) or truncated input.
pub fn decrypt(data: &[u8], machine_id: &str, state_dir: &str) -> Result<String> {
    let header = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;
    if data.len() < header {
        return Err(anyhow!("Invalid encrypted data: too short"));
    }
    let salt = &data[0..SALT_LENGTH];
    let iv = &data[SALT_LENGTH..SALT_LENGTH + IV_LENGTH];
    let tag = &data[SALT_LENGTH + IV_LENGTH..header];
    let ciphertext = &data[header..];

    let key = derive_key(machine_id, state_dir, salt);
    let cipher = Aes256Gcm16::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(iv);

    // aes-gcm expects ciphertext || tag.
    let mut input = Vec::with_capacity(ciphertext.len() + AUTH_TAG_LENGTH);
    input.extend_from_slice(ciphertext);
    input.extend_from_slice(tag);

    let plaintext = cipher
        .decrypt(nonce, input.as_ref())
        .map_err(|_| anyhow!("decryption failed (tampered or wrong key)"))?;
    Ok(String::from_utf8(plaintext)?)
}

/// Ensure `<stateDir>/.secureops/` exists and a keystore verification token is
/// present (port of `ensureKeystore`). Returns `(machine_id, keystore_path)`.
pub async fn ensure_keystore(state_dir: &str) -> Result<(String, PathBuf)> {
    let sc_dir = Path::new(state_dir).join(".secureops");
    let _ = tokio::fs::create_dir_all(&sc_dir).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&sc_dir, std::fs::Permissions::from_mode(0o700)).await;
    }
    let keystore_path = sc_dir.join("keystore");
    let machine_id = get_machine_id();

    if tokio::fs::metadata(&keystore_path).await.is_err() {
        let token = encrypt("secureops-keystore-verify", &machine_id, state_dir);
        tokio::fs::write(&keystore_path, &token).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                tokio::fs::set_permissions(&keystore_path, std::fs::Permissions::from_mode(0o400))
                    .await;
        }
    }
    Ok((machine_id, keystore_path))
}

/// Encrypt a file to `<path>.enc`, backing up the original first (port of
/// `encryptFile`).
pub async fn encrypt_file(
    file_path: &str,
    machine_id: &str,
    state_dir: &str,
    backup_dir: &str,
) -> Result<()> {
    let content = tokio::fs::read_to_string(file_path).await?;
    let base = Path::new(file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let _ = tokio::fs::copy(file_path, Path::new(backup_dir).join(base)).await;
    let enc = encrypt(&content, machine_id, state_dir);
    tokio::fs::write(format!("{file_path}.enc"), &enc).await?;
    Ok(())
}

/// Decrypt a `.enc` file and return its plaintext (port of `decryptFile`).
pub async fn decrypt_file(file_path: &str, machine_id: &str, state_dir: &str) -> Result<String> {
    let enc_path = if file_path.ends_with(".enc") {
        file_path.to_string()
    } else {
        format!("{file_path}.enc")
    };
    let data = tokio::fs::read(&enc_path).await?;
    decrypt(&data, machine_id, state_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ct = encrypt("hunter2 secret", "machine-abc", "/state");
        // layout: salt(32)+iv(16)+tag(16)+ct
        assert!(ct.len() > SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
        let pt = decrypt(&ct, "machine-abc", "/state").unwrap();
        assert_eq!(pt, "hunter2 secret");
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt("x", "m1", "/state");
        assert!(decrypt(&ct, "m2", "/state").is_err());
        assert!(decrypt(&ct, "m1", "/other").is_err());
    }

    #[test]
    fn tamper_detected() {
        let mut ct = encrypt("important", "m", "/s");
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(decrypt(&ct, "m", "/s").is_err());
    }

    #[test]
    fn too_short_errors() {
        assert!(decrypt(&[0u8; 10], "m", "/s").is_err());
    }

    /// Interop regression: a ciphertext produced by the **TypeScript** tool
    /// (`encrypt('secureclaw-interop-test', 'machine-xyz', '/var/state')`) must
    /// decrypt here - proves the byte layout + KDF + cipher match exactly.
    /// NOTE: plaintext literal is the pre-rename brand on purpose - this blob is
    /// a frozen TS-generated fixture; the bytes cannot be renamed.
    #[test]
    fn decrypts_typescript_ciphertext() {
        let hex = "59e9a57f203254712508c4bdf1837501de90d8ec5d5a2e9f7e80fc4e47fc8fa678f16b20f81b22b3278a26f1b0a935a49b50036b22c93098320651d3a337c832ab3c49df0d8107793c778db78dc11b0a1dd07b07d79b40";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let pt = decrypt(&bytes, "machine-xyz", "/var/state").unwrap();
        assert_eq!(pt, "secureclaw-interop-test");
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [7u8; 32];
        assert_eq!(derive_key("m", "/s", &salt), derive_key("m", "/s", &salt));
        assert_ne!(
            derive_key("m", "/s", &salt),
            derive_key("m", "/other", &salt)
        );
    }
}
