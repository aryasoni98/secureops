//! Directory hash baselines - faithful port of the remaining `utils/hash.ts`
//! functions (`hashDirectory`, `createBaseline`, `compareBaseline`,
//! `saveBaseline`, `loadBaseline`). Used for drift / integrity detection.
//!
//! These do one-shot synchronous I/O (`std::fs`); `compare_baseline` is pure.

use crate::hash_bytes;
use secureops_core::{BaselineComparison, HashBaseline};
use std::collections::HashMap;
use std::path::Path;

/// Recursively hash every file under `dir` → `{ relative_path: sha256_hex }`
/// (port of `hashDirectory`). Unreadable files/dirs are skipped.
pub fn hash_directory(dir: &str) -> HashMap<String, String> {
    fn walk(base: &Path, dir: &Path, out: &mut HashMap<String, String>) {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        for entry in rd.flatten() {
            let p = entry.path();
            match std::fs::metadata(&p) {
                Ok(m) if m.is_dir() => walk(base, &p, out),
                Ok(m) if m.is_file() => {
                    if let Ok(bytes) = std::fs::read(&p) {
                        let rel = p
                            .strip_prefix(base)
                            .unwrap_or(&p)
                            .to_string_lossy()
                            .to_string();
                        out.insert(rel, hash_bytes(&bytes));
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = HashMap::new();
    walk(Path::new(dir), Path::new(dir), &mut out);
    out
}

/// Create a [`HashBaseline`] for `dir` (port of `createBaseline`). `now` is the
/// injected RFC3339 timestamp.
pub fn create_baseline(dir: &str, now: &str) -> HashBaseline {
    HashBaseline {
        timestamp: now.to_string(),
        files: hash_directory(dir),
    }
}

/// Compare current hashes against a stored baseline (port of `compareBaseline`).
pub fn compare_baseline(
    baseline: &HashBaseline,
    current: &HashMap<String, String>,
) -> BaselineComparison {
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut removed = Vec::new();
    for (path, hash) in &baseline.files {
        match current.get(path) {
            None => removed.push(path.clone()),
            Some(c) if c != hash => modified.push(path.clone()),
            _ => {}
        }
    }
    for path in current.keys() {
        if !baseline.files.contains_key(path) {
            added.push(path.clone());
        }
    }
    BaselineComparison {
        added,
        modified,
        removed,
    }
}

/// Save a baseline to a JSON file (port of `saveBaseline`; 2-space pretty).
pub fn save_baseline(baseline: &HashBaseline, path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(baseline).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

/// Load a baseline from a JSON file, or `None` if absent/invalid (port of
/// `loadBaseline`).
pub fn load_baseline(path: &str) -> Option<HashBaseline> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_detects_add_modify_remove() {
        let base = HashBaseline {
            files: HashMap::from([
                ("keep".into(), "h1".into()),
                ("change".into(), "h2".into()),
                ("gone".into(), "h3".into()),
            ]),
            ..Default::default()
        };
        let current = HashMap::from([
            ("keep".to_string(), "h1".to_string()),
            ("change".to_string(), "h2-NEW".to_string()),
            ("new".to_string(), "h4".to_string()),
        ]);
        let c = compare_baseline(&base, &current);
        assert_eq!(c.modified, vec!["change".to_string()]);
        assert_eq!(c.removed, vec!["gone".to_string()]);
        assert_eq!(c.added, vec!["new".to_string()]);
    }

    #[test]
    fn hash_directory_and_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "alpha").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("b.txt"), "beta").unwrap();

        let hashes = hash_directory(dir.path().to_str().unwrap());
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains_key("a.txt"));
        assert!(hashes.contains_key("sub/b.txt"));

        let baseline = create_baseline(dir.path().to_str().unwrap(), "t");
        let path = dir.path().join("base.json");
        save_baseline(&baseline, path.to_str().unwrap()).unwrap();
        let loaded = load_baseline(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.files, baseline.files);
    }
}
