//! # secureops-tokenbudget
//!
//! Pack the most decision-relevant evidence into an LLM context window
//! (PRODUCT.md §10 "Token Compression" + Phase 6). The bug-hunter calls
//! [`TokenBudget::pack`] before *every* LLM call so a long investigation never
//! blows the window or the bill.
//!
//! Strategy: a greedy **relevance/cost knapsack** ([`TokenBudget::pack`]) over
//! [`Evidence`], plus composable compression passes:
//! - [`cosine_dedup`] - collapse near-duplicate findings to one representative + a count.
//! - [`schema_ref`] - send a repeated JSON schema once, reference it by id.
//! - [`diff_delta`] - for configs/manifests, keep only the changed/violating lines.
//! - [`map_reduce_chunks`] - split an oversized blob into window-sized chunks.
//! - [`anthropic_cache_control`] - mark a stable prefix for prompt caching.
//!
//! All passes are pure, deterministic, and model-free (no network), so they
//! unit-test everywhere. Token counts use a `chars/4` estimate ([`estimate_tokens`]).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The kind of evidence being packed (drives default handling/labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Finding,
    IamPolicy,
    Manifest,
    Log,
    Schema,
    Other,
}

/// A single piece of context competing for room in the window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub kind: EvidenceKind,
    pub raw: String,
    /// Caller-assigned relevance in `[0.0, 1.0]`.
    pub relevance: f32,
    /// Estimated token cost (filled by [`Evidence::new`]).
    pub est_tokens: usize,
}

impl Evidence {
    /// Build evidence, estimating its token cost from `raw`.
    pub fn new(kind: EvidenceKind, raw: impl Into<String>, relevance: f32) -> Self {
        let raw = raw.into();
        let est_tokens = estimate_tokens(&raw);
        Self {
            id: Uuid::new_v4(),
            kind,
            raw,
            relevance: relevance.clamp(0.0, 1.0),
            est_tokens,
        }
    }

    /// Value density used by the knapsack: relevance per token.
    fn density(&self) -> f32 {
        if self.est_tokens == 0 {
            self.relevance
        } else {
            self.relevance / self.est_tokens as f32
        }
    }
}

/// The token window for a model (PRODUCT.md §10 `struct TokenBudget`).
#[derive(Debug, Clone)]
pub struct TokenBudget {
    pub model: String,
    pub window: usize,
    pub reserved_output: usize,
}

/// Result of [`TokenBudget::pack`].
#[derive(Debug, Default)]
pub struct PackResult {
    pub included: Vec<Evidence>,
    pub dropped: Vec<Evidence>,
    pub used_tokens: usize,
}

impl TokenBudget {
    /// New budget for `model` with a `window` and output reservation.
    pub fn new(model: impl Into<String>, window: usize, reserved_output: usize) -> Self {
        Self {
            model: model.into(),
            window,
            reserved_output,
        }
    }

    /// Tokens available for input after reserving output headroom.
    pub fn available(&self) -> usize {
        self.window.saturating_sub(self.reserved_output)
    }

    /// Greedily pack the highest value-density evidence until the input budget
    /// is exhausted. Deterministic: ties break by descending relevance then id.
    pub fn pack(&self, items: Vec<Evidence>) -> PackResult {
        let budget = self.available();
        let mut ordered = items;
        ordered.sort_by(|a, b| {
            b.density()
                .partial_cmp(&a.density())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(
                    b.relevance
                        .partial_cmp(&a.relevance)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then(a.id.cmp(&b.id))
        });

        let mut result = PackResult::default();
        for item in ordered {
            if result.used_tokens + item.est_tokens <= budget {
                result.used_tokens += item.est_tokens;
                result.included.push(item);
            } else {
                result.dropped.push(item);
            }
        }
        result
    }
}

/// Estimate token count: ~4 characters per token (cheap, model-agnostic).
pub fn estimate_tokens(s: &str) -> usize {
    s.chars().count().div_ceil(4)
}

/// Bag-of-words cosine similarity in `[0.0, 1.0]` (whitespace tokens).
pub fn cosine_similarity(a: &str, b: &str) -> f32 {
    fn freq(s: &str) -> BTreeMap<&str, f32> {
        let mut m = BTreeMap::new();
        for w in s.split_whitespace() {
            *m.entry(w).or_insert(0.0) += 1.0;
        }
        m
    }
    let (fa, fb) = (freq(a), freq(b));
    if fa.is_empty() || fb.is_empty() {
        return 0.0;
    }
    let dot: f32 = fa
        .iter()
        .map(|(k, va)| fb.get(k).map(|vb| va * vb).unwrap_or(0.0))
        .sum();
    let na: f32 = fa.values().map(|v| v * v).sum::<f32>().sqrt();
    let nb: f32 = fb.values().map(|v| v * v).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// Collapse near-duplicate evidence (cosine ≥ `threshold`) into one
/// representative each (the highest-relevance member of the cluster). Returns
/// `(representatives, duplicates_removed)`.
pub fn cosine_dedup(items: Vec<Evidence>, threshold: f32) -> (Vec<Evidence>, usize) {
    let mut reps: Vec<Evidence> = Vec::new();
    let mut removed = 0usize;
    for item in items {
        if let Some(rep) = reps
            .iter_mut()
            .find(|r| cosine_similarity(&r.raw, &item.raw) >= threshold)
        {
            removed += 1;
            // Keep the higher-relevance representative.
            if item.relevance > rep.relevance {
                *rep = item;
            }
        } else {
            reps.push(item);
        }
    }
    (reps, removed)
}

/// Send a repeated `schema` once and replace each occurrence in `texts` with a
/// short reference token. Returns `(schema_block, rewritten_texts)`. The caller
/// prepends `schema_block` to the system prompt once.
pub fn schema_ref(texts: &[String], schema: &str) -> (String, Vec<String>) {
    const REF: &str = "{$ref:schema#1}";
    let schema_block = format!("schema#1:\n{schema}");
    let rewritten = texts.iter().map(|t| t.replace(schema, REF)).collect();
    (schema_block, rewritten)
}

/// Keep only the lines present in `candidate` but not in `baseline` - the
/// changed/violating fragment of an IAM policy or K8s manifest.
pub fn diff_delta(baseline: &str, candidate: &str) -> String {
    use std::collections::HashSet;
    let base: HashSet<&str> = baseline.lines().map(str::trim).collect();
    candidate
        .lines()
        .filter(|l| !base.contains(l.trim()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Split `s` into chunks of about `chunk_tokens` tokens each (for map-reduce
/// summarization of oversized plans). Concatenating the chunks reproduces `s`.
pub fn map_reduce_chunks(s: &str, chunk_tokens: usize) -> Vec<String> {
    let chunk_chars = chunk_tokens.max(1) * 4;
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return vec![];
    }
    chars
        .chunks(chunk_chars)
        .map(|c| c.iter().collect())
        .collect()
}

/// Anthropic `cache_control` marker for a stable prompt prefix (prompt caching).
pub fn anthropic_cache_control() -> serde_json::Value {
    serde_json::json!({ "type": "ephemeral" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(raw: &str, rel: f32) -> Evidence {
        Evidence::new(EvidenceKind::Finding, raw, rel)
    }

    #[test]
    fn pack_respects_window_and_prefers_density() {
        let budget = TokenBudget::new("test", 100, 0); // 100 tokens available
                                                       // Each ~10 tokens (40 chars). High relevance first.
        let items = vec![
            ev(&"x".repeat(40), 0.9),
            ev(&"y".repeat(40), 0.1),
            ev(&"z".repeat(40), 0.5),
        ];
        let r = budget.pack(items);
        assert!(r.used_tokens <= budget.available());
        // Highest relevance/density item must be included.
        assert!(r.included.iter().any(|e| e.relevance == 0.9));
    }

    #[test]
    fn pack_drops_when_over_budget() {
        let budget = TokenBudget::new("test", 12, 0); // ~12 tokens
        let items = vec![ev(&"a".repeat(40), 1.0), ev(&"b".repeat(40), 1.0)]; // ~10 each
        let r = budget.pack(items);
        assert_eq!(r.included.len(), 1);
        assert_eq!(r.dropped.len(), 1);
    }

    #[test]
    fn cosine_dedup_collapses_near_identical() {
        let items = vec![
            ev("open security group allows 0.0.0.0/0 on port 22", 0.4),
            ev("open security group allows 0.0.0.0/0 on port 22", 0.8),
            ev("s3 bucket is public", 0.5),
        ];
        let (reps, removed) = cosine_dedup(items, 0.85);
        assert_eq!(reps.len(), 2);
        assert_eq!(removed, 1);
        // Kept the higher-relevance representative.
        assert!(reps.iter().any(|e| (e.relevance - 0.8).abs() < 1e-6));
    }

    #[test]
    fn schema_ref_cuts_tokens_below_half() {
        let schema = "x".repeat(2000); // ~500 tokens
        let texts: Vec<String> = (0..10).map(|i| format!("{schema} item{i}")).collect();
        let before: usize = texts.iter().map(|t| estimate_tokens(t)).sum();
        let (block, rewritten) = schema_ref(&texts, &schema);
        let after =
            estimate_tokens(&block) + rewritten.iter().map(|t| estimate_tokens(t)).sum::<usize>();
        assert!(
            (after as f32 / before as f32) < 0.5,
            "schema_ref ratio {} not < 0.5",
            after as f32 / before as f32
        );
    }

    #[test]
    fn diff_delta_returns_only_violating_lines() {
        let baseline = "allow read\nallow list";
        let candidate = "allow read\nallow list\nallow s3:* on *";
        assert_eq!(diff_delta(baseline, candidate), "allow s3:* on *");
    }

    #[test]
    fn map_reduce_chunks_partitions_and_reassembles() {
        let s = "a".repeat(100);
        let chunks = map_reduce_chunks(&s, 5); // 20 chars/chunk → 5 chunks
        assert_eq!(chunks.len(), 5);
        assert_eq!(chunks.concat(), s);
    }
}
