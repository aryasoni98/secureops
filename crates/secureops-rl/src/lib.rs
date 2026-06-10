//! # secureops-rl
//!
//! Online **LinUCB** contextual bandit for ranking findings by predicted analyst
//! value (PRODUCT.md §18 + Phase 7). Ridge regression with a UCB exploration
//! bonus; rank-1 online updates via the **Sherman-Morrison** identity, so there
//! is no matrix inversion and therefore no BLAS/LAPACK dependency (keeps the
//! crate pure-Rust and clear of the workspace `cc` cap).
//!
//! Reward comes from analyst actions — confirm `+1.0`, escalate `+1.5`,
//! dismiss `-1.0` — decayed by recency. Ranking quality is measured with
//! [`ndcg_at_k`] / [`precision_at_k`]. Weights serialize for a model registry.

#![forbid(unsafe_code)]
// Matrix/vector math indexes flat row-major buffers (`a_inv[r*d + c]`); explicit
// range loops are clearer here than iterator gymnastics.
#![allow(clippy::needless_range_loop)]

use serde::{Deserialize, Serialize};

/// Base reward for a confirmed finding.
pub const REWARD_CONFIRM: f32 = 1.0;
/// Base reward for an escalated finding (highest — caught something real & urgent).
pub const REWARD_ESCALATE: f32 = 1.5;
/// Base reward for a dismissed finding (noise; negative).
pub const REWARD_DISMISS: f32 = -1.0;

/// An analyst decision on a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Confirm,
    Escalate,
    Dismiss,
}

impl Action {
    /// Undecayed reward magnitude for this action.
    pub fn base_reward(self) -> f32 {
        match self {
            Action::Confirm => REWARD_CONFIRM,
            Action::Escalate => REWARD_ESCALATE,
            Action::Dismiss => REWARD_DISMISS,
        }
    }
}

/// Reward with time decay: `base * 0.95^hours` (older feedback counts less).
pub fn decayed_reward(action: Action, hours: f32) -> f32 {
    action.base_reward() * 0.95f32.powf(hours.max(0.0))
}

/// Dimensionality config: onehot widths for categorical features.
#[derive(Debug, Clone, Copy)]
pub struct FeatureSpec {
    pub n_rule_categories: usize,
    pub n_clouds: usize,
}

impl FeatureSpec {
    /// Total feature-vector dimension:
    /// severity + blast + exposed + recency + rule onehot + cloud onehot + bias.
    pub fn dim(&self) -> usize {
        4 + self.n_rule_categories + self.n_clouds + 1
    }
}

/// Raw finding attributes mapped to a feature vector.
#[derive(Debug, Clone)]
pub struct FindingFeatures {
    /// 0..=4 (info..critical).
    pub severity: u8,
    /// Normalised blast radius in `[0,1]`.
    pub blast_radius_norm: f32,
    pub exposed_internet: bool,
    /// Index into rule categories (`< n_rule_categories`).
    pub rule_category: usize,
    /// Index into clouds (`< n_clouds`).
    pub cloud: usize,
    /// Recency decay weight in `[0,1]` (1.0 = brand new).
    pub recency_decay: f32,
}

impl FindingFeatures {
    /// Build the feature vector for `spec` (length `spec.dim()`).
    pub fn to_vec(&self, spec: &FeatureSpec) -> Vec<f32> {
        let mut v = Vec::with_capacity(spec.dim());
        v.push(self.severity as f32 / 4.0);
        v.push(self.blast_radius_norm.clamp(0.0, 1.0));
        v.push(if self.exposed_internet { 1.0 } else { 0.0 });
        v.push(self.recency_decay.clamp(0.0, 1.0));
        let mut rule = vec![0.0; spec.n_rule_categories];
        if self.rule_category < rule.len() {
            rule[self.rule_category] = 1.0;
        }
        v.extend(rule);
        let mut cloud = vec![0.0; spec.n_clouds];
        if self.cloud < cloud.len() {
            cloud[self.cloud] = 1.0;
        }
        v.extend(cloud);
        v.push(1.0); // bias
        v
    }
}

/// LinUCB model: holds `A^-1` and `b` so scoring needs no inversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinUcb {
    d: usize,
    alpha: f32,
    /// Row-major `d×d` inverse of the design matrix `A` (starts as `I`).
    a_inv: Vec<f32>,
    /// `d`-vector of accumulated reward·feature.
    b: Vec<f32>,
    /// Number of updates applied (telemetry).
    pub updates: u64,
}

impl LinUcb {
    /// New model of dimension `d` with exploration weight `alpha`
    /// (`A = I`, `b = 0`).
    pub fn new(d: usize, alpha: f32) -> Self {
        let mut a_inv = vec![0.0; d * d];
        for i in 0..d {
            a_inv[i * d + i] = 1.0;
        }
        Self {
            d,
            alpha,
            a_inv,
            b: vec![0.0; d],
            updates: 0,
        }
    }

    fn at(&self, r: usize, c: usize) -> f32 {
        self.a_inv[r * self.d + c]
    }

    /// `A^-1 · v`.
    fn a_inv_mul(&self, v: &[f32]) -> Vec<f32> {
        let mut out = vec![0.0; self.d];
        for r in 0..self.d {
            let mut acc = 0.0;
            for c in 0..self.d {
                acc += self.at(r, c) * v[c];
            }
            out[r] = acc;
        }
        out
    }

    /// `theta = A^-1 · b` (ridge-regression weight estimate).
    pub fn theta(&self) -> Vec<f32> {
        self.a_inv_mul(&self.b)
    }

    /// UCB score for feature vector `x`: `theta·x + alpha·sqrt(xᵀ A^-1 x)`.
    pub fn score(&self, x: &[f32]) -> f32 {
        let theta = self.theta();
        let pred: f32 = theta.iter().zip(x).map(|(t, xi)| t * xi).sum();
        let a_inv_x = self.a_inv_mul(x);
        let var: f32 = x.iter().zip(&a_inv_x).map(|(xi, u)| xi * u).sum();
        pred + self.alpha * var.max(0.0).sqrt()
    }

    /// Online update with observed `reward` for `x`: `A += x xᵀ`, `b += reward·x`,
    /// and `A^-1` via the Sherman-Morrison rank-1 formula.
    pub fn update(&mut self, x: &[f32], reward: f32) {
        let u = self.a_inv_mul(x); // A^-1 x
        let denom = 1.0 + x.iter().zip(&u).map(|(xi, ui)| xi * ui).sum::<f32>();
        if denom.abs() > f32::EPSILON {
            // A_inv -= (u uᵀ) / denom
            for r in 0..self.d {
                for c in 0..self.d {
                    self.a_inv[r * self.d + c] -= u[r] * u[c] / denom;
                }
            }
        }
        for i in 0..self.d {
            self.b[i] += reward * x[i];
        }
        self.updates += 1;
    }

    /// Indices of `items` sorted by descending UCB score (best first).
    pub fn rank(&self, items: &[Vec<f32>]) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..items.len()).collect();
        idx.sort_by(|&a, &b| {
            self.score(&items[b])
                .partial_cmp(&self.score(&items[a]))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        idx
    }

    /// Serialize weights for the model registry.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
    /// Load weights from the registry.
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

/// DCG of the relevance scores in ranked order, truncated at `k`.
fn dcg(rels: &[f32], k: usize) -> f32 {
    rels.iter()
        .take(k)
        .enumerate()
        .map(|(i, &rel)| rel / ((i + 2) as f32).log2())
        .sum()
}

/// Normalised DCG at `k`: `DCG(ranked) / DCG(ideal)`. `ranked_relevance[i]` is
/// the true relevance of the item placed at rank `i`.
pub fn ndcg_at_k(ranked_relevance: &[f32], k: usize) -> f32 {
    let mut ideal = ranked_relevance.to_vec();
    ideal.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let idcg = dcg(&ideal, k);
    if idcg == 0.0 {
        0.0
    } else {
        dcg(ranked_relevance, k) / idcg
    }
}

/// Precision@k: fraction of the top-`k` ranked items that are relevant.
pub fn precision_at_k(ranked_relevant: &[bool], k: usize) -> f32 {
    let k = k.min(ranked_relevant.len()).max(1);
    let hits = ranked_relevant.iter().take(k).filter(|r| **r).count();
    hits as f32 / k as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_shrinks_reward() {
        assert!((decayed_reward(Action::Confirm, 0.0) - 1.0).abs() < 1e-6);
        assert!((decayed_reward(Action::Escalate, 0.0) - 1.5).abs() < 1e-6);
        assert!(decayed_reward(Action::Confirm, 10.0) < 1.0);
        assert!(decayed_reward(Action::Dismiss, 0.0) < 0.0);
    }

    #[test]
    fn sherman_morrison_matches_closed_form_1d() {
        // d=1: after update x=[1], A = I + 1 = 2 → A^-1 = 0.5, b = reward.
        let mut m = LinUcb::new(1, 0.0);
        m.update(&[1.0], 1.0);
        assert!((m.a_inv[0] - 0.5).abs() < 1e-6);
        assert!((m.theta()[0] - 0.5).abs() < 1e-6);
        // alpha=0 → score is pure prediction.
        assert!((m.score(&[1.0]) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn positive_reward_raises_score_in_that_direction() {
        let mut m = LinUcb::new(3, 0.1);
        let x = vec![1.0, 0.0, 1.0];
        let before = m.score(&x);
        m.update(&x, 1.0);
        let after = m.score(&x);
        assert!(after > before, "score should rise after positive reward");
    }

    #[test]
    fn ranking_improves_after_feedback() {
        let spec = FeatureSpec {
            n_rule_categories: 2,
            n_clouds: 2,
        };
        let mut m = LinUcb::new(spec.dim(), 0.05);
        // "Real" findings: high severity, exposed, rule 0. Noise: low, not exposed, rule 1.
        let real = FindingFeatures {
            severity: 4,
            blast_radius_norm: 0.9,
            exposed_internet: true,
            rule_category: 0,
            cloud: 0,
            recency_decay: 1.0,
        }
        .to_vec(&spec);
        let noise = FindingFeatures {
            severity: 1,
            blast_radius_norm: 0.1,
            exposed_internet: false,
            rule_category: 1,
            cloud: 1,
            recency_decay: 1.0,
        }
        .to_vec(&spec);

        // 20 feedback cycles: confirm real, dismiss noise.
        for _ in 0..20 {
            m.update(&real, REWARD_CONFIRM);
            m.update(&noise, REWARD_DISMISS);
        }
        let ranked = m.rank(&[noise.clone(), real.clone()]);
        assert_eq!(ranked[0], 1, "the real finding must rank first");

        // NDCG of the learned order beats the reversed (worst) order.
        let learned = vec![1.0, 0.0]; // real(rel 1) first, noise(rel 0) second
        let worst = vec![0.0, 1.0];
        assert!(ndcg_at_k(&learned, 2) > ndcg_at_k(&worst, 2));
    }

    #[test]
    fn ndcg_and_precision_known_values() {
        // Perfect ranking → NDCG 1.0.
        assert!((ndcg_at_k(&[3.0, 2.0, 1.0], 3) - 1.0).abs() < 1e-6);
        // Precision@2 with [true,false,true] = 0.5.
        assert!((precision_at_k(&[true, false, true], 2) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn weights_round_trip_through_registry() {
        let mut m = LinUcb::new(4, 0.1);
        m.update(&[1.0, 0.0, 1.0, 1.0], 1.5);
        let json = m.to_json();
        let back = LinUcb::from_json(&json).unwrap();
        assert_eq!(back.updates, 1);
        assert!((back.score(&[1.0, 0.0, 1.0, 1.0]) - m.score(&[1.0, 0.0, 1.0, 1.0])).abs() < 1e-6);
    }
}
