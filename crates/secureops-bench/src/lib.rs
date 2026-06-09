//! Shared bench helpers (PRODUCT.md Phase 9). The actual measurements live in
//! `benches/`. Targets:
//!
//! - graph BFS p95 < 200 ms on a 10 000-node graph
//! - TokenBudget compression ratio > 0.40 on 20 IAM-style payloads
//! - LinUCB scoring stays sublinear in the feature count

#![forbid(unsafe_code)]

use secureops_graph::{EdgeKind, NodeData, SecurityGraph};

/// Build a synthetic 10 000-node mesh with one internet-exposed root and a
/// fan-out tree of regular nodes plus one sensitive leaf reachable through K
/// hops. Used by the graph BFS bench.
pub fn synthetic_graph(n: usize) -> SecurityGraph {
    let mut g = SecurityGraph::new();
    let mut root = NodeData::new("internet".to_string(), "net".to_string());
    root.exposed = true;
    g.add_node(root);
    for i in 0..n {
        let mut nd = NodeData::new(format!("n{i}"), "asset".to_string());
        if i == n - 1 {
            nd.sensitive = true;
        }
        g.add_node(nd);
    }
    let mut prev = "internet".to_string();
    for i in 0..n {
        let next = format!("n{i}");
        g.add_edge(prev.clone(), next.clone(), EdgeKind::Exposes, 1.0);
        prev = next;
    }
    g
}
