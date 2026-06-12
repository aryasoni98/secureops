//! # secureops-graph
//!
//! A security knowledge graph (PRODUCT.md §11 "Graphify-inspired" + Phase 6):
//! cloud assets and identities as nodes, typed security relationships as edges.
//! Two analyses drive remediation priority:
//!
//! - [`SecurityGraph::attack_paths`] - shortest (lowest exploit-difficulty)
//!   paths from any internet-`Exposes`d node to any `sensitive` node, via
//!   Dijkstra with path reconstruction, sorted by blast radius then difficulty.
//! - [`SecurityGraph::blast_radius`] - how many sensitive nodes become reachable
//!   if a given node is compromised (BFS).
//!
//! Pure in-memory + deterministic (no DB), so it unit-tests anywhere. A Neo4j
//! backend and the Postgres-CTE fallback are wired in P6b behind the same shape.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

/// Live Neo4j backend (gated `neo4j` feature).
#[cfg(feature = "neo4j")]
pub mod neo4j;

/// Typed security relationship between two nodes (PRODUCT.md §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Identity A can assume identity/role B.
    CanAssume,
    /// Principal A holds permission over resource B.
    HasPermission,
    /// A can open a network connection to B.
    ConnectsTo,
    /// A exposes B to the internet (entry point).
    Exposes,
    /// A has a known vulnerability B.
    HasVuln,
    /// A violates policy/control B.
    Violates,
    /// A owns B.
    Owns,
}

/// A graph node - a cloud asset or identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeData {
    pub id: String,
    /// `ec2` | `s3` | `role` | `internet` | …
    pub kind: String,
    /// Reachable from the internet (an attack entry point).
    pub exposed: bool,
    /// Holds sensitive data / high-value (an attack target).
    pub sensitive: bool,
}

impl NodeData {
    pub fn new(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            exposed: false,
            sensitive: false,
        }
    }
    pub fn exposed(mut self) -> Self {
        self.exposed = true;
        self
    }
    pub fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }
}

#[derive(Debug, Clone)]
struct EdgeRef {
    to: String,
    #[allow(dead_code)]
    kind: EdgeKind,
    difficulty: f32,
}

/// A reconstructed attack path from an exposed entry to a sensitive target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackPath {
    /// Node ids from entry → target inclusive.
    pub nodes: Vec<String>,
    /// Summed exploit difficulty along the path (lower = easier to exploit).
    pub total_difficulty: f32,
    /// Sensitive nodes reachable from the entry node (impact if breached).
    pub blast_radius: usize,
}

/// In-memory security graph.
#[derive(Debug, Default)]
pub struct SecurityGraph {
    nodes: HashMap<String, NodeData>,
    adj: HashMap<String, Vec<EdgeRef>>,
}

impl SecurityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a node (keyed by id).
    pub fn add_node(&mut self, node: NodeData) {
        self.adj.entry(node.id.clone()).or_default();
        self.nodes.insert(node.id.clone(), node);
    }

    /// Add a directed edge `from → to`. `difficulty` is the exploit cost
    /// (1.0 trivial … 10.0 hard); nodes are auto-created if absent.
    pub fn add_edge(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        kind: EdgeKind,
        difficulty: f32,
    ) {
        let (from, to) = (from.into(), to.into());
        if !self.nodes.contains_key(&from) {
            self.add_node(NodeData::new(from.clone(), "unknown"));
        }
        if !self.nodes.contains_key(&to) {
            self.add_node(NodeData::new(to.clone(), "unknown"));
        }
        self.adj.entry(from).or_default().push(EdgeRef {
            to,
            kind,
            difficulty: difficulty.max(0.0),
        });
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Count sensitive nodes reachable from `start` (excluding `start` itself).
    pub fn blast_radius(&self, start: &str) -> usize {
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        seen.insert(start.to_string());
        queue.push_back(start.to_string());
        let mut count = 0;
        while let Some(n) = queue.pop_front() {
            for e in self.adj.get(&n).into_iter().flatten() {
                if seen.insert(e.to.clone()) {
                    if self.nodes.get(&e.to).is_some_and(|nd| nd.sensitive) {
                        count += 1;
                    }
                    queue.push_back(e.to.clone());
                }
            }
        }
        count
    }

    /// All attack paths from an exposed entry to a sensitive target, each the
    /// lowest-total-difficulty route (Dijkstra). Sorted by blast radius desc,
    /// then total difficulty asc.
    pub fn attack_paths(&self) -> Vec<AttackPath> {
        let mut out = Vec::new();
        let entries: Vec<&String> = self
            .nodes
            .values()
            .filter(|n| n.exposed)
            .map(|n| &n.id)
            .collect();

        for entry in entries {
            let (dist, prev) = self.dijkstra(entry);
            let blast = self.blast_radius(entry);
            for (target, node) in &self.nodes {
                if !node.sensitive || target == entry {
                    continue;
                }
                if let Some(&total) = dist.get(target) {
                    out.push(AttackPath {
                        nodes: reconstruct(&prev, entry, target),
                        total_difficulty: total,
                        blast_radius: blast,
                    });
                }
            }
        }

        out.sort_by(|a, b| {
            b.blast_radius.cmp(&a.blast_radius).then(
                a.total_difficulty
                    .partial_cmp(&b.total_difficulty)
                    .unwrap_or(Ordering::Equal),
            )
        });
        out
    }

    /// Dijkstra from `src`: (distances, predecessor map).
    fn dijkstra(&self, src: &str) -> (HashMap<String, f32>, HashMap<String, String>) {
        let mut dist: HashMap<String, f32> = HashMap::new();
        let mut prev: HashMap<String, String> = HashMap::new();
        let mut heap: BinaryHeap<HeapState> = BinaryHeap::new();
        dist.insert(src.to_string(), 0.0);
        heap.push(HeapState {
            cost: 0.0,
            node: src.to_string(),
        });

        while let Some(HeapState { cost, node }) = heap.pop() {
            if cost > *dist.get(&node).unwrap_or(&f32::INFINITY) {
                continue;
            }
            for e in self.adj.get(&node).into_iter().flatten() {
                let next = cost + e.difficulty;
                if next < *dist.get(&e.to).unwrap_or(&f32::INFINITY) {
                    dist.insert(e.to.clone(), next);
                    prev.insert(e.to.clone(), node.clone());
                    heap.push(HeapState {
                        cost: next,
                        node: e.to.clone(),
                    });
                }
            }
        }
        (dist, prev)
    }
}

fn reconstruct(prev: &HashMap<String, String>, src: &str, target: &str) -> Vec<String> {
    let mut path = vec![target.to_string()];
    let mut cur = target.to_string();
    while cur != src {
        match prev.get(&cur) {
            Some(p) => {
                path.push(p.clone());
                cur = p.clone();
            }
            None => break,
        }
    }
    path.reverse();
    path
}

/// Min-heap state ordered by ascending cost (via `Reverse` semantics in `Ord`).
struct HeapState {
    cost: f32,
    node: String,
}
impl PartialEq for HeapState {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
    }
}
impl Eq for HeapState {}
impl Ord for HeapState {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse: smaller cost = greater priority in the max-heap.
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
    }
}
impl PartialOrd for HeapState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_lowest_difficulty_path_internet_to_sensitive() {
        let mut g = SecurityGraph::new();
        g.add_node(NodeData::new("internet", "internet").exposed());
        g.add_node(NodeData::new("ec2", "ec2"));
        g.add_node(NodeData::new("rds", "rds").sensitive());
        // Two routes to rds: direct hard (9) vs via ec2 cheap (1+1).
        g.add_edge("internet", "ec2", EdgeKind::Exposes, 1.0);
        g.add_edge("ec2", "rds", EdgeKind::ConnectsTo, 1.0);
        g.add_edge("internet", "rds", EdgeKind::ConnectsTo, 9.0);

        let paths = g.attack_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].nodes, vec!["internet", "ec2", "rds"]);
        assert_eq!(paths[0].total_difficulty, 2.0);
        assert_eq!(paths[0].blast_radius, 1);
    }

    #[test]
    fn blast_radius_counts_reachable_sensitive() {
        let mut g = SecurityGraph::new();
        g.add_node(NodeData::new("a", "role").exposed());
        g.add_node(NodeData::new("s1", "s3").sensitive());
        g.add_node(NodeData::new("s2", "rds").sensitive());
        g.add_node(NodeData::new("n", "ec2"));
        g.add_edge("a", "s1", EdgeKind::HasPermission, 1.0);
        g.add_edge("a", "n", EdgeKind::ConnectsTo, 1.0);
        g.add_edge("n", "s2", EdgeKind::ConnectsTo, 1.0);
        assert_eq!(g.blast_radius("a"), 2);
        assert_eq!(g.blast_radius("n"), 1);
    }

    #[test]
    fn paths_sorted_by_blast_radius_then_difficulty() {
        let mut g = SecurityGraph::new();
        // Entry e1 reaches 2 sensitive (big blast); e2 reaches 1.
        g.add_node(NodeData::new("e1", "ec2").exposed());
        g.add_node(NodeData::new("e2", "ec2").exposed());
        g.add_node(NodeData::new("t1", "rds").sensitive());
        g.add_node(NodeData::new("t2", "s3").sensitive());
        g.add_edge("e1", "t1", EdgeKind::ConnectsTo, 5.0);
        g.add_edge("e1", "t2", EdgeKind::ConnectsTo, 5.0);
        g.add_edge("e2", "t1", EdgeKind::ConnectsTo, 1.0);
        let paths = g.attack_paths();
        // e1 (blast 2) paths come before e2 (blast 1).
        assert_eq!(paths[0].blast_radius, 2);
        assert!(paths.last().unwrap().blast_radius == 1);
    }

    #[test]
    fn scales_to_a_thousand_nodes() {
        let mut g = SecurityGraph::new();
        g.add_node(NodeData::new("internet", "internet").exposed());
        for i in 0..1000 {
            g.add_node(NodeData::new(format!("n{i}"), "ec2"));
        }
        g.add_node(NodeData::new("crown", "rds").sensitive());
        g.add_edge("internet", "n0", EdgeKind::Exposes, 1.0);
        for i in 0..999 {
            g.add_edge(
                format!("n{i}"),
                format!("n{}", i + 1),
                EdgeKind::ConnectsTo,
                1.0,
            );
        }
        g.add_edge("n999", "crown", EdgeKind::ConnectsTo, 1.0);
        let paths = g.attack_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].nodes.first().unwrap(), "internet");
        assert_eq!(paths[0].nodes.last().unwrap(), "crown");
        assert_eq!(paths[0].total_difficulty, 1001.0);
    }
}
