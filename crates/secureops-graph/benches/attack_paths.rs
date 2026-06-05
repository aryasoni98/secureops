//! Criterion benchmark (PRODUCT.md Phase 9 perf target: graph BFS/Dijkstra
//! p95 < 200ms on a 10k-node graph).

use criterion::{criterion_group, criterion_main, Criterion};
use secureops_graph::{EdgeKind, NodeData, SecurityGraph};

fn build(n: usize) -> SecurityGraph {
    let mut g = SecurityGraph::new();
    g.add_node(NodeData::new("internet", "internet").exposed());
    for i in 0..n {
        g.add_node(NodeData::new(format!("n{i}"), "ec2"));
    }
    g.add_node(NodeData::new("crown", "rds").sensitive());
    g.add_edge("internet", "n0", EdgeKind::Exposes, 1.0);
    for i in 0..n - 1 {
        g.add_edge(
            format!("n{i}"),
            format!("n{}", i + 1),
            EdgeKind::ConnectsTo,
            1.0,
        );
    }
    g.add_edge(format!("n{}", n - 1), "crown", EdgeKind::ConnectsTo, 1.0);
    g
}

fn bench_attack_paths(c: &mut Criterion) {
    let g = build(10_000);
    c.bench_function("attack_paths_10k", |b| b.iter(|| g.attack_paths()));
}

criterion_group!(benches, bench_attack_paths);
criterion_main!(benches);
