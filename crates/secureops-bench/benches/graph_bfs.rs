use criterion::{criterion_group, criterion_main, Criterion};
use secureops_bench::synthetic_graph;

fn bench_bfs_10k(c: &mut Criterion) {
    let g = synthetic_graph(10_000);
    c.bench_function("graph_bfs_10k", |b| {
        b.iter(|| {
            let r = g.blast_radius("internet");
            assert!(r >= 1);
        })
    });
}

criterion_group!(benches, bench_bfs_10k);
criterion_main!(benches);
