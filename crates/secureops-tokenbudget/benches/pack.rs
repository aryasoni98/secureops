//! Criterion benchmark (PRODUCT.md Phase 9 perf target: TokenBudget packing /
//! compression throughput).

use criterion::{criterion_group, criterion_main, Criterion};
use secureops_tokenbudget::{Evidence, EvidenceKind, TokenBudget};

fn corpus() -> Vec<Evidence> {
    (0..1000)
        .map(|i| {
            Evidence::new(
                EvidenceKind::Finding,
                format!("finding {i}: open security group, public bucket, weak iam ").repeat(3),
                (i % 10) as f32 / 10.0,
            )
        })
        .collect()
}

fn bench_pack(c: &mut Criterion) {
    let budget = TokenBudget::new("model", 8000, 1000);
    let items = corpus();
    c.bench_function("pack_1000", |b| b.iter(|| budget.pack(items.clone())));
}

criterion_group!(benches, bench_pack);
criterion_main!(benches);
