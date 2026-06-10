use criterion::{criterion_group, criterion_main, Criterion};
use secureops_rl::{FeatureSpec, FindingFeatures, LinUcb};

fn bench_rank(c: &mut Criterion) {
    let spec = FeatureSpec {
        n_rule_categories: 16,
        n_clouds: 4,
    };
    let mut model = LinUcb::new(spec.dim(), 0.1);
    let mut items = Vec::new();
    for i in 0..500 {
        items.push(
            FindingFeatures {
                severity: (i % 5) as u8,
                blast_radius_norm: (i as f32 / 500.0).min(1.0),
                exposed_internet: i % 2 == 0,
                rule_category: i % spec.n_rule_categories,
                cloud: i % spec.n_clouds,
                recency_decay: 1.0,
            }
            .to_vec(&spec),
        );
    }
    for x in items.iter().take(50) {
        model.update(x, 1.0);
    }
    c.bench_function("rl_rank_500", |b| {
        b.iter(|| {
            let _ = model.rank(&items);
        })
    });
}

criterion_group!(benches, bench_rank);
criterion_main!(benches);
