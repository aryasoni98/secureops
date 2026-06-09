use criterion::{criterion_group, criterion_main, Criterion};
use secureops_tokenbudget::{Evidence, EvidenceKind, TokenBudget};

fn bench_pack(c: &mut Criterion) {
    let mut items = Vec::new();
    for i in 0..100 {
        items.push(Evidence::new(
            EvidenceKind::Finding,
            format!(
                "finding-{i}: very long IAM policy fragment with arn:aws:iam::123:role/test and several actions including s3:GetObject, s3:PutObject, ec2:Describe* applied to multiple resources"
            ),
            0.5 + (i as f32 / 200.0),
        ));
    }
    let budget = TokenBudget::new("local", 4096, 512);
    c.bench_function("tokenbudget_pack_100", |b| {
        b.iter(|| {
            let res = budget.pack(items.clone());
            assert!(res.used_tokens <= 4096);
        })
    });
}

criterion_group!(benches, bench_pack);
criterion_main!(benches);
