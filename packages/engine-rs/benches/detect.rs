use criterion::{Criterion, black_box, criterion_group, criterion_main};
use invariant_engine::engine::InvariantEngine;
use invariant_engine::normalizer;
use invariant_engine::types::AnalysisRequest;

fn bench_detect_sql(c: &mut Criterion) {
    let engine = InvariantEngine::new();
    c.bench_function("bench_detect_sql", |b| {
        b.iter(|| engine.detect(black_box("' OR 1=1--")))
    });
}

fn bench_detect_xss(c: &mut Criterion) {
    let engine = InvariantEngine::new();
    c.bench_function("bench_detect_xss", |b| {
        b.iter(|| engine.detect(black_box("<script>alert(1)</script>")))
    });
}

fn bench_detect_deep_sql(c: &mut Criterion) {
    let engine = InvariantEngine::new();
    c.bench_function("bench_detect_deep_sql", |b| {
        b.iter(|| engine.detect_deep(black_box("' OR 1=1--"), None))
    });
}

fn bench_analyze_full(c: &mut Criterion) {
    let engine = InvariantEngine::new();
    c.bench_function("bench_analyze_full", |b| {
        b.iter(|| {
            let request = AnalysisRequest {
                input: black_box("' OR 1=1--").to_owned(),
                known_context: None,
                source_reputation: None,
                request_meta: None,
            };
            engine.analyze(&request)
        })
    });
}

fn bench_benign(c: &mut Criterion) {
    let engine = InvariantEngine::new();
    c.bench_function("bench_benign", |b| {
        b.iter(|| engine.detect(black_box("Hello world")))
    });
}

fn bench_canonicalize(c: &mut Criterion) {
    let payload = "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E";
    c.bench_function("bench_canonicalize", |b| {
        b.iter(|| normalizer::quick_canonical(black_box(payload)))
    });
}

criterion_group!(
    benches,
    bench_detect_sql,
    bench_detect_xss,
    bench_detect_deep_sql,
    bench_analyze_full,
    bench_benign,
    bench_canonicalize,
);
criterion_main!(benches);
