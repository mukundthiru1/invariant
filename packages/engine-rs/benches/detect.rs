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

fn bench_detect_deep_latency_matrix(c: &mut Criterion) {
    let engine = InvariantEngine::new();
    let short_benign = "abcdefghij";
    let medium_benign = "abcdefghij".repeat(20);
    let long_benign = "abcdefghij".repeat(500);
    let known_attack = "' UNION SELECT username,password FROM users--";
    let encoded_attack = "%2527%20UNION%2520SELECT%2520username%252Cpassword%2520FROM%2520users--";

    c.bench_function("detect_deep_short_benign_10", |b| {
        b.iter(|| engine.detect_deep(black_box(short_benign), None))
    });
    c.bench_function("detect_deep_medium_benign_200", |b| {
        b.iter(|| engine.detect_deep(black_box(medium_benign.as_str()), None))
    });
    c.bench_function("detect_deep_long_benign_5000", |b| {
        b.iter(|| engine.detect_deep(black_box(long_benign.as_str()), None))
    });
    c.bench_function("detect_deep_known_attack", |b| {
        b.iter(|| engine.detect_deep(black_box(known_attack), None))
    });
    c.bench_function("detect_deep_encoded_attack", |b| {
        b.iter(|| engine.detect_deep(black_box(encoded_attack), None))
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
    bench_detect_deep_latency_matrix,
    bench_analyze_full,
    bench_benign,
    bench_canonicalize,
);
criterion_main!(benches);
