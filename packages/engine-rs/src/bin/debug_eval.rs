use invariant_engine::engine::InvariantEngine;
fn main() {
    let engine = InvariantEngine::new();
    let res = engine.detect_deep("' \u{FF2F}\u{FF32} 1=1--", None);
    println!("Matches: {:?}", res.matches);
}
