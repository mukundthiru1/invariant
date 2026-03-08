use invariant_engine::engine::InvariantEngine;
fn main() {
    let engine = InvariantEngine::new();
    let res = engine.detect_deep("ＯＲ 1=1--", Some("sql"));
    println!("SQL context: {:?}", res.matches);
    let res2 = engine.detect_deep("ＯＲ 1=1--", None);
    println!("No context: {:?}", res2.matches);
}
