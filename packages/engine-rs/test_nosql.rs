use invariant_engine::evaluators::nosql::NoSqlEvaluator;
use invariant_engine::evaluators::L2Evaluator;
fn main() {
    let eval = NoSqlEvaluator;
    let payload = r#"{"\": "this.password.match(/^a/)"}"#;
    let dets = eval.detect(payload);
    println!("{:?}", dets);
}
