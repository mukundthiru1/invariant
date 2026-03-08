use invariant_engine::types::InvariantClass;
fn main() {
    let tags = invariant_engine::class_registry::compliance_for(InvariantClass::PathDotdotEscape);
    println!("{:?}", tags);
}
