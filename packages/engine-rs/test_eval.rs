use invariant_engine::request_decomposer::{RawHttpRequest, decompose_request};
fn main() {
    let mut req = RawHttpRequest {
        method: "GET".into(),
        path: "/search?q=' OR 1=1--".into(),
        query_string: None,
        headers: Default::default(),
        cookies: None,
        body: None,
        content_type: None,
    };
    let surfaces = decompose_request(&req);
    println!("{:#?}", surfaces);
}
