use regex::Regex;
fn main() {
    let re = Regex::new(r"(?i)\bOR\b").unwrap();
    println!("Matches: {}", re.is_match("ＯＲ 1=1--"));
}
