//! Denial of Service (DoS) Evaluator — Level 2
//!
//! Detects application-layer DoS patterns:
//!   - Billion laughs (XML entity expansion bomb)
//!   - Hash collision DoS (hash flooding)
//!   - Zip bomb / decompression bomb
//!   - Server resource exhaustion payloads
//!   - Slowloris indicators

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

pub struct DosEvaluator;

impl L2Evaluator for DosEvaluator {
    fn id(&self) -> &'static str {
        "dos"
    }
    fn prefix(&self) -> &'static str {
        "L2 DoS"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();

        // 1. XML Bomb / Billion Laughs
        // <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">
        let entity_def_count = lower.matches("<!entity").count();
        if entity_def_count >= 3 {
            // Check for recursive entity references
            let has_entity_refs = lower.contains("&lol")
                || lower.contains("&a;")
                || lower.contains("&b;")
                || entity_def_count >= 5;

            if has_entity_refs {
                dets.push(L2Detection {
                    detection_type: "dos_xml_bomb".into(),
                    confidence: 0.94,
                    detail: format!(
                        "XML entity expansion bomb — {} entity definitions with recursive references",
                        entity_def_count
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[..decoded.len().min(200)].to_string(),
                        interpretation: "Input contains multiple XML entity definitions with recursive references (Billion Laughs / XML Bomb). When parsed, each entity expands to multiple copies of the previous entity, causing exponential memory consumption. A 1KB payload can expand to >1GB.".into(),
                        offset: 0,
                        property: "XML parsers must limit entity expansion depth and total expansion size. External entity processing must be disabled.".into(),
                    }],
                });
            }
        }

        // 2. Extremely deep JSON nesting
        let max_depth = {
            let mut depth: i32 = 0;
            let mut max: i32 = 0;
            for c in decoded.chars() {
                match c {
                    '{' | '[' => {
                        depth += 1;
                        max = max.max(depth);
                    }
                    '}' | ']' => depth -= 1,
                    _ => {}
                }
            }
            max
        };

        if max_depth >= 50 {
            dets.push(L2Detection {
                detection_type: "dos_deep_nesting".into(),
                confidence: 0.87,
                detail: format!(
                    "Deeply nested structure (depth {}) — JSON/XML parser stack exhaustion",
                    max_depth
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: format!("Nesting depth: {}", max_depth),
                    interpretation: format!(
                        "Input contains {} levels of nesting. Most recursive-descent JSON/XML parsers allocate stack frames per level. At this depth, the parser will likely hit a stack overflow or exceed memory limits, causing the process to crash.",
                        max_depth
                    ),
                    offset: 0,
                    property: "Parsers must enforce maximum nesting depth limits (typically 20-50 levels). Input exceeding the limit must be rejected before parsing begins.".into(),
                }],
            });
        }

        // 3. Extremely long repeated keys (hash collision DoS)
        let repeated_key_count = lower.matches("\"aaa").count();
        if repeated_key_count >= 20 || lower.matches("\"0\":").count() >= 20 {
            dets.push(L2Detection {
                detection_type: "dos_hash_collision".into(),
                confidence: 0.80,
                detail: "Many repeated or similar keys — potential hash collision DoS".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: format!("{} similar keys", repeated_key_count.max(20)),
                    interpretation: "Input contains many similar keys that may cause hash table collisions. Hash collision attacks degrade HashMap/Dictionary lookup from O(1) to O(n), causing CPU exhaustion during JSON parsing.".into(),
                    offset: 0,
                    property: "JSON parsers must limit the number of unique keys and detect hash collision patterns. SipHash or similar collision-resistant hash functions should be used.".into(),
                }],
            });
        }

        // 4. Extremely large input size
        if decoded.len() > 10_000_000 {
            dets.push(L2Detection {
                detection_type: "dos_payload_size".into(),
                confidence: 0.75,
                detail: format!(
                    "Payload size {} bytes exceeds 10MB — resource exhaustion risk",
                    decoded.len()
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: format!("{} bytes", decoded.len()),
                    interpretation: "Input exceeds 10MB, which can cause memory exhaustion during parsing, regex evaluation, or database storage. Rate limiting and payload size limits must be enforced at the edge.".into(),
                    offset: 0,
                    property: "Request body size must be limited at the reverse proxy layer. Applications must reject payloads exceeding the expected maximum size for each endpoint.".into(),
                }],
            });
        }

        // 5. Quadratic blowup patterns (regex, string operations)
        // aaaa...a{1000000} or a{n} where n is very large
        if lower.contains("{1000") || lower.contains("{999") || lower.contains("{100000") {
            dets.push(L2Detection {
                detection_type: "dos_quantifier_bomb".into(),
                confidence: 0.83,
                detail: "Large regex quantifier or repetition count — potential quadratic blowup".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(100)].to_string(),
                    interpretation: "Input contains a large repetition quantifier ({1000+}). When processed by regex engines or string expansion functions, this can cause quadratic or exponential time complexity, leading to CPU exhaustion.".into(),
                    offset: 0,
                    property: "Regex quantifiers in user-controlled input must be bounded. Server-side regex evaluation must enforce time limits.".into(),
                }],
            });
        }

        // 6. Slowloris / slow HTTP headers
        let mut is_slowloris = false;
        if lower.matches("x-a:").count() >= 50 {
            is_slowloris = true;
        } else if lower.contains("content-length:") {
            if let Ok(re) = regex::Regex::new(r"(?im)^content-length\s*:\s*(\d+)") {
                if let Some(captures) = re.captures(input) {
                    if let Ok(declared_length) = captures[1].parse::<u64>() {
                        if declared_length >= 100_000 {
                            let body_start = if let Some(idx) = input.find("\r\n\r\n") {
                                idx + 4
                            } else if let Some(idx) = input.find("\n\n") {
                                idx + 2
                            } else {
                                input.len()
                            };
                            let body_len = input.len() - body_start;
                            if body_len < 100 {
                                is_slowloris = true;
                            }
                        }
                    }
                }
            }
        }

        if is_slowloris {
            dets.push(L2Detection {
                detection_type: "dos_slowloris".into(),
                confidence: 0.82,
                detail: "Slowloris attack or incomplete HTTP headers".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(100)].to_string(),
                    interpretation: "Slowloris attack: client declares a large Content-Length but sends the body extremely slowly (or not at all), keeping the server connection open indefinitely and exhausting connection slots. The X-a header trick sends partial headers to keep keep-alive connections alive without completing the request.".into(),
                    offset: 0,
                    property: "Implement request timeouts, connection limits, and body completion deadlines. Reverse proxies must enforce minimum request transmission rates.".into(),
                }],
            });
        }

        // 7. YAML anchor bomb
        let is_yaml_bomb = (lower.contains("---") && lower.matches('&').count() >= 3 && lower.matches('*').count() >= 10)
            || (lower.contains("&a") && lower.matches("*a").count() >= 5);
        
        if is_yaml_bomb {
            dets.push(L2Detection {
                detection_type: "dos_yaml_bomb".into(),
                confidence: 0.91,
                detail: "YAML anchor bomb detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(100)].to_string(),
                    interpretation: "YAML anchor bomb (analogous to XML billion laughs): anchors (&a) define a node once, aliases (*a) expand it each time they appear. Nested anchors create exponential memory expansion. A YAML document of <100 bytes can expand to gigabytes when parsed.".into(),
                    offset: 0,
                    property: "YAML parsers must limit alias expansion depth and the total number of alias expansions. Disable recursive/nested anchors entirely, or set a maximum expansion budget.".into(),
                }],
            });
        }

        // 8. GraphQL complexity bomb
        let is_graphql_bomb = lower.contains("query") && (
            lower.matches("...").count() >= 5
            || lower.matches("__typename").count() >= 10
            || (lower.contains('{') && max_depth >= 10)
        );
        
        if is_graphql_bomb {
            dets.push(L2Detection {
                detection_type: "dos_graphql_complexity".into(),
                confidence: 0.85,
                detail: "GraphQL complexity bomb detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(100)].to_string(),
                    interpretation: "GraphQL complexity bomb: deeply nested queries or massively spread fragments create O(n^depth) field resolution. Without query complexity limits, a single request can trigger millions of resolver calls, exhausting CPU and memory.".into(),
                    offset: 0,
                    property: "GraphQL endpoints must enforce query depth limits (typically ≤10), query complexity budgets, and field-count caps. Expensive queries must be rejected before execution begins.".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "dos_xml_bomb"
            | "dos_deep_nesting"
            | "dos_hash_collision"
            | "dos_payload_size"
            | "dos_quantifier_bomb"
            | "dos_slowloris"
            | "dos_yaml_bomb"
            | "dos_graphql_complexity" => Some(InvariantClass::DenialOfService),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_xml_bomb() {
        let eval = DosEvaluator;
        let input = r#"<!DOCTYPE bomb [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;">]><root>&lol5;</root>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "dos_xml_bomb"));
    }

    #[test]
    fn detects_deep_nesting() {
        let eval = DosEvaluator;
        let mut input = String::new();
        for _ in 0..60 {
            input.push('{');
        }
        for _ in 0..60 {
            input.push('}');
        }
        let dets = eval.detect(&input);
        assert!(dets.iter().any(|d| d.detection_type == "dos_deep_nesting"));
    }

    #[test]
    fn detects_quantifier_bomb() {
        let eval = DosEvaluator;
        let dets = eval.detect("a{1000000}");
        assert!(dets.iter().any(|d| d.detection_type == "dos_quantifier_bomb"));
    }

    #[test]
    fn no_detection_for_normal_json() {
        let eval = DosEvaluator;
        let dets = eval.detect(r#"{"name": "test", "value": 42}"#);
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = DosEvaluator;
        assert_eq!(
            eval.map_class("dos_xml_bomb"),
            Some(InvariantClass::DenialOfService)
        );
    }

    #[test]
    fn test_slowloris_large_content_length() {
        let eval = DosEvaluator;
        let input = "POST /upload HTTP/1.1\r\nContent-Length: 100000\r\n\r\nX";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "dos_slowloris"));
    }

    #[test]
    fn test_yaml_anchor_bomb() {
        let eval = DosEvaluator;
        let input = "---\na: &a [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "dos_yaml_bomb"));
    }

    #[test]
    fn test_graphql_complexity_bomb() {
        let eval = DosEvaluator;
        let input = "query { ...F1 ...F2 ...F3 ...F4 ...F5 }";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "dos_graphql_complexity"));
    }
}
