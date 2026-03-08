//! GraphQL Abuse Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::collections::HashMap;

pub struct GraphqlEvaluator;

impl L2Evaluator for GraphqlEvaluator {
    fn id(&self) -> &'static str {
        "graphql"
    }
    fn prefix(&self) -> &'static str {
        "L2 GraphQL"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // Introspection query
        static intro: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)__schema\s*\{|__type\s*\(|__typename").unwrap()
        });
        if let Some(m) = intro.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "graphql_introspection".into(),
                confidence: 0.85,
                detail: format!("GraphQL introspection query: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Introspection exposes full API schema".into(),
                    offset: m.start(),
                    property: "GraphQL introspection must be disabled in production".into(),
                }],
            });
        }

        // Deeply nested query (DoS via query complexity)
        let depth = decoded.matches('{').count();
        if depth > 8 {
            dets.push(L2Detection {
                detection_type: "graphql_depth".into(),
                confidence: 0.82 + (depth as f64 * 0.01).min(0.13),
                detail: format!("Deeply nested GraphQL query (depth: {})", depth),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(80)].to_owned(),
                    interpretation: "Deep nesting causes exponential resolver execution".into(),
                    offset: 0,
                    property: "GraphQL query depth must be bounded".into(),
                }],
            });
        }

        // Batch query abuse: [{query:...}, {query:...}]
        static BATCH_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"\[\s*\{[^}]*"query"#).unwrap());
        static QUERY_COUNT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#""query"\s*:"#).unwrap());
        let batch = &*BATCH_RE;
        if let Some(m) = batch.find(&decoded) {
            let query_count = QUERY_COUNT_RE.find_iter(&decoded).count();
            if query_count > 3 {
                dets.push(L2Detection {
                    detection_type: "graphql_batch".into(),
                    confidence: 0.78,
                    detail: format!("GraphQL batch query with {} operations", query_count),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[..decoded.len().min(60)].to_owned(),
                        interpretation: "Batch queries bypass rate limiting".into(),
                        offset: m.start(),
                        property: "GraphQL batch operations must be rate-limited".into(),
                    }],
                });
            }
        }

        // Multiple named operations in one payload (single-request multiplexing)
        static OP_DEF_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\b(?:query|mutation|subscription)\s+[A-Za-z_][A-Za-z0-9_]*\b").unwrap()
        });
        let op_defs = OP_DEF_RE.find_iter(&decoded).count();
        if op_defs >= 3 {
            dets.push(L2Detection {
                detection_type: "graphql_multi_operation_abuse".into(),
                confidence: (0.82 + ((op_defs as f64) * 0.01).min(0.12)).min(0.94),
                detail: format!(
                    "GraphQL payload defines {} named operations in a single request",
                    op_defs
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(100)].to_owned(),
                    interpretation: "Multiple operations in one payload can bypass per-request controls and amplify workload".into(),
                    offset: 0,
                    property: "GraphQL endpoints should limit operation count per request payload".into(),
                }],
            });
        }

        // Field suggestion abuse (error-based schema leak)
        static SUGGESTION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)"query"\s*:\s*"\s*\{\s*[a-z_]{1,3}\s*\}"#).unwrap()
        });
        let suggestion = &*SUGGESTION_RE;
        if let Some(m) = suggestion.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "graphql_suggestion".into(),
                confidence: 0.75,
                detail: "Short field name query — field suggestion enumeration".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Short field names trigger 'did you mean' suggestions exposing schema"
                            .into(),
                    offset: m.start(),
                    property: "GraphQL error messages must not suggest valid field names".into(),
                }],
            });
        }

        static DID_YOU_MEAN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)did you mean\s+(?:\\?["'])?[A-Za-z_][A-Za-z0-9_]*"#).unwrap()
        });
        if let Some(m) = DID_YOU_MEAN_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "graphql_field_suggestion_exploit".into(),
                confidence: 0.84,
                detail: "GraphQL field suggestion leakage detected in response/error text".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Schema hints in error strings enable guided enumeration of hidden fields"
                            .into(),
                    offset: m.start(),
                    property: "Production GraphQL errors should suppress Did you mean suggestions"
                        .into(),
                }],
            });
        }

        // Alias-based DoS: many aliases resolving to the same field
        static alias_re: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\b([A-Za-z_]\w*)\s*:\s*([A-Za-z_]\w*)\b").unwrap()
        });
        let mut alias_targets: HashMap<String, usize> = HashMap::new();
        for caps in alias_re.captures_iter(&decoded) {
            if let Some(target) = caps.get(2) {
                *alias_targets.entry(target.as_str().to_owned()).or_insert(0) += 1;
            }
        }
        if let Some((field, count)) = alias_targets.into_iter().max_by_key(|(_, c)| *c) {
            if count > 5 {
                dets.push(L2Detection {
                    detection_type: "graphql_alias_dos".into(),
                    confidence: 0.90,
                    detail: format!(
                        "GraphQL alias amplification against field '{}' with {} aliases",
                        field, count
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: decoded[..decoded.len().min(100)].to_owned(),
                        interpretation:
                            "Repeated aliases can multiply expensive resolver execution".into(),
                        offset: 0,
                        property: "GraphQL servers must cap alias count and query complexity"
                            .into(),
                    }],
                });
            }
        }

        // Directive abuse for logic bypass
        static directive_re: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)@(?:deprecated|skip|include)\b").unwrap());
        let directive_count = directive_re.find_iter(&decoded).count();
        if directive_count > 0 {
            dets.push(L2Detection {
                detection_type: "graphql_directive_abuse".into(),
                confidence: (0.80 + (directive_count as f64 * 0.02).min(0.12)).min(0.92),
                detail: format!("GraphQL directive usage includes bypass-prone directives (count: {})", directive_count),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(100)].to_owned(),
                    interpretation: "Directives like @skip/@include/@deprecated can alter resolver and auth control flow".into(),
                    offset: 0,
                    property: "Authorization checks must be enforced independent of query directives".into(),
                }],
            });
        }

        // Fragment cycle: fragment A spreads B and fragment B spreads A
        static fragment_re: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)fragment\s+([A-Za-z_]\w*)\s+on\s+[A-Za-z_]\w*\s*\{([^}]*)\}").unwrap()
        });
        static spread_re: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\.\.\.([A-Za-z_]\w*)").unwrap());
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();
        for caps in fragment_re.captures_iter(&decoded) {
            if let (Some(name), Some(body)) = (caps.get(1), caps.get(2)) {
                let mut edges = Vec::new();
                for s in spread_re.captures_iter(body.as_str()) {
                    if let Some(to) = s.get(1) {
                        edges.push(to.as_str().to_owned());
                    }
                }
                graph.insert(name.as_str().to_owned(), edges);
            }
        }
        let mut has_cycle = false;
        for (src, edges) in &graph {
            for dst in edges {
                if graph
                    .get(dst)
                    .map(|b| b.iter().any(|x| x == src))
                    .unwrap_or(false)
                {
                    has_cycle = true;
                    break;
                }
            }
            if has_cycle {
                break;
            }
        }
        if has_cycle {
            dets.push(L2Detection {
                detection_type: "graphql_fragment_cycle".into(),
                confidence: 0.91,
                detail: "GraphQL fragments form a cyclic reference".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation:
                        "Fragment cycles can trigger parser recursion or expensive planning loops"
                            .into(),
                    offset: 0,
                    property: "Fragment dependency graph must be acyclic".into(),
                }],
            });
        }

        // Persisted query bypass: unknown/invalid sha256 hash with persistedQuery extension
        static PERSISTED_QUERY_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)"persistedQuery"\s*:"#).unwrap());
        static SHA256_HASH_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)"sha256Hash"\s*:\s*"([^"]+)""#).unwrap());
        if PERSISTED_QUERY_RE.is_match(&decoded) {
            let mut unknown_hash = false;
            if let Some(caps) = SHA256_HASH_RE.captures(&decoded) {
                if let Some(hash) = caps.get(1) {
                    let hv = hash.as_str().to_ascii_lowercase();
                    let valid_hex = hv.len() == 64 && hv.chars().all(|c| c.is_ascii_hexdigit());
                    if !valid_hex
                        || hv == "unknown"
                        || hv == "invalid"
                        || hv.chars().all(|c| c == '0')
                    {
                        unknown_hash = true;
                    }
                }
            } else {
                unknown_hash = true;
            }
            if unknown_hash {
                dets.push(L2Detection {
                    detection_type: "graphql_persisted_bypass".into(),
                    confidence: 0.88,
                    detail: "Persisted query extension uses unknown/invalid sha256Hash".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: decoded[..decoded.len().min(120)].to_owned(),
                        interpretation: "Client is attempting persisted-query flow without a recognized digest".into(),
                        offset: 0,
                        property: "Persisted queries must require pre-registered hashes and reject unknown digests".into(),
                    }],
                });
            }
        }

        // Combined mutation + introspection payload
        static MUTATION_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)\bmutation\b").unwrap());
        static INTROSPECTION_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)__schema\s*\{|__type\s*\(").unwrap());
        let has_mutation = MUTATION_RE.is_match(&decoded);
        let has_introspection = INTROSPECTION_RE.is_match(&decoded);
        if has_mutation && has_introspection {
            dets.push(L2Detection {
                detection_type: "graphql_mutation_introspection".into(),
                confidence: 0.93,
                detail: "Mutation request combines state change and introspection primitives".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "Combining mutation with introspection can support chained reconnaissance+impact attacks".into(),
                    offset: 0,
                    property: "Mutation execution paths must block introspection fields in production".into(),
                }],
            });
        }

        dets.extend(self.advanced_detections(&decoded));

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "graphql_introspection" | "graphql_suggestion" | "graphql_field_suggestion_exploit" => {
                Some(InvariantClass::GraphqlIntrospection)
            }
            "graphql_depth" | "graphql_batch" | "graphql_multi_operation_abuse" => {
                Some(InvariantClass::GraphqlBatchAbuse)
            }
            "graphql_directive_abuse"
            | "graphql_persisted_bypass"
            | "graphql_mutation_introspection" => Some(InvariantClass::GraphqlIntrospection),
            "graphql_alias_dos" | "graphql_fragment_cycle" | "graphql_alias_dos_extreme" => {
                Some(InvariantClass::GraphqlBatchAbuse)
            }
            "graphql_batch_abuse_advanced"
            | "graphql_field_duplication"
            | "graphql_fragment_cycle_deep"
            | "graphql_depth_bomb"
            | "graphql_alias_amplification"
            | "graphql_subscription_abuse"
            | "graphql_subscription_channel_abuse" => Some(InvariantClass::GraphqlBatchAbuse),
            "graphql_directive_excessive"
            | "graphql_persisted_apq_bypass"
            | "graphql_directive_malicious_condition" => Some(InvariantClass::GraphqlIntrospection),
            _ => None,
        }
    }
}

impl GraphqlEvaluator {
    fn advanced_detections(&self, decoded: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        if let Some(d) = self.detect_batched_query_abuse(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_field_duplication_attack(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_circular_fragment_deep(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_query_depth_bomb(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_alias_amplification(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_extreme_alias_dos(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_directive_abuse_excessive(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_malicious_directive_conditions(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_persisted_query_bypass_apq(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_subscription_abuse(decoded) {
            dets.push(d);
        }
        if let Some(d) = self.detect_subscription_channel_fanout(decoded) {
            dets.push(d);
        }
        dets
    }

    fn detect_batched_query_abuse(&self, decoded: &str) -> Option<L2Detection> {
        static BATCH_ARRAY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)^\s*\[\s*\{.*\}\s*(,\s*\{.*\}\s*)+\]\s*$"#).unwrap()
        });
        static OP_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)"(?:query|mutation|subscription)"\s*:"#).unwrap()
        });

        if !BATCH_ARRAY_RE.is_match(decoded) {
            return None;
        }

        let op_count = OP_KEY_RE.find_iter(decoded).count();
        if op_count < 2 {
            return None;
        }

        Some(L2Detection {
            detection_type: "graphql_batch_abuse_advanced".into(),
            confidence: (0.88 + ((op_count as f64) * 0.005).min(0.10)).min(0.96),
            detail: format!(
                "Batched GraphQL operations in a single request can bypass per-request rate limits (operations: {})",
                op_count
            ),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: decoded[..decoded.len().min(140)].to_owned(),
                interpretation: "A JSON array of GraphQL operations enables multiplexed execution in one HTTP request".into(),
                offset: 0,
                property: "Batch transport must enforce per-operation limits and authentication checks".into(),
            }],
        })
    }

    fn detect_field_duplication_attack(&self, decoded: &str) -> Option<L2Detection> {
        static FIELD_TOKEN_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\b").unwrap());
        let keywords = [
            "query",
            "mutation",
            "subscription",
            "fragment",
            "on",
            "true",
            "false",
            "null",
            "__schema",
            "__type",
            "__typename",
        ];

        let mut counts: HashMap<String, usize> = HashMap::new();
        for caps in FIELD_TOKEN_RE.captures_iter(decoded) {
            if let Some(token) = caps.get(1) {
                let t = token.as_str();
                if keywords.iter().any(|k| k.eq_ignore_ascii_case(t)) {
                    continue;
                }
                *counts.entry(t.to_ascii_lowercase()).or_insert(0) += 1;
            }
        }

        if let Some((field, count)) = counts.into_iter().max_by_key(|(_, c)| *c) {
            if count > 18 {
                return Some(L2Detection {
                    detection_type: "graphql_field_duplication".into(),
                    confidence: (0.86 + ((count as f64) * 0.002).min(0.10)).min(0.95),
                    detail: format!(
                        "Repeated field '{}' appears {} times and may amplify resolver and response cost",
                        field, count
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: decoded[..decoded.len().min(140)].to_owned(),
                        interpretation: "Field duplication can create superlinear execution and response amplification".into(),
                        offset: 0,
                        property: "Query complexity controls must include duplicate field penalties".into(),
                    }],
                });
            }
        }

        None
    }

    fn detect_circular_fragment_deep(&self, decoded: &str) -> Option<L2Detection> {
        let graph = Self::build_fragment_graph(decoded);
        if graph.is_empty() {
            return None;
        }
        if !Self::has_fragment_cycle(&graph) {
            return None;
        }

        Some(L2Detection {
            detection_type: "graphql_fragment_cycle_deep".into(),
            confidence: 0.95,
            detail: "Circular fragment dependency detected (transitive cycle)".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: decoded[..decoded.len().min(160)].to_owned(),
                interpretation: "Recursive fragment spreads can force unbounded planner recursion"
                    .into(),
                offset: 0,
                property: "Fragment spreads must be validated as a directed acyclic graph".into(),
            }],
        })
    }

    fn detect_query_depth_bomb(&self, decoded: &str) -> Option<L2Detection> {
        let mut depth = 0usize;
        let mut max_depth = 0usize;
        let mut first_overflow_offset = None;
        for (idx, ch) in decoded.char_indices() {
            if ch == '{' {
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
                if depth > 15 && first_overflow_offset.is_none() {
                    first_overflow_offset = Some(idx);
                }
            } else if ch == '}' {
                depth = depth.saturating_sub(1);
            }
        }

        if max_depth <= 15 {
            return None;
        }

        let offset = first_overflow_offset.unwrap_or(0);
        Some(L2Detection {
            detection_type: "graphql_depth_bomb".into(),
            confidence: (0.90 + ((max_depth as f64 - 15.0) * 0.004).min(0.08)).min(0.98),
            detail: format!(
                "GraphQL query nesting depth {} exceeds safe bound (>15)",
                max_depth
            ),
            position: offset,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: decoded[..decoded.len().min(140)].to_owned(),
                interpretation: "Excessive nesting drives deep resolver stacks and DoS risk".into(),
                offset,
                property: "Depth limits should hard-fail queries beyond 15 nested levels".into(),
            }],
        })
    }

    fn detect_alias_amplification(&self, decoded: &str) -> Option<L2Detection> {
        static ALIAS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\b([A-Za-z_]\w*)\s*:\s*([A-Za-z_]\w*)\b").unwrap()
        });

        let mut alias_targets: HashMap<String, usize> = HashMap::new();
        for caps in ALIAS_RE.captures_iter(decoded) {
            if let Some(target) = caps.get(2) {
                *alias_targets.entry(target.as_str().to_owned()).or_insert(0) += 1;
            }
        }

        if let Some((target, count)) = alias_targets.into_iter().max_by_key(|(_, c)| *c) {
            if count >= 100 {
                return Some(L2Detection {
                    detection_type: "graphql_alias_amplification".into(),
                    confidence: (0.92 + ((count as f64) * 0.0005).min(0.06)).min(0.98),
                    detail: format!(
                        "Alias amplification targets '{}' with {} aliases in one operation",
                        target, count
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: decoded[..decoded.len().min(160)].to_owned(),
                        interpretation: "Mass aliasing multiplies execution of the same resolver".into(),
                        offset: 0,
                        property: "Alias count per target field must be capped to prevent computation amplification".into(),
                    }],
                });
            }
        }

        None
    }

    fn detect_extreme_alias_dos(&self, decoded: &str) -> Option<L2Detection> {
        static ALIAS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\b([A-Za-z_]\w*)\s*:\s*([A-Za-z_]\w*)\b").unwrap()
        });

        let mut alias_targets: HashMap<String, usize> = HashMap::new();
        for caps in ALIAS_RE.captures_iter(decoded) {
            if let Some(target) = caps.get(2) {
                *alias_targets.entry(target.as_str().to_owned()).or_insert(0) += 1;
            }
        }

        if let Some((target, count)) = alias_targets.into_iter().max_by_key(|(_, c)| *c) {
            if count >= 1000 {
                return Some(L2Detection {
                    detection_type: "graphql_alias_dos_extreme".into(),
                    confidence: 0.99,
                    detail: format!("Extreme alias DoS against '{}' with {} aliases", target, count),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: decoded[..decoded.len().min(180)].to_owned(),
                        interpretation: "Massive alias fan-out can exhaust CPU/memory in a single GraphQL execution".into(),
                        offset: 0,
                        property: "Alias caps and complexity limits must hard-block extreme alias multiplicity".into(),
                    }],
                });
            }
        }
        None
    }

    fn detect_directive_abuse_excessive(&self, decoded: &str) -> Option<L2Detection> {
        static SKIP_INCLUDE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)@(?:skip|include)\b").unwrap());
        let directive_count = SKIP_INCLUDE_RE.find_iter(decoded).count();
        if directive_count <= 20 {
            return None;
        }

        Some(L2Detection {
            detection_type: "graphql_directive_excessive".into(),
            confidence: (0.87 + ((directive_count as f64) * 0.002).min(0.09)).min(0.96),
            detail: format!(
                "Excessive conditional directives detected (@skip/@include count: {})",
                directive_count
            ),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: decoded[..decoded.len().min(160)].to_owned(),
                interpretation: "High conditional directive density can obscure true complexity and authorization paths".into(),
                offset: 0,
                property: "Complexity analysis should weight @skip/@include usage and enforce directive limits".into(),
            }],
        })
    }

    fn detect_malicious_directive_conditions(&self, decoded: &str) -> Option<L2Detection> {
        static MALICIOUS_DIRECTIVE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(
                r#"(?i)@(?:skip|include)\s*\(\s*if\s*:\s*(?:"[^"]+"|\{[^}]*\}|\[[^\]]*\]|-?\d+|null)\s*\)"#,
            )
            .unwrap()
            },
        );

        if let Some(m) = MALICIOUS_DIRECTIVE_RE.find(decoded) {
            return Some(L2Detection {
                detection_type: "graphql_directive_malicious_condition".into(),
                confidence: 0.89,
                detail: "Directive condition uses suspicious non-boolean literal/structure".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Malformed directive conditions can stress parser/validation and obscure logic gates".into(),
                    offset: m.start(),
                    property: "Directive if arguments should be strict booleans or validated variables only".into(),
                }],
            });
        }
        None
    }

    fn detect_persisted_query_bypass_apq(&self, decoded: &str) -> Option<L2Detection> {
        static PERSISTED_QUERY_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)"persistedQuery"\s*:"#).unwrap());
        static QUERY_BODY_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)"query"\s*:\s*"\s*[^"]"#).unwrap());
        static SHA256_HASH_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)"sha256Hash"\s*:\s*"([^"]*)""#).unwrap());

        if !PERSISTED_QUERY_RE.is_match(decoded) {
            return None;
        }

        let has_inline_query = QUERY_BODY_RE.is_match(decoded);
        let mut manipulated_hash = true;
        if let Some(caps) = SHA256_HASH_RE.captures(decoded) {
            if let Some(hash) = caps.get(1) {
                let hv = hash.as_str().to_ascii_lowercase();
                manipulated_hash = hv.len() != 64
                    || !hv.chars().all(|c| c.is_ascii_hexdigit())
                    || hv.chars().all(|c| c == '0');
            }
        }

        if !has_inline_query || !manipulated_hash {
            return None;
        }

        Some(L2Detection {
            detection_type: "graphql_persisted_apq_bypass".into(),
            confidence: 0.94,
            detail: "APQ bypass attempt: inline query supplied with manipulated persisted-query hash".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::TypeCoerce,
                matched_input: decoded[..decoded.len().min(180)].to_owned(),
                interpretation: "Supplying executable query text in APQ flow can bypass persisted-only policy".into(),
                offset: 0,
                property: "Persisted-only mode must reject inline query text and strictly validate APQ hash registration".into(),
            }],
        })
    }

    fn detect_subscription_abuse(&self, decoded: &str) -> Option<L2Detection> {
        static SUB_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)\bsubscription\b").unwrap());
        static FIELD_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\b").unwrap());
        if !SUB_RE.is_match(decoded) {
            return None;
        }

        let wildcard = decoded.contains('*');
        let has_introspection = decoded.contains("__schema") || decoded.contains("__type");
        let field_count = FIELD_RE.find_iter(decoded).count();
        let excessive_selection = field_count > 50;
        if !wildcard && !has_introspection && !excessive_selection {
            return None;
        }

        Some(L2Detection {
            detection_type: "graphql_subscription_abuse".into(),
            confidence: 0.93,
            detail: format!(
                "Suspicious subscription pattern (wildcard: {}, field_count: {}, introspection: {})",
                wildcard, field_count, has_introspection
            ),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: decoded[..decoded.len().min(180)].to_owned(),
                interpretation: "Broad subscription selection can pin long-lived high-cost streams"
                    .into(),
                offset: 0,
                property:
                    "Subscription queries require strict field allowlists and complexity budgets"
                        .into(),
            }],
        })
    }

    fn detect_subscription_channel_fanout(&self, decoded: &str) -> Option<L2Detection> {
        static SUB_HEADER_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)\bsubscription\b").unwrap());
        static ROOT_FIELD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::|\(|\{)").unwrap()
        });
        if !SUB_HEADER_RE.is_match(decoded) {
            return None;
        }

        let root_block = decoded
            .find('{')
            .and_then(|start| Self::extract_braced_block(decoded, start));
        let Some(root_block) = root_block else {
            return None;
        };
        let channel_count = ROOT_FIELD_RE.find_iter(root_block).count();
        if channel_count <= 30 {
            return None;
        }

        Some(L2Detection {
            detection_type: "graphql_subscription_channel_abuse".into(),
            confidence: (0.90 + ((channel_count as f64) * 0.001).min(0.08)).min(0.98),
            detail: format!(
                "Subscription requests excessive channels/fields (count: {})",
                channel_count
            ),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: decoded[..decoded.len().min(180)].to_owned(),
                interpretation:
                    "Large subscription fan-out can create long-lived high-cardinality streams"
                        .into(),
                offset: 0,
                property:
                    "Subscription root-field/channel fan-out must be capped per client request"
                        .into(),
            }],
        })
    }

    fn build_fragment_graph(decoded: &str) -> HashMap<String, Vec<String>> {
        static FRAGMENT_HEADER_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r"(?i)fragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+[A-Za-z_][A-Za-z0-9_]*\s*\{",
            )
            .unwrap()
        });
        static SPREAD_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\.\.\.([A-Za-z_][A-Za-z0-9_]*)").unwrap());

        let mut graph = HashMap::new();
        for caps in FRAGMENT_HEADER_RE.captures_iter(decoded) {
            if let Some(header_match) = caps.get(0) {
                let body_start = header_match.end().saturating_sub(1);
                if let Some(body) = Self::extract_braced_block(decoded, body_start) {
                    if let Some(name) = caps.get(1) {
                        let mut edges = Vec::new();
                        for spread in SPREAD_RE.captures_iter(body) {
                            if let Some(spread_name) = spread.get(1) {
                                edges.push(spread_name.as_str().to_owned());
                            }
                        }
                        graph.insert(name.as_str().to_owned(), edges);
                    }
                }
            }
        }
        graph
    }

    fn extract_braced_block<'a>(decoded: &'a str, opening_brace_idx: usize) -> Option<&'a str> {
        let bytes = decoded.as_bytes();
        if bytes.get(opening_brace_idx).copied()? != b'{' {
            return None;
        }
        let mut depth = 0usize;
        let mut body_start = None;
        for (idx, ch) in decoded
            .char_indices()
            .skip_while(|(i, _)| *i < opening_brace_idx)
        {
            if ch == '{' {
                depth += 1;
                if depth == 1 {
                    body_start = Some(idx + 1);
                }
            } else if ch == '}' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if let Some(start) = body_start {
                        return decoded.get(start..idx);
                    }
                    return None;
                }
            }
        }
        None
    }

    fn has_fragment_cycle(graph: &HashMap<String, Vec<String>>) -> bool {
        fn dfs(
            node: &str,
            graph: &HashMap<String, Vec<String>>,
            visit: &mut HashMap<String, u8>,
        ) -> bool {
            let state = *visit.get(node).unwrap_or(&0);
            if state == 1 {
                return true;
            }
            if state == 2 {
                return false;
            }
            visit.insert(node.to_owned(), 1);
            if let Some(edges) = graph.get(node) {
                for next in edges {
                    if dfs(next, graph, visit) {
                        return true;
                    }
                }
            }
            visit.insert(node.to_owned(), 2);
            false
        }

        let mut visit: HashMap<String, u8> = HashMap::new();
        for node in graph.keys() {
            if dfs(node, graph, &mut visit) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_alias_based_dos() {
        let eval = GraphqlEvaluator;
        let input = "{ a1: expensiveField a2: expensiveField a3: expensiveField a4: expensiveField a5: expensiveField a6: expensiveField }";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "graphql_alias_dos"));
    }

    #[test]
    fn detects_directive_abuse() {
        let eval = GraphqlEvaluator;
        let input = r#"{"query":"query Q { users @skip(if:true) @include(if:false) { id } }"}"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_directive_abuse")
        );
    }

    #[test]
    fn detects_fragment_cycle() {
        let eval = GraphqlEvaluator;
        let input =
            r#"fragment A on User { ...B } fragment B on User { ...A } query { user { ...A } }"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_fragment_cycle")
        );
    }

    #[test]
    fn detects_persisted_query_bypass_unknown_hash() {
        let eval = GraphqlEvaluator;
        let input = r#"{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"unknown"}}}"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_persisted_bypass")
        );
    }

    #[test]
    fn detects_mutation_with_introspection_combo() {
        let eval = GraphqlEvaluator;
        let input =
            r#"mutation { updateUser(id:1,data:{name:"x"}) { id } __schema { types { name } } }"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_mutation_introspection")
        );
    }

    #[test]
    fn detects_advanced_batch_abuse_array_transport() {
        let eval = GraphqlEvaluator;
        let input = r#"[{"query":"query { a }"},{"query":"query { b }"}]"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_batch_abuse_advanced")
        );
    }

    #[test]
    fn detects_field_duplication_attack() {
        let eval = GraphqlEvaluator;
        let input = "query { user { id profile profile profile profile profile profile profile profile profile profile profile profile profile profile profile profile profile profile profile profile } }";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_field_duplication")
        );
    }

    #[test]
    fn detects_transitive_fragment_cycle() {
        let eval = GraphqlEvaluator;
        let input = r#"fragment A on User { ...B } fragment B on User { ...C } fragment C on User { ...A } query { user { ...A } }"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_fragment_cycle_deep")
        );
    }

    #[test]
    fn detects_depth_bomb_over_15() {
        let eval = GraphqlEvaluator;
        let input = "query { a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { p { id } } } } } } } } } } } } } } } }";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_depth_bomb")
        );
    }

    #[test]
    fn detects_alias_amplification_hundreds() {
        let eval = GraphqlEvaluator;
        let mut aliases = String::new();
        for idx in 0..120 {
            aliases.push_str(&format!("a{}: expensive ", idx));
        }
        let input = format!("query {{ {} }}", aliases);
        let dets = eval.detect(&input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_alias_amplification")
        );
    }

    #[test]
    fn detects_excessive_skip_include_directives() {
        let eval = GraphqlEvaluator;
        let mut directives = String::new();
        for _ in 0..24 {
            directives.push_str(" @skip(if:true)");
        }
        let input = format!("query {{ users{} {{ id }} }}", directives);
        let dets = eval.detect(&input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_directive_excessive")
        );
    }

    #[test]
    fn detects_apq_bypass_with_inline_query_and_bad_hash() {
        let eval = GraphqlEvaluator;
        let input = r#"{"query":"query { adminSecrets { id } }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"0000000000000000000000000000000000000000000000000000000000000000"}}}"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_persisted_apq_bypass")
        );
    }

    #[test]
    fn detects_subscription_abuse_wildcard_pattern() {
        let eval = GraphqlEvaluator;
        let input = r#"subscription WatchAll { events(filter:"*") { id type payload actor timestamp metadata details } }"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_subscription_abuse")
        );
    }

    #[test]
    fn detects_multi_operation_abuse_single_payload() {
        let eval = GraphqlEvaluator;
        let input = r#"query A { a } mutation B { b } query C { c }"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_multi_operation_abuse")
        );
    }

    #[test]
    fn detects_field_suggestion_exploit_from_error_text() {
        let eval = GraphqlEvaluator;
        let input = r#"{"errors":[{"message":"Cannot query field \"admn\" on type \"Query\". Did you mean \"admin\"?"}]}"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_field_suggestion_exploit")
        );
    }

    #[test]
    fn detects_extreme_alias_dos_thousand_aliases() {
        let eval = GraphqlEvaluator;
        let mut aliases = String::new();
        for idx in 0..1005 {
            aliases.push_str(&format!("a{}: expensive ", idx));
        }
        let input = format!("query {{ {} }}", aliases);
        let dets = eval.detect(&input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_alias_dos_extreme")
        );
    }

    #[test]
    fn detects_malicious_directive_condition_string_literal() {
        let eval = GraphqlEvaluator;
        let input = r#"query { users @skip(if:"true") { id } }"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_directive_malicious_condition")
        );
    }

    #[test]
    fn detects_malicious_directive_condition_object_literal() {
        let eval = GraphqlEvaluator;
        let input = r#"query { users @include(if:{force:true}) { id } }"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_directive_malicious_condition")
        );
    }

    #[test]
    fn detects_subscription_channel_fanout_abuse() {
        let eval = GraphqlEvaluator;
        let mut fields = String::new();
        for idx in 0..40 {
            fields.push_str(&format!("c{}: channel{} {{ id }} ", idx, idx));
        }
        let input = format!("subscription Flood {{ {} }}", fields);
        let dets = eval.detect(&input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "graphql_subscription_channel_abuse")
        );
    }

    #[test]
    fn map_class_handles_new_graphql_types() {
        let eval = GraphqlEvaluator;
        assert_eq!(
            eval.map_class("graphql_multi_operation_abuse"),
            Some(InvariantClass::GraphqlBatchAbuse)
        );
        assert_eq!(
            eval.map_class("graphql_field_suggestion_exploit"),
            Some(InvariantClass::GraphqlIntrospection)
        );
        assert_eq!(
            eval.map_class("graphql_directive_malicious_condition"),
            Some(InvariantClass::GraphqlIntrospection)
        );
    }

    #[test]
    fn does_not_flag_directive_condition_for_boolean_literal() {
        let eval = GraphqlEvaluator;
        let input = r#"query { users @skip(if:true) { id } }"#;
        let dets = eval.detect(input);
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "graphql_directive_malicious_condition")
        );
    }
}
