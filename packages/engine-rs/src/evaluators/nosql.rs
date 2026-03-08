//! NoSQL Injection Evaluator — L2 Detection
//!
//! Detects MongoDB operator injection ($gt, $ne, $where, $regex),
//! JSON injection structures, and JavaScript execution in NoSQL context.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use serde_json::Value;

// Reserved for future use: operator allowlist validation
#[allow(dead_code)]
const MONGO_OPERATORS: &[&str] = &[
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$ne",
    "$nin",
    "$in",
    "$exists",
    "$regex",
    "$where",
    "$elemMatch",
    "$not",
    "$or",
    "$and",
    "$nor",
    "$type",
    "$mod",
    "$all",
    "$size",
    "$expr",
];

const DANGEROUS_OPERATORS: &[&str] = &["$where", "$regex", "$expr"];

const DANGEROUS_PIPELINES: &[&str] = &[
    "$lookup",
    "$graphLookup",
    "$merge",
    "$out",
    "$unionWith",
    "$function",
];

const EXFIL_PIPELINES: &[&str] = &["$lookup", "$merge", "$out"];

pub struct NoSqlEvaluator;

impl L2Evaluator for NoSqlEvaluator {
    fn id(&self) -> &'static str {
        "nosql"
    }
    fn prefix(&self) -> &'static str {
        "L2 NoSQL"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // MongoDB operator injection: {"$gt": ""} or $ne
        static op_re: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"\$(?:gt|gte|lt|lte|ne|nin|in|exists|regex|where|elemMatch|not|or|and|nor|type|mod|all|size|expr)\b"#).unwrap()
        });
        for m in op_re.find_iter(&decoded) {
            let op = m.as_str();
            let is_dangerous = DANGEROUS_OPERATORS.contains(&op);

            dets.push(L2Detection {
                detection_type: if is_dangerous {
                    "nosql_code_exec"
                } else {
                    "nosql_operator"
                }
                .into(),
                confidence: if is_dangerous { 0.90 } else { 0.82 },
                detail: format!("MongoDB operator injection: {}", op),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: op.to_owned(),
                    interpretation: format!("NoSQL query operator {} modifies query logic", op),
                    offset: m.start(),
                    property: "User input must not inject NoSQL query operators".into(),
                }],
            });
        }

        // Explicit operator object values like: {field: {$gt: ""}}
        static JSON_OPERATOR_VALUE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?is)\{\s*[^\{\}]{0,260}:\s*\{\s*(?:"|')?(\$[a-zA-Z][a-zA-Z0-9_]+)"#)
                    .unwrap()
            });
        let json_operator_value = &*JSON_OPERATOR_VALUE_RE;
        for caps in json_operator_value.captures_iter(&decoded) {
            if let Some(opm) = caps.get(1) {
                let op = opm.as_str();
                if dets
                    .iter()
                    .any(|d| d.detail.contains(op) && d.position == opm.start())
                {
                    continue;
                }
                dets.push(L2Detection {
                    detection_type: "nosql_operator".into(),
                    confidence: 0.84,
                    detail: format!("MongoDB JSON value operator key detected: {}", op),
                    position: opm.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: op.to_owned(),
                        interpretation: format!(
                            "Query object value starts a MongoDB operator {}",
                            op
                        ),
                        offset: opm.start(),
                        property: "User input must not inject operator keys in NoSQL values".into(),
                    }],
                });
            }
        }

        // JSON structure injection: {"$gt": ""}
        static JSON_INJECT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"\{[^}]*"\$[a-z]+"#).unwrap());
        let json_inject = &*JSON_INJECT_RE;
        if json_inject.is_match(&decoded) && dets.is_empty() {
            dets.push(L2Detection {
                detection_type: "nosql_operator".into(),
                confidence: 0.80,
                detail: "JSON object with MongoDB operator syntax".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(80)].to_owned(),
                    interpretation: "JSON structure contains NoSQL query operators".into(),
                    offset: 0,
                    property: "User input must not inject NoSQL query operators".into(),
                }],
            });
        }

        // JavaScript in $where context
        static JS_WHERE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)\$where\s*:\s*['"]?(?:function|this\.|return\s)"#).unwrap()
        });
        let js_where = &*JS_WHERE_RE;
        if let Some(m) = js_where.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "nosql_code_exec".into(),
                confidence: 0.92,
                detail: "JavaScript execution via $where operator".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "JavaScript code injected into $where context".into(),
                    offset: m.start(),
                    property: "User input must not inject executable code into NoSQL queries"
                        .into(),
                }],
            });
        }

        // Regex operator abuse and potential ReDoS-style patterns
        static REGEX_OPS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)\$regex\s*:\s*(?:"([^"]*)"|'([^']*)')"#).unwrap()
        });
        let regex_ops = &*REGEX_OPS_RE;
        for caps in regex_ops.captures_iter(&decoded) {
            let pattern = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|g| g.as_str())
                .unwrap_or("");
            let confidence =
                if pattern.contains(".*") || pattern.contains("(.+") || pattern.contains("{") {
                    0.87
                } else {
                    0.82
                };
            dets.push(L2Detection {
                detection_type: "nosql_operator".into(),
                confidence,
                detail: format!("MongoDB regex operator with injected pattern: {}", pattern),
                position: caps.get(0).map(|m| m.start()).unwrap_or(0),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: caps
                        .get(0)
                        .map(|m| m.as_str().to_owned())
                        .unwrap_or_default(),
                    interpretation: "User-controlled regex pattern is injected into NoSQL query"
                        .into(),
                    offset: caps.get(0).map(|m| m.start()).unwrap_or(0),
                    property:
                        "NoSQL regex operators must reject untrusted user-controlled patterns"
                            .into(),
                }],
            });
        }

        // Timing attacks via $where + sleep()
        static where_sleep: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)\$where\b[^\n\r}]{0,400}(sleep\(|thread\.sleep|java\.lang\.Thread\.sleep|Date\.now\(\)\s*\+\s*\d+)"#).unwrap()
        });
        if let Some(m) = where_sleep.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "nosql_code_exec".into(),
                confidence: 0.94,
                detail: "Potential NoSQL timing attack via $where sleep/function call".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "$where expression invokes timing-oriented code".into(),
                    offset: m.start(),
                    property: "NoSQL operators must reject JS expressions with execution or timing side-effects".into(),
                }],
            });
        }

        // Aggregation pipeline operator injection
        static PIPELINE_INJECTION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)\[\s*\{\s*(?:"|')?(\$[a-zA-Z][a-zA-Z0-9]*)"#).unwrap()
        });
        let pipeline_injection = &*PIPELINE_INJECTION_RE;
        for caps in pipeline_injection.captures_iter(&decoded) {
            let op = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if !op.is_empty() {
                let is_pipeline = DANGEROUS_PIPELINES.contains(&op);
                let confidence = if is_pipeline { 0.93 } else { 0.82 };
                if is_pipeline {
                    dets.push(L2Detection {
                        detection_type: "nosql_code_exec".into(),
                        confidence,
                        detail: format!("Dangerous aggregation pipeline stage detected: {}", op),
                        position: caps.get(0).map(|m| m.start()).unwrap_or(0),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: caps.get(0).map(|m| m.as_str().to_owned()).unwrap_or_default(),
                            interpretation: format!("Agg pipeline stage {} can alter query execution semantics", op),
                            offset: caps.get(0).map(|m| m.start()).unwrap_or(0),
                            property: "NoSQL aggregation pipelines must not accept untrusted pipeline stages".into(),
                        }],
                    });
                }
            }
        }

        // Explicit MongoDB exfiltration-oriented pipeline stages: $lookup/$merge/$out
        static MONGO_EXFIL_PIPELINE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?is)(?:"|')(\$(?:lookup|merge|out))(?:"|')\s*:"#).unwrap()
            });
        for caps in MONGO_EXFIL_PIPELINE_RE.captures_iter(&decoded) {
            let stage = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if !stage.is_empty() && EXFIL_PIPELINES.contains(&stage) {
                let pos = caps.get(1).map(|m| m.start()).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "nosql_code_exec".into(),
                    confidence: 0.95,
                    detail: format!("MongoDB aggregation exfiltration stage injection: {}", stage),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: caps.get(0).map(|m| m.as_str().to_owned()).unwrap_or_default(),
                        interpretation: format!("Pipeline stage {} can join/write data and facilitate exfiltration", stage),
                        offset: pos,
                        property: "MongoDB aggregation pipelines must block untrusted exfiltration-oriented stages".into(),
                    }],
                });
            }
        }

        // MongoDB JavaScript injection via $where function() payloads
        static MONGO_WHERE_FUNCTION_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?is)\$where\s*[:=]\s*['"]?\s*function\s*\("#).unwrap()
            });
        if let Some(m) = MONGO_WHERE_FUNCTION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "nosql_code_exec".into(),
                confidence: 0.96,
                detail: "MongoDB JavaScript injection via $where function()".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "$where accepts executable JavaScript function bodies".into(),
                    offset: m.start(),
                    property: "MongoDB $where must reject user-controlled function bodies".into(),
                }],
            });
        }

        // MongoDB server-side JavaScript operators: $accumulator and $function
        static MONGO_JS_OPERATORS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:"|')(\$(?:accumulator|function))(?:"|')\s*:"#).unwrap()
        });
        for caps in MONGO_JS_OPERATORS_RE.captures_iter(&decoded) {
            let op = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if !op.is_empty() {
                let pos = caps.get(1).map(|m| m.start()).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "nosql_code_exec".into(),
                    confidence: 0.95,
                    detail: format!("MongoDB JavaScript operator injection detected: {}", op),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: caps.get(0).map(|m| m.as_str().to_owned()).unwrap_or_default(),
                        interpretation: format!("{} enables execution of user-controlled JavaScript in aggregation context", op),
                        offset: pos,
                        property: "MongoDB JS-capable operators must reject untrusted input".into(),
                    }],
                });
            }
        }

        // Redis command injection via Lua eval interfaces
        static REDIS_EVAL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)\b(?:EVALSHA?|EVAL)\b\s+(?:"[^"\r\n]{0,500}(?:redis\.call|loadstring|os\.execute|package\.loadlib|io\.popen)[^"\r\n]{0,500}"|'[^'\r\n]{0,500}(?:redis\.call|loadstring|os\.execute|package\.loadlib|io\.popen)[^'\r\n]{0,500}')"#).unwrap()
        });
        for caps in REDIS_EVAL_RE.captures_iter(&decoded) {
            let full = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            if !full.is_empty() {
                let pos = caps.get(0).map(|m| m.start()).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "nosql_code_exec".into(),
                    confidence: 0.96,
                    detail: "Redis Lua script injection via EVAL/EVALSHA".into(),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: full.to_owned(),
                        interpretation: "Injected Redis Lua script may execute privileged commands"
                            .into(),
                        offset: pos,
                        property: "Redis EVAL/EVALSHA must never run user-controlled scripts"
                            .into(),
                    }],
                });
            }
        }

        // Redis CONFIG SET abuse often used to pivot to RCE primitives
        static REDIS_CONFIG_SET_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)\bCONFIG\s+SET\b\s+(?:dir|dbfilename|appendfilename|requirepass)\b"#)
                .unwrap()
        });
        if let Some(m) = REDIS_CONFIG_SET_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "nosql_code_exec".into(),
                confidence: 0.93,
                detail: "Redis CONFIG SET command injection".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "CONFIG SET modifies Redis runtime configuration and can enable command abuse".into(),
                    offset: m.start(),
                    property: "Redis administrative commands must not be user-influenced".into(),
                }],
            });
        }

        // Cassandra CQL injection: ALLOW FILTERING often indicates unsafe query composition
        static CASSANDRA_ALLOW_FILTERING_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?is)\bALLOW\s+FILTERING\b"#).unwrap());
        if let Some(m) = CASSANDRA_ALLOW_FILTERING_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "nosql_operator".into(),
                confidence: 0.88,
                detail: "Cassandra CQL injection pattern: ALLOW FILTERING abuse".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "ALLOW FILTERING in user-driven CQL can bypass intended query constraints"
                            .into(),
                    offset: m.start(),
                    property: "CQL clauses must not be user-controlled".into(),
                }],
            });
        }

        // Cassandra UDF/UDA injection via CREATE FUNCTION / CREATE AGGREGATE with language/runtime body
        static CASSANDRA_UDF_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|AGGREGATE)\b[^\n;]{0,350}\b(?:LANGUAGE|AS)\b"#).unwrap()
        });
        if let Some(m) = CASSANDRA_UDF_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "nosql_code_exec".into(),
                confidence: 0.94,
                detail: "Cassandra UDF/UDA injection pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "User-influenced CREATE FUNCTION/AGGREGATE may introduce executable UDF logic".into(),
                    offset: m.start(),
                    property: "Cassandra UDF/UDA definitions must not include untrusted input".into(),
                }],
            });
        }

        // DynamoDB expression injection via FilterExpression / ConditionExpression payloads
        static DYNAMODB_FILTER_EXPR_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r#"(?is)\b(FilterExpression|ConditionExpression)\b\s*[:=]\s*['"][^'"]{0,220}(?:\bOR\b|\bAND\b|\(|\)|contains\(|begins_with\(|size\()"#).unwrap()
            },
        );
        for caps in DYNAMODB_FILTER_EXPR_RE.captures_iter(&decoded) {
            let expr_key = caps
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or("FilterExpression");
            let pos = caps.get(0).map(|m| m.start()).unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "nosql_operator".into(),
                confidence: 0.89,
                detail: format!("DynamoDB expression injection via {}", expr_key),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: caps.get(0).map(|m| m.as_str().to_owned()).unwrap_or_default(),
                    interpretation: format!("{} appears to include user-controlled expression logic", expr_key),
                    offset: pos,
                    property: "DynamoDB expressions must be parameterized and not concatenated from user input".into(),
                }],
            });
        }

        // DynamoDB existence-check abuse via attribute_exists / attribute_not_exists
        static DYNAMODB_ATTR_EXISTS_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?is)\b(attribute_exists|attribute_not_exists)\s*\("#).unwrap()
            });
        for caps in DYNAMODB_ATTR_EXISTS_RE.captures_iter(&decoded) {
            let fn_name = caps
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or("attribute_exists");
            let pos = caps.get(0).map(|m| m.start()).unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "nosql_operator".into(),
                confidence: 0.87,
                detail: format!("DynamoDB conditional existence abuse via {}", fn_name),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: caps
                        .get(0)
                        .map(|m| m.as_str().to_owned())
                        .unwrap_or_default(),
                    interpretation: format!(
                        "{} can be abused when condition expressions are user-controlled",
                        fn_name
                    ),
                    offset: pos,
                    property: "DynamoDB conditional functions must not be directly user-injected"
                        .into(),
                }],
            });
        }

        // Additional time-based NoSQL blind injection patterns in JS contexts
        static NOSQL_TIME_BLIND_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:\$where|function\s*\(|\bthis\.)[^\n\r}]{0,500}(?:sleep\(\s*\d+\s*\)|setTimeout\s*\(|while\s*\(\s*Date\.now\(\)\s*<\s*Date\.now\(\)\s*\+\s*\d+\s*\)|new\s+Date\(\)\.getTime\(\)\s*\+\s*\d+)"#).unwrap()
        });
        for m in NOSQL_TIME_BLIND_RE.find_iter(&decoded) {
            dets.push(L2Detection {
                detection_type: "nosql_code_exec".into(),
                confidence: 0.95,
                detail: "Time-based blind NoSQL injection pattern in JavaScript query context"
                    .into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Detected timing primitive consistent with blind NoSQL injection probing"
                            .into(),
                    offset: m.start(),
                    property:
                        "NoSQL JS execution contexts must reject timing primitives from user input"
                            .into(),
                }],
            });
        }

        // JSON parse sanity check for nested operator keys anywhere in object values
        if let Ok(value) = serde_json::from_str::<Value>(&decoded) {
            collect_nested_ops(&value, &mut dets);
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "nosql_operator" => Some(InvariantClass::NosqlOperatorInjection),
            "nosql_code_exec" => Some(InvariantClass::NosqlJsInjection),
            _ => None,
        }
    }
}

fn collect_nested_ops(value: &Value, dets: &mut Vec<L2Detection>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if key.starts_with('$') {
                    dets.push(L2Detection {
                        detection_type: "nosql_operator".into(),
                        confidence: 0.90,
                        detail: format!("Nested JSON key injection via operator key {}", key),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: key.to_owned(),
                            interpretation: format!("Nested object contains operator key {}", key),
                            offset: 0,
                            property:
                                "JSON keys starting with $ must be validated in NoSQL query context"
                                    .into(),
                        }],
                    });
                }
                collect_nested_ops(nested, dets);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_nested_ops(item, dets);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InvariantClass;

    fn detect_classes(input: &str) -> Vec<InvariantClass> {
        let dets = NoSqlEvaluator.detect(input);
        dets.into_iter()
            .filter_map(|d| match d.detection_type.as_str() {
                "nosql_operator" => Some(InvariantClass::NosqlOperatorInjection),
                "nosql_code_exec" => Some(InvariantClass::NosqlJsInjection),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn detects_json_operator_value_pattern() {
        let input = r#"{"user":{"$gt":""},"active":true}"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlOperatorInjection)
        );
    }

    #[test]
    fn detects_pipeline_lookup_and_timing_where() {
        let input = r#"[{"$lookup":{"from":"users","pipeline":[{"$match":{"role":"admin"}}]}},{"$where":"sleep(1000)"}]"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlOperatorInjection)
        );
    }

    #[test]
    fn detects_mongo_exfil_lookup_stage() {
        let input = r#"[{"$lookup":{"from":"payments","localField":"uid","foreignField":"uid","as":"leak"}}]"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
    }

    #[test]
    fn detects_mongo_exfil_merge_stage() {
        let input = r#"[{"$merge":{"into":"archive_admin_dump"}}]"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
    }

    #[test]
    fn detects_mongo_where_function_injection() {
        let input = r#"{"$where":"function(){ return this.role == 'admin'; }"}"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
    }

    #[test]
    fn detects_mongo_accumulator_or_function_operator() {
        let input = r#"[{"$project":{"x":{"$function":{"body":"function(v){return v}","args":["$a"],"lang":"js"}}}}]"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
    }

    #[test]
    fn detects_redis_eval_lua_injection() {
        let input = r#"EVAL "return redis.call('CONFIG','GET','dir')" 0"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
    }

    #[test]
    fn detects_redis_config_set_rce_pattern() {
        let input = "CONFIG SET dir /var/spool/cron";
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
    }

    #[test]
    fn detects_cassandra_allow_filtering_abuse() {
        let input = "SELECT * FROM users WHERE token = 'x' ALLOW FILTERING";
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlOperatorInjection)
        );
    }

    #[test]
    fn detects_cassandra_udf_injection() {
        let input = "CREATE FUNCTION ks.exec(v text) RETURNS NULL ON NULL INPUT RETURNS text LANGUAGE javascript AS $$return v$$;";
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
    }

    #[test]
    fn detects_dynamodb_filter_expression_injection() {
        let input = r#"{"FilterExpression":"username = :u OR attribute_exists(isAdmin)"}"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlOperatorInjection)
        );
    }

    #[test]
    fn detects_dynamodb_attribute_exists_abuse() {
        let input = r#"ConditionExpression='attribute_not_exists(deletedAt)'"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlOperatorInjection)
        );
    }

    #[test]
    fn detects_time_based_blind_nosql_injection_patterns() {
        let input =
            r#"{"$where":"function(){ while(Date.now() < Date.now()+5000){}; return true; }"}"#;
        let classes = detect_classes(input);
        assert!(
            classes
                .iter()
                .any(|c| *c == InvariantClass::NosqlJsInjection)
        );
    }
}
