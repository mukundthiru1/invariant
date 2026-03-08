//! Prototype Pollution Evaluator — L2 Detection

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct ProtoPollutionEvaluator;

// Additional precompiled patterns for advanced prototype pollution evasions.
static CONSTRUCTOR_PROTO_BRACKET_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(
        r#"(?is)(?:constructor\s*(?:\[\s*["']prototype["']\s*\]|\.\s*prototype)|\[\s*["']constructor["']\s*\]\s*\[\s*["']prototype["']\s*\])\s*(?:\[|\.)"#,
    )
    .unwrap()
});
static OBJECT_ASSIGN_PROTO_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?is)Object\.assign\s*\([^)]{0,260}(?:__proto__|["']__proto__["'])"#).unwrap()
});
static JSON_PARSE_PROTO_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?is)JSON\.parse\s*\([^)]{0,320}__proto__[^)]{0,320}\)"#).unwrap()
});
static LIB_MERGE_POLLUTION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?is)(?:_\.merge|lodash\.merge|\$\.extend|jQuery\.extend|deepmerge)\s*\([^)]{0,260}(?:__proto__|constructor(?:\s*[\[.]\s*prototype)?)"#).unwrap()
});
static ARRAY_INDEX_POLLUTION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?is)(?:__proto__|constructor\s*[\[.]\s*prototype)\s*\[\s*\d+\s*\]"#).unwrap()
});
static SYMBOL_HAS_INSTANCE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?is)(?:__proto__|prototype|constructor\s*[\[.]\s*prototype)[^\n\r;]{0,180}Symbol\s*\.\s*hasInstance"#).unwrap()
});

impl L2Evaluator for ProtoPollutionEvaluator {
    fn id(&self) -> &'static str { "proto_pollution" }
    fn prefix(&self) -> &'static str { "L2 ProtoPollution" }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // __proto__ property access
        static proto: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?:__proto__|prototype)\s*[\[.]").unwrap());
        if let Some(m) = proto.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_access".into(),
                confidence: 0.90,
                detail: format!("Prototype chain access: {}", &decoded[m.start()..decoded.len().min(m.start() + 60)]),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Direct __proto__ or prototype access modifies object prototype chain".into(),
                    offset: m.start(),
                    property: "User input must not access or modify object prototype chain".into(),
                }],
            });
        }

        // JSON with __proto__: {"__proto__": {"isAdmin": true}}
        static JSON_PROTO_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"["']__proto__["']\s*:"#).unwrap());
        let json_proto = &*JSON_PROTO_RE;
        if let Some(m) = json_proto.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_json".into(),
                confidence: 0.92,
                detail: "JSON prototype pollution via __proto__ key".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "JSON key __proto__ pollutes Object.prototype on merge/assign".into(),
                    offset: m.start(),
                    property: "User-supplied JSON must not contain prototype-polluting keys".into(),
                }],
            });
        }

        // constructor.prototype
        static constructor: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"constructor\s*[\[.]\s*prototype").unwrap());
        if let Some(m) = constructor.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_constructor".into(),
                confidence: 0.90,
                detail: "Prototype pollution via constructor.prototype access".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "constructor.prototype access pollutes object prototype".into(),
                    offset: m.start(),
                    property: "User input must not access constructor.prototype".into(),
                }],
            });
        }

        // constructor.prototype assignment sinks
        static constructor_assign: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"constructor\s*\.\s*prototype\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*\s*=").unwrap());
        if let Some(m) = constructor_assign.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_constructor_assign".into(),
                confidence: 0.91,
                detail: "constructor.prototype property assignment".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Prototype property assignment can globally taint object behavior".into(),
                    offset: m.start(),
                    property: "Untrusted input must never reach constructor.prototype assignment".into(),
                }],
            });
        }

        // Deep merge/object assign sinks with prototype-polluting keys
        static deep_merge: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?is)(?:Object\.assign|merge|deepMerge|defaultsDeep|extend)\s*\([^)]{0,220}(?:__proto__|constructor\s*[\[.]\s*prototype|prototype)").unwrap());
        if let Some(m) = deep_merge.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_deep_merge".into(),
                confidence: 0.86,
                detail: "Prototype key used in deep merge/assign flow".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str()[..m.as_str().len().min(100)].to_owned(),
                    interpretation: "Merge primitive may copy attacker-controlled prototype keys into global object chain".into(),
                    offset: m.start(),
                    property: "Merge utilities must block __proto__/prototype/constructor keys".into(),
                }],
            });
        }

        // Query string pollution payloads
        static qs_nested: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\?(?:[^#\n\r]*)(?:__proto__\[[^\]]+\]|constructor(?:\[prototype\]|\.prototype)\[[^\]]+\])=").unwrap());
        if let Some(m) = qs_nested.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_query_nested".into(),
                confidence: 0.88,
                detail: "Nested query-string prototype pollution payload".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Parser can coerce nested query params into prototype mutation".into(),
                    offset: m.start(),
                    property: "Query parser must reject __proto__/constructor.prototype paths".into(),
                }],
            });
        }

        // JSON payload containing nested prototype key forms
        static JSON_NESTED_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?is)\{[^}]{0,240}["'](?:__proto__|constructor|prototype)["']\s*:\s*\{"#).unwrap());
        let json_nested = &*JSON_NESTED_RE;
        if let Some(m) = json_nested.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_json_nested".into(),
                confidence: 0.90,
                detail: "Nested JSON object includes prototype-polluting key".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str()[..m.as_str().len().min(90)].to_owned(),
                    interpretation: "Deserialized object can poison prototypes when merged into runtime state".into(),
                    offset: m.start(),
                    property: "JSON schema validation must deny __proto__/constructor/prototype keys".into(),
                }],
            });
        }

        // Object.assign + JSON.parse bypass pattern
        static assign_bypass: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r#"(?is)Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:JSON\.parse\s*\([^)]*\)|[^)]*__proto__)"#).unwrap());
        if let Some(m) = assign_bypass.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_object_assign_bypass".into(),
                confidence: 0.87,
                detail: "Object.assign used with attacker-controlled object payload".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str()[..m.as_str().len().min(100)].to_owned(),
                    interpretation: "Object.assign can apply polluted keys from parsed input into object prototypes".into(),
                    offset: m.start(),
                    property: "Object.assign inputs must be sanitized for prototype-polluting keys".into(),
                }],
            });
        }

        // Prototype pollution to RCE gadget pivots
        static gadget: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?is)(?:__proto__|constructor\s*[\[.]\s*prototype)[^\n\r;]{0,140}(?:child_process|mainModule|process|require|exec|spawn|fork)").unwrap());
        if let Some(m) = gadget.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_gadget".into(),
                confidence: 0.93,
                detail: "Prototype pollution gadget pivot to code execution sink".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str()[..m.as_str().len().min(120)].to_owned(),
                    interpretation: "Polluted prototype appears linked to dangerous runtime gadget (child_process/require)".into(),
                    offset: m.start(),
                    property: "Prototype keys must not influence command execution or module loading paths".into(),
                }],
            });
        }

        // Bracket/dot constructor.prototype access forms.
        if let Some(m) = CONSTRUCTOR_PROTO_BRACKET_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_constructor_pattern".into(),
                confidence: 0.92,
                detail: "constructor.prototype/bracket chain access".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Bracket/dot constructor prototype path reaches mutable prototype chain".into(),
                    offset: m.start(),
                    property: "Untrusted property paths must block constructor/prototype traversal".into(),
                }],
            });
        }

        // Explicit Object.assign with prototype-polluting keys.
        if let Some(m) = OBJECT_ASSIGN_PROTO_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_object_assign_proto".into(),
                confidence: 0.91,
                detail: "Object.assign called with __proto__-bearing payload".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str()[..m.as_str().len().min(110)].to_owned(),
                    interpretation: "Object.assign may copy __proto__ onto object graph and taint global prototype".into(),
                    offset: m.start(),
                    property: "Object.assign sources must reject prototype-polluting keys".into(),
                }],
            });
        }

        // JSON.parse strings containing __proto__ key.
        if let Some(m) = JSON_PARSE_PROTO_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_json_parse_proto".into(),
                confidence: 0.90,
                detail: "JSON.parse payload includes __proto__ key".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str()[..m.as_str().len().min(110)].to_owned(),
                    interpretation: "Parsed object can later pollute prototype when merged/assigned".into(),
                    offset: m.start(),
                    property: "JSON.parse results from untrusted input must be key-sanitized".into(),
                }],
            });
        }

        // Lodash/jQuery/deepmerge sinks with prototype keys.
        if let Some(m) = LIB_MERGE_POLLUTION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_library_merge".into(),
                confidence: 0.93,
                detail: "Prototype key used with merge helper (lodash/jQuery/deepmerge)".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str()[..m.as_str().len().min(120)].to_owned(),
                    interpretation: "Known merge helpers can recursively apply attacker-supplied prototype keys".into(),
                    offset: m.start(),
                    property: "Merge libraries must enforce deny-lists for __proto__/constructor/prototype".into(),
                }],
            });
        }

        // Array index mutation of prototype slots (__proto__[0], constructor.prototype[0], etc.).
        if let Some(m) = ARRAY_INDEX_POLLUTION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_array_index".into(),
                confidence: 0.89,
                detail: "Array-index prototype pollution path".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Indexed writes on prototype paths can poison array/object behavior globally".into(),
                    offset: m.start(),
                    property: "Parsers must block numeric indexing on prototype-related keys".into(),
                }],
            });
        }

        // Symbol.hasInstance pollution affects `instanceof` semantics.
        if let Some(m) = SYMBOL_HAS_INSTANCE_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "proto_symbol_hasinstance".into(),
                confidence: 0.94,
                detail: "Prototype pollution attempt on Symbol.hasInstance".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str()[..m.as_str().len().min(120)].to_owned(),
                    interpretation: "Mutating Symbol.hasInstance can corrupt type checks across the runtime".into(),
                    offset: m.start(),
                    property: "Prototype state must not permit writes to Symbol.hasInstance from untrusted input".into(),
                }],
            });
        }

        // Query string pollution: ?__proto__[x]=y
        static qs_proto: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:__proto__|constructor)(?:\[|\.)").unwrap());
        if let Some(m) = qs_proto.find(&decoded) {
            if dets.is_empty() {
                dets.push(L2Detection {
                    detection_type: "proto_query".into(),
                    confidence: 0.85,
                    detail: format!("Query parameter prototype pollution: {}", m.as_str()),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Query parameter pollutes prototype via nested property parsing".into(),
                        offset: m.start(),
                        property: "User-supplied query parameters must not modify object prototypes".into(),
                    }],
                });
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "proto_access" | "proto_json" | "proto_constructor" | "proto_query"
            | "proto_constructor_assign" | "proto_deep_merge" | "proto_query_nested"
            | "proto_json_nested" | "proto_object_assign_bypass"
            | "proto_constructor_pattern" | "proto_object_assign_proto"
            | "proto_json_parse_proto" | "proto_library_merge"
            | "proto_array_index" | "proto_symbol_hasinstance"
                => Some(InvariantClass::ProtoPollution),
            "proto_gadget" => Some(InvariantClass::ProtoPollutionGadget),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nested_query_pollution() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("/api?a=1&?__proto__[isAdmin]=true");
        assert!(dets.iter().any(|d| d.detection_type == "proto_query_nested"));
    }

    #[test]
    fn detects_constructor_assignment() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("obj.constructor.prototype.isAdmin = true");
        assert!(dets.iter().any(|d| d.detection_type == "proto_constructor_assign"));
    }

    #[test]
    fn detects_object_assign_bypass() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect(r#"Object.assign({}, JSON.parse('{"__proto__":{"polluted":1}}'))"#);
        assert!(dets.iter().any(|d| d.detection_type == "proto_object_assign_bypass"));
    }

    #[test]
    fn maps_gadget_to_proto_gadget_class() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("__proto__.shell = require('child_process').exec");
        assert!(dets.iter().any(|d| d.detection_type == "proto_gadget"));
        assert_eq!(eval.map_class("proto_gadget"), Some(InvariantClass::ProtoPollutionGadget));
    }

    #[test]
    fn detects_constructor_bracket_pattern() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect(r#"obj["constructor"]["prototype"]["isAdmin"] = true"#);
        assert!(dets.iter().any(|d| d.detection_type == "proto_constructor_pattern"));
    }

    #[test]
    fn detects_constructor_dot_pattern_chain() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("payload.constructor.prototype.isAdmin = true");
        assert!(dets.iter().any(|d| d.detection_type == "proto_constructor_pattern"));
    }

    #[test]
    fn detects_object_assign_with_proto_key_literal() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect(r#"Object.assign(target, {"__proto__": {"polluted": 1}})"#);
        assert!(dets.iter().any(|d| d.detection_type == "proto_object_assign_proto"));
    }

    #[test]
    fn detects_json_parse_with_proto_key() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect(r#"const x = JSON.parse("{\"__proto__\":{\"a\":1}}")"#);
        assert!(dets.iter().any(|d| d.detection_type == "proto_json_parse_proto"));
    }

    #[test]
    fn detects_lodash_merge_pollution_pattern() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("_.merge({}, userInput, {\"__proto__\": {\"isAdmin\": true}})");
        assert!(dets.iter().any(|d| d.detection_type == "proto_library_merge"));
    }

    #[test]
    fn detects_jquery_extend_pollution_pattern() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("$.extend(true, {}, payload, {\"constructor\":{\"prototype\":{\"x\":1}}})");
        assert!(dets.iter().any(|d| d.detection_type == "proto_library_merge"));
    }

    #[test]
    fn detects_array_index_pollution_proto_slot() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("__proto__[0] = { hacked: true }");
        assert!(dets.iter().any(|d| d.detection_type == "proto_array_index"));
    }

    #[test]
    fn detects_array_index_pollution_constructor_slot() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("user.constructor.prototype[0] = 'polluted'");
        assert!(dets.iter().any(|d| d.detection_type == "proto_array_index"));
    }

    #[test]
    fn detects_symbol_hasinstance_pollution() {
        let eval = ProtoPollutionEvaluator;
        let dets = eval.detect("obj.__proto__[Symbol.hasInstance] = () => true");
        assert!(dets.iter().any(|d| d.detection_type == "proto_symbol_hasinstance"));
    }
}
