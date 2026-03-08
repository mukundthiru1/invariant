//! Mass Assignment Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

const DANGEROUS_FIELDS: &[&str] = &[
    "role",
    "isAdmin",
    "is_admin",
    "admin",
    "permissions",
    "privilege",
    "access_level",
    "verified",
    "email_verified",
    "approved",
    "password",
    "password_hash",
    "api_key",
    "secret",
    "balance",
    "credit",
    "price",
    "amount",
];

pub struct MassAssignmentEvaluator;

impl L2Evaluator for MassAssignmentEvaluator {
    fn id(&self) -> &'static str {
        "mass_assignment"
    }
    fn prefix(&self) -> &'static str {
        "L2 MassAssign"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // Check for JSON with dangerous field names
        for field in DANGEROUS_FIELDS {
            let pattern = format!(r#"[\"']{}[\"']\s*:"#, regex::escape(field));
            let re = Regex::new(&pattern).unwrap();
            if let Some(m) = re.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "mass_assign_field".into(),
                    confidence: 0.82,
                    detail: format!("Sensitive field in request body: {}", field),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation: format!(
                            "Field '{}' modifies authorization/privilege state",
                            field
                        ),
                        offset: m.start(),
                        property: "Request body must not set privileged fields directly".into(),
                    }],
                });
            }
        }

        // Query string mass assignment: ?role=admin&isAdmin=true
        static qs_assign: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:role|isAdmin|is_admin|admin|permissions?)=(?:admin|true|1)\b")
                .unwrap()
        });
        if let Some(m) = qs_assign.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "mass_assign_qs".into(),
                confidence: 0.85,
                detail: format!("Privilege escalation via query parameter: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Query parameter sets privileged field to elevated value"
                        .into(),
                    offset: m.start(),
                    property: "Privilege-controlling parameters must not be user-settable".into(),
                }],
            });
        }

        // Nested dot/bracket notation: user[role]=admin, user.role=admin
        for field in DANGEROUS_FIELDS {
            let bracket = format!(
                r"(?i)(?:^|[?&;,])\s*user\[\s*{}\s*\]\s*=\s*[^&\s]+",
                regex::escape(field)
            );
            let dot = format!(
                r"(?i)(?:^|[?&;,])\s*user\.{}\s*=\s*[^&\s]+",
                regex::escape(field)
            );
            let re_bracket = Regex::new(&bracket).unwrap();
            let re_dot = Regex::new(&dot).unwrap();
            if let Some(m) = re_bracket.find(&decoded).or_else(|| re_dot.find(&decoded)) {
                dets.push(L2Detection {
                    detection_type: "mass_assign_nested_field".into(),
                    confidence: 0.90,
                    detail: format!("Nested privilege field in request: {}", field),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation: format!(
                            "Nested field '{}' can bypass flat-parameter binding checks",
                            field
                        ),
                        offset: m.start(),
                        property: "Nested request parameters should be explicitly whitelisted"
                            .into(),
                    }],
                });
            }
        }

        // GraphQL mutation + JSON-like variable payload mass assignment: { role: "admin" }
        let gql_fields = DANGEROUS_FIELDS.join("|");
        let gql_re = Regex::new(&format!(
            r#"(?is)mutation\b[^\n]*\b(?:{})\s*:\s*(?:"[^"]+"|'[^']+'|true|false|\d+)"#,
            gql_fields
        ))
        .unwrap();
        if gql_re.find(&decoded).is_some() {
            dets.push(L2Detection {
                detection_type: "mass_assign_graphql".into(),
                confidence: 0.94,
                detail: "GraphQL mutation contains privileged assignment field".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(90)].to_owned(),
                    interpretation: "Mutation input payload sets authorization fields directly"
                        .into(),
                    offset: 0,
                    property: "GraphQL mutations should enforce authorization-aware input schemas"
                        .into(),
                }],
            });
        }

        // HTTP method override: _method=PUT/PATCH with privileged fields
        static method_override: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[?&;,])_method\s*=\s*(?:PUT|PATCH)\b").unwrap()
        });
        if method_override.is_match(&decoded) {
            let mut found_privilege = false;
            let mut position = 0;
            let mut snippet = String::new();
            for field in DANGEROUS_FIELDS {
                let field_re =
                    format!(r"(?i)(?:^|[?&;,])\s*{}\s*=\s*[^&\s]+", regex::escape(field));
                let re = Regex::new(&field_re).unwrap();
                if let Some(m) = re.find(&decoded) {
                    position = m.start();
                    snippet = m.as_str().to_owned();
                    found_privilege = true;
                    break;
                }
            }
            if found_privilege {
                dets.push(L2Detection {
                    detection_type: "mass_assign_method_override".into(),
                    confidence: 0.91,
                    detail: "HTTP method override paired with privilege field assignment".into(),
                    position,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: snippet,
                        interpretation:
                            "Method override may execute update path with sensitive fields".into(),
                        offset: position,
                        property: "Only approved routes should accept _method overrides".into(),
                    }],
                });
            }
        }

        // Rails-style strong params bypass keys.
        static DESTROY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)(?:^|[?&;,])(?:[A-Za-z0-9_]+\[)?_destroy(?:\]\[[^\]]+\])*\]?(?:\s*=|\s*:)\s*(?:true|false|[1-9]|"[^"]+"|'[^']+)"#).unwrap()
        });
        static ATTRS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)(?:^|[?&;,])(?:[A-Za-z0-9_]+\[)?_attributes(?:\]\[[^\]]+\])*\]?(?:\s*=|\s*:)\s*(?:\{|\[|"[^"]+"|'[^']+)"#).unwrap()
        });
        let destroy_re = &*DESTROY_RE;
        let attrs_re = &*ATTRS_RE;
        static nested_json_destroy: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:\{|,)\s*[\"']?_destroy[\"']?\s*:\s*(?:true|false|[0-9]+|[\"'][^\"']+[\"'])"#).unwrap()
        });
        static nested_json_attrs: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:\{|,)\s*[\"']?_attributes[\"']?\s*:\s*(?:\{|\[)"#).unwrap()
        });
        if destroy_re.find(&decoded).is_some() || nested_json_destroy.find(&decoded).is_some() {
            dets.push(L2Detection {
                detection_type: "mass_assign_strong_params".into(),
                confidence: 0.88,
                detail: "Potential Rails strong-params bypass key detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(90)].to_owned(),
                    interpretation:
                        "_destroy can bypass safe-parameter filtering in nested payloads".into(),
                    offset: 0,
                    property:
                        "Nested allowlist validation must strip framework-specific override keys"
                            .into(),
                }],
            });
        } else if attrs_re.find(&decoded).is_some() || nested_json_attrs.find(&decoded).is_some() {
            dets.push(L2Detection {
                detection_type: "mass_assign_strong_params".into(),
                confidence: 0.88,
                detail: "Potential Rails strong-params bypass key detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(90)].to_owned(),
                    interpretation:
                        "_attributes can bypass attribute filtering in nested structures".into(),
                    offset: 0,
                    property:
                        "Nested allowlist validation must strip framework-specific override keys"
                            .into(),
                }],
            });
        }

        // ORM operator/metadata injection in TypeORM / Sequelize payloads.
        static typeorm_metadata: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)__typeorm_metadata__").unwrap());
        static sequelize_ops: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)(?:^|[^a-zA-Z0-9_])\$(?:or|and|not|where|gt|gte|lt|lte|ne|in|nin|like|regex|eq)\b"#).unwrap()
        });
        if typeorm_metadata.find(&decoded).is_some() || sequelize_ops.find(&decoded).is_some() {
            dets.push(L2Detection {
                detection_type: "mass_assign_orm_injection".into(),
                confidence: 0.93,
                detail: "TypeORM/Sequelize operator or metadata key in user payload".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(90)].to_owned(),
                    interpretation: "ORM magic keys can alter query/update semantics".into(),
                    offset: 0,
                    property: "ORM payload keys should be strictly validated and stripped of internal operators".into(),
                }],
            });
        }

        // Generic nested object assignment (non-user object): account[role]=admin, profile.isAdmin=true
        for field in DANGEROUS_FIELDS {
            let bracket = format!(
                r"(?i)(?:^|[?&;,])\s*[A-Za-z0-9_]+\[\s*{}\s*\]\s*=\s*(?:admin|true|1|[^&\s]+)",
                regex::escape(field)
            );
            let dot = format!(
                r"(?i)(?:^|[?&;,])\s*[A-Za-z0-9_]+\.{}\s*=\s*(?:admin|true|1|[^&\s]+)",
                regex::escape(field)
            );
            let re_bracket = Regex::new(&bracket).unwrap();
            let re_dot = Regex::new(&dot).unwrap();
            if let Some(m) = re_bracket.find(&decoded).or_else(|| re_dot.find(&decoded)) {
                let normalized = m.as_str().to_ascii_lowercase();
                if !normalized.contains("user[") && !normalized.contains("user.") {
                    dets.push(L2Detection {
                        detection_type: "mass_assign_nested_generic".into(),
                        confidence: 0.92,
                        detail: format!("Nested privileged field assignment in object path: {}", field),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: m.as_str().to_owned(),
                            interpretation: "Nested object path can bypass allowlist checks scoped to flat keys".into(),
                            offset: m.start(),
                            property: "All nested object keys must be authorization-filtered before model binding".into(),
                        }],
                    });
                }
            }
        }

        // Array parameter manipulation: roles[]=admin&roles[]=user, permissions[]=*
        static ARRAY_PRIV_ESC_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r"(?i)(?:^|[?&;,])\s*(?:roles?|permissions?|scopes?|privileges?)\[\]\s*=\s*(?:admin|root|owner|superuser|all|\*|true|1)\b",
            )
            .unwrap()
        });
        static ARRAY_REPEAT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[?&;,])\s*(?:roles?|permissions?|scopes?)\[\]\s*=[^&]+(?:&(?:roles?|permissions?|scopes?)\[\]\s*=[^&]+)+").unwrap()
        });
        if let Some(m) = ARRAY_PRIV_ESC_RE
            .find(&decoded)
            .or_else(|| ARRAY_REPEAT_RE.find(&decoded))
        {
            dets.push(L2Detection {
                detection_type: "mass_assign_array_param".into(),
                confidence: if ARRAY_PRIV_ESC_RE.is_match(&decoded) {
                    0.93
                } else {
                    0.88
                },
                detail: format!("Array-based mass assignment parameter: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Array binding can inject unauthorized role/permission collections".into(),
                    offset: m.start(),
                    property:
                        "Array-valued privilege fields must be explicit-allowlisted and normalized"
                            .into(),
                }],
            });
        }

        // GraphQL mutation variable/object assignment to privileged fields.
        static GQL_MUT_UNAUTH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)\bmutation\b[\s\S]{0,500}\b(?:input|data|patch|set|update\w*)\s*:\s*\{[\s\S]{0,500}\b(?:role|isAdmin|is_admin|admin|permissions?|access_level|verified|approved)\b\s*:"#,
            )
            .unwrap()
        });
        static GQL_VAR_UNAUTH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)"variables"\s*:\s*\{[\s\S]{0,500}"(?:role|isAdmin|is_admin|admin|permissions?|access_level|verified|approved)"\s*:\s*(?:"[^"]*"|true|false|\d+|\[[^\]]*\]|\{[^}]*\})"#,
            )
            .unwrap()
        });
        if let Some(m) = GQL_MUT_UNAUTH_RE
            .find(&decoded)
            .or_else(|| GQL_VAR_UNAUTH_RE.find(&decoded))
        {
            dets.push(L2Detection {
                detection_type: "mass_assign_graphql_unauthorized".into(),
                confidence: 0.95,
                detail: "GraphQL mutation/variables include privileged fields likely outside user authorization scope".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[m.start()..decoded.len().min(m.start() + 120)].to_owned(),
                    interpretation: "GraphQL input object includes privileged fields that can be auto-bound to model updates".into(),
                    offset: m.start(),
                    property: "GraphQL resolver must enforce field-level authorization for mutation inputs".into(),
                }],
            });
        }

        // JSON Merge Patch abuse (RFC 7396): merge-patch content type plus privileged key mutation/nullification.
        static MERGE_PATCH_CT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)application/merge-patch\+json").unwrap());
        static MERGE_PATCH_FIELD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)[\"'](?:role|isAdmin|is_admin|admin|permissions?|access_level|verified|approved|password|secret)[\"']\s*:\s*(?:null|true|false|[0-9]+|\"[^\"]*\"|'[^']*'|\[[^\]]*\]|\{[^}]*\})"#,
            )
            .unwrap()
        });
        if MERGE_PATCH_CT_RE.is_match(&decoded) {
            if let Some(m) = MERGE_PATCH_FIELD_RE.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "mass_assign_json_merge_patch".into(),
                    confidence: 0.94,
                    detail: "JSON Merge Patch payload mutates privileged fields".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "RFC 7396 merge semantics can overwrite or delete sensitive attributes via user patch".into(),
                        offset: m.start(),
                        property: "Merge patch documents must be schema-constrained and privilege-filtered".into(),
                    }],
                });
            }
        }
        // Fallback for canonicalization pipelines that normalize '+' in merge-patch content type.
        static MERGE_PATCH_CT_FLEX_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)application/merge-patch(?:\+|\s)json").unwrap()
            });
        if dets
            .iter()
            .all(|d| d.detection_type != "mass_assign_json_merge_patch")
            && MERGE_PATCH_CT_FLEX_RE.is_match(&decoded)
        {
            if let Some(m) = MERGE_PATCH_FIELD_RE.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "mass_assign_json_merge_patch".into(),
                    confidence: 0.93,
                    detail: "JSON Merge Patch payload mutates privileged fields".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Merge-patch media type normalization still yields sensitive field overwrite/delete".into(),
                        offset: m.start(),
                        property: "Merge patch validation must run on canonicalized content-type and body together".into(),
                    }],
                });
            }
        }

        // Multipart form-data privilege field injection in upload flows.
        static MULTIPART_PRIV_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)Content-Disposition:\s*form-data;\s*name\s*=\s*["'](?:role|isAdmin|is_admin|admin|permissions?|access_level|verified|approved)["']\s*\r?\n(?:Content-Type:[^\n]*\r?\n)?\r?\n(?:admin|true|1|owner|superuser|[A-Za-z0-9_,*-]+)"#,
            )
            .unwrap()
        });
        if let Some(m) = MULTIPART_PRIV_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "mass_assign_multipart_field".into(),
                confidence: 0.92,
                detail: "Multipart form contains privileged field injection".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "File upload multipart stream injects privileged non-file form field".into(),
                    offset: m.start(),
                    property: "Multipart parsers must enforce allowlists for non-file form fields".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "mass_assign_field"
            | "mass_assign_qs"
            | "mass_assign_nested_field"
            | "mass_assign_graphql"
            | "mass_assign_method_override"
            | "mass_assign_strong_params"
            | "mass_assign_orm_injection"
            | "mass_assign_nested_generic"
            | "mass_assign_array_param"
            | "mass_assign_graphql_unauthorized"
            | "mass_assign_json_merge_patch"
            | "mass_assign_multipart_field" => Some(InvariantClass::MassAssignment),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nested_dot_bracket_fields() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect("user[role]=admin&user.role=admin");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_nested_field")
        );
    }

    #[test]
    fn detects_graphql_mass_assignment() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect("mutation { updateUser(input: { role: \"admin\" }) { id } }");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_graphql")
        );
    }

    #[test]
    fn detects_http_method_override_mass_assignment() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect("id=1&_method=PUT&role=admin");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_method_override")
        );
    }

    #[test]
    fn detects_strong_params_bypass_keys() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect("user[_destroy]=true&user[_attributes][role]=admin");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_strong_params")
        );
    }

    #[test]
    fn detects_orm_operator_injection() {
        let eval = MassAssignmentEvaluator;
        let dets =
            eval.detect("{ \"__typeorm_metadata__\": { source: \"x\" }, \"role\": \"admin\" }");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_orm_injection")
        );
        let dets = eval.detect("{ \"where\": { \"$or\": [{ \"role\": \"admin\" }] }");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_orm_injection")
        );
    }

    #[test]
    fn detects_generic_nested_bracket_assignment() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect("account[role]=admin&account[name]=bob");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_nested_generic")
        );
    }

    #[test]
    fn detects_generic_nested_dot_assignment() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect("profile.is_admin=true&profile.email=a@b.com");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_nested_generic")
        );
    }

    #[test]
    fn detects_array_parameter_privilege_escalation() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect("roles[]=admin&roles[]=user");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_array_param")
        );
    }

    #[test]
    fn detects_array_parameter_repeated_permission_manipulation() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect("permissions[]=read&permissions[]=write&permissions[]=all");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_array_param")
        );
    }

    #[test]
    fn detects_graphql_unauthorized_mutation_assignment() {
        let eval = MassAssignmentEvaluator;
        let dets = eval.detect(
            "mutation UpdateUser { updateUser(input: { id: 1, permissions: [\"admin\"] }) { id } }",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_graphql_unauthorized")
        );
    }

    #[test]
    fn detects_graphql_variables_unauthorized_assignment() {
        let eval = MassAssignmentEvaluator;
        let payload = r#"{"query":"mutation U($input: UpdateUserInput!){updateUser(input:$input){id}}","variables":{"input":{"admin":true,"name":"x"}}}"#;
        let dets = eval.detect(payload);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_graphql_unauthorized")
        );
    }

    #[test]
    fn detects_json_merge_patch_privileged_mutation() {
        let eval = MassAssignmentEvaluator;
        let payload = "PATCH /users/1 HTTP/1.1\r\nContent-Type: application/merge-patch+json\r\n\r\n{\"role\":\"admin\",\"email\":\"x@y.z\"}";
        let dets = eval.detect(payload);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_json_merge_patch")
        );
    }

    #[test]
    fn detects_json_merge_patch_nullification_of_sensitive_field() {
        let eval = MassAssignmentEvaluator;
        let payload = "Content-Type: application/merge-patch+json\n{\"permissions\":null}";
        let dets = eval.detect(payload);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_json_merge_patch")
        );
    }

    #[test]
    fn detects_multipart_form_privileged_field_injection() {
        let eval = MassAssignmentEvaluator;
        let payload = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--boundary\r\nContent-Disposition: form-data; name=\"admin\"\r\n\r\ntrue\r\n--boundary--";
        let dets = eval.detect(payload);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mass_assign_multipart_field")
        );
    }
}
