//! API Abuse Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::collections::HashMap;

fn decode_base64url_nopad(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;

    for c in input.chars() {
        let val = match c {
            'A'..='Z' => (c as u8 - b'A') as u32,
            'a'..='z' => (c as u8 - b'a' + 26) as u32,
            '0'..='9' => (c as u8 - b'0' + 52) as u32,
            '-' => 62,
            '_' => 63,
            '=' => continue,
            _ => return None,
        };

        buffer = (buffer << 6) | val;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }

    Some(out)
}

pub struct ApiAbuseEvaluator;

impl L2Evaluator for ApiAbuseEvaluator {
    fn id(&self) -> &'static str {
        "api_abuse"
    }
    fn prefix(&self) -> &'static str {
        "L2 API"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // API GraphQL batch abuse: array-form request containing multiple query documents
        static GRAPHQL_BATCH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)\[[^\]]*\bquery\b[^\]]*,[^\]]*\bquery\b[^\]]*\]"#).unwrap()
        });
        let is_graphql = decoded.to_lowercase().contains("/graphql")
            || decoded.to_lowercase().contains("graphql");
        if is_graphql && GRAPHQL_BATCH_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "api_graphql_batching_abuse".into(),
                confidence: 0.91,
                detail: "GraphQL batch payload contains multiple query documents in a single request".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "Batch mode can bypass per-query rate limiting and mutation quotas".into(),
                    offset: 0,
                    property: "GraphQL batch execution should be explicitly limited and authenticated per operation".into(),
                }],
            });
        }

        // HTTP Parameter Pollution: duplicate parameters with conflicting values
        static HPP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:[?&\s]|^)([A-Za-z0-9._~-]+)=([^&\r\n\s]*)").unwrap()
        });
        let mut param_values: HashMap<String, String> = HashMap::new();
        let mut polluted: Option<String> = None;
        for cap in HPP_RE.captures_iter(&decoded) {
            let key = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
            let val = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
            match param_values.get(key) {
                Some(existing) if existing != &val => {
                    polluted = Some(key.to_string());
                    break;
                }
                Some(_) => {}
                None => {
                    param_values.insert(key.to_string(), val.to_string());
                }
            }
        }
        if let Some(param_name) = polluted {
            dets.push(L2Detection {
                detection_type: "api_http_parameter_pollution".into(),
                confidence: 0.88,
                detail: format!("HTTP Parameter Pollution: {} repeated with divergent values", param_name),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(140)].to_owned(),
                    interpretation: "Duplicate mutable parameters can produce cache/authorization split-brain behavior".into(),
                    offset: 0,
                    property: "Normalize duplicate query/form parameters before downstream processing".into(),
                }],
            });
        }

        // IDOR patterning: repeated sequential numeric IDs in API resources
        static IDOR_RESOURCE_ID_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|/)(?:(?:api/)?[A-Za-z0-9._-]+/)(\d+)(?:[/?.\s]|$)").unwrap()
        });
        let mut resource_ids: Vec<u64> = Vec::new();
        for cap in IDOR_RESOURCE_ID_RE.captures_iter(&decoded) {
            if let Some(raw_id) = cap.get(1).map(|m| m.as_str()) {
                if let Ok(id) = raw_id.parse::<u64>() {
                    resource_ids.push(id);
                }
            }
        }
        if resource_ids.len() >= 3 {
            let mut sorted = resource_ids.clone();
            sorted.sort_unstable();
            let mut seq_len = 1usize;
            let mut max_seq = 1usize;
            for pair in sorted.windows(2) {
                if pair[1] == pair[0] + 1 {
                    seq_len += 1;
                    max_seq = max_seq.max(seq_len);
                } else {
                    seq_len = 1;
                }
            }

            if max_seq >= 3 {
                dets.push(L2Detection {
                    detection_type: "api_idor_pattern".into(),
                    confidence: 0.89,
                    detail: format!("Sequential numeric IDs observed ({} consecutive IDs)", max_seq),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: decoded[..decoded.len().min(160)].to_owned(),
                        interpretation: "Predictable numeric resource IDs suggest broken object-level authorization checks".into(),
                        offset: 0,
                        property: "Object-level authorization must be enforced for every resource identifier".into(),
                    }],
                });
            }
        }

        // Mass enumeration: sequential ID sweep in query/path payloads
        static ENUM_ID_QUERY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)[?&](?:id|user_id|item_id|resource_id)=([0-9]+)").unwrap()
        });
        static ENUM_ID_LIST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)[?&](?:ids|user_ids)=[0-9]+(?:\s*,\s*[0-9]+)+").unwrap()
        });
        static ENUM_ID_PATH_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?:/api/[A-Za-z0-9._-]+/)([0-9]+)").unwrap());
        let mut enum_ids: Vec<u64> = Vec::new();
        for cap in ENUM_ID_QUERY_RE.captures_iter(&decoded) {
            if let Some(raw_id) = cap.get(1).map(|m| m.as_str()) {
                if let Ok(id) = raw_id.parse::<u64>() {
                    enum_ids.push(id);
                }
            }
        }
        for m in ENUM_ID_LIST_RE.find_iter(&decoded) {
            let list = &decoded[m.start()..m.end()];
            let ids = list.split(|c| c == '=' || c == ',').skip(1);
            for raw_id in ids {
                if let Ok(id) = raw_id.trim().parse::<u64>() {
                    enum_ids.push(id);
                }
            }
        }
        for cap in ENUM_ID_PATH_RE.captures_iter(&decoded) {
            if let Some(raw_id) = cap.get(1).map(|m| m.as_str()) {
                if let Ok(id) = raw_id.parse::<u64>() {
                    enum_ids.push(id);
                }
            }
        }

        if enum_ids.len() >= 4 {
            enum_ids.sort_unstable();
            let mut seq_len = 1usize;
            let mut max_seq = 1usize;
            for pair in enum_ids.windows(2) {
                if pair[1] == pair[0] + 1 {
                    seq_len += 1;
                    max_seq = max_seq.max(seq_len);
                } else {
                    seq_len = 1;
                }
            }

            if max_seq >= 4 {
                dets.push(L2Detection {
                    detection_type: "api_mass_enumeration".into(),
                    confidence: 0.86,
                    detail: format!("Sequential enumeration sequence detected with {} accesses", enum_ids.len()),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: decoded[..decoded.len().min(120)].to_owned(),
                        interpretation: "Repeated numeric accesses indicate brute enumeration behavior".into(),
                        offset: 0,
                        property: "API endpoints must apply stable pagination and per-object anti-enumeration controls".into(),
                    }],
                });
            }
        }

        // BOLA/IDOR: sequential ID enumeration pattern
        static seq_ids: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"/api/[^/]+/(\d+)\b").unwrap());
        let matches: Vec<_> = seq_ids.find_iter(&decoded).collect();
        if matches.len() > 3 {
            dets.push(L2Detection {
                detection_type: "bola_enumeration".into(),
                confidence: 0.80,
                detail: format!("Sequential API ID enumeration ({} requests)", matches.len()),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(80)].to_owned(),
                    interpretation: "Sequential ID access pattern indicates BOLA/IDOR exploitation"
                        .into(),
                    offset: 0,
                    property: "API endpoints must enforce object-level authorization".into(),
                }],
            });
        }

        // Excessive data exposure: large limit parameters
        static large_limit: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:limit|page_size|per_page|count)\s*=\s*(\d+)").unwrap()
        });
        if let Some(caps) = large_limit.captures(&decoded) {
            if let Ok(val) = caps.get(1).unwrap().as_str().parse::<u64>() {
                if val > 10000 {
                    dets.push(L2Detection {
                        detection_type: "excessive_data".into(),
                        confidence: 0.78,
                        detail: format!("Excessive data request: limit={}", val),
                        position: caps.get(0).unwrap().start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: caps.get(0).unwrap().as_str().to_owned(),
                            interpretation: format!(
                                "Requesting {} records may indicate data exfiltration",
                                val
                            ),
                            offset: caps.get(0).unwrap().start(),
                            property: "API pagination limits must be bounded server-side".into(),
                        }],
                    });
                }
            }
        }

        // Rate limit bypass headers
        static bypass: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*(?:X-Forwarded-For|X-Real-IP|X-Client-IP|True-Client-IP|CF-Connecting-IP|X-Originating-IP|X-Remote-IP|X-Remote-Addr|X-Cluster-Client-IP|Fastly-Client-IP)\s*:\s*(?:(?:\d{1,3}\.){3}\d{1,3}|::1|fe80::|fc00::|\[::1\])").unwrap()
        });
        if let Some(m) = bypass.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "rate_limit_bypass".into(),
                confidence: 0.82,
                detail: "IP spoofing header — potential rate limit bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "IP header spoofing bypasses per-IP rate limiting".into(),
                    offset: m.start(),
                    property:
                        "Rate limiting must use verified client IP, not user-supplied headers"
                            .into(),
                }],
            });
        }

        // JWT claim manipulation: forged admin claims in Authorization bearer payload
        static jwt_auth: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*Authorization\s*:\s*Bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)").unwrap()
        });
        for caps in jwt_auth.captures_iter(&decoded) {
            if let Some(payload) = caps.get(2) {
                if let Some(decoded_payload_bytes) = decode_base64url_nopad(payload.as_str()) {
                    if let Ok(payload_json) = String::from_utf8(decoded_payload_bytes) {
                        if payload_json.contains("\"admin\":true")
                            || payload_json.contains("\"role\":\"admin\"")
                            || payload_json.contains("\"scope\":\"admin\"")
                        {
                            dets.push(L2Detection {
                                detection_type: "api_jwt_claim_manipulation".into(),
                                confidence: 0.90,
                                detail: "JWT payload carries privileged claim values in Authorization header".into(),
                                position: 0,
                                evidence: vec![ProofEvidence {
                                    operation: EvidenceOperation::TypeCoerce,
                                    matched_input: payload_json.chars().take(120).collect(),
                                    interpretation: "Bearer token payload contains elevated claims likely manipulated client-side".into(),
                                    offset: 0,
                                    property: "JWT claims must be integrity-verified and authorization must not trust client-modified claims".into(),
                                }],
                            });
                        }
                    }
                }
            }
        }

        // HTTP method tampering via override headers
        static method_tamper: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*(?:X-HTTP-Method-Override|X-Method-Override)\s*:\s*(?:PUT|PATCH|DELETE|TRACE|CONNECT)\b").unwrap()
        });
        if let Some(m) = method_tamper.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "api_method_tampering".into(),
                confidence: 0.86,
                detail: "HTTP method override header present".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Method override header may bypass gateway ACLs based on original verb"
                            .into(),
                    offset: m.start(),
                    property: "Method override headers must be disabled or strictly authenticated"
                        .into(),
                }],
            });
        }

        // API version downgrade: v1 used while v2/v3 is also referenced
        static V1_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:/api/)?v1(?:/|\b)|[?&](?:api_)?version=1\b").unwrap()
        });
        static NEWER_VERSION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:/api/)?v(?:2|3)(?:/|\b)|[?&](?:api_)?version=(?:2|3)\b").unwrap()
        });
        let using_v1 = V1_RE.is_match(&decoded);
        let has_newer_versions = NEWER_VERSION_RE.is_match(&decoded);
        if using_v1 && has_newer_versions {
            dets.push(L2Detection {
                detection_type: "api_version_downgrade".into(),
                confidence: 0.84,
                detail: "Request indicates API v1 usage while newer API versions are available".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "Downgrading to older API surface may bypass stronger auth/validation in newer versions".into(),
                    offset: 0,
                    property: "Clients should be pinned to secure API versions and downgrade paths gated".into(),
                }],
            });
        }

        // Protocol negotiation downgrade: requesting v1 while advertising newer API contracts
        static VERSION_NEGOTIATION_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)(?:accept|x-api-version|api-version)\s*[:=]\s*([^;\s,]+)").unwrap()
            });
        static VERSION_LIST_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)version\s*=\s*(\d+)").unwrap());
        static VERSION_MEDIA_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)application/[A-Za-z0-9.-]+\+json;\s*version=(\d+)").unwrap()
        });
        let mut versions: Vec<u32> = Vec::new();
        for cap in VERSION_NEGOTIATION_RE.captures_iter(&decoded) {
            if let Some(raw) = cap.get(1) {
                if raw.as_str() == "1" || raw.as_str() == "v1" {
                    versions.push(1);
                }
            }
        }
        for cap in VERSION_LIST_RE.captures_iter(&decoded) {
            if let Some(raw) = cap.get(1).and_then(|m| m.as_str().parse::<u32>().ok()) {
                versions.push(raw);
            }
        }
        for cap in VERSION_MEDIA_RE.captures_iter(&decoded) {
            if let Some(raw) = cap.get(1).and_then(|m| m.as_str().parse::<u32>().ok()) {
                versions.push(raw);
            }
        }

        if !versions.is_empty() {
            let has_low = versions.contains(&1);
            let has_high = versions.iter().any(|v| *v >= 2);
            if has_low && has_high {
                dets.push(L2Detection {
                    detection_type: "api_version_downgrade".into(),
                    confidence: 0.83,
                    detail: "API version negotiation requests downgrade to v1 while higher versions are present".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: decoded[..decoded.len().min(120)].to_owned(),
                        interpretation: "Mixed version negotiation indicates intentional downgrade attempt".into(),
                        offset: 0,
                        property: "Version negotiation must enforce monotonic, allowlisted API versions".into(),
                    }],
                });
            }
        }

        // SSRF through API callback/url parameters to internal addresses
        static SSRF_PARAM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?i)(?:^|[?&\s"'])?(?:url|webhook|callback)\s*[:=]\s*["']?(?:(?:https?|file|gopher|dict)://)?(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0|::1|metadata\.google\.internal|metadata\.internal|2130706433|0177\.[0-9.]+)\b"#,
            )
            .unwrap()
        });
        let ssrf_param = &*SSRF_PARAM_RE;
        if let Some(m) = ssrf_param.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "api_ssrf_param_internal".into(),
                confidence: 0.91,
                detail: "API callback/url parameter targets internal IP address".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "User-controlled URL-like parameter points to internal network range".into(),
                    offset: m.start(),
                    property: "Server-side HTTP clients must block private/link-local destinations for user-provided URLs".into(),
                }],
            });
        }

        // Excessive OAuth scope requests
        static excessive_scope: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[?&\s])scope\s*=\s*[^&]*(?:\*|\badmin\b|\bread_write\b|\bfull_access\b|\broot\b|\bsystem\b)").unwrap()
        });
        if let Some(m) = excessive_scope.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "api_excessive_scope".into(),
                confidence: 0.87,
                detail: "OAuth scope request includes wildcard or admin privilege".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Client requests over-privileged OAuth scope that exceeds least-privilege expectations".into(),
                    offset: m.start(),
                    property: "OAuth scope grants must enforce least privilege and deny wildcard/admin-by-default scopes".into(),
                }],
            });
        }

        // Undocumented endpoint probing for sensitive/debug surfaces
        static UNDOCUMENTED_ENDPOINT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)(?:^|/)(?:swagger(?:-ui)?|api-docs?|openapi|graphiql|redoc|scalar|\.env(?:\.local|\.production)?|\.git(?:/config|/)|config\.(?:php|json|yaml|yml|ini)|appsettings\.json|credentials\.json|secrets\.json|aws/credentials|actuator/|debug(?:\.php)?|phpinfo\.php|server-status|jmx/|metrics/?|health/?\?.*verbose|admin/api|management/|_profiler/|__debug__)(?:/|\?|$)").unwrap()
            });
        if let Some(m) = UNDOCUMENTED_ENDPOINT_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "undocumented_endpoint_probe".into(),
                confidence: 0.78,
                detail: "Request targets undocumented or sensitive debug/management endpoint".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Discovery probing against debug/management endpoints often precedes abuse of unintended API surface".into(),
                    offset: m.start(),
                    property: "Disable or restrict internal/debug endpoints and ensure non-production disclosure controls".into(),
                }],
            });
        }

        // JWT None Algorithm
        static JWT_NONE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)['"]alg['"]\s*:\s*['"]none['"]"#).unwrap()
        });
        static JWT_NONE_B64_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"eyJ[A-Za-z0-9_-]+").unwrap()
        });
        
        let mut jwt_none_detected = false;
        if JWT_NONE_RE.is_match(&decoded) {
            jwt_none_detected = true;
        } else {
            for caps in jwt_auth.captures_iter(&decoded) {
                if let Some(header) = caps.get(1) {
                    if let Some(decoded_header_bytes) = decode_base64url_nopad(header.as_str()) {
                        if let Ok(header_json) = String::from_utf8(decoded_header_bytes) {
                            if JWT_NONE_RE.is_match(&header_json) {
                                jwt_none_detected = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !jwt_none_detected {
                for m in JWT_NONE_B64_RE.find_iter(&decoded) {
                     let b64_part = m.as_str();
                     if let Some(decoded_bytes) = decode_base64url_nopad(b64_part) {
                         if let Ok(json_str) = String::from_utf8(decoded_bytes) {
                             if JWT_NONE_RE.is_match(&json_str) {
                                 jwt_none_detected = true;
                                 break;
                             }
                         }
                     }
                }
            }
        }
        
        if jwt_none_detected {
            dets.push(L2Detection {
                detection_type: "api_jwt_none_alg".into(),
                confidence: 0.96,
                detail: "JWT none algorithm detected in header".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "JWT none algorithm disables signature verification. Tokens with alg:none are accepted by vulnerable servers without validating the signature, allowing arbitrary claim forgery.".into(),
                    offset: 0,
                    property: "JWT signature validation must reject 'none' algorithm and enforce explicit allowed algorithms".into(),
                }],
            });
        }

        // Pagination scraping (deep offset)
        static DEEP_OFFSET_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)[?&](?:offset|skip|start)=([0-9]{6,})").unwrap()
        });
        static DEEP_PAGE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)[?&]page=([0-9]{4,})").unwrap()
        });
        
        let mut is_deep_pagination = false;
        for cap in DEEP_OFFSET_RE.captures_iter(&decoded) {
            if let Ok(val) = cap[1].parse::<u64>() {
                if val >= 100000 {
                    is_deep_pagination = true;
                    break;
                }
            }
        }
        if !is_deep_pagination {
            for cap in DEEP_PAGE_RE.captures_iter(&decoded) {
                if let Ok(val) = cap[1].parse::<u64>() {
                    if val >= 1000 {
                        is_deep_pagination = true;
                        break;
                    }
                }
            }
        }
        if is_deep_pagination {
            dets.push(L2Detection {
                detection_type: "api_deep_pagination".into(),
                confidence: 0.82,
                detail: "Extremely large offset or page value requested".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "Extremely large offset/page values indicate pagination-based data harvesting. Attackers enumerate entire datasets by iterating through pages, bypassing record-count limits while extracting all data.".into(),
                    offset: 0,
                    property: "API pagination must enforce a maximum absolute offset/page depth to prevent full data extraction".into(),
                }],
            });
        }

        // Content-Type confusion
        static CT_CONFUSION_JSON_BODY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^content-type\s*:\s*(?:application/x-www-form-urlencoded|text/plain)").unwrap()
        });
        static CT_CONFUSION_FORM_BODY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^content-type\s*:\s*application/json").unwrap()
        });
        static JSON_LIKE_BODY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\{[^}]{3,}:").unwrap()
        });

        let body_idx = decoded.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
        let body = if body_idx > 0 && body_idx < decoded.len() { decoded[body_idx..].trim_start() } else { &decoded };
        
        let mut is_ct_confusion = false;
        if CT_CONFUSION_JSON_BODY_RE.is_match(&decoded) && JSON_LIKE_BODY_RE.is_match(body) {
            is_ct_confusion = true;
        } else if CT_CONFUSION_FORM_BODY_RE.is_match(&decoded) && !body.starts_with('{') && !body.starts_with('[') && body.contains('=') && body.contains('&') {
            is_ct_confusion = true;
        }

        if is_ct_confusion {
            dets.push(L2Detection {
                detection_type: "api_content_type_confusion".into(),
                confidence: 0.85,
                detail: "Content-Type header contradicts body structure".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "Content-Type mismatch exploits server-side parsing confusion. Some frameworks parse form-encoded POST bodies as JSON if the body structure looks like JSON, bypassing Content-Type-based security controls and validation.".into(),
                    offset: 0,
                    property: "Server frameworks must strictly reject requests where the body format does not match the Content-Type header".into(),
                }],
            });
        }

        // JWT array role claim
        static JWT_ARRAY_ROLE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)['"](?:roles?|groups?|permissions?)['"]\s*:\s*\[[^\]]*['"]admin['"]"#).unwrap()
        });
        
        let mut jwt_array_role_detected = false;
        if JWT_ARRAY_ROLE_RE.is_match(&decoded) {
            jwt_array_role_detected = true;
        } else {
            for cap in jwt_auth.captures_iter(&decoded) {
                if let Some(payload) = cap.get(2) {
                    if let Some(decoded_payload_bytes) = decode_base64url_nopad(payload.as_str()) {
                        if let Ok(payload_json) = String::from_utf8(decoded_payload_bytes) {
                            if JWT_ARRAY_ROLE_RE.is_match(&payload_json) {
                                jwt_array_role_detected = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        if jwt_array_role_detected {
            dets.push(L2Detection {
                detection_type: "api_jwt_array_role".into(),
                confidence: 0.88,
                detail: "JWT payload contains array-format role with admin privilege".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "JWT payload contains an array-format role claim with admin value. Some authorization frameworks check only scalar role claims and miss array-format role injection.".into(),
                    offset: 0,
                    property: "Authorization frameworks must safely process both scalar and array role claims or reject ambiguous formats".into(),
                }],
            });
        }

        // HPP in JSON body (duplicate keys)
        static JSON_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"['"]([a-zA-Z_][a-zA-Z0-9_]{2,})['"]\s*:"#).unwrap()
        });
        
        if decoded.contains('{') && decoded.contains(':') {
            let mut keys_found = Vec::new();
            let mut has_duplicate_key = false;
            for cap in JSON_KEY_RE.captures_iter(&decoded) {
                let key = cap[1].to_string();
                if keys_found.contains(&key) {
                    has_duplicate_key = true;
                    break;
                }
                keys_found.push(key);
            }
            if has_duplicate_key {
                dets.push(L2Detection {
                    detection_type: "api_json_hpp".into(),
                    confidence: 0.83,
                    detail: "Duplicate keys found in JSON-like structure".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[..decoded.len().min(120)].to_owned(),
                        interpretation: "Duplicate JSON keys exploit last-key-wins vs first-key-wins behavior differences between parsers. A duplicate key like {\"role\":\"user\",\"role\":\"admin\"} may be parsed as admin by some and user by others, enabling privilege escalation.".into(),
                        offset: 0,
                        property: "JSON parsers must reject payloads with duplicate keys to prevent parsing confusion".into(),
                    }],
                });
            }
        }

        // API version disclosure in infrastructure headers
        static VERSION_DISCLOSURE_HEADER_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?im)^\s*(?:Server|X-Powered-By)\s*:\s*([^\r\n]+)").unwrap()
            });
        static VERSION_DISCLOSURE_VALUE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)(?:express/(?:3\.[0-9]|4\.[0-9]{1,2})|php/[0-9]+\.[0-9]+|apache/[12]\.[0-9]|nginx/1\.[0-9]\.[0-9]|tomcat/[0-9]|spring-boot/[0-9]|struts/[0-9]|django/[0-9])").unwrap()
            });
        for caps in VERSION_DISCLOSURE_HEADER_RE.captures_iter(&decoded) {
            let Some(value) = caps.get(1) else {
                continue;
            };
            if let Some(version_match) = VERSION_DISCLOSURE_VALUE_RE.find(value.as_str()) {
                dets.push(L2Detection {
                    detection_type: "version_disclosure".into(),
                    confidence: 0.72,
                    detail: "Response header discloses framework/server version information".into(),
                    position: value.start() + version_match.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: value.as_str().to_owned(),
                        interpretation: "Disclosed platform versions increase exploitability by enabling targeted vulnerability mapping".into(),
                        offset: value.start() + version_match.start(),
                        property: "Server and framework version headers should be suppressed or normalized in production".into(),
                    }],
                });
                break;
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "bola_enumeration" => Some(InvariantClass::BolaIdor),
            "excessive_data" | "rate_limit_bypass" => Some(InvariantClass::ApiMassEnum),
            "api_graphql_batching_abuse"
            | "api_http_parameter_pollution"
            | "api_mass_enumeration"
            | "api_version_downgrade"
            | "api_jwt_claim_manipulation"
            | "api_method_tampering"
            | "api_ssrf_param_internal"
            | "api_excessive_scope"
            | "undocumented_endpoint_probe"
            | "version_disclosure"
            | "api_jwt_none_alg"
            | "api_deep_pagination"
            | "api_content_type_confusion"
            | "api_jwt_array_role"
            | "api_json_hpp" => Some(InvariantClass::ApiMassEnum),
            "api_idor_pattern" => Some(InvariantClass::BolaIdor),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_jwt_claim_manipulation_admin_claim() {
        let eval = ApiAbuseEvaluator;
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZSwidXNlciI6ImJvYiJ9.signature";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_jwt_claim_manipulation")
        );
    }

    #[test]
    fn detects_http_method_tampering_headers() {
        let eval = ApiAbuseEvaluator;
        let input = "POST /api/users/1 HTTP/1.1\r\nX-HTTP-Method-Override: DELETE\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_method_tampering")
        );
    }

    #[test]
    fn detects_api_version_downgrade() {
        let eval = ApiAbuseEvaluator;
        let input = "/api/v1/users?supported=/api/v2,/api/v3";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_version_downgrade")
        );
    }

    #[test]
    fn detects_graphql_batching_abuse() {
        let eval = ApiAbuseEvaluator;
        let input = r#"POST /graphql HTTP/1.1
Content-Type: application/json

[{"query":"{ users { id } }"},{"query":"{ users { name } }"}]"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_graphql_batching_abuse")
        );
    }

    #[test]
    fn detects_http_parameter_pollution_duplicates() {
        let eval = ApiAbuseEvaluator;
        let input = "GET /api/accounts?user=alice&id=10&id=11&status=active HTTP/1.1";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_http_parameter_pollution")
        );
    }

    #[test]
    fn detects_api_idor_sequential_path_ids() {
        let eval = ApiAbuseEvaluator;
        let input = "/api/users/1001/profile /api/users/1002/profile /api/users/1003/profile";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "api_idor_pattern"));
    }

    #[test]
    fn detects_api_mass_enumeration_via_query_list() {
        let eval = ApiAbuseEvaluator;
        let input = "/api/products?ids=101,102,103,104,105&limit=5";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_mass_enumeration")
        );
    }

    #[test]
    fn detects_api_mass_enumeration_via_repeated_ids() {
        let eval = ApiAbuseEvaluator;
        let input = "/api/items?id=200&id=201&id=202&id=203&id=204";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_mass_enumeration")
        );
    }

    #[test]
    fn detects_api_version_downgrade_media_type_hint() {
        let eval = ApiAbuseEvaluator;
        let input = "POST /api/users HTTP/1.1\nAccept: application/vnd.vendor+json;version=1, application/vnd.vendor+json;version=2\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_version_downgrade")
        );
    }

    #[test]
    fn maps_graphql_batching_to_api_mass_enum() {
        let eval = ApiAbuseEvaluator;
        assert_eq!(
            eval.map_class("api_graphql_batching_abuse"),
            Some(InvariantClass::ApiMassEnum)
        );
    }

    #[test]
    fn maps_idor_pattern_to_bola_idor() {
        let eval = ApiAbuseEvaluator;
        assert_eq!(
            eval.map_class("api_idor_pattern"),
            Some(InvariantClass::BolaIdor)
        );
    }

    #[test]
    fn detects_ssrf_via_api_callback_param() {
        let eval = ApiAbuseEvaluator;
        let input = "POST /hooks callback=http://169.254.169.254/latest/meta-data";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_ssrf_param_internal")
        );
    }

    #[test]
    fn detects_excessive_oauth_scope() {
        let eval = ApiAbuseEvaluator;
        let input = "grant_type=client_credentials&scope=read%20admin";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "api_excessive_scope")
        );
    }

    #[test]
    fn detects_undocumented_endpoint_probe() {
        let eval = ApiAbuseEvaluator;
        let input = "GET /swagger-ui?format=openapi HTTP/1.1";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "undocumented_endpoint_probe")
        );
    }

    #[test]
    fn detects_version_disclosure_in_headers() {
        let eval = ApiAbuseEvaluator;
        let input = "HTTP/1.1 200 OK\r\nServer: nginx/1.9.9\r\nX-Powered-By: Express/4.16\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "version_disclosure"));
    }

    #[test]
    fn detects_jwt_none_alg() {
        let eval = ApiAbuseEvaluator;
        // base64url of {"alg":"none"} is eyJhbGciOiJub25lIn0
        let input = "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "api_jwt_none_alg"));
    }

    #[test]
    fn detects_api_deep_pagination() {
        let eval = ApiAbuseEvaluator;
        let input = "GET /api/users?offset=100000 HTTP/1.1";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "api_deep_pagination"));
    }

    #[test]
    fn detects_api_content_type_confusion() {
        let eval = ApiAbuseEvaluator;
        let input = "POST /api/users HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{\"user\":\"admin\"}";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "api_content_type_confusion"));
    }

    #[test]
    fn detects_api_jwt_array_role() {
        let eval = ApiAbuseEvaluator;
        // base64url of {"roles":["user","admin"]} is eyJyb2xlcyI6WyJ1c2VyIiwiYWRtaW4iXX0
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlcyI6WyJ1c2VyIiwiYWRtaW4iXX0.sig";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "api_jwt_array_role"));
    }

    #[test]
    fn detects_api_json_hpp() {
        let eval = ApiAbuseEvaluator;
        let input = "{\"role\":\"user\", \"role\":\"admin\"}";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "api_json_hpp"));
    }
}
