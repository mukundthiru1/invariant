//! JWT Abuse Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct JwtEvaluator;

impl L2Evaluator for JwtEvaluator {
    fn id(&self) -> &'static str {
        "jwt"
    }
    fn prefix(&self) -> &'static str {
        "L2 JWT"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let far_future_threshold = now_epoch + (60 * 60 * 24 * 365 * 5);

        // JWT structure: base64.base64[.base64]
        static jwt_re: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(eyJ[A-Za-z0-9_-]+)\.(eyJ[A-Za-z0-9_-]+)(?:\.([A-Za-z0-9_-]*))?").unwrap()
        });
        for caps in jwt_re.captures_iter(&decoded) {
            let m = caps.get(0).unwrap();
            let header_b64 = caps.get(1).unwrap().as_str();
            let payload_b64 = caps.get(2).unwrap().as_str();
            let sig_segment = caps.get(3).map(|x| x.as_str()).unwrap_or_default();
            let has_signature_segment = caps.get(3).is_some();
            let token_without_signature = !has_signature_segment && !m.as_str().ends_with('.');

            // Try to decode header
            if let Some(header) = try_base64_decode_json(header_b64) {
                let header_norm = header.replace("\\/", "/");
                let header_lower = header.to_ascii_lowercase();
                let mut has_asymmetric_hint =
                    header_lower.contains("\"x5c\"") || header_lower.contains("\"x5u\"");

                // JKU header injection via attacker-controlled JWKS endpoint
                static JKU_HEADER_URL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
                    || Regex::new(r#"(?i)"jku"\s*:\s*"(https?://[^"]+)""#).unwrap(),
                );
                for cap in JKU_HEADER_URL_RE.captures_iter(&header_norm) {
                    let url = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                    if !is_allowlisted_api_host(url) {
                        dets.push(L2Detection {
                            detection_type: "jwt_jku_header_injection".into(),
                            confidence: 0.90,
                            detail: "JWT header jku points to non-allowlisted external JWKS URL"
                                .into(),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::PayloadInject,
                                matched_input: url.to_owned(),
                                interpretation:
                                    "Attacker-controlled jku can redirect key retrieval to untrusted JWKS"
                                        .into(),
                                offset: m.start(),
                                property: "JWT jku URLs must be strictly allowlisted".into(),
                            }],
                        });
                    }
                }
                // Algorithm: none
                static ALG_NONE_RE: std::sync::LazyLock<Regex> =
                    std::sync::LazyLock::new(|| Regex::new(r#"(?i)"alg"\s*:\s*"none""#).unwrap());
                if ALG_NONE_RE.is_match(&header) {
                    dets.push(L2Detection {
                        detection_type: "jwt_alg_none".into(),
                        confidence: 0.95,
                        detail: "JWT with algorithm 'none' — signature verification bypass".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::ContextEscape,
                            matched_input: "alg: none".into(),
                            interpretation:
                                "Algorithm 'none' bypasses all JWT signature verification".into(),
                            offset: m.start(),
                            property: "JWT algorithm must not be 'none' or user-controllable"
                                .into(),
                        }],
                    });
                }

                // Algorithm confusion: HS256 when asymmetric key metadata is present
                static ALG_HS256_RE: std::sync::LazyLock<Regex> =
                    std::sync::LazyLock::new(|| Regex::new(r#"(?i)"alg"\s*:\s*"HS256""#).unwrap());
                if ALG_HS256_RE.is_match(&header) {
                    let (confidence, detail) = if has_asymmetric_hint {
                        (
                            0.93,
                            "JWT advertises HS256 while including asymmetric-key material".into(),
                        )
                    } else {
                        (
                            0.82,
                            "JWT with HMAC algorithm — potential algorithm confusion attack".into(),
                        )
                    };
                    dets.push(L2Detection {
                        detection_type: "jwt_alg_confusion".into(),
                        confidence,
                        detail,
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::TypeCoerce,
                            matched_input: "alg: HS256".into(),
                            interpretation:
                                "HMAC algorithm may sign with public RSA key as HMAC secret".into(),
                            offset: m.start(),
                            property: "JWT algorithm must match server-expected algorithm".into(),
                        }],
                    });
                }

                // RS256-to-HS256 confusion with asymmetric key material present in header
                static RS_TO_HS_CONFUSION_RE: std::sync::LazyLock<Regex> =
                    std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?is)"alg"\s*:\s*"HS256".*?"(?:x5c|x5u|n|e)""#).unwrap()
                    });
                if RS_TO_HS_CONFUSION_RE.is_match(&header) {
                    dets.push(L2Detection {
                        detection_type: "jwt_rs256_to_hs256_confusion".into(),
                        confidence: 0.89,
                        detail:
                            "JWT uses HS256 while carrying asymmetric key material in header".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::TypeCoerce,
                            matched_input: header[..header.len().min(120)].to_owned(),
                            interpretation:
                                "Public-key metadata in HS256 token indicates RS256/HS256 confusion attempt"
                                    .into(),
                            offset: m.start(),
                            property:
                                "JWT alg must not be switchable between asymmetric and HMAC modes"
                                    .into(),
                        }],
                    });
                }

                // RFC 7797 b64=false can bypass validation in incompatible JWT libraries
                static B64_FALSE_RE: std::sync::LazyLock<Regex> =
                    std::sync::LazyLock::new(|| Regex::new(r#"(?i)"b64"\s*:\s*false"#).unwrap());
                if B64_FALSE_RE.is_match(&header) {
                    dets.push(L2Detection {
                        detection_type: "jwt_unencoded_payload".into(),
                        confidence: 0.92,
                        detail: "JWT header sets b64=false (unencoded payload form)".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::TypeCoerce,
                            matched_input: "\"b64\":false".into(),
                            interpretation: "Unencoded JWS payload mode can create parser/verification inconsistencies".into(),
                            offset: m.start(),
                            property: "JWT validators must reject b64=false unless explicitly required and fully supported".into(),
                        }],
                    });
                }

                // Empty/null signature with signed algorithm indicates unsigned-token bypass attempt
                if token_without_signature {
                    if !ALG_NONE_RE.is_match(&header) {
                        dets.push(L2Detection {
                            detection_type: "jwt_null_signature".into(),
                            confidence: 0.94,
                            detail: "JWT has no signature segment after payload".into(),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::ContextEscape,
                                matched_input: format!("{}.{}", header_b64, payload_b64),
                                interpretation: "Token omits signature bytes but may be parsed by permissive JWT middleware".into(),
                                offset: m.start(),
                                property: "JWT verification must require a signature segment for signed tokens".into(),
                            }],
                        });
                    }
                } else if sig_segment.is_empty() && !ALG_NONE_RE.is_match(&header) {
                    dets.push(L2Detection {
                        detection_type: "jwt_missing_signature".into(),
                        confidence: 0.93,
                        detail: "JWT has empty signature segment while header declares signed algorithm".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::ContextEscape,
                            matched_input: format!("{}.{}.", header_b64, caps.get(2).map(|x| x.as_str()).unwrap_or_default()),
                            interpretation: "Token omits signature bytes but may be parsed as valid by weak JWT middleware".into(),
                            offset: m.start(),
                            property: "JWT verification must require non-empty valid signature for signed algorithms".into(),
                        }],
                    });
                }

                // kid parameter injection
                static KID_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                    Regex::new(r#"(?i)"kid"\s*:\s*"((?:[^"\\]|\\.)*)""#).unwrap()
                });
                if let Some(cap) = KID_RE.captures(&header) {
                    let kid = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                    let kid_lower = kid.to_ascii_lowercase();
                    if kid.contains("../")
                        || kid.contains("%2e%2e")
                        || kid_lower.contains("' or")
                        || kid_lower.contains(" or ")
                        || kid_lower.contains("; drop")
                        || kid.contains("/dev/null")
                        || kid.contains("/proc/self")
                    {
                        dets.push(L2Detection {
                            detection_type: "jwt_kid_injection".into(),
                            confidence: 0.90,
                            detail: "JWT header 'kid' contains path traversal or SQL injection payload".into(),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::TypeCoerce,
                                matched_input: kid.to_owned(),
                                interpretation: "Kid key is used for key lookup and can alter key resolution when untrusted".into(),
                                offset: m.start(),
                                property: "JWT 'kid' should be validated as a fixed identifier".into(),
                            }],
                        });
                    }

                    if kid.contains("$(")
                        || kid.contains('%')
                        || kid.contains('`')
                        || kid.contains('|')
                        || kid_lower.starts_with("http://")
                        || kid_lower.starts_with("https://")
                        || kid_lower.starts_with("file://")
                        || kid_lower.contains("169.254.169.254")
                        || kid_lower.contains("localhost")
                    {
                        dets.push(L2Detection {
                            detection_type: "jwt_kid_command_or_ssrf".into(),
                            confidence: 0.92,
                            detail: "JWT kid includes command/meta-URL payload likely to taint key lookup".into(),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::PayloadInject,
                                matched_input: kid.to_owned(),
                                interpretation: "Kid value can be interpreted as shell/path/URL in dynamic key-fetch implementations".into(),
                                offset: m.start(),
                                property: "JWT kid must be a strict opaque identifier from a constrained character allowlist".into(),
                            }],
                        });
                    }
                }

                // KID path traversal payloads in key-id lookup
                static KID_PATH_TRAVERSAL_RE: std::sync::LazyLock<Regex> =
                    std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?i)"kid"\s*:\s*"([^"]*(?:\.\.[\\/]|/etc/|/dev/|/proc/|\\x00|%00)[^"]*)""#).unwrap()
                    });
                if let Some(cap) = KID_PATH_TRAVERSAL_RE.captures(&header_norm) {
                    let kid = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                    dets.push(L2Detection {
                        detection_type: "jwt_kid_path_traversal".into(),
                        confidence: 0.91,
                        detail: "JWT kid contains path traversal or null-byte lookup payload".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::TypeCoerce,
                            matched_input: kid.to_owned(),
                            interpretation:
                                "Path/meta characters in kid can alter filesystem or key-store lookup"
                                    .into(),
                            offset: m.start(),
                            property: "JWT kid must be constrained to a safe identifier format".into(),
                        }],
                    });
                }

                // Embedded JWK declaration
                static JWK_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                    Regex::new(r#"(?s)"jwk"\s*:\s*\{([^}]*)\}"#).unwrap()
                });
                static EMBEDDED_JWK_RE: std::sync::LazyLock<Regex> =
                    std::sync::LazyLock::new(|| Regex::new(r#"(?s)"jwk"\s*:\s*\{"#).unwrap());
                if EMBEDDED_JWK_RE.is_match(&header) {
                    dets.push(L2Detection {
                        detection_type: "jwt_embedded_jwk_attacker_key".into(),
                        confidence: 0.88,
                        detail: "JWT header contains embedded jwk object".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: header[..header.len().min(120)].to_owned(),
                            interpretation:
                                "Embedded JWK can inject attacker-selected signing key material".into(),
                            offset: m.start(),
                            property:
                                "JWT verification keys must come from trusted server-side stores"
                                    .into(),
                        }],
                    });
                }
                if let Some(cap) = JWK_RE.captures(&header) {
                    let jwk_body = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                    static KTY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?i)"kty"\s*:\s*"[^"]+""#).unwrap()
                    });
                    static N_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?i)"n"\s*:\s*"[^"]+""#).unwrap()
                    });
                    static E_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?i)"e"\s*:\s*"[^"]+""#).unwrap()
                    });
                    let has_kty = KTY_RE.is_match(jwk_body);
                    let has_n = N_RE.is_match(jwk_body);
                    let has_e = E_RE.is_match(jwk_body);

                    if has_kty && has_n && has_e {
                        has_asymmetric_hint = true;
                        dets.push(L2Detection {
                            detection_type: "jwt_jwk_embedding".into(),
                            confidence: 0.92,
                            detail: "JWT header includes embedded JWK with key fields".into(),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::PayloadInject,
                                matched_input: cap.get(0).map(|m| m.as_str().to_owned()).unwrap_or_default(),
                                interpretation: "Embedded JWK fields can inject attacker-controlled signing material".into(),
                                offset: m.start(),
                                property: "JWT header must not contain attacker-controlled JWK objects".into(),
                            }],
                        });
                    }

                    static OCT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?i)"kty"\s*:\s*"oct""#).unwrap()
                    });
                    static K_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?i)"k"\s*:\s*"[^"]+""#).unwrap()
                    });
                    let is_oct = OCT_RE.is_match(jwk_body);
                    let has_k = K_RE.is_match(jwk_body);
                    if is_oct && has_k {
                        dets.push(L2Detection {
                            detection_type: "jwt_jwk_symmetric".into(),
                            confidence: 0.90,
                            detail: "JWT embeds symmetric JWK material (kty=oct, k=...)".into(),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::TypeCoerce,
                                matched_input: cap.get(0).map(|x| x.as_str().to_owned()).unwrap_or_default(),
                                interpretation: "Embedded symmetric key can force HMAC verification under attacker-controlled secret".into(),
                                offset: m.start(),
                                property: "JWT key material must come from trusted server-side keystores, not token headers".into(),
                            }],
                        });
                    }
                }

                // JKU/X5U header injection
                static JKU_X5U_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                    Regex::new(r#"(?i)"(?:jku|x5u)"\s*:\s*"https?://"#).unwrap()
                });
                static JKU_INJECTION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
                    || {
                        Regex::new(r#"(?i)"(?:jku|x5u)"\s*:\s*"(?:http://|https://|file://|gopher://|ftp://)"#).unwrap()
                    },
                );
                if JKU_INJECTION_RE.is_match(&header_norm) {
                    dets.push(L2Detection {
                        detection_type: "jwt_jku_injection".into(),
                        confidence: 0.91,
                        detail: "JWT JKU/X5U header points to attacker-controlled key endpoint"
                            .into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: header[..header.len().min(90)].to_owned(),
                            interpretation: "External key URL may alter verification trust chain"
                                .into(),
                            offset: m.start(),
                            property: "JWT key URLs must be validated against an allowlist".into(),
                        }],
                    });
                }
                if JKU_X5U_RE.is_match(&header_norm) {
                    dets.push(L2Detection {
                        detection_type: "jwt_key_injection".into(),
                        confidence: 0.90,
                        detail: "JWT JKU/X5U header points to external key — key injection".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: header[..header.len().min(60)].to_owned(),
                            interpretation: "JKU/X5U URL loads attacker-controlled signing keys"
                                .into(),
                            offset: m.start(),
                            property: "JWT key URLs must be validated against allowlist".into(),
                        }],
                    });
                }

                // JKU/X5U SSRF/internal-host key retrieval
                if let Some(url) = extract_internal_key_url(&header_norm) {
                    dets.push(L2Detection {
                        detection_type: "jwt_jku_ssrf".into(),
                        confidence: 0.95,
                        detail: "JWT key URL points to internal/local address".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: url,
                            interpretation: "Key-fetch URL can be abused to SSRF internal services or metadata endpoints".into(),
                            offset: m.start(),
                            property: "JWT key URL resolution must block internal/private/link-local addresses and non-HTTPS schemes".into(),
                        }],
                    });
                }

                // Claim manipulation checks: issuer/audience spoofing and expiry inflation
                if let Some(payload_json) = try_base64_decode_json(payload_b64) {
                    static EXP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?i)"exp"\s*:\s*(\d{5,})"#).unwrap()
                    });
                    static CLAIM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                        Regex::new(r#"(?i)"(iss|aud)"\s*:\s*"([^"]+)""#).unwrap()
                    });
                    static NESTED_JWT_RE: std::sync::LazyLock<Regex> =
                        std::sync::LazyLock::new(|| {
                            Regex::new(r#""[^"]*"\s*:\s*"([A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})""#).unwrap()
                        });

                    if let Some(cap) = NESTED_JWT_RE.captures(&payload_json) {
                        dets.push(L2Detection {
                            detection_type: "jwt_nested_bypass".into(),
                            confidence: 0.78,
                            detail: "JWT payload contains nested JWT token-like claim value".into(),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::SemanticEval,
                                matched_input: cap.get(1).map(|x| x.as_str().to_owned()).unwrap_or_default(),
                                interpretation: "Nested JWTs can bypass single-pass claim validation and trust boundaries".into(),
                                offset: m.start(),
                                property: "JWT claims must reject nested unsigned/untrusted token structures".into(),
                            }],
                        });
                    }

                    if let Some(cap) = EXP_RE.captures(&payload_json) {
                        if let Some(exp) = cap.get(1).and_then(|m| m.as_str().parse::<i64>().ok()) {
                            if exp >= far_future_threshold {
                                dets.push(L2Detection {
                                    detection_type: "jwt_claim_manipulation".into(),
                                    confidence: 0.91,
                                    detail: "JWT exp claim is set too far in the future".into(),
                                    position: m.start(),
                                    evidence: vec![ProofEvidence {
                                        operation: EvidenceOperation::SemanticEval,
                                        matched_input: cap
                                            .get(0)
                                            .map(|x| x.as_str().to_owned())
                                            .unwrap_or_default(),
                                        interpretation:
                                            "Excessive expiry suggests token lifetime manipulation"
                                                .into(),
                                        offset: m.start(),
                                        property:
                                            "JWT exp should be bounded and validated server-side"
                                                .into(),
                                    }],
                                });
                            }
                        }
                    }

                    for cap in CLAIM_RE.captures_iter(&payload_json) {
                        let claim_name = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                        let value = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
                        let lower = value.to_ascii_lowercase();
                        let suspicious_claim = lower.contains("admin")
                            || lower.contains("attacker")
                            || lower.contains("localhost")
                            || value.starts_with("http://")
                            || value.starts_with("https://")
                            || lower.contains("evil")
                            || value.contains("..");

                        if suspicious_claim {
                            dets.push(L2Detection {
                                detection_type: "jwt_claim_manipulation".into(),
                                confidence: 0.90,
                                detail: format!("JWT claim {} appears spoofed", claim_name),
                                position: m.start(),
                                evidence: vec![ProofEvidence {
                                    operation: EvidenceOperation::SemanticEval,
                                    matched_input: cap.get(0).map(|x| x.as_str().to_owned()).unwrap_or_default(),
                                    interpretation: "iss/aud claims can be attacker-controlled to alter authority context".into(),
                                    offset: m.start(),
                                    property: "JWT iss/aud claims should be strict allowlisted identities".into(),
                                }],
                            });
                            break;
                        }
                    }
                }

                // Critical header confusion via unsupported crit claims
                static CRIT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                    Regex::new(r#"(?is)"crit"\s*:\s*\[([^\]]+)\]"#).unwrap()
                });
                if let Some(cap) = CRIT_RE.captures(&header) {
                    let crit_items = cap
                        .get(1)
                        .map(|x| x.as_str())
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if crit_items.contains("b64")
                        || crit_items.contains("jwk")
                        || crit_items.contains("jku")
                    {
                        dets.push(L2Detection {
                            detection_type: "jwt_crit_header_abuse".into(),
                            confidence: 0.88,
                            detail: "JWT uses critical headers likely to trigger verification inconsistencies".into(),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::TypeCoerce,
                                matched_input: cap.get(0).map(|x| x.as_str().to_owned()).unwrap_or_default(),
                                interpretation: "Critical header claims can bypass validation in libraries that ignore unsupported crit values".into(),
                                offset: m.start(),
                                property: "JWT processors must reject tokens with unsupported critical header parameters".into(),
                            }],
                        });
                    }
                }
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "jwt_alg_none" => Some(InvariantClass::AuthNoneAlgorithm),
            "jwt_alg_confusion"
            | "jwt_unencoded_payload"
            | "jwt_missing_signature"
            | "jwt_null_signature"
            | "jwt_crit_header_abuse"
            | "jwt_rs256_to_hs256_confusion"
            | "jwt_nested_bypass"
            | "jwt_claim_manipulation" => Some(InvariantClass::JwtConfusion),
            "jwt_key_injection" | "jwt_jku_injection" | "jwt_jwk_embedding"
            | "jwt_jwk_symmetric"
            | "jwt_jku_ssrf"
            | "jwt_jku_header_injection"
            | "jwt_embedded_jwk_attacker_key" => Some(InvariantClass::JwtJwkEmbedding),
            "jwt_kid_injection" | "jwt_kid_command_or_ssrf" | "jwt_kid_path_traversal" => {
                Some(InvariantClass::JwtKidInjection)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT_KID_HEADER: &str = "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLyJ9";
    const JWT_JWK_HEADER: &str =
        "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiYSIsImUiOiJBIn19";
    const JWT_HS256_RSA_JWK_HEADER: &str =
        "eyJhbGciOiJIUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiWVEiLCJlIjoiQVFBQiJ9fQ";
    const JWT_KID_PATH_HEADER: &str = "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLyJ9";
    const JWT_JKU_HEADER: &str =
        "eyJhbGciOiJIUzI1NiIsImprdSI6Imh0dHA6Ly9hdHRhY2tlci5sb2NhbC9qd2tzLmpzb24ifQ";
    const JWT_FAR_FUTURE_CLAIMS: &str = "eyJleHAiOjk5OTk5OTk5OTksImlzcyI6ImF0dGFja2VyIiwiYXVkIjoiaHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tIn0";
    const JWT_PAYLOAD: &str = "eyJmb28iOiJiYXIifQ";

    #[test]
    fn detects_jwt_kid_injection() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_KID_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        assert!(dets.iter().any(|d| d.detection_type == "jwt_kid_injection"));
        assert!(dets.iter().any(|d| !d.evidence.is_empty()));
        assert_eq!(
            eval.map_class("jwt_kid_injection"),
            Some(InvariantClass::JwtKidInjection)
        );
    }

    #[test]
    fn detects_jwt_jwk_embedding() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_JWK_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        assert!(dets.iter().any(|d| d.detection_type == "jwt_jwk_embedding"));
        assert!(dets.iter().any(|d| !d.evidence.is_empty()));
        assert_eq!(
            eval.map_class("jwt_jwk_embedding"),
            Some(InvariantClass::JwtJwkEmbedding)
        );
    }

    #[test]
    fn detects_jwt_alg_confusion_rs256_to_hs256_with_jwk_hint() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_HS256_RSA_JWK_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        assert!(dets.iter().any(|d| d.detection_type == "jwt_alg_confusion"));
    }

    #[test]
    fn detects_jwt_jku_injection_header() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_JKU_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        assert!(dets.iter().any(|d| d.detection_type == "jwt_jku_injection"));
    }

    #[test]
    fn detects_jku_header_injection_confidence_threshold() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_JKU_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "jwt_jku_header_injection");
        assert!(det.is_some());
        assert!(det.map(|d| d.confidence > 0.75).unwrap_or(false));
    }

    #[test]
    fn detects_jwt_kid_path_traversal_injection() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_KID_PATH_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        assert!(dets.iter().any(|d| d.detection_type == "jwt_kid_injection"));
    }

    #[test]
    fn detects_kid_path_traversal_confidence_threshold() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_KID_PATH_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "jwt_kid_path_traversal");
        assert!(det.is_some());
        assert!(det.map(|d| d.confidence > 0.75).unwrap_or(false));
    }

    #[test]
    fn detects_jwt_forge_far_future_exp_claim() {
        let eval = JwtEvaluator;
        let header = "eyJhbGciOiJIUzI1NiJ9";
        let token = format!("{}.{}.c2ln", header, JWT_FAR_FUTURE_CLAIMS);
        let dets = eval.detect(&token);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "jwt_claim_manipulation")
        );
    }

    #[test]
    fn detects_jwt_iss_aud_spoof_claims() {
        let eval = JwtEvaluator;
        let token = format!(
            "{}.{}.c2ln",
            JWT_HS256_RSA_JWK_HEADER, JWT_FAR_FUTURE_CLAIMS
        );
        let dets = eval.detect(&token);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "jwt_claim_manipulation")
        );
    }

    #[test]
    fn detects_rs256_to_hs256_confusion_confidence_threshold() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_HS256_RSA_JWK_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "jwt_rs256_to_hs256_confusion");
        assert!(det.is_some());
        assert!(det.map(|d| d.confidence > 0.75).unwrap_or(false));
    }

    #[test]
    fn detects_jwt_null_signature_removed() {
        let eval = JwtEvaluator;
        let header = "eyJhbGciOiJIUzI1NiJ9";
        let token = format!("{}.{}", header, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "jwt_null_signature")
        );
    }

    #[test]
    fn maps_jku_injection_to_jwk_embedding_class() {
        let eval = JwtEvaluator;
        assert_eq!(
            eval.map_class("jwt_jku_injection"),
            Some(InvariantClass::JwtJwkEmbedding)
        );
    }

    #[test]
    fn maps_alg_none_to_auth_none() {
        let eval = JwtEvaluator;
        assert_eq!(
            eval.map_class("jwt_alg_none"),
            Some(InvariantClass::AuthNoneAlgorithm)
        );
    }

    #[test]
    fn maps_key_injection_to_jwk_embedding_class() {
        let eval = JwtEvaluator;
        assert_eq!(
            eval.map_class("jwt_key_injection"),
            Some(InvariantClass::JwtJwkEmbedding)
        );
    }

    #[test]
    fn detects_b64_false_and_missing_signature() {
        let eval = JwtEvaluator;
        let header = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2V9";
        let token = format!("{}.{}.", header, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "jwt_unencoded_payload")
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "jwt_missing_signature")
        );
    }

    #[test]
    fn detects_kid_command_payload() {
        let eval = JwtEvaluator;
        let header = "eyJhbGciOiJIUzI1NiIsImtpZCI6IiQoY2F0IC9ldGMvcGFzc3dkKSJ9";
        let token = format!("{}.{}.c2ln", header, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "jwt_kid_command_or_ssrf")
        );
    }

    #[test]
    fn detects_jku_ssrf_and_jwk_symmetric() {
        let eval = JwtEvaluator;
        let jku_header =
            "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly8xNjkuMjU0LjE2OS4yNTQva2V5cy5qc29uIn0";
        let jwk_oct_header =
            "eyJhbGciOiJIUzI1NiIsImp3ayI6eyJrdHkiOiJvY3QiLCJrIjoiYXR0YWNrZXJzZWNyZXQifX0";
        let jku = eval.detect(&format!("{}.{}.c2ln", jku_header, JWT_PAYLOAD));
        let jwk = eval.detect(&format!("{}.{}.c2ln", jwk_oct_header, JWT_PAYLOAD));
        assert!(jku.iter().any(|d| d.detection_type == "jwt_jku_ssrf"));
        assert!(jwk.iter().any(|d| d.detection_type == "jwt_jwk_symmetric"));
    }

    #[test]
    fn detects_embedded_jwk_attacker_key_confidence_threshold() {
        let eval = JwtEvaluator;
        let token = format!("{}.{}.c2ln", JWT_JWK_HEADER, JWT_PAYLOAD);
        let dets = eval.detect(&token);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "jwt_embedded_jwk_attacker_key");
        assert!(det.is_some());
        assert!(det.map(|d| d.confidence > 0.75).unwrap_or(false));
    }

    #[test]
    fn detects_nested_jwt_bypass_confidence_threshold() {
        let eval = JwtEvaluator;
        let header = "eyJhbGciOiJIUzI1NiJ9";
        let nested_payload = "eyJpbm5lciI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBLkJCQkJCQkJCQkJCQkJCQkJCQkJCLkNDQ0NDQ0NDQ0MifQ";
        let token = format!("{}.{}.c2ln", header, nested_payload);
        let dets = eval.detect(&token);
        let det = dets.iter().find(|d| d.detection_type == "jwt_nested_bypass");
        assert!(det.is_some());
        assert!(det.map(|d| d.confidence > 0.75).unwrap_or(false));
    }
}

fn try_base64_decode_json(input: &str) -> Option<String> {
    if let Some(bytes) = decode_base64_urlsafe(input) {
        if let Ok(s) = String::from_utf8(bytes) {
            if s.starts_with('{') && s.contains('"') {
                return Some(s);
            }
        }
    }

    // URL-safe base64 to standard
    let standard: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            x => x,
        })
        .collect();

    // Add padding
    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        _ => standard,
    };

    let decoded = crate::encoding::multi_layer_decode(&padded);
    // If it decoded base64, use that
    for form in &decoded.all_forms {
        if form.starts_with('{') && form.contains('"') {
            return Some(form.clone());
        }
    }

    None
}

fn decode_base64_urlsafe(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;

    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let val = match ch {
            'A'..='Z' => ch as u8 - b'A',
            'a'..='z' => ch as u8 - b'a' + 26,
            '0'..='9' => ch as u8 - b'0' + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return None,
        } as u32;

        buffer = (buffer << 6) | val;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }

    Some(out)
}

fn extract_internal_key_url(header_json: &str) -> Option<String> {
    static KEY_URL_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r#"(?i)"(?:jku|x5u)"\s*:\s*"([^"]+)""#).unwrap());
    for cap in KEY_URL_RE.captures_iter(header_json) {
        let url = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        if is_internal_or_local_key_url(url) {
            return Some(url.to_string());
        }
    }
    None
}

fn is_allowlisted_api_host(url: &str) -> bool {
    static API_HOST_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)^api\.[a-z]+\.[a-z]+$").unwrap());
    extract_url_host(url)
        .map(|host| API_HOST_RE.is_match(&host))
        .unwrap_or(false)
}

fn extract_url_host(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    let allowed_scheme = ["http://", "https://", "ftp://", "file://", "gopher://"];
    let scheme = allowed_scheme.iter().find(|s| lower.starts_with(**s))?;
    let rest = &lower[scheme.len()..];
    let host = if let Some(stripped) = rest.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        rest.split(['/', ':', '?', '#']).next().unwrap_or("")
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn is_internal_or_local_key_url(url: &str) -> bool {
    let Some(host) = extract_url_host(url) else {
        return false;
    };
    if host == "localhost" || host == "0.0.0.0" || host == "127.0.0.1" || host == "::1" {
        return true;
    }
    if host == "169.254.169.254" {
        return true;
    }
    if host.starts_with("10.") || host.starts_with("192.168.") {
        return true;
    }
    if let Some(second) = host.strip_prefix("172.").and_then(|s| s.split('.').next()) {
        if let Ok(octet) = second.parse::<u8>() {
            if (16..=31).contains(&octet) {
                return true;
            }
        }
    }
    false
}
