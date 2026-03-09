//! OAuth Flow Abuse Evaluator — Level 2
//!
//! Detects attacks against OAuth 2.0 authorization flows:
//!   - Open redirect in redirect_uri (authorization code theft)
//!   - State parameter missing/predictable (CSRF on OAuth)
//!   - Token leakage via Referer/fragment
//!   - PKCE downgrade attacks
//!   - Scope manipulation
//!   - Client confusion / IdP mix-up

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct OAuthEvaluator;

impl OAuthEvaluator {
    fn detect_oauth_fixation(&self, lower: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();

        if lower.contains("response_type=token") {
            let pos = lower.find("response_type=token").unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "oauth_token_fixation_implicit".into(),
                confidence: 0.85,
                detail: "OAuth implicit flow (response_type=token) enables token fixation via URL fragment"
                    .into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: "response_type=token".into(),
                    interpretation: "Implicit flow leaks the access_token in the URL fragment, which can be fixated or stolen via Referer or redirect chain abuse.".into(),
                    offset: pos,
                    property: "Authorization code flow with PKCE must be used instead of implicit flow."
                        .into(),
                }],
            });
        }

        if lower.contains("redirect_uri=") {
            if let Some(pos) = lower.find("redirect_uri=") {
                let value_start = pos + "redirect_uri=".len();
                let value_end = lower[value_start..]
                    .find('&')
                    .map(|i| value_start + i)
                    .unwrap_or(lower.len());
                let redirect_value = &lower[value_start..value_end];

                if redirect_value.contains("authorize?")
                    || redirect_value.contains("/oauth/")
                    || redirect_value.contains("response_type=")
                {
                    dets.push(L2Detection {
                        detection_type: "oauth_redirect_chain_abuse".into(),
                        confidence: 0.95,
                        detail: "OAuth redirect_uri contains another OAuth endpoint (redirect chain abuse)"
                            .into(),
                        position: pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::SemanticEval,
                            matched_input: redirect_value.to_string(),
                            interpretation: "Chaining OAuth redirect URIs can be used to leak authorization codes or tokens to unintended endpoints in a token fixation or theft attack.".into(),
                            offset: pos,
                            property: "redirect_uri must be strictly validated against a static allowlist and should not chain into other authorization endpoints.".into(),
                        }],
                    });
                }
            }
        }

        let seq_code_re = Regex::new(r"(?i)[?&]code=(?:12345?|23456?|34567?|45678?|56789?|01234?|98765?|87654?|76543?|65432?|54321?|\d{1,4})(?:&|$)").unwrap();
        if let Some(m) = seq_code_re.find(lower) {
            dets.push(L2Detection {
                detection_type: "oauth_code_fixation_probe".into(),
                confidence: 0.88,
                detail:
                    "OAuth authorization code contains predictable or sequential numeric values (fixation probe)"
                        .into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Short, numeric, or sequential authorization codes indicate a brute-force or fixation probe attempt against the OAuth callback.".into(),
                    offset: m.start(),
                    property: "Authorization codes must be cryptographically random strings with high entropy.".into(),
                }],
            });
        }

        dets
    }
}

impl L2Evaluator for OAuthEvaluator {
    fn id(&self) -> &'static str {
        "oauth"
    }
    fn prefix(&self) -> &'static str {
        "L2 OAuth"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();
        let pkce_plain_re = Regex::new(r"(?i)code_challenge_method=plain").expect("valid regex");
        let pkce_no_s256_re = Regex::new(r"code_challenge=[^&]+").expect("valid regex");
        let auth_code_re = Regex::new(r"(?:[?&])code=[A-Za-z0-9._~+/-]{10,}").expect("valid regex");
        let token_referer_re = Regex::new(r"(?i)(?:access_token|id_token)=[A-Za-z0-9._~+/-]+=*|[?&]code=[A-Za-z0-9._~+/-]{10,}").expect("valid regex");
        let request_uri_re = Regex::new(r"(?i)[?&]request_uri=https?://[^\s&]+").expect("valid regex");
        let redirect_double_encoded_re =
            Regex::new(r"(?i)[?&]redirect_uri=[^&]*%25(?:2f|3a|40|00|0a|0d)[^&]*")
                .expect("valid regex");

        // 1. redirect_uri manipulation (the #1 OAuth attack vector)
        if lower.contains("redirect_uri=") {
            // Check for suspicious redirect targets
            if let Some(pos) = lower.find("redirect_uri=") {
                let value_start = pos + "redirect_uri=".len();
                let value_end = lower[value_start..].find('&').map(|i| value_start + i).unwrap_or(lower.len());
                let redirect_value = &decoded[value_start..value_end];

                let is_suspicious = redirect_value.contains("@") ||
                    redirect_value.contains("\\") ||
                    redirect_value.contains("//evil") ||
                    redirect_value.contains("//attacker") ||
                    redirect_value.contains(".evil.") ||
                    redirect_value.contains("localhost") ||
                    redirect_value.contains("127.0.0.1") ||
                    // URL encoding tricks
                    redirect_value.contains("%2f%2f") ||
                    redirect_value.contains("%40") ||
                    // Path traversal in redirect_uri
                    redirect_value.contains("/../") ||
                    redirect_value.contains("/..%2f") ||
                    // Fragment smuggling
                    redirect_value.contains("#");

                if is_suspicious {
                    dets.push(L2Detection {
                        detection_type: "oauth_redirect_uri_manipulation".into(),
                        confidence: 0.88,
                        detail: format!(
                            "OAuth redirect_uri contains suspicious pattern: {}",
                            &redirect_value[..redirect_value.len().min(80)]
                        ),
                        position: pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::ContextEscape,
                            matched_input: redirect_value[..redirect_value.len().min(100)].to_string(),
                            interpretation: "redirect_uri manipulation is the primary OAuth attack vector. If the authorization server redirects the authorization code to an attacker-controlled URI, the attacker can exchange it for an access token. Path traversal, fragment tricks, and encoding bypasses are used to defeat allowlist validation.".into(),
                            offset: pos,
                            property: "OAuth redirect_uri must be validated using exact string comparison against a pre-registered allowlist. Partial matching, subdomain matching, and path-based matching are insufficient.".into(),
                        }],
                    });
                }
            }
        }

        // 2. Missing or weak state parameter
        if (lower.contains("response_type=code") || lower.contains("response_type=token")) &&
            !lower.contains("state=")
        {
            dets.push(L2Detection {
                detection_type: "oauth_missing_state".into(),
                confidence: 0.82,
                detail: "OAuth authorization request missing 'state' parameter — CSRF vulnerability".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(120)].to_string(),
                    interpretation: "OAuth authorization request lacks the 'state' parameter. Without it, an attacker can craft a malicious authorization URL and trick the victim into authorizing the attacker's account (login CSRF) or linking the attacker's identity to the victim's session.".into(),
                    offset: 0,
                    property: "OAuth authorization requests must include a cryptographically random 'state' parameter bound to the user's session. The callback must verify the state matches.".into(),
                }],
            });
        }

        // 3. response_type=token (implicit flow — deprecated, insecure)
        if lower.contains("response_type=token") {
            dets.push(L2Detection {
                detection_type: "oauth_implicit_flow".into(),
                confidence: 0.75,
                detail: "OAuth implicit flow (response_type=token) — deprecated and insecure".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: "response_type=token".into(),
                    interpretation: "The OAuth implicit flow exposes the access token in the URL fragment, making it vulnerable to theft via Referer headers, browser history, and open redirect chains. OAuth 2.1 deprecates this flow entirely.".into(),
                    offset: 0,
                    property: "Applications must use the authorization code flow with PKCE instead of the implicit flow. response_type=token should be rejected.".into(),
                }],
            });
        }

        // 4. Scope escalation
        let dangerous_scopes = [
            "admin",
            "write",
            "delete",
            "manage",
            "root",
            "superuser",
            "*",
            "all",
            "full_access",
            "read_write",
        ];
        let standard_oidc_scopes = ["openid", "profile", "email", "phone", "address", "offline_access"];

        if lower.contains("scope=") {
            if let Some(pos) = lower.find("scope=") {
                let value_start = pos + "scope=".len();
                let value_end = lower[value_start..].find('&').map(|i| value_start + i).unwrap_or(lower.len());
                let scope_value = &lower[value_start..value_end];
                let normalized_scope = scope_value.replace('+', " ");
                let scope_tokens: Vec<&str> = normalized_scope
                    .split(|c: char| c.is_whitespace() || c == ',')
                    .filter(|s| !s.is_empty())
                    .collect();
                let is_only_standard_oidc = !scope_tokens.is_empty()
                    && scope_tokens
                        .iter()
                        .all(|s| standard_oidc_scopes.contains(s));

                if !is_only_standard_oidc {
                    for &scope in &dangerous_scopes {
                        if scope_value.contains(scope)
                            || scope_tokens.iter().any(|token| token == &scope)
                        {
                            dets.push(L2Detection {
                                detection_type: "oauth_scope_escalation".into(),
                                confidence: 0.78,
                                detail: format!("OAuth scope contains sensitive permission: {}", scope),
                                position: pos,
                                evidence: vec![ProofEvidence {
                                    operation: EvidenceOperation::SemanticEval,
                                    matched_input: decoded[value_start..value_end.min(decoded.len())].to_string(),
                                    interpretation: format!(
                                        "OAuth scope contains '{}' which grants elevated privileges. If the authorization server does not enforce scope restrictions per-client, an attacker can escalate permissions by modifying the scope parameter.",
                                        scope
                                    ),
                                    offset: pos,
                                    property: "OAuth scopes must be validated against the client's registered scope allowlist. Scope escalation beyond the client's allowed scopes must be rejected.".into(),
                                }],
                            });
                            break;
                        }
                    }
                }
            }
        }

        // 5. client_id/client_secret in URL (token leakage risk)
        if lower.contains("client_secret=") {
            dets.push(L2Detection {
                detection_type: "oauth_secret_exposure".into(),
                confidence: 0.90,
                detail: "OAuth client_secret in request — must never be in URL/query parameters".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: "client_secret=***".into(),
                    interpretation: "The OAuth client_secret is present in the request. Client secrets in URL parameters are logged by proxies, CDNs, and browser history. They must be transmitted only in the HTTP body or Authorization header.".into(),
                    offset: 0,
                    property: "OAuth client_secret must never appear in URL query parameters. Use HTTP POST body or Authorization header for confidential client authentication.".into(),
                }],
            });
        }

        // 6. PKCE bypass/downgrade patterns
        if let Some(m) = pkce_plain_re.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "oauth_pkce_plain".into(),
                confidence: 0.82,
                detail: "OAuth PKCE uses code_challenge_method=plain — downgrade risk".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_string(),
                    interpretation: "PKCE with code_challenge_method=plain weakens verifier protection and enables downgrade behavior in misconfigured authorization servers.".into(),
                    offset: m.start(),
                    property: "PKCE must require code_challenge_method=S256 and reject plain challenges.".into(),
                }],
            });
        }

        if let Some(m) = pkce_no_s256_re.find(&decoded) {
            if !lower.contains("code_challenge_method=s256") {
            dets.push(L2Detection {
                detection_type: "oauth_pkce_missing_s256".into(),
                confidence: 0.75,
                detail: "OAuth code_challenge present without explicit S256 method".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Authorization request includes code_challenge but does not enforce code_challenge_method=S256, which can permit weaker PKCE handling.".into(),
                    offset: m.start(),
                    property: "Authorization servers must enforce PKCE S256 for code flow clients and reject requests without S256.".into(),
                }],
            });
            }
        }

        if lower.contains("grant_type=authorization_code")
            && lower.contains("code_challenge=")
            && !lower.contains("code_verifier=")
        {
            let pos = lower.find("grant_type=authorization_code").unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "oauth_pkce_missing_verifier".into(),
                confidence: 0.82,
                detail: "OAuth token request missing code_verifier while using PKCE challenge".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(180)].to_string(),
                    interpretation: "Authorization code token exchange appears without code_verifier despite PKCE challenge usage, indicating verifier validation may be bypassed.".into(),
                    offset: pos,
                    property: "Token endpoints must require and validate code_verifier for PKCE-protected authorization code grants.".into(),
                }],
            });
        }

        // 7. Token leakage via Referer header / URL contexts
        let in_referer_header =
            lower.contains("referer:") || (lower.contains("header") && lower.contains("referer"));
        let in_url_context = lower.contains("http://") || lower.contains("https://") || lower.contains("get ");
        if in_referer_header {
            if let Some(m) = token_referer_re.find(&decoded) {
                let prefix = &lower[..m.start().min(lower.len())];
                if prefix.contains("referer") {
                    dets.push(L2Detection {
                        detection_type: "oauth_token_leakage_referer".into(),
                        confidence: 0.88,
                        detail: "OAuth token or authorization code appears in Referer header value".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::SemanticEval,
                            matched_input: m.as_str().to_string(),
                            interpretation: "OAuth credential in Referer context indicates leakage to downstream origins, logs, or analytics services. This includes access_token, id_token, and authorization code values.".into(),
                            offset: m.start(),
                            property: "Tokens and authorization codes must not appear in URLs or Referer headers. Use Authorization headers and strict referrer policy.".into(),
                        }],
                    });
                }
            }
        } else if in_url_context {
            if let Some(m) = token_referer_re.find(&decoded) {
                let matched = m.as_str().to_ascii_lowercase();
                let is_code = matched.starts_with("?code=") || matched.starts_with("&code=");
                let looks_callback = lower.contains("callback")
                    || lower.contains("/cb")
                    || lower.contains("redirect_uri");
                if !is_code || !looks_callback {
                    dets.push(L2Detection {
                        detection_type: "oauth_token_leakage_referer".into(),
                        confidence: 0.88,
                        detail: "OAuth token or authorization code appears in URL context".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::SemanticEval,
                            matched_input: m.as_str().to_string(),
                            interpretation: "OAuth credential appears directly in a URL context, which risks leakage through logs, history, and downstream systems.".into(),
                            offset: m.start(),
                            property: "Tokens and authorization codes must not appear in URL fragments or query strings except on tightly controlled callback exchanges.".into(),
                        }],
                    });
                }
            }
        }

        // 8. Authorization code injection / replay-like transport misuse
        let code_matches: Vec<_> = auth_code_re.find_iter(&decoded).collect();
        if code_matches.len() >= 2 {
            let first = code_matches[0];
            dets.push(L2Detection {
                detection_type: "oauth_code_injection".into(),
                confidence: 0.78,
                detail: "Duplicate OAuth code parameter indicates potential authorization code injection".into(),
                position: first.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: first.as_str().to_string(),
                    interpretation: "Multiple authorization code parameters can trigger parser ambiguity and code substitution during callback processing.".into(),
                    offset: first.start(),
                    property: "OAuth callbacks must accept a single code parameter and reject duplicates.".into(),
                }],
            });
        } else if let Some(m) = code_matches.first() {
            let non_callback = !lower.contains("callback")
                && !lower.contains("/cb")
                && !lower.contains("redirect_uri");
            let in_get_url = lower.contains("get ") || m.as_str().starts_with("?") || m.as_str().starts_with("&");
            if non_callback && in_get_url {
                dets.push(L2Detection {
                    detection_type: "oauth_code_injection".into(),
                    confidence: 0.78,
                    detail: "OAuth authorization code found in non-callback URL context".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: m.as_str().to_string(),
                        interpretation: "Authorization code parameter appears in a context that looks unrelated to OAuth callback handling, which can indicate replay or code injection attempts.".into(),
                        offset: m.start(),
                        property: "Authorization codes should only be accepted at the registered callback endpoint and exchanged once.".into(),
                    }],
                });
            }
        }

        // 9. OAuth request_uri parameter injection
        if lower.contains("request_uri=") {
            if let Some(m) = request_uri_re.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "oauth_request_uri_injection".into(),
                    confidence: 0.93,
                    detail: "OAuth request_uri points to external URL".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: m.as_str().to_string(),
                        interpretation: "request_uri parameter allows loading OAuth request parameters from an external URL. Attackers can host a malicious JWT at an attacker-controlled URL, enabling parameter injection (scope escalation, redirect_uri override, client_id spoofing) that bypasses inline parameter validation.".into(),
                        offset: m.start(),
                        property: "Authorization servers must tightly restrict request_uri usage to pre-registered, allowlisted URIs or require signed request objects with strict validation.".into(),
                    }],
                });
            }
        }

        // 10. OIDC nonce missing for id_token or implicit token flows
        let has_response_type = lower.contains("response_type=");
        let has_id_token_response = lower.contains("response_type=") && lower.contains("id_token");
        let has_token_response = lower.contains("response_type=") && lower.contains("token");
        let has_openid_scope = lower.contains("scope=openid")
            || lower.contains("scope=openid+")
            || lower.contains("scope=openid%20")
            || lower.contains(" openid");
        let is_oidc_request = has_openid_scope || has_id_token_response;
        if has_response_type
            && (has_id_token_response || has_token_response)
            && !lower.contains("nonce=")
            && is_oidc_request
        {
            let pos = lower.find("response_type=").unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "oauth_nonce_missing_oidc".into(),
                confidence: 0.86,
                detail: "OIDC request with id_token/implicit response is missing nonce".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(160)].to_string(),
                    interpretation: "OIDC requires a nonce for id_token responses to prevent replay attacks. Without a nonce, an id_token can be replayed to authenticate as the victim user on any relying party that accepts it. This is a standard OIDC security requirement (Section 3.1.2.1).".into(),
                    offset: pos,
                    property: "OIDC authorization requests returning id_token must include a cryptographically random nonce and validate it in the returned token.".into(),
                }],
            });
        }

        // 11. redirect_uri double-encoding bypass patterns
        if let Some(m) = redirect_double_encoded_re
            .find(input)
            .or_else(|| redirect_double_encoded_re.find(&decoded))
        {
            dets.push(L2Detection {
                detection_type: "oauth_redirect_double_encoded".into(),
                confidence: 0.88,
                detail: "OAuth redirect_uri contains double-encoded control/path characters".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Double-encoded URL characters (%252f = %2f = /) in redirect_uri bypass single-pass URL decoders used in validation. The registration endpoint sees the encoded safe URL, while the OAuth server decodes it to a different, attacker-controlled redirect target.".into(),
                    offset: m.start(),
                    property: "redirect_uri validation must canonicalize with full decoding and compare exact normalized URIs against an allowlist.".into(),
                }],
            });
        }

        // 12. prompt=none silent authorization abuse
        if lower.contains("prompt=none") {
            let pos = lower.find("prompt=none").unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "oauth_prompt_none_bypass".into(),
                confidence: 0.81,
                detail: "OAuth request uses prompt=none (silent authentication flow)".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: "prompt=none".into(),
                    interpretation: "prompt=none instructs the Authorization Server to authenticate without showing any UI. If the user is already authenticated, this silently grants tokens without user confirmation. Attackers embed this in OAuth requests to silently obtain tokens from authenticated users in iframe or redirect contexts (CSRF-like attack).".into(),
                    offset: pos,
                    property: "Applications must strictly validate origin, CSRF state, and consent requirements before accepting results from prompt=none authorization flows.".into(),
                }],
            });
        }

        dets.extend(self.detect_oauth_fixation(&lower));

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "oauth_redirect_uri_manipulation"
            | "oauth_missing_state"
            | "oauth_implicit_flow"
            | "oauth_scope_escalation"
            | "oauth_secret_exposure"
            | "oauth_pkce_plain"
            | "oauth_pkce_missing_s256"
            | "oauth_pkce_missing_verifier"
            | "oauth_token_leakage_referer"
            | "oauth_code_injection"
            | "oauth_request_uri_injection"
            | "oauth_nonce_missing_oidc"
            | "oauth_redirect_double_encoded"
            | "oauth_prompt_none_bypass" | "oauth_token_fixation_implicit" | "oauth_redirect_chain_abuse" | "oauth_code_fixation_probe" => Some(InvariantClass::OauthFlowAbuse),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_redirect_uri_manipulation() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=code&redirect_uri=https://evil.com/callback&client_id=abc");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_redirect_uri_manipulation"));
    }

    #[test]
    fn detects_missing_state() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=code&client_id=abc&redirect_uri=https://app.com/cb");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_missing_state"));
    }

    #[test]
    fn detects_implicit_flow() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=token&client_id=abc&state=xyz");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_implicit_flow"));
    }

    #[test]
    fn detects_secret_exposure() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("client_id=abc&client_secret=supersecret&grant_type=authorization_code");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_secret_exposure"));
    }

    #[test]
    fn detects_pkce_plain_downgrade() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=code&code_challenge=abc123&code_challenge_method=plain");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_pkce_plain"));
    }

    #[test]
    fn detects_pkce_plain_downgrade_case_insensitive() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=code&code_challenge=abc123&code_challenge_method=PLAIN");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_pkce_plain"));
    }

    #[test]
    fn detects_pkce_missing_s256() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=code&code_challenge=abc123xyz&client_id=abc");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_pkce_missing_s256"));
    }

    #[test]
    fn detects_pkce_missing_verifier() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("grant_type=authorization_code&code=abcd1234xyz0&code_challenge=xyz123");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_pkce_missing_verifier"));
    }

    #[test]
    fn detects_referer_token_leakage() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nReferer: https://app.example/cb#access_token=abcDEF123\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_token_leakage_referer"));
    }

    #[test]
    fn detects_authorization_code_injection_duplicate_code() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("GET /oauth/start?code=abc123def456&state=x&code=zzz999yyy888 HTTP/1.1");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_code_injection"));
    }

    #[test]
    fn detects_request_uri_injection() {
        let eval = OAuthEvaluator;
        let dets = eval.detect(
            "response_type=code&client_id=abc&request_uri=https://attacker.example/malicious.jwt",
        );
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "oauth_request_uri_injection"));
    }

    #[test]
    fn detects_nonce_missing_for_oidc_id_token_flow() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=id_token token&scope=openid profile email&client_id=abc");
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "oauth_nonce_missing_oidc"));
    }

    #[test]
    fn detects_double_encoded_redirect_uri() {
        let eval = OAuthEvaluator;
        let dets = eval.detect(
            "response_type=code&client_id=abc&redirect_uri=https://app.example/cb%252fadmin",
        );
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "oauth_redirect_double_encoded"));
    }

    #[test]
    fn detects_prompt_none_bypass() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=code&client_id=abc&scope=openid&prompt=none&state=s1");
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "oauth_prompt_none_bypass"));
    }

    #[test]
    fn no_detection_for_proper_oauth() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=code&client_id=abc&redirect_uri=https://app.com/cb&state=random123&scope=openid");
        // With proper state and non-suspicious redirect_uri, nothing malicious
        assert!(dets.is_empty());
    }

    #[test]
    fn detects_oauth_token_fixation_implicit() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("response_type=token&client_id=123");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_token_fixation_implicit"));
    }

    #[test]
    fn detects_oauth_redirect_chain_abuse() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("redirect_uri=https://example.com/oauth/authorize?response_type=code");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_redirect_chain_abuse"));
    }

    #[test]
    fn detects_oauth_code_fixation_probe() {
        let eval = OAuthEvaluator;
        let dets = eval.detect("?code=12345");
        assert!(dets.iter().any(|d| d.detection_type == "oauth_code_fixation_probe"));
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = OAuthEvaluator;
        assert_eq!(
            eval.map_class("oauth_redirect_uri_manipulation"),
            Some(InvariantClass::OauthFlowAbuse)
        );
    }
}
