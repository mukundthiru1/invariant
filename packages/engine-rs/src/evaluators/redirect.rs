//! Open Redirect Evaluator — L2 Detection

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct RedirectEvaluator;

impl L2Evaluator for RedirectEvaluator {
    fn id(&self) -> &'static str {
        "redirect"
    }
    fn prefix(&self) -> &'static str {
        "L2 Redirect"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded_data = crate::encoding::multi_layer_decode(input);
        let decoded = decoded_data.fully_decoded;
        let all_forms = decoded_data.all_forms;

        static REDIRECT_CONTEXT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:redirect|return|next|url|goto|target|dest|continue|rurl|redir|callback|redirect_uri|redirect_url|return_to)").unwrap()
        });
        static PROTOCOL_RELATIVE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"^/{2,}[^/]").unwrap());
        static ABS_HTTP_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)^https?://").unwrap());
        static ABS_URL_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)^(?:https?|ftp)://[^"]+"#).unwrap());
        let has_redirect_context = REDIRECT_CONTEXT_RE.is_match(&decoded);

        // Protocol-relative redirect: //evil.com
        if PROTOCOL_RELATIVE_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "open_redirect".into(),
                confidence: 0.85,
                detail: format!(
                    "Protocol-relative URL redirect: {}",
                    &decoded[..decoded.len().min(60)]
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: decoded[..decoded.len().min(40)].to_owned(),
                    interpretation: "Protocol-relative URL redirects to external domain".into(),
                    offset: 0,
                    property: "Redirect targets must be validated against an allowlist".into(),
                }],
            });
        }

        // Absolute URL to external domain
        if ABS_HTTP_RE.is_match(&decoded) {
            if has_redirect_context {
                dets.push(L2Detection {
                    detection_type: "open_redirect".into(),
                    confidence: 0.80,
                    detail: format!(
                        "Absolute URL in redirect context: {}",
                        &decoded[..decoded.len().min(60)]
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[..decoded.len().min(40)].to_owned(),
                        interpretation: "Absolute URL used as redirect target".into(),
                        offset: 0,
                        property: "Redirect targets must be validated against an allowlist".into(),
                    }],
                });
            }
        }

        // Open redirect with data URI payload: data:text/html,<script>alert(1)</script>
        static data_uri: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[?&](?:redirect|return|next|url|goto|target|dest|continue|rurl|redir|callback|redirect_uri|redirect_url|return_to)=)data:text/html,").unwrap()
        });
        if data_uri.is_match(&decoded) || decoded.starts_with("data:text/html,") {
            dets.push(L2Detection {
                detection_type: "data_uri_redirect".into(),
                confidence: 0.96,
                detail: format!(
                    "Data URI redirect payload: {}",
                    &decoded[..decoded.len().min(60)]
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(60)].to_owned(),
                    interpretation: "Data URI can execute HTML/JS in redirect target".into(),
                    offset: 0,
                    property: "Redirect targets must only allow safe, same-origin schemes".into(),
                }],
            });
        }

        // Open redirect with javascript: scheme
        static js_uri: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[?&](?:redirect|return|next|url|goto|target|dest|continue|rurl|redir|callback|redirect_uri|redirect_url|return_to)=)javascript:").unwrap()
        });
        if js_uri.is_match(&decoded) || decoded.starts_with("javascript:") {
            dets.push(L2Detection {
                detection_type: "javascript_uri_redirect".into(),
                confidence: 0.97,
                detail: format!(
                    "javascript URI redirect payload: {}",
                    &decoded[..decoded.len().min(60)]
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(60)].to_owned(),
                    interpretation: "javascript: URL executes script at redirect target".into(),
                    offset: 0,
                    property: "Redirect targets must not allow executable URI schemes".into(),
                }],
            });
        }

        // User-info bypass: https://allowed.com@evil.com
        static userinfo_bypass: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)^(?:https?|ftp)://[^/@\s?#]+@[^\s/?#]+(?:/.*)?$").unwrap()
        });
        if userinfo_bypass.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "userinfo_bypass_redirect".into(),
                confidence: 0.92,
                detail: "Redirect URL contains user-info before authority".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(70)].to_owned(),
                    interpretation:
                        "User-info component can confuse host handling in redirect parsers".into(),
                    offset: 0,
                    property:
                        "Redirect host validation must reject user-info based authority confusion"
                            .into(),
                }],
            });
        }

        // OAuth redirect URI externalization
        static oauth_param: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r"(?i)(?:^|[?&])(?:redirect_uri|redirect_url|callback|return_to)\s*=\s*([^&]+)",
            )
            .unwrap()
        });
        if let Some(caps) = oauth_param.captures(&decoded) {
            let target = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if ABS_URL_RE.is_match(target) {
                dets.push(L2Detection {
                    detection_type: "oauth_redirect_bypass".into(),
                    confidence: 0.91,
                    detail: format!("OAuth redirect_uri target: {}", target),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: target.to_owned(),
                        interpretation: "Untrusted redirect callback target in OAuth parameter"
                            .into(),
                        offset: 0,
                        property: "OAuth redirect parameters should be validated against allowlist"
                            .into(),
                    }],
                });
            }
        }

        // URL fragment abuse: #@evil.com
        static fragment_abuse: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)^(?:https?|ftp)://[^#\s]+#@[^#\s]+").unwrap()
        });
        static fragment_param: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)[?&](?:redirect|return|next|url|goto|target|dest|continue|rurl|redir|callback|redirect_uri|redirect_url|return_to)=[^&]*#@[^&]*").unwrap()
        });
        if fragment_abuse.is_match(&decoded) || fragment_param.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "fragment_authority_redirect".into(),
                confidence: 0.84,
                detail: "Redirect URL uses fragment authority confusion".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: decoded[..decoded.len().min(70)].to_owned(),
                    interpretation: "Fragments with '@' can alter effective URL authority parsing"
                        .into(),
                    offset: 0,
                    property:
                        "Redirect URL parser should normalize fragment handling before routing"
                            .into(),
                }],
            });
        }

        // Double-encoded redirect payload: %252f%252f
        static double_encoded_redirect: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)%25(?:2[fF])%25(?:2[fF])").unwrap());
        if all_forms
            .iter()
            .any(|f| double_encoded_redirect.is_match(f))
        {
            let matched_input = all_forms
                .iter()
                .find(|f| double_encoded_redirect.is_match(f))
                .map(|f| f.as_str().to_owned())
                .unwrap_or_else(|| decoded.clone());
            dets.push(L2Detection {
                detection_type: "double_encoded_redirect".into(),
                confidence: 0.89,
                detail: format!(
                    "Double-encoded redirect syntax: {}",
                    &decoded[..decoded.len().min(50)]
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input,
                    interpretation: "Double-encoded slash bypasses simplistic scheme checks".into(),
                    offset: 0,
                    property: "Decode URL inputs before validation and allowlisting".into(),
                }],
            });
        }

        // Backslash trick: /\evil.com (browsers interpret as //evil.com)
        if decoded.starts_with("/\\") || decoded.starts_with("\\\\") {
            dets.push(L2Detection {
                detection_type: "open_redirect".into(),
                confidence: 0.88,
                detail: "Backslash-based redirect bypass".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: decoded[..decoded.len().min(30)].to_owned(),
                    interpretation:
                        "Backslash trick causes browser to interpret as protocol-relative URL"
                            .into(),
                    offset: 0,
                    property: "Redirect targets must be validated against an allowlist".into(),
                }],
            });
        }

        // Protocol-relative redirect in redirect parameters (including encoded value).
        static PROTO_REL_PARAM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[?&])(?:redirect|return|next|url|goto|target|dest|continue|rurl|redir|callback|redirect_uri|redirect_url|return_to)\s*=\s*(?:/{2,}|%2f%2f|%252f%252f)").unwrap()
        });
        if let Some(m) = PROTO_REL_PARAM_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "protocol_relative_param_redirect".into(),
                confidence: 0.91,
                detail: format!(
                    "Protocol-relative redirect target in parameter: {}",
                    m.as_str()
                ),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Redirect parameter value resolves to protocol-relative external authority"
                            .into(),
                    offset: m.start(),
                    property:
                        "Redirect parameters must reject protocol-relative forms before decoding"
                            .into(),
                }],
            });
        }

        // Backslash confusion via encoded or mixed slash/backslash path.
        static BACKSLASH_CONFUSION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r"(?i)(?:^|[?&](?:redirect|return|next|url|goto|target|dest|continue|rurl|redir|callback|redirect_uri|redirect_url|return_to)=)(?:\\\\|/\\|%5c%5c|/%5c|%2f%5c)").unwrap()
            },
        );
        if let Some(m) = BACKSLASH_CONFUSION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "backslash_confusion_redirect".into(),
                confidence: 0.90,
                detail: format!("Backslash confusion redirect target: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Mixed slash/backslash patterns can be normalized into external redirects by clients".into(),
                    offset: m.start(),
                    property: "Redirect parser must normalize separators and reject authority-like backslash forms".into(),
                }],
            });
        }

        // URL parser differential (userinfo confusion): http://expected@evil.com and encoded @.
        static PARSER_DIFF_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:https?|ftp)://[^/\s?#@]+(?:@|%40)[^/\s?#]+").unwrap()
        });
        if let Some(m) = PARSER_DIFF_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "url_parser_differential_redirect".into(),
                confidence: 0.93,
                detail: format!("Authority differential via userinfo syntax: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Host allowlist checks may validate pre-@ token while browser navigates to post-@ host".into(),
                    offset: m.start(),
                    property: "Redirect host validation must parse authority components exactly as client runtime does".into(),
                }],
            });
        }

        // Encoded scheme payload in redirect parameters: data:/javascript:
        static ENCODED_SCHEME_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[?&](?:redirect|return|next|url|goto|target|dest|continue|rurl|redir|callback|redirect_uri|redirect_url|return_to)=)(?:(?:data|javascript)%3a|(?:data|javascript):|(?:data|javascript)%253a)").unwrap()
        });
        if let Some(m) = ENCODED_SCHEME_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "dangerous_scheme_param_redirect".into(),
                confidence: 0.97,
                detail: format!("Dangerous URI scheme in redirect parameter: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Encoded/decoded executable scheme survives redirect parameter handling"
                            .into(),
                    offset: m.start(),
                    property:
                        "Redirect parameter schemes must be constrained to safe same-origin targets"
                            .into(),
                }],
            });
        }

        // CRLF injection in redirect target, often used to smuggle new Location/header values.
        static CRLF_REDIRECT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r"(?is)(?:^|[?&](?:redirect|return|next|url|goto|target|dest|continue|rurl|redir|callback|redirect_uri|redirect_url|return_to)=)[^&]*(?:%0d%0a|\r\n|%250d%250a)(?:location:|set-cookie:|x-)",
            )
            .unwrap()
        });
        if let Some(m) = CRLF_REDIRECT_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "crlf_redirect_injection".into(),
                confidence: 0.96,
                detail: "CRLF sequence in redirect target may inject response headers".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "CRLF lets attacker split headers and craft secondary redirect/location behavior".into(),
                    offset: m.start(),
                    property: "Redirect values must reject control characters and encoded CRLF sequences".into(),
                }],
            });
        }

        // Unicode normalization/homoglyph domain bypass in absolute/protocol-relative redirect values.
        static UNICODE_HOST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:https?:)?//[^\s/?#]*[^\x00-\x7F][^\s/?#]*").unwrap()
        });
        static PUNYCODE_HOST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:https?:)?//(?:[^/\s?#]+\.)?xn--[a-z0-9-]+(?:\.[^/\s?#]+)*").unwrap()
        });
        if let Some(m) = UNICODE_HOST_RE
            .find(&decoded)
            .or_else(|| PUNYCODE_HOST_RE.find(&decoded))
        {
            dets.push(L2Detection {
                detection_type: "unicode_normalization_redirect".into(),
                confidence: 0.90,
                detail: format!("Unicode/punycode host in redirect target may bypass visual/domain checks: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Unicode normalization and IDN rendering can hide true redirect destination".into(),
                    offset: m.start(),
                    property: "Redirect host allowlisting must validate canonical punycode form and script policy".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "open_redirect"
            | "data_uri_redirect"
            | "javascript_uri_redirect"
            | "userinfo_bypass_redirect"
            | "oauth_redirect_bypass"
            | "fragment_authority_redirect"
            | "double_encoded_redirect"
            | "protocol_relative_param_redirect"
            | "backslash_confusion_redirect"
            | "url_parser_differential_redirect"
            | "dangerous_scheme_param_redirect"
            | "crlf_redirect_injection"
            | "unicode_normalization_redirect" => Some(InvariantClass::OpenRedirectBypass),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_data_uri_redirect() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("data:text/html,<script>alert(1)</script>");
        assert!(dets.iter().any(|d| d.detection_type == "data_uri_redirect"));
    }

    #[test]
    fn detects_javascript_uri_redirect() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("javascript:alert(1)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "javascript_uri_redirect")
        );
    }

    #[test]
    fn detects_userinfo_host_confusion() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("https://allowed.com@evil.com");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "userinfo_bypass_redirect")
        );
    }

    #[test]
    fn detects_oauth_redirect_bypass() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("https://app.example.com/oauth?redirect_uri=https://evil.com/login");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "oauth_redirect_bypass")
        );
    }

    #[test]
    fn detects_fragment_authority_confusion() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("https://allowed.com#@evil.com/profile");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "fragment_authority_redirect")
        );
    }

    #[test]
    fn detects_double_encoded_redirect() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("%252f%252Fevil.com/path");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "double_encoded_redirect")
        );
    }

    #[test]
    fn detects_protocol_relative_redirect_parameter() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/login?next=//evil.com");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "protocol_relative_param_redirect")
        );
    }

    #[test]
    fn detects_encoded_protocol_relative_redirect_parameter() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/login?redirect=%2F%2Fevil.com");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "protocol_relative_param_redirect")
        );
    }

    #[test]
    fn detects_backslash_confusion_redirect_parameter() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/login?target=/\\evil.com");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "backslash_confusion_redirect")
        );
    }

    #[test]
    fn detects_url_parser_differential_with_encoded_at() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/oauth?redirect_uri=http://trusted.example%40evil.com/cb");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "url_parser_differential_redirect")
        );
    }

    #[test]
    fn detects_dangerous_data_scheme_in_param() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/redir?return=data%3Atext%2Fhtml%2C<script>alert(1)</script>");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dangerous_scheme_param_redirect")
        );
    }

    #[test]
    fn detects_dangerous_javascript_scheme_in_param() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/redir?url=javascript:alert(1)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dangerous_scheme_param_redirect")
        );
    }

    #[test]
    fn detects_crlf_injected_redirect_target() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/redirect?next=%0d%0aLocation:%20https://evil.com");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "crlf_redirect_injection")
        );
    }

    #[test]
    fn detects_unicode_homoglyph_domain_redirect() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/redir?target=https://аррӏе.com/login");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "unicode_normalization_redirect")
        );
    }

    #[test]
    fn detects_punycode_redirect_host() {
        let eval = RedirectEvaluator;
        let dets = eval.detect("/redir?target=https://xn--pple-43d.com/login");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "unicode_normalization_redirect")
        );
    }
}
