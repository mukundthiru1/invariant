//! CRLF Injection Evaluator — HTTP Response Splitting Detection

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

pub struct CrlfEvaluator;

// Precompile once: regex compilation in `detect()` is expensive in WASM hot paths.
static CRLF_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\r\n|\n)([A-Za-z][\w-]*)\s*:\s*").unwrap());
static LOG_TIMESTAMP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)(?:\r\n|\n)\s*(?:\d{4}[-/]\d{2}[-/]\d{2}[Tt ]\d{2}:\d{2}:\d{2}|\w+\s+\d{1,2},\s*\d{4}\s+\d{2}:\d{2}:\d{2})\s*\[(?:INFO|ERROR|WARN|DEBUG|TRACE|FATAL)\]").unwrap()
});
static LOG_LEVEL_ONLY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)(?:\r\n|\n)\s*\[(?:INFO|ERROR|WARN|DEBUG|TRACE|FATAL)\]").unwrap());
static ENCODED_PERCENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)%0d%0a").unwrap());
static DOUBLE_ENCODED_PERCENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)%250d%250a").unwrap());
static ENCODED_UNICODE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\\u000d\\u000a").unwrap());
static ENCODED_UNICODE_LINE_SEP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:\\u2028|\\u2029|%e2%80%a8|%e2%80%a9)").unwrap());
static SET_COOKIE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)(?:\r\n|\n)\s*Set-Cookie\s*:").unwrap());
static XFH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)(?:\r\n|\n)\s*X-Forwarded-Host\s*:").unwrap());
static HEADER_CONTINUATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:\r\n|\n)[ \t]+[^\r\n]+").unwrap());
static RESPONSE_SPLIT_HEADERS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)(?:\r\n|\n)\s*(?:Set-Cookie|Location|Content-Length|Transfer-Encoding|Content-Type|Refresh)\s*:").unwrap()
});
static NULL_BYTE_CRLF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)(?:\x00(?:\r\n|\n)|(?:\r\n|\n)\x00|%00%0d%0a|%0d%0a%00|\\x00\\r\\n)").unwrap()
});
static HTML_BODY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<(?:script|html|body|iframe|img)").unwrap());

impl L2Evaluator for CrlfEvaluator {
    fn id(&self) -> &'static str { "crlf" }
    fn prefix(&self) -> &'static str { "L2 CRLF" }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded_data = crate::encoding::multi_layer_decode(input);
        let decoded = decoded_data.fully_decoded;
        let all_forms = decoded_data.all_forms;

        // CRLF followed by HTTP header injection
        if let Some(m) = CRLF_HEADER_RE.find(&decoded) {
            let header_name = CRLF_HEADER_RE.captures(&decoded)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str())
                .unwrap_or("unknown");

            let mut confidence = 0.82;
            let dangerous_headers = ["Set-Cookie", "Location", "Content-Type",
                "X-Forwarded-For", "Host", "Transfer-Encoding"];
            if dangerous_headers.iter().any(|h| h.eq_ignore_ascii_case(header_name)) {
                confidence = 0.92;
            }

            dets.push(L2Detection {
                detection_type: "header_injection".into(),
                confidence,
                detail: format!("CRLF followed by HTTP header: {}", header_name),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Line break injects new HTTP header into response".into(),
                    offset: m.start(),
                    property: "User input must not contain CRLF sequences that inject HTTP headers".into(),
                }],
            });
        }

        // Log injection/forgery: fake log timestamps and levels after CRLF.
        if let Some(m) = LOG_TIMESTAMP_RE.find(&decoded).or_else(|| LOG_LEVEL_ONLY_RE.find(&decoded)) {
            dets.push(L2Detection {
                detection_type: "log_forgery".into(),
                confidence: 0.88,
                detail: format!("Log forgery pattern after CRLF: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Line break injects fake timestamp/level log entry format".into(),
                    offset: m.start(),
                    property: "User input should not inject synthetic log lines".into(),
                }],
            });
        }

        // Encoded CRLF forms (\u000d\u000a, %0d%0a, etc.) and literal CRLF variants.
        if let Some(form) = all_forms.iter().find(|f| ENCODED_PERCENT_RE.is_match(f) || ENCODED_UNICODE_RE.is_match(f) || f.contains("\r\n")) {
            let matched = if ENCODED_PERCENT_RE.is_match(form) {
                "percent-encoded CRLF (%0d%0a)".to_owned()
            } else if ENCODED_UNICODE_RE.is_match(form) {
                "\\u000d\\u000a unicode escape".to_owned()
            } else {
                "literal CRLF".to_owned()
            };
            dets.push(L2Detection {
                detection_type: "encoded_crlf".into(),
                confidence: 0.86,
                detail: format!("Encoded CRLF variant detected: {}", matched),
                position: decoded.find("\r\n").unwrap_or(0),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: form[..form.len().min(80)].to_owned(),
                    interpretation: "Decoder output still contains CRLF-style control encoding".into(),
                    offset: decoded.find("\r\n").unwrap_or(0),
                    property: "User input must not encode CRLF control sequences".into(),
                }],
            });
        }

        // Double-encoded CRLF often bypasses single-pass decoders (%250d%250a -> %0d%0a -> CRLF).
        if let Some(form) = all_forms.iter().find(|f| DOUBLE_ENCODED_PERCENT_RE.is_match(f)) {
            let offset = decoded.find("%0d%0a").unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "double_encoded_crlf".into(),
                confidence: 0.90,
                detail: "Double-encoded CRLF detected (%250d%250a)".into(),
                position: offset,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: form[..form.len().min(80)].to_owned(),
                    interpretation: "Nested percent-encoding can reveal CRLF after multi-pass decode".into(),
                    offset,
                    property: "Input normalization must block multi-layer encoded CRLF controls".into(),
                }],
            });
        }

        // Unicode line separators can act as alternate line breaks (U+2028/U+2029).
        if let Some(m) = ENCODED_UNICODE_LINE_SEP_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "unicode_line_separator".into(),
                confidence: 0.84,
                detail: "Unicode line separator used as CRLF evasion (U+2028/U+2029)".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: decoded[m.start()..decoded.len().min(m.end() + 8)].to_owned(),
                    interpretation: "Unicode separator may bypass CRLF-only sanitizers and split headers/logs".into(),
                    offset: m.start(),
                    property: "Input validation must normalize and reject alternate newline codepoints".into(),
                }],
            });
        } else if let Some(i) = decoded.find(['\u{2028}', '\u{2029}']) {
            let end = decoded[i..].chars().next().map(|c| i + c.len_utf8()).unwrap_or(i);
            dets.push(L2Detection {
                detection_type: "unicode_line_separator".into(),
                confidence: 0.84,
                detail: "Unicode line separator used as CRLF evasion (U+2028/U+2029)".into(),
                position: i,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: decoded[i..decoded.len().min(end + 8)].to_owned(),
                    interpretation: "Unicode separator may bypass CRLF-only sanitizers and split headers/logs".into(),
                    offset: i,
                    property: "Input validation must normalize and reject alternate newline codepoints".into(),
                }],
            });
        }

        // Obsolete HTTP header folding / continuation lines can hide injected header values.
        if let Some(m) = HEADER_CONTINUATION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "header_continuation_injection".into(),
                confidence: 0.89,
                detail: "Leading whitespace continuation line after CRLF".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Injected folded header line can extend or smuggle header content".into(),
                    offset: m.start(),
                    property: "HTTP header values must not include CRLF followed by SP/HT continuation".into(),
                }],
            });
        }

        // Response splitting chain: CRLF directly followed by high-impact headers.
        if let Some(m) = RESPONSE_SPLIT_HEADERS_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "response_split_header_chain".into(),
                confidence: 0.93,
                detail: format!("Response splitting header chain: {}", m.as_str().trim()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Injected line break starts a new server-controlled HTTP header".into(),
                    offset: m.start(),
                    property: "Header names like Set-Cookie/Location must never be user-injectable".into(),
                }],
            });
        }

        // Null-byte + CRLF combinations can bypass parsers and trigger split behavior.
        if let Some(form) = all_forms.iter().find(|f| NULL_BYTE_CRLF_RE.is_match(f)) {
            let offset = decoded.find('\0').or_else(|| decoded.find("%00")).unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "null_byte_crlf".into(),
                confidence: 0.91,
                detail: "Null-byte + CRLF evasive sequence detected".into(),
                position: offset,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: form[..form.len().min(90)].to_owned(),
                    interpretation: "NUL with CRLF can desync validation and downstream parser behavior".into(),
                    offset,
                    property: "Control bytes (NUL/CR/LF) must be rejected across all decoded forms".into(),
                }],
            });
        }

        // Set-Cookie chaining via CRLF allows session fixation and cookie injection.
        if let Some(m) = SET_COOKIE_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "set_cookie_injection".into(),
                confidence: 0.93,
                detail: "Set-Cookie injected after CRLF".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Line break injects a response Set-Cookie header".into(),
                    offset: m.start(),
                    property: "Response headers must stay immutable and strictly server-controlled".into(),
                }],
            });
        }

        // CRLF + X-Forwarded-Host injection can poison cache keys.
        if let Some(m) = XFH_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cache_key_poisoning".into(),
                confidence: 0.90,
                detail: "X-Forwarded-Host injected after CRLF".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Line break injects cache-influencing proxy header".into(),
                    offset: m.start(),
                    property: "Proxy-derived cache keys must not be controllable by user input".into(),
                }],
            });
        }

        // Double CRLF = body injection (HTTP response splitting)
        if decoded.contains("\r\n\r\n") || decoded.contains("\n\n") {
            let has_html = HTML_BODY_RE.is_match(&decoded);
            dets.push(L2Detection {
                detection_type: "response_splitting".into(),
                confidence: if has_html { 0.92 } else { 0.80 },
                detail: format!("HTTP response splitting via double CRLF{}",
                    if has_html { " with HTML body injection" } else { "" }),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: decoded[..decoded.len().min(60)].to_owned(),
                    interpretation: "Double line break injects response body".into(),
                    offset: 0,
                    property: "User input must not contain double CRLF sequences".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "header_injection" => Some(InvariantClass::CrlfHeaderInjection),
            "set_cookie_injection" => Some(InvariantClass::CrlfHeaderInjection),
            "cache_key_poisoning" => Some(InvariantClass::CrlfHeaderInjection),
            "response_splitting" => Some(InvariantClass::CrlfLogInjection),
            "log_forgery" => Some(InvariantClass::CrlfLogInjection),
            "encoded_crlf" => Some(InvariantClass::CrlfLogInjection),
            "double_encoded_crlf" => Some(InvariantClass::CrlfHeaderInjection),
            "unicode_line_separator" => Some(InvariantClass::CrlfLogInjection),
            "header_continuation_injection" => Some(InvariantClass::CrlfHeaderInjection),
            "response_split_header_chain" => Some(InvariantClass::CrlfHeaderInjection),
            "null_byte_crlf" => Some(InvariantClass::CrlfHeaderInjection),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_log_forgery_pattern() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("abc\r\n2026-03-07 00:00:00 [ERROR] service down");
        assert!(dets.iter().any(|d| d.detection_type == "log_forgery"));
    }

    #[test]
    fn detects_encoded_crlf_variants() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("%0D%0ASet-Cookie:test=1");
        assert!(dets.iter().any(|d| d.detection_type == "encoded_crlf"));
        let dets = eval.detect("\\u000d\\u000aSet-Cookie:test=2");
        assert!(dets.iter().any(|d| d.detection_type == "encoded_crlf"));
    }

    #[test]
    fn detects_set_cookie_header_injection_chain() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("id=1\r\nSet-Cookie: session=attacker");
        assert!(dets.iter().any(|d| d.detection_type == "set_cookie_injection"));
    }

    #[test]
    fn detects_x_forwarded_host_cache_poisoning() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("id=1\r\nX-Forwarded-Host: evil.example");
        assert!(dets.iter().any(|d| d.detection_type == "cache_key_poisoning"));
    }

    #[test]
    fn detects_percent_encoded_crlf_uppercase_sequence() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("foo%0D%0ALocation:%20https://evil.example");
        assert!(dets.iter().any(|d| d.detection_type == "encoded_crlf"));
    }

    #[test]
    fn detects_double_encoded_crlf_sequence() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("foo%250d%250aSet-Cookie:%20x=1");
        assert!(dets.iter().any(|d| d.detection_type == "double_encoded_crlf"));
    }

    #[test]
    fn detects_unicode_line_separator_literal() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("username\u{2028}Set-Cookie: session=evil");
        assert!(dets.iter().any(|d| d.detection_type == "unicode_line_separator"));
    }

    #[test]
    fn detects_unicode_line_separator_escape_form() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("username\\u2029Location: https://evil.example");
        assert!(dets.iter().any(|d| d.detection_type == "unicode_line_separator"));
    }

    #[test]
    fn detects_header_continuation_injection() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("X-Test: ok\r\n\tSet-Cookie: injected=true");
        assert!(dets.iter().any(|d| d.detection_type == "header_continuation_injection"));
    }

    #[test]
    fn detects_response_split_header_chain_location() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("name=abc\r\nLocation: https://evil.example");
        assert!(dets.iter().any(|d| d.detection_type == "response_split_header_chain"));
    }

    #[test]
    fn detects_response_split_header_chain_transfer_encoding() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("x\r\nTransfer-Encoding: chunked");
        assert!(dets.iter().any(|d| d.detection_type == "response_split_header_chain"));
    }

    #[test]
    fn detects_null_byte_crlf_raw_combo() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("abc\0\r\nSet-Cookie: pwn=1");
        assert!(dets.iter().any(|d| d.detection_type == "null_byte_crlf"));
    }

    #[test]
    fn detects_null_byte_crlf_encoded_combo() {
        let eval = CrlfEvaluator;
        let dets = eval.detect("abc%00%0d%0aSet-Cookie:%20pwn=1");
        assert!(dets.iter().any(|d| d.detection_type == "null_byte_crlf"));
    }
}
