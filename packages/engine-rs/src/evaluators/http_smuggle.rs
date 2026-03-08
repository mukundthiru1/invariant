//! HTTP Request Smuggling Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

pub struct HttpSmuggleEvaluator;

// Compile once for request-path throughput; avoid per-call regex construction in WASM.
static HAS_CL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Content-Length\s*:").unwrap());
static HAS_TE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Transfer-Encoding\s*:").unwrap());
static CL_VALUES_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Content-Length\s*:\s*\d+\s*$").unwrap());
static H2_PSEUDO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^:method[^\r\n]*\r?\n:path[^\r\n]*\r?\n").unwrap());
static TE_OBFUSCATED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)Transfer-Encoding\s*:\s*(?:chunked\s*,\s*identity|identity\s*,\s*chunked|chunked\s*[\r\n]+\s*Transfer-Encoding)").unwrap()
});
static CHUNKED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Transfer-Encoding\s*:\s*chunked\b").unwrap());
static CHUNK_EXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^[0-9A-Fa-f]+\s*;[^\r\n]+\r?\n").unwrap());
static CL_ZERO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Content-Length\s*:\s*0").unwrap());
static EMBEDDED_REQ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/[^\s]*\s+HTTP/").unwrap()
});
static CL_VALUE_CAPTURE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Content-Length\s*:\s*(\d+)\s*$").unwrap());
static TE_XCHUNKED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Transfer-Encoding\s*:\s*xchunked\b").unwrap());
static TE_SPACE_COLON_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Transfer-Encoding\s+:\s*chunked\b").unwrap());
static TE_TRAILING_WS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Transfer-Encoding\s*:\s*chunked[ \t]+\r?$").unwrap());
static XFF_TE_CHAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^X-Forwarded-For\s*:[^\r\n]*\r?\n\s*Transfer-Encoding\s*:\s*chunked\b")
        .unwrap()
});
static H2C_UPGRADE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Upgrade\s*:\s*h2c\b").unwrap());
static HTTP2_SETTINGS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^HTTP2-Settings\s*:").unwrap());
static CONNECTION_UPGRADE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^Connection\s*:\s*[^\r\n]*(?:upgrade|http2-settings)[^\r\n]*").unwrap()
});
static H2_PSEUDO_INJECT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^(?::method|:path|:authority|:scheme)\s*:").unwrap());
static METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b").unwrap()
});
static REQUEST_LINE_ENCODED_INJECT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S*(?:%0d|%0a|\\r|\\n)\S*\s+HTTP/\d(?:\.\d)?\s*$",
    )
    .unwrap()
});
static CL_HEADER_VALUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Content-Length\s*:\s*([^\r\n]+)\s*$").unwrap());
static CL_INTERNAL_WS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Content-Length\s*:\s*\d+\s+\d+\s*$").unwrap());
static H2_PRIOR_KNOWLEDGE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^PRI\s+\*\s+HTTP/2\.0$").unwrap());
static H2_PSEUDO_CRLF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^:(?:method|path)\s*:\s*[^\r\n]*(?:%0d|%0a|\\r|\\n)[^\r\n]*$").unwrap()
});
static TE_LIST_OBFUSCATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^Transfer-Encoding\s*:\s*(?:chunked\s*,(?:\s*|[^\r\n]+)|[^\r\n,]+,\s*chunked(?:\s*,[^\r\n]+)?)\s*$").unwrap()
});
static NEGATIVE_CHUNK_SIZE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^-\s*[0-9A-Fa-f]+\s*(?:;[^\r\n]*)?\r?$").unwrap());
static WEBSOCKET_UPGRADE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Upgrade\s*:\s*websocket\b").unwrap());
static CONNECTION_WS_UPGRADE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^Connection\s*:\s*[^\r\n]*\bupgrade\b[^\r\n]*$").unwrap());
static REQUEST_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/(1\.[01]|2(?:\.0)?)\s*$").unwrap()
});

fn split_headers_body(input: &str) -> (&str, &str, usize) {
    if let Some(i) = input.find("\r\n\r\n") {
        return (&input[..i], &input[i + 4..], i + 4);
    }
    if let Some(i) = input.find("\n\n") {
        return (&input[..i], &input[i + 2..], i + 2);
    }
    (input, "", input.len())
}

fn looks_like_http2(decoded: &str) -> bool {
    H2_PRIOR_KNOWLEDGE_RE.is_match(decoded)
        || H2_PSEUDO_INJECT_RE.is_match(decoded)
        || H2C_UPGRADE_RE.is_match(decoded)
        || decoded.contains("HTTP/2")
}

fn detect_cl_cl_desync(decoded: &str) -> Option<L2Detection> {
    let mut values: Vec<(usize, u64, String)> = Vec::new();
    for caps in CL_VALUE_CAPTURE_RE.captures_iter(decoded) {
        let all = caps.get(0)?;
        let parsed = caps.get(1)?.as_str().parse::<u64>().ok()?;
        values.push((all.start(), parsed, all.as_str().to_owned()));
    }
    if values.len() < 2 {
        return None;
    }

    let first = values[0].1;
    if values.iter().any(|(_, v, _)| *v != first) {
        let joined = values
            .iter()
            .map(|(_, _, raw)| raw.as_str())
            .collect::<Vec<_>>()
            .join(" | ");
        return Some(L2Detection {
            detection_type: "cl_cl_desync".into(),
            confidence: 0.95,
            detail: "Duplicate Content-Length headers with mismatched values detected".into(),
            position: values[0].0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: joined,
                interpretation:
                    "Differing Content-Length values can desynchronize front-end and back-end parsers"
                        .into(),
                offset: values[0].0,
                property:
                    "Requests must not include multiple Content-Length values with differing lengths"
                        .into(),
            }],
        });
    }
    None
}

fn detect_te_cl_order_desync(decoded: &str) -> Vec<L2Detection> {
    let mut dets = Vec::new();
    let first_cl = HAS_CL_RE.find(decoded);
    let first_te = HAS_TE_RE.find(decoded);

    if let (Some(cl), Some(te)) = (first_cl, first_te) {
        if te.start() < cl.start() {
            dets.push(L2Detection {
                detection_type: "te_cl_desync".into(),
                confidence: 0.93,
                detail: "TE.CL desync pattern detected (Transfer-Encoding before Content-Length)".into(),
                position: te.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: format!("{} | {}", te.as_str(), cl.as_str()),
                    interpretation:
                        "Some intermediaries honor Transfer-Encoding while back-ends honor Content-Length"
                            .into(),
                    offset: te.start(),
                    property:
                        "Transfer-Encoding and Content-Length must not be combined in a single request"
                            .into(),
                }],
            });
        } else if cl.start() < te.start() {
            dets.push(L2Detection {
                detection_type: "cl_te_desync".into(),
                confidence: 0.93,
                detail: "CL.TE desync pattern detected (Content-Length before Transfer-Encoding)".into(),
                position: cl.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: format!("{} | {}", cl.as_str(), te.as_str()),
                    interpretation:
                        "Differing parser precedence for CL vs TE can produce request boundary confusion"
                            .into(),
                    offset: cl.start(),
                    property:
                        "Transfer-Encoding and Content-Length must not be combined in a single request"
                            .into(),
                }],
            });
        }
    }

    dets
}

fn detect_obfuscated_te_variants(decoded: &str) -> Option<L2Detection> {
    let patterns = [
        (
            &*TE_XCHUNKED_RE,
            "Transfer-Encoding value obfuscated as xchunked",
        ),
        (
            &*TE_SPACE_COLON_RE,
            "Transfer-Encoding header uses colon-spacing obfuscation",
        ),
        (
            &*TE_TRAILING_WS_RE,
            "Transfer-Encoding: chunked contains trailing whitespace",
        ),
        (
            &*XFF_TE_CHAIN_RE,
            "Header chain includes X-Forwarded-For followed by injected Transfer-Encoding",
        ),
    ];

    for (re, detail) in patterns {
        if let Some(m) = re.find(decoded) {
            return Some(L2Detection {
                detection_type: "te_obfuscation_advanced".into(),
                confidence: 0.91,
                detail: detail.into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Obfuscated Transfer-Encoding headers can trigger differential parsing decisions"
                            .into(),
                    offset: m.start(),
                    property:
                        "Transfer-Encoding must be canonical and unambiguous across all intermediaries"
                            .into(),
                }],
            });
        }
    }

    None
}

fn detect_http2_downgrade_smuggle(decoded: &str) -> Option<L2Detection> {
    if let Some(h2c) = H2C_UPGRADE_RE.find(decoded) {
        let has_settings = HTTP2_SETTINGS_RE.is_match(decoded);
        let has_connection = CONNECTION_UPGRADE_RE.is_match(decoded);
        if has_settings || has_connection {
            return Some(L2Detection {
                detection_type: "http2_downgrade_smuggle".into(),
                confidence: 0.90,
                detail: "HTTP/2 cleartext upgrade (h2c) downgrade-smuggling pattern detected".into(),
                position: h2c.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: h2c.as_str().to_owned(),
                    interpretation:
                        "h2c upgrade metadata can be abused when proxies downgrade traffic to HTTP/1".into(),
                    offset: h2c.start(),
                    property:
                        "Protocol upgrades must not allow ambiguous request framing across hops".into(),
                }],
            });
        }
    }

    if let Some(pseudo) = H2_PSEUDO_INJECT_RE.find(decoded) {
        return Some(L2Detection {
            detection_type: "http2_downgrade_smuggle".into(),
            confidence: 0.90,
            detail: "HTTP/2 pseudo-header injection observed in HTTP/1 message".into(),
            position: pseudo.start(),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: pseudo.as_str().to_owned(),
                interpretation:
                    "Pseudo-headers interpreted during downgrade can create parser state confusion"
                        .into(),
                offset: pseudo.start(),
                property: "HTTP/2 pseudo-headers must not appear as regular HTTP/1 headers".into(),
            }],
        });
    }

    None
}

fn detect_request_line_injection(decoded: &str) -> Option<L2Detection> {
    if let Some(encoded) = REQUEST_LINE_ENCODED_INJECT_RE.find(decoded) {
        return Some(L2Detection {
            detection_type: "request_line_injection".into(),
            confidence: 0.89,
            detail: "Encoded CRLF sequence in request target suggests request-line injection".into(),
            position: encoded.start(),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: encoded.as_str().to_owned(),
                interpretation:
                    "CRLF sequences in URI path can terminate the line early and inject a second request"
                        .into(),
                offset: encoded.start(),
                property:
                    "Request target must not carry CRLF characters or encoded CRLF control bytes".into(),
            }],
        });
    }

    let mut req_lines = decoded.split('\n');
    let line1 = req_lines.next().unwrap_or("").trim_end_matches('\r');
    let line2 = req_lines.next().unwrap_or("").trim_end_matches('\r');
    if METHOD_RE.is_match(line1)
        && !line1.contains("HTTP/")
        && METHOD_RE.is_match(line2)
        && line2.contains("HTTP/")
    {
        return Some(L2Detection {
            detection_type: "request_line_injection".into(),
            confidence: 0.89,
            detail: "Request start-line appears split, indicating CRLF request-line injection".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: format!("{}\\n{}", line1, line2),
                interpretation:
                    "Injected CRLF in path can terminate the first start-line and create a second request-line"
                        .into(),
                offset: 0,
                property:
                    "Request-line must be a single syntactically valid line ending with HTTP version".into(),
            }],
        });
    }

    let (_, body, body_start) = split_headers_body(decoded);
    let mut lines = body.split('\n');
    let first = lines.next().unwrap_or("").trim_end_matches('\r');
    let second = lines.next().unwrap_or("").trim_end_matches('\r');
    if METHOD_RE.is_match(first) && !first.contains("HTTP/") && METHOD_RE.is_match(second) {
        return Some(L2Detection {
            detection_type: "request_line_injection".into(),
            confidence: 0.89,
            detail: "Potential second request-line injected via CRLF in request path".into(),
            position: body_start,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: format!("{}\\n{}", first, second),
                interpretation:
                    "A split request-line can hide a second start-line that downstream parsers accept"
                        .into(),
                offset: body_start,
                property:
                    "Request-line parsing must reject CRLF-induced start-line splitting".into(),
            }],
        });
    }

    None
}

fn detect_chunk_size_overflow(decoded: &str) -> Option<L2Detection> {
    if !CHUNKED_RE.is_match(decoded) {
        return None;
    }
    let (_, body, body_start) = split_headers_body(decoded);
    let mut offset = body_start;

    for line_raw in body.split_inclusive('\n') {
        let line = line_raw.trim_end_matches('\n').trim_end_matches('\r');
        let size_raw = line.split(';').next().unwrap_or("").trim();
        if !size_raw.is_empty() && size_raw.chars().all(|c| c.is_ascii_hexdigit()) {
            let overflows = size_raw.len() > 8
                || u64::from_str_radix(size_raw, 16)
                    .map(|v| v > 0x7fffffff_u64)
                    .unwrap_or(true);
            if overflows {
                return Some(L2Detection {
                    detection_type: "chunk_size_overflow".into(),
                    confidence: 0.92,
                    detail: "Oversized chunk length may trigger integer overflow in downstream parser".into(),
                    position: offset,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: line.to_owned(),
                        interpretation:
                            "Extremely large chunk size can wrap parser counters and corrupt framing"
                                .into(),
                        offset,
                        property:
                            "Chunk size must fit parser integer bounds and be strictly validated".into(),
                    }],
                });
            }
        }
        offset += line_raw.len();
    }
    None
}

fn detect_chunk_extension_abuse(decoded: &str) -> Option<L2Detection> {
    if !CHUNKED_RE.is_match(decoded) {
        return None;
    }
    let (_, body, body_start) = split_headers_body(decoded);
    let mut offset = body_start;

    for line_raw in body.split_inclusive('\n') {
        let line = line_raw.trim_end_matches('\n').trim_end_matches('\r');
        let Some((size_part, ext)) = line.split_once(';') else {
            offset += line_raw.len();
            continue;
        };
        let size_clean = size_part.trim();
        if size_clean.is_empty() || !size_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            offset += line_raw.len();
            continue;
        }

        let ext_lc = ext.to_ascii_lowercase();
        let suspicious = ext.len() > 128
            || ext_lc.contains("%0d")
            || ext_lc.contains("%0a")
            || ext_lc.contains("../")
            || ext_lc.contains("__proto__")
            || ext_lc.contains("transfer-encoding");
        if suspicious {
            return Some(L2Detection {
                detection_type: "chunk_ext_abuse".into(),
                confidence: 0.90,
                detail: "Malicious or oversized chunk extension detected".into(),
                position: offset,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: line.to_owned(),
                    interpretation:
                        "Chunk extensions can carry parser-confusing metadata and smuggling controls".into(),
                    offset,
                    property:
                        "Chunk extensions from untrusted clients should be constrained or rejected".into(),
                }],
            });
        }
        offset += line_raw.len();
    }
    None
}

fn detect_h2_cl_smuggle(decoded: &str) -> Option<L2Detection> {
    if !looks_like_http2(decoded) || !HAS_CL_RE.is_match(decoded) {
        return None;
    }

    let (_, body, body_start) = split_headers_body(decoded);
    let body_has_non_ws = body.chars().any(|c| !c.is_whitespace());
    let mut raw_values = Vec::new();
    for caps in CL_HEADER_VALUE_RE.captures_iter(decoded) {
        raw_values.push(caps.get(1)?.as_str().trim().to_owned());
    }

    let has_multi_cl = raw_values.len() > 1;
    let has_non_numeric = raw_values
        .iter()
        .any(|v| !v.chars().all(|c| c.is_ascii_digit()));
    let has_mismatch = has_multi_cl && raw_values.iter().skip(1).any(|v| v != &raw_values[0]);
    let has_zero_with_body = raw_values.iter().any(|v| v == "0") && body_has_non_ws;
    let has_ws_abuse = CL_INTERNAL_WS_RE.is_match(decoded);

    if has_mismatch || has_non_numeric || has_zero_with_body || has_ws_abuse {
        return Some(L2Detection {
            detection_type: "h2_cl_smuggle".into(),
            confidence: 0.95,
            detail: "HTTP/2 Content-Length manipulation pattern detected".into(),
            position: decoded.find("Content-Length").unwrap_or(body_start),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: "HTTP/2 + Content-Length manipulation".into(),
                interpretation:
                    "Protocol conversion with ambiguous Content-Length can desynchronize downstream framing".into(),
                offset: decoded.find("Content-Length").unwrap_or(body_start),
                property:
                    "HTTP/2-to-HTTP/1 translation must enforce a single valid Content-Length with consistent framing".into(),
            }],
        });
    }

    None
}

fn detect_h2_te_smuggle(decoded: &str) -> Option<L2Detection> {
    if looks_like_http2(decoded) && HAS_TE_RE.is_match(decoded) {
        let te_pos = decoded.find("Transfer-Encoding").unwrap_or(0);
        return Some(L2Detection {
            detection_type: "h2_te_smuggle".into(),
            confidence: 0.95,
            detail: "HTTP/2 Transfer-Encoding injection pattern detected".into(),
            position: te_pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: "HTTP/2 + Transfer-Encoding".into(),
                interpretation:
                    "Transfer-Encoding is invalid in HTTP/2 and can cause parser differentials after downgrade".into(),
                offset: te_pos,
                property:
                    "HTTP/2 request translation must strip or reject Transfer-Encoding fields".into(),
            }],
        });
    }
    None
}

fn detect_cl_0_smuggle(decoded: &str) -> Option<L2Detection> {
    let cl0 = CL_ZERO_RE.find(decoded)?;
    let (_, body, body_start) = split_headers_body(decoded);
    if body.chars().any(|c| !c.is_whitespace()) {
        return Some(L2Detection {
            detection_type: "cl_0_smuggle".into(),
            confidence: 0.92,
            detail: "CL.0 smuggling pattern detected: Content-Length is 0 but body bytes follow".into(),
            position: cl0.start(),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: body.to_owned(),
                interpretation:
                    "Some intermediaries forward body bytes even when CL=0, enabling hidden request injection".into(),
                offset: body_start,
                property: "Requests with Content-Length: 0 must not carry body bytes".into(),
            }],
        });
    }
    None
}

fn detect_h2_pseudo_crlf_injection(decoded: &str) -> Option<L2Detection> {
    if !looks_like_http2(decoded) {
        return None;
    }
    let lines: Vec<&str> = decoded.lines().collect();
    for (idx, raw_line) in lines.iter().enumerate() {
        let line = raw_line.trim_end_matches('\r');
        let lower = line.to_ascii_lowercase();
        if lower.starts_with(":method:") || lower.starts_with(":path:") {
            let l = lower.as_str();
            if l.contains("%0d") || l.contains("%0a") || l.contains("\\r") || l.contains("\\n") {
                return Some(L2Detection {
                    detection_type: "h2_pseudo_crlf_injection".into(),
                    confidence: 0.93,
                    detail: "Encoded CRLF in HTTP/2 pseudo-header value detected".into(),
                    position: decoded.find(line).unwrap_or(0),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: line.to_owned(),
                        interpretation:
                            "CRLF in pseudo-header values can inject downstream headers during protocol translation".into(),
                        offset: decoded.find(line).unwrap_or(0),
                        property: "HTTP/2 pseudo-header values must reject CR/LF bytes and encodings".into(),
                    }],
                });
            }

            if let Some(next) = lines.get(idx + 1) {
                let next_trimmed = next.trim_end_matches('\r');
                if next_trimmed.contains(':')
                    && !next_trimmed.trim_start().starts_with(':')
                    && !next_trimmed.to_ascii_lowercase().starts_with("host:")
                {
                    return Some(L2Detection {
                        detection_type: "h2_pseudo_crlf_injection".into(),
                        confidence: 0.91,
                        detail: "Pseudo-header line split suggests CRLF header injection".into(),
                        position: decoded.find(line).unwrap_or(0),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::ContextEscape,
                            matched_input: format!("{}\\n{}", line, next_trimmed),
                            interpretation:
                                "A decoded CRLF in pseudo-header value can create an attacker-controlled header line".into(),
                            offset: decoded.find(line).unwrap_or(0),
                            property:
                                "Pseudo-header values must remain single-line and reject header-delimiter bytes".into(),
                        }],
                    });
                }
            }
        }
    }

    if let Some(m) = H2_PSEUDO_CRLF_RE.find(decoded) {
        return Some(L2Detection {
            detection_type: "h2_pseudo_crlf_injection".into(),
            confidence: 0.93,
            detail: "Encoded CRLF in HTTP/2 pseudo-header value detected".into(),
            position: m.start(),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: m.as_str().to_owned(),
                interpretation:
                    "CRLF in pseudo-header values can inject downstream headers during protocol translation".into(),
                offset: m.start(),
                property: "HTTP/2 pseudo-header values must reject CR/LF bytes and encodings".into(),
            }],
        });
    }
    None
}

fn detect_chunked_edge_cases(decoded: &str) -> Vec<L2Detection> {
    let mut dets = Vec::new();
    if !CHUNKED_RE.is_match(decoded) {
        return dets;
    }

    let (_, body, body_start) = split_headers_body(decoded);
    if let Some(m) = NEGATIVE_CHUNK_SIZE_RE.find(body) {
        dets.push(L2Detection {
            detection_type: "chunked_edge_case".into(),
            confidence: 0.93,
            detail: "Negative chunk size detected".into(),
            position: body_start + m.start(),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: m.as_str().to_owned(),
                interpretation:
                    "Negative chunk sizes trigger parser disagreement and may bypass framing validation".into(),
                offset: body_start + m.start(),
                property: "Chunk sizes must be unsigned hexadecimal values".into(),
            }],
        });
    }

    if (body.contains("0\r\n") || body.contains("0\n"))
        && !body.ends_with("\r\n\r\n")
        && !body.ends_with("\n\n")
    {
        let pos = body.find("0\r\n").or_else(|| body.find("0\n")).unwrap_or(0);
        dets.push(L2Detection {
            detection_type: "chunked_edge_case".into(),
            confidence: 0.90,
            detail: "Chunked terminator found without final empty line".into(),
            position: body_start + pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: "0\\r\\n (missing terminal CRLF)".into(),
                interpretation:
                    "Missing final CRLF after zero-size chunk can desynchronize request boundary handling".into(),
                offset: body_start + pos,
                property: "Chunked message termination must include complete terminal CRLF sequence".into(),
            }],
        });
    }

    dets
}

fn detect_double_content_length(decoded: &str) -> Option<L2Detection> {
    let mut values: Vec<(usize, String)> = Vec::new();
    for caps in CL_HEADER_VALUE_RE.captures_iter(decoded) {
        let all = caps.get(0)?;
        values.push((all.start(), caps.get(1)?.as_str().trim().to_owned()));
    }
    if values.len() < 2 {
        return None;
    }
    let first = &values[0].1;
    if values.iter().skip(1).any(|(_, v)| v != first) {
        let joined = values
            .iter()
            .map(|(_, v)| format!("Content-Length: {}", v))
            .collect::<Vec<_>>()
            .join(" | ");
        return Some(L2Detection {
            detection_type: "double_content_length".into(),
            confidence: 0.95,
            detail: "Two Content-Length headers with different values detected".into(),
            position: values[0].0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: joined,
                interpretation:
                    "Different Content-Length values are parsed inconsistently by intermediaries and backends".into(),
                offset: values[0].0,
                property:
                    "A request must include at most one Content-Length, or multiple identical normalized values".into(),
            }],
        });
    }
    None
}

fn detect_content_length_whitespace(decoded: &str) -> Option<L2Detection> {
    if let Some(m) = CL_INTERNAL_WS_RE.find(decoded) {
        return Some(L2Detection {
            detection_type: "cl_whitespace_desync".into(),
            confidence: 0.90,
            detail: "Whitespace-obfuscated Content-Length value detected".into(),
            position: m.start(),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: m.as_str().to_owned(),
                interpretation:
                    "Internal whitespace in numeric length may be normalized differently across parsers".into(),
                offset: m.start(),
                property: "Content-Length value must be a canonical integer without internal whitespace".into(),
            }],
        });
    }
    None
}

fn detect_te_list_obfuscation(decoded: &str) -> Option<L2Detection> {
    if let Some(m) = TE_LIST_OBFUSCATION_RE.find(decoded) {
        return Some(L2Detection {
            detection_type: "te_list_obfuscation".into(),
            confidence: 0.92,
            detail: "Transfer-Encoding list obfuscation detected".into(),
            position: m.start(),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: m.as_str().to_owned(),
                interpretation:
                    "Ambiguous Transfer-Encoding lists can make one parser honor chunked while another ignores it".into(),
                offset: m.start(),
                property: "Transfer-Encoding list must be canonical and free of ambiguous trailing tokens".into(),
            }],
        });
    }
    None
}

fn detect_request_line_differentials(decoded: &str) -> Vec<L2Detection> {
    let mut dets = Vec::new();
    let line1 = decoded.lines().next().unwrap_or("").trim_end_matches('\r');
    let parts: Vec<&str> = line1.split_whitespace().collect();
    if parts.len() > 3 && METHOD_RE.is_match(parts[0]) {
        dets.push(L2Detection {
            detection_type: "request_line_space_uri".into(),
            confidence: 0.87,
            detail: "Request target contains unescaped spaces".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: line1.to_owned(),
                interpretation:
                    "Space-delimited URI segments can split parser interpretation of target and version".into(),
                offset: 0,
                property: "Request target must encode spaces and preserve a 3-token request line".into(),
            }],
        });
    }

    let mut versions = Vec::new();
    for cap in REQUEST_LINE_RE.captures_iter(decoded) {
        if let Some(v) = cap.get(3) {
            versions.push(v.as_str().to_owned());
        }
    }
    if versions.iter().any(|v| v == "1.1") && versions.iter().any(|v| v == "1.0") {
        dets.push(L2Detection {
            detection_type: "request_line_version_downgrade".into(),
            confidence: 0.90,
            detail: "Mixed HTTP/1.1 and HTTP/1.0 request lines detected".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: "HTTP/1.1 + HTTP/1.0".into(),
                interpretation:
                    "Version downgrade differentials can alter connection reuse and boundary parsing".into(),
                offset: 0,
                property:
                    "A single inbound request stream should not mix inconsistent HTTP versions".into(),
            }],
        });
    }

    dets
}

fn detect_websocket_upgrade_smuggle(decoded: &str) -> Option<L2Detection> {
    let (headers, body, body_start) = split_headers_body(decoded);
    let headers_lc = headers.to_ascii_lowercase();
    let ws_upgrade_present = headers_lc
        .lines()
        .any(|l| l.trim_start().starts_with("upgrade: websocket"));
    let conn_upgrade_present = headers_lc
        .lines()
        .any(|l| l.trim_start().starts_with("connection:") && l.contains("upgrade"));
    let has_body = body.chars().any(|c| !c.is_whitespace());
    if ws_upgrade_present
        && conn_upgrade_present
        && ((HAS_CL_RE.is_match(decoded) && has_body) || HAS_TE_RE.is_match(decoded))
    {
        let pos = headers_lc.find("upgrade: websocket").unwrap_or(0);
        return Some(L2Detection {
            detection_type: "websocket_upgrade_smuggle".into(),
            confidence: 0.91,
            detail: "WebSocket upgrade request carries ambiguous HTTP framing".into(),
            position: pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: "Upgrade: websocket".into(),
                interpretation:
                    "Upgrade handshakes with CL/TE or extra body bytes can smuggle trailing requests".into(),
                offset: body_start.min(pos),
                property:
                    "WebSocket upgrade requests should have unambiguous framing and no hidden payload".into(),
            }],
        });
    }

    if !WEBSOCKET_UPGRADE_RE.is_match(decoded) || !CONNECTION_WS_UPGRADE_RE.is_match(decoded) {
        return None;
    }
    let has_body = body.chars().any(|c| !c.is_whitespace());
    if (HAS_CL_RE.is_match(decoded) && has_body) || HAS_TE_RE.is_match(decoded) {
        let pos = decoded.find("Upgrade").unwrap_or(0);
        return Some(L2Detection {
            detection_type: "websocket_upgrade_smuggle".into(),
            confidence: 0.91,
            detail: "WebSocket upgrade request carries ambiguous HTTP framing".into(),
            position: pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: "Upgrade: websocket".into(),
                interpretation:
                    "Upgrade handshakes with CL/TE or extra body bytes can smuggle trailing requests".into(),
                offset: body_start.min(pos),
                property:
                    "WebSocket upgrade requests should have unambiguous framing and no hidden payload".into(),
            }],
        });
    }
    None
}

impl L2Evaluator for HttpSmuggleEvaluator {
    fn id(&self) -> &'static str {
        "http_smuggle"
    }
    fn prefix(&self) -> &'static str {
        "L2 HTTPSmuggle"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // Conflicting Content-Length and Transfer-Encoding (CL.TE / TE.CL)
        let has_cl = HAS_CL_RE.is_match(&decoded);
        let has_te = HAS_TE_RE.is_match(&decoded);
        if has_cl && has_te {
            dets.push(L2Detection {
                detection_type: "cl_te_conflict".into(),
                confidence: 0.92,
                detail:
                    "Both Content-Length and Transfer-Encoding present — HTTP request smuggling"
                        .into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: "Content-Length + Transfer-Encoding".into(),
                    interpretation: "Conflicting headers cause front-end/back-end desync".into(),
                    offset: 0,
                    property:
                        "HTTP requests must not contain both Content-Length and Transfer-Encoding"
                            .into(),
                }],
            });
        }

        // HTTP/2 pseudo-header smuggling: multiple CL values or pseudo headers with CRLF
        if CL_VALUES_RE.find_iter(&decoded).count() > 1 {
            dets.push(L2Detection {
                detection_type: "http2_smuggle".into(),
                confidence: 0.88,
                detail: "Multiple Content-Length headers with HTTP/2 pseudo headers".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: "Content-Length".into(),
                    interpretation: "Multiple Content-Length headers can trigger content-length desync during protocol conversion".into(),
                    offset: 0,
                    property: "HTTP request must contain only one Content-Length header".into(),
                }],
            });
        }

        if let Some(pseudo_match) = H2_PSEUDO_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "http2_smuggle".into(),
                confidence: 0.88,
                detail: "HTTP/2 pseudo-header block detected with CRLF".into(),
                position: pseudo_match.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: pseudo_match.as_str().to_owned(),
                    interpretation:
                        "Invalid HTTP/1 proxying of HTTP/2 pseudo headers can cause request desync"
                            .into(),
                    offset: pseudo_match.start(),
                    property: "HTTP/1 parsers must not process HTTP/2 pseudo headers directly"
                        .into(),
                }],
            });
        }

        // Obfuscated Transfer-Encoding: Transfer-Encoding: chunked\r\nTransfer-Encoding: identity
        if let Some(m) = TE_OBFUSCATED_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "te_obfuscation".into(),
                confidence: 0.90,
                detail: "Obfuscated Transfer-Encoding header — TE.TE smuggling".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Multiple/obfuscated TE headers cause parsing ambiguity".into(),
                    offset: m.start(),
                    property: "Transfer-Encoding header must not be duplicated or obfuscated"
                        .into(),
                }],
            });
        }

        // Chunked encoding with chunk extensions
        let is_chunked = CHUNKED_RE.is_match(&decoded);
        let has_chunk_ext = CHUNK_EXT_RE.is_match(&decoded);
        if is_chunked && has_chunk_ext {
            if let Some(m) = CHUNK_EXT_RE.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "http_chunk_ext".into(),
                    confidence: 0.85,
                    detail: "Chunked body includes chunk extensions".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation:
                            "Chunk extensions alter parsing behavior in chunked transfer bodies"
                                .into(),
                        offset: m.start(),
                        property:
                            "Servers should reject chunk-extensions in untrusted request bodies"
                                .into(),
                    }],
                });
            }
        }

        // Content-Length: 0 with non-empty body
        if let Some(cl_zero) = CL_ZERO_RE.find(&decoded) {
            let sep_crlf = decoded.find("\r\n\r\n");
            let sep_lf = decoded.find("\n\n");

            let (start, header_end) = match (sep_crlf, sep_lf) {
                (Some(i), _) if cl_zero.start() < i => (i + 4, "\r\n\r\n"),
                (_, Some(i)) if cl_zero.start() < i => (i + 2, "\n\n"),
                _ => (0, ""),
            };

            if header_end != "" {
                let body = &decoded[start..];
                if body.chars().any(|c| !c.is_whitespace()) {
                    dets.push(L2Detection {
                        detection_type: "http_zero_cl".into(),
                        confidence: 0.87,
                        detail: "Content-Length is 0 but request body contains data".into(),
                        position: cl_zero.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: body.to_owned(),
                            interpretation: "Body bytes with CL=0 indicate framing mismatch".into(),
                            offset: start,
                            property: "Content-Length 0 must not have trailing body bytes".into(),
                        }],
                    });
                }
            }
        }

        // Embedded HTTP request in body (smuggled request)
        let matches: Vec<_> = EMBEDDED_REQ_RE.find_iter(&decoded).collect();
        if matches.len() > 1 {
            dets.push(L2Detection {
                detection_type: "embedded_request".into(),
                confidence: 0.88,
                detail: format!(
                    "Multiple HTTP requests in single body ({} found)",
                    matches.len()
                ),
                position: matches[1].start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matches[1].as_str().to_owned(),
                    interpretation: "Second HTTP request smuggled inside first request body".into(),
                    offset: matches[1].start(),
                    property: "HTTP request body must not contain embedded HTTP requests".into(),
                }],
            });
        }

        if let Some(det) = detect_cl_cl_desync(&decoded) {
            dets.push(det);
        }

        dets.extend(detect_te_cl_order_desync(&decoded));

        if let Some(det) = detect_obfuscated_te_variants(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_http2_downgrade_smuggle(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_request_line_injection(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_chunk_size_overflow(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_chunk_extension_abuse(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_h2_cl_smuggle(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_h2_te_smuggle(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_cl_0_smuggle(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_h2_pseudo_crlf_injection(&decoded) {
            dets.push(det);
        }

        dets.extend(detect_chunked_edge_cases(&decoded));

        if let Some(det) = detect_double_content_length(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_content_length_whitespace(&decoded) {
            dets.push(det);
        }

        if let Some(det) = detect_te_list_obfuscation(&decoded) {
            dets.push(det);
        }

        dets.extend(detect_request_line_differentials(&decoded));

        if let Some(det) = detect_websocket_upgrade_smuggle(&decoded) {
            dets.push(det);
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "cl_te_conflict" | "te_obfuscation" | "embedded_request" => {
                Some(InvariantClass::HttpSmuggleClTe)
            }
            "cl_cl_desync"
            | "te_cl_desync"
            | "cl_te_desync"
            | "te_obfuscation_advanced"
            | "request_line_injection" => Some(InvariantClass::HttpSmuggleClTe),
            "http2_smuggle" => Some(InvariantClass::HttpSmuggleH2),
            "http2_downgrade_smuggle" => Some(InvariantClass::HttpSmuggleH2),
            "http_chunk_ext" => Some(InvariantClass::HttpSmuggleChunkExt),
            "chunk_size_overflow" | "chunk_ext_abuse" => Some(InvariantClass::HttpSmuggleChunkExt),
            "http_zero_cl" => Some(InvariantClass::HttpSmuggleZeroCl),
            "h2_cl_smuggle" | "h2_te_smuggle" | "h2_pseudo_crlf_injection" => {
                Some(InvariantClass::HttpSmuggleH2)
            }
            "cl_0_smuggle" => Some(InvariantClass::HttpSmuggleZeroCl),
            "chunked_edge_case" => Some(InvariantClass::HttpSmuggleChunkExt),
            "double_content_length"
            | "cl_whitespace_desync"
            | "te_list_obfuscation"
            | "request_line_space_uri"
            | "request_line_version_downgrade"
            | "websocket_upgrade_smuggle" => Some(InvariantClass::HttpSmuggleClTe),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http2_smuggle_multiple_content_length() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nabcde";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "http2_smuggle"));
        assert_eq!(
            eval.map_class("http2_smuggle"),
            Some(InvariantClass::HttpSmuggleH2)
        );
    }

    #[test]
    fn detects_http2_smuggle_pseudo_headers() {
        let eval = HttpSmuggleEvaluator;
        let input = ":method: GET\r\n:path: /admin\r\nHost: example.com\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "http2_smuggle"));
    }

    #[test]
    fn detects_http_chunk_extension_abuse() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=1\r\nWiki\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "http_chunk_ext"));
        assert_eq!(
            eval.map_class("http_chunk_ext"),
            Some(InvariantClass::HttpSmuggleChunkExt)
        );
    }

    #[test]
    fn detects_http_zero_content_length() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nBODY";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "http_zero_cl"));
        assert_eq!(
            eval.map_class("http_zero_cl"),
            Some(InvariantClass::HttpSmuggleZeroCl)
        );
    }

    #[test]
    fn detects_cl_cl_desync_mismatched_values() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nContent-Length: 9\r\n\r\nabcd";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "cl_cl_desync"));
        assert_eq!(
            eval.map_class("cl_cl_desync"),
            Some(InvariantClass::HttpSmuggleClTe)
        );
    }

    #[test]
    fn detects_te_cl_desync_order() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "te_cl_desync"));
    }

    #[test]
    fn detects_cl_te_desync_order() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "cl_te_desync"));
    }

    #[test]
    fn detects_obfuscated_transfer_encoding_xchunked() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: xchunked\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "te_obfuscation_advanced")
        );
    }

    #[test]
    fn detects_obfuscated_transfer_encoding_xff_chain() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "te_obfuscation_advanced")
        );
    }

    #[test]
    fn detects_http2_h2c_downgrade_pattern() {
        let eval = HttpSmuggleEvaluator;
        let input = "PRI * HTTP/2.0\r\nHost: example.com\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "http2_downgrade_smuggle")
        );
        assert_eq!(
            eval.map_class("http2_downgrade_smuggle"),
            Some(InvariantClass::HttpSmuggleH2)
        );
    }

    #[test]
    fn detects_request_line_injection_with_encoded_crlf() {
        let eval = HttpSmuggleEvaluator;
        let input = "GET /search%0d%0aGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "request_line_injection")
        );
    }

    #[test]
    fn detects_chunk_size_overflow() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n80000000\r\nA\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "chunk_size_overflow")
        );
    }

    #[test]
    fn detects_malicious_chunk_extension_abuse() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=../../../../etc/passwd\r\nWiki\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "chunk_ext_abuse"));
    }

    #[test]
    fn detects_h2_cl_smuggle_with_mismatched_lengths() {
        let eval = HttpSmuggleEvaluator;
        let input = "PRI * HTTP/2.0\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 1\r\n\r\nabcde";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "h2_cl_smuggle"));
    }

    #[test]
    fn detects_h2_cl_smuggle_with_internal_whitespace() {
        let eval = HttpSmuggleEvaluator;
        let input = ":method: POST\r\n:path: /submit\r\nContent-Length: 1 0\r\n\r\nabcdefghij";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "h2_cl_smuggle"));
    }

    #[test]
    fn detects_h2_te_smuggle_in_prior_knowledge_request() {
        let eval = HttpSmuggleEvaluator;
        let input =
            "PRI * HTTP/2.0\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "h2_te_smuggle"));
    }

    #[test]
    fn detects_h2_te_smuggle_in_upgrade_flow() {
        let eval = HttpSmuggleEvaluator;
        let input = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "h2_te_smuggle"));
    }

    #[test]
    fn detects_cl_0_smuggle_basic() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "cl_0_smuggle"));
    }

    #[test]
    fn detects_cl_0_smuggle_with_plain_body() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nbody";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "cl_0_smuggle"));
    }

    #[test]
    fn detects_h2_pseudo_header_crlf_injection_in_path() {
        let eval = HttpSmuggleEvaluator;
        let input = ":method: GET\r\n:path: /api%0d%0aX-Smuggled: 1\r\nHost: example.com\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "h2_pseudo_crlf_injection")
        );
    }

    #[test]
    fn detects_h2_pseudo_header_crlf_injection_in_method() {
        let eval = HttpSmuggleEvaluator;
        let input = ":method: GE\\r\\nT\r\n:path: /\r\nHost: example.com\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "h2_pseudo_crlf_injection")
        );
    }

    #[test]
    fn detects_chunked_edge_case_missing_final_empty_line() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "chunked_edge_case"));
    }

    #[test]
    fn detects_chunked_edge_case_negative_chunk_size() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nA\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "chunked_edge_case"));
    }

    #[test]
    fn detects_double_content_length_mismatch() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nContent-Length: 9\r\n\r\nabcdefghi";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "double_content_length")
        );
    }

    #[test]
    fn detects_double_content_length_mismatch_with_spacing() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0005\r\nContent-Length: 5  \r\n\r\nabcde";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "double_content_length")
        );
    }

    #[test]
    fn detects_content_length_whitespace_desync() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1 0\r\n\r\nabcdefghij";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cl_whitespace_desync")
        );
    }

    #[test]
    fn detects_content_length_whitespace_desync_with_tab() {
        let eval = HttpSmuggleEvaluator;
        let input =
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\t0\r\n\r\nabcdefghij";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cl_whitespace_desync")
        );
    }

    #[test]
    fn detects_transfer_encoding_list_obfuscation_trailing_comma() {
        let eval = HttpSmuggleEvaluator;
        let input =
            "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked ,\r\n\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "te_list_obfuscation")
        );
    }

    #[test]
    fn detects_transfer_encoding_list_obfuscation_prefixed_value() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: x, chunked\r\n\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "te_list_obfuscation")
        );
    }

    #[test]
    fn detects_request_line_space_in_uri() {
        let eval = HttpSmuggleEvaluator;
        let input = "GET /admin panel HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "request_line_space_uri")
        );
    }

    #[test]
    fn detects_request_line_version_downgrade_mix() {
        let eval = HttpSmuggleEvaluator;
        let input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 28\r\n\r\nGET /safe HTTP/1.0\r\nHost: b\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "request_line_version_downgrade")
        );
    }

    #[test]
    fn detects_websocket_upgrade_smuggle_with_content_length_body() {
        let eval = HttpSmuggleEvaluator;
        let input = "GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 4\r\n\r\nPING";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "websocket_upgrade_smuggle")
        );
    }

    #[test]
    fn detects_websocket_upgrade_smuggle_with_transfer_encoding() {
        let eval = HttpSmuggleEvaluator;
        let input = "GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "websocket_upgrade_smuggle")
        );
    }

    #[test]
    fn maps_new_h2_detectors_to_h2_class() {
        let eval = HttpSmuggleEvaluator;
        assert_eq!(
            eval.map_class("h2_cl_smuggle"),
            Some(InvariantClass::HttpSmuggleH2)
        );
        assert_eq!(
            eval.map_class("h2_te_smuggle"),
            Some(InvariantClass::HttpSmuggleH2)
        );
        assert_eq!(
            eval.map_class("h2_pseudo_crlf_injection"),
            Some(InvariantClass::HttpSmuggleH2)
        );
    }

    #[test]
    fn maps_new_smuggle_detectors_to_expected_classes() {
        let eval = HttpSmuggleEvaluator;
        assert_eq!(
            eval.map_class("chunked_edge_case"),
            Some(InvariantClass::HttpSmuggleChunkExt)
        );
        assert_eq!(
            eval.map_class("cl_0_smuggle"),
            Some(InvariantClass::HttpSmuggleZeroCl)
        );
        assert_eq!(
            eval.map_class("websocket_upgrade_smuggle"),
            Some(InvariantClass::HttpSmuggleClTe)
        );
    }
}
