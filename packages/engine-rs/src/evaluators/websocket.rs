//! WebSocket Attack Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::collections::HashMap;

pub struct WebSocketEvaluator;

impl L2Evaluator for WebSocketEvaluator {
    fn id(&self) -> &'static str { "websocket" }
    fn prefix(&self) -> &'static str { "L2 WebSocket" }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // WS message with embedded SQL/XSS/command injection
        static JSONISH_FRAME_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\{[\s\S]*\}").unwrap());
        static WS_KEYWORD_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:websocket|ws[_-]?(?:message|frame))").unwrap());
        let looks_like_ws = JSONISH_FRAME_RE.is_match(&decoded) || WS_KEYWORD_RE.is_match(&decoded);

        if looks_like_ws {
            // SQL in WS
            static WS_SQL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(r#"(?i)(?:'\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|union\s+(?:all\s+)?select|;\s*(?:drop|delete|insert|update|alter|create|exec|execute))"#).unwrap()
            });
            if WS_SQL_RE.is_match(&decoded) {
                dets.push(L2Detection {
                    detection_type: "ws_sql_injection".into(),
                    confidence: 0.88,
                    detail: "SQL injection payload inside WebSocket message".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[..decoded.len().min(80)].to_owned(),
                        interpretation: "WebSocket message carries SQL injection payload".into(),
                        offset: 0,
                        property: "WebSocket message payloads must be validated against injection".into(),
                    }],
                });
            }

            // XSS in WS
            static WS_XSS_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:<script[\s>]|javascript\s*:|\bon(?:error|load|click)\s*=)").unwrap());
            if WS_XSS_RE.is_match(&decoded) {
                dets.push(L2Detection {
                    detection_type: "ws_xss".into(),
                    confidence: 0.88,
                    detail: "XSS payload inside WebSocket message".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[..decoded.len().min(80)].to_owned(),
                        interpretation: "WebSocket message carries XSS payload".into(),
                        offset: 0,
                        property: "WebSocket message payloads must be validated against XSS".into(),
                    }],
                });
            }
        }

        // WS hijack: Upgrade header with suspicious origin
        static UPGRADE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*upgrade\s*:\s*websocket\b").unwrap());
        let has_upgrade = UPGRADE_RE.is_match(&decoded);
        if has_upgrade {
            static SUSPICIOUS_ORIGIN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(r"(?im)^\s*origin\s*:\s*(?:null|https?://(?:evil|attacker|malicious|phish|exploit))").unwrap()
            });
            static SEC_WS_KEY_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*sec-websocket-key\s*:").unwrap());
            let suspicious_origin = SUSPICIOUS_ORIGIN_RE.is_match(&decoded);
            let missing_key = !SEC_WS_KEY_RE.is_match(&decoded);

            if suspicious_origin || missing_key {
                dets.push(L2Detection {
                    detection_type: "ws_hijack".into(),
                    confidence: 0.85,
                    detail: format!("WebSocket hijack attempt{}{}",
                        if suspicious_origin { " (suspicious origin)" } else { "" },
                        if missing_key { " (missing Sec-WebSocket-Key)" } else { "" }),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: "Upgrade: websocket".into(),
                        interpretation: "WebSocket upgrade with missing or suspicious security headers".into(),
                        offset: 0,
                        property: "WebSocket upgrades must validate origin and include security headers".into(),
                    }],
                });
            }
        }

        // Cross-site WebSocket hijacking: valid upgrade + null/missing Origin
        if has_upgrade {
            static NULL_ORIGIN_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*origin\s*:\s*null\s*$").unwrap());
            static ORIGIN_HEADER_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*origin\s*:").unwrap());
            let null_origin = NULL_ORIGIN_RE.is_match(&decoded);
            let missing_origin = !ORIGIN_HEADER_RE.is_match(&decoded);
            if null_origin || missing_origin {
                dets.push(L2Detection {
                    detection_type: "ws_csws_hijack".into(),
                    confidence: 0.91,
                    detail: "Cross-site WebSocket hijacking indicator: Upgrade present with null/missing Origin".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: "Upgrade: websocket".into(),
                        interpretation: "WebSocket handshake can be initiated cross-site without origin validation".into(),
                        offset: 0,
                        property: "WebSocket handshake must enforce strict Origin checks".into(),
                    }],
                });
            }
        }

        // WS command injection: shell metacharacters in JSON string values
        static WS_CMD_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?is)"[^"]+"\s*:\s*"[^"\r\n]*(?:\||;|`)[^"\r\n]*""#).unwrap());
        if WS_CMD_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "ws_command_injection".into(),
                confidence: 0.90,
                detail: "WebSocket JSON value contains shell metacharacters".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(100)].to_owned(),
                    interpretation: "Shell metacharacters in WS frame value indicate command-injection payload delivery".into(),
                    offset: 0,
                    property: "WebSocket JSON values must be allowlisted and command execution must never concatenate user input".into(),
                }],
            });
        }

        // WS path traversal via message fields
        static WS_PATH_TRAVERSAL_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?is)"[^"]+"\s*:\s*"[^"\r\n]*(?:\.\./){2,}[^"\r\n]*""#).unwrap());
        if WS_PATH_TRAVERSAL_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "ws_path_traversal".into(),
                confidence: 0.89,
                detail: "WebSocket frame includes directory traversal sequence in field value".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(100)].to_owned(),
                    interpretation: "WS payload includes repeated ../ traversal targeting filesystem paths".into(),
                    offset: 0,
                    property: "Server-side path operations over WebSocket data must normalize and confine paths".into(),
                }],
            });
        }

        // WS auth bypass: null/empty/admin marker in auth or token fields
        static WS_AUTH_EMPTY_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?is)"(?:auth|token|accessToken|session)"\s*:\s*(?:null|""|'')"#).unwrap());
        static WS_AUTH_ADMIN_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?is)"(?:auth|token|role)"\s*:\s*"admin""#).unwrap());
        if WS_AUTH_EMPTY_RE.is_match(&decoded) || WS_AUTH_ADMIN_RE.is_match(&decoded)
        {
            dets.push(L2Detection {
                detection_type: "ws_auth_bypass".into(),
                confidence: 0.87,
                detail: "WebSocket frame attempts authentication bypass via weak auth field values".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: decoded[..decoded.len().min(100)].to_owned(),
                    interpretation: "Auth-related WS fields are explicitly null/empty/privileged marker values".into(),
                    offset: 0,
                    property: "WebSocket authentication fields must be required, signed, and role-validated server-side".into(),
                }],
            });
        }

        // WS message flooding / replay: repeated identical frame payloads
        if looks_like_ws {
            static frame_re: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r#"(?s)\{[^{}\r\n]{2,300}\}"#).unwrap());
            let mut seen: HashMap<String, usize> = HashMap::new();
            for m in frame_re.find_iter(&decoded) {
                let frame = m.as_str().trim().to_owned();
                *seen.entry(frame).or_insert(0) += 1;
            }
            if let Some((frame, count)) = seen.into_iter().max_by_key(|(_, c)| *c) {
                if count >= 4 {
                    dets.push(L2Detection {
                        detection_type: "ws_message_flood".into(),
                        confidence: 0.86,
                        detail: format!("Repeated identical WebSocket frame detected {} times (possible replay/flood)", count),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::SemanticEval,
                            matched_input: frame,
                            interpretation: "Same WebSocket message pattern repeats at high frequency, consistent with replay/flood behavior".into(),
                            offset: 0,
                            property: "WebSocket servers should enforce anti-replay controls and per-message rate limits".into(),
                        }],
                    });
                }
            }
        }

        if let Some(det) = detect_csws_origin_mismatch(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_websocket_control_frame_injection(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_websocket_fragmentation_abuse(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_websocket_tunneling(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_websocket_subprotocol_abuse(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_websocket_extension_abuse(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_websocket_masking_key_prediction(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_websocket_close_frame_abuse(&decoded) {
            dets.push(det);
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "ws_sql_injection" | "ws_xss" => Some(InvariantClass::WsInjection),
            "ws_hijack" => Some(InvariantClass::WsHijack),
            "ws_command_injection" | "ws_path_traversal" => Some(InvariantClass::WsInjection),
            "ws_csws_hijack" | "ws_auth_bypass" | "ws_message_flood" => Some(InvariantClass::WsHijack),
            "ws_control_frame_injection" | "ws_fragmentation_abuse" | "ws_tunneling" => Some(InvariantClass::WsInjection),
            "ws_csws_origin_mismatch"
            | "ws_subprotocol_abuse"
            | "ws_extension_abuse"
            | "ws_masking_key_prediction"
            | "ws_close_frame_abuse" => Some(InvariantClass::WsHijack),
            _ => None,
        }
    }
}

fn detect_csws_origin_mismatch(decoded: &str) -> Option<L2Detection> {
    static UPGRADE_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*upgrade\s*:\s*websocket\b").unwrap());
    static ORIGIN_HOST_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*origin\s*:\s*https?://([^/\s:]+)").unwrap());
    static HOST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?im)^\s*host\s*:\s*([a-z0-9][a-z0-9\.-]*[a-z0-9])(?::\d+)?\s*$").unwrap()
    });

    if !UPGRADE_RE.is_match(decoded) {
        return None;
    }

    let origin_host = ORIGIN_HOST_RE
        .captures(decoded)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_ascii_lowercase());
    let host = HOST_RE
        .captures(decoded)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_ascii_lowercase());

    match (origin_host, host) {
        (Some(origin), Some(host)) if origin != host => Some(L2Detection {
            detection_type: "ws_csws_origin_mismatch".into(),
            confidence: 0.93,
            detail: format!(
                "Cross-site WebSocket hijacking indicator: Origin/Host mismatch (origin={}, host={})",
                origin, host
            ),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: "Origin/Host mismatch in WebSocket upgrade".into(),
                interpretation: "Handshake indicates cross-site initiation with mismatched Origin and Host".into(),
                offset: 0,
                property: "WebSocket upgrades must enforce strict Origin allowlists and reject cross-site mismatches".into(),
            }],
        }),
        _ => None,
    }
}

fn detect_websocket_control_frame_injection(decoded: &str) -> Option<L2Detection> {
    static RESERVED_OPCODE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:opcode|op)\s*[:=]\s*(?:0x)?(?:3|4|5|6|7|b|c|d|e|f)\b").unwrap()
    });
    static OVERSIZED_CONTROL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?is)\b(?:opcode|op)\s*[:=]\s*(?:0x)?(?:8|9|a)\b[\s\S]{0,120}?\b(?:payload(?:_len| length)?|len)\s*[:=]\s*(1[2-9]\d|[2-9]\d{2,})\b").unwrap()
    });

    if !RESERVED_OPCODE_RE.is_match(decoded) && !OVERSIZED_CONTROL_RE.is_match(decoded) {
        return None;
    }

    Some(L2Detection {
        detection_type: "ws_control_frame_injection".into(),
        confidence: 0.92,
        detail: "WebSocket control-frame injection pattern detected (reserved opcode or oversized control payload)".into(),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: decoded[..decoded.len().min(120)].to_owned(),
            interpretation: "Frame metadata indicates opcode manipulation consistent with control-frame injection".into(),
            offset: 0,
            property: "WebSocket frame parser must reject reserved opcodes and control payloads larger than 125 bytes".into(),
        }],
    })
}

fn detect_websocket_fragmentation_abuse(decoded: &str) -> Option<L2Detection> {
    static FIN_ZERO_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)\bfin\s*[:=]\s*0\b").unwrap());
    static CONTINUATION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:opcode|op)\s*[:=]\s*(?:0x)?0\b|\bcontinuation\b").unwrap()
    });

    let fin_zero_count = FIN_ZERO_RE.find_iter(decoded).count();
    let continuation_count = CONTINUATION_RE.find_iter(decoded).count();
    if fin_zero_count < 3 || continuation_count < 2 {
        return None;
    }

    Some(L2Detection {
        detection_type: "ws_fragmentation_abuse".into(),
        confidence: 0.90,
        detail: format!(
            "WebSocket fragmented-message abuse detected (fin=0 count {}, continuation count {})",
            fin_zero_count, continuation_count
        ),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: decoded[..decoded.len().min(140)].to_owned(),
            interpretation: "Abnormal continuation-fragment cadence can be used to bypass inspection or exhaust parser state".into(),
            offset: 0,
            property: "WebSocket handlers must enforce strict fragmentation limits and reassembly timeouts".into(),
        }],
    })
}

fn detect_websocket_tunneling(decoded: &str) -> Option<L2Detection> {
    static CONNECT_TUNNEL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?is)\bconnect\s+[a-z0-9\.-]+:\d{2,5}\s+http/1\.[01]\b").unwrap()
    });
    static SOCKS_TUNNEL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(?:\bsocks(?:4|5)?\b|\bsocks\s*proxy\b|\\x05\\x01\\x00|0x05 0x01 0x00)").unwrap()
    });

    let has_connect_tunnel = CONNECT_TUNNEL_RE.is_match(decoded);
    let has_socks_tunnel = SOCKS_TUNNEL_RE.is_match(decoded);
    if !has_connect_tunnel && !has_socks_tunnel {
        return None;
    }

    Some(L2Detection {
        detection_type: "ws_tunneling".into(),
        confidence: 0.93,
        detail: format!(
            "WebSocket tunneling pattern detected{}{}",
            if has_connect_tunnel { " (HTTP CONNECT)" } else { "" },
            if has_socks_tunnel { " (SOCKS signature)" } else { "" }
        ),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: decoded[..decoded.len().min(140)].to_owned(),
            interpretation: "WebSocket payload includes proxy/tunnel negotiation patterns for arbitrary transport pivoting".into(),
            offset: 0,
            property: "WebSocket endpoints must disallow CONNECT/SOCKS relay semantics and enforce message schema validation".into(),
        }],
    })
}

fn detect_websocket_subprotocol_abuse(decoded: &str) -> Option<L2Detection> {
    static SUBPROTOCOL_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*sec-websocket-protocol\s*:\s*([^\r\n]+)\s*$").unwrap());
    static DOWNGRADE_TOKEN_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)\b(?:draft76|draft75|hybi-00|v0|version=0)\b").unwrap());
    static CONFUSION_TOKEN_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)\b(?:http/1\.1|h2c|spdy|raw)\b").unwrap());

    let value = SUBPROTOCOL_RE
        .captures(decoded)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_ascii_lowercase())?;

    let tokens: Vec<&str> = value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let mut seen = HashMap::new();
    for token in &tokens {
        *seen.entry(*token).or_insert(0usize) += 1;
    }

    let has_duplicates = seen.values().any(|count| *count > 1);
    let has_downgrade = DOWNGRADE_TOKEN_RE.is_match(&value);
    let has_confusion_token = CONFUSION_TOKEN_RE.is_match(&value);
    let mixed_graphql_protocols = value.contains("graphql-ws") && value.contains("graphql-transport-ws");

    if !has_duplicates && !has_downgrade && !has_confusion_token && !mixed_graphql_protocols {
        return None;
    }

    Some(L2Detection {
        detection_type: "ws_subprotocol_abuse".into(),
        confidence: 0.89,
        detail: "Suspicious Sec-WebSocket-Protocol manipulation indicates downgrade or protocol confusion".into(),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::TypeCoerce,
            matched_input: format!("Sec-WebSocket-Protocol: {}", value),
            interpretation: "Subprotocol negotiation contains duplicate, downgrade, or incompatible protocol tokens".into(),
            offset: 0,
            property: "WebSocket servers must enforce a strict allowlist of expected subprotocols and reject ambiguous negotiation".into(),
        }],
    })
}

fn detect_websocket_extension_abuse(decoded: &str) -> Option<L2Detection> {
    static EXT_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*sec-websocket-extensions\s*:\s*([^\r\n]+)\s*$").unwrap());
    static WINDOW_BITS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:client|max|server)_window_bits\s*=\s*(\d{1,3})\b").unwrap()
    });
    static LEGACY_EXTENSION_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)\bx-webkit-deflate-frame\b").unwrap());

    let value = EXT_RE
        .captures(decoded)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_ascii_lowercase())?;

    let has_invalid_window_bits = WINDOW_BITS_RE.captures_iter(&value).any(|caps| {
        caps.get(1)
            .and_then(|m| m.as_str().parse::<u16>().ok())
            .map(|bits| bits == 0 || bits > 15)
            .unwrap_or(false)
    });
    let has_legacy_extension = LEGACY_EXTENSION_RE.is_match(&value);
    let repeated_permessage_deflate = value.matches("permessage-deflate").count() > 1;

    if !has_invalid_window_bits && !has_legacy_extension && !repeated_permessage_deflate {
        return None;
    }

    Some(L2Detection {
        detection_type: "ws_extension_abuse".into(),
        confidence: 0.90,
        detail: "Suspicious Sec-WebSocket-Extensions parameters indicate compression-extension abuse".into(),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: format!("Sec-WebSocket-Extensions: {}", value),
            interpretation: "Extension negotiation includes invalid compression parameters or legacy extension confusion".into(),
            offset: 0,
            property: "WebSocket extensions must be strictly validated and compression parameters constrained to RFC-compliant values".into(),
        }],
    })
}

fn detect_websocket_masking_key_prediction(decoded: &str) -> Option<L2Detection> {
    static MASK_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?im)\b(?:mask(?:ing)?[_-]?key)\s*[:=]\s*(?:0x)?([0-9a-f]{8})\b").unwrap()
    });

    let mut counts: HashMap<String, usize> = HashMap::new();
    for caps in MASK_KEY_RE.captures_iter(decoded) {
        if let Some(m) = caps.get(1) {
            let key = m.as_str().to_ascii_lowercase();
            *counts.entry(key).or_insert(0) += 1;
        }
    }

    if counts.is_empty() {
        return None;
    }

    let has_zero_mask = counts.contains_key("00000000");
    let repeated_key = counts.iter().find(|(_, count)| **count >= 2).map(|(key, _)| key.clone());
    if !has_zero_mask && repeated_key.is_none() {
        return None;
    }

    let detail = if has_zero_mask {
        "Predictable WebSocket masking key detected (all-zero mask)".to_owned()
    } else {
        format!(
            "Predictable WebSocket masking key detected (repeated key {})",
            repeated_key.unwrap_or_else(|| "unknown".to_owned())
        )
    };

    Some(L2Detection {
        detection_type: "ws_masking_key_prediction".into(),
        confidence: 0.91,
        detail,
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::EncodingDecode,
            matched_input: decoded[..decoded.len().min(140)].to_owned(),
            interpretation: "Masking keys are predictable or reused, enabling traffic manipulation and payload recovery".into(),
            offset: 0,
            property: "Client-to-server WebSocket masking keys must be unpredictable and never reused".into(),
        }],
    })
}

fn detect_websocket_close_frame_abuse(decoded: &str) -> Option<L2Detection> {
    static CLOSE_CODE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?im)\b(?:close(?:_code)?|code)\b(?:["'])?\s*[:=]\s*(\d{3,4})\b"#).unwrap()
    });
    static OVERSIZED_REASON_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?is)\b(?:close_reason|reason)\s*[:=]\s*"([^"]{124,})""#).unwrap()
    });

    let mut invalid_code: Option<u16> = None;
    for caps in CLOSE_CODE_RE.captures_iter(decoded) {
        if let Some(code_match) = caps.get(1) {
            if let Ok(code) = code_match.as_str().parse::<u16>() {
                if !is_valid_ws_close_code(code) {
                    invalid_code = Some(code);
                    break;
                }
            }
        }
    }

    let oversized_reason = OVERSIZED_REASON_RE
        .captures(decoded)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().len() > 123)
        .unwrap_or(false);

    if invalid_code.is_none() && !oversized_reason {
        return None;
    }

    Some(L2Detection {
        detection_type: "ws_close_frame_abuse".into(),
        confidence: 0.90,
        detail: match invalid_code {
            Some(code) => format!("WebSocket close frame abuse detected: invalid close code {}", code),
            None => "WebSocket close frame abuse detected: oversized close reason string".to_owned(),
        },
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SyntaxRepair,
            matched_input: decoded[..decoded.len().min(140)].to_owned(),
            interpretation: "Close frame metadata violates RFC constraints and may trigger parser inconsistencies".into(),
            offset: 0,
            property: "Close frames must use valid close codes and reason strings no longer than 123 bytes".into(),
        }],
    })
}

fn is_valid_ws_close_code(code: u16) -> bool {
    matches!(
        code,
        1000 | 1001 | 1002 | 1003 | 1007 | 1008 | 1009 | 1010 | 1011 | 1012 | 1013 | 1014
    ) || (3000..=4999).contains(&code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ws_csws_hijack_missing_origin() {
        let eval = WebSocketEvaluator;
        let input = "GET /socket HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc123==\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_csws_hijack"));
    }

    #[test]
    fn detects_ws_command_injection_in_json_value() {
        let eval = WebSocketEvaluator;
        let input = r#"{"action":"run","cmd":"cat /etc/passwd; id"}"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_command_injection"));
    }

    #[test]
    fn detects_ws_path_traversal_in_frame() {
        let eval = WebSocketEvaluator;
        let input = r#"{"type":"read","path":"../../../etc/shadow"}"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_path_traversal"));
    }

    #[test]
    fn detects_ws_auth_bypass_marker_values() {
        let eval = WebSocketEvaluator;
        let input = r#"{"event":"auth","token":"","role":"admin"}"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_auth_bypass"));
    }

    #[test]
    fn detects_ws_message_flood_replay() {
        let eval = WebSocketEvaluator;
        let input = r#"{"msg":"ping"}
{"msg":"ping"}
{"msg":"ping"}
{"msg":"ping"}"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_message_flood"));
    }

    #[test]
    fn detects_ws_cswsh_origin_host_mismatch() {
        let eval = WebSocketEvaluator;
        let input = "GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc123==\r\nOrigin: https://evil.example.net\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_csws_origin_mismatch"));
    }

    #[test]
    fn detects_ws_control_frame_injection_reserved_opcode() {
        let eval = WebSocketEvaluator;
        let input = r#"ws_frame opcode=0xB fin=1 payload_len=1"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_control_frame_injection"));
    }

    #[test]
    fn detects_ws_fragmentation_abuse() {
        let eval = WebSocketEvaluator;
        let input = r#"frame1 fin=0 opcode=0x1
frame2 fin=0 opcode=0x0 continuation
frame3 fin=0 opcode=0x0 continuation
frame4 fin=1 opcode=0x0"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_fragmentation_abuse"));
    }

    #[test]
    fn detects_ws_tunneling_via_connect() {
        let eval = WebSocketEvaluator;
        let input = "ws payload CONNECT internal.service.local:443 HTTP/1.1\r\nHost: internal.service.local:443\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_tunneling"));
    }

    #[test]
    fn detects_ws_tunneling_via_socks_pattern() {
        let eval = WebSocketEvaluator;
        let input = r#"{"raw":"\x05\x01\x00","mode":"socks5"}"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_tunneling"));
    }

    #[test]
    fn detects_ws_subprotocol_abuse_downgrade() {
        let eval = WebSocketEvaluator;
        let input = "GET /socket HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: graphql-ws, draft76\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_subprotocol_abuse"));
    }

    #[test]
    fn detects_ws_extension_abuse_invalid_window_bits() {
        let eval = WebSocketEvaluator;
        let input = "GET /socket HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate; server_window_bits=32\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_extension_abuse"));
    }

    #[test]
    fn detects_ws_masking_key_prediction_repeated_key() {
        let eval = WebSocketEvaluator;
        let input = "masking-key=deadbeef\nmasking-key=deadbeef\nmasking-key=cafebabe";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_masking_key_prediction"));
    }

    #[test]
    fn detects_ws_masking_key_prediction_zero_mask() {
        let eval = WebSocketEvaluator;
        let input = "mask_key: 00000000";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_masking_key_prediction"));
    }

    #[test]
    fn detects_ws_close_frame_abuse_invalid_code() {
        let eval = WebSocketEvaluator;
        let input = r#"{"opcode":8,"close_code":999,"reason":"bye"}"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_close_frame_abuse"));
    }

    #[test]
    fn detects_ws_close_frame_abuse_oversized_reason() {
        let eval = WebSocketEvaluator;
        let input = format!(r#"close_code=1000 reason="{}""#, "a".repeat(130));
        let dets = eval.detect(&input);
        assert!(dets.iter().any(|d| d.detection_type == "ws_close_frame_abuse"));
    }
}
