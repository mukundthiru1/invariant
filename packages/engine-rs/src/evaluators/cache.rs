//! Cache Poisoning Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct CacheEvaluator;

impl L2Evaluator for CacheEvaluator {
    fn id(&self) -> &'static str {
        "cache"
    }
    fn prefix(&self) -> &'static str {
        "L2 Cache"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let low = decoded.to_lowercase();

        // Unkeyed headers used for cache poisoning
        static unkeyed: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*(?:X-Forwarded-Host|X-Forwarded-Scheme|X-Original-URL|X-Rewrite-URL|X-Forwarded-Prefix)\s*:\s*([^\r\n]+)").unwrap()
        });
        if let Some(m) = unkeyed.find(&decoded) {
            let header_line = m.as_str();
            let has_host = header_line.to_lowercase().contains("x-forwarded-host");
            let has_path = header_line.to_lowercase().contains("x-original-url");
            static HOST_PAYLOAD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(
                    r"(?i)(?:https?://|/|\.{2}|%2e%2e|%252e%252e|javascript:|%0a|%0d|script)",
                )
                .unwrap()
            });
            let has_host_payload = HOST_PAYLOAD_RE.is_match(&decoded);
            if has_host_payload && (has_host || has_path) {
                dets.push(L2Detection {
                    detection_type: "header_key_injection".into(),
                    confidence: 0.89,
                    detail: "Cache key injection via unkeyed header".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: header_line.to_owned(),
                        interpretation: "Unkeyed header values can alter cache key resolution"
                            .into(),
                        offset: m.start(),
                        property:
                            "Cache key derivation must include and normalize trusted proxy headers"
                                .into(),
                    }],
                });
            }
        }

        // Cache deception: path confusion to cache sensitive pages
        static cache_deception: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)/(?:account|profile|settings|admin|api/me|dashboard)(?:/[^?\s]{0,80})?\.(?:css|js|jpg|png|gif|ico|svg|woff2?)(?:\?.*)?$").unwrap()
        });
        if let Some(m) = cache_deception.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cache_deception".into(),
                confidence: 0.82,
                detail: format!(
                    "Web cache deception: static extension on sensitive path: {}",
                    m.as_str()
                ),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Static file extension causes cache to store sensitive page"
                        .into(),
                    offset: m.start(),
                    property:
                        "Cache must not store responses for paths with trailing static extensions"
                            .into(),
                }],
            });
        }

        // Cache key injection via sensitive query parameters (parameter cloaking)
        static cloak: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)[?&](utm_content|utm_campaign|utm_source)\s*=\s*([^&\s]+)").unwrap()
        });
        for caps in cloak.captures_iter(&decoded) {
            let raw = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            static SUSPICIOUS_PARAM_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| {
                    Regex::new(r"(?i)<|javascript:|%3c|onerror|onload|<script|eval|alert|svg")
                        .unwrap()
                });
            let suspicious = SUSPICIOUS_PARAM_RE.is_match(value);
            if suspicious {
                dets.push(L2Detection {
                    detection_type: "query_cloak".into(),
                    confidence: 0.84,
                    detail: "Parameter cloaking via user-controlled cache key parameter".into(),
                    position: caps.get(0).map(|m| m.start()).unwrap_or(0),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: raw.to_owned(),
                        interpretation: "Query parameter intended for tracking carries executable payload".into(),
                        offset: caps.get(0).map(|m| m.start()).unwrap_or(0),
                        property: "Tracking or cloaking params must be stripped or normalized before cache keying".into(),
                    }],
                });
            }
        }

        // Cache poisoning via path confusion in static prefixes
        static path_confusion: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)/(?:static|assets|public|cdn)(?:/[^/\s?#]{1,30})*/(?:\.{2}|%2e%2e|%252e%252e)/(?:[^?\s#]{1,120})").unwrap()
        });
        if path_confusion.is_match(&low) {
            if let Some(m) = path_confusion.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "cache_path_confusion".into(),
                    confidence: 0.90,
                    detail: format!("Cache deception via path traversal under static prefix: {}", m.as_str()),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Traversal can force cache to store a dynamic endpoint as static".into(),
                        offset: m.start(),
                        property: "Path normalization must occur before cache key derivation".into(),
                    }],
                });
            }
        }

        // Static extension on sensitive path with traversal prefix
        static static_extension_confusion: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r"(?i)/(?:static|assets|public|cdn)/\.\./(?:api|v[0-9]+/user|account|profile|settings|dashboard|admin)(?:/[^.\s?]+)?\.(?:css|js|json|html|xml|txt)").unwrap()
            },
        );
        if let Some(m) = static_extension_confusion.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cache_path_confusion".into(),
                confidence: 0.92,
                detail: format!("Cache path confusion with static extension and sensitive traversal: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Static-looking endpoint targets sensitive API/user data".into(),
                    offset: m.start(),
                    property: "Cache layer should reject traversal + static-extension sensitive endpoint combinations".into(),
                }],
            });
        }

        // Host header override poisoning: conflicting Host and X-Forwarded-Host
        static HOST_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*Host\s*:\s*([^\r\n]+)").unwrap());
        static XFH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*X-Forwarded-Host\s*:\s*([^\r\n]+)").unwrap()
        });
        let host = HOST_RE.captures(&decoded).and_then(|c| c.get(1));
        let xfh = XFH_RE.captures(&decoded).and_then(|c| c.get(1));
        if let (Some(host), Some(xfh)) = (host, xfh) {
            let host_val = host.as_str().trim().to_ascii_lowercase();
            let xfh_val = xfh.as_str().trim().to_ascii_lowercase();
            if !host_val.is_empty() && !xfh_val.is_empty() && host_val != xfh_val {
                dets.push(L2Detection {
                    detection_type: "host_header_override".into(),
                    confidence: 0.91,
                    detail: "Conflicting Host and X-Forwarded-Host headers can poison cache keys".into(),
                    position: xfh.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: format!("Host: {}; X-Forwarded-Host: {}", host.as_str(), xfh.as_str()),
                        interpretation: "Multiple host authorities can desynchronize origin routing and cache key derivation".into(),
                        offset: xfh.start(),
                        property: "Cache key host must come from a single trusted source after proxy normalization".into(),
                    }],
                });
            }
        }

        // Forwarded/X-Host poisoning vectors often excluded from default cache keys
        static forwarded_host: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?im)^\s*(?:Forwarded\s*:\s*[^\r\n]*\bhost=|X-Host\s*:)\s*([^\r\n;,\"]+)"#,
            )
            .unwrap()
        });
        if let Some(m) = forwarded_host.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "forwarded_host_poison".into(),
                confidence: 0.88,
                detail: "Forwarded host override header can alter cached variant routing".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Forwarded host authority may be consumed by upstream apps while cache key ignores it".into(),
                    offset: m.start(),
                    property: "Forwarded/X-Host headers must be stripped unless coming from trusted edge proxies".into(),
                }],
            });
        }

        // Query parameter cloaking using ';' delimiter to desync cache and origin parsers
        static param_cloak: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\?[^#\r\n]{0,200}(?:;|%3b)[^#\r\n]{0,200}(?:admin|role|token|redirect|callback|url|format|lang)\s*=").unwrap()
        });
        if let Some(m) = param_cloak.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cache_param_cloaking".into(),
                confidence: 0.90,
                detail: "Semicolon parameter cloaking can split cache-key and origin parameter parsing".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Parser disagreement around ';' parameters can cache a response under the wrong variant".into(),
                    offset: m.start(),
                    property: "Cache and origin must canonicalize query delimiters identically before key derivation".into(),
                }],
            });
        }

        // Cacheable authenticated/private response indicators
        static AUTH_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*Authorization\s*:").unwrap());
        static CACHE_PUBLIC_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*Cache-Control\s*:\s*[^\r\n]*(?:public|s-maxage=\d+|max-age=\d+)")
                .unwrap()
        });
        static CACHE_CONTROL_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*Cache-Control\s*:[^\r\n]+").unwrap());
        let has_auth = AUTH_RE.is_match(&decoded);
        let cache_public = CACHE_PUBLIC_RE.is_match(&decoded);
        if has_auth && cache_public {
            let m = CACHE_CONTROL_RE.find(&decoded);
            let (snippet, pos) = m
                .map(|x| (x.as_str().to_owned(), x.start()))
                .unwrap_or(("Cache-Control".into(), 0));
            dets.push(L2Detection {
                detection_type: "auth_cacheable_response".into(),
                confidence: 0.86,
                detail: "Authenticated request context appears cacheable".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: snippet,
                    interpretation: "Public/shared cache directives alongside Authorization can leak personalized content cross-user".into(),
                    offset: pos,
                    property: "Responses tied to authenticated state must be marked private/no-store and excluded from shared cache".into(),
                }],
            });
        }

        // Vary on attacker-controlled headers can enable cache poisoning across variants
        static vary_untrusted: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*Vary\s*:\s*[^\r\n]*(?:X-Forwarded-Host|X-Original-URL|X-Rewrite-URL|Origin)").unwrap()
        });
        if let Some(m) = vary_untrusted.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cache_vary_override".into(),
                confidence: 0.85,
                detail: "Vary includes attacker-controlled header likely to create poisonable cache variants".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Vary on untrusted request headers can cause unbounded or attacker-directed cache variant poisoning".into(),
                    offset: m.start(),
                    property: "Vary should include only normalized, trusted headers with strict cardinality controls".into(),
                }],
            });
        }

        // Advanced web cache deception: authenticated paths ending in fake static resources
        static WCD_PATH_CONFUSION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)/(?:account|profile|settings|dashboard)(?:/[^/?#\s]{1,40}){0,4}/(?:nonexistent|notfound|404|[a-z0-9_-]{3,40})\.(?:css|js|jpg|png|gif|ico|svg|woff2?)(?:\?[^#\r\n]*)?$").unwrap()
        });
        if let Some(m) = WCD_PATH_CONFUSION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "web_cache_deception_path_confusion".into(),
                confidence: 0.91,
                detail: "Potential web cache deception via authenticated-path static extension confusion".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "A dynamic authenticated route appears as a static object and may be cached in shared layers".into(),
                    offset: m.start(),
                    property: "Sensitive/authenticated paths must not be cached solely due to static-looking suffixes".into(),
                }],
            });
        }
        static WCD_REQUEST_TARGET_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)(?:^|[\s"'])/(?:account|profile|settings|dashboard)(?:/[^/?#\s]{1,40}){1,5}\.(?:css|js|jpg|png|gif|ico|svg|woff2?)(?:\?[^ \r\n]*)?(?:\s|$)"#).unwrap()
        });
        if dets
            .iter()
            .all(|d| d.detection_type != "web_cache_deception_path_confusion")
        {
            if let Some(m) = WCD_REQUEST_TARGET_RE.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "web_cache_deception_path_confusion".into(),
                    confidence: 0.89,
                    detail: "Potential web cache deception in HTTP request target with static suffix on authenticated route".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: m.as_str().trim().to_owned(),
                        interpretation: "A sensitive route in request-target can be misclassified as cacheable static content".into(),
                        offset: m.start(),
                        property: "Cache key derivation should classify authenticated routes before extension-based caching".into(),
                    }],
                });
            }
        }

        // Cache key normalization bypass via encoded separators / null bytes in routes
        static CACHE_KEY_NORMALIZATION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r"(?i)/(?:api|account|profile|users?|v[0-9]+)[^?\s\r\n]{0,180}(?:%00|%2500|%2f|%252f|%5c|%255c|%2e|%252e)[^?\s\r\n]{0,120}").unwrap()
            },
        );
        if let Some(m) = CACHE_KEY_NORMALIZATION_RE.find(&low) {
            dets.push(L2Detection {
                detection_type: "cache_key_normalization_bypass".into(),
                confidence: 0.90,
                detail: "Encoded path component can desynchronize cache key normalization from origin routing".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Encoded delimiters/nulls may be canonicalized differently by cache and origin".into(),
                    offset: m.start(),
                    property: "Cache keys must use identical canonicalization rules as origin path parsing".into(),
                }],
            });
        }
        static CACHE_KEY_NORMALIZATION_RAW_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?i)(?:^|[\s"'])/(?:api|account|profile|users?|v[0-9]+)[^ \r\n?]{0,180}(?:%00|%2500|%2f|%252f|%5c|%255c|%2e|%252e)[^ \r\n?]{0,120}(?:\s|$)"#).unwrap()
            });
        static CACHE_KEY_NORMALIZATION_NUL_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(
                    r"(?is)/(?:api|account|profile|users?|v[0-9]+)[^\r\n]{0,120}\x00[^\r\n]{0,120}",
                )
                .unwrap()
            });
        if dets
            .iter()
            .all(|d| d.detection_type != "cache_key_normalization_bypass")
        {
            if let Some(m) = CACHE_KEY_NORMALIZATION_RAW_RE.find(input) {
                dets.push(L2Detection {
                    detection_type: "cache_key_normalization_bypass".into(),
                    confidence: 0.91,
                    detail: "Encoded request-target normalization can desynchronize cache and origin keying".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: m.as_str().trim().to_owned(),
                        interpretation: "Raw encoded separators/null bytes may hash differently in edge cache and origin".into(),
                        offset: m.start(),
                        property: "Raw request-target must be canonicalized consistently across all cache layers".into(),
                    }],
                });
            } else if let Some(m) = CACHE_KEY_NORMALIZATION_NUL_RE.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "cache_key_normalization_bypass".into(),
                    confidence: 0.90,
                    detail: "Decoded NUL byte in path indicates cache key normalization bypass attempt".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Post-decoding NUL bytes can truncate or alter key computation in intermediaries".into(),
                        offset: m.start(),
                        property: "Reject control bytes in request paths before key generation".into(),
                    }],
                });
            }
        }

        // Vary manipulation with attacker-controlled or high-cardinality headers
        static VARY_MANIPULATION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*Vary\s*:\s*[^\r\n]*(?:Accept-Language|X-Forwarded-Host|X-Original-URL)[^\r\n]*").unwrap()
        });
        static VARY_MANIP_INPUT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*(?:Accept-Language\s*:\s*[^\r\n]{12,}|X-Forwarded-Host\s*:\s*[^\r\n]+|X-Original-URL\s*:\s*[^\r\n]+)").unwrap()
        });
        if let Some(vary) = VARY_MANIPULATION_RE.find(&decoded) {
            if let Some(hdr) = VARY_MANIP_INPUT_RE.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "vary_header_manipulation".into(),
                    confidence: 0.88,
                    detail: "Vary includes manipulable cache-key components supplied by request headers".into(),
                    position: vary.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: format!("{} | {}", vary.as_str().trim(), hdr.as_str().trim()),
                        interpretation: "Attacker-controlled/high-cardinality headers in Vary can poison or fragment cache variants".into(),
                        offset: vary.start(),
                        property: "Vary should avoid untrusted headers and enforce strict normalization/cardinality limits".into(),
                    }],
                });
            }
        }

        // CDN IP segmentation abuse via spoofed client-IP headers
        static CDN_IP_HEADER_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*(CF-Connecting-IP|X-Real-IP|Fastly-Client-IP)\s*:\s*([^\r\n]+)")
                .unwrap()
        });
        static CDN_IP_SPOOF_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:,|%0a|%0d|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|localhost|::1)").unwrap()
        });
        for caps in CDN_IP_HEADER_RE.captures_iter(&decoded) {
            let full = match caps.get(0) {
                Some(m) => m,
                None => continue,
            };
            let value = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            if CDN_IP_SPOOF_RE.is_match(value) {
                dets.push(L2Detection {
                    detection_type: "cdn_ip_header_injection".into(),
                    confidence: 0.89,
                    detail: "Spoofable CDN client-IP header can create attacker-controlled cache segmentation".into(),
                    position: full.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: full.as_str().to_owned(),
                        interpretation: "Client-IP override headers may be trusted for cache sharding despite user control".into(),
                        offset: full.start(),
                        property: "Only edge-injected client-IP headers should influence cache key segmentation".into(),
                    }],
                });
            }
        }

        // HTTP response splitting payloads targeting cached headers
        static RESPONSE_SPLIT_ENCODED_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(
                    r"(?i)%0d%0a\s*(?:set-cookie|location)\s*:|%0a\s*(?:set-cookie|location)\s*:",
                )
                .unwrap()
            });
        static RESPONSE_SPLIT_DECODED_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r"(?is)(?:x-forwarded-host|x-original-url|x-rewrite-url|x-host|referer|user-agent)\s*:[^\r\n]*(?:\r\n|\n)\s*(?:set-cookie|location)\s*:").unwrap()
            },
        );
        if let Some(m) = RESPONSE_SPLIT_ENCODED_RE.find(&low) {
            dets.push(L2Detection {
                detection_type: "cache_response_splitting".into(),
                confidence: 0.94,
                detail: "Encoded CRLF sequence can inject cache-poisoning response headers".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Injected CRLF can append Set-Cookie/Location to cached responses".into(),
                    offset: m.start(),
                    property:
                        "All header values must reject CR/LF and encoded CRLF before cache storage"
                            .into(),
                }],
            });
        } else if let Some(m) = RESPONSE_SPLIT_DECODED_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cache_response_splitting".into(),
                confidence: 0.92,
                detail: "Header value newline injection indicates response-splitting cache poisoning attempt".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Header boundary confusion can poison shared cache metadata/redirects".into(),
                    offset: m.start(),
                    property: "Cache-facing header parsers must enforce single-line header values".into(),
                }],
            });
        }

        // Cache key confusion with repeated Host/X-Forwarded-Host authorities
        static MULTI_HOST_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^\s*(Host|X-Forwarded-Host)\s*:\s*([^\r\n]+)").unwrap()
        });
        let mut host_count = 0usize;
        let mut xfh_count = 0usize;
        let mut host_lines: Vec<String> = Vec::new();
        for caps in MULTI_HOST_KEY_RE.captures_iter(&decoded) {
            let header_name = caps
                .get(1)
                .map(|m| m.as_str().to_ascii_lowercase())
                .unwrap_or_default();
            if header_name == "host" {
                host_count += 1;
            } else if header_name == "x-forwarded-host" {
                xfh_count += 1;
            }
            if let Some(line) = caps.get(0) {
                host_lines.push(line.as_str().trim().to_owned());
            }
        }
        if host_count > 1 || xfh_count > 1 {
            let offset = MULTI_HOST_KEY_RE
                .find(&decoded)
                .map(|m| m.start())
                .unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "cache_key_confusion_multi_host".into(),
                confidence: 0.93,
                detail: "Multiple Host/X-Forwarded-Host headers can desynchronize cache and origin key computation".into(),
                position: offset,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: host_lines.join(" | "),
                    interpretation: "Duplicate authority headers let intermediaries pick different host values".into(),
                    offset,
                    property: "Requests with repeated host authority headers should be rejected before cache lookup".into(),
                }],
            });
        }

        // Fat GET cache poisoning
        static FAT_GET_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^GET\s+[^\r\n]+\s+HTTP/\d\.\d\r?\n(?:[^\r\n]+\r?\n)*Content-Length\s*:\s*[1-9]\d*").unwrap()
        });
        if let Some(m) = FAT_GET_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cache_fat_get_body".into(),
                confidence: 0.87,
                detail: "Fat GET request with Content-Length body indicating potential cache poisoning".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Fat GET requests (GET with Content-Length body) are rejected by some servers but accepted by CDN cache. If the cache stores the body-influenced response and the backend ignores the body, different content is served to cached vs uncached requests, enabling cache poisoning".into(),
                    offset: m.start(),
                    property: "GET requests must not contain Content-Length or body content. Reject or strip body from GET requests at the proxy/CDN layer".into(),
                }],
            });
        }

        // X-Original-URL override
        static X_ORIGINAL_URL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)^X-Original-URL\s*:\s*(/[^\r\n]+)").unwrap()
        });
        if let Some(m) = X_ORIGINAL_URL_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cache_x_original_url_override".into(),
                confidence: 0.89,
                detail: "X-Original-URL header overrides request path".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "X-Original-URL and X-Rewrite-URL headers override the request path in many reverse proxies (Nginx, IIS). An attacker can supply X-Original-URL: /admin to access restricted paths while the cache key uses the original harmless URL, enabling cache poisoning of admin responses onto public cache entries".into(),
                    offset: m.start(),
                    property: "X-Original-URL and X-Rewrite-URL headers must only be accepted from trusted internal reverse proxies. Validate against expected internal IP ranges".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        if matches!(
            detection_type,
            "cache_key_normalization_bypass"
                | "vary_header_manipulation"
                | "cdn_ip_header_injection"
                | "cache_response_splitting"
                | "cache_key_confusion_multi_host"
                | "cache_fat_get_body"
                | "cache_x_original_url_override"
        ) {
            return Some(InvariantClass::CachePoisoning);
        }
        if matches!(detection_type, "web_cache_deception_path_confusion") {
            return Some(InvariantClass::CacheDeception);
        }
        match detection_type {
            "header_key_injection"
            | "query_cloak"
            | "host_header_override"
            | "forwarded_host_poison"
            | "cache_param_cloaking"
            | "cache_vary_override" => Some(InvariantClass::CachePoisoning),
            "cache_deception" | "cache_path_confusion" | "auth_cacheable_response" => {
                Some(InvariantClass::CacheDeception)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unkeyed_header_cache_key_injection() {
        let results = crate::evaluators::evaluate_l2(
            "GET /search?q=1 HTTP/1.1\nX-Original-URL: /admin\nX-Forwarded-Host: attacker.com\n",
        );
        assert!(
            results
                .iter()
                .any(|r| r.class == InvariantClass::CachePoisoning)
        );
    }

    #[test]
    fn detects_static_path_confusion_cache_deception() {
        let results = crate::evaluators::evaluate_l2("/static/../api/user.js?cache=1");
        assert!(
            results
                .iter()
                .any(|r| r.class == InvariantClass::CacheDeception)
        );
    }

    #[test]
    fn detects_host_header_override_poisoning() {
        let eval = CacheEvaluator;
        let dets = eval.detect(
            "GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-Host: attacker.example\r\n\r\n",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "host_header_override")
        );
        assert_eq!(
            eval.map_class("host_header_override"),
            Some(InvariantClass::CachePoisoning)
        );
    }

    #[test]
    fn detects_semicolon_parameter_cloaking() {
        let eval = CacheEvaluator;
        let dets = eval.detect("/products?item=1;admin=true&view=public");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cache_param_cloaking")
        );
    }

    #[test]
    fn detects_cacheable_authenticated_context() {
        let eval = CacheEvaluator;
        let dets = eval.detect(
            "GET /account HTTP/1.1\r\nAuthorization: Bearer token\r\nCache-Control: public, max-age=600\r\n\r\n",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "auth_cacheable_response")
        );
        assert_eq!(
            eval.map_class("auth_cacheable_response"),
            Some(InvariantClass::CacheDeception)
        );
    }

    #[test]
    fn detects_web_cache_deception_nonexistent_css_on_authenticated_path() {
        let eval = CacheEvaluator;
        let dets = eval
            .detect("GET /account/profile/nonexistent.css HTTP/1.1\r\nHost: app.example\r\n\r\n");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "web_cache_deception_path_confusion")
        );
        assert_eq!(
            eval.map_class("web_cache_deception_path_confusion"),
            Some(InvariantClass::CacheDeception)
        );
    }

    #[test]
    fn detects_cache_key_normalization_bypass_with_null_byte_encoding() {
        let eval = CacheEvaluator;
        let dets = eval.detect("GET /api/v1/users%00 HTTP/1.1\r\nHost: app.example\r\n\r\n");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cache_key_normalization_bypass")
        );
        assert_eq!(
            eval.map_class("cache_key_normalization_bypass"),
            Some(InvariantClass::CachePoisoning)
        );
    }

    #[test]
    fn detects_vary_header_manipulation_with_accept_language_and_xfh() {
        let eval = CacheEvaluator;
        let dets = eval.detect(
            "HTTP/1.1 200 OK\r\nVary: Accept-Language, X-Forwarded-Host\r\nAccept-Language: en-US,en;q=0.9,zz-ZZ;q=0.8\r\nX-Forwarded-Host: attacker.example\r\n\r\n",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "vary_header_manipulation")
        );
    }

    #[test]
    fn detects_cdn_client_ip_header_injection() {
        let eval = CacheEvaluator;
        let dets = eval.detect(
            "GET / HTTP/1.1\r\nHost: app.example\r\nCF-Connecting-IP: 127.0.0.1, 8.8.8.8\r\n\r\n",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cdn_ip_header_injection")
        );
    }

    #[test]
    fn detects_cache_response_splitting_set_cookie_payload() {
        let eval = CacheEvaluator;
        let dets = eval.detect(
            "GET / HTTP/1.1\r\nHost: app.example\r\nX-Forwarded-Host: attacker.example%0d%0aSet-Cookie: cachepwn=1\r\n\r\n",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cache_response_splitting")
        );
    }

    #[test]
    fn detects_cache_response_splitting_location_payload() {
        let eval = CacheEvaluator;
        let dets = eval.detect(
            "GET / HTTP/1.1\r\nHost: app.example\r\nX-Original-URL: /ok\r\nLocation: /safe\r\nUser-Agent: ok%0d%0aLocation: https://evil.example\r\n\r\n",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cache_response_splitting")
        );
    }

    #[test]
    fn detects_cache_key_confusion_with_multiple_host_headers() {
        let eval = CacheEvaluator;
        let dets = eval.detect(
            "GET / HTTP/1.1\r\nHost: app.example\r\nHost: attacker.example\r\nX-Forwarded-Host: app.example\r\n\r\n",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cache_key_confusion_multi_host")
        );
        assert_eq!(
            eval.map_class("cache_key_confusion_multi_host"),
            Some(InvariantClass::CachePoisoning)
        );
    }

    #[test]
    fn detects_cache_fat_get_body() {
        let eval = CacheEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nbody123456");
        assert!(dets.iter().any(|d| d.detection_type == "cache_fat_get_body"));
        assert_eq!(eval.map_class("cache_fat_get_body"), Some(InvariantClass::CachePoisoning));
    }

    #[test]
    fn detects_cache_x_original_url_override() {
        let eval = CacheEvaluator;
        let dets = eval.detect("GET /safe HTTP/1.1\r\nHost: example.com\r\nX-Original-URL: /admin\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "cache_x_original_url_override"));
        assert_eq!(eval.map_class("cache_x_original_url_override"), Some(InvariantClass::CachePoisoning));
    }
}
