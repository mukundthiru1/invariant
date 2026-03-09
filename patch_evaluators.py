import re

def update_http_smuggle():
    with open("packages/engine-rs/src/evaluators/http_smuggle.rs", "r") as f:
        content = f.read()

    new_detect = """
        if let Some(det) = detect_smuggle_h2_status_pseudo(&decoded) {
            dets.push(det);
        }

        self.detect_new_smuggle_types(&decoded, &mut dets);

        dets
"""
    content = content.replace("        dets
    }

    fn map_class", new_detect + "    }

    fn map_class")

    new_func = """
    fn detect_new_smuggle_types(&self, decoded: &str, dets: &mut Vec<L2Detection>) {
        // 1. smuggle_chunk_size_overflow
        static CHUNK_SIZE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?im)^([0-9a-fA-F]+)\s*$").unwrap());
        if let Some(pos) = decoded.find("

") {
            let body = &decoded[pos+4..];
            for line_raw in body.split('
') {
                let line = line_raw.trim_end_matches('');
                let size_raw = line.split(';').next().unwrap_or("").trim();
                if !size_raw.is_empty() && size_raw.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Ok(val) = u64::from_str_radix(size_raw, 16) {
                        if val > 0xFFFF {
                            dets.push(L2Detection {
                                detection_type: "smuggle_chunk_size_overflow".into(),
                                confidence: 0.88,
                                detail: "Oversized chunk size in chunked encoding (> 0xFFFF)".into(),
                                position: pos,
                                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: size_raw.to_owned(), interpretation: "Chunk size overflow".into(), offset: pos, property: "Max 0xFFFF".into() }]
                            });
                            break;
                        }
                    }
                }
            }
        }

        // 2. smuggle_te_priority_override
        static HAS_CL_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)
content-length\s*:").unwrap());
        static HAS_TE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)
transfer-encoding\s*:").unwrap());
        if let (Some(cl), Some(te)) = (HAS_CL_RE.find(decoded), HAS_TE_RE.find(decoded)) {
            if cl.start() < te.start() {
                dets.push(L2Detection {
                    detection_type: "smuggle_te_priority_override".into(),
                    confidence: 0.90,
                    detail: "Transfer-Encoding header appears after Content-Length in same request".into(),
                    position: te.start(),
                    evidence: vec![ProofEvidence { operation: EvidenceOperation::ContextEscape, matched_input: "TE after CL".into(), interpretation: "TE priority exploit".into(), offset: te.start(), property: "TE should not follow CL".into() }]
                });
            }
        }

        // 3. smuggle_h2_header_inject
        static H2_PSEUDO_INJ_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?im)^[a-zA-Z0-9-]+:\s*:(?:method|path|authority|scheme)").unwrap());
        if let Some(m) = H2_PSEUDO_INJ_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "smuggle_h2_header_inject".into(),
                confidence: 0.87,
                detail: "HTTP/2 pseudo-header injection via header value".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::ContextEscape, matched_input: m.as_str().to_owned(), interpretation: "H2 pseudo header inject".into(), offset: m.start(), property: "No pseudo headers in values".into() }]
            });
        }

        // 4. smuggle_whitespace_before_colon
        static WS_BEFORE_COLON_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?im)^[a-zA-Z0-9-]+[ 	]+:").unwrap());
        if let Some(m) = WS_BEFORE_COLON_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "smuggle_whitespace_before_colon".into(),
                confidence: 0.85,
                detail: "Whitespace before colon in header name".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::ContextEscape, matched_input: m.as_str().to_owned(), interpretation: "Whitespace before colon".into(), offset: m.start(), property: "No whitespace before colon".into() }]
            });
        }

        // 5. smuggle_pipeline_bypass
        static GET_IN_BODY_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?m)^(?:GET|POST|PUT|DELETE)\s+/[^\s]*\s+HTTP/1\.[01]").unwrap());
        if let Some(pos) = decoded.find("

") {
            let body = &decoded[pos+4..];
            if let Some(m) = GET_IN_BODY_RE.find(body) {
                dets.push(L2Detection {
                    detection_type: "smuggle_pipeline_bypass".into(),
                    confidence: 0.89,
                    detail: "HTTP pipelining with second request smuggled in body".into(),
                    position: pos + 4 + m.start(),
                    evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "Smuggled pipeline request".into(), offset: pos + 4 + m.start(), property: "No requests in body".into() }]
                });
            }
        }
    }
"""
    content = content.replace("fn map_class", new_func + "
    fn map_class")

    content = content.replace(
        '"cl_te_desync" | "te_cl_desync" => Some(InvariantClass::HttpSmuggleClTe),',
        '"cl_te_desync" | "te_cl_desync" | "smuggle_chunk_size_overflow" | "smuggle_te_priority_override" | "smuggle_h2_header_inject" | "smuggle_whitespace_before_colon" | "smuggle_pipeline_bypass" => Some(InvariantClass::HttpSmuggleClTe),'
    )

    tests_to_add = """
    #[test]
    fn test_smuggle_chunk_size_overflow() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
Transfer-Encoding: chunked

100000
").iter().any(|d| d.detection_type == "smuggle_chunk_size_overflow"));
        assert!(eval.detect("POST / HTTP/1.1
Transfer-Encoding: chunked

FFFFF
").iter().any(|d| d.detection_type == "smuggle_chunk_size_overflow"));
        assert!(!eval.detect("POST / HTTP/1.1
Transfer-Encoding: chunked

100
").iter().any(|d| d.detection_type == "smuggle_chunk_size_overflow"));
    }

    #[test]
    fn test_smuggle_te_priority_override() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
Content-Length: 10
Transfer-Encoding: chunked

").iter().any(|d| d.detection_type == "smuggle_te_priority_override"));
        assert!(eval.detect("POST / HTTP/1.1
Content-Length: 5
Transfer-Encoding: gzip

").iter().any(|d| d.detection_type == "smuggle_te_priority_override"));
        assert!(!eval.detect("POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 10

").iter().any(|d| d.detection_type == "smuggle_te_priority_override"));
    }

    #[test]
    fn test_smuggle_h2_header_inject() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
x-inject: :method GET

").iter().any(|d| d.detection_type == "smuggle_h2_header_inject"));
        assert!(eval.detect("POST / HTTP/1.1
x-inject: :path /admin

").iter().any(|d| d.detection_type == "smuggle_h2_header_inject"));
        assert!(!eval.detect("POST / HTTP/1.1
Host: example.com

").iter().any(|d| d.detection_type == "smuggle_h2_header_inject"));
    }

    #[test]
    fn test_smuggle_whitespace_before_colon() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
Host : example.com

").iter().any(|d| d.detection_type == "smuggle_whitespace_before_colon"));
        assert!(eval.detect("POST / HTTP/1.1
Transfer-Encoding	: chunked

").iter().any(|d| d.detection_type == "smuggle_whitespace_before_colon"));
        assert!(!eval.detect("POST / HTTP/1.1
Host: example.com

").iter().any(|d| d.detection_type == "smuggle_whitespace_before_colon"));
    }

    #[test]
    fn test_smuggle_pipeline_bypass() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
Content-Length: 100

GET /admin HTTP/1.1
Host: abc

").iter().any(|d| d.detection_type == "smuggle_pipeline_bypass"));
        assert!(eval.detect("POST / HTTP/1.1
Content-Length: 100

POST /admin HTTP/1.0
").iter().any(|d| d.detection_type == "smuggle_pipeline_bypass"));
        assert!(!eval.detect("POST / HTTP/1.1
Content-Length: 10

hello GET").iter().any(|d| d.detection_type == "smuggle_pipeline_bypass"));
    }
}
"""
    last_brace = content.rfind("}")
    content = content[:last_brace] + tests_to_add + content[last_brace+1:]

    with open("packages/engine-rs/src/evaluators/http_smuggle.rs", "w") as f:
        f.write(content)

def update_ssrf():
    with open("packages/engine-rs/src/evaluators/ssrf.rs", "r") as f:
        content = f.read()
    
    new_detect = """
        detect_redirect_chain_targets(&decoded, &mut dets);
        self.detect_new_ssrf_types(&decoded, &mut dets);

        dets
"""
    content = content.replace("detect_redirect_chain_targets(&decoded, &mut dets);

        dets
    }

    fn map_class", new_detect + "    }

    fn map_class")

    new_func = """
    fn detect_new_ssrf_types(&self, decoded: &str, dets: &mut Vec<L2Detection>) {
        // 1. ssrf_ipv6_bypass
        static IPV6_BYPASS_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)\[::1\]|\[::ffff:127\.0\.0\.1\]|\[0:0:0:0:0:ffff:7f00:1\]").unwrap());
        if let Some(m) = IPV6_BYPASS_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_ipv6_bypass".into(),
                confidence: 0.90,
                detail: "IPv6 representation used to bypass IP blocklists".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "IPv6 bypass".into(), offset: m.start(), property: "Filter IPV6".into() }]
            });
        }

        // 2. ssrf_decimal_ip
        static DECIMAL_IP_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)://(?:2130706433|0x7f000001)(?:/|:|$)").unwrap());
        if let Some(m) = DECIMAL_IP_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_decimal_ip".into(),
                confidence: 0.88,
                detail: "Decimal-encoded IP addresses".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "Decimal IP".into(), offset: m.start(), property: "Filter Decimal IP".into() }]
            });
        }

        // 3. ssrf_cname_chain
        static CNAME_CHAIN_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)://[a-zA-Z0-9-]+\.attacker\.com").unwrap());
        if let Some(m) = CNAME_CHAIN_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_cname_chain".into(),
                confidence: 0.80,
                detail: "CNAME chain bypass pattern".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "CNAME chain".into(), offset: m.start(), property: "Resolve CNAME".into() }]
            });
        }

        // 4. ssrf_file_scheme
        static FILE_SCHEME_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)file://").unwrap());
        if let Some(m) = FILE_SCHEME_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_file_scheme".into(),
                confidence: 0.93,
                detail: "file:// scheme in URLs used to read local files".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::ContextEscape, matched_input: m.as_str().to_owned(), interpretation: "file:// scheme".into(), offset: m.start(), property: "No file://".into() }]
            });
        }

        // 5. ssrf_gopher_scheme
        static GOPHER_SCHEME_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)gopher://").unwrap());
        if let Some(m) = GOPHER_SCHEME_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_gopher_scheme".into(),
                confidence: 0.92,
                detail: "gopher:// protocol used for port scanning".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::ContextEscape, matched_input: m.as_str().to_owned(), interpretation: "gopher:// scheme".into(), offset: m.start(), property: "No gopher://".into() }]
            });
        }
    }
"""
    content = content.replace("fn map_class", new_func + "
    fn map_class")
    
    content = content.replace(
        '"protocol_smuggle" => Some(InvariantClass::SsrfProtocolSmuggle),',
        '"protocol_smuggle" | "ssrf_ipv6_bypass" | "ssrf_decimal_ip" | "ssrf_cname_chain" | "ssrf_file_scheme" | "ssrf_gopher_scheme" => Some(InvariantClass::SsrfProtocolSmuggle),'
    )

    tests_to_add = """
    #[test]
    fn test_ssrf_ipv6_bypass() {
        let eval = SsrfEvaluator;
        assert!(eval.detect("http://[::1]/").iter().any(|d| d.detection_type == "ssrf_ipv6_bypass"));
        assert!(eval.detect("http://[::ffff:127.0.0.1]/").iter().any(|d| d.detection_type == "ssrf_ipv6_bypass"));
        assert!(!eval.detect("http://[2001:db8::1]/").iter().any(|d| d.detection_type == "ssrf_ipv6_bypass"));
    }

    #[test]
    fn test_ssrf_decimal_ip() {
        let eval = SsrfEvaluator;
        assert!(eval.detect("http://2130706433/").iter().any(|d| d.detection_type == "ssrf_decimal_ip"));
        assert!(eval.detect("http://0x7f000001/").iter().any(|d| d.detection_type == "ssrf_decimal_ip"));
        assert!(!eval.detect("http://example.com/").iter().any(|d| d.detection_type == "ssrf_decimal_ip"));
    }

    #[test]
    fn test_ssrf_cname_chain() {
        let eval = SsrfEvaluator;
        assert!(eval.detect("http://test.attacker.com/").iter().any(|d| d.detection_type == "ssrf_cname_chain"));
        assert!(eval.detect("http://sub.attacker.com/").iter().any(|d| d.detection_type == "ssrf_cname_chain"));
        assert!(!eval.detect("http://example.com/").iter().any(|d| d.detection_type == "ssrf_cname_chain"));
    }

    #[test]
    fn test_ssrf_file_scheme() {
        let eval = SsrfEvaluator;
        assert!(eval.detect("file:///etc/passwd").iter().any(|d| d.detection_type == "ssrf_file_scheme"));
        assert!(eval.detect("FILE:///C:/windows/win.ini").iter().any(|d| d.detection_type == "ssrf_file_scheme"));
        assert!(!eval.detect("http://example.com/").iter().any(|d| d.detection_type == "ssrf_file_scheme"));
    }

    #[test]
    fn test_ssrf_gopher_scheme() {
        let eval = SsrfEvaluator;
        assert!(eval.detect("gopher://127.0.0.1:6379/_").iter().any(|d| d.detection_type == "ssrf_gopher_scheme"));
        assert!(eval.detect("GOPHER://10.0.0.1:25/_").iter().any(|d| d.detection_type == "ssrf_gopher_scheme"));
        assert!(!eval.detect("http://example.com/").iter().any(|d| d.detection_type == "ssrf_gopher_scheme"));
    }
}
"""
    last_brace = content.rfind("}")
    content = content[:last_brace] + tests_to_add + content[last_brace+1:]
    
    with open("packages/engine-rs/src/evaluators/ssrf.rs", "w") as f:
        f.write(content)

def update_upload():
    with open("packages/engine-rs/src/evaluators/upload.rs", "r") as f:
        content = f.read()

    new_detect = """
        self.detect_new_upload_types(&decoded, &lower, &mut dets);

        dets
"""
    content = content.replace("        dets
    }

    fn map_class", new_detect + "    }

    fn map_class")

    new_func = """
    fn detect_new_upload_types(&self, decoded: &str, lower: &str, dets: &mut Vec<L2Detection>) {
        // 1. upload_php_in_image
        static PHP_IN_IMAGE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?is)(?:\x{00ff}\x{00d8}\x{00ff}|GIF8[79]a|\x{0089}PNG).*?<\?php").unwrap());
        if let Some(m) = PHP_IN_IMAGE_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "upload_php_in_image".into(),
                confidence: 0.92,
                detail: "PHP code injected into image files".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str()[..std::cmp::min(100, m.as_str().len())].to_owned(), interpretation: "PHP inside image".into(), offset: m.start(), property: "Images must not contain PHP code".into() }]
            });
        }

        // 2. upload_double_extension
        static DOUBLE_EXT_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)filename\s*=\s*.*?\.([a-zA-Z0-9]+)\.(jpg|jpeg|png|gif)\b").unwrap());
        if let Some(caps) = DOUBLE_EXT_RE.captures(decoded) {
            if let Some(ext1) = caps.get(1) {
                let e1 = format!(".{}", ext1.as_str().to_lowercase());
                if EXECUTABLE_EXTENSIONS.contains(&e1.as_str()) {
                    dets.push(L2Detection {
                        detection_type: "upload_double_extension".into(),
                        confidence: 0.88,
                        detail: "Double extension bypass".into(),
                        position: caps.get(0).unwrap().start(),
                        evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: caps.get(0).unwrap().as_str().to_owned(), interpretation: "Double extension".into(), offset: caps.get(0).unwrap().start(), property: "Double extensions must not contain executable types".into() }]
                    });
                }
            }
        }

        // 3. upload_null_byte_extension
        static NULL_BYTE_EXT_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)filename\s*=\s*.*?\.([a-zA-Z0-9]+)(?:%00|\x00)\.(jpg|jpeg|png|gif)\b").unwrap());
        if let Some(caps) = NULL_BYTE_EXT_RE.captures(decoded) {
            if let Some(ext1) = caps.get(1) {
                let e1 = format!(".{}", ext1.as_str().to_lowercase());
                if EXECUTABLE_EXTENSIONS.contains(&e1.as_str()) {
                    dets.push(L2Detection {
                        detection_type: "upload_null_byte_extension".into(),
                        confidence: 0.91,
                        detail: "Null byte extension bypass".into(),
                        position: caps.get(0).unwrap().start(),
                        evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: caps.get(0).unwrap().as_str().to_owned(), interpretation: "Null byte extension".into(), offset: caps.get(0).unwrap().start(), property: "Null byte must not be used".into() }]
                    });
                }
            }
        }

        // 4. upload_zip_slip
        static ZIP_SLIP_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)(?:zip-entry|tar-entry|entry|name|filename)\s*[:=]\s*.*?(\.\./\.\./\.\./)").unwrap());
        if let Some(m) = ZIP_SLIP_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "upload_zip_slip".into(),
                confidence: 0.90,
                detail: "Zip slip path traversal in archive entry names".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::ContextEscape, matched_input: m.as_str().to_owned(), interpretation: "Zip slip".into(), offset: m.start(), property: "Archive entry names must not contain path traversal".into() }]
            });
        }

        // 5. upload_svg_xss
        static SVG_XSS_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)<svg[^>]*>.*?(?:<script|onload=)").unwrap());
        if let Some(m) = SVG_XSS_RE.find(decoded) {
            dets.push(L2Detection {
                detection_type: "upload_svg_xss".into(),
                confidence: 0.89,
                detail: "SVG file uploads containing script tags or onload handlers".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str()[..std::cmp::min(100, m.as_str().len())].to_owned(), interpretation: "SVG XSS vector".into(), offset: m.start(), property: "SVGs must not contain XSS payloads".into() }]
            });
        }
    }
"""
    content = content.replace("fn map_class", new_func + "
    fn map_class")

    content = content.replace(
        '"upload_multipart_boundary_inject" => Some(InvariantClass::MaliciousUpload),',
        '"upload_multipart_boundary_inject" | "upload_php_in_image" | "upload_null_byte_extension" => Some(InvariantClass::MaliciousUpload),'
    )

    tests_to_add = """
    #[test]
    fn test_upload_php_in_image() {
        let eval = UploadEvaluator;
        assert!(eval.detect("GIF89a...<?php info(); ?>").iter().any(|d| d.detection_type == "upload_php_in_image"));
        assert!(eval.detect("\u{0089}PNG...<?php ?>").iter().any(|d| d.detection_type == "upload_php_in_image"));
        assert!(!eval.detect("GIF89a...plain image data").iter().any(|d| d.detection_type == "upload_php_in_image"));
    }

    #[test]
    fn test_upload_double_extension_specific() {
        let eval = UploadEvaluator;
        assert!(eval.detect("filename=shell.php.jpg").iter().any(|d| d.detection_type == "upload_double_extension" && d.confidence == 0.88));
        assert!(eval.detect("filename=evil.asp.png").iter().any(|d| d.detection_type == "upload_double_extension" && d.confidence == 0.88));
        assert!(!eval.detect("filename=photo.jpg").iter().any(|d| d.detection_type == "upload_double_extension" && d.confidence == 0.88));
    }

    #[test]
    fn test_upload_null_byte_extension() {
        let eval = UploadEvaluator;
        assert!(eval.detect("filename=file.php%00.jpg").iter().any(|d| d.detection_type == "upload_null_byte_extension"));
        assert!(eval.detect("filename=shell.php\0.png").iter().any(|d| d.detection_type == "upload_null_byte_extension"));
        assert!(!eval.detect("filename=photo.jpg").iter().any(|d| d.detection_type == "upload_null_byte_extension"));
    }

    #[test]
    fn test_upload_zip_slip_specific() {
        let eval = UploadEvaluator;
        assert!(eval.detect("zip-entry=../../../etc/passwd").iter().any(|d| d.detection_type == "upload_zip_slip" && d.confidence == 0.90));
        assert!(eval.detect("filename=../../../etc/shadow").iter().any(|d| d.detection_type == "upload_zip_slip" && d.confidence == 0.90));
        assert!(!eval.detect("filename=images/photo.jpg").iter().any(|d| d.detection_type == "upload_zip_slip" && d.confidence == 0.90));
    }

    #[test]
    fn test_upload_svg_xss_specific() {
        let eval = UploadEvaluator;
        assert!(eval.detect("<svg><script>alert(1)</script></svg>").iter().any(|d| d.detection_type == "upload_svg_xss" && d.confidence == 0.89));
        assert!(eval.detect("<svg onload=alert(1)></svg>").iter().any(|d| d.detection_type == "upload_svg_xss" && d.confidence == 0.89));
        assert!(!eval.detect("<svg><rect></rect></svg>").iter().any(|d| d.detection_type == "upload_svg_xss" && d.confidence == 0.89));
    }
}
"""
    last_brace = content.rfind("}")
    content = content[:last_brace] + tests_to_add + content[last_brace+1:]
    
    with open("packages/engine-rs/src/evaluators/upload.rs", "w") as f:
        f.write(content)

if __name__ == "__main__":
    update_http_smuggle()
    update_ssrf()
    update_upload()
