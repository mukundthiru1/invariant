//! SSRF Evaluator — Level 2 Invariant Detection
//!
//! Invariant property:
//!   resolve(parse(input, URL_GRAMMAR)).host NOT IN INTERNAL_RANGES
//!   AND NOT cloud metadata IP/hostname
//!   AND protocol NOT IN NON_HTTP_PROTOCOLS
//!
//! Key advantage over regex: resolves ALL numeric IP representations
//! (hex, octal, decimal integer, compressed, IPv4-mapped IPv6) to
//! canonical form before range checking.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};

const CLOUD_METADATA_IPS: &[&str] = &["169.254.169.254", "100.100.100.200", "169.254.170.2"];

const CLOUD_METADATA_HOSTNAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "metadata.azure.internal",
    "metadata.azure.com",
    "metadata.azure.com.",
    "metadata.google.internal.",
    "metadata.digitalocean.com",
    "metadata.digitalocean.com.",
];

const AWS_IMDSV2_TOKEN_PATH: &str = "/latest/api/token";
const AWS_IMDSV2_TOKEN_HEADER: &str = "x-aws-ec2-metadata-token-ttl-seconds";
const DIGITAL_OCEAN_METADATA_PREFIX: &str = "/metadata/v1/";
const GCP_METADATA_FLAVOR_HEADER: &str = "metadata-flavor";
const GCP_METADATA_FLAVOR_VALUE: &str = "google";
const KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";

const CLOUD_METADATA_PATHS: &[&str] = &[
    "/latest/meta-data",
    "/metadata/instance",
    "/metadata/identity",
    "/metadata/v1",
    "/metadata/instance?",
    "/metadata/instance/compute/",
    "/computeMetadata/v1",
    "/openstack/latest/meta_data.json",
    "/opc/v1/",
    "/opc/v2/",
    "api-version=",
];

const DNS_REBINDING_SUFFIXES: &[&str] = &[".nip.io", ".xip.io", ".sslip.io", ".dnsfor.work"];

const URL_SHORTENER_DOMAINS: &[&str] = &["bit.ly", "t.co", "tinyurl.com", "is.gd"];

const DANGEROUS_PROTOCOLS: &[&str] = &[
    "file:", "gopher:", "dict:", "ftp:", "ldap:", "ldaps:", "tftp:", "sftp:", "jar:", "netdoc:",
    "phar:", "expect:", "glob:", "data:", "php:",
];

#[derive(Clone)]
struct HttpRequestLine {
    method: String,
    target: String,
}

struct IpRange {
    start: u32,
    end: u32,
    label: &'static str,
}

fn ip4_to_num(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

fn ip_num_to_string(num: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (num >> 24) & 0xFF,
        (num >> 16) & 0xFF,
        (num >> 8) & 0xFF,
        num & 0xFF
    )
}

fn internal_ranges() -> &'static [IpRange] {
    static RANGES: std::sync::LazyLock<Vec<IpRange>> = std::sync::LazyLock::new(|| {
        vec![
            IpRange {
                start: ip4_to_num(10, 0, 0, 0),
                end: ip4_to_num(10, 255, 255, 255),
                label: "RFC1918 10/8",
            },
            IpRange {
                start: ip4_to_num(172, 16, 0, 0),
                end: ip4_to_num(172, 31, 255, 255),
                label: "RFC1918 172.16/12",
            },
            IpRange {
                start: ip4_to_num(192, 168, 0, 0),
                end: ip4_to_num(192, 168, 255, 255),
                label: "RFC1918 192.168/16",
            },
            IpRange {
                start: ip4_to_num(127, 0, 0, 0),
                end: ip4_to_num(127, 255, 255, 255),
                label: "Loopback 127/8",
            },
            IpRange {
                start: ip4_to_num(0, 0, 0, 0),
                end: ip4_to_num(0, 255, 255, 255),
                label: "This network 0/8",
            },
            IpRange {
                start: ip4_to_num(169, 254, 0, 0),
                end: ip4_to_num(169, 254, 255, 255),
                label: "Link-local 169.254/16",
            },
        ]
    });
    &RANGES
}

fn is_internal_ip(ip_num: u32) -> Option<&'static str> {
    for range in internal_ranges() {
        if ip_num >= range.start && ip_num <= range.end {
            return Some(range.label);
        }
    }
    None
}

/// Parse any numeric IP representation to canonical u32.
/// Handles: dotted decimal, hex integer, octal integer, decimal integer,
/// compressed forms (127.1), mixed radix (0x7f.0.0.1), IPv6 loopback,
/// IPv4-mapped IPv6.
fn parse_ip_representation(host: &str) -> Option<u32> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');

    // IPv6 loopback
    if h == "::1" {
        return Some(ip4_to_num(127, 0, 0, 1));
    }

    // IPv4-mapped IPv6 (including uncompressed form like 0:0:0:0:0:ffff:7f00:1)
    if let Ok(v6) = h.parse::<Ipv6Addr>() {
        if let Some(v4) = v6.to_ipv4_mapped() {
            let o = v4.octets();
            return Some(ip4_to_num(o[0], o[1], o[2], o[3]));
        }
    }

    // IPv4-mapped IPv6: ::ffff:127.0.0.1
    static v4mapped: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$").unwrap()
    });
    let h = if let Some(caps) = v4mapped.captures(h) {
        caps.get(1).unwrap().as_str().to_owned()
    } else {
        // IPv4-mapped IPv6 hex: ::ffff:7f00:0001
        static v4hex: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$").unwrap()
        });
        if let Some(caps) = v4hex.captures(h) {
            let high = u32::from_str_radix(caps.get(1).unwrap().as_str(), 16).ok()?;
            let low = u32::from_str_radix(caps.get(2).unwrap().as_str(), 16).ok()?;
            return Some((high << 16) | low);
        }
        h.to_owned()
    };
    let h = h.as_str();

    // Single integer representations
    static HEX_INT_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)^0x[0-9a-f]+$").unwrap());
    static OCT_INT_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^0[0-7]+$").unwrap());
    static DEC_INT_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^\d+$").unwrap());
    if HEX_INT_RE.is_match(h) {
        let val = u64::from_str_radix(&h[2..], 16).ok()?;
        if val <= 0xFFFFFFFF {
            return Some(val as u32);
        }
    }

    if OCT_INT_RE.is_match(h) && h.len() > 1 {
        let val = u64::from_str_radix(&h[1..], 8).ok()?;
        if val <= 0xFFFFFFFF {
            return Some(val as u32);
        }
    }

    if DEC_INT_RE.is_match(h) {
        let val: u64 = h.parse().ok()?;
        if val > 255 && val <= 0xFFFFFFFF {
            return Some(val as u32);
        }
    }

    // Dotted representation (handles mixed radix)
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() >= 1 && parts.len() <= 4 {
        let mut octets = Vec::new();
        let mut valid = true;

        for part in &parts {
            let val = if HEX_INT_RE.is_match(part) {
                u64::from_str_radix(&part[2..], 16).ok()
            } else if OCT_INT_RE.is_match(part) && part.len() > 1 {
                u64::from_str_radix(&part[1..], 8).ok()
            } else if DEC_INT_RE.is_match(part) {
                part.parse().ok()
            } else {
                valid = false;
                None
            };

            if let Some(v) = val {
                octets.push(v);
            } else if valid {
                valid = false;
            }
        }

        if valid && !octets.is_empty() {
            match octets.len() {
                4 => {
                    if octets.iter().all(|&o| o <= 255) {
                        return Some(ip4_to_num(
                            octets[0] as u8,
                            octets[1] as u8,
                            octets[2] as u8,
                            octets[3] as u8,
                        ));
                    }
                }
                3 => {
                    if octets[0] <= 255 && octets[1] <= 255 && octets[2] <= 65535 {
                        return Some(ip4_to_num(
                            octets[0] as u8,
                            octets[1] as u8,
                            ((octets[2] >> 8) & 0xFF) as u8,
                            (octets[2] & 0xFF) as u8,
                        ));
                    }
                }
                2 => {
                    if octets[0] <= 255 && octets[1] <= 16777215 {
                        return Some(ip4_to_num(
                            octets[0] as u8,
                            ((octets[1] >> 16) & 0xFF) as u8,
                            ((octets[1] >> 8) & 0xFF) as u8,
                            (octets[1] & 0xFF) as u8,
                        ));
                    }
                }
                1 => {
                    if octets[0] <= 0xFFFFFFFF {
                        return Some(octets[0] as u32);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

fn is_ipv6_internal(host: &str) -> Option<&'static str> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    let ip = h.parse::<Ipv6Addr>().ok()?;

    if let Some(v4) = ip.to_ipv4_mapped() {
        let o = v4.octets();
        if let Some(label) = is_internal_ip(ip4_to_num(o[0], o[1], o[2], o[3])) {
            return Some(label);
        }
    }

    if ip.is_loopback() {
        return Some("IPv6 loopback ::1");
    }

    if ip.is_unspecified() {
        return Some("IPv6 unspecified ::");
    }

    if ip.is_unicast_link_local() {
        return Some("IPv6 link-local fe80::/10");
    }

    if ip.is_unique_local() {
        return Some("IPv6 unique-local fc00::/7");
    }

    None
}

struct ParsedUrl {
    protocol: String,
    authority: String,
    hostname: String,
    path: String,
    has_credentials: bool,
}

fn is_url_shortener(host: &str) -> bool {
    URL_SHORTENER_DOMAINS
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{}", d)))
}

fn map_enclosed_alnum(ch: char) -> Option<String> {
    match ch {
        '\u{24D0}'..='\u{24E9}' => {
            let idx = ch as u32 - '\u{24D0}' as u32;
            Some(char::from_u32('a' as u32 + idx).unwrap().to_string())
        }
        '\u{24B6}'..='\u{24CF}' => {
            let idx = ch as u32 - '\u{24B6}' as u32;
            Some(char::from_u32('a' as u32 + idx).unwrap().to_string())
        }
        '\u{24EA}' => Some("0".to_string()),
        '\u{2460}'..='\u{2473}' => {
            let idx = ch as u32 - '\u{2460}' as u32 + 1;
            Some(idx.to_string())
        }
        '\u{2080}'..='\u{2089}' => {
            let idx = ch as u32 - '\u{2080}' as u32;
            Some(idx.to_string())
        }
        '\u{FF10}'..='\u{FF19}' => {
            let idx = ch as u32 - '\u{FF10}' as u32;
            Some(idx.to_string())
        }
        '\u{2070}' => Some("0".to_string()),
        '\u{2071}' => None,
        _ => None,
    }
}

fn normalize_enclosed_alnum(input: &str) -> (String, bool) {
    let mut out = String::with_capacity(input.len());
    let mut changed = false;
    for ch in input.chars() {
        if let Some(mapped) = map_enclosed_alnum(ch) {
            out.push_str(&mapped);
            changed = true;
        } else {
            out.push(ch);
        }
    }
    (out, changed)
}

fn normalize_unicode_dotlike_host(input: &str) -> (String, bool) {
    let mut out = String::with_capacity(input.len());
    let mut changed = false;

    for ch in input.chars() {
        match ch {
            '\u{FF0E}' | '\u{3002}' | '\u{FF61}' => {
                out.push('.');
                changed = true;
            }
            _ => {
                if let Some(mapped) = map_enclosed_alnum(ch) {
                    out.push_str(&mapped);
                    changed = true;
                } else {
                    out.push(ch);
                }
            }
        }
    }

    let lowered = out.to_lowercase();
    let changed = changed || lowered != input.to_lowercase();
    (lowered, changed)
}

fn extract_http_request_line(input: &str) -> Option<HttpRequestLine> {
    for line in input.lines() {
        let mut it = line.split_whitespace();
        let method = it.next()?;
        let target = it.next()?;
        let version = it.next()?;
        let is_request_line = matches!(
            method.to_ascii_lowercase().as_str(),
            "get" | "head" | "post" | "put" | "delete" | "connect" | "options" | "patch" | "trace"
        );

        if is_request_line && version.starts_with("HTTP/") {
            return Some(HttpRequestLine {
                method: method.to_ascii_lowercase(),
                target: target.to_owned(),
            });
        }
    }

    None
}

fn extract_header_value(input: &str, header: &str) -> Option<String> {
    let header = header.to_ascii_lowercase();
    for line in input.lines() {
        let mut it = line.splitn(2, ':');
        let raw_name = it.next()?;
        let Some(raw_value) = it.next() else {
            continue;
        };

        if raw_name.trim().to_ascii_lowercase() == header {
            return Some(raw_value.trim().to_string());
        }
    }
    None
}

fn parse_request_target_host(
    request: &HttpRequestLine,
    parsed: Option<&ParsedUrl>,
    host_header: Option<&str>,
) -> Option<String> {
    if let Some(p) = parsed {
        if !p.hostname.is_empty() {
            return Some(p.hostname.clone());
        }
    }

    if request.target.starts_with('/')
        && let Some(host) = host_header
    {
        return Some(host.to_owned());
    }

    if request.target.starts_with('/') {
        return None;
    }

    parse_url(&request.target).map(|p| p.hostname)
}

fn extract_request_path(request: &HttpRequestLine, parsed: Option<&ParsedUrl>) -> String {
    if request.target.starts_with('/') {
        return request.target.clone();
    }

    if let Some(p) = parsed {
        return p.path.clone();
    }

    "/".to_owned()
}

fn request_host_is_cloud_metadata(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };

    if CLOUD_METADATA_HOSTNAMES.contains(&host) {
        return true;
    }

    if let Some(ip_num) = parse_ip_representation(host) {
        return CLOUD_METADATA_IPS.contains(&ip_num_to_string(ip_num).as_str());
    }

    false
}

fn has_obfuscated_ipv4_notation(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if h.chars().all(|c| c.is_ascii_digit()) {
        return h.len() > 1;
    }

    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .any(|p| p.len() > 1 && p.starts_with('0') && p.chars().all(|c| c.is_ascii_digit()))
}

fn host_looks_internal_name(host: &str) -> bool {
    let h = host.to_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h == "0"
        || h.contains("internal")
        || CLOUD_METADATA_HOSTNAMES.contains(&h.as_str())
}

fn parse_low_dns_ttl_header(input: &str) -> Option<u32> {
    static TTL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?im)^\s*(?:x-dns-ttl|dns-ttl|ttl|x-ttl)\s*:\s*(\d{1,5})\s*$|^\s*cache-control\s*:\s*[^\r\n]*?\bmax-age\s*=\s*(\d{1,5})",
        )
        .unwrap()
    });

    for caps in TTL_RE.captures_iter(input) {
        let ttl = caps
            .get(1)
            .or_else(|| caps.get(2))
            .and_then(|m| m.as_str().parse::<u32>().ok());
        if let Some(v) = ttl {
            if v <= 60 {
                return Some(v);
            }
        }
    }

    None
}

fn detect_protocol_smuggle_in_params(input: &str, dets: &mut Vec<L2Detection>) {
    static PARAM_SCHEME_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(?:^|[?&][^=\s&#]{1,64}=)((?:[a-zA-Z][a-zA-Z0-9+.-]*:)?//[^&\s#]+)").unwrap()
    });

    for caps in PARAM_SCHEME_RE.captures_iter(input) {
        let Some(value) = caps.get(1) else { continue };
        let start = value.start();
        let candidate = value.as_str();
        let Some(parsed) = parse_url(candidate) else {
            continue;
        };
        
        if candidate.starts_with("//") {
            let mut is_internal = false;
            let mut label = String::new();
            if let Some(ip_num) = parse_ip_representation(&parsed.hostname) {
                if let Some(range_label) = is_internal_ip(ip_num) {
                    is_internal = true;
                    label = range_label.to_string();
                }
            } else if parsed.hostname == "localhost" {
                is_internal = true;
                label = "localhost".to_string();
            } else if let Some(ipv6_label) = is_ipv6_internal(&parsed.hostname) {
                is_internal = true;
                label = ipv6_label.to_string();
            }
            
            if is_internal {
                dets.push(L2Detection {
                    detection_type: "internal_reach".into(),
                    confidence: 0.90,
                    detail: format!("Scheme-relative URL parameter targets internal host: {}", parsed.hostname),
                    position: start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: candidate.to_owned(),
                        interpretation: format!("Scheme-relative URL (//host) bypasses protocol checks and resolves to {}", label),
                        offset: start,
                        property: "Server-side URL parameters must not resolve to internal network addresses".into(),
                    }],
                });
            }
        }

        if DANGEROUS_PROTOCOLS.contains(&parsed.protocol.as_str()) {
            dets.push(L2Detection {
                detection_type: "protocol_smuggle".into(),
                confidence: 0.90,
                detail: format!(
                    "Dangerous protocol in URL parameter: {}//{}",
                    parsed.protocol, parsed.hostname
                ),
                position: start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: candidate.to_owned(),
                    interpretation: "Nested URL parameter contains a non-HTTP scheme target".into(),
                    offset: start,
                    property: "Server-side URL parameters must reject dangerous schemes".into(),
                }],
            });
        }
    }
}

fn detect_parser_confusion(decoded: &str, parsed: &ParsedUrl, dets: &mut Vec<L2Detection>) {
    static FRAGMENT_AT_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)^https?://[^/\s?#]+#@([^/\s?#]+)").unwrap());
    static FRAGMENT_URL_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)#.*([a-z][a-z0-9+.-]*://[^\\s#]+)").unwrap());
    static URL_AT_HOST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)[a-z][a-z0-9+.-]*://[^/\s?#]*://[^@\s?#]*@").unwrap()
    });

    if let Some(pos) = decoded.find("://") {
        let remainder = &decoded[pos + 3..];
        let boundary = remainder
            .find(['/', '?', '#', '\\'])
            .unwrap_or(remainder.len());
        let boundary_sep = boundary
            .checked_add(pos + 3)
            .and_then(|idx| decoded[idx..].chars().next())
            .and_then(|c| if c == '\\' { Some(c) } else { None });
        let authority = &remainder[..boundary];
        if authority.contains('\\') || boundary_sep == Some('\\') {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.92,
                detail: format!(
                    "Backslash in URL authority used for parser confusion: {}",
                    authority
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded.to_owned(),
                    interpretation: "Backslashes in authority can produce parser divergence".into(),
                    offset: 0,
                    property: "Normalize and reject mixed path separators before URL validation"
                        .into(),
                }],
            });
        }
    }

    if let Some(caps) = FRAGMENT_AT_RE.captures(decoded) {
        let alt_host = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        dets.push(L2Detection {
            detection_type: "internal_reach".into(),
            confidence: if host_looks_internal_name(alt_host) { 0.90 } else { 0.86 },
            detail: format!(
                "Parser confusion pattern '#@' detected; host split can differ across parsers (base={}, alt={})",
                parsed.hostname, alt_host
            ),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: decoded.to_owned(),
                interpretation: "Different URL parsers may disagree on effective host due to fragment/userinfo ambiguity".into(),
                offset: 0,
                property: "Host validation must use a single canonical parser".into(),
            }],
        });
    }

    if let Some(caps) = FRAGMENT_URL_RE.captures(decoded) {
        let fragment_url = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Some(fragment_parsed) = parse_url(fragment_url) {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.87,
                detail: format!(
                    "Fragment URL injection pattern detected: {}://{}",
                    fragment_parsed.protocol, fragment_parsed.hostname
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded.to_owned(),
                    interpretation:
                        "Some parsers can treat URL fragments as redirect or path targets".into(),
                    offset: 0,
                    property: "Fragments should not be interpreted as request targets".into(),
                }],
            });
        }
    }

    if URL_AT_HOST_RE.is_match(decoded) {
        dets.push(L2Detection {
            detection_type: "internal_reach".into(),
            confidence: 0.89,
            detail: "Double-protocol URL with userinfo may cause parser mismatch".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: decoded.to_owned(),
                interpretation: "Some parsers treat nested protocol fragments as credentials, others as part of authority/path"
                    .into(),
                offset: 0,
                property: "Normalize and reject URL forms containing multiple protocol tokens".into(),
            }],
        });
    }

    if parsed.has_credentials {
        let mut before_at = "";
        let parts: Vec<&str> = parsed.authority.split('@').collect();
        if parts.len() > 1 {
            before_at = parts[0];
            
            // Bug 2 Fix: Check all segments before the last one for internal targets
            // because some parsers split at the FIRST '@' instead of the LAST '@'
            for i in 0..parts.len() - 1 {
                let mut segment = parts[i];
                if let Some(colon) = segment.find(':') {
                    segment = &segment[..colon];
                }
                
                let segment_lower = segment.to_lowercase();
                let mut is_internal = false;
                let mut label = String::new();
                
                if let Some(ip_num) = parse_ip_representation(&segment_lower) {
                    if let Some(range_label) = is_internal_ip(ip_num) {
                        is_internal = true;
                        label = range_label.to_string();
                    }
                } else if segment_lower == "localhost" {
                    is_internal = true;
                    label = "localhost".to_string();
                } else if let Some(ipv6_label) = is_ipv6_internal(&segment_lower) {
                    is_internal = true;
                    label = ipv6_label.to_string();
                }
                
                if is_internal {
                    dets.push(L2Detection {
                        detection_type: "internal_reach".into(),
                        confidence: 0.90,
                        detail: format!("Ambiguous authority segment resolves to internal host: {}", segment_lower),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: parsed.authority.clone(),
                            interpretation: format!("A segment of the URL authority before '@' is an internal target ({}). Parsers splitting at the first '@' will connect to it.", label),
                            offset: 0,
                            property: "All authority segments must be validated to prevent credential parser confusion".into(),
                        }],
                    });
                }
            }
        }
        
        if before_at.contains("://") {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.88,
                detail: format!(
                    "Embedded URL-like userinfo in authority: {}",
                    parsed.authority
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: parsed.authority.clone(),
                    interpretation:
                        "URL-like userinfo can cause host parsing to desynchronize across parsers"
                            .into(),
                    offset: 0,
                    property: "Reject URL-like tokens in userinfo segments".into(),
                }],
            });
        }
    }

    if parsed.authority.matches('@').count() > 1 {
        dets.push(L2Detection {
            detection_type: "internal_reach".into(),
            confidence: 0.84,
            detail: format!(
                "Multiple '@' markers in authority may induce parser disagreement: {}",
                parsed.authority
            ),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: parsed.authority.clone(),
                interpretation: "Ambiguous authority section can bypass naive host extractors"
                    .into(),
                offset: 0,
                property: "Authority must be strictly validated to avoid parser confusion".into(),
            }],
        });
    }
}

fn is_cloud_metadata_path(path: &str) -> bool {
    let p = path.to_lowercase();
    CLOUD_METADATA_PATHS.iter().any(|needle| p.contains(needle))
}

fn is_dns_rebind_target(host: &str) -> Option<String> {
    let (h, _) = normalize_unicode_dotlike_host(&host.to_lowercase());
    for suffix in DNS_REBINDING_SUFFIXES {
        if !h.ends_with(suffix) {
            continue;
        }

        let Some(prefix) = h.strip_suffix(suffix) else {
            continue;
        };
        if prefix
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == '-')
        {
            let maybe = parse_ip_representation(prefix);
            if let Some(ip_num) = maybe {
                return Some(ip_num_to_string(ip_num));
            }
        }
    }

    let localhost_domains = ["localtest.me", "lvh.me", "vcap.me", "lacolhost.com", "spoofed.burpcollaborator.net"];
    for domain in &localhost_domains {
        if h == *domain || h.ends_with(&format!(".{}", domain)) {
            return Some("127.0.0.1".to_string());
        }
    }

    static IP_SUBDOMAIN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.[a-z]+\.[a-z]+").unwrap()
    });
    
    if let Some(caps) = IP_SUBDOMAIN_RE.captures(&h) {
        if let Some(ip_str) = caps.get(1) {
            if let Some(ip_num) = parse_ip_representation(ip_str.as_str()) {
                return Some(ip_num_to_string(ip_num));
            }
        }
    }

    None
}

fn detect_redirect_chain_targets(input: &str, dets: &mut Vec<L2Detection>) {
    static REDIRECT_STATUS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?im)^\s*HTTP/\d+\.\d+\s+(301|302|307|308)\s").unwrap()
    });
    static REDIRECT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?i)(?:^|[&?])(url|uri|next|redirect|return|return_url|continue|target|to|dest|callback|goto|path|callback_url)\s*=\s*([^&\s#]+)",
        )
        .unwrap()
    });

    let mut values = Vec::new();
    for caps in REDIRECT_RE.captures_iter(input) {
        let start = caps.get(2).map(|m| m.start()).unwrap_or(0);
        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        values.push((start, value));
    }

    let has_http_redirect = REDIRECT_STATUS_RE.is_match(input);
    let mut location = Vec::new();
    static LOCATION_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?im)^\s*Location:\s*([^\r\n]+)").unwrap());
    for caps in LOCATION_RE.captures_iter(input) {
        if let Some(v) = caps.get(1) {
            location.push((v.start(), v.as_str().trim()));
        }
    }

    let candidates = values.into_iter().chain(location);

    for (start, raw_target) in candidates {
        let target = crate::encoding::multi_layer_decode(raw_target).fully_decoded;
        if target.is_empty() {
            continue;
        }

        if !target.contains("://") && !target.starts_with("//") {
            continue;
        }

        let parsed = match parse_url(&target) {
            Some(p) => p,
            None => continue,
        };

        if has_http_redirect {
            if let Some(ip_num) = parse_ip_representation(&parsed.hostname) {
                if is_internal_ip(ip_num).is_some() {
                    dets.push(L2Detection {
                        detection_type: "internal_reach".into(),
                        confidence: 0.95,
                        detail: format!(
                            "Redirect response target is internal: {}",
                            parsed.hostname
                        ),
                        position: start,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: raw_target.to_owned(),
                            interpretation:
                                "HTTP 3xx redirect to internal target can escalate SSRF".into(),
                            offset: start,
                            property: "SSRF checks must revalidate targets after redirects".into(),
                        }],
                    });
                }
            } else if request_host_is_cloud_metadata(Some(&parsed.hostname)) {
                dets.push(L2Detection {
                    detection_type: "cloud_metadata".into(),
                    confidence: 0.97,
                    detail: format!(
                        "Redirect response targets metadata hostname: {}",
                        parsed.hostname
                    ),
                    position: start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: raw_target.to_owned(),
                        interpretation: "HTTP 3xx redirect to metadata endpoint".into(),
                        offset: start,
                        property: "SSRF checks must revalidate metadata targets after redirects"
                            .into(),
                    }],
                });
            }
        }

        if is_url_shortener(&parsed.hostname) {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.81,
                detail: format!(
                    "Redirect chain uses URL shortener {} as potential SSRF redirector",
                    parsed.hostname
                ),
                position: start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: raw_target.to_owned(),
                    interpretation: "Short links can hide internal destinations behind redirects"
                        .into(),
                    offset: start,
                    property: "Redirect targets should be expanded and revalidated before follow"
                        .into(),
                }],
            });
        }

        if let Some(ip_num) = parse_ip_representation(&parsed.hostname) {
            let resolved = ip_num_to_string(ip_num);

            if CLOUD_METADATA_IPS.contains(&resolved.as_str()) {
                dets.push(L2Detection {
                    detection_type: "cloud_metadata".into(),
                    confidence: 0.96,
                    detail: format!("Redirect/metadata chain targets cloud metadata IP {} -> {}", parsed.hostname, resolved),
                    position: start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: raw_target.to_owned(),
                        interpretation: "Redirect chain resolves to cloud metadata IP endpoint".into(),
                        offset: start,
                        property: "Request redirection chains must be normalized and validated before external hops".into(),
                    }],
                });
            }

            if let Some(range_label) = is_internal_ip(ip_num) {
                dets.push(L2Detection {
                    detection_type: "internal_reach".into(),
                    confidence: 0.94,
                    detail: format!("Redirect chain to internal IP {} -> {} [{}]", parsed.hostname, resolved, range_label),
                    position: start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: raw_target.to_owned(),
                        interpretation: format!("Redirect chain final target resolves to internal range: {}", range_label),
                        offset: start,
                        property: "Server-side requests must not reach internal/private IP ranges through redirect chain follow-ups".into(),
                    }],
                });
            }
        }

        if let Some(rebound) = is_dns_rebind_target(&parsed.hostname) {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.93,
                detail: format!("Redirect chain includes DNS rebinding hostname {} -> {}", parsed.hostname, rebound),
                position: start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: raw_target.to_owned(),
                    interpretation: "DNS rebinding redirect target resolves to internal network host".into(),
                    offset: start,
                    property: "Redirect chain follow-ups must not permit DNS rebinding into private addresses".into(),
                }],
            });
        }

        if is_cloud_metadata_path(&parsed.path) {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.95,
                detail: format!("Redirect chain reaches cloud metadata path {}", parsed.path),
                position: start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: raw_target.to_owned(),
                    interpretation: "Redirect chain path indicates metadata endpoint access".into(),
                    offset: start,
                    property: "Request redirection chains must block cloud metadata paths beyond host checks".into(),
                }],
            });
        }

        if DANGEROUS_PROTOCOLS.contains(&parsed.protocol.as_str()) {
            dets.push(L2Detection {
                detection_type: "protocol_smuggle".into(),
                confidence: 0.9,
                detail: format!(
                    "Redirect chain to non-HTTP protocol {}//{}",
                    parsed.protocol, parsed.hostname
                ),
                position: start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: raw_target.to_owned(),
                    interpretation: "Redirect chain can execute non-HTTP scheme handlers".into(),
                    offset: start,
                    property: "Redirect chains must only follow HTTP(S) targets".into(),
                }],
            });
        }

        if CLOUD_METADATA_HOSTNAMES.contains(&parsed.hostname.as_str()) {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.9,
                detail: format!(
                    "Redirect chain target matches metadata hostname {}",
                    parsed.hostname
                ),
                position: start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: raw_target.to_owned(),
                    interpretation: "Redirect chain target can hit metadata hostname".into(),
                    offset: start,
                    property: "Redirect chains must validate metadata hostnames".into(),
                }],
            });
        }

        if let Some(label) = is_ipv6_internal(&parsed.hostname) {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.93,
                detail: format!("Redirect chain reaches {}", label),
                position: start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: raw_target.to_owned(),
                    interpretation: "Redirect chain ends in internal IPv6 endpoint".into(),
                    offset: start,
                    property: "Redirects to internal IPv6 addresses must be denied".into(),
                }],
            });
        }
    }
}

fn detect_cloud_metadata_context(
    input: &str,
    host: Option<&str>,
    path: &str,
    method: Option<&str>,
    dets: &mut Vec<L2Detection>,
) {
    let lowered_path = path.to_lowercase();
    let is_put = method.is_some_and(|m| m == "put");

    if request_host_is_cloud_metadata(host) {
        if lowered_path == AWS_IMDSV2_TOKEN_PATH
            && is_put
            && extract_header_value(input, AWS_IMDSV2_TOKEN_HEADER).is_some()
        {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.99,
                detail: format!(
                    "IMDSv2 token endpoint request detected: {} {}",
                    method.unwrap_or(""),
                    lowered_path
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation:
                        "AWS EC2 metadata token workflow can expose instance credentials".into(),
                    offset: 0,
                    property: "Block AWS IMDSv2 token acquisition in SSRF contexts".into(),
                }],
            });
        }

        if let Some(flavor) = extract_header_value(input, GCP_METADATA_FLAVOR_HEADER)
            && host.unwrap_or("").contains("metadata.google.internal")
            && flavor.to_lowercase() == GCP_METADATA_FLAVOR_VALUE
        {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.99,
                detail: "GCP metadata request with Metadata-Flavor: Google".to_owned(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation:
                        "GCP metadata requires special header but still indicates metadata probing"
                            .into(),
                    offset: 0,
                    property: "Block metadata.google.internal requests in SSRF flow".into(),
                }],
            });
        }

        if lowered_path.starts_with("/computeMetadata/v1") {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.95,
                detail: format!("GCP metadata namespace: {}", lowered_path),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "Google metadata namespace should be blocked".into(),
                    offset: 0,
                    property: "Reject /computeMetadata/v1 paths in SSRF flow".into(),
                }],
            });
        }

        if lowered_path.contains("/metadata/instance")
            && lowered_path.contains("api-version=")
        {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.99,
                detail: format!(
                    "Azure metadata request with API version: {}",
                    lowered_path
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "Azure IMDS endpoint with versioned token path".into(),
                    offset: 0,
                    property: "Block Azure metadata endpoint metadata/instance requests".into(),
                }],
            });
        }
        if lowered_path.starts_with(DIGITAL_OCEAN_METADATA_PREFIX) {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.95,
                detail: format!("DigitalOcean metadata namespace {}", lowered_path),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation:
                        "DigitalOcean metadata namespace can leak instance identity secrets".into(),
                    offset: 0,
                    property: "Block DigitalOcean metadata path access".into(),
                }],
            });
        }
    }
}

fn parse_url(input: &str) -> Option<ParsedUrl> {
    let url = input.trim();
    let url = if url.starts_with("//") {
        format!("http:{}", url)
    } else {
        url.to_owned()
    };

    static proto_re: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)^([a-z][a-z0-9+.-]*)://").unwrap());
    let caps = proto_re.captures(&url)?;
    let protocol = format!("{}:", caps.get(1)?.as_str().to_lowercase());
    let remainder = &url[caps.get(0)?.len()..];

    let boundary = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..boundary];
    let path = if boundary < remainder.len() {
        &remainder[boundary..]
    } else {
        "/"
    };
    let has_credentials = authority.contains('@');

    // Keep only host[:port], stripping trailing userinfo if present.
    let host_port = if let Some(at) = authority.rfind('@') {
        &authority[at + 1..]
    } else {
        authority
    };

    // IPv6: [::1]:8080
    static IPV6_BRACKET_HOST_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^\[([^\]]+)\]").unwrap());
    let hostname = if let Some(caps) = IPV6_BRACKET_HOST_RE.captures(host_port) {
        caps.get(1)?.as_str().to_lowercase()
    } else {
        // Strip port
        let h = if let Some(colon) = host_port.rfind(':') {
            if host_port[colon + 1..].chars().all(|c| c.is_ascii_digit()) {
                &host_port[..colon]
            } else {
                host_port
            }
        } else {
            host_port
        };
        h.to_lowercase()
    };

    Some(ParsedUrl {
        protocol,
        authority: authority.to_owned(),
        hostname,
        path: path.to_owned(),
        has_credentials,
    })
}

pub struct SsrfEvaluator;

impl L2Evaluator for SsrfEvaluator {
    fn id(&self) -> &'static str {
        "ssrf"
    }
    fn prefix(&self) -> &'static str {
        "L2 SSRF"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        if input.len() < 4 {
            return dets;
        }

        static SSRF_IPV6_ZONE_LOCALHOST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\[(?:[0-9a-fA-F:]+)(?:%25?|%)(?:lo|eth|en|wlan|docker|br|veth)[0-9]*\]").unwrap()
        });
        for m in SSRF_IPV6_ZONE_LOCALHOST_RE.find_iter(input) {
            dets.push(L2Detection {
                detection_type: "ssrf_ipv6_zone_localhost".into(),
                confidence: 0.92,
                detail: "IPv6 zone ID with localhost interfaces".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "IPv6 zone IDs (%lo0, %eth0, %docker0) specify network interface scoping. http://[fe80::1%lo0]/ routes to the local loopback interface despite the IPv6 address appearing non-local. Many SSRF filters check for 127.0.0.1 and ::1 but miss interface-scoped IPv6 addresses that also resolve locally".into(),
                    offset: m.start(),
                    property: "IPv6 addresses with zone IDs must be treated as interface-specific addresses. Reject all SSRF targets where the zone ID references loopback, Ethernet, or Docker bridge interfaces".into(),
                }],
            });
        }

        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lowered_decoded = decoded.to_lowercase();

        static SSRF_IPV6_MAPPED_METADATA_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)https?://\[\s*::ffff:169\.254\.169\.254\s*\](?:[/:?#]|$)")
                    .unwrap()
            });
        for m in SSRF_IPV6_MAPPED_METADATA_RE.find_iter(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_ipv6_mapped_metadata".into(),
                confidence: 0.96,
                detail: "IPv6-mapped metadata endpoint target detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "IPv6 mapped notation ::ffff:169.254.169.254 bypasses naive IPv4-only metadata filters"
                            .into(),
                    offset: m.start(),
                    property:
                        "SSRF policy must normalize IPv6-mapped IPv4 hosts before metadata/IP range checks"
                            .into(),
                }],
            });
        }

        static SSRF_DECIMAL_LOOPBACK_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)https?://2130706433(?:[/:?#]|$)").unwrap());
        for m in SSRF_DECIMAL_LOOPBACK_RE.find_iter(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_decimal_ip_loopback".into(),
                confidence: 0.95,
                detail: "Decimal integer IPv4 SSRF bypass target detected (2130706433)".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Single-integer decimal host 2130706433 resolves to loopback 127.0.0.1"
                            .into(),
                    offset: m.start(),
                    property:
                        "SSRF protection must canonicalize integer IPv4 host representations".into(),
                }],
            });
        }

        static SSRF_IMDSV2_TOKEN_URL_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)https?://169\.254\.169\.254/latest/api/token(?:[/?#]|$)")
                    .unwrap()
            });
        for m in SSRF_IMDSV2_TOKEN_URL_RE.find_iter(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_aws_imdsv2_token_url".into(),
                confidence: 0.99,
                detail: "Direct AWS IMDSv2 token URL target detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Direct access to /latest/api/token can acquire IMDSv2 token for metadata credential theft"
                            .into(),
                    offset: m.start(),
                    property:
                        "Block all requests to AWS metadata token endpoint in SSRF contexts".into(),
                }],
            });
        }

        static SSRF_IMDSV2_TOKEN_PATH_RAW_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)\b(?:get|post|put)\s+/latest/api/token\b|/latest/api/token")
                    .unwrap()
            });
        for m in SSRF_IMDSV2_TOKEN_PATH_RAW_RE.find_iter(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_imdsv2_token_path_probe".into(),
                confidence: 0.97,
                detail: "AWS IMDSv2 token path probe detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Token endpoint probing is a precursor to AWS metadata credential extraction"
                            .into(),
                    offset: m.start(),
                    property:
                        "Requests containing IMDSv2 token path indicators must be blocked in SSRF flows"
                            .into(),
                }],
            });
        }

        static SSRF_DECIMAL_LOCALHOST_WITH_PORT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)https?://2130706433:\d{1,5}(?:[/?#]|$)").unwrap());
        for m in SSRF_DECIMAL_LOCALHOST_WITH_PORT_RE.find_iter(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_decimal_ip_with_port".into(),
                confidence: 0.95,
                detail: "Decimal localhost integer with explicit port".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Decimal host integer with port still resolves to localhost and internal service reachability"
                            .into(),
                    offset: m.start(),
                    property:
                        "Numeric host canonicalization must be applied before host:port SSRF validation"
                            .into(),
                }],
            });
        }
        
        static CONTAINER_K8S_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:unix:///var/run/docker\.sock|tcp://localhost:2375|localhost:2376|kubernetes\.default\.svc|localhost:2379|localhost:4001|localhost:8500|localhost:15000|localhost:9901|localhost:9001|169\.254\.76\.1)").unwrap()
        });
        if CONTAINER_K8S_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_container_internal".into(),
                confidence: 0.94,
                detail: "References to container orchestration internal APIs detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "Container and orchestration platform internal APIs (Docker socket, Kubernetes API server, etcd, Consul, Envoy admin, Lambda runtime) are accessible from within containers. SSRF to these endpoints enables container escape, credential theft, and cluster compromise.".into(),
                    offset: 0,
                    property: "Server-side requests must not access container runtime or orchestration internal endpoints".into(),
                }],
            });
        }

        static IPV6_ZONE_ID_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:http|https|ftp)://\[fe80::[^\]]*%(?:25)?[a-z0-9]+\]").unwrap()
        });
        if IPV6_ZONE_ID_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_ipv6_zone_id".into(),
                confidence: 0.88,
                detail: "IPv6 link-local address with zone identifier detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "IPv6 link-local addresses with zone identifiers (%eth0, %25eth0) are local to the machine. URL parsers may incorrectly treat the zone ID as a port or path component, allowing bypass of IP allowlists while targeting localhost.".into(),
                    offset: 0,
                    property: "IPv6 zone identifiers must not be permitted in URL targets".into(),
                }],
            });
        }

        static AWS_VPC_ENDPOINT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:[a-z0-9-]+)\.vpce-[a-z0-9-]+\.(?:[a-z0-9-]+)\.vpce\.amazonaws\.com|\.execute-api\.[a-z0-9-]+\.vpce\.amazonaws\.com").unwrap()
        });
        if AWS_VPC_ENDPOINT_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssrf_aws_vpc_endpoint".into(),
                confidence: 0.87,
                detail: "AWS VPC endpoint URL detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "AWS VPC endpoints resolve to private IP addresses within the VPC. SSRF to VPC endpoint URLs can reach internal AWS services (S3, API Gateway, SQS) without going through the public internet, potentially exposing internal APIs.".into(),
                    offset: 0,
                    property: "Server-side requests must validate and restrict targets pointing to VPC endpoints".into(),
                }],
            });
        }

        if lowered_decoded.contains("computemetadata/v1") || 
           lowered_decoded.contains("/latest/meta-data/iam/") || 
           lowered_decoded.contains("/metadata/instance?api-version=") || 
           lowered_decoded.contains("/metadata/service/") {
            dets.push(L2Detection {
                detection_type: "ssrf_cloud_metadata_alt_path".into(),
                confidence: 0.92,
                detail: "Cloud metadata accessed via known alternative paths/methods".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "Cloud metadata services expose instance credentials and configuration at well-known paths. Alternative or vendor-specific paths (GCP /computeMetadata/v1, Azure /metadata/instance, DO /metadata/service) allow attackers to retrieve cloud credentials for lateral movement.".into(),
                    offset: 0,
                    property: "All potential paths to cloud instance metadata services must be blocked".into(),
                }],
            });
        }

        let request_line = extract_http_request_line(&decoded);
        let request_host_header = request_line
            .as_ref()
            .and_then(|_| extract_header_value(&decoded, "Host"));
        let parsed = parse_url(&decoded).or_else(|| parse_url(&decoded.replace('\\', "/")));
        let request_host = request_line.as_ref().and_then(|request| {
            parse_request_target_host(request, parsed.as_ref(), request_host_header.as_deref())
        });
        let request_path = request_line
            .as_ref()
            .map(|request| extract_request_path(request, parsed.as_ref()));
        let request_method = request_line.as_ref().map(|request| request.method.as_str());

        let parsed = if let Some(parsed) = parsed {
            parsed
        } else {
            if let Some(path) = request_path {
                if path.contains(KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH) {
                    dets.push(L2Detection {
                        detection_type: "internal_reach".into(),
                        confidence: 0.94,
                        detail: "Kubernetes service account token file path".to_owned(),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: decoded.to_owned(),
                            interpretation: "Direct file path to Kubernetes service account token"
                                .into(),
                            offset: 0,
                            property:
                                "Disallow file access to mounted Kubernetes service account tokens"
                                    .into(),
                        }],
                    });
                }
                detect_cloud_metadata_context(
                    &decoded,
                    request_host.as_deref(),
                    &path,
                    request_method,
                    &mut dets,
                );
            }

            detect_protocol_smuggle_in_params(&decoded, &mut dets);
            detect_redirect_chain_targets(&decoded, &mut dets);
            return dets;
        };

        if is_url_shortener(&parsed.hostname) {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.80,
                detail: format!(
                    "URL shortener host {} may conceal SSRF destination",
                    parsed.hostname
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: parsed.hostname.clone(),
                    interpretation:
                        "Short URL hosts can redirect server-side requests to internal services"
                            .into(),
                    offset: 0,
                    property:
                        "Short links should be expanded and destination-validated before fetch"
                            .into(),
                }],
            });
        }

        let effective_host = if parsed.hostname.is_empty() {
            request_host.as_deref()
        } else {
            Some(parsed.hostname.as_str())
        };
        detect_cloud_metadata_context(
            &decoded,
            effective_host,
            &parsed.path,
            request_method,
            &mut dets,
        );
        if parsed.path.contains(KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH) {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.94,
                detail: "Kubernetes service account token file path".to_owned(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: parsed.path.clone(),
                    interpretation: "Direct file path to Kubernetes service account token".into(),
                    offset: 0,
                    property: "Disallow file access to mounted Kubernetes service account tokens"
                        .into(),
                }],
            });
        }

        // Cloud metadata (highest severity)
        if let Some(ip_num) = parse_ip_representation(&parsed.hostname) {
            let resolved = ip_num_to_string(ip_num);
            if CLOUD_METADATA_IPS.contains(&resolved.as_str()) {
                dets.push(L2Detection {
                    detection_type: "cloud_metadata".into(),
                    confidence: 0.95,
                    detail: format!(
                        "Cloud metadata endpoint: {} → {}{}",
                        parsed.hostname, resolved, parsed.path
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: input.to_owned(),
                        interpretation: "Request targets cloud instance metadata service".into(),
                        offset: 0,
                        property: "Server-side requests must not reach cloud metadata endpoints"
                            .into(),
                    }],
                });
            }
        }
        if CLOUD_METADATA_HOSTNAMES.contains(&parsed.hostname.as_str()) {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.92,
                detail: format!("Cloud metadata hostname: {}", parsed.hostname),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: parsed.hostname.clone(),
                    interpretation: "Request targets cloud metadata hostname".into(),
                    offset: 0,
                    property: "Server-side requests must not reach cloud metadata endpoints".into(),
                }],
            });
        }

        // Internal IP reach
        if let Some(ip_num) = parse_ip_representation(&parsed.hostname) {
            if let Some(range_label) = is_internal_ip(ip_num) {
                let resolved = ip_num_to_string(ip_num);
                dets.push(L2Detection {
                    detection_type: "internal_reach".into(),
                    confidence: 0.92,
                    detail: format!(
                        "Internal IP ({}): {} → {}",
                        range_label, parsed.hostname, resolved
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: parsed.hostname.clone(),
                        interpretation: format!("IP resolves to internal range: {}", range_label),
                        offset: 0,
                        property: "Server-side requests must not reach internal/private IP ranges"
                            .into(),
                    }],
                });
            }
        }

        // Localhost hostname
        let h = &parsed.hostname;
        let (unicode_host, unicode_host_changed) = normalize_unicode_dotlike_host(h);
        if unicode_host_changed
            && unicode_host != *h
            && (unicode_host == "127.0.0.1" || unicode_host == "localhost")
        {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.9,
                detail: format!("Unicode host normalization maps {} to {}", h, unicode_host),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: h.clone(),
                    interpretation:
                        "Unicode host normalization can map to local/loopback-like targets".into(),
                    offset: 0,
                    property: "Host normalization should be applied before allowlist checks".into(),
                }],
            });
        }

        if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") || h == "0" {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.90,
                detail: format!("Localhost hostname: {}", h),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: h.clone(),
                    interpretation: "Hostname resolves to localhost".into(),
                    offset: 0,
                    property: "Server-side requests must not reach internal/private IP ranges"
                        .into(),
                }],
            });
        }

        // DNS rebinding services
        if let Some(rebound_ip) = is_dns_rebind_target(h) {
            if let Some(ip_num) = parse_ip_representation(&rebound_ip) {
                if is_internal_ip(ip_num).is_some() {
                    dets.push(L2Detection {
                        detection_type: "internal_reach".into(),
                        confidence: 0.92,
                        detail: format!(
                            "DNS rebinding resolves to internal range: {} → {}",
                            h, rebound_ip
                        ),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: h.clone(),
                            interpretation: format!(
                                "DNS rebinding endpoint resolves to {}",
                                rebound_ip
                            ),
                            offset: 0,
                            property:
                                "Server-side requests must not reach internal/private IP ranges"
                                    .into(),
                        }],
                    });
                }
            }
        }

        // Protocol smuggle
        if DANGEROUS_PROTOCOLS.contains(&parsed.protocol.as_str()) {
            dets.push(L2Detection {
                detection_type: "protocol_smuggle".into(),
                confidence: 0.88,
                detail: format!("Non-HTTP protocol: {}//{}", parsed.protocol, parsed.hostname),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: parsed.protocol.clone(),
                    interpretation: "Non-HTTP protocol can access local resources or trigger server-side behavior".into(),
                    offset: 0,
                    property: "Server-side requests must use only HTTP/HTTPS protocols".into(),
                }],
            });
        }

        if parsed.has_credentials {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.90,
                detail: format!(
                    "URL authority contains credentials prefix before host: {}",
                    parsed.authority
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: parsed.authority.clone(),
                    interpretation: "userinfo@host can bypass naive host filters".into(),
                    offset: 0,
                    property: "Host validation must parse and validate authority canonically"
                        .into(),
                }],
            });
        }

        let (enclosed_host, enclosed_changed) = normalize_enclosed_alnum(h);
        let enclosed_host = enclosed_host.to_lowercase();
        if enclosed_changed
            && (enclosed_host == "localhost" || enclosed_host.ends_with(".localhost"))
        {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.90,
                detail: format!(
                    "Enclosed alphanumeric localhost obfuscation: {} -> {}",
                    h, enclosed_host
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: h.clone(),
                    interpretation: "Unicode enclosed letters normalize to localhost".into(),
                    offset: 0,
                    property: "Hostnames must be Unicode-normalized before SSRF policy checks"
                        .into(),
                }],
            });
        }

        if has_obfuscated_ipv4_notation(h) && parse_ip_representation(h).is_some() {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.88,
                detail: format!("Obfuscated IPv4 notation (leading zeros / integer): {}", h),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: h.clone(),
                    interpretation:
                        "Numeric host uses obfuscated IPv4 encoding commonly used in SSRF bypass"
                            .into(),
                    offset: 0,
                    property: "Numeric hosts should be canonicalized prior to allow/deny checks"
                        .into(),
                }],
            });
        }

        if let Some(label) = is_ipv6_internal(&parsed.hostname) {
            dets.push(L2Detection {
                detection_type: "internal_reach".into(),
                confidence: 0.91,
                detail: format!("IPv6 internal range: {}", label),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: parsed.hostname.clone(),
                    interpretation: label.into(),
                    offset: 0,
                    property: "Server-side requests must not reach internal/private IP ranges"
                        .into(),
                }],
            });
        }

        if is_cloud_metadata_path(&parsed.path) {
            dets.push(L2Detection {
                detection_type: "cloud_metadata".into(),
                confidence: 0.9,
                detail: format!("Cloud metadata path detected: {}", parsed.path),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: parsed.path.clone(),
                    interpretation: "URL path is cloud metadata namespace".into(),
                    offset: 0,
                    property: "Server-side requests must not reach cloud metadata endpoints".into(),
                }],
            });
        }

        if let Some(ttl) = parse_low_dns_ttl_header(&decoded) {
            let parsed_ip = parse_ip_representation(h).or_else(|| {
                h.parse::<Ipv4Addr>().ok().map(|ip| {
                    let o = ip.octets();
                    ip4_to_num(o[0], o[1], o[2], o[3])
                })
            });
            if parsed_ip.is_none() {
                dets.push(L2Detection {
                    detection_type: "internal_reach".into(),
                    confidence: 0.82,
                    detail: format!(
                        "Low DNS TTL ({ttl}s) with URL target {} suggests DNS rebinding setup",
                        h
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded.clone(),
                        interpretation:
                            "Very low DNS TTL allows quick resolver pivots toward internal IPs"
                                .into(),
                        offset: 0,
                        property:
                            "Low-TTL hostname targets should be treated as DNS rebinding risk"
                                .into(),
                    }],
                });
            }
        }

        if h.contains("xn--") {
            let normalized = crate::normalizer::quick_canonical(h).to_lowercase();
            let punycode_embeds_internal = h.to_lowercase().split('.').any(|label| {
                if let Some(rest) = label.strip_prefix("xn--") {
                    // In punycode, the base ASCII label is everything before the last '-'
                    let base = rest.rsplit_once('-').map(|(b, _)| b).unwrap_or(rest);
                    host_looks_internal_name(base)
                } else {
                    false
                }
            });
            if punycode_embeds_internal
                || (normalized != *h && host_looks_internal_name(&normalized))
            {
                dets.push(L2Detection {
                    detection_type: "internal_reach".into(),
                    confidence: 0.87,
                    detail: format!("Punycode/homoglyph hostname normalizes toward internal-like target: {} -> {}", h, normalized),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: h.clone(),
                        interpretation: "Punycode label can disguise internal-looking hostnames".into(),
                        offset: 0,
                        property: "Host validation should normalize punycode/unicode before policy checks".into(),
                    }],
                });
            }
        }

        detect_parser_confusion(&decoded, &parsed, &mut dets);
        detect_protocol_smuggle_in_params(&decoded, &mut dets);

        detect_redirect_chain_targets(&decoded, &mut dets);

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "internal_reach"
            | "ssrf_container_internal"
            | "ssrf_ipv6_zone_id"
            | "ssrf_aws_vpc_endpoint"
            | "ssrf_ipv6_zone_localhost"
            | "ssrf_decimal_ip_loopback"
            | "ssrf_ipv6_mapped_metadata"
            | "ssrf_decimal_ip_with_port" => Some(InvariantClass::SsrfInternalReach),
            "cloud_metadata"
            | "ssrf_cloud_metadata_alt_path"
            | "ssrf_aws_imdsv2_token_url"
            | "ssrf_imdsv2_token_path_probe" => Some(InvariantClass::SsrfCloudMetadata),
            "protocol_smuggle" => Some(InvariantClass::SsrfProtocolSmuggle),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_ssrf_ipv6_zone_localhost_pattern() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://[fe80::1%25lo0]/internal/");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssrf_ipv6_zone_localhost")
        );
    }

    #[test]
    fn localhost_ssrf() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://127.0.0.1/admin");
        assert!(dets.iter().any(|d| d.detection_type == "internal_reach"));
    }

    #[test]
    fn cloud_metadata() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://169.254.169.254/latest/meta-data/");
        assert!(dets.iter().any(|d| d.detection_type == "cloud_metadata"));
    }

    #[test]
    fn hex_ip_bypass() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://0x7f000001/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "Hex IP should be resolved to internal range"
        );
    }

    #[test]
    fn decimal_ip_bypass() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://2130706433/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "Decimal IP should be resolved to internal range"
        );
    }

    #[test]
    fn decimal_ip_explicit_pattern_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://2130706433/");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssrf_decimal_ip_loopback")
        );
    }

    #[test]
    fn protocol_smuggle() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("gopher://internal:25/");
        assert!(dets.iter().any(|d| d.detection_type == "protocol_smuggle"));
    }

    #[test]
    fn safe_url() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("https://example.com/api/data");
        assert!(dets.is_empty(), "External URL should not trigger SSRF");
    }

    #[test]
    fn dns_rebinding() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://127.0.0.1.nip.io/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "DNS rebinding should be detected"
        );
    }

    #[test]
    fn gopher_internal_target() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("gopher://127.0.0.1:6379/_INFO");
        assert!(
            dets.iter().any(|d| d.detection_type == "protocol_smuggle")
                && dets.iter().any(|d| d.detection_type == "internal_reach"),
            "gopher internal target should trigger protocol + internal reach detections"
        );
    }

    #[test]
    fn ipv6_loopback_shorthand() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://[::1]/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "IPv6 loopback shorthand should be detected"
        );
    }

    #[test]
    fn shortener_domain_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://bit.ly/abc123");
        assert!(
            dets.iter().any(|d| d.detail.contains("shortener")),
            "URL shortener should be detected"
        );
    }

    #[test]
    fn ipv6_mapped_ipv4_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://[::ffff:127.0.0.1]/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "IPv6 mapped IPv4 should be detected"
        );
    }

    #[test]
    fn ipv6_mapped_metadata_explicit_pattern_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://[::ffff:169.254.169.254]/");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssrf_ipv6_mapped_metadata")
        );
    }

    #[test]
    fn ipv6_mapped_ipv4_uncompressed_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://[0:0:0:0:0:ffff:7f00:1]/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "Uncompressed IPv6 mapped IPv4 should be detected"
        );
    }

    #[test]
    fn enclosed_alphanumeric_localhost_detected() {
        // Test normalize_enclosed_alnum directly
        let (normalized, changed) = super::normalize_enclosed_alnum("ⓛⓞⓒⓐⓛⓗⓞⓢⓣ");
        eprintln!("normalized={} changed={}", normalized, changed);
        assert!(changed, "Enclosed chars should be detected as changed");
        assert_eq!(normalized, "localhost");

        // Test via the full evaluator
        let eval = SsrfEvaluator;
        let decoded = crate::encoding::multi_layer_decode("http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/admin");
        eprintln!("decoded={}", decoded.fully_decoded);
        let parsed = super::parse_url(&decoded.fully_decoded);
        eprintln!("parsed={:?}", parsed.as_ref().map(|p| &p.hostname));

        let dets = eval.detect("http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/admin");
        for d in &dets {
            eprintln!("  DET type={} detail={}", d.detection_type, d.detail);
        }
        assert!(
            !dets.is_empty(),
            "Enclosed unicode localhost should produce at least one detection"
        );
    }

    #[test]
    fn url_credentials_confusion_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://attacker:password@internal-host/admin");
        assert!(
            dets.iter().any(|d| d.detail.contains("credentials prefix")),
            "Credentials prefix confusion should be detected"
        );
    }

    #[test]
    fn double_parser_confusion_fragment_at_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://google.com#@evil.com");
        assert!(
            dets.iter().any(|d| d.detail.contains("Parser confusion")),
            "Fragment-@ parser confusion should be detected"
        );
    }

    #[test]
    fn punycode_internal_confusion_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://xn--localhost-9za/admin");
        assert!(
            dets.iter().any(|d| d.detail.contains("Punycode/homoglyph")),
            "Punycode internal confusion should be detected"
        );
    }

    #[test]
    fn leading_zero_octal_ipv4_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://0177.0.0.1/admin");
        assert!(
            dets.iter()
                .any(|d| d.detail.contains("Obfuscated IPv4 notation")),
            "Leading-zero dotted decimal/octal should be explicitly detected"
        );
    }

    #[test]
    fn decimal_integer_ipv4_detected_as_obfuscated() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://2130706433/admin");
        assert!(
            dets.iter()
                .any(|d| d.detail.contains("Obfuscated IPv4 notation")),
            "Decimal integer host should be explicitly detected as obfuscated notation"
        );
    }

    #[test]
    fn dns_rebinding_low_ttl_header_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://example.com/path\r\nX-DNS-TTL: 1");
        assert!(
            dets.iter().any(|d| d.detail.contains("Low DNS TTL")),
            "Low DNS TTL header should be detected as rebinding setup"
        );
    }

    #[test]
    fn protocol_smuggle_in_query_parameter_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("https://example.com/fetch?next=gopher://127.0.0.1:6379/_INFO");
        assert!(
            dets.iter().any(|d| d.detection_type == "protocol_smuggle"),
            "Protocol smuggling via URL parameter should be detected"
        );
    }

    #[test]
    fn file_protocol_smuggle_in_query_parameter_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("https://example.com/read?url=file:///etc/passwd");
        assert!(
            dets.iter().any(|d| d.detection_type == "protocol_smuggle"),
            "file:// smuggling via URL parameter should be detected"
        );
    }

    #[test]
    fn aws_imdsv2_token_endpoint_request() {
        let eval = SsrfEvaluator;
        let dets = eval.detect(
            "PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\n",
        );
        assert!(
            dets.iter().any(|d| d.detection_type == "cloud_metadata"),
            "AWS IMDSv2 token workflow should be blocked"
        );
    }

    #[test]
    fn aws_imdsv2_token_url_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://169.254.169.254/latest/api/token");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssrf_aws_imdsv2_token_url")
        );
    }

    #[test]
    fn aws_imdsv2_token_path_probe_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("GET /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\n");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssrf_imdsv2_token_path_probe")
        );
    }

    #[test]
    fn decimal_ip_with_port_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://2130706433:8080/admin");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssrf_decimal_ip_with_port")
        );
    }

    #[test]
    fn gcp_metadata_flavor_header_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect(
            "GET /computeMetadata/v1/?recursive=true HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\n",
        );
        assert!(
            dets.iter().any(|d| d.detection_type == "cloud_metadata"),
            "GCP metadata flavor header should trigger metadata detection"
        );
    }

    #[test]
    fn azure_metadata_api_version_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://169.254.169.254/metadata/instance?api-version=2021-02-01");
        assert!(
            dets.iter().any(|d| d.detection_type == "cloud_metadata"),
            "Azure metadata endpoint with API version should be detected"
        );
    }

    #[test]
    fn digitalocean_metadata_prefix_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://metadata.digitalocean.com/metadata/v1/attributes");
        assert!(
            dets.iter().any(|d| d.detection_type == "cloud_metadata"),
            "DigitalOcean metadata path should trigger detection"
        );
    }

    #[test]
    fn kubernetes_service_account_token_path_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("file:///var/run/secrets/kubernetes.io/serviceaccount/token");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "Kubernetes service-account token path should be reachable via parser checks"
        );
    }

    #[test]
    fn dns_rebind_suffix_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://127.0.0.1.xip.io/metadata");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "DNS rebinding suffix should be treated as internal risk"
        );
    }

    #[test]
    fn ipv6_mapped_hex_full_form_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://[0:0:0:0:0:ffff:a9fe:a9fe]/metadata");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "IPv6 unique mapped form to internal metadata IP should be detected"
        );
    }

    #[test]
    fn parser_confusion_backslash_in_authority_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("https://example.com\\127.0.0.1/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "Backslash authority confusion should trigger parser-diff detection"
        );
    }

    #[test]
    fn parser_confusion_url_at_confusion_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("https://http://127.0.0.1@internal.example/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "url@host style parser confusion should be detected"
        );
    }

    #[test]
    fn parser_confusion_fragment_url_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://example.com/page#https://169.254.169.254/latest/meta-data/");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "Fragment URL injection should trigger parser confusion detection"
        );
    }

    #[test]
    fn redirect_302_to_internal_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "HTTP 302 redirect to internal target should be detected"
        );
    }

    #[test]
    fn dict_protocol_smuggle_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("dict://127.0.0.1:11211/INFO");
        assert!(
            dets.iter().any(|d| d.detection_type == "protocol_smuggle"),
            "dict:// protocol to internal host should be detected"
        );
    }

    #[test]
    fn file_protocol_internal_target_smuggle_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("file:///etc/passwd");
        assert!(
            dets.iter().any(|d| d.detection_type == "protocol_smuggle"),
            "file:// protocol should be flagged as protocol smuggle"
        );
    }

    #[test]
    fn unicode_digit_confusion_to_localhost_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://①②⑦.₀.₀.₁/");
        assert!(
            dets.iter().any(|d| d.detection_type == "internal_reach"),
            "Unicode digits that normalize into internal IPv4 should be detected"
        );
    }

    #[test]
    fn false_positive_subdomain_not_matched_as_metadata_host() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://metadata.google.internal.example.com/admin");
        assert!(
            dets.is_empty(),
            "Metadata-like subdomain should not match exact metadata hostname list"
        );
    }

    #[test]
    fn alibaba_cloud_metadata_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://100.100.100.200/latest/meta-data/");
        let detection = dets.iter().find(|d| d.detection_type == "cloud_metadata");
        assert!(detection.is_some(), "Alibaba cloud metadata should be detected");
        assert!(detection.unwrap().confidence > 0.85, "Confidence should be > 0.85");
    }

    #[test]
    fn huawei_cloud_metadata_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://169.254.169.254/openstack/latest/meta_data.json");
        let detection = dets.iter().find(|d| d.detection_type == "cloud_metadata");
        assert!(detection.is_some(), "Huawei cloud metadata should be detected");
        assert!(detection.unwrap().confidence > 0.85, "Confidence should be > 0.85");
    }

    #[test]
    fn oracle_cloud_metadata_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://169.254.169.254/opc/v2/");
        let detection = dets.iter().find(|d| d.detection_type == "cloud_metadata");
        assert!(detection.is_some(), "Oracle cloud metadata should be detected");
        assert!(detection.unwrap().confidence > 0.85, "Confidence should be > 0.85");
    }

    #[test]
    fn azure_metadata_any_api_version_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://169.254.169.254/metadata/instance?api-version=2023-11-01");
        let detection = dets.iter().find(|d| d.detection_type == "cloud_metadata");
        assert!(detection.is_some(), "Azure metadata with arbitrary API version should be detected");
        assert!(detection.unwrap().confidence > 0.85, "Confidence should be > 0.85");
    }

    #[test]
    fn dns_rebind_localtest_me_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://localtest.me/admin");
        let detection = dets.iter().find(|d| d.detection_type == "internal_reach");
        assert!(detection.is_some(), "localtest.me should be detected as internal reach");
        assert!(detection.unwrap().confidence > 0.85, "Confidence should be > 0.85");
    }

    #[test]
    fn ip_subdomain_detected() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://192.168.1.1.evil.com/admin");
        let detection = dets.iter().find(|d| d.detection_type == "internal_reach");
        assert!(detection.is_some(), "IP as subdomain should be detected as internal reach");
        assert!(detection.unwrap().confidence > 0.85, "Confidence should be > 0.85");
    }

    #[test]
    fn test_container_k8s_endpoint() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("GET http://kubernetes.default.svc.cluster.local/api/v1/secrets");
        assert!(dets.iter().any(|d| d.detection_type == "ssrf_container_internal"));
    }

    #[test]
    fn test_ipv6_zone_id() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://[fe80::1%25eth0]/");
        assert!(dets.iter().any(|d| d.detection_type == "ssrf_ipv6_zone_id"));
    }

    #[test]
    fn test_aws_vpc_endpoint() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("https://vpce-abc123.execute-api.us-east-1.vpce.amazonaws.com/prod");
        assert!(dets.iter().any(|d| d.detection_type == "ssrf_aws_vpc_endpoint"));
    }

    #[test]
    fn test_gcp_metadata_alt_path() {
        let eval = SsrfEvaluator;
        let dets = eval.detect("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts");
        assert!(dets.iter().any(|d| d.detection_type == "ssrf_cloud_metadata_alt_path"));
    }
}
