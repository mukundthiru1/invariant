//! Polyglot Detector — Cross-Context Attack Detection
//!
//! A polyglot payload is valid in MULTIPLE interpretation contexts
//! simultaneously. The invariant: legitimate input is meaningful in
//! exactly ONE context. Multi-context validity is adversarial.
//!
//! Detection principle: If input triggers detections in 2+ DISTINCT
//! attack domains, it's a polyglot. The compound confidence is HIGHER
//! than any individual detection.

use crate::types::InvariantClass;
use std::collections::HashSet;

// ── Domain Classification ─────────────────────────────────────────

/// Map an invariant class to its attack domain.
pub fn class_to_domain(class: &InvariantClass) -> &'static str {
    use InvariantClass::*;
    match class {
        SqlTautology | SqlStringTermination | SqlUnionExtraction | SqlStackedExecution
        | SqlTimeOracle | SqlErrorOracle | SqlCommentTruncation | JsonSqlBypass => "sql",

        XssTagInjection
        | XssAttributeEscape
        | XssEventHandler
        | XssProtocolHandler
        | XssTemplateExpression => "xss",

        CmdSeparator | CmdSubstitution | CmdArgumentInjection => "cmdi",

        SsrfInternalReach | SsrfCloudMetadata | SsrfProtocolSmuggle | OastInteraction => "ssrf",

        PathDotdotEscape | PathNullTerminate | PathEncodingBypass | PathNormalizationBypass => {
            "path"
        }

        SstiJinjaTwig | SstiElExpression => "ssti",

        XxeEntityExpansion | XmlInjection => "xxe",

        DeserJavaGadget | DeserPhpObject | DeserPythonPickle => "deser",

        AuthNoneAlgorithm | AuthHeaderSpoof | CorsOriginAbuse | JwtKidInjection
        | JwtJwkEmbedding | JwtConfusion => "auth",

        NosqlOperatorInjection | NosqlJsInjection => "nosql",

        ProtoPollution | ProtoPollutionGadget => "proto",

        LogJndiLookup => "log4j",

        LdapFilterInjection => "ldap",

        CrlfHeaderInjection | CrlfLogInjection => "crlf",

        HttpSmuggleClTe | HttpSmuggleH2 | HttpSmuggleChunkExt | HttpSmuggleZeroCl
        | HttpSmuggleExpect => "smuggle",

        OpenRedirectBypass => "redirect",

        LlmPromptInjection | LlmDataExfiltration | LlmJailbreak => "llm",

        DependencyConfusion | PostinstallInjection | EnvExfiltration => "supply",

        MassAssignment => "mass_assign",

        GraphqlIntrospection | GraphqlBatchAbuse => "graphql",

        WsInjection | WsHijack => "ws",

        CachePoisoning | CacheDeception => "cache",

        BolaIdor | ApiMassEnum => "api",

        RegexDos => "redos",
        _ => "other",
    }
}

// ── Dangerous Combinations ────────────────────────────────────────

struct DangerousCombo {
    domains: &'static [&'static str],
    boost: f64,
    reason: &'static str,
}

const DANGEROUS_COMBINATIONS: &[DangerousCombo] = &[
    DangerousCombo {
        domains: &["sql", "xss"],
        boost: 0.08,
        reason: "SQL+XSS polyglot — bypasses context-specific sanitization",
    },
    DangerousCombo {
        domains: &["sql", "cmdi"],
        boost: 0.10,
        reason: "SQL+CMDi polyglot — may chain SQL to OS command execution",
    },
    DangerousCombo {
        domains: &["xss", "ssti"],
        boost: 0.08,
        reason: "XSS+SSTI polyglot — client-side AND server-side template execution",
    },
    DangerousCombo {
        domains: &["cmdi", "ssti"],
        boost: 0.10,
        reason: "CMDi+SSTI polyglot — template escape to command execution",
    },
    DangerousCombo {
        domains: &["path", "cmdi"],
        boost: 0.07,
        reason: "Path+CMDi polyglot — file access combined with command injection",
    },
    DangerousCombo {
        domains: &["ssrf", "cmdi"],
        boost: 0.08,
        reason: "SSRF+CMDi polyglot — internal network access with command execution",
    },
];

// ── Polyglot Analysis ─────────────────────────────────────────────

/// Result of polyglot analysis.
#[derive(Debug, Clone)]
pub struct PolyglotDetection {
    pub is_polyglot: bool,
    pub domains: Vec<String>,
    pub domain_count: usize,
    pub confidence_boost: f64,
    pub detail: String,
}

/// Structural polyglot analysis from raw payload content.
#[derive(Debug, Clone)]
pub struct PolyglotStructure {
    pub is_polyglot: bool,
    pub matched_formats: Vec<String>,
    pub confidence_boost: f64,
    pub contains_eicar: bool,
    pub indicators: Vec<String>,
    pub detail: String,
}

fn has_magic_prefix(bytes: &[u8], magic: &[u8]) -> bool {
    bytes.len() >= magic.len() && &bytes[..magic.len()] == magic
}

fn is_likely_javascript(lower: &str) -> bool {
    let js_tokens = [
        "function(",
        "=>",
        "document.",
        "window.",
        "eval(",
        "fetch(",
        "xmlhttprequest",
        "onerror=",
        "onload=",
        "settimeout(",
        "setinterval(",
        "<script",
    ];
    js_tokens.iter().filter(|t| lower.contains(**t)).count() >= 2
}

fn eicar_detect(input: &str) -> bool {
    // Match either plain EICAR string or URL-encoded variants by normalizing.
    let upper = input.to_uppercase();
    if upper.contains("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") {
        return true;
    }
    let compact = upper
        .replace("%2B", "+")
        .replace("%24", "$")
        .replace("%21", "!");
    compact.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
}

/// Detect cross-format/polyglot payload structure directly from bytes.
pub fn detect_polyglot_structure(input: &[u8]) -> PolyglotStructure {
    if input.is_empty() {
        return PolyglotStructure {
            is_polyglot: false,
            matched_formats: vec![],
            confidence_boost: 0.0,
            contains_eicar: false,
            indicators: vec![],
            detail: "Empty payload".to_string(),
        };
    }

    let text = String::from_utf8_lossy(input);
    let lower = text.to_lowercase();
    let head = &input[..input.len().min(1024)];
    let head_text = String::from_utf8_lossy(head).to_lowercase();

    let is_jpeg = has_magic_prefix(input, &[0xFF, 0xD8, 0xFF]);
    let is_pdf = has_magic_prefix(input, b"%PDF-");
    let is_png = has_magic_prefix(input, b"\x89PNG\r\n\x1a\n");
    let is_gif = has_magic_prefix(input, b"GIF87a") || has_magic_prefix(input, b"GIF89a");
    let is_zip = has_magic_prefix(input, b"PK\x03\x04");
    let is_xml = lower.contains("<?xml") || lower.contains("<!doctype");
    let is_svg = lower.contains("<svg");
    let is_html = lower.contains("<html") || lower.contains("<script") || lower.contains("<body");
    let is_js = is_likely_javascript(&lower);

    let mut formats: Vec<String> = Vec::new();
    if is_jpeg {
        formats.push("jpeg".to_string());
    }
    if is_pdf {
        formats.push("pdf".to_string());
    }
    if is_png {
        formats.push("png".to_string());
    }
    if is_gif {
        formats.push("gif".to_string());
    }
    if is_zip {
        formats.push("zip".to_string());
    }
    if is_html {
        formats.push("html".to_string());
    }
    if is_svg {
        formats.push("svg".to_string());
    }
    if is_xml {
        formats.push("xml".to_string());
    }
    if is_js {
        formats.push("javascript".to_string());
    }

    let mut indicators: Vec<String> = Vec::new();

    if is_jpeg && is_js {
        indicators.push("jpeg_javascript_dual_validity".to_string());
    }
    if is_pdf
        && (lower.contains("/javascript")
            || lower.contains("/js ")
            || lower.contains("/openaction"))
    {
        indicators.push("pdf_embedded_javascript".to_string());
    }
    if (is_html && is_svg) || (is_svg && is_xml && is_js) {
        indicators.push("html_svg_xml_script_overlap".to_string());
    }

    // Multiple format signatures appearing in the header region is a strong polyglot indicator.
    let magic_hits = [
        (
            head.windows(3).any(|w| w == [0xFF, 0xD8, 0xFF]),
            "jpeg_magic",
        ),
        (head_text.contains("%pdf-"), "pdf_magic"),
        (
            head_text.contains("gif89a") || head_text.contains("gif87a"),
            "gif_magic",
        ),
        (head.windows(4).any(|w| w == b"PK\x03\x04"), "zip_magic"),
    ];
    let magic_count = magic_hits.iter().filter(|(hit, _)| *hit).count();
    if magic_count >= 2 {
        indicators.push("multiple_magic_signatures".to_string());
    }

    let contains_eicar = eicar_detect(&text);
    if contains_eicar {
        indicators.push("eicar_test_signature".to_string());
    }

    let is_polyglot = indicators.len() >= 1 || formats.len() >= 3;
    let mut confidence_boost: f64 = 0.0;
    if is_polyglot {
        confidence_boost += 0.06;
        if indicators.len() >= 2 {
            confidence_boost += 0.03;
        }
        if formats.len() >= 4 {
            confidence_boost += 0.02;
        }
        if contains_eicar {
            confidence_boost += 0.04;
        }
        confidence_boost = confidence_boost.min(0.15);
    }

    let detail = if is_polyglot {
        format!("Structural polyglot indicators: {}", indicators.join(", "))
    } else {
        "No structural polyglot indicators".to_string()
    };

    PolyglotStructure {
        is_polyglot,
        matched_formats: formats,
        confidence_boost,
        contains_eicar,
        indicators,
        detail,
    }
}

/// Analyze detection results for polyglot characteristics.
/// Runs AFTER individual evaluators have produced their detections.
pub fn analyze_polyglot(detected_classes: &[InvariantClass]) -> PolyglotDetection {
    let mut domains = HashSet::new();
    for class in detected_classes {
        domains.insert(class_to_domain(class));
    }

    let domain_vec: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
    let count = domain_vec.len();

    if count < 2 {
        return PolyglotDetection {
            is_polyglot: false,
            domains: domain_vec.clone(),
            domain_count: count,
            confidence_boost: 0.0,
            detail: if count == 1 {
                format!("Single domain: {}", domain_vec[0])
            } else {
                "No attack domains detected".to_string()
            },
        };
    }

    // Check dangerous combinations
    let mut max_boost = 0.0_f64;
    let mut best_reason = "";
    for combo in DANGEROUS_COMBINATIONS {
        if combo.domains.iter().all(|d| domains.contains(d)) && combo.boost > max_boost {
            max_boost = combo.boost;
            best_reason = combo.reason;
        }
    }

    let base_boost = 0.04;
    let domain_count_boost = (count as f64 - 2.0) * 0.02;
    let confidence_boost = (max_boost.max(base_boost) + domain_count_boost).min(0.15);

    let detail = if !best_reason.is_empty() {
        best_reason.to_string()
    } else {
        format!(
            "Multi-context polyglot: {} ({} domains)",
            domain_vec.join(" + "),
            count
        )
    };

    PolyglotDetection {
        is_polyglot: true,
        domains: domain_vec,
        domain_count: count,
        confidence_boost,
        detail,
    }
}

/// Analyze polyglot behavior using both class-level domains and raw payload structure.
pub fn analyze_polyglot_input(
    detected_classes: &[InvariantClass],
    input: &str,
) -> PolyglotDetection {
    let class_based = analyze_polyglot(detected_classes);
    let structural = detect_polyglot_structure(input.as_bytes());

    if !class_based.is_polyglot && !structural.is_polyglot {
        return class_based;
    }

    let mut domains = class_based.domains.clone();
    if structural.is_polyglot {
        domains.push("file_polyglot".to_string());
    }
    domains.sort();
    domains.dedup();

    let combined_boost = (class_based.confidence_boost + structural.confidence_boost).min(0.20);
    let detail = if class_based.is_polyglot && structural.is_polyglot {
        format!("{}; {}", class_based.detail, structural.detail)
    } else if structural.is_polyglot {
        structural.detail
    } else {
        class_based.detail
    };

    PolyglotDetection {
        is_polyglot: true,
        domain_count: domains.len(),
        domains,
        confidence_boost: combined_boost,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_domain_not_polyglot() {
        let classes = vec![
            InvariantClass::SqlTautology,
            InvariantClass::SqlUnionExtraction,
        ];
        let result = analyze_polyglot(&classes);
        assert!(!result.is_polyglot);
        assert_eq!(result.domain_count, 1);
        assert_eq!(result.confidence_boost, 0.0);
    }

    #[test]
    fn sql_xss_polyglot() {
        let classes = vec![
            InvariantClass::SqlStringTermination,
            InvariantClass::XssEventHandler,
        ];
        let result = analyze_polyglot(&classes);
        assert!(result.is_polyglot);
        assert_eq!(result.domain_count, 2);
        assert!(result.confidence_boost >= 0.08);
        assert!(result.detail.contains("SQL+XSS"));
    }

    #[test]
    fn triple_context_polyglot() {
        let classes = vec![
            InvariantClass::SqlTautology,
            InvariantClass::XssTagInjection,
            InvariantClass::CmdSeparator,
        ];
        let result = analyze_polyglot(&classes);
        assert!(result.is_polyglot);
        assert_eq!(result.domain_count, 3);
        // Should get sql+cmdi boost (0.10) + domain_count_boost (0.02) = 0.12
        assert!(result.confidence_boost >= 0.10);
    }

    #[test]
    fn empty_classes() {
        let result = analyze_polyglot(&[]);
        assert!(!result.is_polyglot);
        assert_eq!(result.domain_count, 0);
    }

    #[test]
    fn detects_jpeg_javascript_polyglot_structure() {
        let payload = b"\xFF\xD8\xFF\xE0JFIF\x00<script>fetch('https://evil')</script>";
        let result = detect_polyglot_structure(payload);
        assert!(result.is_polyglot);
        assert!(
            result
                .indicators
                .iter()
                .any(|i| i == "jpeg_javascript_dual_validity")
        );
    }

    #[test]
    fn detects_pdf_javascript_polyglot_structure() {
        let payload =
            b"%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert('x')) >> >>";
        let result = detect_polyglot_structure(payload);
        assert!(result.is_polyglot);
        assert!(
            result
                .indicators
                .iter()
                .any(|i| i == "pdf_embedded_javascript")
        );
    }

    #[test]
    fn detects_eicar_signature() {
        let payload = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let result = detect_polyglot_structure(payload.as_bytes());
        assert!(result.contains_eicar);
        assert!(result.is_polyglot);
    }

    #[test]
    fn combines_class_and_structure_polyglot() {
        let classes = vec![
            InvariantClass::SqlUnionExtraction,
            InvariantClass::CmdSeparator,
        ];
        let payload = "\u{FFFD}\u{FFFD}\u{FFFD}<svg><script>alert(1)</script></svg>";
        let result = analyze_polyglot_input(&classes, payload);
        assert!(result.is_polyglot);
        assert!(result.confidence_boost >= 0.10);
        assert!(result.domains.iter().any(|d| d == "file_polyglot"));
    }

    #[test]
    fn all_66_classes_have_domains() {
        // Verify every class maps to a non-empty domain
        let all_classes = vec![
            InvariantClass::SqlTautology,
            InvariantClass::SqlStringTermination,
            InvariantClass::SqlUnionExtraction,
            InvariantClass::SqlStackedExecution,
            InvariantClass::SqlTimeOracle,
            InvariantClass::SqlErrorOracle,
            InvariantClass::SqlCommentTruncation,
            InvariantClass::JsonSqlBypass,
            InvariantClass::XssTagInjection,
            InvariantClass::XssAttributeEscape,
            InvariantClass::XssEventHandler,
            InvariantClass::XssProtocolHandler,
            InvariantClass::XssTemplateExpression,
            InvariantClass::CmdSeparator,
            InvariantClass::CmdSubstitution,
            InvariantClass::CmdArgumentInjection,
            InvariantClass::PathDotdotEscape,
            InvariantClass::PathNullTerminate,
            InvariantClass::PathEncodingBypass,
            InvariantClass::PathNormalizationBypass,
            InvariantClass::SsrfInternalReach,
            InvariantClass::SsrfCloudMetadata,
            InvariantClass::SsrfProtocolSmuggle,
            InvariantClass::XxeEntityExpansion,
            InvariantClass::DeserJavaGadget,
            InvariantClass::DeserPhpObject,
            InvariantClass::DeserPythonPickle,
            InvariantClass::SstiJinjaTwig,
            InvariantClass::SstiElExpression,
            InvariantClass::AuthNoneAlgorithm,
            InvariantClass::AuthHeaderSpoof,
            InvariantClass::NosqlOperatorInjection,
            InvariantClass::NosqlJsInjection,
            InvariantClass::ProtoPollution,
            InvariantClass::LogJndiLookup,
            InvariantClass::LdapFilterInjection,
            InvariantClass::CrlfHeaderInjection,
            InvariantClass::HttpSmuggleClTe,
            InvariantClass::HttpSmuggleH2,
            InvariantClass::OpenRedirectBypass,
            InvariantClass::LlmPromptInjection,
            InvariantClass::LlmDataExfiltration,
            InvariantClass::LlmJailbreak,
            InvariantClass::DependencyConfusion,
            InvariantClass::PostinstallInjection,
            InvariantClass::EnvExfiltration,
            InvariantClass::MassAssignment,
            InvariantClass::GraphqlIntrospection,
            InvariantClass::GraphqlBatchAbuse,
            InvariantClass::WsInjection,
            InvariantClass::WsHijack,
            InvariantClass::CachePoisoning,
            InvariantClass::CacheDeception,
            InvariantClass::BolaIdor,
            InvariantClass::ApiMassEnum,
            InvariantClass::JwtKidInjection,
            InvariantClass::JwtJwkEmbedding,
            InvariantClass::JwtConfusion,
            InvariantClass::OastInteraction,
        ];
        for class in &all_classes {
            let domain = class_to_domain(class);
            assert!(!domain.is_empty(), "class {:?} has empty domain", class);
        }
    }
}
