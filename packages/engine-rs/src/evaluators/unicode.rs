//! Unicode Attack Evaluator — Level 2
//!
//! Detects attacks that exploit Unicode normalization, bidirectional control
//! characters, homoglyphs, and encoding confusion to bypass security controls.
//!
//! Key attack classes:
//!   - Unicode normalization bypass (NFKC/NFKD collapse creates injection vectors)
//!   - Bidi override (RTL/LTR control chars hide malicious content)
//!   - Homoglyph substitution (Cyrillic/Greek lookalikes bypass allowlists)
//!   - Overlong UTF-8 encoding (IDS/WAF bypass)
//!   - Zero-width characters (invisible payload smuggling)

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

/// Bidirectional control characters (Unicode).
const BIDI_CHARS: &[char] = &[
    '\u{200E}', // LRM - Left-to-Right Mark
    '\u{200F}', // RLM - Right-to-Left Mark
    '\u{202A}', // LRE - Left-to-Right Embedding
    '\u{202B}', // RLE - Right-to-Left Embedding
    '\u{202C}', // PDF - Pop Directional Formatting
    '\u{202D}', // LRO - Left-to-Right Override
    '\u{202E}', // RLO - Right-to-Left Override
    '\u{2066}', // LRI - Left-to-Right Isolate
    '\u{2067}', // RLI - Right-to-Left Isolate
    '\u{2068}', // FSI - First Strong Isolate
    '\u{2069}', // PDI - Pop Directional Isolate
];

/// Zero-width characters used for invisible content smuggling.
const ZERO_WIDTH: &[char] = &[
    '\u{200B}', // Zero Width Space
    '\u{200C}', // Zero Width Non-Joiner
    '\u{200D}', // Zero Width Joiner
    '\u{FEFF}', // BOM / Zero Width No-Break Space
    '\u{2060}', // Word Joiner
    '\u{180E}', // Mongolian Vowel Separator
];

/// Common homoglyph pairs (Cyrillic/Greek lookalikes for Latin).
const HOMOGLYPH_GROUPS: &[(&str, &[char])] = &[
    ("a", &['а', 'ɑ', 'α']),     // Cyrillic а, Latin alpha, Greek alpha
    ("c", &['с', 'ϲ']),           // Cyrillic с, Greek lunate sigma
    ("e", &['е', 'ε']),           // Cyrillic е, Greek epsilon
    ("o", &['о', 'ο', '0']),     // Cyrillic о, Greek omicron
    ("p", &['р', 'ρ']),           // Cyrillic р, Greek rho
    ("x", &['х', 'χ']),           // Cyrillic х, Greek chi
    ("y", &['у', 'γ']),           // Cyrillic у, Greek gamma
    ("s", &['ѕ']),                // Cyrillic ѕ
    ("i", &['і', 'ι']),           // Ukrainian і, Greek iota
    ("d", &['ԁ']),                // Cyrillic d
];

static UNICODE_NORMALIZATION_BYPASS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"[\u{2100}-\u{214F}\u{1D400}-\u{1D7FF}\u{2460}-\u{2473}\u{24B6}-\u{24E9}]+")
        .unwrap()
});

static UNICODE_VARIATION_SELECTOR: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"[\u{FE00}-\u{FE0F}\u{180B}-\u{180D}]+").unwrap()
});

static UNICODE_EXTENDED_HOMOGRAPH: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(
        r"[\u{0430}\u{0435}\u{043E}\u{0440}\u{0441}\u{0445}\u{0443}\u{0455}\u{0456}\u{03B1}\u{03B5}\u{03BF}\u{03C1}\u{0458}]+",
    )
    .unwrap()
});

static UNICODE_LINE_PARA_SEP: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"[\u{2028}\u{2029}]").unwrap()
});

static UNICODE_NONSTANDARD_WS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"[\u{00A0}\u{1680}\u{2000}-\u{200A}\u{202F}\u{205F}\u{3000}\u{2060}]+").unwrap()
});

pub struct UnicodeEvaluator;

impl L2Evaluator for UnicodeEvaluator {
    fn id(&self) -> &'static str {
        "unicode"
    }
    fn prefix(&self) -> &'static str {
        "L2 Unicode"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();

        // 1. Bidirectional control characters
        let bidi_count = input.chars().filter(|c| BIDI_CHARS.contains(c)).count();
        if bidi_count > 0 {
            dets.push(L2Detection {
                detection_type: "unicode_bidi_override".into(),
                confidence: 0.88,
                detail: format!(
                    "{} bidirectional control character(s) detected — text rendering manipulation",
                    bidi_count
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: format!("{} bidi control chars", bidi_count),
                    interpretation: "Bidirectional Unicode control characters (RLO, LRI, etc.) manipulate text rendering direction. Attackers use these to visually hide malicious filenames (e.g., 'harmlesstxt.exe' appears as 'harmlessexe.txt') or disguise URLs in phishing attacks.".into(),
                    offset: 0,
                    property: "User input must not contain Unicode bidirectional control characters (U+200E-U+200F, U+202A-U+202E, U+2066-U+2069).".into(),
                }],
            });
        }

        // 2. Zero-width characters (invisible infiltration)
        let zw_count = input.chars().filter(|c| ZERO_WIDTH.contains(c)).count();
        if zw_count >= 2 {
            dets.push(L2Detection {
                detection_type: "unicode_zero_width".into(),
                confidence: 0.80,
                detail: format!(
                    "{} zero-width character(s) detected — invisible content smuggling",
                    zw_count
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: format!("{} zero-width chars", zw_count),
                    interpretation: "Zero-width characters are invisible but present in the byte stream. They can smuggle data past visual inspection, bypass keyword blocklists (inserting ZWSP between blocked words), or fingerprint text leaks.".into(),
                    offset: 0,
                    property: "User input should be stripped of zero-width characters (U+200B-U+200D, U+FEFF, U+2060) before processing.".into(),
                }],
            });
        }

        // 3. Homoglyph detection (mixed scripts)
        let has_latin = input.chars().any(|c| c.is_ascii_alphabetic());
        let has_cyrillic = input.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c));
        let has_greek = input.chars().any(|c| ('\u{0370}'..='\u{03FF}').contains(&c));

        if has_latin && (has_cyrillic || has_greek) {
            // Mixed script — potential homoglyph attack
            let mut homoglyph_count = 0;
            for &(_latin, lookalikes) in HOMOGLYPH_GROUPS {
                for c in input.chars() {
                    if lookalikes.contains(&c) {
                        homoglyph_count += 1;
                    }
                }
            }

            if homoglyph_count > 0 {
                dets.push(L2Detection {
                    detection_type: "unicode_homoglyph".into(),
                    confidence: 0.85,
                    detail: format!(
                        "Mixed script with {} homoglyph character(s) — IDN homograph or allowlist bypass",
                        homoglyph_count
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: input[..input.len().min(80)].to_string(),
                        interpretation: "Input mixes Latin with Cyrillic/Greek characters that are visually identical (homoglyphs). This technique bypasses domain allowlists (аpple.com vs apple.com), keyword filters, and visual inspection. It's the core of IDN homograph attacks.".into(),
                        offset: 0,
                        property: "Input containing mixed Unicode scripts must be normalized and script-consistency validated. Homoglyph characters must be mapped to their canonical Latin equivalents.".into(),
                    }],
                });
            }
        }

        // 4. Overlong UTF-8 encoding indicators
        let overlong_patterns = [
            "%c0%af",      // Overlong / (directory traversal bypass)
            "%c0%ae",      // Overlong . (directory traversal bypass)
            "%c1%1c",      // Overlong / (alternative)
            "%c0%2f",      // Overlong /
            "%e0%80%af",   // 3-byte overlong /
            "%f0%80%80%af", // 4-byte overlong /
        ];

        let lower = input.to_ascii_lowercase();
        for pattern in &overlong_patterns {
            if lower.contains(pattern) {
                let pos = lower.find(pattern).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "unicode_overlong_utf8".into(),
                    confidence: 0.93,
                    detail: format!("Overlong UTF-8 encoding detected: {} — WAF/IDS bypass via encoding confusion", pattern),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: pattern.to_string(),
                        interpretation: "Overlong UTF-8 encoding represents ASCII characters using more bytes than necessary. Security controls that validate the encoded form but the application decodes before use will miss the attack. CVE-2000-0884 (IIS Unicode directory traversal) is the classic example.".into(),
                        offset: pos,
                        property: "UTF-8 decoders must reject overlong sequences (RFC 3629). Security validation must occur after full Unicode normalization.".into(),
                    }],
                });
                break;
            }
        }

        // 5. Fullwidth characters (Unicode codepoints that normalize to ASCII equivalents)
        let fullwidth: Vec<char> = input.chars().filter(|c| ('\u{FF01}'..='\u{FF5E}').contains(c)).collect();
        if fullwidth.len() >= 2 {
            let ascii_equiv: String = fullwidth.iter().map(|c| {
                char::from_u32(*c as u32 - 0xFF01 + 0x21).unwrap_or('?')
            }).collect();
            dets.push(L2Detection {
                detection_type: "unicode_fullwidth".into(),
                confidence: 0.82,
                detail: format!(
                    "{} fullwidth character(s) detected — normalizes to ASCII: '{}'",
                    fullwidth.len(),
                    ascii_equiv
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: ascii_equiv,
                    interpretation: "Fullwidth Unicode characters (U+FF01-U+FF5E) are visually wider versions of ASCII. When NFKC-normalized, they collapse to their ASCII equivalents. Attackers use this to bypass WAFs (' → ' for SQL injection, ＜script＞ for XSS).".into(),
                    offset: 0,
                    property: "Input must be Unicode-normalized (NFKC) before security validation. Fullwidth ASCII equivalents must be treated as their canonical forms.".into(),
                }],
            });
        }

        // 6. Unicode normalization bypass via mathematical/enclosed alphanumerics
        if let Some(m) = UNICODE_NORMALIZATION_BYPASS.find(input) {
            dets.push(L2Detection {
                detection_type: "unicode_normalization_bypass".into(),
                confidence: 0.87,
                detail: "Unicode mathematical/enclosed alphanumeric symbols detected — NFKC normalization bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Mathematical alphanumeric symbols (Unicode block 1D400-1D7FF) and enclosed alphanumerics (2460-24E9) NFKC-normalize to standard ASCII characters. WAFs scanning for ASCII keywords miss these payloads while downstream systems that normalize text execute them".into(),
                    offset: m.start(),
                    property: "Input must be NFKC-normalized before keyword scanning. Mathematical and enclosed alphanumeric Unicode blocks must be treated as their ASCII equivalents".into(),
                }],
            });
        }

        // 7. Unicode variation selectors
        if let Some(m) = UNICODE_VARIATION_SELECTOR.find(input) {
            dets.push(L2Detection {
                detection_type: "unicode_variation_selector".into(),
                confidence: 0.84,
                detail: "Unicode variation selector characters detected — parser/view mismatch obfuscation".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Unicode variation selectors (U+FE00-FE0F) modify character rendering but are ignored by some parsers while visible to others, enabling payload smuggling through systems with inconsistent Unicode handling".into(),
                    offset: m.start(),
                    property: "Variation selector characters must be stripped from all user input as they serve no legitimate purpose in user-generated content and are exclusively used for obfuscation".into(),
                }],
            });
        }

        // 8. Extended Cyrillic/Greek homograph characters
        if let Some(m) = UNICODE_EXTENDED_HOMOGRAPH.find(input) {
            dets.push(L2Detection {
                detection_type: "unicode_extended_homograph".into(),
                confidence: 0.86,
                detail: "Extended Cyrillic/Greek lookalike glyphs detected — homograph attack surface".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Cyrillic (а,е,о,р,с,х,у,ѕ,і) and Greek (α,ε,ο,ρ,ψ) characters that are visually identical to Latin letters are used in IDN homograph attacks and bypass ASCII-only security filters by appearing as legitimate domain names or identifiers".into(),
                    offset: m.start(),
                    property: "Domain names and identifiers must use Punycode/IDN validation. Mixed-script strings combining Cyrillic or Greek with Latin characters must be flagged as homograph attempts".into(),
                }],
            });
        }

        // 9. Unicode line/paragraph separator injection
        if let Some(m) = UNICODE_LINE_PARA_SEP.find(input) {
            dets.push(L2Detection {
                detection_type: "unicode_line_para_separator".into(),
                confidence: 0.88,
                detail: "Unicode line/paragraph separator detected — newline interpretation bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_string(),
                    interpretation: "U+2028 Line Separator and U+2029 Paragraph Separator are interpreted as newlines by JavaScript engines and some XML/HTML parsers. Injecting them into JavaScript string literals that appear single-line to scanners enables comment bypass and code injection".into(),
                    offset: m.start(),
                    property: "U+2028 and U+2029 must be escaped or rejected in all user-controlled string contexts, especially in JavaScript templates and JSON responses".into(),
                }],
            });
        }

        // 10. Non-standard whitespace homoglyphs
        if let Some(m) = UNICODE_NONSTANDARD_WS.find(input) {
            dets.push(L2Detection {
                detection_type: "unicode_nonstandard_whitespace".into(),
                confidence: 0.81,
                detail: "Non-standard Unicode whitespace detected — tokenization/filter bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Non-standard Unicode whitespace characters (NBSP U+00A0, en-space U+2002, em-space U+2003, narrow no-break U+202F, ideographic space U+3000) bypass ASCII whitespace filters in SQL injection, shell injection, and XSS payloads while being recognized as whitespace by target parsers".into(),
                    offset: m.start(),
                    property: "Only ASCII whitespace (0x09, 0x0A, 0x0D, 0x20) should be permitted in security-sensitive contexts. All Unicode whitespace variants must be normalized or rejected".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "unicode_bidi_override"
            | "unicode_zero_width"
            | "unicode_homoglyph"
            | "unicode_overlong_utf8"
            | "unicode_fullwidth"
            | "unicode_normalization_bypass"
            | "unicode_variation_selector"
            | "unicode_extended_homograph"
            | "unicode_line_para_separator"
            | "unicode_nonstandard_whitespace" => Some(InvariantClass::UnicodeBypass),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bidi_override() {
        let eval = UnicodeEvaluator;
        let input = format!("harmless{}\u{202E}txt.exe", "file");
        let dets = eval.detect(&input);
        assert!(dets.iter().any(|d| d.detection_type == "unicode_bidi_override"));
    }

    #[test]
    fn detects_zero_width_smuggling() {
        let eval = UnicodeEvaluator;
        let input = "pass\u{200B}word\u{200B}bypass";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "unicode_zero_width"));
    }

    #[test]
    fn detects_cyrillic_homoglyph() {
        let eval = UnicodeEvaluator;
        // Mix Latin 'a' + 'pple' with Cyrillic 'а' (U+0430) at the start
        let input = "\u{0430}pple.com";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "unicode_homoglyph"));
    }

    #[test]
    fn detects_overlong_utf8() {
        let eval = UnicodeEvaluator;
        let dets = eval.detect("..%c0%af..%c0%afetc/passwd");
        assert!(dets.iter().any(|d| d.detection_type == "unicode_overlong_utf8"));
    }

    #[test]
    fn detects_fullwidth_bypass() {
        let eval = UnicodeEvaluator;
        // Fullwidth < and > (U+FF1C, U+FF1E) with 'script'
        let input = "\u{FF1C}script\u{FF1E}alert(1)";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "unicode_fullwidth"));
    }

    #[test]
    fn test_normalization_bypass() {
        let eval = UnicodeEvaluator;
        let input = "x\u{1D400}y";
        let dets = eval.detect(input);
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "unicode_normalization_bypass"));
    }

    #[test]
    fn test_variation_selector() {
        let eval = UnicodeEvaluator;
        let input = "safe\u{FE0F}";
        let dets = eval.detect(input);
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "unicode_variation_selector"));
    }

    #[test]
    fn test_extended_homograph() {
        let eval = UnicodeEvaluator;
        let input = "micro\u{0455}oft.com";
        let dets = eval.detect(input);
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "unicode_extended_homograph"));
    }

    #[test]
    fn test_line_sep() {
        let eval = UnicodeEvaluator;
        let input = "a\u{2028}b";
        let dets = eval.detect(input);
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "unicode_line_para_separator"));
    }

    #[test]
    fn test_nonstandard_ws() {
        let eval = UnicodeEvaluator;
        let input = "cmd\u{00A0}arg";
        let dets = eval.detect(input);
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "unicode_nonstandard_whitespace"));
    }

    #[test]
    fn no_detection_for_normal_ascii() {
        let eval = UnicodeEvaluator;
        let dets = eval.detect("hello world normal text");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = UnicodeEvaluator;
        assert_eq!(
            eval.map_class("unicode_homoglyph"),
            Some(InvariantClass::UnicodeBypass)
        );
    }
}
