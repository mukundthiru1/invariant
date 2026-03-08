//! Entropy Analyzer — Statistical Anomaly Detection Primitive
//!
//! Attack payloads have DIFFERENT statistical properties than legitimate input.
//! This module captures universal properties:
//!
//!   1. Shannon Entropy — information density per character
//!   2. Character Class Distribution — alpha/numeric/special/control ratios
//!   3. Repetition Index — n-gram uniqueness ratio
//!   4. Structural Density — metacharacter-to-content ratio
//!   5. Composite Anomaly Score — weighted signal combination
//!
//! These are UNIVERSAL properties that apply to every attack class.
//! They serve as a cross-cutting confidence signal, never a gate.

use std::collections::{HashMap, HashSet};

// ── Metacharacter Set ─────────────────────────────────────────────

const META_CHARS: &[char] = &[
    '(', ')', '[', ']', '{', '}', '<', '>', '|', ';', '&', '$', '#', '`', '\\', '/', '=', '"',
    '\'', '%', '@', '!', '^', '~', '*', '?', '+',
];

fn is_meta(ch: char) -> bool {
    META_CHARS.contains(&ch)
}

// ── Shannon Entropy ───────────────────────────────────────────────

/// Shannon entropy in bits per character: H = -Σ p(x) * log2(p(x))
fn shannon_entropy_filtered<F>(input: &str, mut skip: F) -> f64
where
    F: FnMut(char) -> bool,
{
    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;
    for ch in input.chars() {
        if skip(ch) {
            continue;
        }
        *freq.entry(ch).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }

    let len = total as f64;
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Shannon entropy in bits per character: H = -Σ p(x) * log2(p(x))
pub fn shannon_entropy(input: &str) -> f64 {
    shannon_entropy_filtered(input, |_| false)
}

/// Shannon entropy ignoring whitespace.
pub fn shannon_entropy_non_whitespace(input: &str) -> f64 {
    shannon_entropy_filtered(input, |ch| ch.is_whitespace())
}

// ── Character Class Distribution ──────────────────────────────────

/// Ratios of character classes in the input (all values 0.0–1.0).
#[derive(Debug, Clone)]
pub struct CharClassDistribution {
    pub alpha: f64,
    pub numeric: f64,
    pub whitespace: f64,
    pub punctuation: f64,
    pub metachar: f64,
    pub control: f64,
    pub other: f64,
}

pub fn char_class_distribution(input: &str) -> CharClassDistribution {
    if input.is_empty() {
        return CharClassDistribution {
            alpha: 0.0,
            numeric: 0.0,
            whitespace: 0.0,
            punctuation: 0.0,
            metachar: 0.0,
            control: 0.0,
            other: 0.0,
        };
    }

    let (mut alpha, mut numeric, mut ws, mut punct) = (0usize, 0, 0, 0);
    let (mut meta, mut ctrl, mut other) = (0usize, 0, 0);

    for ch in input.chars() {
        if ch.is_ascii_alphabetic() {
            alpha += 1;
        } else if ch.is_ascii_digit() {
            numeric += 1;
        } else if ch.is_whitespace() {
            ws += 1;
        } else if is_meta(ch) {
            meta += 1;
        } else if ch == '.' || ch == ',' || ch == ':' || ch == '-' || ch == '_' {
            punct += 1;
        } else if (ch as u32) < 0x20 || ch as u32 == 0x7F {
            ctrl += 1;
        } else {
            other += 1;
        }
    }

    let len = input.chars().count() as f64;
    CharClassDistribution {
        alpha: alpha as f64 / len,
        numeric: numeric as f64 / len,
        whitespace: ws as f64 / len,
        punctuation: punct as f64 / len,
        metachar: meta as f64 / len,
        control: ctrl as f64 / len,
        other: other as f64 / len,
    }
}

// ── Repetition Index ──────────────────────────────────────────────

/// Measures repetitiveness via n-gram uniqueness ratio.
/// Returns 0.0 (no repetition) to 1.0 (fully repetitive).
pub fn repetition_index(input: &str, n: usize) -> f64 {
    let chars: Vec<char> = input.chars().collect();
    if chars.len() < n {
        return 0.0;
    }

    let total = chars.len() - n + 1;
    let mut ngrams = HashSet::new();
    for i in 0..total {
        ngrams.insert(&chars[i..i + n]);
    }

    1.0 - (ngrams.len() as f64 / total as f64)
}

// ── Structural Density ────────────────────────────────────────────

/// Ratio of metacharacters to total characters.
pub fn structural_density(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let total = input.chars().count();
    let meta_count = input.chars().filter(|&ch| is_meta(ch)).count();
    meta_count as f64 / total as f64
}

// ── Anomaly Profile ───────────────────────────────────────────────

/// Full statistical anomaly profile for an input.
#[derive(Debug, Clone)]
pub struct AnomalyProfile {
    pub entropy: f64,
    pub char_classes: CharClassDistribution,
    pub repetition: f64,
    pub structural_density: f64,
    pub anomaly_score: f64,
    pub high_entropy_segments: Vec<EntropySegment>,
    pub uri_entropy_profile: UriEntropyProfile,
    pub signals: Vec<&'static str>,
}

/// Focused high-entropy slice discovered inside a longer input.
#[derive(Debug, Clone)]
pub struct EntropySegment {
    /// Start offset in UTF-8 char indices (not byte offsets).
    pub start: usize,
    /// End offset in UTF-8 char indices (exclusive).
    pub end: usize,
    pub entropy: f64,
    pub length: usize,
}

/// Extract suspicious high-entropy windows with overlap-aware merging.
pub fn entropy_segments(
    input: &str,
    min_window: usize,
    step: usize,
    min_entropy: f64,
) -> Vec<EntropySegment> {
    let chars: Vec<char> = input.chars().collect();
    if input.is_empty() || min_window == 0 || step == 0 || chars.len() < min_window {
        return Vec::new();
    }

    let mut segments: Vec<EntropySegment> = Vec::new();
    let mut segment_start: Option<usize> = None;
    let mut segment_end: usize = 0;

    let mut i = 0usize;
    while i + min_window <= chars.len() {
        let window: String = chars[i..i + min_window].iter().collect();
        let window_entropy = shannon_entropy(&window);

        if window_entropy >= min_entropy {
            if segment_start.is_none() {
                segment_start = Some(i);
            }
            segment_end = i + min_window;
        } else if let Some(start) = segment_start {
            let segment_chars: String = chars[start..segment_end].iter().collect();
            let segment_entropy = shannon_entropy(&segment_chars);
            segments.push(EntropySegment {
                start,
                end: segment_end,
                entropy: segment_entropy,
                length: segment_end.saturating_sub(start),
            });
            segment_start = None;
        }

        i += step;
    }

    if let Some(start) = segment_start {
        let segment_chars: String = chars[start..segment_end].iter().collect();
        let segment_entropy = shannon_entropy(&segment_chars);
        segments.push(EntropySegment {
            start,
            end: segment_end,
            entropy: segment_entropy,
            length: segment_end.saturating_sub(start),
        });
    }

    segments
}

/// Entropy behavior by request/URI sections.
#[derive(Debug, Clone)]
pub struct UriEntropyProfile {
    pub path_entropy: Option<f64>,
    pub query_entropy: Option<f64>,
    pub body_entropy: Option<f64>,
    pub query_vs_path_delta: Option<f64>,
    pub body_vs_path_delta: Option<f64>,
    pub signals: Vec<&'static str>,
}

/// Split a request-like input into path/query/body sections and compare entropy between them.
pub fn entropy_by_uri_parts(input: &str) -> UriEntropyProfile {
    let mut path: &str = input;
    let mut body: Option<&str> = None;

    if let Some(pos) = input.find("\r\n\r\n") {
        path = &input[..pos];
        body = Some(&input[pos + 4..]);
    } else if let Some(pos) = input.find("\n\n") {
        path = &input[..pos];
        body = Some(&input[pos + 2..]);
    }

    let (path_part, query_part) = if let Some(qpos) = path.find('?') {
        (&path[..qpos], Some(&path[qpos + 1..]))
    } else {
        (path, None)
    };

    let path_entropy = if path_part.len() > 2 {
        Some(shannon_entropy(path_part))
    } else {
        None
    };

    let query_entropy = query_part.filter(|q| q.len() > 3).map(shannon_entropy);

    let body_entropy = body.filter(|b| b.len() > 6).map(shannon_entropy);

    let mut signals = Vec::new();

    let query_vs_path_delta = match (query_entropy, path_entropy) {
        (Some(qe), Some(pe)) if query_part.unwrap_or("").len() > 12 => {
            let delta = qe - pe;
            if delta >= 1.0 {
                signals.push("query_entropy_spike");
            }
            Some(delta)
        }
        _ => None,
    };

    let body_vs_path_delta = match (body_entropy, path_entropy) {
        (Some(be), Some(pe)) if body.unwrap_or("").len() > 16 => {
            let delta = be - pe;
            if delta >= 1.0 {
                signals.push("body_entropy_spike");
            }
            Some(delta)
        }
        _ => None,
    };

    if let (Some(delta), Some(qe)) = (query_vs_path_delta, query_entropy) {
        if delta >= 1.0 && qe > 4.3 {
            signals.push("query_entropy_high_and_spiky");
        }
    }

    UriEntropyProfile {
        path_entropy,
        query_entropy,
        body_entropy,
        query_vs_path_delta,
        body_vs_path_delta,
        signals,
    }
}

fn is_base64_alphabet(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' |
        b'a'..=b'z' |
        b'0'..=b'9' |
        b'+' | b'/' | b'='
    )
}

fn is_base64_index(b: u8) -> Option<usize> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as usize),
        b'a'..=b'z' => Some((b - b'a') as usize + 26),
        b'0'..=b'9' => Some((b - b'0') as usize + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn is_hex_index(b: u8) -> Option<usize> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as usize),
        b'a'..=b'f' | b'A'..=b'F' => Some((b.to_ascii_lowercase() - b'a') as usize + 10),
        _ => None,
    }
}

fn chi_squared_stat(counts: &[usize], total: usize) -> f64 {
    if counts.is_empty() || total == 0 {
        return 0.0;
    }
    let expected = total as f64 / counts.len() as f64;
    if expected == 0.0 {
        return 0.0;
    }
    counts
        .iter()
        .map(|&count| {
            let diff = count as f64 - expected;
            (diff * diff) / expected
        })
        .sum()
}

/// Ratio of printable ASCII bytes.
pub fn printable_ascii_ratio(input: &str) -> f64 {
    if input.is_empty() {
        return 1.0;
    }
    let bytes = input.as_bytes();
    let printable = bytes
        .iter()
        .filter(|&&b| matches!(b, 0x20..=0x7e | b'\n' | b'\r' | b'\t'))
        .count();
    printable as f64 / bytes.len() as f64
}

/// Maximum byte-frequency skew (0.0..1.0).
/// Higher values indicate one/few bytes dominate the payload.
pub fn byte_distribution_skew(input: &str) -> f64 {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let max = counts.iter().copied().max().unwrap_or(0) as f64;
    max / bytes.len() as f64
}

/// Index of coincidence over bytes.
/// Random-like streams trend low; language/text tends higher.
pub fn index_of_coincidence(input: &str) -> f64 {
    let bytes = input.as_bytes();
    let n = bytes.len();
    if n < 2 {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let numerator: u128 = counts
        .iter()
        .map(|&c| (c as u128).saturating_mul((c as u128).saturating_sub(1)))
        .sum();
    let denom = (n as u128) * ((n - 1) as u128);
    numerator as f64 / denom as f64
}

/// Approximate normalized Lempel-Ziv complexity (0.0..1.0).
/// Higher means less compressible / more algorithmically complex.
pub fn normalized_lz_complexity(input: &str) -> f64 {
    let bytes = input.as_bytes();
    let n = bytes.len();
    if n < 2 {
        return 0.0;
    }
    let mut i = 0usize;
    let mut c = 1usize;
    let mut l = 1usize;
    let mut k = 1usize;
    let mut k_max = 1usize;

    while l + k <= n {
        if bytes[i + k - 1] == bytes[l + k - 1] {
            k += 1;
            if l + k > n {
                c += 1;
                break;
            }
        } else {
            if k > k_max {
                k_max = k;
            }
            i += 1;
            if i == l {
                c += 1;
                l += k_max;
                if l >= n {
                    break;
                }
                i = 0;
                k = 1;
                k_max = 1;
            } else {
                k = 1;
            }
        }
    }

    let denom = (n as f64 / (n as f64).log2()).max(1.0);
    (c as f64 / denom).min(1.0)
}

fn is_base64_candidate(input: &str) -> bool {
    let s = input.trim();
    if s.len() < 12 {
        return false;
    }
    let bytes = s.as_bytes();
    let mut saw_padding = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'=' {
            if i < bytes.len() - 2 {
                return false;
            }
            if saw_padding {
                return false;
            }
            saw_padding = true;
            let remaining = bytes.len() - i;
            if remaining > 2 {
                return false;
            }
        } else if !is_base64_alphabet(b) {
            return false;
        } else if saw_padding {
            return false;
        }
        i += 1;
    }
    s.len() % 4 == 0 || s.len() % 4 == 2 || s.len() % 4 == 3
}

pub fn is_hex_candidate(input: &str) -> bool {
    let s = input.trim();
    s.len() >= 8 && s.bytes().all(|b| is_hex_index(b).is_some())
}

/// Chi-squared score for base64 alphabet uniformity.
/// Lower score means closer to random-like distribution.
pub fn chi_squared_base64(input: &str) -> Option<f64> {
    let s = input.trim();
    if !is_base64_candidate(s) {
        return None;
    }

    let bytes = s.as_bytes();
    let mut counts = [0usize; 64];
    let mut total = 0usize;

    for &b in bytes {
        if b == b'=' {
            continue;
        }
        let idx = is_base64_index(b)?;
        counts[idx] += 1;
        total += 1;
    }

    if total < 12 {
        return None;
    }

    Some(chi_squared_stat(&counts, total))
}

/// Chi-squared score for hex alphabet uniformity.
/// Lower score means closer to random-like distribution.
pub fn chi_squared_hex(input: &str) -> Option<f64> {
    let s = input.trim();
    if !is_hex_candidate(s) {
        return None;
    }
    if s.len() < 12 {
        return None;
    }

    let mut counts = [0usize; 16];
    for b in s.bytes() {
        let idx = is_hex_index(b)?;
        counts[idx] += 1;
    }

    Some(chi_squared_stat(&counts, s.len()))
}

/// Compute full anomaly profile with calibrated thresholds.
pub fn compute_anomaly_profile(input: &str) -> AnomalyProfile {
    let mut signals: Vec<&'static str> = Vec::new();
    let mut score = 0.0_f64;
    let len = input.len();
    let segments = entropy_segments(input, 12, 2, 4.8);
    let compact_input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let compact_entropy = shannon_entropy(&compact_input);
    let compact_segments = if compact_input.is_empty() {
        Vec::new()
    } else {
        entropy_segments(&compact_input, 12, 2, 4.8)
    };
    let compact_repetition = if compact_input.is_empty() {
        0.0
    } else {
        repetition_index(&compact_input, 3)
    };
    let uri_profile = entropy_by_uri_parts(input);

    // ── Entropy ──
    let entropy = shannon_entropy(input);
    if len > 10 && entropy < 2.5 {
        signals.push("low_entropy");
        score += 0.20;
    }
    if len > 10 && entropy > 5.5 {
        signals.push("high_entropy");
        score += 0.15;
    }
    if len > 10
        && compact_entropy > 5.4
        && compact_entropy > entropy + 0.45
        && !compact_input.is_empty()
    {
        signals.push("high_entropy_after_whitespace_stripping");
        score += 0.12;
    }

    // ── Character classes ──
    let classes = char_class_distribution(input);
    if classes.metachar > 0.15 {
        signals.push("high_metachar");
        score += 0.25;
    } else if classes.metachar > 0.08 {
        signals.push("moderate_metachar");
        score += 0.10;
    }
    if len > 20 && classes.alpha < 0.30 {
        signals.push("low_alpha");
        score += 0.15;
    }
    if len > 200 && classes.numeric + classes.alpha < 0.30 && classes.other > 0.30 {
        signals.push("low_meaningful_mix");
        score += 0.05;
    }
    if classes.control > 0.0 {
        signals.push("control_chars");
        score += 0.20;
    }

    let printable_ratio = printable_ascii_ratio(input);
    if len > 24 && printable_ratio < 0.75 {
        signals.push("binary_like_payload");
        score += 0.10;
    }

    let byte_skew = byte_distribution_skew(input);
    if len > 40 && byte_skew > 0.30 {
        signals.push("byte_distribution_skew");
        score += 0.08;
    }

    let ioc = index_of_coincidence(input);
    if len > 32 && ioc < 0.02 && entropy > 4.4 {
        signals.push("random_like_stream");
        score += 0.08;
    } else if len > 32 && ioc > 0.11 && classes.alpha < 0.2 {
        signals.push("high_ioc_symbolic_payload");
        score += 0.06;
    }

    let lz = normalized_lz_complexity(input);
    let rep = repetition_index(input, 3);
    if len > 48 && lz > 0.72 && entropy > 4.2 {
        signals.push("high_lz_complexity");
        score += 0.08;
    } else if len > 24 && lz < 0.20 && rep > 0.55 {
        signals.push("templated_low_complexity_payload");
        score += 0.05;
    }
    if compact_repetition > rep + 0.25 {
        signals.push("repetition_hidden_by_whitespace");
        score += 0.05;
    }

    // ── Repetition ──
    if rep > 0.7 {
        signals.push("high_repetition");
        score += 0.20;
    } else if rep > 0.5 {
        signals.push("moderate_repetition");
        score += 0.08;
    }

    // ── Structural density ──
    let density = structural_density(input);
    if density > 0.25 {
        signals.push("high_structural_density");
        score += 0.20;
    } else if density > 0.12 {
        signals.push("moderate_structural_density");
        score += 0.08;
    }

    // ── Length anomalies ──
    if len > 500 && entropy > 4.5 {
        signals.push("long_high_entropy");
        score += 0.10;
    }
    if len < 30 && len > 3 && classes.metachar > 0.20 {
        signals.push("short_high_metachar");
        score += 0.12;
    }
    if segments.len() >= 1 && segments.iter().all(|s| s.entropy > 4.8) {
        signals.push("embedded_high_entropy_segment");
        score += 0.12;
        if segments.len() > 1 {
            signals.push("multiple_high_entropy_segments");
            score += 0.10;
        }
    } else if segments.is_empty() && !compact_segments.is_empty() {
        signals.push("embedded_high_entropy_segment_after_whitespace_stripping");
        score += 0.10;
    }

    if uri_profile.query_entropy.is_some() || uri_profile.body_entropy.is_some() {
        for &s in &uri_profile.signals {
            signals.push(s);
        }
        if let Some(delta) = uri_profile.query_vs_path_delta {
            if delta >= 1.6 {
                score += 0.08;
            } else if delta >= 0.95 {
                score += 0.04;
            }
        }
        if let Some(delta) = uri_profile.body_vs_path_delta {
            if delta >= 1.5 {
                score += 0.10;
            } else if delta >= 0.90 {
                score += 0.05;
            }
        }
    }

    if let Some(cs) = chi_squared_base64(input) {
        if cs < 120.0 {
            signals.push("base64_chi2");
            score += 0.10;
        }
    }
    if let Some(cs) = chi_squared_hex(input) {
        if cs < 40.0 {
            signals.push("hex_chi2");
            score += 0.10;
        }
    }

    AnomalyProfile {
        entropy,
        char_classes: classes,
        repetition: rep,
        structural_density: density,
        high_entropy_segments: segments,
        uri_entropy_profile: uri_profile,
        anomaly_score: score.min(1.0),
        signals,
    }
}

// ── Cross-Cutting Integration API ─────────────────────────────────

/// Confidence multiplier based on statistical anomaly.
/// > 1.0 = anomalous → boost, = 1.0 = normal, < 1.0 = surprisingly normal.
/// Never gates detection — only adjusts confidence.
pub fn anomaly_confidence_multiplier(input: &str) -> f64 {
    if input.len() < 10 {
        return 1.0;
    }
    let profile = compute_anomaly_profile(input);
    if profile.anomaly_score >= 0.50 {
        1.0 + (profile.anomaly_score - 0.50) * 0.15
    } else if profile.anomaly_score <= 0.10 && profile.signals.is_empty() {
        0.97
    } else {
        1.0
    }
}

/// Check if input shows encoding evasion via entropy analysis.
pub fn is_likely_encoded(input: &str) -> bool {
    if input.len() < 15 {
        return false;
    }
    let entropy = shannon_entropy(input);
    let entropy_non_ws = shannon_entropy_non_whitespace(input);
    let classes = char_class_distribution(input);
    let ioc = index_of_coincidence(input);
    let printable = printable_ascii_ratio(input);

    // Base64-like: elevated entropy, mostly alphanumeric
    if (entropy > 4.2 || entropy_non_ws > 4.2)
        && classes.alpha + classes.numeric > 0.75
        && classes.whitespace < 0.05
        && classes.punctuation < 0.05
    {
        return true;
    }

    if (entropy > 4.6 || entropy_non_ws > 4.6) && ioc < 0.02 && printable > 0.95 {
        return true;
    }

    // Hex-encoded: percent-encoded sequences

    if let Some(cs) = chi_squared_base64(input) {
        if cs < 120.0 {
            return true;
        }
    }
    if let Some(cs) = chi_squared_hex(input) {
        if cs < 40.0 {
            return true;
        }
    }

    let bytes = input.as_bytes();
    let mut pct_count = 0u32;
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' && bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit()
        {
            pct_count += 1;
            i += 3;
        } else {
            i += 1;
        }
    }
    if pct_count >= 4 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn entropy_uniform() {
        let e = shannon_entropy("abcdefgh");
        assert!(e > 2.9 && e < 3.1, "expected ~3.0, got {e}");
    }

    #[test]
    fn entropy_sql_injection() {
        let e = shannon_entropy("' OR 1=1 -- ' OR 1=1 -- ' OR 1=1 --");
        assert!(
            e < 3.5,
            "repetitive SQL payload should have low entropy, got {e}"
        );
    }

    #[test]
    fn shannon_entropy_single_char_repeated_10k() {
        let input = "A".repeat(10_000);
        assert_eq!(shannon_entropy(&input), 0.0);
        assert_eq!(shannon_entropy_non_whitespace(&input), 0.0);
    }

    #[test]
    fn shannon_entropy_printable_ascii_is_high() {
        let input: String = (0x20u8..=0x7E).map(char::from).collect();
        assert!(
            shannon_entropy(&input) > 5.8,
            "expected high printable ASCII entropy, got {}",
            shannon_entropy(&input)
        );
    }

    #[test]
    fn shannon_entropy_handles_binary_like_input() {
        let bytes = [0x00u8, 0xFF, 0x10, 0x7F, b'A', b'\n', 0x80];
        let input = String::from_utf8_lossy(&bytes).to_string();
        let e = shannon_entropy(&input);
        assert!(
            e > 1.0,
            "binary-like payload should still yield entropy, got {e}"
        );
        let _ = is_likely_encoded(&input);
    }

    #[test]
    fn shannon_entropy_unicode_heavy_input() {
        let input = "火".repeat(5_000);
        assert!(
            shannon_entropy(&input) < 0.5,
            "uniform unicode should be low entropy, got {}",
            shannon_entropy(&input)
        );
        assert_eq!(
            shannon_entropy_non_whitespace(&input),
            shannon_entropy(&input)
        );
    }

    #[test]
    fn entropy_segments_alternating_high_low_blocks() {
        let low_entropy = "AAAAAA".repeat(20);
        // High-entropy block: every character unique, covering many char classes
        let high_entropy = "aB3!xZ9@qR7#wK1$mN5%pL2^vT8&cF4*jH6(gY0)dSuE";
        let input = format!("{low_entropy}{high_entropy}{low_entropy}{high_entropy}");
        let segments = entropy_segments(&input, 10, 1, 3.0);
        assert!(
            segments.len() >= 2,
            "expected at least two high-entropy segments, got {:?}",
            segments
        );
        assert!(segments.iter().any(|s| s.entropy > 3.0));
    }

    #[test]
    fn entropy_profile_detects_whitespace_obfuscation() {
        // Use a high-entropy payload with many distinct characters so that
        // compact_entropy > 5.4 and compact_entropy > full_entropy + 0.45
        let core = "aB3!xZ9@qR7#wK1$mN5%pL2^vT8&cF4*jH6(gY0)dS+uE-fG=hI/kJ\\lM|nO;rP:tQ<uR>wS?xT[yU]zA{bC}cD~eF`gH,iJ.kL mN";
        let padded: String = core.chars().flat_map(|c| [c, ' ']).collect();
        let compact_entropy = shannon_entropy_non_whitespace(&padded);
        let full_entropy = shannon_entropy(&padded);
        assert!(
            compact_entropy > full_entropy + 0.05,
            "compact={compact_entropy} full={full_entropy}"
        );
        let profile = compute_anomaly_profile(&padded);
        assert!(
            profile.signals.iter().any(|s| matches!(
                *s,
                "high_entropy_after_whitespace_stripping"
                    | "embedded_high_entropy_segment_after_whitespace_stripping"
            )),
            "signals: {:?}, compact_entropy={compact_entropy}, full_entropy={full_entropy}",
            profile.signals
        );
    }

    #[test]
    fn index_of_coincidence_no_overflow_for_large_repetitions() {
        let input = "AB".repeat(50_000);
        let ioc = index_of_coincidence(&input);
        assert!(ioc > 0.45);
        assert!(ioc <= 1.0);
    }

    #[test]
    fn likely_encoded_detects_whitespace_spaced_payload() {
        let core = "QmFzZTY0U3RyZWV0";
        let padded: String = core.chars().flat_map(|c| [c, '\t']).collect();
        let _ = is_likely_encoded(&padded);
    }

    #[test]
    fn structural_density_normal_text() {
        let d = structural_density("Hello this is a normal search query");
        assert!(
            d < 0.05,
            "normal text should have low structural density, got {d}"
        );
    }

    #[test]
    fn structural_density_attack() {
        let d = structural_density("';|$(cat /etc/passwd)&& rm -rf /");
        assert!(
            d > 0.15,
            "attack payload should have high structural density, got {d}"
        );
    }

    #[test]
    fn anomaly_profile_benign() {
        let p = compute_anomaly_profile("Hello world this is a normal message");
        assert!(
            p.anomaly_score < 0.20,
            "benign input should have low anomaly: {}",
            p.anomaly_score
        );
    }

    #[test]
    fn anomaly_profile_attack() {
        // High metachar density payload triggers anomaly signals
        let p = compute_anomaly_profile("';|$(cat /etc/passwd)&&rm -rf /;echo$IFS'pwned'");
        assert!(
            p.anomaly_score > 0.10,
            "attack should have elevated anomaly: {}",
            p.anomaly_score
        );
    }

    #[test]
    fn multiplier_benign() {
        let m = anomaly_confidence_multiplier("Just a normal search query here");
        assert!(
            (0.95..=1.05).contains(&m),
            "benign multiplier should be near 1.0, got {m}"
        );
    }

    #[test]
    fn likely_encoded_base64() {
        assert!(is_likely_encoded("SGVsbG8gV29ybGQgdGhpcyBpcyBiYXNlNjQ="));
    }

    #[test]
    fn likely_encoded_percent() {
        assert!(is_likely_encoded("%27%20OR%201%3D1%20--%20"));
    }

    #[test]
    fn likely_encoded_hex_uniform_like() {
        assert!(is_likely_encoded("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn entropy_segments_detects_high_entropy_payload() {
        let input = "cmd=run&payload=QmFzZTY0RW5jb2RlZFNlY3JldEhlbGxvV29ybGQxMjM0NQ==&done";
        let segments = entropy_segments(input, 20, 1, 4.0);
        assert!(
            !segments.is_empty(),
            "embedded high-entropy window should be extracted"
        );
        assert!(segments.iter().any(|s| s.entropy > 4.0 && s.length >= 12));
    }

    #[test]
    fn entropy_by_uri_parts_detects_spikes() {
        let req = "/api/v1/report?user=alice&token=QmFzZTY0VG9rZW5NYW5pZmVzdDEyMzQ1Njc4OTA=\r\nHost: x\r\n\r\nWWV0YVNlY3JldFRva2VuSW50ZXJuYWxQYXlsb2Fk";
        let profile = entropy_by_uri_parts(req);
        assert!(
            profile.query_entropy.is_some(),
            "query entropy should be available"
        );
        assert!(
            profile.body_entropy.is_some(),
            "body entropy should be available"
        );
        assert!(
            profile
                .signals
                .iter()
                .any(|s| matches!(*s, "query_entropy_high_and_spiky" | "query_entropy_spike"))
        );
        assert!(
            profile
                .signals
                .iter()
                .any(|s| matches!(*s, "body_entropy_spike"))
        );
    }

    #[test]
    fn chi_square_base64_and_hex() {
        let uniform_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let skewed_base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let uniform_chi = chi_squared_base64(uniform_base64)
            .unwrap_or_else(|| panic!("uniform base64 should be detectable"));
        let skewed_chi = chi_squared_base64(skewed_base64)
            .unwrap_or_else(|| panic!("uniform candidate should be detectable"));
        assert!(
            uniform_chi < skewed_chi,
            "uniform-like base64 should produce lower chi-squared score"
        );

        let uniform_hex = "0123456789abcdef0123456789abcdef";
        let skewed_hex = "00000000000000000000000000000000000000000000";
        let uniform_hex_chi = chi_squared_hex(uniform_hex)
            .unwrap_or_else(|| panic!("uniform hex should be detectable"));
        let skewed_hex_chi = chi_squared_hex(skewed_hex)
            .unwrap_or_else(|| panic!("skewed hex should be detectable"));
        assert!(uniform_hex_chi < skewed_hex_chi);
    }

    #[test]
    fn repetition_high() {
        let r = repetition_index("AAAAAAAAAAAAAAAAAAAAAA", 3);
        assert!(
            r > 0.8,
            "fully repetitive input should have high index, got {r}"
        );
    }

    #[test]
    fn repetition_low() {
        let r = repetition_index("abcdefghijklmnopqrstuvwxyz", 3);
        assert!(r < 0.2, "unique input should have low index, got {r}");
    }

    #[test]
    fn byte_distribution_skew_detects_dominance() {
        let skewed = byte_distribution_skew("AAAAAAAAAAAAAAAAAAAAAAAB");
        let balanced = byte_distribution_skew("ABCDEFGH12345678");
        assert!(skewed > balanced);
    }

    #[test]
    fn index_of_coincidence_separates_randomish_from_text() {
        let text_ioc = index_of_coincidence(
            "this is normal english text repeated this is normal english text",
        );
        let randomish_ioc =
            index_of_coincidence("QmFzZTY0RW5jb2RlZFBheWxvYWRTdHJlYW0xMjM0NTY3ODkwQUJDREVGRw==");
        assert!(text_ioc > randomish_ioc);
    }

    #[test]
    fn normalized_lz_complexity_higher_for_randomish_stream() {
        let low = normalized_lz_complexity("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let high = normalized_lz_complexity("1a9FzQ2kLm8Pw3Xr7Bt0Cv5Ny6Hd4Su");
        assert!(high > low);
    }

    #[test]
    fn anomaly_profile_emits_random_stream_signal() {
        let p = compute_anomaly_profile(
            "QmFzZTY0RW5jb2RlZE1hbGljaW91c1BheWxvYWQxMjM0NTY3ODkwQUJDREVGR0hJSg==",
        );
        assert!(
            p.signals
                .iter()
                .any(|s| *s == "random_like_stream" || *s == "high_lz_complexity")
        );
    }
}
