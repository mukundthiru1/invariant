//! Multi-layer encoding decoder.
//!
//! Attackers use nested encodings to evade detection:
//!   URL → double-URL → HTML entity → Unicode escape → hex → base64
//!
//! This module peels all layers, returning every intermediate form.
//! Why all forms? An attacker might use double-encoding where the
//! intermediate form is the actual payload.

/// Maximum decode depth to prevent infinite loops on pathological input.
const MAX_DECODE_DEPTH: usize = 8;

/// Result of multi-layer decoding.
#[derive(Debug, Clone)]
pub struct DecodedForms {
    /// Original input.
    pub raw: String,
    /// After all decodable layers are peeled.
    pub fully_decoded: String,
    /// Every intermediate form (raw first, fully decoded last).
    pub all_forms: Vec<String>,
    /// Number of encoding layers detected.
    pub encoding_depth: usize,
    /// Whether any encoding was present.
    pub uses_encoding: bool,
    /// UTF-8 and encoding anomaly observations.
    pub anomalies: Vec<String>,
}

/// Decode input through every encoding layer attackers use.
/// Returns all decoded forms — raw AND every intermediate decode.
#[inline]
pub fn multi_layer_decode(input: &str) -> DecodedForms {
    use std::collections::HashSet;

    let mut forms = vec![input.to_owned()];
    let mut current = input.to_owned();
    let mut anomalies_set = HashSet::new();

    collect_encoding_anomalies(input, &mut anomalies_set);

    for _ in 0..MAX_DECODE_DEPTH {
        let decoded = decode_one_layer(&current);
        if decoded == current {
            break;
        }
        collect_encoding_anomalies(&decoded, &mut anomalies_set);
        forms.push(decoded.clone());
        current = decoded;
    }

    collect_encoding_anomalies(&current, &mut anomalies_set);

    // Also try base64 decode if it looks like base64
    if let Some(b64) = try_base64_decode(input) {
        if b64 != input {
            forms.push(b64);
        }
    }

    let mut anomalies = Vec::with_capacity(anomalies_set.len());
    anomalies.extend(anomalies_set);
    anomalies.sort();

    let depth = forms.len() - 1;
    DecodedForms {
        raw: input.to_owned(),
        fully_decoded: current,
        encoding_depth: depth,
        uses_encoding: depth > 0,
        all_forms: forms,
        anomalies,
    }
}

/// Peel one encoding layer. Returns the input unchanged if no decoding applies.
fn decode_one_layer(input: &str) -> String {
    // Overlong UTF-8 percent forms (e.g. %C0%AF, %E0%80%AF, %F0%80%80%AF)
    let overlong_decoded = decode_overlong_utf8(input);
    if overlong_decoded != input {
        return overlong_decoded;
    }

    // URL decode
    if let Some(decoded) = try_url_decode(input) {
        if decoded != input {
            return decoded;
        }
    }

    // HTML entity decode
    let html_decoded = decode_html_entities(input);
    if html_decoded != input {
        return html_decoded;
    }

    // Unicode escapes: \u0027
    let uni_decoded = decode_unicode_escapes(input);
    if uni_decoded != input {
        return uni_decoded;
    }

    // Hex escapes: \x27
    let hex_decoded = decode_hex_escapes(input);
    if hex_decoded != input {
        return hex_decoded;
    }

    // SQL comment-space bypass: /**/ → space
    let sql_decoded = decode_sql_comments(input);
    if sql_decoded != input {
        return sql_decoded;
    }

    input.to_owned()
}

/// URL-decode a string. Returns None if no decoding occurred.
fn try_url_decode(input: &str) -> Option<String> {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_digit(bytes[i + 1]);
            let lo = hex_digit(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push(h << 4 | l);
                i += 3;
                changed = true;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
            changed = true;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }

    if changed {
        let decoded = String::from_utf8(result.clone())
            .unwrap_or_else(|_| result.iter().map(|&b| b as char).collect::<String>());
        Some(decoded)
    } else {
        None
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode HTML entities: &lt; &gt; &amp; &quot; &#xNN; &#NNN;
fn decode_html_entities(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' {
            let mut entity = String::new();
            for ec in chars.by_ref() {
                if ec == ';' {
                    break;
                }
                entity.push(ec);
                if entity.len() > 10 {
                    // Not a valid entity, emit raw
                    result.push('&');
                    result.push_str(&entity);
                    entity.clear();
                    break;
                }
            }
            if entity.is_empty() {
                continue;
            }
            match entity.as_str() {
                "lt" => result.push('<'),
                "gt" => result.push('>'),
                "amp" => result.push('&'),
                "quot" => result.push('"'),
                "apos" => result.push('\''),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                    if let Ok(code) = u32::from_str_radix(&entity[2..], 16) {
                        if let Some(ch) = char::from_u32(code) {
                            result.push(ch);
                            continue;
                        }
                    }
                    result.push('&');
                    result.push_str(&entity);
                    result.push(';');
                }
                _ if entity.starts_with('#') => {
                    if let Ok(code) = entity[1..].parse::<u32>() {
                        if let Some(ch) = char::from_u32(code) {
                            result.push(ch);
                            continue;
                        }
                    }
                    result.push('&');
                    result.push_str(&entity);
                    result.push(';');
                }
                _ => {
                    result.push('&');
                    result.push_str(&entity);
                    result.push(';');
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Decode \uNNNN unicode escapes.
fn decode_unicode_escapes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 5 < bytes.len()
            && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U')
        {
            let hex_str = &input[i + 2..i + 6];
            if let Ok(code) = u32::from_str_radix(hex_str, 16) {
                if let Some(ch) = char::from_u32(code) {
                    result.push(ch);
                    i += 6;
                    continue;
                }
            }
        }
        i += push_utf8_char(&mut result, bytes, i);
    }
    result
}

/// Decode \xNN hex escapes.
fn decode_hex_escapes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
        {
            let hi = hex_digit(bytes[i + 2]);
            let lo = hex_digit(bytes[i + 3]);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h << 4 | l) as char);
                i += 4;
                continue;
            }
        }
        i += push_utf8_char(&mut result, bytes, i);
    }
    result
}

/// Replace SQL inline comments /**/ with a single space.
fn decode_sql_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            // Find closing */
            let mut j = i + 2;
            while j + 1 < bytes.len() {
                if bytes[j] == b'*' && bytes[j + 1] == b'/' {
                    result.push(' ');
                    i = j + 2;
                    break;
                }
                j += 1;
            }
            if j + 1 >= bytes.len() {
                // Unclosed comment — emit raw
                result.push_str(&input[i..]);
                return result;
            }
        } else {
            i += push_utf8_char(&mut result, bytes, i);
        }
    }
    result
}

/// Push one UTF-8 character from a byte slice into a String, returning bytes consumed.
/// Handles multi-byte sequences correctly instead of treating each byte as a Latin-1 char.
fn push_utf8_char(result: &mut String, bytes: &[u8], i: usize) -> usize {
    let b = bytes[i];
    let seq_len = if b & 0x80 == 0 {
        1
    } else if b & 0xE0 == 0xC0 {
        2
    } else if b & 0xF0 == 0xE0 {
        3
    } else if b & 0xF8 == 0xF0 {
        4
    } else {
        1
    };
    if i + seq_len <= bytes.len() {
        if let Ok(s) = std::str::from_utf8(&bytes[i..i + seq_len]) {
            result.push_str(s);
            return seq_len;
        }
    }
    result.push(b as char);
    1
}

fn parse_pct_byte(bytes: &[u8], i: usize) -> Option<(u8, usize)> {
    if i + 2 >= bytes.len() || bytes[i] != b'%' {
        return None;
    }
    let hi = hex_digit(bytes[i + 1])?;
    let lo = hex_digit(bytes[i + 2])?;
    Some(((hi << 4) | lo, i + 3))
}

fn collect_encoding_anomalies(input: &str, anomalies: &mut std::collections::HashSet<String>) {
    detect_percent_utf8_anomalies(input, anomalies);
    detect_bom_confusion(input, anomalies);
}

fn detect_bom_confusion(input: &str, anomalies: &mut std::collections::HashSet<String>) {
    if input.starts_with('\u{FEFF}')
        || input.starts_with("\u{00EF}\u{00BB}\u{00BF}")
        || input.starts_with("\u{00FE}\u{00FF}")
        || input.starts_with("\u{00FF}\u{00FE}")
    {
        anomalies.insert("utf8_bom_prefix".to_owned());
    }

    let lower = input.to_ascii_lowercase();
    if lower.contains("%ef%bb%bf") {
        anomalies.insert("url_encoded_utf8_bom".to_owned());
    }
    if lower.contains("%fe%ff") || lower.contains("%ff%fe") {
        anomalies.insert("url_encoded_utf16_bom".to_owned());
    }
}

fn detect_percent_utf8_anomalies(input: &str, anomalies: &mut std::collections::HashSet<String>) {
    let bytes = input.as_bytes();
    let mut decoded = Vec::<u8>::new();

    let mut i = 0;
    while i < bytes.len() {
        if let Some((b, n)) = parse_pct_byte(bytes, i) {
            decoded.push(b);
            i = n;
        } else {
            // Include raw bytes only when they are ASCII and could be part of UTF-8 structure.
            if bytes[i] < 0x80 {
                decoded.push(bytes[i]);
            }
            i += 1;
        }
    }

    let mut idx = 0;
    while idx < decoded.len() {
        let b = decoded[idx];
        if b == 0xC0 || b == 0xC1 {
            anomalies.insert("overlong_utf8_sequence".to_owned());
        }

        let expected = if b < 0x80 {
            0
        } else if (0xC2..=0xDF).contains(&b) {
            1
        } else if (0xE0..=0xEF).contains(&b) {
            2
        } else if (0xF0..=0xF7).contains(&b) {
            3
        } else {
            0
        };

        if expected > 0 {
            if b == 0xC0 || b == 0xC1 {
                anomalies.insert("overlong_utf8_sequence".to_owned());
            }
            if b == 0xE0 && idx + 2 < decoded.len() {
                let b2 = decoded[idx + 1];
                let b3 = decoded[idx + 2];
                if (0x80..=0x9F).contains(&b2) && (0x80..=0xBF).contains(&b3) {
                    anomalies.insert("overlong_utf8_sequence".to_owned());
                }
            }
            if b == 0xF0 && idx + 3 < decoded.len() {
                let b2 = decoded[idx + 1];
                let b3 = decoded[idx + 2];
                let b4 = decoded[idx + 3];
                if (0x80..=0x8F).contains(&b2)
                    && (0x80..=0xBF).contains(&b3)
                    && (0x80..=0xBF).contains(&b4)
                {
                    anomalies.insert("overlong_utf8_sequence".to_owned());
                }
            }
            if idx + expected >= decoded.len() {
                anomalies.insert("invalid_utf8_truncated_sequence".to_owned());
                break;
            }
            for offset in 1..=expected {
                if !(0x80..=0xBF).contains(&decoded[idx + offset]) {
                    anomalies.insert("invalid_utf8_continuation".to_owned());
                }
            }
            idx += expected + 1;
            continue;
        }

        if (0x80..=0xBF).contains(&b) {
            anomalies.insert("invalid_utf8_leading_continuation".to_owned());
        } else if b >= 0xF8 {
            anomalies.insert("invalid_utf8_leading_byte".to_owned());
        }
        idx += 1;
    }
}

fn decode_overlong_utf8(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        if let Some((b1, n1)) = parse_pct_byte(bytes, i) {
            // 2-byte overlong: C0/C1 80..BF
            if (0xC0..=0xC1).contains(&b1) {
                if let Some((b2, n2)) = parse_pct_byte(bytes, n1) {
                    if (0x80..=0xBF).contains(&b2) {
                        let cp = (((b1 & 0x1F) as u32) << 6) | ((b2 & 0x3F) as u32);
                        if cp <= 0x7F {
                            if let Some(ch) = char::from_u32(cp) {
                                result.push(ch);
                                i = n2;
                                continue;
                            }
                        }
                    }
                }
            }

            // 3-byte overlong: E0 80..9F 80..BF
            if b1 == 0xE0 {
                if let Some((b2, n2)) = parse_pct_byte(bytes, n1) {
                    if (0x80..=0x9F).contains(&b2) {
                        if let Some((b3, n3)) = parse_pct_byte(bytes, n2) {
                            if (0x80..=0xBF).contains(&b3) {
                                let cp = (((b1 & 0x0F) as u32) << 12)
                                    | (((b2 & 0x3F) as u32) << 6)
                                    | ((b3 & 0x3F) as u32);
                                if cp <= 0x7FF {
                                    if let Some(ch) = char::from_u32(cp) {
                                        result.push(ch);
                                        i = n3;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 4-byte overlong: F0 80..8F 80..BF 80..BF
            if b1 == 0xF0 {
                if let Some((b2, n2)) = parse_pct_byte(bytes, n1) {
                    if (0x80..=0x8F).contains(&b2) {
                        if let Some((b3, n3)) = parse_pct_byte(bytes, n2) {
                            if (0x80..=0xBF).contains(&b3) {
                                if let Some((b4, n4)) = parse_pct_byte(bytes, n3) {
                                    if (0x80..=0xBF).contains(&b4) {
                                        let cp = (((b1 & 0x07) as u32) << 18)
                                            | (((b2 & 0x3F) as u32) << 12)
                                            | (((b3 & 0x3F) as u32) << 6)
                                            | ((b4 & 0x3F) as u32);
                                        if cp <= 0xFFFF {
                                            if let Some(ch) = char::from_u32(cp) {
                                                result.push(ch);
                                                i = n4;
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(ch) = input[i..].chars().next() {
            result.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    result
}

/// Try to base64-decode a string. Returns None if it doesn't look like base64
/// or decodes to non-printable content.
fn try_base64_decode(input: &str) -> Option<String> {
    // Only attempt if input looks like base64: length >= 16, valid charset
    let candidate = input.split(|c: char| c == '=' || c == '&').find(|s| {
        s.len() >= 16
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    })?;

    // Manual base64 decode (no dependency)
    let decoded_bytes = base64_decode(candidate.as_bytes())?;

    // Check that ≥80% is printable ASCII
    let printable = decoded_bytes
        .iter()
        .filter(|&&b| (32..=126).contains(&b) || b == 9 || b == 10 || b == 13)
        .count();

    if printable * 5 >= decoded_bytes.len() * 4 {
        String::from_utf8(decoded_bytes).ok()
    } else {
        None
    }
}

/// Simple base64 decoder (no external dependency).
fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn b64_val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0), // padding
            _ => None,
        }
    }

    let clean: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    if clean.len() % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let c_val = b64_val(chunk[2])?;
        let d = b64_val(chunk[3])?;

        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c_val >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c_val << 6) | d);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_simple() {
        let d = multi_layer_decode("%27%20OR%201%3D1--");
        assert_eq!(d.fully_decoded, "' OR 1=1--");
        assert!(d.uses_encoding);
    }

    #[test]
    fn double_url_decode() {
        let d = multi_layer_decode("%2527%2520OR%25201%253D1--");
        assert_eq!(d.fully_decoded, "' OR 1=1--");
        assert_eq!(d.encoding_depth, 2);
    }

    #[test]
    fn html_entity_decode() {
        let d = multi_layer_decode("&lt;script&gt;alert(1)&lt;/script&gt;");
        assert_eq!(d.fully_decoded, "<script>alert(1)</script>");
    }

    #[test]
    fn unicode_escape_decode() {
        let d = multi_layer_decode("\\u003cscript\\u003e");
        assert_eq!(d.fully_decoded, "<script>");
    }

    #[test]
    fn hex_escape_decode() {
        let d = multi_layer_decode("\\x3cscript\\x3e");
        assert_eq!(d.fully_decoded, "<script>");
    }

    #[test]
    fn sql_comment_decode() {
        let d = multi_layer_decode("SELECT/**/1/**/FROM/**/users");
        assert_eq!(d.fully_decoded, "SELECT 1 FROM users");
    }

    #[test]
    fn no_encoding() {
        let d = multi_layer_decode("hello world");
        assert!(!d.uses_encoding);
        assert_eq!(d.encoding_depth, 0);
        assert_eq!(d.fully_decoded, "hello world");
    }

    #[test]
    fn mixed_encoding() {
        // URL-encoded HTML entity
        let d = multi_layer_decode("%26lt%3b");
        // First decode: &lt;
        // Second decode: <
        assert_eq!(d.fully_decoded, "<");
        assert_eq!(d.encoding_depth, 2);
    }

    #[test]
    fn quad_url_decode() {
        let d = multi_layer_decode("%2525252e");
        assert_eq!(d.fully_decoded, ".");
        assert!(d.encoding_depth >= 4);
    }

    #[test]
    fn mixed_chain_numeric_entity_inside_url() {
        let d = multi_layer_decode("%26%2360%3bscript%26%2362%3b");
        assert_eq!(d.fully_decoded, "<script>");
    }

    #[test]
    fn mixed_chain_unicode_escape_inside_url() {
        let d = multi_layer_decode("%5cu003cscript%5cu003e");
        assert_eq!(d.fully_decoded, "<script>");
    }

    #[test]
    fn overlong_two_byte_decode() {
        let d = multi_layer_decode("%C0%AFetc");
        assert_eq!(d.fully_decoded, "/etc");
    }

    #[test]
    fn overlong_three_byte_decode() {
        let d = multi_layer_decode("%E0%80%AFetc");
        assert_eq!(d.fully_decoded, "/etc");
    }

    #[test]
    fn overlong_four_byte_decode() {
        let d = multi_layer_decode("%F0%80%80%AFetc");
        assert_eq!(d.fully_decoded, "/etc");
    }

    #[test]
    fn detects_overlong_utf8_sequences() {
        let d = multi_layer_decode("%C0%AF/etc");
        assert_eq!(d.fully_decoded, "//etc");
        assert!(d.anomalies.iter().any(|a| a == "overlong_utf8_sequence"));
    }

    #[test]
    fn detects_invalid_utf8_continuation_bytes() {
        let d = multi_layer_decode("%80%80");
        assert!(
            d.anomalies
                .iter()
                .any(|a| a == "invalid_utf8_leading_continuation")
        );
        assert_eq!(d.fully_decoded, "\u{80}\u{80}");
    }

    #[test]
    fn detects_bom_encoded_prefix_confusion() {
        let d = multi_layer_decode("%EF%BB%BF%3Cscript%3E");
        assert!(d.fully_decoded == "\u{FEFF}<script>");
        assert!(d.anomalies.iter().any(|a| a == "url_encoded_utf8_bom"));
    }

    #[test]
    fn mixed_url_html_and_unicode_layers() {
        let d = multi_layer_decode("%26%2360%3b%5Cu0078script%5Cu0079%26%2362%3b");
        assert_eq!(d.fully_decoded, "<xscripty>");
    }

    #[test]
    fn detects_truncated_utf8_sequence() {
        let d = multi_layer_decode("%E2%82");
        assert!(
            d.anomalies
                .iter()
                .any(|a| a == "invalid_utf8_truncated_sequence")
        );
    }

    #[test]
    fn detects_bom_literal_prefix() {
        let d = multi_layer_decode("\u{FEFF}alert(1)");
        assert!(d.anomalies.iter().any(|a| a == "utf8_bom_prefix"));
    }

    #[test]
    fn multi_layer_decode_mixed_url_html_unicode() {
        let d = multi_layer_decode("%26lt%3b%5Cu0078%5Cu0079%26gt%3b");
        assert_eq!(d.fully_decoded, "<xy>");
    }

    #[test]
    fn multi_layer_decode_url_html_unicode_chain_with_script() {
        let d = multi_layer_decode("%26%2360%3b%5Cu0078script%5Cu0079%26%2362%3b");
        assert_eq!(d.fully_decoded, "<xscripty>");
    }

    #[test]
    fn detects_invalid_utf8_continuation_sequence() {
        let d = multi_layer_decode("%E2%28%AF");
        assert!(d.anomalies.iter().any(|a| a == "invalid_utf8_continuation"));
    }

    #[test]
    fn detects_invalid_utf8_leading_byte() {
        let d = multi_layer_decode("%FF%FE%FD");
        assert!(d.anomalies.iter().any(|a| a == "invalid_utf8_leading_byte"));
    }

    #[test]
    fn detects_overlong_utf8_four_byte_to_ascii() {
        let d = multi_layer_decode("%F0%80%80%AF%61");
        assert_eq!(d.fully_decoded, "/a");
        assert!(d.anomalies.iter().any(|a| a == "overlong_utf8_sequence"));
    }

    #[test]
    fn preserves_multibyte_char_from_url_decoding() {
        let d = multi_layer_decode("%F0%9F%98%80");
        assert_eq!(d.fully_decoded, "😀");
    }

    #[test]
    fn detects_url_encoded_utf16_bom() {
        let d = multi_layer_decode("%FE%FF%003C");
        assert!(d.anomalies.iter().any(|a| a == "url_encoded_utf16_bom"));
    }
}
