//! Canonical Normalizer — Universal Input Normalization
//!
//! The invariant: canonical(encode₁(input)) === canonical(encode₂(input))
//! for ALL encoding functions encode₁, encode₂.
//!
//! Normalization layers (applied in order):
//!   1. Overlong UTF-8 resolution
//!   2. URL decoding (iterative, up to 3 layers)
//!   3. HTML entity decoding (named + numeric)
//!   4. Unicode escape decoding (\uXXXX, \xXX)
//!   5. Null byte removal
//!   6. Case-fold (optional)
//!   7. Whitespace normalization (optional)

use std::collections::HashSet;

const MAX_URL_DECODE_LAYERS: usize = 8;

// ── HTML Entity Decoding ──────────────────────────────────────────

fn decode_named_entity(name: &str) -> Option<char> {
    // Avoid `to_lowercase()` allocation for every candidate entity.
    if name.eq_ignore_ascii_case("amp") { Some('&') }
    else if name.eq_ignore_ascii_case("lt") { Some('<') }
    else if name.eq_ignore_ascii_case("gt") { Some('>') }
    else if name.eq_ignore_ascii_case("quot") { Some('"') }
    else if name.eq_ignore_ascii_case("apos") { Some('\'') }
    else if name.eq_ignore_ascii_case("nbsp") { Some(' ') }
    else if name.eq_ignore_ascii_case("copy") { Some('\u{00a9}') }
    else if name.eq_ignore_ascii_case("reg") { Some('\u{00ae}') }
    else if name.eq_ignore_ascii_case("trade") { Some('\u{2122}') }
    else if name.eq_ignore_ascii_case("euro") { Some('\u{20ac}') }
    else if name.eq_ignore_ascii_case("tab") { Some('\t') }
    else if name.eq_ignore_ascii_case("newline") { Some('\n') }
    else if name.eq_ignore_ascii_case("excl") { Some('!') }
    else if name.eq_ignore_ascii_case("num") { Some('#') }
    else if name.eq_ignore_ascii_case("dollar") { Some('$') }
    else if name.eq_ignore_ascii_case("percnt") { Some('%') }
    else if name.eq_ignore_ascii_case("lpar") { Some('(') }
    else if name.eq_ignore_ascii_case("rpar") { Some(')') }
    else if name.eq_ignore_ascii_case("ast") { Some('*') }
    else if name.eq_ignore_ascii_case("plus") { Some('+') }
    else if name.eq_ignore_ascii_case("comma") { Some(',') }
    else if name.eq_ignore_ascii_case("period") { Some('.') }
    else if name.eq_ignore_ascii_case("sol") { Some('/') }
    else if name.eq_ignore_ascii_case("colon") { Some(':') }
    else if name.eq_ignore_ascii_case("semi") { Some(';') }
    else if name.eq_ignore_ascii_case("equals") { Some('=') }
    else if name.eq_ignore_ascii_case("quest") { Some('?') }
    else if name.eq_ignore_ascii_case("commat") { Some('@') }
    else if name.eq_ignore_ascii_case("lsqb") { Some('[') }
    else if name.eq_ignore_ascii_case("rsqb") { Some(']') }
    else if name.eq_ignore_ascii_case("lbrace") { Some('{') }
    else if name.eq_ignore_ascii_case("rbrace") { Some('}') }
    else if name.eq_ignore_ascii_case("vert") { Some('|') }
    else if name.eq_ignore_ascii_case("bsol") { Some('\\') }
    else if name.eq_ignore_ascii_case("grave") { Some('`') }
    else if name.eq_ignore_ascii_case("tilde") { Some('~') }
    else if name.eq_ignore_ascii_case("times") { Some('\u{d7}') }
    else if name.eq_ignore_ascii_case("divide") { Some('\u{f7}') }
    else if name.eq_ignore_ascii_case("minus") { Some('-') }
    else if name.eq_ignore_ascii_case("ndash") { Some('\u{2013}') }
    else if name.eq_ignore_ascii_case("mdash") { Some('\u{2014}') }
    else { None }
}

fn html_entity_codepoint(entity: &str) -> Option<u32> {
    if entity.is_empty() {
        return None;
    }

    if let Some(rest) = entity.strip_prefix('#') {
        let cp = if let Some(hex) = rest.strip_prefix('x').or_else(|| rest.strip_prefix('X')) {
            u32::from_str_radix(&hex, 16).ok()
        } else {
            rest.parse::<u32>().ok()
        }?;
        return (cp > 0 && cp <= 0x10FFFF).then_some(cp);
    }

    decode_named_entity(entity).map(|ch| ch as u32)
}

fn has_numeric_ampersand_chain(input: &str) -> bool {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] != '&' {
            i += 1;
            continue;
        }

        if i + 1 >= chars.len() {
            break;
        }

        if let Some(end) = chars[i + 1..].iter().position(|&c| c == ';') {
            let entity = &chars[i + 1..i + 1 + end];
            let entity_str: String = entity.iter().collect();
            if html_entity_codepoint(&entity_str) == Some('&' as u32) && chars.get(i + 1 + end + 1) == Some(&'#') {
                return true;
            }
            i = i + 1 + end + 1;
            continue;
        }

        if i + 3 < chars.len() && chars[i + 1] == '#' {
            let is_hex = matches!(chars[i + 2], 'x' | 'X');
            let start = if is_hex { i + 3 } else { i + 2 };
            let mut j = start;
            let max_len = if is_hex { start + 6 } else { start + 7 };

            while j < chars.len() && j < max_len {
                let c = chars[j];
                if is_hex {
                    if !c.is_ascii_hexdigit() {
                        break;
                    }
                } else if !c.is_ascii_digit() {
                    break;
                }
                j += 1;
            }

            if j > start {
                let digits: String = chars[start..j].iter().collect();
                let cp = if is_hex {
                    u32::from_str_radix(&digits, 16).ok()
                } else {
                    digits.parse::<u32>().ok()
                };
                if cp == Some('&' as u32) && chars.get(j) == Some(&'#') {
                    return true;
                }
            }
        }

        i += 1;
    }

    false
}

fn decode_html_entities_recursive(input: &str, max_passes: usize) -> String {
    let mut current = input.to_string();
    for _ in 0..max_passes {
        let stop_after_this_pass = has_numeric_ampersand_chain(current.as_str());
        let next = decode_html_entities(&current);
        if next == current {
            return current;
        }
        current = next;
        if stop_after_this_pass {
            return current;
        }
    }
    current
}

fn decode_html_entities(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '&' {
            // Try to find entity
            if let Some(end) = chars[i + 1..].iter().position(|&c| c == ';') {
                let entity = &chars[i + 1..i + 1 + end];
                let entity_str: String = entity.iter().collect();

                if entity_str.starts_with('#') {
                    // Numeric entity
                    let num_str = &entity_str[1..];
                    let cp = if num_str.starts_with('x') || num_str.starts_with('X') {
                        u32::from_str_radix(&num_str[1..], 16).ok()
                    } else {
                        num_str.parse::<u32>().ok()
                    };
                    if let Some(cp) = cp {
                        if cp > 0 && cp <= 0x10FFFF {
                            if let Some(ch) = char::from_u32(cp) {
                                result.push(ch);
                                i += 2 + end;
                                continue;
                            }
                        }
                    }
                } else if let Some(ch) = decode_named_entity(&entity_str) {
                    result.push(ch);
                    i += 2 + end;
                    continue;
                }
            }
            // Also handle entities without trailing semicolon for numeric
            if i + 3 < len && chars[i + 1] == '#' {
                let is_hex = i + 4 < len && (chars[i + 2] == 'x' || chars[i + 2] == 'X');
                let start = if is_hex { i + 3 } else { i + 2 };
                let mut j = start;
                while j < len && j < start + 7 {
                    if is_hex {
                        if !chars[j].is_ascii_hexdigit() { break; }
                    } else {
                        if !chars[j].is_ascii_digit() { break; }
                    }
                    j += 1;
                }
                if j > start {
                    let digits: String = chars[start..j].iter().collect();
                    let cp = if is_hex {
                        u32::from_str_radix(&digits, 16).ok()
                    } else {
                        digits.parse::<u32>().ok()
                    };
                    if let Some(cp) = cp {
                        if cp > 0 && cp <= 0x10FFFF {
                            if let Some(ch) = char::from_u32(cp) {
                                result.push(ch);
                                // Skip optional semicolon
                                i = if j < len && chars[j] == ';' { j + 1 } else { j };
                                continue;
                            }
                        }
                    }
                }
            }
            result.push('&');
            i += 1;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    result
}

fn is_zero_width_mark(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{180E}' | '\u{2060}'
            | '\u{200E}' | '\u{200F}'
    )
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}' | '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}' |
            '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
    ) || (ch >= '\u{2000}' && ch <= '\u{200F}'
        && matches!(ch, '\u{200E}' | '\u{200F}'))
}

fn is_invisible_unicode(ch: char) -> bool {
    is_zero_width_mark(ch)
        || is_bidi_control(ch)
        || (('\u{FE00}'..='\u{FE0F}').contains(&ch))
        || (ch >= '\u{2000}' && ch <= '\u{200F}' && !matches!(ch, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' | '\u{2060}'))
}

fn strip_invisible_unicode(input: &str) -> (String, bool) {
    let mut result = String::with_capacity(input.len());
    let mut changed = false;
    for ch in input.chars() {
        if is_invisible_unicode(ch) {
            changed = true;
            continue;
        }
        result.push(ch);
    }
    (result, changed)
}

fn punycode_digit_to_value(d: char) -> Option<u32> {
    match d {
        'A'..='Z' => Some((d as u32) - ('A' as u32)),
        'a'..='z' => Some((d as u32) - ('a' as u32)),
        '0'..='9' => Some((d as u32) - ('0' as u32) + 26),
        _ => None,
    }
}

fn punycode_adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
    let mut delta = if first_time { delta / 700 } else { delta / 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((36 - 1) * 26) / 2 {
        delta /= 35;
        k += 36;
    }
    k + 36 * delta / (delta + 38)
}

fn punycode_decode(input: &str) -> Option<String> {
    let input = input.trim().to_ascii_lowercase();
    if input.is_empty() {
        return Some(String::new());
    }
    if !input.starts_with("xn--") {
        return None;
    }

    let mut output: Vec<u32> = Vec::new();
    let mut n: u32 = 128;
    let mut i: u32 = 0;
    let mut bias: u32 = 72;

    let encoded_start = if let Some(pos) = input[4..].find('-') {
        let basic = &input[4..4 + pos];
        for ch in basic.chars() {
            output.push(ch as u32);
        }
        4 + pos + 1
    } else {
        4
    };

    if encoded_start >= input.len() {
        let decoded = output.into_iter().filter_map(char::from_u32).collect::<String>();
        return Some(decoded);
    }

    let mut idx = encoded_start;
    while idx < input.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k: u32 = 36;
        loop {
            let ch = input[idx..].chars().next().map(|c| c)?;
            let digit = punycode_digit_to_value(ch)?;
            idx += ch.len_utf8();

            i = i.saturating_add(digit.saturating_mul(w));
            let t = if k <= bias {
                1
            } else if k >= bias + 26 {
                26
            } else {
                k - bias
            };

            if digit < t {
                break;
            }
            w = w.saturating_mul(36 - t);
            k = k.saturating_add(36);
        }

        let out_len = output.len() as u32 + 1;
        bias = punycode_adapt(i - old_i, out_len, old_i == 0);
        n = n.saturating_add(i / out_len);
        i = i % out_len;

        if n > 0x10ffff {
            return None;
        }
        output.insert(i as usize, n);
        i = i.saturating_add(1);
    }

    let decoded = output.into_iter()
        .map(|cp| char::from_u32(cp))
        .collect::<Option<String>>()?;
    Some(decoded)
}

fn normalize_punycode_labels(input: &str) -> (String, bool) {
    let mut output = String::with_capacity(input.len());
    let mut token = String::new();
    let mut changed = false;

    let flush = |token: &str, output: &mut String, changed: &mut bool| {
        if token.is_empty() {
            return;
        }
        if !token.contains("xn--") && !token.contains("XN--") {
            output.push_str(token);
            return;
        }

        let mut rewritten = String::with_capacity(token.len());
        let mut local_changed = false;
        let mut first = true;
        for label in token.split('.') {
            if !first {
                rewritten.push('.');
            }
            first = false;
            if label.to_ascii_lowercase().starts_with("xn--") {
                if let Some(decoded) = punycode_decode(label) {
                    rewritten.push_str(&decoded);
                    local_changed = true;
                } else {
                    rewritten.push_str(&label.to_ascii_lowercase());
                }
            } else {
                rewritten.push_str(label);
            }
        }
        if local_changed {
            *changed = true;
        }
        output.push_str(&rewritten);
    };

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
            token.push(ch);
        } else {
            flush(&token, &mut output, &mut changed);
            token.clear();
            output.push(ch);
        }
    }
    if !token.is_empty() {
        flush(&token, &mut output, &mut changed);
    }

    (output, changed)
}

fn normalize_homoglyphs(input: &str) -> (String, bool) {
    let mut result = String::with_capacity(input.len());
    let mut changed = false;
    for ch in input.chars() {
        let mapped = match ch {
            '\u{0430}' => 'a',
            '\u{0410}' => 'A',
            '\u{0435}' => 'e',
            '\u{0415}' => 'E',
            '\u{0432}' => 'v',
            '\u{0412}' => 'V',
            '\u{0443}' => 'y',
            '\u{0423}' => 'Y',
            '\u{043E}' => 'o',
            '\u{041E}' => 'O',
            '\u{0445}' => 'x',
            '\u{0425}' => 'X',
            '\u{0440}' => 'p',
            '\u{0420}' => 'P',
            '\u{0441}' => 'c',
            '\u{0421}' => 'C',
            '\u{043A}' => 'k',
            '\u{041A}' => 'K',
            '\u{043C}' => 'm',
            '\u{041C}' => 'M',
            '\u{043D}' => 'H',
            '\u{041D}' => 'H',
            '\u{0438}' => 'i',
            '\u{0418}' => 'I',
            '\u{0442}' => 't',
            '\u{0422}' => 'T',
            '\u{043B}' => 'l',
            '\u{041B}' => 'L',
            '\u{03B1}' => 'a',
            '\u{0391}' => 'A',
            '\u{03B5}' => 'e',
            '\u{0395}' => 'E',
            '\u{03B8}' => 'h',
            '\u{0398}' => 'H',
            '\u{03B7}' => 'h',
            '\u{0397}' => 'H',
            '\u{03B9}' => 'i',
            '\u{0399}' => 'I',
            '\u{03BF}' => 'o',
            '\u{039F}' => 'O',
            '\u{03C3}' => 's',
            '\u{03A3}' => 'S',
            '\u{03C5}' => 'y',
            '\u{03A5}' => 'Y',
            '\u{03BC}' => 'm',
            '\u{039C}' => 'M',
            '\u{03C1}' => 'p',
            '\u{03A1}' => 'P',
            '\u{0394}' => 'A',
            '\u{03B4}' => 'd',
            '\u{03C7}' => 'x',
            '\u{03A7}' => 'X',
            '\u{FF0D}' => '-',
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' => '-',
            '\u{FF0C}' => ',',
            '\u{FF1B}' => ';',
            '\u{FF1A}' => ':',
            _ => '\0',
        };
        if mapped != '\0' {
            result.push(mapped);
            changed = true;
        } else {
            result.push(ch);
        }
    }
    (result, changed)
}

// ── Unicode Escape Decoding ───────────────────────────────────────

fn decode_unicode_escapes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let ch = match input[i..].chars().next() {
            Some(ch) => ch,
            None => break,
        };

        if ch == '\\' && i + 1 < len {
            match bytes[i + 1] {
                // \uXXXX
                b'u' if i + 5 < len => {
                    let hex: &str = &input[i + 2..i + 6];
                    if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        if let Ok(cp) = u16::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(cp as u32) {
                                result.push(ch);
                                i += 6;
                                continue;
                            }
                        }
                    }
                    result.push('\\');
                    i += 1;
                }
                // \xXX
                b'x' if i + 3 < len => {
                    let hex = &input[i + 2..i + 4];
                    if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        if let Ok(cp) = u8::from_str_radix(hex, 16) {
                            result.push(cp as char);
                            i += 4;
                            continue;
                        }
                    }
                    result.push('\\');
                    i += 1;
                }
                // \OOO (octal, 3 digits)
                d @ b'0'..=b'3' if i + 3 < len
                    && bytes[i + 2].is_ascii_digit() && bytes[i + 2] <= b'7'
                    && bytes[i + 3].is_ascii_digit() && bytes[i + 3] <= b'7' =>
                {
                    let oct = &input[i + 1..i + 4];
                    if let Ok(cp) = u8::from_str_radix(oct, 8) {
                        result.push(cp as char);
                        i += 4;
                        continue;
                    }
                    result.push('\\');
                    i += 1;
                }
                _ => {
                    result.push('\\');
                    i += 1;
                }
            }
        } else {
            result.push(ch);
            i += ch.len_utf8();
        }
    }

    result
}

fn sanitize_unicode_edge_cases(input: &str) -> (String, bool) {
    let mut result = String::with_capacity(input.len());
    let mut changed = false;

    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if i + 5 < bytes.len()
            && bytes[i] == b'\\'
            && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U')
        {
            let digits = &input[i + 2..i + 6];
            if digits.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(cp) = u16::from_str_radix(digits, 16) {
                    if (0xD800..=0xDFFF).contains(&cp) {
                        result.push('\u{FFFD}');
                        i += 6;
                        changed = true;
                        continue;
                    }
                }
            }
        }

        if let Some(ch) = input[i..].chars().next() {
            if is_combining_or_zero_width(ch) {
                changed = true;
                i += ch.len_utf8();
                continue;
            }
            // Normalize fullwidth Latin characters (U+FF01..U+FF5E) to ASCII (U+0021..U+007E)
            let cp = ch as u32;
            if (0xFF01..=0xFF5E).contains(&cp) {
                result.push(char::from_u32(cp - 0xFF01 + 0x0021).unwrap_or(ch));
                changed = true;
                i += ch.len_utf8();
                continue;
            }
            // Normalize fullwidth digits (U+FF10..U+FF19) already covered above
            result.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    (result, changed)
}

fn is_combining_or_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
    ) || is_combining_mark(ch)
}

fn is_combining_mark(ch: char) -> bool {
    matches!(
        ch,
        '\u{0300}'..='\u{036F}'
            | '\u{1AB0}'..='\u{1ACE}'
            | '\u{1B00}'..='\u{1BFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE20}'..='\u{FE2F}'
    )
}

fn strip_bom_markers(input: &str) -> (String, bool) {
    let mut s = input;
    let mut changed = false;

    loop {
        if let Some(rest) = s.strip_prefix('\u{FEFF}') {
            s = rest;
            changed = true;
            continue;
        }
        if let Some(rest) = s.strip_prefix("\u{00EF}\u{00BB}\u{00BF}") {
            s = rest;
            changed = true;
            continue;
        }
        if let Some(rest) = s.strip_prefix("\u{00FE}\u{00FF}") {
            s = rest;
            changed = true;
            continue;
        }
        if let Some(rest) = s.strip_prefix("\u{00FF}\u{00FE}") {
            s = rest;
            changed = true;
            continue;
        }
        break;
    }

    (s.to_string(), changed)
}

// ── URL Decoding ──────────────────────────────────────────────────

fn url_decode_once(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut result = Vec::with_capacity(len);
    let mut changed = false;
    let mut i = 0;

    while i < len {
        if bytes[i] == b'%' && i + 2 < len {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() {
                let hi = hex_val(h1);
                let lo = hex_val(h2);
                result.push((hi << 4) | lo);
                i += 3;
                changed = true;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(b' ');
            if bytes[i] != b' ' {
                changed = true;
            }
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }

    if changed {
        let decoded = match String::from_utf8(result.clone()) {
            Ok(s) => s,
            Err(_) => result.iter().map(|&b| b as char).collect(),
        };
        Some(decoded)
    } else {
        None
    }
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// ── Overlong UTF-8 ────────────────────────────────────────────────

fn parse_pct_byte(bytes: &[u8], i: usize) -> Option<(u8, usize)> {
    if i + 2 >= bytes.len() || bytes[i] != b'%' {
        return None;
    }
    let h1 = bytes[i + 1];
    let h2 = bytes[i + 2];
    if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
        return None;
    }
    Some(((hex_val(h1) << 4) | hex_val(h2), i + 3))
}

fn detect_overlong_utf8_sequences(input: &str) -> bool {
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if let Some((b1, n1)) = parse_pct_byte(bytes, i) {
            if (0xC0..=0xC1).contains(&b1) {
                let Some((b2, _)) = parse_pct_byte(bytes, n1) else {
                    return true;
                };
                if (0x80..=0xBF).contains(&b2) {
                    return true;
                }
            }

            if b1 == 0xE0 {
                if let Some((b2, n2)) = parse_pct_byte(bytes, n1) {
                    if (0x80..=0x9F).contains(&b2) {
                        if let Some((b3, _)) = parse_pct_byte(bytes, n2) {
                            if (0x80..=0xBF).contains(&b3) {
                                return true;
                            }
                        } else {
                            return true;
                        }
                    }
                } else {
                    return true;
                }
            }

            if b1 == 0xF0 {
                if let Some((b2, n2)) = parse_pct_byte(bytes, n1) {
                    if (0x80..=0x8F).contains(&b2) {
                        if let Some((b3, n3)) = parse_pct_byte(bytes, n2) {
                            if (0x80..=0xBF).contains(&b3) {
                                if let Some((b4, _)) = parse_pct_byte(bytes, n3) {
                                    if (0x80..=0xBF).contains(&b4) {
                                        return true;
                                    }
                                } else {
                                    return true;
                                }
                            }
                        } else {
                            return true;
                        }
                    }
                } else {
                    return true;
                }
            }

            i = n1;
            continue;
        }

        if let Some(ch) = input[i..].chars().next() {
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    false
}

fn decode_overlong_utf8(input: &str) -> (String, bool) {
    let bytes = input.as_bytes();
    let mut result = String::with_capacity(input.len());
    let mut changed = false;
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
                                changed = true;
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
                                        changed = true;
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
                                                changed = true;
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

    (result, changed)
}

// ── Null Byte Removal ─────────────────────────────────────────────

fn remove_null_bytes(input: &str) -> (String, bool) {
    let mut result = String::with_capacity(input.len());
    let mut changed = false;

    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 < bytes.len()
            && bytes[i] == b'%'
            && bytes[i + 1].eq_ignore_ascii_case(&b'0')
            && bytes[i + 2].eq_ignore_ascii_case(&b'0')
        {
            changed = true;
            i += 3;
            continue;
        }

        let ch = match input[i..].chars().next() {
            Some(ch) => ch,
            None => break,
        };
        if ch == '\0' {
            changed = true;
        } else {
            result.push(ch);
        }
        i += ch.len_utf8();
    }

    (result, changed)
}

fn security_case_fold(input: &str) -> String {
    let mut folded = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\u{0131}' | '\u{0130}' => folded.push('i'),
            '\u{00DF}' => folded.push_str("ss"),
            '\u{03C2}' => folded.push('\u{03C3}'),
            '\u{0307}' => {}
            _ => {
                for lower in ch.to_lowercase() {
                    folded.push(lower);
                }
            }
        }
    }
    folded
}

// ── Public API ────────────────────────────────────────────────────

/// Result of canonicalization with encoding metadata.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    pub canonical: String,
    pub encoding_depth: usize,
    pub encodings_detected: HashSet<String>,
    pub was_encoded: bool,
}

/// Options for canonicalization.
#[derive(Debug, Clone, Default)]
pub struct NormalizationOptions {
    pub case_fold: bool,
    pub normalize_ws: bool,
    pub max_length: Option<usize>,
}

/// Normalize an input string to its canonical form.
#[inline]
pub fn canonicalize(input: &str, options: &NormalizationOptions) -> NormalizationResult {
    let max_len = options.max_length.unwrap_or(16384);
    let mut current = if input.len() > max_len {
        input[..max_len].to_string()
    } else {
        input.to_string()
    };
    let mut encodings = HashSet::new();
    let mut depth = 0usize;

    // 1. Overlong UTF-8
    let overlong_detected = detect_overlong_utf8_sequences(&current);
    let (after_overlong, overlong_changed) = decode_overlong_utf8(&current);
    if overlong_changed || overlong_detected {
        encodings.insert("overlong_utf8".to_string());
        depth += 1;
        if overlong_changed {
            current = after_overlong;
        }
    }

    // 2. Iterative URL decoding (interleaved with overlong normalization)
    let mut url_depth = 0usize;
    for _ in 0..MAX_URL_DECODE_LAYERS {
        let Some(decoded_once) = url_decode_once(&current) else {
            break;
        };
        current = decoded_once;
        url_depth += 1;

        // If a URL layer reveals overlong bytes, normalize before next layer.
        let has_overlong = detect_overlong_utf8_sequences(&current);
        let (after_overlong_interleaved, interleaved_changed) = decode_overlong_utf8(&current);
        if interleaved_changed || has_overlong {
            encodings.insert("overlong_utf8".to_string());
            depth += 1;
            if interleaved_changed {
                current = after_overlong_interleaved;
            }
        }
    }
    if url_depth > 0 {
        if url_depth == 1 {
            encodings.insert("url_single".to_string());
        } else {
            encodings.insert("url_double".to_string());
        }
        depth += url_depth;
    }

    // 3. Strip leading BOM markers (UTF-8 / UTF-16 bytes interpreted as text)
    let (after_bom, bom_changed) = strip_bom_markers(&current);
    if bom_changed {
        encodings.insert("bom".to_string());
        depth += 1;
        current = after_bom;
    }

    // 4. HTML5 entity decoding (recursive decode)
    let after_html = decode_html_entities_recursive(&current, 4);
    if after_html != current {
        encodings.insert("html_entity".to_string());
        depth += 1;
        current = after_html;
    }

    // 5. Unicode escape decoding
    let after_unicode = decode_unicode_escapes(&current);
    if after_unicode != current {
        encodings.insert("unicode_escape".to_string());
        depth += 1;
        current = after_unicode;
    }

    let (after_unicode_safety, unicode_safety_changed) = sanitize_unicode_edge_cases(&current);
    if unicode_safety_changed {
        encodings.insert("unicode_edge_case".to_string());
        depth += 1;
        current = after_unicode_safety;
    }

    // 6. Punycode label normalization
    let (after_puny, puny_changed) = normalize_punycode_labels(&current);
    if puny_changed {
        encodings.insert("punycode".to_string());
        depth += 1;
        current = after_puny;
    }

    // 7. Invisible unicode stripping
    let (after_invisible, invisible_changed) = strip_invisible_unicode(&current);
    if invisible_changed {
        encodings.insert("invisible_unicode".to_string());
        depth += 1;
        current = after_invisible;
    }

    // 8. Homoglyph normalization
    let (after_homoglyph, homoglyph_changed) = normalize_homoglyphs(&current);
    if homoglyph_changed {
        encodings.insert("homoglyph".to_string());
        depth += 1;
        current = after_homoglyph;
    }

    // 9. Null byte removal
    let (after_null, null_changed) = remove_null_bytes(&current);
    if null_changed {
        encodings.insert("null_byte".to_string());
        depth += 1;
        current = after_null;
    }

    // 10. Case folding
    if options.case_fold {
        current = security_case_fold(&current);
    }

    // 11. Whitespace normalization
    if options.normalize_ws {
        let mut normalized = String::with_capacity(current.len());
        let mut last_was_ws = true; // trim leading
        for ch in current.chars() {
            if ch.is_whitespace() || ch == '\u{200B}' || ch == '\u{FEFF}' {
                if !last_was_ws {
                    normalized.push(' ');
                    last_was_ws = true;
                }
            } else {
                normalized.push(ch);
                last_was_ws = false;
            }
        }
        // Trim trailing space
        if normalized.ends_with(' ') {
            normalized.pop();
        }
        current = normalized;
    }

    let was_encoded = current != input;

    NormalizationResult {
        canonical: current,
        encoding_depth: depth,
        encodings_detected: encodings,
        was_encoded,
    }
}

/// Quick canonical form — just the string, no metadata.
#[inline]
pub fn quick_canonical(input: &str) -> String {
    let (normalized, _) = sanitize_unicode_edge_cases(&canonicalize(input, &NormalizationOptions::default()).canonical);
    normalized
}

/// Detect encoding evasion — multiple encoding layers indicate deliberate evasion.
#[inline]
pub fn detect_encoding_evasion(input: &str) -> EncodingEvasionResult {
    let result = canonicalize(input, &NormalizationOptions::default());

    let is_normal_url = result.encodings_detected.len() == 1
        && result.encodings_detected.contains("url_single");

    let is_evasion = result.encoding_depth >= 2 && !is_normal_url;

    let confidence = if is_evasion {
        (0.60 + (result.encoding_depth as f64 - 1.0) * 0.10
            + (result.encodings_detected.len() as f64 - 1.0) * 0.08)
            .min(0.95)
    } else {
        0.0
    };

    EncodingEvasionResult {
        is_evasion,
        depth: result.encoding_depth,
        encodings: result.encodings_detected.into_iter().collect(),
        confidence,
    }
}

/// Result of encoding evasion detection.
#[derive(Debug, Clone)]
pub struct EncodingEvasionResult {
    pub is_evasion: bool,
    pub depth: usize,
    pub encodings: Vec<String>,
    pub confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_basic() {
        let r = canonicalize("%27%20OR%201%3D1", &NormalizationOptions::default());
        assert_eq!(r.canonical, "' OR 1=1");
        assert!(r.was_encoded);
        assert!(r.encodings_detected.contains("url_single"));
    }

    #[test]
    fn double_url_decode() {
        let r = canonicalize("%2527%2520OR", &NormalizationOptions::default());
        assert_eq!(r.canonical, "' OR");
        assert!(r.encodings_detected.contains("url_double"));
    }

    #[test]
    fn html_entity_decode() {
        let r = canonicalize("&lt;script&gt;alert(1)&lt;/script&gt;", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>alert(1)</script>");
        assert!(r.encodings_detected.contains("html_entity"));
    }

    #[test]
    fn recursive_html_entities_expand() {
        let r = canonicalize("&amp;lt;script&amp;gt;", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn html_numeric_entity() {
        let r = canonicalize("&#60;script&#62;", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn html_hex_entity() {
        let r = canonicalize("&#x3C;script&#x3E;", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn unicode_escape() {
        let r = canonicalize("\\u003Cscript\\u003E", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
        assert!(r.encodings_detected.contains("unicode_escape"));
    }

    #[test]
    fn hex_escape() {
        let r = canonicalize("\\x3Cscript\\x3E", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn null_byte_removal() {
        let r = canonicalize("admin%00.php", &NormalizationOptions::default());
        assert_eq!(r.canonical, "admin.php");
        assert!(r.encodings_detected.contains("null_byte"));
    }

    #[test]
    fn strip_invisible_unicode() {
        let r = canonicalize("pa\u{200b}ylo\u{200d}ad", &NormalizationOptions::default());
        assert_eq!(r.canonical, "payload");
        assert!(r.encodings_detected.contains("unicode_edge_case") || r.encodings_detected.contains("invisible_unicode"));
    }

    #[test]
    fn homoglyph_normalization() {
        let r = canonicalize("раураl", &NormalizationOptions::default()); // looks like 'paypal' with Cyrillic a,p,a, etc
        assert_eq!(r.canonical, "paypal");
    }

    #[test]
    fn punycode_host_normalization() {
        let r = canonicalize("https://xn--bcher-kva.example", &NormalizationOptions::default());
        assert_eq!(r.canonical, "https://bücher.example");
        assert!(r.encodings_detected.contains("punycode"));
    }

    #[test]
    fn case_fold() {
        let r = canonicalize("UNION SELECT", &NormalizationOptions {
            case_fold: true,
            ..Default::default()
        });
        assert_eq!(r.canonical, "union select");
    }

    #[test]
    fn whitespace_normalize() {
        let r = canonicalize("  hello   world  ", &NormalizationOptions {
            normalize_ws: true,
            ..Default::default()
        });
        assert_eq!(r.canonical, "hello world");
    }

    #[test]
    fn no_encoding_passthrough() {
        let r = canonicalize("normal input", &NormalizationOptions::default());
        assert_eq!(r.canonical, "normal input");
        assert!(!r.was_encoded);
        assert_eq!(r.encoding_depth, 0);
    }

    #[test]
    fn evasion_detection_double() {
        let r = detect_encoding_evasion("%2527%2520OR%25201%253D1");
        assert!(r.is_evasion);
        assert!(r.depth >= 2);
        assert!(r.confidence > 0.5);
    }

    #[test]
    fn evasion_detection_single_url_normal() {
        let r = detect_encoding_evasion("%20hello%20world");
        assert!(!r.is_evasion, "single URL encoding is normal HTTP transport");
    }

    #[test]
    fn quick_canonical_works() {
        assert_eq!(quick_canonical("%3Cscript%3E"), "<script>");
    }

    #[test]
    fn quick_canonical_removes_surrogate_unicode_escapes() {
        assert_eq!(quick_canonical("\\uD800"), "\u{FFFD}");
    }

    #[test]
    fn quick_canonical_removes_combining_marks() {
        assert_eq!(quick_canonical("a\u{0301}b"), "ab");
    }

    #[test]
    fn quick_canonical_strips_zero_width_joiners() {
        assert_eq!(quick_canonical("pa\u{200D}y"), "pay");
    }

    #[test]
    fn quick_canonical_strips_bidi_override() {
        assert_eq!(quick_canonical("sc\u{202D}ript"), "script");
    }

    #[test]
    fn quick_canonical_normalizes_homoglyph_path() {
        assert_eq!(quick_canonical("/admin/раураl/profile"), "/admin/paypal/profile");
    }

    #[test]
    fn quick_canonical_normalizes_bidi_in_hostname() {
        assert_eq!(quick_canonical("https://example\u{202E}com/@"), "https://examplecom/@");
    }

    #[test]
    fn quick_canonical_normalizes_homoglyph_hostname() {
        assert_eq!(quick_canonical("https://раураl.com/account"), "https://paypal.com/account");
    }

    #[test]
    fn quick_canonical_strips_multiple_zero_width_characters() {
        assert_eq!(quick_canonical("a\u{200B}\u{200C}\u{200D}\u{FEFF}b"), "ab");
    }

    #[test]
    fn quick_canonical_overlong_utf8_surfaces_as_normalized_path_segment() {
        assert_eq!(quick_canonical("%C0%AF"), "/");
    }

    #[test]
    fn overlong_utf8_two_byte_slash() {
        let r = canonicalize("%C0%AFetc/passwd", &NormalizationOptions::default());
        assert_eq!(r.canonical, "/etc/passwd");
    }

    #[test]
    fn overlong_utf8_two_byte_letter() {
        let r = canonicalize("%C1%81lert(1)", &NormalizationOptions::default());
        assert_eq!(r.canonical, "Alert(1)");
    }

    #[test]
    fn overlong_utf8_three_byte_slash() {
        let r = canonicalize("%E0%80%AFevil", &NormalizationOptions::default());
        assert_eq!(r.canonical, "/evil");
    }

    #[test]
    fn overlong_utf8_three_byte_lt() {
        let r = canonicalize("%E0%80%BCscript%E0%80%BE", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn overlong_utf8_four_byte_slash() {
        let r = canonicalize("%F0%80%80%AFetc", &NormalizationOptions::default());
        assert_eq!(r.canonical, "/etc");
    }

    #[test]
    fn overlong_utf8_four_byte_lt_gt() {
        let r = canonicalize("%F0%80%80%BCscript%F0%80%80%BE", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn overlong_utf8_null_then_removed() {
        let r = canonicalize("%C0%80admin.php", &NormalizationOptions::default());
        assert_eq!(r.canonical, "admin.php");
        assert!(r.encodings_detected.contains("overlong_utf8"));
        assert!(r.encodings_detected.contains("null_byte"));
    }

    #[test]
    fn overlong_utf8_mixed_layers() {
        let r = canonicalize("%25C0%25AFetc", &NormalizationOptions::default());
        assert_eq!(r.canonical, "/etc");
    }

    #[test]
    fn overlong_utf8_keeps_non_overlong() {
        let r = canonicalize("%E2%82%AC", &NormalizationOptions::default());
        assert_eq!(r.canonical, "€");
    }

    #[test]
    fn overlong_utf8_detects_multiple_tokens() {
        let r = canonicalize("%C0%AE%C0%AE%C0%AF", &NormalizationOptions::default());
        assert_eq!(r.canonical, "../");
    }

    #[test]
    fn quad_url_encoded_dot_decodes_fully() {
        let r = canonicalize("%2525252e", &NormalizationOptions::default());
        assert_eq!(r.canonical, ".");
        assert!(r.encoding_depth >= 4);
    }

    #[test]
    fn quad_url_encoded_path_traversal_decodes_fully() {
        let r = canonicalize("%2525252e%2525252e%25252fetc%25252fpasswd", &NormalizationOptions::default());
        assert_eq!(r.canonical, "../etc/passwd");
        assert!(r.encoding_depth >= 4);
    }

    #[test]
    fn case_fold_turkish_dotless_i() {
        let r = canonicalize("UN\u{0131}ON SELECT", &NormalizationOptions {
            case_fold: true,
            ..Default::default()
        });
        assert_eq!(r.canonical, "union select");
    }

    #[test]
    fn case_fold_turkish_capital_i_with_dot() {
        let r = canonicalize("UN\u{0130}ON SELECT", &NormalizationOptions {
            case_fold: true,
            ..Default::default()
        });
        assert_eq!(r.canonical, "union select");
    }

    #[test]
    fn case_fold_sharp_s_to_ss() {
        let r = canonicalize("PA\u{00DF}WORD", &NormalizationOptions {
            case_fold: true,
            ..Default::default()
        });
        assert_eq!(r.canonical, "password");
    }

    #[test]
    fn case_fold_final_sigma_to_sigma() {
        let r = canonicalize("UNI\u{03C2}ON", &NormalizationOptions {
            case_fold: true,
            ..Default::default()
        });
        assert_eq!(r.canonical, "uniσon");
    }

    #[test]
    fn mixed_chain_url_encoded_numeric_entity() {
        let r = canonicalize("%26%2360%3bscript%26%2362%3b", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn mixed_chain_url_encoded_unicode_escape() {
        let r = canonicalize("%5cu003cscript%5cu003e", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn mixed_chain_double_url_then_unicode_escape() {
        let r = canonicalize("%255Cu003cscript%255Cu003e", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn mixed_chain_url_html_and_unicode() {
        let r = canonicalize("%26lt%3b%5Cu0078%5Cu0079%26gt%3b", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<xy>");
    }

    #[test]
    fn null_byte_middle_percent_encoded() {
        let r = canonicalize("abc%00def", &NormalizationOptions::default());
        assert_eq!(r.canonical, "abcdef");
    }

    #[test]
    fn null_byte_middle_literal() {
        let r = canonicalize("abc\0def", &NormalizationOptions::default());
        assert_eq!(r.canonical, "abcdef");
    }

    #[test]
    fn null_byte_mixed_with_url_decode() {
        let r = canonicalize("%61%00%62", &NormalizationOptions::default());
        assert_eq!(r.canonical, "ab");
    }

    #[test]
    fn strips_utf8_bom_char() {
        let r = canonicalize("\u{FEFF}<script>", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
        assert!(r.encodings_detected.contains("bom") || r.encodings_detected.contains("invisible_unicode"));
    }

    #[test]
    fn strips_utf16_bom_big_endian_marker() {
        let r = canonicalize("\u{00FE}\u{00FF}<script>", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
        assert!(r.encodings_detected.contains("bom"));
    }

    #[test]
    fn strips_utf16_bom_little_endian_marker() {
        let r = canonicalize("\u{00FF}\u{00FE}<script>", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
        assert!(r.encodings_detected.contains("bom"));
    }

    #[test]
    fn strips_url_encoded_utf8_bom() {
        let r = canonicalize("%EF%BB%BF%3Cscript%3E", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
    }

    #[test]
    fn strips_rlo_from_middle() {
        let r = canonicalize("sc\u{202E}ript", &NormalizationOptions::default());
        assert_eq!(r.canonical, "script");
        assert!(r.encodings_detected.contains("invisible_unicode"));
    }

    #[test]
    fn strips_variation_selector_fe0f() {
        let r = canonicalize("ja\u{FE0F}vascript", &NormalizationOptions::default());
        assert_eq!(r.canonical, "javascript");
        assert!(r.encodings_detected.contains("invisible_unicode"));
    }

    #[test]
    fn strips_variation_selector_fe00() {
        let r = canonicalize("sc\u{FE00}ript", &NormalizationOptions::default());
        assert_eq!(r.canonical, "script");
        assert!(r.encodings_detected.contains("invisible_unicode"));
    }

    #[test]
    fn strips_multiple_variation_selectors() {
        let r = canonicalize("a\u{FE0E}l\u{FE0F}e\u{FE00}rt", &NormalizationOptions::default());
        assert_eq!(r.canonical, "alert");
    }

    #[test]
    fn url_multi_layer_matrix_10_cases() {
        let cases = [
            ("%25252e", "."),
            ("%2525252e", "."),
            ("%252525252e", "."),
            ("%25252525252e", "."),
            ("%2525252525252e", "."),
            ("%252525252525252e", "."),
            ("%25252f", "/"),
            ("%2525252f", "/"),
            ("%2525252e%2525252e%2525252f", "../"),
            ("%2525252e%2525252e%2525252fetc", "../etc"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
        }
    }

    #[test]
    fn case_fold_edge_matrix_10_cases() {
        let opts = NormalizationOptions {
            case_fold: true,
            ..Default::default()
        };
        let cases = [
            ("UN\u{0131}ON", "union"),
            ("UN\u{0130}ON", "union"),
            ("PA\u{00DF}WORD", "password"),
            ("STRA\u{00DF}E", "strasse"),
            ("UNI\u{03C2}ON", "uniσon"),
            ("\u{0130}\u{0131}", "ii"),
            ("A\u{0130}B\u{0131}C", "aibic"),
            ("\u{00DF}\u{00DF}", "ssss"),
            ("TE\u{03C2}T", "teσt"),
            ("I\u{0307}NPUT", "input"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &opts);
            assert_eq!(r.canonical, expected, "input={input}");
        }
    }

    #[test]
    fn mixed_chain_matrix_10_cases() {
        let cases = [
            ("%26%2360%3b", "<"),
            ("%26%2362%3b", ">"),
            ("%26lt%3b", "<"),
            ("%26gt%3b", ">"),
            ("%5cu003c", "<"),
            ("%5Cu003e", ">"),
            ("%255Cu003c", "<"),
            ("%255Cu003e", ">"),
            ("%26%23x3c%3b", "<"),
            ("%2526%252360%253b", "<"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
        }
    }

    #[test]
    fn null_byte_middle_matrix_10_cases() {
        let cases = [
            ("ab%00cd", "abcd"),
            ("ab%00%00cd", "abcd"),
            ("%00ab%00", "ab"),
            ("a\0b", "ab"),
            ("\0ab\0", "ab"),
            ("%61%00%62", "ab"),
            ("%2500ab", "ab"),
            ("%252500ab", "ab"),
            ("mid%00dle%00x", "middlex"),
            ("nul\0l%00x", "nullx"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
        }
    }

    #[test]
    fn bom_matrix_10_cases() {
        let cases = [
            ("\u{FEFF}<x>", "<x>"),
            ("\u{00FE}\u{00FF}<x>", "<x>"),
            ("\u{00FF}\u{00FE}<x>", "<x>"),
            ("%EF%BB%BF%3Cx%3E", "<x>"),
            ("%25EF%25BB%25BF%3Cx%3E", "<x>"),
            ("\u{FEFF}\u{FEFF}<x>", "<x>"),
            ("\u{00FE}\u{00FF}\u{00FE}\u{00FF}<x>", "<x>"),
            ("\u{00EF}\u{00BB}\u{00BF}<x>", "<x>"),
            ("\u{FEFF}%3Cx%3E", "<x>"),
            ("%EF%BB%BF%253Cx%253E", "<x>"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
        }
    }

    #[test]
    fn rlo_matrix_10_cases() {
        let cases = [
            ("sc\u{202E}ript", "script"),
            ("ja\u{202E}vascript", "javascript"),
            ("\u{202E}alert(1)", "alert(1)"),
            ("al\u{202E}ert(1)", "alert(1)"),
            ("<scr\u{202E}ipt>", "<script>"),
            ("%E2%80%AEalert(1)", "alert(1)"),
            ("ab\u{202E}cd\u{202E}ef", "abcdef"),
            ("x\u{202E}x\u{202E}x", "xxx"),
            ("pre\u{202E}fix", "prefix"),
            ("s\u{202E}c\u{202E}r\u{202E}ipt", "script"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
        }
    }

    #[test]
    fn variation_selector_matrix_10_cases() {
        let cases = [
            ("ja\u{FE0F}vascript", "javascript"),
            ("sc\u{FE00}ript", "script"),
            ("a\u{FE0E}lert", "alert"),
            ("al\u{FE0F}ert", "alert"),
            ("ale\u{FE01}rt", "alert"),
            ("aler\u{FE02}t", "alert"),
            ("s\u{FE03}c\u{FE04}r\u{FE05}i\u{FE06}p\u{FE07}t", "script"),
            ("<\u{FE08}script\u{FE09}>", "<script>"),
            ("%EF%B8%8Fscript", "script"),
            ("te\u{FE0A}st", "test"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
        }
    }

    #[test]
    fn html_entity_double_decode_guard_blocking_numeric_ampersand_chain() {
        let r = canonicalize("&#x26;#x3C;script&#x26;#x3E;", &NormalizationOptions::default());
        assert_eq!(r.canonical, "&#x3C;script&#x3E;");
        assert!(!r.canonical.contains('<'));
        assert!(!r.canonical.contains('>'));
        assert!(r.encodings_detected.contains("html_entity"));
    }

    #[test]
    fn html_entity_double_decode_still_allows_named_ampersand_chain() {
        let r = canonicalize("&amp;lt;script&amp;gt;", &NormalizationOptions::default());
        assert_eq!(r.canonical, "<script>");
        assert!(r.encodings_detected.contains("html_entity"));
    }

    #[test]
    fn html_entity_double_decode_matrix_8_cases() {
        let cases = [
            ("&#x26;#x3C;", "&#x3C;"),
            ("%26%23x3c%3b", "<"),
            ("%26%23x3e%3b", ">"),
            ("%26lt%3b", "<"),
            ("%26gt%3b", ">"),
            ("%5cu0078%5Cu0079", "xy"),
            ("%255Cu0078%255Cu0079", "xy"),
            ("&#x26;script&#x3e;", "&script>"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
        }
    }

    #[test]
    fn overlong_utf8_detection_8_cases() {
        let cases = [
            "%C0%AF",
            "%E0%80%AF",
            "%F0%80%80%AF",
            "%25C0%25AF",
            "%2525C0%2525AF",
            "%E0%80",
            "%25E0%2580",
            "%25E0%2580%25AFe",
        ];
        for input in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert!(r.encodings_detected.contains("overlong_utf8"), "input={input}");
            assert_ne!(r.canonical, "");
        }
    }

    #[test]
    fn charset_like_multibyte_bytes_do_not_spawn_false_html() {
        let cases = [
            "%8E%A0%8E%AE",
            "%8F%E3%81%82",
            "%A1%5C%9F",
        ];
        for input in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert!(!r.canonical.contains('<') && !r.canonical.contains('>'));
            assert!(r.was_encoded);
        }
    }

    #[test]
    fn bidi_control_and_zero_width_matrix_10_cases() {
        let cases = [
            ("a\u{200B}b\u{200C}c\u{200D}d", "abcd"),
            ("http://exam\u{FEFF}ple.com", "http://example.com"),
            ("ab\u{200E}cd\u{200F}", "abcd"),
            ("\u{202E}alert(1)", "alert(1)"),
            ("abc\u{202D}def", "abcdef"),
            ("\u{202A}x\u{202B}y\u{202C}z", "xyz"),
            ("\u{2066}admin\u{2069}/", "admin/"),
            ("\u{2067}a\u{2068}b\u{2069}c\u{2066}", "abc"),
            ("\u{061C}payload\u{061C}", "payload"),
            ("s\u{200D}c\u{200C}r\u{200B}i\u{200D}p\u{200B}t", "script"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
            assert!(
                r.encodings_detected.contains("invisible_unicode")
                    || r.encodings_detected.contains("unicode_edge_case"),
                "input={input}"
            );
        }
    }

    #[test]
    fn homoglyph_matrix_8_cases() {
        let cases = [
            ("\u{0432}\u{0435}\u{0440}\u{043D}\u{0430}\u{0441}", "vepHac"),
            ("\u{0412}\u{0418}\u{041B}\u{041A}\u{041E}", "VILKO"),
            ("\u{03B1}\u{03B5}\u{03BF}\u{03B9}\u{03C5}\u{03C3}", "aeoiys"),
            ("\u{03A7}\u{03C5}\u{03A5}\u{03A3}", "XyYS"),
            ("\u{03B8}\u{03B5}\u{03C1}\u{03C3}\u{03B5}", "hepse"),
            ("/\u{0412}\u{0435}\u{0440}\u{043D}\u{0430}\u{0441}", "/VepHac"),
            ("admin\u{0430}\u{03BF}\u{03B7}\u{03BC}", "adminaohm"),
        ("sc\u{03BF}\u{03B9}\u{0440}", "scoip"),
        ];
        for (input, expected) in cases {
            let r = canonicalize(input, &NormalizationOptions::default());
            assert_eq!(r.canonical, expected, "input={input}");
            assert!(r.encodings_detected.contains("homoglyph"));
        }
    }
}
