use serde::{Deserialize, Serialize};

use crate::types::{MAX_TOKEN_COUNT, MAX_TOKENIZER_INPUT};

use super::{Token, TokenStream, to_value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTokenType {
    Separator,
    Traversal,
    CurrentDir,
    Segment,
    SensitiveTarget,
    NullByte,
    Extension,
    EncodingLayer,
    ParamInjection,
    TrailingDot,
    Whitespace,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PathTokenizer;

impl PathTokenizer {
    pub fn tokenize(&self, input: &str) -> TokenStream<PathTokenType> {
        let mut end = input.len().min(MAX_TOKENIZER_INPUT);
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }
        let bounded = &input[..end];

        let (decoded, encoding_layers) = decode_path_encoding(bounded);
        let bytes = decoded.as_bytes();
        let original_bytes = bounded.as_bytes();

        let mut tokens = Vec::new();
        let mut i = 0usize;

        while i < bytes.len() && tokens.len() < MAX_TOKEN_COUNT {
            if bytes[i] == b'\0'
                || matches_subseq(bytes, i, b"%00")
                || matches_subseq(bytes, i, b"\\x00")
            {
                let len = if bytes[i] == b'\0' {
                    1
                } else if matches_subseq(bytes, i, b"%00") {
                    3
                } else {
                    4
                };
                push(&mut tokens, PathTokenType::NullByte, bytes, i, i + len);
                i += len;
                continue;
            }

            if bytes[i] == b'/' || bytes[i] == b'\\' {
                push(&mut tokens, PathTokenType::Separator, bytes, i, i + 1);
                i += 1;
                continue;
            }

            if bytes[i].is_ascii_whitespace() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                push(&mut tokens, PathTokenType::Whitespace, bytes, start, i);
                continue;
            }

            if bytes[i] == b';' {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'/' && bytes[i] != b'\\' {
                    i += 1;
                }
                push(&mut tokens, PathTokenType::ParamInjection, bytes, start, i);
                continue;
            }

            let seg_start = i;
            while i < bytes.len()
                && !matches!(bytes[i], b'/' | b'\\' | b';' | b'\0')
                && !bytes[i].is_ascii_whitespace()
            {
                i += 1;
            }
            let segment = to_value(bytes, seg_start, i);

            if segment == ".." {
                push(&mut tokens, PathTokenType::Traversal, bytes, seg_start, i);
                continue;
            }

            if segment == "." {
                push(&mut tokens, PathTokenType::CurrentDir, bytes, seg_start, i);
                continue;
            }

            if is_trailing_dot_segment(&segment) {
                push(&mut tokens, PathTokenType::TrailingDot, bytes, seg_start, i);
                continue;
            }

            if !segment.is_empty() {
                let remaining_path = extract_path_from_here(bytes, seg_start);
                if is_sensitive_path(&remaining_path) {
                    let full_end = seg_start + remaining_path.len();
                    let actual_end = full_end.min(bytes.len());
                    push(
                        &mut tokens,
                        PathTokenType::SensitiveTarget,
                        bytes,
                        seg_start,
                        actual_end,
                    );
                    i = actual_end;
                    continue;
                }

                let orig_segment = if seg_start < original_bytes.len() {
                    let end_idx = i.min(original_bytes.len());
                    String::from_utf8_lossy(&original_bytes[seg_start..end_idx]).into_owned()
                } else {
                    String::new()
                };
                if is_encoded_special(&orig_segment) || encoding_layers > 1 {
                    push(
                        &mut tokens,
                        PathTokenType::EncodingLayer,
                        bytes,
                        seg_start,
                        i,
                    );
                } else {
                    if has_extension(&segment) {
                        push(&mut tokens, PathTokenType::Extension, bytes, seg_start, i);
                    } else {
                        push(&mut tokens, PathTokenType::Segment, bytes, seg_start, i);
                    }
                }
                continue;
            }

            push(
                &mut tokens,
                PathTokenType::Unknown,
                bytes,
                seg_start,
                seg_start + 1,
            );
            i += 1;
        }

        TokenStream::new(tokens)
    }
}

fn has_extension(segment: &str) -> bool {
    if let Some(idx) = segment.rfind('.') {
        let ext = &segment[idx + 1..];
        return !ext.is_empty() && ext.len() <= 8 && ext.chars().all(|c| c.is_ascii_alphanumeric());
    }
    false
}

fn extract_path_from_here(bytes: &[u8], start: usize) -> String {
    let mut end = start;
    while end < bytes.len()
        && !matches!(
            bytes[end],
            b' ' | b'\t' | b'\r' | b'\n' | b'?' | b'#' | b'\0'
        )
    {
        end += 1;
    }
    let mut path = to_value(bytes, start, end);
    while path.starts_with('/') || path.starts_with('\\') {
        path.remove(0);
    }
    path.replace('\\', "/")
}

fn is_trailing_dot_segment(segment: &str) -> bool {
    if !segment.ends_with('.') || segment.len() <= 1 {
        return false;
    }
    let trimmed = segment.trim_end_matches('.');
    !has_extension(trimmed)
}

fn decode_path_encoding(input: &str) -> (String, usize) {
    let mut current = input.to_string();
    let mut layers = 0usize;

    while layers < 4 {
        let decoded = percent_decode_once(&current);
        if decoded == current {
            break;
        }
        current = decoded;
        layers += 1;
    }

    (current, layers)
}

fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() {
                let hex = [h1, h2];
                let hex_str = String::from_utf8_lossy(&hex);
                if let Ok(v) = u8::from_str_radix(&hex_str, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn is_encoded_special(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
        || lower.contains("%c0%ae")
        || lower.contains("%c0%af")
        || lower.contains("%e0%80%ae")
        || lower.contains("%252e")
}

fn matches_subseq(haystack: &[u8], start: usize, needle: &[u8]) -> bool {
    start + needle.len() <= haystack.len() && &haystack[start..start + needle.len()] == needle
}

fn is_sensitive_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();

    let exact = [
        "etc/passwd",
        "etc/shadow",
        "etc/hosts",
        ".env",
        "boot.ini",
        "wp-config.php",
        "web.config",
        ".htaccess",
        ".htpasswd",
    ];

    if exact.contains(&p.as_str()) {
        return true;
    }

    p.starts_with("etc/")
        || p.starts_with("proc/self/")
        || p.starts_with(".git/")
        || p.starts_with(".ssh/")
        || p.starts_with(".aws/credentials")
        || p.starts_with(".docker/config.json")
        || p.starts_with("windows/")
        || p.starts_with("inetpub/wwwroot/web.config")
        || p.starts_with("config/database.yml")
}

fn push(
    tokens: &mut Vec<Token<PathTokenType>>,
    ty: PathTokenType,
    bytes: &[u8],
    start: usize,
    end: usize,
) {
    tokens.push(Token {
        token_type: ty,
        value: to_value(bytes, start, end),
        start,
        end,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_basic_tokenization() {
        let stream = PathTokenizer.tokenize("/var/www/index.html");
        assert!(stream.has(PathTokenType::Separator));
        assert!(stream.has(PathTokenType::Extension));
    }

    #[test]
    fn path_edge_traversal_and_sensitive_target() {
        let stream = PathTokenizer.tokenize("../../etc/passwd");
        assert!(stream.has(PathTokenType::Traversal));
        assert!(stream.has(PathTokenType::SensitiveTarget));
    }

    #[test]
    fn path_encoding_detection() {
        let stream = PathTokenizer.tokenize("%2561bc/def");
        assert!(stream.has(PathTokenType::EncodingLayer));
    }

    #[test]
    fn path_max_input_bound() {
        let s = format!("{}etc/passwd", "../".repeat(MAX_TOKENIZER_INPUT));
        let stream = PathTokenizer.tokenize(&s);
        assert!(stream.all().len() <= MAX_TOKEN_COUNT);
    }

    #[test]
    fn path_empty_input() {
        let stream = PathTokenizer.tokenize("");
        assert!(stream.all().is_empty());
    }
}
