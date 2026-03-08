use serde::{Deserialize, Serialize};

use crate::types::{MAX_TOKEN_COUNT, MAX_TOKENIZER_INPUT};

use super::{Token, TokenStream, to_value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlTokenType {
    Scheme,
    AuthoritySep,
    Userinfo,
    HostInternal,
    HostMetadata,
    HostExternal,
    HostObfuscated,
    Port,
    PathSegment,
    Query,
    Fragment,
    Ipv6,
    Whitespace,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UrlTokenizer;

impl UrlTokenizer {
    pub fn tokenize(&self, input: &str) -> TokenStream<UrlTokenType> {
        let mut end = input.len().min(MAX_TOKENIZER_INPUT);
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }
        let bounded = &input[..end];
        let bytes = bounded.as_bytes();

        let mut tokens = Vec::new();
        let mut i = 0usize;

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            push(&mut tokens, UrlTokenType::Whitespace, bytes, start, i);
        }

        if i < bytes.len() {
            if let Some((scheme_len, has_slashes)) = parse_scheme(&bytes[i..]) {
                let start = i;
                push(
                    &mut tokens,
                    UrlTokenType::Scheme,
                    bytes,
                    start,
                    start + scheme_len + 1,
                );
                i += scheme_len + 1;

                if has_slashes {
                    push(&mut tokens, UrlTokenType::AuthoritySep, bytes, i, i + 2);
                    i += 2;
                }

                let scheme = to_value(bytes, start, start + scheme_len).to_ascii_lowercase();
                if scheme != "data" {
                    i = self.parse_authority(bytes, i, &mut tokens);
                }
            } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
                push(&mut tokens, UrlTokenType::AuthoritySep, bytes, i, i + 2);
                i += 2;
                i = self.parse_authority(bytes, i, &mut tokens);
            }
        }

        while i < bytes.len() && tokens.len() < MAX_TOKEN_COUNT {
            if bytes[i] == b'/' {
                let start = i;
                i += 1;
                while i < bytes.len()
                    && bytes[i] != b'/'
                    && bytes[i] != b'?'
                    && bytes[i] != b'#'
                    && !bytes[i].is_ascii_whitespace()
                {
                    i += 1;
                }
                push(&mut tokens, UrlTokenType::PathSegment, bytes, start, i);
            } else if bytes[i] == b'?' {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'#' && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                push(&mut tokens, UrlTokenType::Query, bytes, start, i);
            } else if bytes[i] == b'#' {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                push(&mut tokens, UrlTokenType::Fragment, bytes, start, i);
            } else if bytes[i].is_ascii_whitespace() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                push(&mut tokens, UrlTokenType::Whitespace, bytes, start, i);
            } else {
                let start = i;
                while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'?' | b'#') {
                    i += 1;
                }
                if i > start {
                    push(&mut tokens, UrlTokenType::Unknown, bytes, start, i);
                }
            }
        }

        TokenStream::new(tokens)
    }

    fn parse_authority(
        &self,
        bytes: &[u8],
        mut pos: usize,
        tokens: &mut Vec<Token<UrlTokenType>>,
    ) -> usize {
        let remaining = &bytes[pos..];
        if let Some(at_idx) = remaining.iter().position(|&b| b == b'@') {
            let slash_idx = remaining.iter().position(|&b| b == b'/');
            if slash_idx.is_none() || at_idx < slash_idx.unwrap_or(usize::MAX) {
                let userinfo = &remaining[..=at_idx];
                if !userinfo.iter().any(|b| b.is_ascii_whitespace()) {
                    push(tokens, UrlTokenType::Userinfo, bytes, pos, pos + userinfo.len());
                    pos += userinfo.len();
                }
            }
        }

        let host_start = pos;
        if pos < bytes.len() && bytes[pos] == b'[' {
            if let Some(close_idx) = bytes[pos..].iter().position(|&b| b == b']') {
                let end = pos + close_idx + 1;
                let host = to_value(bytes, pos, end);
                let host_type = if is_ipv6_internal(&host) {
                    UrlTokenType::HostInternal
                } else {
                    UrlTokenType::HostExternal
                };
                push(tokens, host_type, bytes, pos, end);
                pos = end;
            }
        } else {
            while pos < bytes.len() && !matches!(bytes[pos], b' ' | b'\t' | b'\r' | b'\n' | b'/' | b':' | b'?' | b'#') {
                pos += 1;
            }
            if pos > host_start {
                let host = to_value(bytes, host_start, pos);
                let host_type = classify_host(&host.to_ascii_lowercase());
                push(tokens, host_type, bytes, host_start, pos);
            }
        }

        if pos < bytes.len() && bytes[pos] == b':' {
            let port_start = pos;
            pos += 1;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            push(tokens, UrlTokenType::Port, bytes, port_start, pos);
        }

        pos
    }
}

fn parse_scheme(bytes: &[u8]) -> Option<(usize, bool)> {
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return None;
    }

    let mut i = 1usize;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'+' | b'.' | b'-')) {
        i += 1;
    }

    if i >= bytes.len() || bytes[i] != b':' {
        return None;
    }

    let has_slashes = i + 2 < bytes.len() && bytes[i + 1] == b'/' && bytes[i + 2] == b'/';
    Some((i, has_slashes))
}

fn classify_host(host: &str) -> UrlTokenType {
    if is_metadata_host(host) {
        UrlTokenType::HostMetadata
    } else if is_internal_hostname(host) || is_private_ipv4(host) || is_ipv6_internal(host) {
        UrlTokenType::HostInternal
    } else if is_obfuscated_ip(host) {
        UrlTokenType::HostObfuscated
    } else {
        UrlTokenType::HostExternal
    }
}

fn is_metadata_host(host: &str) -> bool {
    matches!(
        host,
        "169.254.169.254"
            | "metadata.google.internal"
            | "metadata.google"
            | "100.100.100.200"
            | "fd00:ec2::254"
    )
}

fn is_internal_hostname(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "localhost.localdomain" | "ip6-localhost" | "ip6-loopback"
    )
}

fn is_private_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let mut nums = [0u16; 4];
    for (idx, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if let Ok(v) = p.parse::<u16>() {
            if v > 255 {
                return false;
            }
            nums[idx] = v;
        } else {
            return false;
        }
    }

    (nums[0] == 127)
        || (nums[0] == 10)
        || (nums[0] == 172 && (16..=31).contains(&nums[1]))
        || (nums[0] == 192 && nums[1] == 168)
        || (nums == [0, 0, 0, 0])
}

fn is_ipv6_internal(host: &str) -> bool {
    let stripped = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if stripped == "::1" || stripped == "::" || stripped == "0000:0000:0000:0000:0000:0000:0000:0001" {
        return true;
    }
    if let Some(mapped) = stripped.strip_prefix("::ffff:") {
        return is_private_ipv4(mapped);
    }
    false
}

fn is_obfuscated_ip(host: &str) -> bool {
    if let Some(hex) = host.strip_prefix("0x") {
        if let Ok(num) = u32::from_str_radix(hex, 16) {
            let ip = num_to_ipv4(num);
            return is_private_ipv4(&ip) || num == 2_852_039_166;
        }
    }

    if host.len() >= 8 && host.len() <= 10 && host.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(num) = host.parse::<u32>() {
            let ip = num_to_ipv4(num);
            return is_private_ipv4(&ip) || num == 2_852_039_166;
        }
    }

    if host.starts_with('0') && host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            let mut parsed = [0u16; 4];
            for (i, part) in parts.iter().enumerate() {
                if let Ok(v) = u16::from_str_radix(part, 8) {
                    if v > 255 {
                        return false;
                    }
                    parsed[i] = v;
                } else {
                    return false;
                }
            }
            let ip = format!("{}.{}.{}.{}", parsed[0], parsed[1], parsed[2], parsed[3]);
            return is_private_ipv4(&ip);
        }
    }

    false
}

fn num_to_ipv4(num: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (num >> 24) & 0xff,
        (num >> 16) & 0xff,
        (num >> 8) & 0xff,
        num & 0xff
    )
}

fn push(tokens: &mut Vec<Token<UrlTokenType>>, ty: UrlTokenType, bytes: &[u8], start: usize, end: usize) {
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
    fn url_basic_tokenization() {
        let stream = UrlTokenizer.tokenize("https://example.com/path?a=1#f");
        assert!(stream.has(UrlTokenType::Scheme));
        assert!(stream.has(UrlTokenType::HostExternal));
        assert!(stream.has(UrlTokenType::PathSegment));
    }

    #[test]
    fn url_edge_ipv6_internal() {
        let stream = UrlTokenizer.tokenize("http://[::1]/admin");
        assert!(stream.has(UrlTokenType::HostInternal));
    }

    #[test]
    fn url_encoding_detection_obfuscated_host() {
        let stream = UrlTokenizer.tokenize("http://0x7f000001/");
        assert!(stream.has(UrlTokenType::HostObfuscated));
    }

    #[test]
    fn url_max_input_bound() {
        let s = format!("http://example.com/{}", "a".repeat(MAX_TOKENIZER_INPUT + 5000));
        let stream = UrlTokenizer.tokenize(&s);
        assert!(stream.all().len() <= MAX_TOKEN_COUNT);
    }

    #[test]
    fn url_empty_input() {
        let stream = UrlTokenizer.tokenize("");
        assert!(stream.all().is_empty());
    }
}
