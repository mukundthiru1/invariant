use serde::{Deserialize, Serialize};

use crate::types::{MAX_TOKEN_COUNT, MAX_TOKENIZER_INPUT};

use super::{Token, TokenStream, to_value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtmlTokenType {
    Text,
    TagOpen,
    TagClose,
    TagSelfClose,
    TagEndOpen,
    TagName,
    AttrName,
    AttrEquals,
    AttrValue,
    Comment,
    Doctype,
    Cdata,
    ScriptContent,
    StyleContent,
    TemplateExpr,
    Whitespace,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtmlState {
    Text,
    TagOpen,
    TagBody,
    AttrName,
    AttrAfterName,
    AttrValueStart,
    AttrValueQuoted,
    AttrValueUnquoted,
    Script,
    Style,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HtmlTokenizer;

impl HtmlTokenizer {
    pub fn tokenize(&self, input: &str) -> TokenStream<HtmlTokenType> {
        let mut end = input.len().min(MAX_TOKENIZER_INPUT);
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }
        let bounded = &input[..end];
        let bytes = bounded.as_bytes();

        let mut tokens = Vec::new();
        let mut state = HtmlState::Text;
        let mut i = 0usize;
        let mut current_tag_name = String::new();
        let mut quote_char = b'\0';

        while i < bytes.len() && tokens.len() < MAX_TOKEN_COUNT {
            match state {
                HtmlState::Text => {
                    if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
                        if let Some(expr_end) = find_subsequence(bytes, i + 2, b"}}") {
                            let end_idx = expr_end + 2;
                            push(&mut tokens, HtmlTokenType::TemplateExpr, bytes, i, end_idx);
                            i = end_idx;
                            continue;
                        }
                    }

                    if i + 3 < bytes.len() && &bytes[i..i + 4] == b"<!--" {
                        let end_idx = find_subsequence(bytes, i + 4, b"-->")
                            .map_or(bytes.len(), |idx| idx + 3);
                        push(&mut tokens, HtmlTokenType::Comment, bytes, i, end_idx);
                        i = end_idx;
                        continue;
                    }

                    if i + 9 <= bytes.len() && starts_with_ignore_ascii_case(bytes, i, b"<!DOCTYPE")
                    {
                        let end_idx =
                            find_byte(bytes, i + 9, b'>').map_or(bytes.len(), |idx| idx + 1);
                        push(&mut tokens, HtmlTokenType::Doctype, bytes, i, end_idx);
                        i = end_idx;
                        continue;
                    }

                    if i + 9 <= bytes.len() && &bytes[i..i + 9] == b"<![CDATA[" {
                        let end_idx = find_subsequence(bytes, i + 9, b"]]>")
                            .map_or(bytes.len(), |idx| idx + 3);
                        push(&mut tokens, HtmlTokenType::Cdata, bytes, i, end_idx);
                        i = end_idx;
                        continue;
                    }

                    if i + 1 < bytes.len() && bytes[i] == b'<' && bytes[i + 1] == b'/' {
                        push(&mut tokens, HtmlTokenType::TagEndOpen, bytes, i, i + 2);
                        i += 2;
                        state = HtmlState::TagOpen;
                        continue;
                    }

                    if i + 1 < bytes.len() && bytes[i] == b'<' && is_tag_start(bytes[i + 1]) {
                        push(&mut tokens, HtmlTokenType::TagOpen, bytes, i, i + 1);
                        i += 1;
                        state = HtmlState::TagOpen;
                        continue;
                    }

                    let text_start = i;
                    while i < bytes.len()
                        && bytes[i] != b'<'
                        && !(i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{')
                    {
                        i += 1;
                    }

                    if i == text_start && i < bytes.len() {
                        i += 1;
                    }

                    if i > text_start {
                        push(&mut tokens, HtmlTokenType::Text, bytes, text_start, i);
                    }
                }
                HtmlState::TagOpen => {
                    let start = i;
                    while i < bytes.len() && is_tag_name_char(bytes[i]) {
                        i += 1;
                    }
                    if i > start {
                        current_tag_name = to_value(bytes, start, i).to_ascii_lowercase();
                        push(&mut tokens, HtmlTokenType::TagName, bytes, start, i);
                        state = HtmlState::TagBody;
                    } else {
                        push(
                            &mut tokens,
                            HtmlTokenType::Unknown,
                            bytes,
                            i,
                            i.saturating_add(1),
                        );
                        i = i.saturating_add(1);
                        state = HtmlState::Text;
                    }
                }
                HtmlState::TagBody => {
                    if i >= bytes.len() {
                        break;
                    }
                    if is_html_space(bytes[i]) {
                        let start = i;
                        while i < bytes.len() && is_html_space(bytes[i]) {
                            i += 1;
                        }
                        push(&mut tokens, HtmlTokenType::Whitespace, bytes, start, i);
                        continue;
                    }

                    if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'>' {
                        push(&mut tokens, HtmlTokenType::TagSelfClose, bytes, i, i + 2);
                        i += 2;
                        state = HtmlState::Text;
                        continue;
                    }

                    if bytes[i] == b'>' {
                        push(&mut tokens, HtmlTokenType::TagClose, bytes, i, i + 1);
                        i += 1;
                        state = match current_tag_name.as_str() {
                            "script" => HtmlState::Script,
                            "style" => HtmlState::Style,
                            _ => HtmlState::Text,
                        };
                        continue;
                    }

                    if is_attr_name_start(bytes[i]) {
                        state = HtmlState::AttrName;
                        continue;
                    }

                    push(&mut tokens, HtmlTokenType::Unknown, bytes, i, i + 1);
                    i += 1;
                }
                HtmlState::AttrName => {
                    let start = i;
                    while i < bytes.len() && is_attr_name_char(bytes[i]) {
                        i += 1;
                    }
                    push(&mut tokens, HtmlTokenType::AttrName, bytes, start, i);
                    state = HtmlState::AttrAfterName;
                }
                HtmlState::AttrAfterName => {
                    if i >= bytes.len() {
                        break;
                    }
                    if is_html_space(bytes[i]) {
                        let start = i;
                        while i < bytes.len() && is_html_space(bytes[i]) {
                            i += 1;
                        }
                        push(&mut tokens, HtmlTokenType::Whitespace, bytes, start, i);
                        continue;
                    }

                    if bytes[i] == b'=' {
                        push(&mut tokens, HtmlTokenType::AttrEquals, bytes, i, i + 1);
                        i += 1;
                        state = HtmlState::AttrValueStart;
                        continue;
                    }

                    state = HtmlState::TagBody;
                }
                HtmlState::AttrValueStart => {
                    if i >= bytes.len() {
                        break;
                    }
                    if is_html_space(bytes[i]) {
                        i += 1;
                        continue;
                    }
                    if bytes[i] == b'"' || bytes[i] == b'\'' {
                        quote_char = bytes[i];
                        i += 1;
                        state = HtmlState::AttrValueQuoted;
                        continue;
                    }
                    state = HtmlState::AttrValueUnquoted;
                }
                HtmlState::AttrValueQuoted => {
                    let start = i;
                    while i < bytes.len() && bytes[i] != quote_char {
                        i += 1;
                    }
                    push(&mut tokens, HtmlTokenType::AttrValue, bytes, start, i);
                    if i < bytes.len() {
                        i += 1;
                    }
                    state = HtmlState::TagBody;
                }
                HtmlState::AttrValueUnquoted => {
                    let start = i;
                    while i < bytes.len() && !is_html_space(bytes[i]) && bytes[i] != b'>' {
                        i += 1;
                    }
                    push(&mut tokens, HtmlTokenType::AttrValue, bytes, start, i);
                    state = HtmlState::TagBody;
                }
                HtmlState::Script => {
                    let start = i;
                    let end_idx = find_case_insensitive(bytes, i, b"</script");
                    if let Some(idx) = end_idx {
                        if idx > start {
                            push(&mut tokens, HtmlTokenType::ScriptContent, bytes, start, idx);
                        }
                        i = idx;
                        if i + 2 <= bytes.len() {
                            push(&mut tokens, HtmlTokenType::TagEndOpen, bytes, i, i + 2);
                            i += 2;
                            state = HtmlState::TagOpen;
                        }
                    } else {
                        push(
                            &mut tokens,
                            HtmlTokenType::ScriptContent,
                            bytes,
                            start,
                            bytes.len(),
                        );
                        i = bytes.len();
                    }
                }
                HtmlState::Style => {
                    let start = i;
                    let end_idx = find_case_insensitive(bytes, i, b"</style");
                    if let Some(idx) = end_idx {
                        if idx > start {
                            push(&mut tokens, HtmlTokenType::StyleContent, bytes, start, idx);
                        }
                        i = idx;
                        if i + 2 <= bytes.len() {
                            push(&mut tokens, HtmlTokenType::TagEndOpen, bytes, i, i + 2);
                            i += 2;
                            state = HtmlState::TagOpen;
                        }
                    } else {
                        push(
                            &mut tokens,
                            HtmlTokenType::StyleContent,
                            bytes,
                            start,
                            bytes.len(),
                        );
                        i = bytes.len();
                    }
                }
            }
        }

        TokenStream::new(tokens)
    }
}

fn push(
    tokens: &mut Vec<Token<HtmlTokenType>>,
    ty: HtmlTokenType,
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

fn is_tag_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'!'
}

fn is_tag_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}

fn is_attr_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || matches!(b, b'_' | b'@' | b':' | b'v' | b'-')
}

fn is_attr_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'@' | b':' | b'.' | b'v')
}

fn is_html_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0C)
}

fn starts_with_ignore_ascii_case(bytes: &[u8], start: usize, needle: &[u8]) -> bool {
    if start + needle.len() > bytes.len() {
        return false;
    }
    bytes[start..start + needle.len()]
        .iter()
        .zip(needle.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn find_byte(bytes: &[u8], start: usize, needle: u8) -> Option<usize> {
    (start..bytes.len()).find(|&i| bytes[i] == needle)
}

fn find_subsequence(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() || haystack.len() < needle.len() {
        return None;
    }
    let end = haystack.len() - needle.len();
    (start..=end).find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn find_case_insensitive(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() || haystack.len() < needle.len() {
        return None;
    }
    let end = haystack.len() - needle.len();
    (start..=end).find(|&i| {
        haystack[i..i + needle.len()]
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_basic_tokenization() {
        let stream = HtmlTokenizer.tokenize("<div class=\"x\">ok</div>");
        assert!(stream.has(HtmlTokenType::TagOpen));
        assert!(stream.has(HtmlTokenType::TagName));
        assert!(stream.has(HtmlTokenType::AttrName));
    }

    #[test]
    fn html_edge_script_context() {
        let stream = HtmlTokenizer.tokenize("<script>alert(1)</script>");
        assert!(stream.has(HtmlTokenType::ScriptContent));
        assert!(stream.count(HtmlTokenType::TagEndOpen) >= 1);
    }

    #[test]
    fn html_encoding_like_payload() {
        let stream = HtmlTokenizer.tokenize("<a href=\"javascript:%61lert(1)\">x</a>");
        assert!(stream.has(HtmlTokenType::AttrValue));
    }

    #[test]
    fn html_max_input_bound() {
        let s = format!("<p>{}</p>", "a".repeat(MAX_TOKENIZER_INPUT + 1000));
        let stream = HtmlTokenizer.tokenize(&s);
        let total: usize = stream.all().iter().map(|t| t.value.len()).sum();
        assert!(total <= MAX_TOKENIZER_INPUT + 10);
        assert!(stream.all().len() <= MAX_TOKEN_COUNT);
    }

    #[test]
    fn html_empty_input() {
        let stream = HtmlTokenizer.tokenize("");
        assert!(stream.all().is_empty());
    }
}
