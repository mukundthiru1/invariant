use serde::{Deserialize, Serialize};

use crate::types::{MAX_TOKEN_COUNT, MAX_TOKENIZER_INPUT};

use super::{Token, TokenStream, to_value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellTokenType {
    Word,
    Separator,
    Pipe,
    AndChain,
    OrChain,
    Background,
    SubshellOpen,
    SubshellClose,
    CmdSubstOpen,
    CmdSubstClose,
    BacktickSubst,
    VarExpansion,
    RedirectIn,
    RedirectOut,
    Heredoc,
    StringSingle,
    StringDouble,
    Flag,
    Glob,
    Comment,
    Whitespace,
    Newline,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ShellTokenizer;

impl ShellTokenizer {
    pub fn tokenize(&self, input: &str) -> TokenStream<ShellTokenType> {
        let mut end = input.len().min(MAX_TOKENIZER_INPUT);
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }
        let bounded = &input[..end];
        let bytes = bounded.as_bytes();

        let mut tokens = Vec::new();
        let mut i = 0usize;

        while i < bytes.len() && tokens.len() < MAX_TOKEN_COUNT {
            let ch = bytes[i];

            if ch == b'\n' {
                push(&mut tokens, ShellTokenType::Newline, bytes, i, i + 1);
                i += 1;
                continue;
            }

            if matches!(ch, b' ' | b'\t' | b'\r') {
                let start = i;
                while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r') {
                    i += 1;
                }
                push(&mut tokens, ShellTokenType::Whitespace, bytes, start, i);
                continue;
            }

            if ch == b'#' {
                let start = i;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                push(&mut tokens, ShellTokenType::Comment, bytes, start, i);
                continue;
            }

            if ch == b';' {
                push(&mut tokens, ShellTokenType::Separator, bytes, i, i + 1);
                i += 1;
                continue;
            }

            if ch == b'|' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                    push(&mut tokens, ShellTokenType::OrChain, bytes, i, i + 2);
                    i += 2;
                } else {
                    push(&mut tokens, ShellTokenType::Pipe, bytes, i, i + 1);
                    i += 1;
                }
                continue;
            }

            if ch == b'&' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    push(&mut tokens, ShellTokenType::AndChain, bytes, i, i + 2);
                    i += 2;
                } else {
                    push(&mut tokens, ShellTokenType::Background, bytes, i, i + 1);
                    i += 1;
                }
                continue;
            }

            if ch == b'$' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                    push(&mut tokens, ShellTokenType::CmdSubstOpen, bytes, i, i + 2);
                    i += 2;
                    continue;
                }

                if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    let start = i;
                    i += 2;
                    while i < bytes.len() && bytes[i] != b'}' {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                    push(&mut tokens, ShellTokenType::VarExpansion, bytes, start, i);
                    continue;
                }

                if i + 1 < bytes.len() && is_var_start(bytes[i + 1]) {
                    let start = i;
                    i += 1;
                    while i < bytes.len() && is_var_char(bytes[i]) {
                        i += 1;
                    }
                    push(&mut tokens, ShellTokenType::VarExpansion, bytes, start, i);
                    continue;
                }

                if i + 1 < bytes.len() && is_special_shell_var(bytes[i + 1]) {
                    push(&mut tokens, ShellTokenType::VarExpansion, bytes, i, i + 2);
                    i += 2;
                    continue;
                }
            }

            if ch == b'`' {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'`' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                push(&mut tokens, ShellTokenType::BacktickSubst, bytes, start, i);
                continue;
            }

            if ch == b'(' {
                push(&mut tokens, ShellTokenType::SubshellOpen, bytes, i, i + 1);
                i += 1;
                continue;
            }

            if ch == b')' {
                let has_open_subst = tokens
                    .iter()
                    .any(|t| t.token_type == ShellTokenType::CmdSubstOpen);
                push(
                    &mut tokens,
                    if has_open_subst {
                        ShellTokenType::CmdSubstClose
                    } else {
                        ShellTokenType::SubshellClose
                    },
                    bytes,
                    i,
                    i + 1,
                );
                i += 1;
                continue;
            }

            if ch == b'>' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'>' {
                    push(&mut tokens, ShellTokenType::RedirectOut, bytes, i, i + 2);
                    i += 2;
                } else {
                    push(&mut tokens, ShellTokenType::RedirectOut, bytes, i, i + 1);
                    i += 1;
                }
                continue;
            }

            if ch == b'<' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'<' {
                    push(&mut tokens, ShellTokenType::Heredoc, bytes, i, i + 2);
                    i += 2;
                } else {
                    push(&mut tokens, ShellTokenType::RedirectIn, bytes, i, i + 1);
                    i += 1;
                }
                continue;
            }

            if ch == b'\'' {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                push(&mut tokens, ShellTokenType::StringSingle, bytes, start, i);
                continue;
            }

            if ch == b'"' {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                push(&mut tokens, ShellTokenType::StringDouble, bytes, start, i);
                continue;
            }

            if ch == b'*' || ch == b'?' {
                push(&mut tokens, ShellTokenType::Glob, bytes, i, i + 1);
                i += 1;
                continue;
            }

            if is_word_char(ch) {
                let start = i;
                while i < bytes.len() && is_word_char(bytes[i]) {
                    i += 1;
                }
                let word = to_value(bytes, start, i);
                if word.starts_with("--")
                    || (word.starts_with('-') && word.len() > 1 && !is_numeric_flag(&word))
                {
                    tokens.push(Token {
                        token_type: ShellTokenType::Flag,
                        value: word,
                        start,
                        end: i,
                    });
                } else {
                    tokens.push(Token {
                        token_type: ShellTokenType::Word,
                        value: word,
                        start,
                        end: i,
                    });
                }
                continue;
            }

            push(&mut tokens, ShellTokenType::Unknown, bytes, i, i + 1);
            i += 1;
        }

        TokenStream::new(tokens)
    }
}

fn is_var_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_var_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_special_shell_var(b: u8) -> bool {
    matches!(
        b,
        b'?' | b'!' | b'$' | b'@' | b'*' | b'#' | b'-' | b'0'..=b'9'
    )
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'_' | b'.' | b'/' | b'~' | b'@' | b':' | b'%' | b'+' | b',' | b'=' | b'\\' | b'-'
        )
}

fn is_numeric_flag(word: &str) -> bool {
    let bytes = word.as_bytes();
    bytes.len() > 1 && bytes[0] == b'-' && bytes[1].is_ascii_digit()
}

fn push(
    tokens: &mut Vec<Token<ShellTokenType>>,
    ty: ShellTokenType,
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
    fn shell_basic_tokenization() {
        let stream = ShellTokenizer.tokenize("ls -la /tmp");
        assert!(stream.has(ShellTokenType::Word));
        assert!(stream.has(ShellTokenType::Flag));
    }

    #[test]
    fn shell_edge_substitution_and_backticks() {
        let stream = ShellTokenizer.tokenize("echo $(id) `whoami`");
        assert!(stream.has(ShellTokenType::CmdSubstOpen));
        assert!(stream.has(ShellTokenType::CmdSubstClose));
        assert!(stream.has(ShellTokenType::BacktickSubst));
    }

    #[test]
    fn shell_encoding_detection_like_var_expansion() {
        let stream = ShellTokenizer.tokenize("echo $IFS$9cat");
        assert!(stream.has(ShellTokenType::VarExpansion));
    }

    #[test]
    fn shell_max_input_bound() {
        let s = "a ".repeat(MAX_TOKENIZER_INPUT + 1000);
        let stream = ShellTokenizer.tokenize(&s);
        assert!(stream.all().len() <= MAX_TOKEN_COUNT);
        let consumed: usize = stream.all().iter().map(|t| t.value.len()).sum();
        assert!(consumed <= MAX_TOKENIZER_INPUT);
    }

    #[test]
    fn shell_empty_input() {
        let stream = ShellTokenizer.tokenize("");
        assert!(stream.all().is_empty());
    }
}
