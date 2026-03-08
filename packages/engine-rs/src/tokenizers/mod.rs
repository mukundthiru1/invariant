use serde::{Deserialize, Serialize};

pub mod html;
pub mod path;
pub mod shell;
pub mod sql;
pub mod url;

pub use html::{HtmlTokenType, HtmlTokenizer};
pub use path::{PathTokenType, PathTokenizer};
pub use shell::{ShellTokenType, ShellTokenizer};
pub use sql::{
    SqlTokenType, SqlTokenizer, TautologyDetection, detect_tautologies,
};
pub use url::{UrlTokenType, UrlTokenizer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token<T> {
    pub token_type: T,
    pub value: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenStream<T> {
    tokens: Vec<Token<T>>,
}

impl<T> TokenStream<T>
where
    T: Copy + PartialEq,
{
    pub fn new(tokens: Vec<Token<T>>) -> Self {
        Self { tokens }
    }

    pub fn all(&self) -> &[Token<T>] {
        &self.tokens
    }

    pub fn has(&self, token_type: T) -> bool {
        self.tokens.iter().any(|t| t.token_type == token_type)
    }

    pub fn count(&self, token_type: T) -> usize {
        self.tokens
            .iter()
            .filter(|t| t.token_type == token_type)
            .count()
    }

    pub fn filter(&self, token_type: T) -> Vec<&Token<T>> {
        self.tokens
            .iter()
            .filter(|t| t.token_type == token_type)
            .collect()
    }

    pub fn find_sequence(&self, pattern: &[T]) -> Vec<(usize, Vec<Token<T>>)> 
    where
        T: Clone,
    {
        if pattern.is_empty() {
            return Vec::new();
        }

        let mut matches = Vec::new();
        if pattern.len() > self.tokens.len() {
            return matches;
        }

        for i in 0..=self.tokens.len() - pattern.len() {
            let mut ok = true;
            for (j, expected) in pattern.iter().enumerate() {
                if self.tokens[i + j].token_type != *expected {
                    ok = false;
                    break;
                }
            }
            if ok {
                matches.push((i, self.tokens[i..i + pattern.len()].to_vec()));
            }
        }

        matches
    }
}

pub(crate) fn to_value(bytes: &[u8], start: usize, end: usize) -> String {
    if start >= end || start >= bytes.len() {
        return String::new();
    }
    let clamped_end = end.min(bytes.len());
    String::from_utf8_lossy(&bytes[start..clamped_end]).into_owned()
}
