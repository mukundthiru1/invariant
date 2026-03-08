use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::types::{MAX_TOKEN_COUNT, MAX_TOKENIZER_INPUT};

use super::{Token, TokenStream, to_value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlTokenType {
    Number,
    String,
    Identifier,
    Operator,
    BooleanOp,
    Keyword,
    ParenOpen,
    ParenClose,
    Comma,
    Separator,
    Wildcard,
    Whitespace,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SqlTokenizer;

impl SqlTokenizer {
    pub fn tokenize(&self, input: &str) -> TokenStream<SqlTokenType> {
        let max_input = MAX_TOKENIZER_INPUT.min(4096);
        let mut end = input.len().min(max_input);
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }
        let bounded = &input[..end];
        let bytes = bounded.as_bytes();

        let mut tokens = Vec::new();
        let mut i = 0usize;

        while i < bytes.len() && tokens.len() < MAX_TOKEN_COUNT {
            let ch = bytes[i];

            if is_whitespace(ch) {
                let start = i;
                while i < bytes.len() && is_whitespace(bytes[i]) {
                    i += 1;
                }
                push(&mut tokens, SqlTokenType::Whitespace, bytes, start, i);
                continue;
            }

            if (ch == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-') || ch == b'#' {
                push(&mut tokens, SqlTokenType::Separator, bytes, i, bytes.len());
                break;
            }

            if ch == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                if let Some(end_idx) = find_subsequence(bytes, i + 2, b"*/") {
                    i = end_idx + 2;
                } else {
                    i = bytes.len();
                }
                continue;
            }

            if ch == b'\'' || ch == b'"' {
                let quote = ch;
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == quote {
                        if i + 1 < bytes.len() && bytes[i + 1] == quote {
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                push(&mut tokens, SqlTokenType::String, bytes, start, i);
                continue;
            }

            if ch == b'`' {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'`' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                push(&mut tokens, SqlTokenType::Identifier, bytes, start, i);
                continue;
            }

            if is_ascii_digit(ch)
                || (ch == b'.' && i + 1 < bytes.len() && is_ascii_digit(bytes[i + 1]))
            {
                let start = i;
                if ch == b'0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
                    i += 2;
                    while i < bytes.len() && is_hex_digit(bytes[i]) {
                        i += 1;
                    }
                } else if ch == b'0'
                    && i + 1 < bytes.len()
                    && (bytes[i + 1] == b'b' || bytes[i + 1] == b'B')
                {
                    i += 2;
                    while i < bytes.len() && (bytes[i] == b'0' || bytes[i] == b'1') {
                        i += 1;
                    }
                } else {
                    while i < bytes.len() && is_ascii_digit(bytes[i]) {
                        i += 1;
                    }
                    if i < bytes.len() && bytes[i] == b'.' {
                        i += 1;
                        while i < bytes.len() && is_ascii_digit(bytes[i]) {
                            i += 1;
                        }
                    }
                }
                push(&mut tokens, SqlTokenType::Number, bytes, start, i);
                continue;
            }

            if matches!(ch, b'=' | b'<' | b'>' | b'!') {
                let start = i;
                if i + 1 < bytes.len()
                    && (bytes[i + 1] == b'=' || (ch == b'<' && bytes[i + 1] == b'>'))
                {
                    i += 2;
                } else {
                    i += 1;
                }
                push(&mut tokens, SqlTokenType::Operator, bytes, start, i);
                continue;
            }

            if ch == b'|' && i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                tokens.push(Token {
                    token_type: SqlTokenType::BooleanOp,
                    value: "OR".to_string(),
                    start: i,
                    end: i + 2,
                });
                i += 2;
                continue;
            }

            match ch {
                b'(' => {
                    push(&mut tokens, SqlTokenType::ParenOpen, bytes, i, i + 1);
                    i += 1;
                    continue;
                }
                b')' => {
                    push(&mut tokens, SqlTokenType::ParenClose, bytes, i, i + 1);
                    i += 1;
                    continue;
                }
                b',' => {
                    push(&mut tokens, SqlTokenType::Comma, bytes, i, i + 1);
                    i += 1;
                    continue;
                }
                b';' => {
                    push(&mut tokens, SqlTokenType::Separator, bytes, i, i + 1);
                    i += 1;
                    continue;
                }
                b'*' => {
                    push(&mut tokens, SqlTokenType::Wildcard, bytes, i, i + 1);
                    i += 1;
                    continue;
                }
                _ => {}
            }

            if is_ident_start(ch) {
                let start = i;
                while i < bytes.len() && is_ident_continue(bytes[i]) {
                    i += 1;
                }
                let word = to_value(bytes, start, i);
                let upper = word.to_ascii_uppercase();
                if is_boolean_op(&upper) {
                    tokens.push(Token {
                        token_type: SqlTokenType::BooleanOp,
                        value: upper,
                        start,
                        end: i,
                    });
                } else if is_sql_keyword(&upper) {
                    tokens.push(Token {
                        token_type: SqlTokenType::Keyword,
                        value: upper,
                        start,
                        end: i,
                    });
                } else {
                    tokens.push(Token {
                        token_type: SqlTokenType::Identifier,
                        value: word,
                        start,
                        end: i,
                    });
                }
                continue;
            }

            push(&mut tokens, SqlTokenType::Unknown, bytes, i, i + 1);
            i += 1;
        }

        TokenStream::new(tokens)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ExpressionNode {
    LiteralNumber(f64),
    LiteralString(String),
    LiteralBool(bool),
    LiteralNull,
    Identifier(String),
    Comparison {
        left: Box<ExpressionNode>,
        operator: String,
        right: Box<ExpressionNode>,
    },
    Not(Box<ExpressionNode>),
    IsNull {
        operand: Box<ExpressionNode>,
        negated: bool,
    },
    Between {
        operand: Box<ExpressionNode>,
        low: Box<ExpressionNode>,
        high: Box<ExpressionNode>,
    },
    InList {
        operand: Box<ExpressionNode>,
        values: Vec<ExpressionNode>,
    },
    Like {
        operand: Box<ExpressionNode>,
        pattern: Box<ExpressionNode>,
    },
    FunctionCall {
        name: String,
        args: Vec<ExpressionNode>,
    },
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
enum EvalResult {
    Value(EvalValue),
    Unevaluable,
}

#[derive(Debug, Clone, PartialEq)]
enum EvalValue {
    Number(f64),
    String(String),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TautologyDetection {
    pub expression: String,
    pub value: String,
    pub position: usize,
}

pub fn detect_tautologies(input: &str) -> Vec<TautologyDetection> {
    let mut detections = Vec::new();
    let mut seen = HashSet::new();

    let tokenizer = SqlTokenizer;
    let tokens = tokenizer.tokenize(input);
    let expressions = extract_conditional_expressions(tokens.all());

    for expr in expressions {
        if is_tautology(&expr) {
            let key = stringify_expression(&expr);
            if seen.insert(key.clone()) {
                let value = match evaluate_expression(&expr) {
                    EvalResult::Value(v) => stringify_eval_value(&v),
                    EvalResult::Unevaluable => "true".to_string(),
                };
                detections.push(TautologyDetection {
                    expression: key,
                    value,
                    position: get_expression_position(&expr),
                });
            }
        }
    }

    let prefixes = [
        (b'\'', true),
        (b'"', true),
        (b')', false),
    ];

    for (prefix, allow_paren) in prefixes {
        if let Some(stripped) = strip_injection_prefix(input, prefix, allow_paren) {
            if !stripped.is_empty() {
                let stripped_tokens = tokenizer.tokenize(stripped);
                let stripped_exprs = extract_conditional_expressions(stripped_tokens.all());
                for expr in stripped_exprs {
                    if is_tautology(&expr) {
                        let key = stringify_expression(&expr);
                        if seen.insert(key.clone()) {
                            let value = match evaluate_expression(&expr) {
                                EvalResult::Value(v) => stringify_eval_value(&v),
                                EvalResult::Unevaluable => "true".to_string(),
                            };
                            detections.push(TautologyDetection {
                                expression: key,
                                value,
                                position: get_expression_position(&expr),
                            });
                        }
                    }
                }
            }
        }
    }

    detections
}

fn strip_injection_prefix(input: &str, quote: u8, allow_paren: bool) -> Option<&str> {
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() && bytes[i] == quote {
        i += 1;
    }
    if i == 0 && quote != b')' {
        return None;
    }

    if allow_paren {
        while i < bytes.len() && bytes[i] == b')' {
            i += 1;
        }
    } else {
        if i == 0 {
            while i < bytes.len() && bytes[i] == b')' {
                i += 1;
            }
            if i == 0 {
                return None;
            }
        }
    }

    while i < bytes.len() && is_whitespace(bytes[i]) {
        i += 1;
    }

    if i >= bytes.len() {
        return None;
    }

    input.get(i..)
}

fn extract_conditional_expressions(tokens: &[Token<SqlTokenType>]) -> Vec<ExpressionNode> {
    let meaningful: Vec<&Token<SqlTokenType>> = tokens
        .iter()
        .filter(|t| t.token_type != SqlTokenType::Whitespace && t.token_type != SqlTokenType::Separator)
        .collect();

    let mut expressions = Vec::new();
    for (i, token) in meaningful.iter().enumerate() {
        if token.token_type == SqlTokenType::BooleanOp {
            let parsed = parse_expression(&meaningful, i + 1);
            if parsed.node != ExpressionNode::Unknown {
                expressions.push(parsed.node);
            }
        }

        if token.token_type == SqlTokenType::Keyword
            && (token.value.eq_ignore_ascii_case("WHERE")
                || token.value.eq_ignore_ascii_case("HAVING"))
        {
            let parsed = parse_expression(&meaningful, i + 1);
            if parsed.node != ExpressionNode::Unknown {
                expressions.push(parsed.node);
            }
        }
    }

    expressions
}

struct ParseResult {
    node: ExpressionNode,
    next_index: usize,
}

fn parse_expression(tokens: &[&Token<SqlTokenType>], start: usize) -> ParseResult {
    if start >= tokens.len() {
        return ParseResult {
            node: ExpressionNode::Unknown,
            next_index: start,
        };
    }

    let left = parse_primary(tokens, start);
    if left.node == ExpressionNode::Unknown {
        return left;
    }

    let mut idx = left.next_index;
    if idx >= tokens.len() {
        return left;
    }

    let next = tokens[idx];
    if next.token_type == SqlTokenType::Operator {
        idx += 1;
        let right = parse_primary(tokens, idx);
        return ParseResult {
            node: ExpressionNode::Comparison {
                left: Box::new(left.node),
                operator: next.value.clone(),
                right: Box::new(right.node),
            },
            next_index: right.next_index,
        };
    }

    if next.token_type == SqlTokenType::Keyword && next.value.eq_ignore_ascii_case("IS") {
        idx += 1;
        let mut negated = false;
        if idx < tokens.len()
            && tokens[idx].token_type == SqlTokenType::Keyword
            && tokens[idx].value.eq_ignore_ascii_case("NOT")
        {
            negated = true;
            idx += 1;
        }

        if idx < tokens.len()
            && tokens[idx].token_type == SqlTokenType::Keyword
            && tokens[idx].value.eq_ignore_ascii_case("NULL")
        {
            idx += 1;
            return ParseResult {
                node: ExpressionNode::IsNull {
                    operand: Box::new(left.node),
                    negated,
                },
                next_index: idx,
            };
        }

        if idx < tokens.len() && tokens[idx].token_type == SqlTokenType::Keyword {
            if tokens[idx].value.eq_ignore_ascii_case("TRUE") {
                return ParseResult {
                    node: ExpressionNode::LiteralBool(!negated),
                    next_index: idx + 1,
                };
            }
            if tokens[idx].value.eq_ignore_ascii_case("FALSE") {
                return ParseResult {
                    node: ExpressionNode::LiteralBool(negated),
                    next_index: idx + 1,
                };
            }
        }
    }

    if next.token_type == SqlTokenType::Keyword && next.value.eq_ignore_ascii_case("LIKE") {
        idx += 1;
        let pattern = parse_primary(tokens, idx);
        return ParseResult {
            node: ExpressionNode::Like {
                operand: Box::new(left.node),
                pattern: Box::new(pattern.node),
            },
            next_index: pattern.next_index,
        };
    }

    if next.token_type == SqlTokenType::Keyword && next.value.eq_ignore_ascii_case("BETWEEN") {
        idx += 1;
        let low = parse_primary(tokens, idx);
        idx = low.next_index;
        if idx < tokens.len()
            && tokens[idx].token_type == SqlTokenType::BooleanOp
            && tokens[idx].value.eq_ignore_ascii_case("AND")
        {
            idx += 1;
        }
        let high = parse_primary(tokens, idx);
        return ParseResult {
            node: ExpressionNode::Between {
                operand: Box::new(left.node),
                low: Box::new(low.node),
                high: Box::new(high.node),
            },
            next_index: high.next_index,
        };
    }

    if next.token_type == SqlTokenType::Keyword && next.value.eq_ignore_ascii_case("IN") {
        idx += 1;
        if idx < tokens.len() && tokens[idx].token_type == SqlTokenType::ParenOpen {
            idx += 1;
            let mut values = Vec::new();
            while idx < tokens.len() && tokens[idx].token_type != SqlTokenType::ParenClose {
                if tokens[idx].token_type == SqlTokenType::Comma {
                    idx += 1;
                    continue;
                }
                let val = parse_primary(tokens, idx);
                values.push(val.node);
                idx = val.next_index;
            }
            if idx < tokens.len() {
                idx += 1;
            }
            return ParseResult {
                node: ExpressionNode::InList {
                    operand: Box::new(left.node),
                    values,
                },
                next_index: idx,
            };
        }
    }

    if next.token_type == SqlTokenType::Keyword && next.value.eq_ignore_ascii_case("NOT") {
        idx += 1;
        let operand = parse_primary(tokens, idx);
        return ParseResult {
            node: ExpressionNode::Not(Box::new(operand.node)),
            next_index: operand.next_index,
        };
    }

    left
}

fn parse_primary(tokens: &[&Token<SqlTokenType>], start: usize) -> ParseResult {
    if start >= tokens.len() {
        return ParseResult {
            node: ExpressionNode::Unknown,
            next_index: start,
        };
    }

    let token = tokens[start];

    if token.token_type == SqlTokenType::Keyword && token.value.eq_ignore_ascii_case("NOT") {
        let operand = parse_primary(tokens, start + 1);
        return ParseResult {
            node: ExpressionNode::Not(Box::new(operand.node)),
            next_index: operand.next_index,
        };
    }

    if token.token_type == SqlTokenType::Number {
        return ParseResult {
            node: ExpressionNode::LiteralNumber(parse_numeric_literal(&token.value)),
            next_index: start + 1,
        };
    }

    if token.token_type == SqlTokenType::String {
        let mut inner = token.value.clone();
        if inner.len() >= 2 {
            inner = inner[1..inner.len() - 1].replace("''", "'").replace("\"\"", "\"");
        }
        return ParseResult {
            node: ExpressionNode::LiteralString(inner),
            next_index: start + 1,
        };
    }

    if token.token_type == SqlTokenType::Keyword {
        if token.value.eq_ignore_ascii_case("TRUE") {
            return ParseResult {
                node: ExpressionNode::LiteralBool(true),
                next_index: start + 1,
            };
        }
        if token.value.eq_ignore_ascii_case("FALSE") {
            return ParseResult {
                node: ExpressionNode::LiteralBool(false),
                next_index: start + 1,
            };
        }
        if token.value.eq_ignore_ascii_case("NULL") {
            return ParseResult {
                node: ExpressionNode::LiteralNull,
                next_index: start + 1,
            };
        }
    }

    if token.token_type == SqlTokenType::Identifier
        || (token.token_type == SqlTokenType::Keyword && !is_boolean_op(&token.value.to_ascii_uppercase()))
    {
        if start + 1 < tokens.len() && tokens[start + 1].token_type == SqlTokenType::ParenOpen {
            let mut idx = start + 2;
            let mut args = Vec::new();
            while idx < tokens.len() && tokens[idx].token_type != SqlTokenType::ParenClose {
                if tokens[idx].token_type == SqlTokenType::Comma {
                    idx += 1;
                    continue;
                }
                let arg = parse_primary(tokens, idx);
                args.push(arg.node);
                idx = arg.next_index;
            }
            if idx < tokens.len() {
                idx += 1;
            }
            return ParseResult {
                node: ExpressionNode::FunctionCall {
                    name: token.value.to_ascii_uppercase(),
                    args,
                },
                next_index: idx,
            };
        }

        return ParseResult {
            node: ExpressionNode::Identifier(token.value.clone()),
            next_index: start + 1,
        };
    }

    if token.token_type == SqlTokenType::ParenOpen {
        let inner = parse_expression(tokens, start + 1);
        let mut idx = inner.next_index;
        if idx < tokens.len() && tokens[idx].token_type == SqlTokenType::ParenClose {
            idx += 1;
        }
        return ParseResult {
            node: inner.node,
            next_index: idx,
        };
    }

    ParseResult {
        node: ExpressionNode::Unknown,
        next_index: start + 1,
    }
}

fn parse_numeric_literal(value: &str) -> f64 {
    if value.starts_with("0x") || value.starts_with("0X") {
        return i64::from_str_radix(&value[2..], 16).map_or(0.0, |v| v as f64);
    }
    if value.starts_with("0b") || value.starts_with("0B") {
        return i64::from_str_radix(&value[2..], 2).map_or(0.0, |v| v as f64);
    }
    value.parse::<f64>().unwrap_or(0.0)
}

fn evaluate_expression(node: &ExpressionNode) -> EvalResult {
    match node {
        ExpressionNode::LiteralNumber(v) => EvalResult::Value(EvalValue::Number(*v)),
        ExpressionNode::LiteralString(v) => EvalResult::Value(EvalValue::String(v.clone())),
        ExpressionNode::LiteralBool(v) => EvalResult::Value(EvalValue::Bool(*v)),
        ExpressionNode::LiteralNull => EvalResult::Value(EvalValue::Null),
        ExpressionNode::Identifier(name) => {
            let _ = name;
            EvalResult::Unevaluable
        }
        ExpressionNode::Comparison {
            left,
            operator,
            right,
        } => {
            let left_val = evaluate_expression(left);
            let right_val = evaluate_expression(right);
            match (left_val, right_val) {
                (EvalResult::Value(lv), EvalResult::Value(rv)) => {
                    if matches!(lv, EvalValue::Null) || matches!(rv, EvalValue::Null) {
                        return EvalResult::Value(EvalValue::Bool(false));
                    }
                    let result = match operator.as_str() {
                        "=" => equals_eval_value(&lv, &rv),
                        "<>" | "!=" => !equals_eval_value(&lv, &rv),
                        "<" => to_number(&lv) < to_number(&rv),
                        ">" => to_number(&lv) > to_number(&rv),
                        "<=" => to_number(&lv) <= to_number(&rv),
                        ">=" => to_number(&lv) >= to_number(&rv),
                        _ => return EvalResult::Unevaluable,
                    };
                    EvalResult::Value(EvalValue::Bool(result))
                }
                _ => EvalResult::Unevaluable,
            }
        }
        ExpressionNode::Not(operand) => match evaluate_expression(operand) {
            EvalResult::Value(v) => EvalResult::Value(EvalValue::Bool(!to_bool(&v))),
            EvalResult::Unevaluable => EvalResult::Unevaluable,
        },
        ExpressionNode::IsNull { operand, negated } => match evaluate_expression(operand) {
            EvalResult::Value(v) => {
                let is_null = matches!(v, EvalValue::Null);
                EvalResult::Value(EvalValue::Bool(if *negated { !is_null } else { is_null }))
            }
            EvalResult::Unevaluable => EvalResult::Unevaluable,
        },
        ExpressionNode::Between { operand, low, high } => {
            match (
                evaluate_expression(operand),
                evaluate_expression(low),
                evaluate_expression(high),
            ) {
                (EvalResult::Value(v), EvalResult::Value(l), EvalResult::Value(h)) => {
                    let vv = to_number(&v);
                    EvalResult::Value(EvalValue::Bool(vv >= to_number(&l) && vv <= to_number(&h)))
                }
                _ => EvalResult::Unevaluable,
            }
        }
        ExpressionNode::InList { operand, values } => {
            let val = evaluate_expression(operand);
            if let EvalResult::Value(v) = val {
                let mut all_evaluable = true;
                for item in values {
                    match evaluate_expression(item) {
                        EvalResult::Value(iv) => {
                            if stringify_eval_value(&v) == stringify_eval_value(&iv) {
                                return EvalResult::Value(EvalValue::Bool(true));
                            }
                        }
                        EvalResult::Unevaluable => all_evaluable = false,
                    }
                }
                if all_evaluable {
                    EvalResult::Value(EvalValue::Bool(false))
                } else {
                    EvalResult::Unevaluable
                }
            } else {
                EvalResult::Unevaluable
            }
        }
        ExpressionNode::Like { operand, pattern } => {
            let val = evaluate_expression(operand);
            let pat = evaluate_expression(pattern);
            match (val, pat) {
                (EvalResult::Value(EvalValue::String(v)), EvalResult::Value(EvalValue::String(p))) => {
                    EvalResult::Value(EvalValue::Bool(like_matches(&v, &p)))
                }
                _ => EvalResult::Unevaluable,
            }
        }
        ExpressionNode::FunctionCall { name, args } => {
            let evaluated: Vec<EvalResult> = args.iter().map(evaluate_expression).collect();
            eval_known_function(name, &evaluated)
        }
        ExpressionNode::Unknown => EvalResult::Unevaluable,
    }
}

fn like_matches(value: &str, pattern: &str) -> bool {
    let mut p = String::with_capacity(pattern.len() * 2);
    for c in pattern.chars() {
        match c {
            '%' => p.push_str(".*"),
            '_' => p.push('.'),
            '.' | '*' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '\\' => {
                p.push('\\');
                p.push(c);
            }
            _ => p.push(c),
        }
    }
    regex::Regex::new(&format!("(?i)^{}$", p)).is_ok_and(|re| re.is_match(value))
}

fn eval_known_function(name: &str, args: &[EvalResult]) -> EvalResult {
    let key = name.to_ascii_uppercase();
    match key.as_str() {
        "ASCII" => {
            if let Some(EvalResult::Value(EvalValue::String(s))) = args.first() {
                if let Some(first) = s.chars().next() {
                    return EvalResult::Value(EvalValue::Number(first as u32 as f64));
                }
            }
            EvalResult::Unevaluable
        }
        "CHAR" => {
            if let Some(EvalResult::Value(v)) = args.first() {
                let n = to_number(v) as u32;
                if let Some(ch) = char::from_u32(n) {
                    return EvalResult::Value(EvalValue::String(ch.to_string()));
                }
            }
            EvalResult::Unevaluable
        }
        "LENGTH" | "LEN" => {
            if let Some(EvalResult::Value(EvalValue::String(s))) = args.first() {
                return EvalResult::Value(EvalValue::Number(s.len() as f64));
            }
            EvalResult::Unevaluable
        }
        "UPPER" => {
            if let Some(EvalResult::Value(EvalValue::String(s))) = args.first() {
                return EvalResult::Value(EvalValue::String(s.to_ascii_uppercase()));
            }
            EvalResult::Unevaluable
        }
        "LOWER" => {
            if let Some(EvalResult::Value(EvalValue::String(s))) = args.first() {
                return EvalResult::Value(EvalValue::String(s.to_ascii_lowercase()));
            }
            EvalResult::Unevaluable
        }
        "ABS" => {
            if let Some(EvalResult::Value(v)) = args.first() {
                return EvalResult::Value(EvalValue::Number(to_number(v).abs()));
            }
            EvalResult::Unevaluable
        }
        "FLOOR" => {
            if let Some(EvalResult::Value(v)) = args.first() {
                return EvalResult::Value(EvalValue::Number(to_number(v).floor()));
            }
            EvalResult::Unevaluable
        }
        "CEIL" | "CEILING" => {
            if let Some(EvalResult::Value(v)) = args.first() {
                return EvalResult::Value(EvalValue::Number(to_number(v).ceil()));
            }
            EvalResult::Unevaluable
        }
        "MOD" => {
            if args.len() >= 2 {
                if let (EvalResult::Value(a), EvalResult::Value(b)) = (&args[0], &args[1]) {
                    let den = to_number(b);
                    if den != 0.0 {
                        return EvalResult::Value(EvalValue::Number(to_number(a) % den));
                    }
                }
            }
            EvalResult::Unevaluable
        }
        "CONCAT" => {
            let mut out = String::new();
            for arg in args {
                if let EvalResult::Value(v) = arg {
                    out.push_str(&stringify_eval_value(v));
                } else {
                    return EvalResult::Unevaluable;
                }
            }
            EvalResult::Value(EvalValue::String(out))
        }
        "SUBSTR" | "SUBSTRING" => {
            if args.len() >= 2 {
                if let (EvalResult::Value(EvalValue::String(s)), EvalResult::Value(start)) =
                    (&args[0], &args[1])
                {
                    let start_idx = (to_number(start) as isize - 1).max(0) as usize;
                    let len = args.get(2).and_then(|v| match v {
                        EvalResult::Value(ev) => Some(to_number(ev).max(0.0) as usize),
                        EvalResult::Unevaluable => None,
                    });
                    let chars: Vec<char> = s.chars().collect();
                    if start_idx >= chars.len() {
                        return EvalResult::Value(EvalValue::String(String::new()));
                    }
                    let end = len.map_or(chars.len(), |l| (start_idx + l).min(chars.len()));
                    let substr: String = chars[start_idx..end].iter().collect();
                    return EvalResult::Value(EvalValue::String(substr));
                }
            }
            EvalResult::Unevaluable
        }
        "REVERSE" => {
            if let Some(EvalResult::Value(EvalValue::String(s))) = args.first() {
                let rev: String = s.chars().rev().collect();
                return EvalResult::Value(EvalValue::String(rev));
            }
            EvalResult::Unevaluable
        }
        "COALESCE" | "IFNULL" | "ISNULL" => {
            for arg in args {
                if let EvalResult::Value(v) = arg {
                    if !matches!(v, EvalValue::Null) {
                        return EvalResult::Value(v.clone());
                    }
                }
            }
            EvalResult::Value(EvalValue::Null)
        }
        _ => EvalResult::Unevaluable,
    }
}

fn is_tautology(node: &ExpressionNode) -> bool {
    matches!(evaluate_expression(node), EvalResult::Value(v) if to_bool(&v))
}

fn stringify_expression(node: &ExpressionNode) -> String {
    match node {
        ExpressionNode::LiteralNumber(v) => {
            if (v.fract() - 0.0).abs() < f64::EPSILON {
                (*v as i64).to_string()
            } else {
                v.to_string()
            }
        }
        ExpressionNode::LiteralString(v) => format!("'{}'", v),
        ExpressionNode::LiteralBool(v) => {
            if *v {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }
        }
        ExpressionNode::LiteralNull => "NULL".to_string(),
        ExpressionNode::Identifier(name) => name.clone(),
        ExpressionNode::Comparison {
            left,
            operator,
            right,
        } => format!(
            "{} {} {}",
            stringify_expression(left),
            operator,
            stringify_expression(right)
        ),
        ExpressionNode::Not(operand) => format!("NOT {}", stringify_expression(operand)),
        ExpressionNode::IsNull { operand, negated } => format!(
            "{} IS {}NULL",
            stringify_expression(operand),
            if *negated { "NOT " } else { "" }
        ),
        ExpressionNode::Between { operand, low, high } => format!(
            "{} BETWEEN {} AND {}",
            stringify_expression(operand),
            stringify_expression(low),
            stringify_expression(high)
        ),
        ExpressionNode::InList { operand, values } => {
            let vals = values
                .iter()
                .map(stringify_expression)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} IN ({})", stringify_expression(operand), vals)
        }
        ExpressionNode::Like { operand, pattern } => format!(
            "{} LIKE {}",
            stringify_expression(operand),
            stringify_expression(pattern)
        ),
        ExpressionNode::FunctionCall { name, args } => {
            let vals = args
                .iter()
                .map(stringify_expression)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}({})", name, vals)
        }
        ExpressionNode::Unknown => "?".to_string(),
    }
}

fn get_expression_position(node: &ExpressionNode) -> usize {
    match node {
        ExpressionNode::Comparison { left, .. }
        | ExpressionNode::Between { operand: left, .. }
        | ExpressionNode::InList { operand: left, .. }
        | ExpressionNode::Like { operand: left, .. }
        | ExpressionNode::IsNull { operand: left, .. } => get_expression_position(left),
        ExpressionNode::Not(operand) => get_expression_position(operand),
        _ => 0,
    }
}

fn to_bool(v: &EvalValue) -> bool {
    match v {
        EvalValue::Bool(b) => *b,
        EvalValue::Number(n) => *n != 0.0,
        EvalValue::String(s) => !s.is_empty(),
        EvalValue::Null => false,
    }
}

fn to_number(v: &EvalValue) -> f64 {
    match v {
        EvalValue::Number(n) => *n,
        EvalValue::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        EvalValue::String(s) => s.parse::<f64>().unwrap_or(0.0),
        EvalValue::Null => 0.0,
    }
}

fn equals_eval_value(left: &EvalValue, right: &EvalValue) -> bool {
    match (left, right) {
        (EvalValue::Number(l), EvalValue::Number(r)) => (*l - *r).abs() < f64::EPSILON,
        _ => stringify_eval_value(left) == stringify_eval_value(right),
    }
}

fn stringify_eval_value(value: &EvalValue) -> String {
    match value {
        EvalValue::Number(n) => {
            if (n.fract() - 0.0).abs() < f64::EPSILON {
                (*n as i64).to_string()
            } else {
                n.to_string()
            }
        }
        EvalValue::String(s) => s.clone(),
        EvalValue::Bool(b) => b.to_string(),
        EvalValue::Null => "null".to_string(),
    }
}

fn is_sql_keyword(upper: &str) -> bool {
    static KEYWORDS: &[&str] = &[
        "SELECT", "FROM", "WHERE", "IS", "NOT", "NULL", "TRUE", "FALSE", "LIKE", "IN", "BETWEEN",
        "EXISTS", "HAVING", "GROUP", "ORDER", "UNION", "ALL", "INSERT", "UPDATE", "DELETE", "DROP",
        "CREATE", "ALTER", "EXEC", "EXECUTE", "CAST", "CONVERT", "AS", "CASE", "WHEN", "THEN", "ELSE",
        "END", "LIMIT", "OFFSET", "ASC", "DESC",
    ];
    KEYWORDS.contains(&upper)
}

fn is_boolean_op(upper: &str) -> bool {
    matches!(upper, "AND" | "OR")
}

fn is_whitespace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_ascii_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_ident_continue(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.')
}

fn find_subsequence(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() || needle.len() > haystack.len() {
        return None;
    }

    let end = haystack.len() - needle.len();
    (start..=end).find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn push(tokens: &mut Vec<Token<SqlTokenType>>, ty: SqlTokenType, bytes: &[u8], start: usize, end: usize) {
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
    fn sql_basic_tokenization() {
        let stream = SqlTokenizer.tokenize("SELECT * FROM users WHERE id = 1");
        assert!(stream.has(SqlTokenType::Keyword));
        assert!(stream.has(SqlTokenType::Operator));
        assert!(stream.count(SqlTokenType::Number) >= 1);
    }

    #[test]
    fn sql_edge_case_comments_and_strings() {
        let stream = SqlTokenizer.tokenize("'a''b' OR 1=1-- trailing");
        assert!(stream.has(SqlTokenType::String));
        assert!(stream.has(SqlTokenType::BooleanOp));
        assert!(stream.has(SqlTokenType::Separator));
    }

    #[test]
    fn sql_encoding_detection_hex_numeric() {
        let stream = SqlTokenizer.tokenize("0x41 = 65 OR 0b1 = 1");
        assert!(stream.count(SqlTokenType::Number) >= 4);
    }

    #[test]
    fn sql_max_input_bound() {
        let long = "A".repeat(MAX_TOKENIZER_INPUT + 5000);
        let stream = SqlTokenizer.tokenize(&long);
        let total_len: usize = stream.all().iter().map(|t| t.value.len()).sum();
        assert!(total_len <= MAX_TOKENIZER_INPUT.min(4096));
        assert!(stream.all().len() <= MAX_TOKEN_COUNT);
    }

    #[test]
    fn sql_empty_input() {
        let stream = SqlTokenizer.tokenize("");
        assert!(stream.all().is_empty());
    }

    #[test]
    fn sql_detects_tautology() {
        let detections = detect_tautologies("' OR 1=1--");
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.expression.contains("1 = 1") || d.expression.contains("1=1")));
    }
}
