//! XSS Context Evaluator — Level 2 Invariant Detection
//!
//! Invariant property for XSS tag injection:
//!   exists element in parse(input, HTML_FRAGMENT_GRAMMAR) :
//!     element.type = HTML_TAG
//!     AND element.tag_name in SCRIPT_CAPABLE_TAGS
//!     OR element.attributes exists attr :
//!         attr.name starts_with 'on' OR attr.value starts_with 'javascript:'

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::tokenizers::html::{HtmlTokenType, HtmlTokenizer};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::OnceLock;

const SCRIPT_CAPABLE_TAGS: &[&str] = &[
    "script",
    "img",
    "svg",
    "iframe",
    "object",
    "embed",
    "video",
    "audio",
    "source",
    "body",
    "input",
    "select",
    "textarea",
    "button",
    "details",
    "marquee",
    "isindex",
    "form",
    "math",
    "base",
    "link",
    "style",
    "meta",
    "applet",
    "bgsound",
    "layer",
    "ilayer",
    "xml",
    "xss",
    "image",
    "animate",
    "set",
    "animatemotion",
    "animatetransform",
    "foreignobject",
];

const DANGEROUS_SCHEMES: &[&str] = &[
    "javascript:",
    "data:text/html",
    "data:text/javascript",
    "data:application/javascript",
    "data:application/ecmascript",
    "data:application/xhtml+xml",
    "data:text/xml",
    "vbscript:",
    "livescript:",
];

const URI_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "action",
    "formaction",
    "data",
    "background",
    "poster",
    "codebase",
    "cite",
    "icon",
    "manifest",
    "dynsrc",
    "lowsrc",
    "srcdoc",
];

const DOM_CLOBBER_TAGS: &[&str] = &["form", "a"];
const DOM_CLOBBER_FORM_TAGS: &[&str] = &["form"];
const DOM_CLOBBER_INPUT_TAGS: &[&str] = &[
    "input", "select", "textarea", "button", "keygen", "fieldset", "object",
];
const DOM_CLOBBER_ATTRS: &[&str] = &["id", "name"];
const DOM_CLOBBER_NAMES: &[&str] = &[
    "location",
    "document",
    "window",
    "top",
    "self",
    "frames",
    "opener",
    "parent",
    "constructor",
];

const SVG_ANIMATION_TAGS: &[&str] = &[
    "animate",
    "set",
    "animatemotion",
    "animatetransform",
    "discard",
    "mpath",
];

pub struct XssEvaluator;

/// Parsed HTML element from token stream
struct ParsedElement {
    tag_name: String,
    attributes: Vec<(String, String)>,
    position: usize,
}

impl XssEvaluator {
    fn normalized_xss_view(input: &str) -> String {
        let html_decoded = Self::decode_html_entities(input);
        let layered = crate::encoding::multi_layer_decode(&html_decoded).fully_decoded;
        crate::normalizer::quick_canonical(&layered)
    }

    fn extract_elements(&self, input: &str) -> Vec<ParsedElement> {
        let tokenizer = HtmlTokenizer;
        let stream = tokenizer.tokenize(input);
        let tokens = stream.all();
        let mut elements = Vec::new();
        let mut i = 0;

        while i < tokens.len() {
            if tokens[i].token_type == HtmlTokenType::TagOpen {
                let position = tokens[i].start;
                i += 1;

                // Next token should be TagName
                if i >= tokens.len() {
                    break;
                }
                // Skip whitespace
                while i < tokens.len() && tokens[i].token_type == HtmlTokenType::Whitespace {
                    i += 1;
                }
                if i >= tokens.len() {
                    break;
                }

                let tag_name = if tokens[i].token_type == HtmlTokenType::TagName {
                    let name = tokens[i].value.to_lowercase();
                    i += 1;
                    name
                } else {
                    continue;
                };

                let mut attrs = Vec::new();

                while i < tokens.len() {
                    match tokens[i].token_type {
                        HtmlTokenType::AttrName => {
                            let name = tokens[i].value.to_lowercase();
                            i += 1;
                            if i < tokens.len() && tokens[i].token_type == HtmlTokenType::AttrEquals
                            {
                                i += 1;
                                if i < tokens.len()
                                    && tokens[i].token_type == HtmlTokenType::AttrValue
                                {
                                    attrs.push((name, tokens[i].value.clone()));
                                    i += 1;
                                } else {
                                    attrs.push((name, String::new()));
                                }
                            } else {
                                attrs.push((name, String::new()));
                            }
                        }
                        HtmlTokenType::TagSelfClose | HtmlTokenType::TagClose => {
                            i += 1;
                            break;
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }

                elements.push(ParsedElement {
                    tag_name,
                    attributes: attrs,
                    position,
                });
            } else {
                i += 1;
            }
        }

        elements
    }

    fn is_event_handler(name: &str) -> bool {
        name.starts_with("on")
            && name.len() > 2
            && name[2..].chars().all(|c| c.is_ascii_alphabetic())
    }

    fn decode_js_escape_sequence(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch != '\\' {
                out.push(ch);
                continue;
            }

            let next = match chars.next() {
                Some(next) => next,
                None => continue,
            };

            match next {
                'x' => {
                    let mut hex = String::with_capacity(2);
                    for _ in 0..2 {
                        if let Some(h) = chars.peek() {
                            if h.is_ascii_hexdigit() {
                                hex.push(*h);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                    if hex.len() == 2 {
                        if let Ok(v) = u8::from_str_radix(&hex, 16) {
                            out.push(v as char);
                            continue;
                        }
                    }
                    out.push('x');
                }
                'u' => {
                    let mut hex = String::with_capacity(4);
                    for _ in 0..4 {
                        if let Some(h) = chars.peek() {
                            if h.is_ascii_hexdigit() {
                                hex.push(*h);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                    if hex.len() == 4 {
                        if let Ok(v) = u16::from_str_radix(&hex, 16) {
                            if let Some(decoded) = char::from_u32(v as u32) {
                                out.push(decoded);
                                continue;
                            }
                        }
                    }
                    out.push('u');
                }
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'n' => out.push('\n'),
                'v' => out.push('\x0b'),
                'f' => out.push('\x0c'),
                'b' => out.push('\x08'),
                '\'' | '"' | '\\' | '/' | '`' => out.push(next),
                _ => out.push(next),
            }
        }

        out
    }

    fn compact_protocol_token(input: &str) -> String {
        let normalized = Self::normalized_xss_view(input);
        let normalized = Self::decode_js_escape_sequence(&normalized);
        normalized
            .chars()
            .filter(|c| {
                !c.is_whitespace()
                    && !c.is_control()
                    && *c != '('
                    && *c != ')'
                    && *c != '\''
                    && *c != '"'
            })
            .collect::<String>()
            .to_ascii_lowercase()
    }

    fn is_dangerous_data_uri(value: &str) -> bool {
        if !value.starts_with("data:") {
            return false;
        }

        let body = value
            .get(5..)
            .unwrap_or("")
            .split(',')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("");
        let body = body
            .chars()
            .map(|c| if c.is_whitespace() { '+' } else { c })
            .collect::<String>();
        let body_without_plus = body.replace('+', "");
        let matches_data_type = |value: &str| {
            body.starts_with(value) || body_without_plus.starts_with(&value.replace('+', ""))
        };

        matches_data_type("text/html")
            || matches_data_type("text/javascript")
            || matches_data_type("application/javascript")
            || matches_data_type("application/ecmascript")
            || matches_data_type("text/xml")
            || matches_data_type("application/xhtml+xml")
            || matches_data_type("image/svg+xml")
    }

    fn has_dangerous_scheme(value: &str) -> bool {
        let compact = Self::compact_protocol_token(value);
        DANGEROUS_SCHEMES
            .iter()
            .any(|scheme| compact.starts_with(scheme))
            || Self::is_dangerous_data_uri(&compact)
    }

    fn decode_html_entities(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut i = 0usize;
        while i < input.len() {
            let tail = &input[i..];
            if let Some(rest) = tail.strip_prefix("&lt;") {
                out.push('<');
                i = input.len() - rest.len();
            } else if let Some(rest) = tail.strip_prefix("&gt;") {
                out.push('>');
                i = input.len() - rest.len();
            } else if let Some(rest) = tail.strip_prefix("&amp;") {
                out.push('&');
                i = input.len() - rest.len();
            } else if let Some(rest) = tail.strip_prefix("&quot;") {
                out.push('"');
                i = input.len() - rest.len();
            } else if let Some(rest) = tail.strip_prefix("&#39;") {
                out.push('\'');
                i = input.len() - rest.len();
            } else if tail.strip_prefix("&apos;").is_some() {
                out.push('\'');
                i += 6;
            } else if tail.starts_with("&#x") || tail.starts_with("&#X") {
                if let Some(end) = tail.find(';') {
                    let num = &tail[3..end];
                    if let Ok(v) = u32::from_str_radix(num, 16) {
                        if let Some(ch) = char::from_u32(v) {
                            out.push(ch);
                            i += end + 1;
                            continue;
                        }
                    }
                }
                out.push('&');
                i += 1;
            } else if tail.starts_with("&#") {
                if let Some(end) = tail.find(';') {
                    let num = &tail[2..end];
                    if let Ok(v) = num.parse::<u32>() {
                        if let Some(ch) = char::from_u32(v) {
                            out.push(ch);
                            i += end + 1;
                            continue;
                        }
                    }
                }
                out.push('&');
                i += 1;
            } else if let Some(ch) = tail.chars().next() {
                out.push(ch);
                i += ch.len_utf8();
            } else {
                break;
            }
        }
        out
    }

    fn detect_attribute_escape(input: &str) -> Option<(usize, String)> {
        static ATTR_ESCAPE_RE: OnceLock<Regex> = OnceLock::new();
        let re = ATTR_ESCAPE_RE.get_or_init(|| {
            Regex::new(
                r#"(?i)(["'])\s*(?:on[a-z]+\s*=|autofocus\b|style\s*=|src\s*=|href\s*=|x\s*=|id\s*=|name\s*=)[^\"'<>]*(?:\s+[a-z_:][-a-z0-9_:.]*\s*=)?"#,
            )
            .unwrap()
        });

        if let Some(m) = re.find(input) {
            let snippet = m.as_str().to_string();
            return Some((m.start(), snippet));
        }

        static QUOTE_CHAIN_RE: OnceLock<Regex> = OnceLock::new();
        let quote_chain_re = QUOTE_CHAIN_RE.get_or_init(|| {
            Regex::new(
                r#"(?i)(?:^|[<\s])(?:[a-z_:][-a-z0-9_:.]*)\s*=\s*[\"'][^\"']*(?:[\"'][^>]*\s+[a-z_:][-a-z0-9_:.]*\s*=)"#,
            )
            .unwrap()
        });
        quote_chain_re
            .find(input)
            .map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_template_expression(input: &str) -> Option<(usize, String)> {
        let decoded = Self::decode_html_entities(input);
        static TEMPLATE_RE: OnceLock<Regex> = OnceLock::new();
        let re = TEMPLATE_RE.get_or_init(|| {
            Regex::new(
                r#"(?is)\{\{\s*(?:(?:on|_c)\s*\.\s*)?constructor(?:\s*\.\s*constructor){1,2}\s*\([^}]*\b(?:alert|Function|constructor)\s*\([^}]*\)[^}]*\)\s*\(\s*\)\s*\}\}|`[^`]*\$\{[^{}]*\b(?:alert|prompt|confirm|Function|constructor)\s*\([^`$}]*\)\s*\}[^`]*`|\$\{[^}]*\b(?:alert|prompt|confirm|Function|constructor)\s*\([^}]*\)\s*\}|#\{[^}]*alert\s*\([^}]*\)\s*\}"#,
            )
            .unwrap()
        });
        re.find(&decoded)
            .map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_template_literal_alert_injection(input: &str) -> Option<(usize, String)> {
        static TEMPLATE_LITERAL_ALERT_RE: OnceLock<Regex> = OnceLock::new();
        let re = TEMPLATE_LITERAL_ALERT_RE.get_or_init(|| {
            Regex::new(r#"(?is)\$\{\s*alert\s*\([^)]{0,80}\)\s*\}"#).unwrap()
        });
        re.find(input).map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_bare_protocol_handler(input: &str) -> Option<(usize, String)> {
        let compact = Self::compact_protocol_token(input);
        if compact.starts_with("javascript:")
            || Self::is_dangerous_data_uri(&compact)
            || compact.starts_with("vbscript:")
            || compact.starts_with("livescript:")
        {
            return Some((0, compact.chars().take(120).collect()));
        }

        None
    }

    fn detect_css_execution(input: &str) -> Option<(usize, String)> {
        static CSS_XSS_RE: OnceLock<Regex> = OnceLock::new();
        let re = CSS_XSS_RE.get_or_init(|| {
            Regex::new(
                r#"(?is)(?:expression\s*\(|-ms-?expression\s*:|behavior\s*:\s*url\s*\(|-moz-binding\s*:\s*url\s*\(|url\(\s*[\"']?\s*javascript:|url\(\s*[\"']?\\?data:)"#,
            )
            .unwrap()
        });
        let normalized = Self::normalized_xss_view(input);
        re.find(&normalized)
            .map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_iframe_srcdoc_xss(input: &str) -> Option<(usize, String)> {
        static IFRAME_SRCDOC_RE: OnceLock<Regex> = OnceLock::new();
        let re = IFRAME_SRCDOC_RE.get_or_init(|| {
            Regex::new(
                r#"(?i)<iframe[^>]*\bsrcdoc\s*=\s*['\"][^'\"]*(?:script|javascript|onerror|onload)[^'\"]*['\"]"#,
            )
            .unwrap()
        });
        re.find(input).map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_meta_refresh_data_uri_xss(input: &str) -> Option<(usize, String)> {
        static META_REFRESH_RE: OnceLock<Regex> = OnceLock::new();
        let re = META_REFRESH_RE.get_or_init(|| {
            Regex::new(
                r#"(?i)<meta[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*content\s*=\s*['\"][^'\"]*(?:javascript:|data:text/html)[^'\"]*['\"]"#,
            )
            .unwrap()
        });
        re.find(input).map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_base_href_javascript(input: &str) -> Option<(usize, String)> {
        static BASE_HREF_RE: OnceLock<Regex> = OnceLock::new();
        let re = BASE_HREF_RE
            .get_or_init(|| Regex::new(r#"(?i)<base[^>]*\bhref\s*=\s*['\"]?javascript:"#).unwrap());
        re.find(input).map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_form_action_javascript(input: &str) -> Option<(usize, String)> {
        static FORM_ACTION_RE: OnceLock<Regex> = OnceLock::new();
        let re = FORM_ACTION_RE
            .get_or_init(|| Regex::new(r#"(?i)<form[^>]*\baction\s*=\s*['\"]?javascript:"#).unwrap());
        re.find(input).map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_legacy_css_expression_injection(input: &str) -> Option<(usize, String)> {
        static LEGACY_CSS_RE: OnceLock<Regex> = OnceLock::new();
        let re = LEGACY_CSS_RE.get_or_init(|| {
            Regex::new(r#"(?is)(?:expression\s*\(|behavior\s*:\s*url\s*\(|-moz-binding)"#).unwrap()
        });
        let normalized = Self::normalized_xss_view(input);
        re.find(&normalized)
            .map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_css_expression_split_keyword(input: &str) -> Option<(usize, String)> {
        static CSS_SPLIT_EXPR_RE: OnceLock<Regex> = OnceLock::new();
        let re = CSS_SPLIT_EXPR_RE.get_or_init(|| {
            Regex::new(r#"(?is)expr\s*/\*[\s\S]*?\*/\s*ession\s*\("#).unwrap()
        });
        re.find(input).map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_svg_animate_onbegin(input: &str) -> Option<(usize, String)> {
        static SVG_ANIMATE_ONBEGIN_RE: OnceLock<Regex> = OnceLock::new();
        let re = SVG_ANIMATE_ONBEGIN_RE.get_or_init(|| {
            Regex::new(
                r#"(?is)<svg\b[^>]*>\s*<animate\b[^>]*\bonbegin\s*=\s*['"]?[^'" >]+[^>]*\battributename\s*=\s*['"]?x"#,
            )
            .unwrap()
        });
        re.find(input).map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_svg_data_uri_payload(input: &str) -> Option<(usize, String)> {
        let normalized = Self::normalized_xss_view(input);
        let lower = normalized.to_lowercase();
        let mut offset = 0;

        while let Some(start_rel) = lower[offset..].find("<iframe") {
            let start = offset + start_rel;
            let bytes = lower.as_bytes();
            let mut i = start;
            let mut in_single = false;
            let mut in_double = false;

            while i < bytes.len() {
                match bytes[i] {
                    b'\'' if !in_double => in_single = !in_single,
                    b'"' if !in_single => in_double = !in_double,
                    b'>' if !in_single && !in_double => break,
                    _ => {}
                }
                i += 1;
            }

            if i >= bytes.len() {
                break;
            }

            let tag = &lower[start..=i];
            if let Some(src) =
                Self::extract_tag_attr_value(tag, "src").map(|v| Self::compact_protocol_token(&v))
            {
                if src.starts_with("data:image/svg+xml")
                    && (src.contains("<svg") || src.contains("onload=") || src.contains("onerror="))
                {
                    return Some((start, tag.to_string()));
                }
            }

            offset = i + 1;
            if offset <= start {
                break;
            }
        }
        None
    }

    fn extract_tag_attr_value(tag: &str, attribute: &str) -> Option<String> {
        let mut i = 0usize;
        let bytes = tag.as_bytes();

        if let Some(first) = bytes.first()
            && *first == b'<'
        {
            i += 1;
        }

        while i < bytes.len() {
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }

            let name_start = i;
            while i < bytes.len() && Self::is_attr_name_char(bytes[i]) {
                i += 1;
            }

            if i <= name_start {
                i += 1;
                continue;
            }

            let name = &tag[name_start..i];
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b'=' {
                continue;
            }
            i += 1;

            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }

            let quote = if bytes[i] == b'\'' || bytes[i] == b'"' {
                Some(bytes[i])
            } else {
                None
            };

            let value_start;
            if let Some(q) = quote {
                i += 1;
                value_start = i;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
            } else {
                value_start = i;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && bytes[i] != b'>'
                    && bytes[i] != b'/'
                {
                    i += 1;
                }
            }

            if !name.eq_ignore_ascii_case(attribute) {
                continue;
            }
            return Some(tag[value_start..i.min(bytes.len())].to_string());
        }

        None
    }

    fn is_attr_name_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b':' || byte == b'.'
    }

    fn detect_mutation_xss(input: &str) -> Option<(usize, String)> {
        static MXSS_RE: OnceLock<Regex> = OnceLock::new();
        let re = MXSS_RE.get_or_init(|| {
            Regex::new(
                r#"(?is)<math\b[^>]*>.*?<mtext\b[^>]*>.*?<table\b[^>]*>.*?<mglyph\b[^>]*>.*?<style\b[^>]*>.*?(?:<!--|<!\[CDATA\[).*?</style>.*?<img\b[^>]*(?:[^>\"]|\"[^\"]*\")*?(?:on[a-z]+\s*=|src\s*=)[^>]*>|<svg\b[^>]*>.*?<foreignobject\b[^>]*>.*?(?:<body|<img|<iframe|<script)\b[^>]*(?:[^>\"]|\"[^\"]*\")*?(?:on[a-z]+\s*=|(?:xlink:)?href\s*=|src\s*=)[^>]*>|<svg\b[^>]*>.*?<foreignobject\b[^>]*>.*?<math\b[^>]*>"#,
            )
            .unwrap()
        });
        let normalized = Self::normalized_xss_view(input);
        re.find(&normalized)
            .map(|m| (m.start(), m.as_str().to_string()))
    }

    fn detect_dom_clobbering_pair(elements: &[ParsedElement]) -> Option<(usize, String)> {
        let mut forms = Vec::new();
        let mut named_inputs = Vec::new();

        for elem in elements {
            if DOM_CLOBBER_FORM_TAGS.contains(&elem.tag_name.as_str())
                && let Some(form_name) = elem.attributes.iter().find_map(|(name, value)| {
                    if DOM_CLOBBER_ATTRS.contains(&name.as_str())
                        && Self::is_safe_dom_identifier(value)
                    {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
            {
                forms.push((elem.position, form_name));
            }

            if DOM_CLOBBER_INPUT_TAGS.contains(&elem.tag_name.as_str())
                && let Some(input_name) = elem.attributes.iter().find_map(|(name, value)| {
                    if (name == "name" || name == "id") && Self::is_safe_dom_identifier(value) {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
            {
                named_inputs.push((elem.position, input_name));
            }
        }

        for (form_pos, form_id) in forms {
            for (input_pos, input_name) in &named_inputs {
                if *input_pos > form_pos {
                    return Some((
                        form_pos.min(*input_pos),
                        format!(
                            "<form id=\"{}\" ...><input name=\"{}\">",
                            form_id, input_name
                        ),
                    ));
                }
            }
        }

        None
    }

    fn is_safe_dom_identifier(value: &str) -> bool {
        let mut chars = value.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }

    fn detect_dom_xss_sinks(input: &str) -> Option<(f32, &'static str)> {
        static DOM_XSS_SINK_RE: OnceLock<Regex> = OnceLock::new();
        let re = DOM_XSS_SINK_RE.get_or_init(|| {
            Regex::new(
                r#"(?is)(?:\b(?:innerhtml|outerhtml)\s*=|\bdocument\.(?:write|writeln)\s*\(|\b(?:eval|settimeout|setinterval)\s*\(\s*['"][^'"]+['"]\s*(?:,|\))|\blocation\.(?:href|hash|search)\s*=|\bwindow\.name\s*=|\bdocument\.domain\s*=)"#,
            )
            .unwrap()
        });
        if re.is_match(&input.to_ascii_lowercase()) {
            Some((0.90, "dom_xss_sink"))
        } else {
            None
        }
    }

    fn detect_svg_namespace_xss(input: &str) -> Option<(f32, &'static str)> {
        static SVG_NAMESPACE_XSS_RE: OnceLock<Regex> = OnceLock::new();
        let re = SVG_NAMESPACE_XSS_RE.get_or_init(|| {
            Regex::new(
                r#"(?is)(?:<svg\b[^>]*\bonload\s*=|<svg/\s*onload\s*=|<svg\b[^>]*>\s*<script\b|<svg\b[^>]*\bxmlns\s*=|<math\b[^>]*>\s*<mtext\b[^>]*>\s*</form>\s*<form\b[^>]*>\s*<mglyph\b[^>]*>\s*<svg\b|<svg\b[^>]*>\s*<use\b[^>]*\bhref\s*=\s*['"]\s*data:image/svg\+xml)"#,
            )
            .unwrap()
        });
        if re.is_match(input) {
            Some((0.88, "svg_namespace_xss"))
        } else {
            None
        }
    }

    fn detect_polyglot_xss(input: &str) -> Option<(f32, &'static str)> {
        static POLYGLOT_XSS_RE: OnceLock<Regex> = OnceLock::new();
        let re = POLYGLOT_XSS_RE.get_or_init(|| {
            Regex::new(
                r#"(?is)(?:javascript://[^\s]*%0a[^\s]*alert\s*\(|</title>\s*<script\b|["']\s*onmouseover\s*=|\\u003cscript\\u003e|\\x3cscript\\x3e|\[\]\[\(!\[\]\+\[\]\)\[\+\[\]\])"#,
            )
            .unwrap()
        });
        if re.is_match(input) {
            Some((0.85, "polyglot_xss"))
        } else {
            None
        }
    }

    fn detect_csp_bypass_xss(input: &str) -> Option<(f32, &'static str)> {
        static CSP_BYPASS_XSS_RE: OnceLock<Regex> = OnceLock::new();
        let re = CSP_BYPASS_XSS_RE.get_or_init(|| {
            Regex::new(
                r#"(?is)(?:\b(?:callback|jsonp|cb)\s*=\s*[a-z_$][\w$]*(?:\.[a-z_$][\w$]*)*(?:\s*\(|%28)|\{\{\s*7\s*\*\s*7\s*\}\}|ng-app\b[^>]*\{\{|\btrusted(?:html|script)\b)"#,
            )
            .unwrap()
        });
        if re.is_match(&input.to_ascii_lowercase()) {
            Some((0.87, "csp_bypass_xss"))
        } else {
            None
        }
    }
}

impl L2Evaluator for XssEvaluator {
    fn id(&self) -> &'static str {
        "xss"
    }
    fn prefix(&self) -> &'static str {
        "L2 XSS"
    }

    #[inline]
    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let elements = self.extract_elements(input);

        if let Some((position, matched)) = Self::detect_attribute_escape(input) {
            detections.push(L2Detection {
                detection_type: "attribute_escape".into(),
                confidence: 0.88,
                detail: "HTML attribute breakout pattern with injected attribute chain".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: matched,
                    interpretation: "Input breaks out of a quoted attribute value and appends attacker-controlled attributes".into(),
                    offset: position,
                    property: "User input inside HTML attributes must remain data and must not escape into new attribute assignments".into(),
                }],
            });
        }

        if let Some((confidence, detection_type)) = Self::detect_dom_xss_sinks(input) {
            detections.push(L2Detection {
                detection_type: detection_type.into(),
                confidence: confidence as f64,
                detail: "DOM-based XSS sink usage pattern".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation:
                        "Input contains dangerous DOM sinks or assignments frequently abused for DOM XSS"
                            .into(),
                    offset: 0,
                    property:
                        "User-controlled data must not flow into script-capable DOM sink assignments"
                            .into(),
                }],
            });
        }

        if let Some((confidence, detection_type)) = Self::detect_svg_namespace_xss(input) {
            detections.push(L2Detection {
                detection_type: detection_type.into(),
                confidence: confidence as f64,
                detail: "SVG/MathML namespace confusion XSS pattern".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: input.to_owned(),
                    interpretation:
                        "Input uses SVG/MathML parsing boundaries or namespace features to reach executable contexts"
                            .into(),
                    offset: 0,
                    property:
                        "User markup must remain inert across SVG/MathML namespace transitions".into(),
                }],
            });
        }

        if let Some((confidence, detection_type)) = Self::detect_polyglot_xss(input) {
            detections.push(L2Detection {
                detection_type: detection_type.into(),
                confidence: confidence as f64,
                detail: "Polyglot or heavily obfuscated XSS payload shape".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: input.to_owned(),
                    interpretation:
                        "Input matches cross-context polyglot payloads or encoded script syntax"
                            .into(),
                    offset: 0,
                    property:
                        "User input must be canonicalized and validated against multi-context XSS encodings"
                            .into(),
                }],
            });
        }

        if let Some((confidence, detection_type)) = Self::detect_csp_bypass_xss(input) {
            detections.push(L2Detection {
                detection_type: detection_type.into(),
                confidence: confidence as f64,
                detail: "Potential CSP bypass vector for XSS execution".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: input.to_owned(),
                    interpretation:
                        "Input includes JSONP, Angular expression, or Trusted Types abuse indicators used in CSP bypass chains"
                            .into(),
                    offset: 0,
                    property:
                        "CSP controls must not be bypassable through callback or trusted-type gadget injection"
                            .into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_template_expression(input) {
            detections.push(L2Detection {
                detection_type: "template_expression".into(),
                confidence: 0.85,
                detail: "Client-side template expression injection pattern".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: matched,
                    interpretation: "Template expression syntax can be evaluated by client-side render engines as executable code".into(),
                    offset: position,
                    property: "User input must not introduce executable template expressions in rendering contexts".into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_template_literal_alert_injection(input) {
            detections.push(L2Detection {
                detection_type: "template_literal_js".into(),
                confidence: 0.89,
                detail: "Template literal JavaScript interpolation payload".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: matched,
                    interpretation:
                        "JavaScript template literal interpolation executes attacker-controlled expression"
                            .into(),
                    offset: position,
                    property:
                        "User input must not inject executable expressions in template-literal contexts"
                            .into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_bare_protocol_handler(input) {
            detections.push(L2Detection {
                detection_type: "protocol_handler".into(),
                confidence: 0.86,
                detail: "Bare dangerous URI scheme payload outside tag context".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched,
                    interpretation: "Input begins with an executable URI scheme (javascript/data/vbscript) that can trigger script execution when used as a sink".into(),
                    offset: position,
                    property: "URI values derived from user input must not use executable protocol schemes".into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_css_execution(input) {
            detections.push(L2Detection {
                detection_type: "tag_injection".into(),
                confidence: 0.84,
                detail: "CSS execution primitive detected (expression/behavior/-moz-binding/javascript URL)".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: matched,
                    interpretation: "Legacy/quirks CSS execution vectors can evaluate script in style contexts".into(),
                    offset: position,
                    property: "User input in CSS/style contexts must not introduce executable CSS primitives".into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_iframe_srcdoc_xss(input) {
            detections.push(L2Detection {
                detection_type: "tag_injection".into(),
                confidence: 0.87,
                detail: "HTML5 iframe srcdoc script-capable payload".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched,
                    interpretation:
                        "iframe srcdoc embeds HTML/JS content that can execute in document context"
                            .into(),
                    offset: position,
                    property: "User input must not control iframe srcdoc with executable content"
                        .into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_meta_refresh_data_uri_xss(input) {
            detections.push(L2Detection {
                detection_type: "protocol_handler".into(),
                confidence: 0.88,
                detail: "Meta refresh redirects to executable javascript/data:text/html URI".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched,
                    interpretation:
                        "Meta refresh content points at executable URI schemes that can trigger script"
                            .into(),
                    offset: position,
                    property:
                        "HTML refresh directives must not include executable URI destinations".into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_base_href_javascript(input) {
            detections.push(L2Detection {
                detection_type: "protocol_handler".into(),
                confidence: 0.91,
                detail: "Base tag javascript: href can hijack relative URL resolution".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched,
                    interpretation:
                        "A javascript: base href can redirect relative links/forms into script execution"
                            .into(),
                    offset: position,
                    property:
                        "Base URL declarations derived from user input must not use executable schemes"
                            .into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_form_action_javascript(input) {
            detections.push(L2Detection {
                detection_type: "protocol_handler".into(),
                confidence: 0.89,
                detail: "Form action uses javascript: protocol".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched,
                    interpretation:
                        "Form submissions can trigger javascript: execution when action is attacker-controlled"
                            .into(),
                    offset: position,
                    property:
                        "Form action attributes must not use executable protocol handlers".into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_legacy_css_expression_injection(input) {
            detections.push(L2Detection {
                detection_type: "tag_injection".into(),
                confidence: 0.85,
                detail: "Legacy CSS expression/behavior/-moz-binding execution primitive".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: matched,
                    interpretation:
                        "Legacy CSS execution syntax may evaluate script in style contexts".into(),
                    offset: position,
                    property:
                        "User-controlled CSS must not include executable legacy expression primitives"
                            .into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_css_expression_split_keyword(input) {
            detections.push(L2Detection {
                detection_type: "css_expression_split_keyword".into(),
                confidence: 0.90,
                detail: "Obfuscated CSS expr/**/ession() execution primitive".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: matched,
                    interpretation:
                        "CSS comments split expression() keyword to evade signature-based XSS filtering"
                            .into(),
                    offset: position,
                    property:
                        "CSS syntax must be normalized by stripping comments before expression checks"
                            .into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_svg_animate_onbegin(input) {
            detections.push(L2Detection {
                detection_type: "xss_svg_animate_onbegin".into(),
                confidence: 0.90,
                detail: "SVG animate element with onbegin handler".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched,
                    interpretation:
                        "SVG animate onbegin event handlers execute script when animation lifecycle starts"
                            .into(),
                    offset: position,
                    property:
                        "User HTML/SVG input must not define script-capable animation event handlers"
                            .into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_svg_data_uri_payload(input) {
            detections.push(L2Detection {
                detection_type: "protocol_handler".into(),
                confidence: 0.87,
                detail: "Potentially dangerous SVG data URI payload".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched,
                    interpretation: "iframe/src contains SVG data URI payload with active SVG execution surface.".into(),
                    offset: position,
                    property: "Data URI payloads in URI attributes must not include executable SVG content.".into(),
                }],
            });
        }

        if let Some((position, matched)) = Self::detect_mutation_xss(input) {
            detections.push(L2Detection {
                detection_type: "tag_injection".into(),
                confidence: 0.86,
                detail: "Mutation XSS pattern using parser mutation boundaries".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: matched,
                    interpretation: "Input relies on browser HTML mutation/reparsing to expose executable elements".into(),
                    offset: position,
                    property: "User input must remain inert under browser DOM mutation and error-recovery parsing".into(),
                }],
            });
        }

        for elem in &elements {
            // Check 1: Script-capable tag
            if SCRIPT_CAPABLE_TAGS.contains(&elem.tag_name.as_str()) {
                if elem.tag_name == "script" {
                    detections.push(L2Detection {
                        detection_type: "tag_injection".into(),
                        confidence: 0.95,
                        detail: "Direct script tag injection — arbitrary JavaScript execution"
                            .into(),
                        position: elem.position,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("<{}>", elem.tag_name),
                            interpretation:
                                "Dangerous HTML tag is injected into trusted markup context".into(),
                            offset: elem.position,
                            property: "User input must not introduce executable HTML elements"
                                .into(),
                        }],
                    });
                    continue;
                }

                // Other script-capable tags with dangerous attributes
                let has_dangerous = elem.attributes.iter().any(|(name, value)| {
                    Self::is_event_handler(name)
                        || (URI_ATTRIBUTES.contains(&name.as_str())
                            && Self::has_dangerous_scheme(value))
                });

                if has_dangerous {
                    detections.push(L2Detection {
                        detection_type: "tag_injection".into(),
                        confidence: 0.90,
                        detail: format!(
                            "Script-capable tag <{}> with dangerous attributes",
                            elem.tag_name
                        ),
                        position: elem.position,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("<{}>", elem.tag_name),
                            interpretation:
                                "Dangerous HTML tag is injected into trusted markup context".into(),
                            offset: elem.position,
                            property: "User input must not introduce executable HTML elements"
                                .into(),
                        }],
                    });
                }

                if SVG_ANIMATION_TAGS.contains(&elem.tag_name.as_str())
                    && elem.attributes.iter().any(|(name, value)| {
                        name == "attributename" && Self::is_event_handler(value.trim())
                    })
                {
                    let value = elem
                        .attributes
                        .iter()
                        .find(|(name, _)| name == "attributename")
                        .map(|(_, value)| value.as_str())
                        .unwrap_or_default();
                    detections.push(L2Detection {
                        detection_type: "tag_injection".into(),
                        confidence: 0.90,
                        detail: format!(
                            "SVG animation attribute gadget on <{}>: attributeName=\"{}\"",
                            elem.tag_name, value
                        ),
                        position: elem.position,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("<{} attributeName=\"...\">", elem.tag_name),
                            interpretation: "SVG animation attributeName is being set to executable event handler names".into(),
                            offset: elem.position,
                            property: "SVG animation/control elements must not expose executable event-name mutations.".into(),
                        }],
                    });
                }
            }

            // Check 2: Event handler attributes (works on ANY tag)
            for (name, value) in &elem.attributes {
                if Self::is_event_handler(name) && !value.is_empty() {
                    detections.push(L2Detection {
                        detection_type: "event_handler".into(),
                        confidence: 0.90,
                        detail: format!("Event handler {}=\"{}\"", name, &value[..value.len().min(50)]),
                        position: elem.position,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("<{} {}=...>", elem.tag_name, name),
                            interpretation: "Untrusted attribute handler enables script execution in event context".into(),
                            offset: elem.position,
                            property: "User input must not introduce JavaScript event handlers".into(),
                        }],
                    });
                }
            }

            // Check 3: Dangerous URI schemes
            for (name, value) in &elem.attributes {
                if URI_ATTRIBUTES.contains(&name.as_str()) && Self::has_dangerous_scheme(value) {
                    detections.push(L2Detection {
                        detection_type: "protocol_handler".into(),
                        confidence: 0.88,
                        detail: format!("Dangerous URI scheme: {}", &value[..value.len().min(50)]),
                        position: elem.position,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("<{} {}=...>", elem.tag_name, name),
                            interpretation: "Attribute value introduces executable URI scheme into document sink".into(),
                            offset: elem.position,
                            property: "URI attributes must not contain executable protocol schemes".into(),
                        }],
                    });
                }
            }

            // Check 4: DOM clobbering via global name shadowing.
            if DOM_CLOBBER_TAGS.contains(&elem.tag_name.as_str()) {
                for (name, value) in &elem.attributes {
                    if DOM_CLOBBER_ATTRS.contains(&name.as_str())
                        && DOM_CLOBBER_NAMES.contains(&value.to_ascii_lowercase().as_str())
                    {
                        detections.push(L2Detection {
                            detection_type: "dom_clobber".into(),
                            confidence: 0.80,
                            detail: format!(
                                "DOM clobbering candidate: <{} {}=\"{}\"> shadows a DOM global",
                                elem.tag_name,
                                name,
                                value
                            ),
                            position: elem.position,
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::PayloadInject,
                                matched_input: format!("<{} {}=\"{}\">", elem.tag_name, name, value),
                                interpretation: "Element id/name shadows built-in DOM globals, enabling object hijacking in script logic".into(),
                                offset: elem.position,
                                property: "User input must not define id/name values that clobber security-sensitive DOM globals".into(),
                            }],
                        });
                    }
                }
            }
        }

        if let Some((position, matched)) = Self::detect_dom_clobbering_pair(&elements) {
            detections.push(L2Detection {
                detection_type: "dom_clobber".into(),
                confidence: 0.84,
                detail: "DOM clobbering gadget: named form container + named control input".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched,
                    interpretation: "Named form and named control can expose document.<formId>.<inputName> in script".into(),
                    offset: position,
                    property: "User input must not create DOM clobbering form/input chains".into(),
                }],
            });
        }

        // Check 5: DOM clobber gadget pattern (`document.<formId>.<inputName>`) with scriptable input.
        let clobber_form = elements.iter().find(|e| {
            e.tag_name == "form"
                && e.attributes
                    .iter()
                    .any(|(n, v)| (n == "id" || n == "name") && Self::is_safe_dom_identifier(v))
        });
        let clobber_input = elements.iter().find(|e| {
            e.tag_name == "input"
                && e.attributes
                    .iter()
                    .any(|(n, v)| n == "name" && Self::is_safe_dom_identifier(v))
                && e.attributes.iter().any(|(n, _)| Self::is_event_handler(n))
        });
        if let (Some(form), Some(input_elem)) = (clobber_form, clobber_input) {
            detections.push(L2Detection {
                detection_type: "dom_clobber".into(),
                confidence: 0.84,
                detail: "DOM clobbering gadget: named <form> + named <input> with event handler".into(),
                position: form.position.min(input_elem.position),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: "<form id/name=...><input name=... on...=>".into(),
                    interpretation: "Named form/input pairs can clobber document properties and expose attacker-controlled callable paths".into(),
                    offset: form.position.min(input_elem.position),
                    property: "User input must not create DOM clobbering object graphs that script can resolve and invoke".into(),
                }],
            });
        }

        let dom_xss_score = detect_dom_xss(input);
        if dom_xss_score > 0.6 {
            detections.push(L2Detection {
                detection_type: "dom_xss".into(),
                confidence: dom_xss_score,
                detail: "DOM-based XSS via browser sink".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "DOM-based XSS sink function invocation detected".into(),
                    offset: 0,
                    property: "User input must not be passed into dangerous DOM sinks".into(),
                }],
            });
        }

        static PROTO_XSS_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let proto_xss_re = PROTO_XSS_RE.get_or_init(|| Regex::new(r"(?is)(?:__proto__|constructor\s*\[\s*['\x22]?prototype['\x22]?\s*\])\s*(?:\.|\[\s*['\x22]?)(?:innerHTML|src|onload|onerror|on[a-z]+)['\x22]?\s*\]?").unwrap());
        if let Some(m) = proto_xss_re.find(input) {
            detections.push(L2Detection {
                detection_type: "proto_pollution_xss".into(),
                confidence: 0.87,
                detail: "Prototype pollution used to overwrite dangerous DOM properties".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input attempts to pollute prototype properties to achieve XSS"
                        .into(),
                    offset: m.start(),
                    property:
                        "User input must not be allowed to assign values to prototype properties"
                            .into(),
                }],
            });
        }

        static DOM_XSS_STORAGE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|new\s+Function|location\.(?:href|replace|assign)|window\.open)\s*(?:=|\.call\s*\(|\.apply\s*\(|\()\s*(?:localStorage|sessionStorage)(?:\.getItem|\[[^\]]*\]|\.[a-zA-Z_$][\w$]*)").unwrap()
        });
        if let Some(m) = DOM_XSS_STORAGE_RE.find(input) {
            detections.push(L2Detection {
                detection_type: "dom_xss_storage_sink".into(),
                confidence: 0.88,
                detail: "DOM XSS via storage sink".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "localStorage/sessionStorage data passed directly to a dangerous DOM sink (innerHTML, eval, document.write) creates a persistent DOM XSS vulnerability — attacker stores payload once, victim executes it on every page load".into(),
                    offset: m.start(),
                    property: "Data retrieved from localStorage/sessionStorage must be sanitized before being assigned to dangerous DOM sinks".into(),
                }],
            });
        }

        static DOM_XSS_WINDOW_NAME_BRACKET_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)(?:innerHTML|outerHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|new\s+Function)\s*(?:=\s*[\(\[]|\.call\s*\(|\.apply\s*\(|\()\s*(?:window|self|top|parent)\s*[\[\(]\s*[\x22\x27]?(?:name|hash)[\x22\x27]?\s*[\]\)]").unwrap()
        });
        if let Some(m) = DOM_XSS_WINDOW_NAME_BRACKET_RE.find(input) {
            detections.push(L2Detection {
                detection_type: "dom_xss_window_name_bracket".into(),
                confidence: 0.85,
                detail: "DOM XSS via window.name bracket notation".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Bracket notation window[\"name\"] or self[\"name\"] accessing attacker-controlled window properties and passing them to dangerous sinks creates DOM XSS, bypassing dot-notation detection".into(),
                    offset: m.start(),
                    property: "window.name and window[\"name\"] must both be treated as untrusted sources and must not be passed to dangerous DOM sinks".into(),
                }],
            });
        }

        static SVG_ANIMATE_JS_TO_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)<(?:animate|set|animatemotion|animatetransform)\b[^>]*\b(?:to|values|from)\s*=\s*[\x22\x27]?[^>]*?(?:javascript\s*:|data\s*:\s*text\s*/\s*html)").unwrap()
        });
        if let Some(m) = SVG_ANIMATE_JS_TO_RE.find(input) {
            detections.push(L2Detection {
                detection_type: "xss_svg_animate_js_to".into(),
                confidence: 0.87,
                detail: "SVG animate/set with javascript: in to= attribute".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "SVG animate/set elements with javascript: or data:text/html in their to/values/from attributes can redirect attribute values to executable JavaScript when the animation completes".into(),
                    offset: m.start(),
                    property: "SVG animate element to/values/from attributes must not contain javascript: or data: URI schemes".into(),
                }],
            });
        }

        static MUTATION_XSS_SPECIAL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)<(?:noscript|xmp|plaintext)\b[^>]*>[^<]*(?:<[^>]+title\s*=)?[^<]*(?:<script\b|javascript\s*:|on\w+\s*=)").unwrap()
        });
        if let Some(m) = MUTATION_XSS_SPECIAL_RE.find(input) {
            detections.push(L2Detection {
                detection_type: "mutation_xss_special_elements".into(),
                confidence: 0.86,
                detail: "Mutation XSS via noscript/xmp/plaintext elements".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "noscript, xmp, and plaintext elements cause different parser behaviors depending on scripting context. In scripting-disabled contexts, noscript children are parsed as HTML, enabling filter bypass when the sanitizer differs from the parser context used at execution time".into(),
                    offset: m.start(),
                    property: "noscript/xmp/plaintext elements must be rejected from user input as they create parser-context-dependent XSS vectors".into(),
                }],
            });
        }

        static IFRAME_SRCDOC_ENTITY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)<iframe\b[^>]*\bsrcdoc\s*=\s*[\x22\x27][^>]*&(?:#x3[cC]|#60|lt|#x2[fF]|#47|gt|#x27|#39|apos|#x22|#34|quot|amp|#38);").unwrap()
        });
        if let Some(m) = IFRAME_SRCDOC_ENTITY_RE.find(input) {
            detections.push(L2Detection {
                detection_type: "xss_srcdoc_entity_encoded".into(),
                confidence: 0.89,
                detail: "iframe srcdoc with entity-encoded XSS".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "iframe srcdoc attribute with HTML entity-encoded content is parsed and executed by the browser but may bypass server-side filters that scan for literal < > characters. The browser decodes entities before parsing the srcdoc content".into(),
                    offset: m.start(),
                    property: "iframe srcdoc content must be fully sanitized. HTML entities must be decoded before scanning for dangerous patterns".into(),
                }],
            });
        }

        static CSS_EXPRESSION_OBFUSCATED_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)(?:\\[0-9a-fA-F]{1,6}\s?){4,}|expression\s*/\*[\s\S]*?\*/\s*\(").unwrap()
        });
        if let Some(m) = CSS_EXPRESSION_OBFUSCATED_RE.find(input) {
            detections.push(L2Detection {
                detection_type: "css_expression_obfuscated".into(),
                confidence: 0.86,
                detail: "CSS expression() with hex/octal escape obfuscation".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "CSS hex escape sequences (\\41 = A) and comments inside expression() calls bypass keyword-based filters while remaining executable by IE and legacy browsers. Four or more sequential CSS hex escapes typically reconstruct dangerous property names".into(),
                    offset: m.start(),
                    property: "CSS content must be normalized by decoding hex escapes and removing comments before scanning for expression() or dangerous property names".into(),
                }],
            });
        }

        detections
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "tag_injection" => Some(InvariantClass::XssTagInjection),
            "dom_clobber" => Some(InvariantClass::XssTagInjection),
            "event_handler" => Some(InvariantClass::XssEventHandler),
            "protocol_handler" => Some(InvariantClass::XssProtocolHandler),
            "template_expression" => Some(InvariantClass::XssTemplateExpression),
            "attribute_escape" => Some(InvariantClass::XssAttributeEscape),
            "dom_xss" => Some(InvariantClass::XssTagInjection),
            "proto_pollution_xss" => Some(InvariantClass::XssTagInjection),
            "dom_xss_storage_sink"
            | "dom_xss_sink"
            | "svg_namespace_xss"
            | "polyglot_xss"
            | "csp_bypass_xss"
            | "dom_xss_window_name_bracket"
            | "xss_svg_animate_js_to"
            | "xss_svg_animate_onbegin"
            | "mutation_xss_special_elements"
            | "xss_srcdoc_entity_encoded"
            | "css_expression_obfuscated"
            | "css_expression_split_keyword" => Some(InvariantClass::XssTagInjection),
            "template_literal_js" => Some(InvariantClass::XssTemplateExpression),
            _ => None,
        }
    }
}

pub fn detect_dom_xss(input: &str) -> f64 {
    let mut max_score: f64 = 0.0;
    static RE_DOC_WRITE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re_doc_write = RE_DOC_WRITE.get_or_init(|| {
        Regex::new(r"(?is)document\.write\s*\(\s*location\.(?:search|hash|href)\s*\)").unwrap()
    });

    static RE_INNERHTML: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re_innerhtml =
        RE_INNERHTML.get_or_init(|| Regex::new(r"(?is)innerHTML\s*=\s*location\b").unwrap());

    static RE_EVAL: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re_eval = RE_EVAL.get_or_init(|| {
        Regex::new(r"(?is)eval\s*\(\s*(?:window\.name|location\.hash)\s*\)").unwrap()
    });

    static RE_LOCATION_JS: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re_location_js = RE_LOCATION_JS
        .get_or_init(|| Regex::new(r"(?is)window\.location\s*=\s*['\x22]javascript:").unwrap());

    static RE_POSTMESSAGE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re_postmessage = RE_POSTMESSAGE.get_or_init(|| {
        Regex::new(r"(?is)addEventListener\s*\(\s*[\x27\x22]message[\x27\x22].*?\.data\b").unwrap()
    });

    if re_doc_write.is_match(input) {
        max_score = max_score.max(0.90);
    }
    if re_innerhtml.is_match(input) {
        max_score = max_score.max(0.90);
    }
    if re_eval.is_match(input) {
        max_score = max_score.max(0.95);
    }
    if re_location_js.is_match(input) {
        max_score = max_score.max(0.95);
    }
    if re_postmessage.is_match(input) && !input.to_lowercase().contains("origin") {
        max_score = max_score.max(0.75);
    }

    max_score
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_type(dets: &[L2Detection], detection_type: &str) -> bool {
        dets.iter().any(|d| d.detection_type == detection_type)
    }

    fn has_any(dets: &[L2Detection], classes: &[&str]) -> bool {
        dets.iter()
            .any(|d| classes.iter().any(|c| d.detection_type == *c))
    }

    #[test]
    fn script_tag() {
        let eval = XssEvaluator;
        let dets = eval.detect("<script>alert(1)</script>");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn event_handler() {
        let eval = XssEvaluator;
        let dets = eval.detect("<img src=x onerror=alert(1)>");
        assert!(has_any(&dets, &["event_handler", "tag_injection"]));
    }

    #[test]
    fn detect_dom_xss_positive() {
        let eval = XssEvaluator;
        let dets = eval.detect("document.write(location.hash)");
        assert!(has_type(&dets, "dom_xss"));
    }

    #[test]
    fn detect_dom_xss_negative() {
        let eval = XssEvaluator;
        let dets = eval.detect("document.write('Hello World')");
        assert!(!has_type(&dets, "dom_xss"));
    }

    #[test]
    fn detect_proto_pollution_xss_positive() {
        let eval = XssEvaluator;
        let dets = eval.detect("__proto__[innerHTML]='<img src=x onerror=alert(1)>'");
        assert!(has_type(&dets, "proto_pollution_xss"));
    }

    #[test]
    fn detect_proto_pollution_xss_negative() {
        let eval = XssEvaluator;
        let dets = eval.detect("let obj = { innerHTML: 'test' };");
        assert!(!has_type(&dets, "proto_pollution_xss"));
    }

    #[test]
    fn javascript_scheme() {
        let eval = XssEvaluator;
        let dets = eval.detect("<a href=\"javascript:alert(1)\">click</a>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn javascript_scheme_tab_obfuscation() {
        let eval = XssEvaluator;
        let dets = eval.detect("<a href=\"java\tscript:alert(1)\">click</a>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn javascript_scheme_null_byte_obfuscation() {
        let eval = XssEvaluator;
        let dets = eval.detect("<a href=\"java\x00script:alert(1)\">click</a>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn javascript_scheme_entity_obfuscation() {
        let eval = XssEvaluator;
        let dets = eval.detect("<a href=\"&#106;avascript:alert(1)\">click</a>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn javascript_scheme_hex_entities() {
        let eval = XssEvaluator;
        let dets = eval.detect("<a href=\"&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)\">x</a>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn javascript_scheme_decimal_entities() {
        let eval = XssEvaluator;
        let dets = eval.detect("<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)\">x</a>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn bare_javascript_scheme() {
        let eval = XssEvaluator;
        let dets = eval.detect("javascript:alert(document.cookie)");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn unicode_escape_in_event_handler() {
        let eval = XssEvaluator;
        let dets = eval.detect("<img src=x onerror=\"\\u0061lert(1)\">");
        assert!(has_any(&dets, &["event_handler", "tag_injection"]));
    }

    #[test]
    fn polyglot_javascript_protocol() {
        let eval = XssEvaluator;
        let dets = eval.detect("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn data_uri_iframe_html() {
        let eval = XssEvaluator;
        let dets = eval.detect("<iframe src='data:text/html,<script>alert(1)</script>'></iframe>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn iframe_srcdoc_xss() {
        let eval = XssEvaluator;
        let dets =
            eval.detect("<iframe srcdoc=\"<img src=x onerror=alert(1)>\"></iframe>");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn meta_refresh_data_uri_xss() {
        let eval = XssEvaluator;
        let dets = eval.detect(
            "<meta http-equiv=\"refresh\" content=\"0;url=data:text/html,<script>alert(1)</script>\">",
        );
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn base_href_javascript_xss() {
        let eval = XssEvaluator;
        let dets = eval.detect("<base href=javascript:alert(1)//>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn form_action_javascript_xss() {
        let eval = XssEvaluator;
        let dets = eval.detect("<form action=javascript:alert(1)><input type=submit></form>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn data_uri_html_base64() {
        let eval = XssEvaluator;
        let dets = eval
            .detect("<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>");
        assert!(has_type(&dets, "protocol_handler"));
    }

    #[test]
    fn svg_onload() {
        let eval = XssEvaluator;
        let dets = eval.detect("<svg onload=alert(1)>");
        assert!(has_any(&dets, &["event_handler", "tag_injection"]));
    }

    #[test]
    fn svg_animate_onbegin() {
        let eval = XssEvaluator;
        let dets = eval.detect("<svg><animate onbegin=alert(1) attributeName=x></svg>");
        assert!(has_type(&dets, "xss_svg_animate_onbegin"));
    }

    #[test]
    fn svg_set_onload_attr_name() {
        let eval = XssEvaluator;
        let dets =
            eval.detect("<svg><set attributeName='onload' to='javascript:alert(1)' /></svg>");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn svg_foreign_object_iframe() {
        let eval = XssEvaluator;
        let dets = eval.detect(
            "<svg><foreignObject><iframe src='javascript:alert(1)'></iframe></foreignObject></svg>",
        );
        assert!(has_any(&dets, &["tag_injection", "protocol_handler"]));
    }

    #[test]
    fn svg_foreign_object_body_onload() {
        let eval = XssEvaluator;
        let dets = eval
            .detect("<svg><foreignobject><body onload='alert(1)'></body></foreignobject></svg>");
        assert!(has_type(&dets, "event_handler"));
    }

    #[test]
    fn mutation_xss_math_payload() {
        let eval = XssEvaluator;
        let dets = eval
            .detect("<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn mutation_xss_style_comment_chain() {
        let eval = XssEvaluator;
        let dets = eval.detect("<math><mtext><table><mglyph><style><![CDATA[--></style><img onerror=alert(1) src=x></math>");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn dom_clobber_form_input_chain() {
        let eval = XssEvaluator;
        let dets = eval.detect("<form id=x><input name=y></form>");
        assert!(has_type(&dets, "dom_clobber"));
    }

    #[test]
    fn dom_clobber_named_anchor_javascript_href() {
        let eval = XssEvaluator;
        let dets = eval.detect("<a id=toString href=javascript:alert(1)>");
        assert!(has_any(&dets, &["dom_clobber", "protocol_handler"]));
    }

    #[test]
    fn dom_clobber_input_named_form() {
        let eval = XssEvaluator;
        let dets = eval.detect("<form id=document><input name=document></form>");
        assert!(has_any(
            &dets,
            &["dom_clobber", "tag_injection", "event_handler"]
        ));
    }

    #[test]
    fn template_expression_backticks() {
        let eval = XssEvaluator;
        let dets = eval.detect("`hello ${alert(1)}`");
        assert!(has_type(&dets, "template_expression"));
    }

    #[test]
    fn template_literal_alert_expression() {
        let eval = XssEvaluator;
        let dets = eval.detect("${alert(1)}");
        assert!(has_type(&dets, "template_literal_js"));
    }

    #[test]
    fn template_expression_mustache() {
        let eval = XssEvaluator;
        let dets = eval.detect("{{constructor.constructor('alert(1)')()}}");
        assert!(has_type(&dets, "template_expression"));
    }

    #[test]
    fn css_expression_payload() {
        let eval = XssEvaluator;
        let dets = eval.detect("<div style=\"width: expression(alert(1))\">");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn css_ms_expression_payload() {
        let eval = XssEvaluator;
        let dets = eval.detect("<div style=\"-ms-expression:alert(1)\"> ");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn css_behavior_url_payload() {
        let eval = XssEvaluator;
        let dets = eval.detect("<div style=\"behavior:url(#default#time2)\">");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn css_moz_binding_payload() {
        let eval = XssEvaluator;
        let dets = eval.detect("<style>body{-moz-binding:url(http://xss.xml#xss)}</style>");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn css_javascript_url_payload() {
        let eval = XssEvaluator;
        let dets = eval.detect("<style>body{background:url(javascript:alert(1))}</style>");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn css_legacy_expression_injection() {
        let eval = XssEvaluator;
        let dets = eval.detect("<div style=\"left:expression(alert(1));behavior:url(x)\">");
        assert!(has_type(&dets, "tag_injection"));
    }

    #[test]
    fn attribute_escape() {
        let eval = XssEvaluator;
        let dets = eval.detect("\" onfocus=alert(1) autofocus x=\"");
        assert!(has_type(&dets, "attribute_escape"));
    }

    #[test]
    fn svg_nested_mutation_polyglot() {
        let eval = XssEvaluator;
        let dets = eval.detect("<math><mtext><table><mglyph><style><!--</style><img src=javascript:alert(1) onerror=\"\" ></math>\n<svg><set attributeName='onload' to=javascript:alert(1)>");
        assert!(has_any(
            &dets,
            &["tag_injection", "dom_clobber", "template_expression"]
        ));
    }

    #[test]
    fn data_uri_svg_polyglot() {
        let eval = XssEvaluator;
        let dets = eval.detect("<iframe src='data:image/svg+xml,<svg onload=alert(1)>'></iframe>");
        assert!(has_any(
            &dets,
            &["protocol_handler", "tag_injection", "event_handler"]
        ));
    }

    #[test]
    fn benign_html() {
        let eval = XssEvaluator;
        let dets = eval.detect("<p>Hello world</p><a href=\"/status\">status</a>");
        assert!(
            dets.is_empty(),
            "Normal HTML should not trigger XSS detection"
        );
    }

    #[test]
    fn benign_style_no_exec() {
        let eval = XssEvaluator;
        let dets = eval.detect("<div style=\"color:red;background:#fff;width:100%\">safe</div>");
        assert!(dets.is_empty());
    }

    #[test]
    fn benign_template_text() {
        let eval = XssEvaluator;
        let dets = eval.detect("<pre>`${not-a-payload}`</pre>");
        assert!(dets.is_empty());
    }

    #[test]
    fn test_dom_xss_storage_sink() {
        let eval = XssEvaluator;
        let dets = eval.detect("element.innerHTML = localStorage.getItem(\"payload\")");
        assert!(has_type(&dets, "dom_xss_storage_sink"));
    }

    #[test]
    fn test_dom_xss_window_name_bracket() {
        let eval = XssEvaluator;
        let dets = eval.detect("eval(window[\"name\"])");
        assert!(has_type(&dets, "dom_xss_window_name_bracket"));
    }

    #[test]
    fn test_svg_animate_js_to() {
        let eval = XssEvaluator;
        let dets = eval.detect("<animate to=\"javascript:alert(1)\" />");
        assert!(has_type(&dets, "xss_svg_animate_js_to"));
    }

    #[test]
    fn test_mutation_xss_noscript() {
        let eval = XssEvaluator;
        let dets = eval.detect("<noscript><p title=\"--!><script>alert(1)</script>\"></noscript>");
        assert!(has_type(&dets, "mutation_xss_special_elements"));
    }

    #[test]
    fn test_srcdoc_entity() {
        let eval = XssEvaluator;
        let dets = eval.detect("<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\"></iframe>");
        assert!(has_type(&dets, "xss_srcdoc_entity_encoded"));
    }

    #[test]
    fn test_css_expression_obfuscated() {
        let eval = XssEvaluator;
        let dets = eval.detect("expression/*comment*/(alert(1))");
        assert!(has_type(&dets, "css_expression_obfuscated"));
    }

    #[test]
    fn test_css_expression_split_keyword() {
        let eval = XssEvaluator;
        let dets = eval.detect(r#"<div style="color:expr/**/ession(alert(1))">"#);
        assert!(has_type(&dets, "css_expression_split_keyword"));
    }

    #[test]
    fn test_dom_xss_sinks_new_detector() {
        let eval = XssEvaluator;
        let dets = eval.detect("setTimeout(\"alert(1)\", 0)");
        assert!(has_type(&dets, "dom_xss_sink"));
    }

    #[test]
    fn test_svg_namespace_xss_detector() {
        let eval = XssEvaluator;
        let dets = eval.detect("<math><mtext></form><form><mglyph><svg onload=alert(1)>");
        assert!(has_type(&dets, "svg_namespace_xss"));
    }

    #[test]
    fn test_polyglot_xss_detector() {
        let eval = XssEvaluator;
        let dets = eval.detect("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e");
        assert!(has_type(&dets, "polyglot_xss"));
    }

    #[test]
    fn test_csp_bypass_xss_detector() {
        let eval = XssEvaluator;
        let dets = eval.detect("/api?callback=alert(1)");
        assert!(has_type(&dets, "csp_bypass_xss"));
    }
}
