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
            _ => None,
        }
    }
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
        let dets = eval.detect(
            "<svg><animate onbegin=alert(1) attributeName='visibility' from='hidden'></svg>",
        );
        assert!(has_type(&dets, "event_handler"));
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
}
