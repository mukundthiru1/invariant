use regex::Regex;
use std::sync::LazyLock;

use crate::classes::{ClassDefinition, decode};
use crate::types::InvariantClass;

static TAG_INJECTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<\s*(?:script|iframe|object|embed|applet|form|meta|link|style|base|svg|math|video|audio|source|details|marquee|isindex|frameset|frame|body|img|input|button|textarea|select|keygen)\b[^>]*>").unwrap());
static ATTRIBUTE_ESCAPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)['"][\s/]*(?:>|on\w+\s*=|style\s*=|xmlns\s*=|src\s*=|href\s*=|action\s*=|formaction\s*=)"#).unwrap());
static EVENT_HANDLER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bon(?:error|load|click|mouseover|mouseout|mousedown|mouseup|focus|blur|change|submit|reset|select|abort|unload|resize|scroll|keydown|keypress|keyup|dblclick|drag|drop|input|invalid|toggle|animationend|copy|cut|paste|search|wheel|contextmenu|auxclick)\s*=\s*[^\s>]").unwrap());
static PROTOCOL_HANDLER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:javascript|vbscript|livescript)\s*:|data\s*:\s*(?:text/html|application/xhtml)").unwrap());
static TEMPLATE_EXPR_1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\{\{.*(?:constructor|__proto__|prototype|\$on|\$emit|\$eval|alert|prompt|confirm|document|window|globalThis|Function).*\}\}").unwrap());
static TEMPLATE_EXPR_2: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\$\{.*(?:alert|document|window|constructor|eval|Function)\s*\(.*\}\s*").unwrap());

fn xss_tag_injection(input: &str) -> bool {
    TAG_INJECTION.is_match(&decode(input))
}
fn xss_attribute_escape(input: &str) -> bool {
    ATTRIBUTE_ESCAPE.is_match(&decode(input))
}
fn xss_event_handler(input: &str) -> bool {
    EVENT_HANDLER.is_match(&decode(input))
}
fn xss_protocol_handler(input: &str) -> bool {
    PROTOCOL_HANDLER.is_match(&decode(input))
}
fn xss_template_expression(input: &str) -> bool {
    let d = decode(input);
    TEMPLATE_EXPR_1.is_match(&d) || TEMPLATE_EXPR_2.is_match(&d)
}

pub const XSS_CLASSES: &[ClassDefinition] = &[
    ClassDefinition {
        id: InvariantClass::XssTagInjection,
        description: "Inject new HTML elements to execute arbitrary JavaScript",
        detect: xss_tag_injection,
        known_payloads: &[
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
        ],
        known_benign: &["<div>hello world</div>", "<p>paragraph text</p>", "<br/>", "use <code> for code blocks", "3 < 5 and 5 > 3"],
        mitre: &["T1059.007"],
        cwe: Some("CWE-79"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::XssEventHandler,
        description: "Inject event handler attributes (onerror, onload, etc.) to execute JavaScript",
        detect: xss_event_handler,
        known_payloads: &["\" onerror=\"alert(1)", "' onmouseover='alert(1)", "\" onfocus=\"alert(1)\" autofocus=\"", "\" onload=\"alert(1)"],
        known_benign: &["onerror callback function", "handle the onload event", "set onfocus to true", "when onmouseover fires"],
        mitre: &["T1059.007"],
        cwe: Some("CWE-79"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::XssProtocolHandler,
        description: "javascript:, vbscript:, or data: URI protocol handlers to execute script",
        detect: xss_protocol_handler,
        known_payloads: &[
            "javascript:alert(1)",
            "vbscript:MsgBox(\"XSS\")",
            "data:text/html,<script>alert(1)</script>",
            "javascript:void(0)",
            "JaVaScRiPt:alert(1)",
        ],
        known_benign: &["https://javascript.com", "the javascript language", "learning javascript basics", "data science course"],
        mitre: &["T1059.007"],
        cwe: Some("CWE-79"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::XssTemplateExpression,
        description: "Client-side template expression injection (Angular, Vue, etc.) or DOM-based template literals",
        detect: xss_template_expression,
        known_payloads: &[
            "{{constructor.constructor(\"alert(1)\")()}}",
            "${alert(1)}",
            "{{$on.constructor(\"alert(1)\")()}}",
        ],
        known_benign: &["price is {{product.price}}", "hello {{user.name}}", "the result is ${result}", "template {{variable}}"],
        mitre: &["T1059.007"],
        cwe: Some("CWE-79"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::XssAttributeEscape,
        description: "Break out of HTML attribute context to inject new attributes or elements",
        detect: xss_attribute_escape,
        known_payloads: &["\" onmouseover=\"alert(1)\" x=\"", "' onfocus='alert(1)' autofocus='", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>"],
        known_benign: &["class=\"active\"", "data-value=\"123\"", "it's a 'quoted' string", "she said \"hello\""],
        mitre: &["T1059.007"],
        cwe: Some("CWE-79"),
        formal_property: None,
        composable_with: &[],
    },
];
