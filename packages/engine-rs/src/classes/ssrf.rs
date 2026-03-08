use regex::Regex;
use std::sync::LazyLock;

use crate::classes::{ClassDefinition, decode};
use crate::types::InvariantClass;

static INTERNAL_REACH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:https?://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0x7f|2130706433|017700000001|\[::1?\]|0177\.0\.0\.01)").unwrap());
static CLOUD_METADATA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|metadata\.azure\.com").unwrap());
static PROTOCOL_SMUGGLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:file|gopher|dict|ldap|tftp|ftp|jar|netdoc|phar)://").unwrap());

fn ssrf_internal_reach(input: &str) -> bool {
    INTERNAL_REACH.is_match(&decode(input))
}
fn ssrf_cloud_metadata(input: &str) -> bool {
    CLOUD_METADATA.is_match(&decode(input))
}
fn ssrf_protocol_smuggle(input: &str) -> bool {
    PROTOCOL_SMUGGLE.is_match(&decode(input))
}

pub const SSRF_CLASSES: &[ClassDefinition] = &[
    ClassDefinition {
        id: InvariantClass::SsrfInternalReach,
        description: "Reach internal network addresses through server-side request",
        detect: ssrf_internal_reach,
        known_payloads: &["http://127.0.0.1", "http://localhost", "http://10.0.0.1", "http://192.168.1.1", "http://[::1]", "http://0x7f000001"],
        known_benign: &["http://example.com", "https://google.com", "http://api.github.com"],
        mitre: &["T1090", "T1018"],
        cwe: Some("CWE-918"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::SsrfCloudMetadata,
        description: "Access cloud provider metadata endpoints to steal credentials/tokens",
        detect: ssrf_cloud_metadata,
        known_payloads: &["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/", "http://100.100.100.200/latest/meta-data/"],
        known_benign: &["http://example.com/metadata", "169.254.0.1", "google internal docs"],
        mitre: &["T1552.005"],
        cwe: Some("CWE-918"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::SsrfProtocolSmuggle,
        description: "Use non-HTTP protocol handlers (file://, gopher://) to access internal resources",
        detect: ssrf_protocol_smuggle,
        known_payloads: &["file:///etc/passwd", "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall", "dict://127.0.0.1:6379/INFO", "phar:///tmp/evil.phar"],
        known_benign: &["https://example.com", "http://api.service.com", "ftp.example.com", "file attached"],
        mitre: &["T1090"],
        cwe: Some("CWE-918"),
        formal_property: None,
        composable_with: &[],
    },
];
