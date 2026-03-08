use regex::Regex;
use std::sync::LazyLock;

use crate::classes::{ClassDefinition, decode};
use crate::types::InvariantClass;

static AUTH_NONE_JSON: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""alg"\s*:\s*"none""#).unwrap());
static AUTH_NONE_B64: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)eyJhbGciOiJub25l").unwrap());
static HEADER_SPOOF_CUSTOM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)x-[a-z-]*(?:ip|authorization)[a-z-]*:\s*(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|localhost)").unwrap());

static JWT_CTX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\beyJ[A-Za-z0-9_-]{10,}\.|\b(?:jwt|bearer|authorization|token)\b|\{"(?:alg|typ|kid|jwk|jku|x5[cu])""#).unwrap());
static JWT_KID_MATCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""kid"\s*:\s*"((?:[^"\\]|\\.)*)""#).unwrap());
static JWT_KID_SQL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:union\s+select|'\s*(?:or|and)\s+|;\s*(?:drop|select|insert)|--\s*$)").unwrap());
static JWT_KID_CMD_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:cat|curl|wget|bash|sh|id|whoami)\b").unwrap());

fn auth_none_algorithm(input: &str) -> bool {
    let d = decode(input);
    AUTH_NONE_JSON.is_match(&d) || AUTH_NONE_B64.is_match(input)
}

fn auth_header_spoof(input: &str) -> bool {
    let i = input.to_ascii_lowercase();
    if i.contains("x-forwarded-for:") || i.contains("x-original-url:") || i.contains("x-rewrite-url:") {
        return true;
    }
    if i.contains("x-real-ip:") || i.contains("x-client-ip:") || i.contains("x-cluster-client-ip:") {
        return true;
    }
    HEADER_SPOOF_CUSTOM.is_match(input)
}

fn cors_origin_abuse(input: &str) -> bool {
    let d = decode(input);
    Regex::new(r"Origin\s*:\s*https?://evil\.com").unwrap().is_match(&d)
        || Regex::new(r"Origin\s*:\s*null").unwrap().is_match(&d)
        || Regex::new(r"Origin\s*:\s*https?://[^.\s]+\.[^.\s]+\.[^.\s]+\.[^.\s]+").unwrap().is_match(&d)
        || Regex::new(r"Origin\s*:.*(?:%60|%00|%0[dD]|%0[aA])").unwrap().is_match(&d)
}

fn jwt_kid_injection(input: &str) -> bool {
    let d = decode(input);
    if !JWT_CTX.is_match(&d) {
        return false;
    }
    let Some(c) = JWT_KID_MATCH.captures(&d) else {
        return false;
    };
    let kid = c.get(1).map(|m| m.as_str()).unwrap_or_default();
    if Regex::new(r"\.\.[\\/]").unwrap().is_match(kid) {
        return true;
    }
    if JWT_KID_SQL.is_match(kid) {
        return true;
    }
    if Regex::new(r"[|;`$]").unwrap().is_match(kid) && JWT_KID_CMD_WORD.is_match(kid) {
        return true;
    }
    Regex::new(r"\\x00|%00|\x00").unwrap().is_match(kid)
}

fn jwt_jwk_embedding(input: &str) -> bool {
    let d = decode(input);
    if !JWT_CTX.is_match(&d) {
        return false;
    }
    (Regex::new(r#""jwk"\s*:\s*\{"#).unwrap().is_match(&d)
        && Regex::new(r#""kty"\s*:\s*""#).unwrap().is_match(&d)
        && Regex::new(r#""alg"\s*:\s*""#).unwrap().is_match(&d))
        || (Regex::new(r#""jku"\s*:\s*"https?://"#).unwrap().is_match(&d)
            && Regex::new(r#""alg"\s*:\s*""#).unwrap().is_match(&d))
        || (Regex::new(r#""x5u"\s*:\s*"https?://"#).unwrap().is_match(&d)
            && Regex::new(r#""alg"\s*:\s*""#).unwrap().is_match(&d))
}

fn jwt_confusion(input: &str) -> bool {
    let d = decode(input);
    if !JWT_CTX.is_match(&d) {
        return false;
    }
    let hmac_alg = Regex::new(r#""alg"\s*:\s*"HS(?:256|384|512)""#).unwrap().is_match(&d);
    if !hmac_alg {
        return false;
    }
    Regex::new(r#"(?i)"kid"\s*:\s*"[^"]*(?:rsa|public|pub[_-]?key|asymmetric)""#).unwrap().is_match(&d)
        || Regex::new(r"(?i)(?:rsa\s+)?public\s+key\s+(?:as|for|used\s+as)\s+(?:hmac|secret|symmetric)").unwrap().is_match(&d)
        || Regex::new(r"(?i)-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY-----").unwrap().is_match(&d)
}

pub const AUTH_CLASSES: &[ClassDefinition] = &[
    ClassDefinition {
        id: InvariantClass::AuthNoneAlgorithm,
        description: "JWT alg:none attack to bypass signature verification entirely",
        detect: auth_none_algorithm,
        known_payloads: &["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."],
        known_benign: &[
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "not.a.jwt.token",
            "hello world",
        ],
        mitre: &["T1550.001"],
        cwe: Some("CWE-347"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::AuthHeaderSpoof,
        description: "Spoof proxy/forwarding headers to bypass IP-based access controls",
        detect: auth_header_spoof,
        known_payloads: &[
            "X-Forwarded-For: 127.0.0.1",
            "X-Original-URL: /admin",
            "X-Rewrite-URL: /admin",
            "X-Custom-IP-Authorization: 127.0.0.1",
            "X-Real-IP: 127.0.0.1",
            "X-Client-IP: 10.0.0.1",
        ],
        known_benign: &["normal header value", "192.168.1.1", "/api/users"],
        mitre: &["T1090"],
        cwe: Some("CWE-290"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::CorsOriginAbuse,
        description: "CORS origin abuse — crafted Origin headers to steal data cross-origin from misconfigured APIs",
        detect: cors_origin_abuse,
        known_payloads: &["Origin: https://evil.com", "Origin: null", "Origin: https://target.com.evil.com", "Origin: https://target.com%60.evil.com"],
        known_benign: &["Origin: https://example.com", "origin story", "the origin of species", "https://api.internal.com"],
        mitre: &["T1557"],
        cwe: Some("CWE-346"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::JwtKidInjection,
        description: "JWT Key ID (kid) header injection — SQLi or path traversal via the kid claim to retrieve attacker-controlled signing key",
        detect: jwt_kid_injection,
        known_payloads: &[
            "{\"alg\":\"HS256\",\"kid\":\"../../dev/null\"}",
            "{\"alg\":\"HS256\",\"kid\":\"' UNION SELECT 'secret' --\"}",
            "{\"alg\":\"HS256\",\"kid\":\"| cat /etc/passwd\"}",
        ],
        known_benign: &[
            "{\"alg\":\"RS256\",\"kid\":\"2024-key-rotation-01\"}",
            "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"prod-key-id\"}",
            "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.test.test",
        ],
        mitre: &["T1550.001"],
        cwe: Some("CWE-347"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::JwtJwkEmbedding,
        description: "JWT self-signed key injection — attacker embeds their own JWK or JKU in the token header to forge signatures",
        detect: jwt_jwk_embedding,
        known_payloads: &[
            "{\"alg\":\"RS256\",\"jwk\":{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQ\",\"e\":\"AQAB\"}}",
            "{\"alg\":\"RS256\",\"jku\":\"https://evil.example/.well-known/jwks.json\"}",
            "{\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83O\",\"y\":\"x_FE\"}}",
        ],
        known_benign: &[
            "{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
            "{\"alg\":\"ES256\",\"kid\":\"prod-key-01\"}",
            "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1\"}]}",
        ],
        mitre: &["T1550.001"],
        cwe: Some("CWE-347"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::JwtConfusion,
        description: "JWT algorithm confusion — switching from asymmetric (RS/ES/PS) to symmetric (HS) to sign with the public key",
        detect: jwt_confusion,
        known_payloads: &[
            "{\"alg\":\"HS256\",\"typ\":\"JWT\"} RSA public key as HMAC secret",
            "{\"alg\":\"HS384\",\"typ\":\"JWT\",\"kid\":\"rsa-pub-key\"}",
            "{\"alg\":\"HS512\"} -----BEGIN PUBLIC KEY-----",
        ],
        known_benign: &["{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"alg\":\"RS256\",\"typ\":\"JWT\"}", "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"],
        mitre: &["T1550.001"],
        cwe: Some("CWE-327"),
        formal_property: None,
        composable_with: &[],
    },
];
