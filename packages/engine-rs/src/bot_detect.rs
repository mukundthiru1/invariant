use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotClassification {
    Legitimate,
    Malicious,
    Automated,
    ScriptKiddie,
    Unknown,
    Human,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BotClassificationResult {
    pub classification: BotClassification,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3Fingerprint {
    pub hash: String,
    pub raw_string: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HeaderProfile {
    pub missing_expected_headers: Vec<String>,
    pub order_anomaly: bool,
    pub known_bot_user_agent: Option<String>,
    pub suspicious_user_agent: bool,
    pub connection_anomaly: bool,
    pub header_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestTiming {
    pub intervals_ms: Vec<u64>,
    pub automated: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BotSignals {
    pub user_agent: String,
    pub header_profile: HeaderProfile,
    pub ja3: Option<Ja3Fingerprint>,
    pub known_legitimate_bot: Option<String>,
    pub known_scanner: Option<String>,
    pub known_bot_ja3: Option<String>,
    pub known_browser_ja3: Option<String>,
    pub timing: Option<RequestTiming>,
    pub credential_stuffing: bool,
    pub source_reputation: Option<f64>,
}

pub const LEGITIMATE_BOTS: &[(&str, &[&str])] = &[
    (
        "Googlebot",
        &["googlebot", "google-inspectiontool", "googleother"],
    ),
    ("Bingbot", &["bingbot", "adidxbot"]),
    ("Slurp", &["slurp"]),
    ("DuckDuckBot", &["duckduckbot"]),
    ("Baiduspider", &["baiduspider"]),
    ("YandexBot", &["yandexbot", "yandeximages"]),
    ("facebot", &["facebot", "facebookexternalhit"]),
    ("Twitterbot", &["twitterbot"]),
    ("LinkedInBot", &["linkedinbot"]),
    ("Applebot", &["applebot"]),
    ("AhrefsBot", &["ahrefsbot"]),
    ("SemrushBot", &["semrushbot"]),
    ("MJ12bot", &["mj12bot"]),
    ("PetalBot", &["petalbot"]),
    ("Sogou", &["sogou web spider", "sogou"]),
    ("Exabot", &["exabot"]),
    ("Discordbot", &["discordbot"]),
    ("WhatsApp", &["whatsapp"]),
    ("TelegramBot", &["telegrambot"]),
];

pub const SCANNER_BOTS: &[(&str, &[&str])] = &[
    ("Nmap", &["nmap scripting engine", "nmap"]),
    ("Nikto", &["nikto"]),
    ("sqlmap", &["sqlmap"]),
    ("DirBuster", &["dirbuster"]),
    ("GoBuster", &["gobuster"]),
    ("Wfuzz", &["wfuzz"]),
    ("ffuf", &["ffuf"]),
    ("nuclei", &["nuclei"]),
    ("Acunetix", &["acunetix"]),
    ("Arachni", &["arachni"]),
    ("masscan", &["masscan"]),
    ("WhatWeb", &["whatweb"]),
    ("w3af", &["w3af"]),
    ("ZAP", &["zaproxy", "owasp zap"]),
    ("Burp", &["burp", "burpsuite"]),
    ("Hydra", &["hydra"]),
    ("Medusa", &["medusa"]),
    ("Patator", &["patator"]),
    ("feroxbuster", &["feroxbuster"]),
    ("httpx", &["projectdiscovery", "httpx"]),
    ("naabu", &["naabu"]),
    ("wpscan", &["wpscan"]),
    ("joomscan", &["joomscan"]),
    ("skipfish", &["skipfish"]),
    ("nessus", &["nessus"]),
    ("openvas", &["openvas"]),
    ("qualys", &["qualys"]),
    ("netsparker", &["netsparker"]),
    ("cloudmapper", &["cloudmapper"]),
    ("amass", &["amass"]),
];

const BOT_USER_AGENT_PATTERNS: &[&str] = &[
    "bot",
    "crawler",
    "spider",
    "scrapy",
    "headless",
    "phantomjs",
    "selenium",
    "webdriver",
    "playwright",
    "puppeteer",
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "httpclient",
    "okhttp",
    "go-http-client",
    "libwww-perl",
    "aiohttp",
    "http.rb",
    "mechanize",
    "axios/",
    "restsharp",
    "java/",
    "apache-httpclient",
    "node-fetch",
    "feedfetcher",
    "slurp",
    "baiduspider",
    "duckduckbot",
    "yandex",
    "semrush",
    "ahrefs",
    "mj12bot",
    "dotbot",
    "petalbot",
    "facebookexternalhit",
    "facebot",
    "twitterbot",
    "linkedinbot",
    "slackbot",
    "discordbot",
    "telegrambot",
    "bingbot",
    "googlebot",
    "nmap",
    "nikto",
    "sqlmap",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "ffuf",
    "nuclei",
    "zaproxy",
    "burp",
    "acunetix",
    "arachni",
    "masscan",
    "wpscan",
    "whatweb",
    "nessus",
    "openvas",
];

const KNOWN_BOT_JA3: &[(&str, &[&str])] = &[
    (
        "curl",
        &[
            "771,4865-4866-4867-49195",
            "771,4865-4866-4867-49196",
            "771,49195-49199",
        ],
    ),
    (
        "python-requests",
        &[
            "771,49195-49199-49196-49200",
            "771,49195-49196-49200-159-52393",
        ],
    ),
    (
        "go-http-client",
        &[
            "771,4865-4866-4867-49195-49199",
            "771,49195-49199-49196-49200-52393",
        ],
    ),
    (
        "scrapy/twisted",
        &[
            "771,4865-4866-4867-49196-49195",
            "771,49195-49196-49199-49200",
        ],
    ),
    (
        "java-http",
        &["771,49195-49199-49196-49200-47-53", "771,49195-49199-49196"],
    ),
    (
        "ruby",
        &[
            "771,49195-49199-49196-49200-158-159",
            "771,49195-49196-49200-159-52392",
        ],
    ),
];

const KNOWN_BROWSER_JA3: &[(&str, &[&str])] = &[
    (
        "Chrome",
        &[
            "771,4865-4866-4867-49195-49199-52393",
            "771,4865-4866-4867,0-23-65281-10-11-35",
        ],
    ),
    (
        "Firefox",
        &[
            "771,4865-4867-4866-49195-49199",
            "771,4865-4867-4866,0-11-10-35-16-5-13",
        ],
    ),
    (
        "Safari",
        &[
            "771,4865-4866-4867-49196-49195",
            "771,4865-4866-4867,0-23-65281-10-11-16-5-13",
        ],
    ),
    (
        "Edge",
        &[
            "771,4865-4866-4867-49195-49199-52393",
            "771,4865-4866-4867,0-43-45-51-13-16-5",
        ],
    ),
];

pub fn parse_ja3(raw: &str) -> Ja3Fingerprint {
    let normalized = raw
        .split(',')
        .map(|part| part.trim())
        .collect::<Vec<_>>()
        .join(",");
    let hash = fnv1a_hex(&normalized);
    Ja3Fingerprint {
        hash,
        raw_string: normalized,
    }
}

pub fn analyze_headers(headers: &[(String, String)]) -> HeaderProfile {
    let expected = ["accept", "accept-language", "accept-encoding"];
    let mut seen = std::collections::HashMap::new();
    for (idx, (name, _)) in headers.iter().enumerate() {
        seen.insert(name.to_lowercase(), idx);
    }

    let missing_expected_headers = expected
        .iter()
        .filter(|h| !seen.contains_key(**h))
        .map(|h| h.to_string())
        .collect::<Vec<_>>();

    let order_anomaly = detect_order_anomaly(&seen);
    let user_agent = extract_user_agent(headers).unwrap_or_default();
    let suspicious_user_agent = is_suspicious_user_agent(&user_agent);

    let known_bot_user_agent =
        identify_known_bot_user_agent(&user_agent).or_else(|| is_known_scanner(&user_agent));

    let connection_anomaly = headers.iter().any(|(name, value)| {
        if !name.eq_ignore_ascii_case("connection") {
            return false;
        }
        let v = value.to_lowercase();
        if v.is_empty() {
            return true;
        }
        !matches!(v.as_str(), "keep-alive" | "close")
            && (v.contains("upgrade") || v.contains("proxy") || v.contains(','))
    });

    HeaderProfile {
        missing_expected_headers,
        order_anomaly,
        known_bot_user_agent,
        suspicious_user_agent,
        connection_anomaly,
        header_count: headers.len(),
    }
}

pub fn is_automated_timing(intervals_ms: &[u64]) -> bool {
    if intervals_ms.len() < 3 {
        return false;
    }

    if intervals_ms.iter().all(|v| *v == intervals_ms[0]) {
        return true;
    }

    let mean = intervals_ms.iter().sum::<u64>() as f64 / intervals_ms.len() as f64;
    if mean <= 0.0 {
        return false;
    }

    let variance = intervals_ms
        .iter()
        .map(|value| {
            let d = *value as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / intervals_ms.len() as f64;

    let coeff_var = variance.sqrt() / mean;
    coeff_var < 0.08 && intervals_ms.len() >= 4
}

pub fn is_credential_stuffing(paths: &[String], intervals: &[u64]) -> bool {
    if paths.len() < 6 {
        return false;
    }

    let loginish = paths
        .iter()
        .filter(|p| {
            let lower = p.to_lowercase();
            lower.contains("login")
                || lower.contains("signin")
                || lower.contains("auth")
                || lower.contains("session")
                || lower.contains("token")
        })
        .count();

    if loginish < 5 {
        return false;
    }

    if intervals.is_empty() {
        return true;
    }

    let fast_ratio =
        intervals.iter().filter(|ms| **ms <= 1500).count() as f64 / intervals.len() as f64;
    fast_ratio >= 0.7 || is_automated_timing(intervals)
}

pub fn is_known_scanner(user_agent: &str) -> Option<String> {
    let ua = user_agent.to_lowercase();
    for (name, patterns) in SCANNER_BOTS {
        if patterns.iter().any(|p| ua.contains(&p.to_lowercase())) {
            return Some((*name).to_string());
        }
    }
    None
}

pub fn identify_legitimate_bot(user_agent: &str) -> Option<String> {
    let ua = user_agent.to_lowercase();
    for (name, patterns) in LEGITIMATE_BOTS {
        if patterns.iter().any(|p| ua.contains(&p.to_lowercase())) {
            return Some((*name).to_string());
        }
    }
    None
}

pub fn identify_known_bot_ja3(ja3: &Ja3Fingerprint) -> Option<String> {
    let raw = ja3.raw_string.to_lowercase();
    KNOWN_BOT_JA3
        .iter()
        .find(|(_, patterns)| patterns.iter().any(|p| raw.contains(&p.to_lowercase())))
        .map(|(name, _)| (*name).to_string())
}

pub fn identify_browser_ja3(ja3: &Ja3Fingerprint) -> Option<String> {
    let raw = ja3.raw_string.to_lowercase();
    KNOWN_BROWSER_JA3
        .iter()
        .find(|(_, patterns)| patterns.iter().any(|p| raw.contains(&p.to_lowercase())))
        .map(|(name, _)| (*name).to_string())
}

pub fn compute_bot_score(signals: &BotSignals) -> f64 {
    let mut score = 0.0_f64;

    if signals.known_scanner.is_some() {
        score += 0.75;
    }
    if signals.header_profile.suspicious_user_agent {
        score += 0.22;
    }
    if signals.header_profile.known_bot_user_agent.is_some() {
        score += 0.18;
    }
    score += (signals.header_profile.missing_expected_headers.len() as f64 * 0.07).min(0.21);
    if signals.header_profile.order_anomaly {
        score += 0.08;
    }
    if signals.header_profile.connection_anomaly {
        score += 0.08;
    }

    if signals.known_bot_ja3.is_some() {
        score += 0.20;
    }
    if let Some(timing) = &signals.timing {
        if timing.automated {
            score += 0.20;
        }
    }
    if signals.credential_stuffing {
        score += 0.28;
    }

    if let Some(rep) = signals.source_reputation {
        if rep >= 0.7 {
            score += (rep - 0.7) * 0.4;
        }
    }

    if signals.known_legitimate_bot.is_some() {
        score -= 0.35;
    }
    if signals.known_browser_ja3.is_some() {
        score -= 0.15;
    }

    score.clamp(0.0, 1.0)
}

pub fn classify_bot(signals: &BotSignals) -> BotClassification {
    classify_bot_with_confidence(signals).classification
}

pub fn classify_bot_with_confidence(signals: &BotSignals) -> BotClassificationResult {
    let score = compute_bot_score(signals);

    if signals.known_legitimate_bot.is_some()
        && signals.known_scanner.is_none()
        && !signals.credential_stuffing
        && !signals.header_profile.suspicious_user_agent
    {
        return BotClassificationResult {
            classification: BotClassification::Legitimate,
            confidence: (0.85 + (1.0 - score) * 0.10).clamp(0.0, 1.0),
        };
    }

    if signals.known_scanner.is_some() || score >= 0.85 {
        return BotClassificationResult {
            classification: BotClassification::Malicious,
            confidence: score.max(0.85),
        };
    }

    if signals.credential_stuffing
        || signals
            .timing
            .as_ref()
            .map(|t| t.automated)
            .unwrap_or(false)
    {
        return BotClassificationResult {
            classification: BotClassification::Automated,
            confidence: score.max(0.7),
        };
    }

    if signals.header_profile.suspicious_user_agent
        && (signals.header_profile.order_anomaly
            || signals.header_profile.missing_expected_headers.len() >= 2)
    {
        return BotClassificationResult {
            classification: BotClassification::ScriptKiddie,
            confidence: score.max(0.65),
        };
    }

    if score <= 0.25 && signals.known_browser_ja3.is_some() {
        return BotClassificationResult {
            classification: BotClassification::Human,
            confidence: (1.0 - score).clamp(0.65, 0.98),
        };
    }

    if score <= 0.2 && signals.header_profile.missing_expected_headers.is_empty() {
        return BotClassificationResult {
            classification: BotClassification::Human,
            confidence: 0.72,
        };
    }

    BotClassificationResult {
        classification: BotClassification::Unknown,
        confidence: (0.45 + (score - 0.5).abs() * 0.4).clamp(0.45, 0.8),
    }
}

fn fnv1a_hex(s: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for b in s.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn detect_order_anomaly(seen: &std::collections::HashMap<String, usize>) -> bool {
    let canonical = [
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "accept-language",
    ];
    let mut last_idx = None;
    let mut observed = 0usize;

    for h in canonical {
        if let Some(idx) = seen.get(h) {
            observed += 1;
            if let Some(last) = last_idx {
                if *idx < last {
                    return true;
                }
            }
            last_idx = Some(*idx);
        }
    }

    observed >= 3
        && seen.len() >= 4
        && !seen.contains_key("sec-fetch-site")
        && !seen.contains_key("sec-ch-ua")
}

fn extract_user_agent(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        .map(|(_, value)| value.clone())
}

fn identify_known_bot_user_agent(user_agent: &str) -> Option<String> {
    let ua = user_agent.to_lowercase();
    BOT_USER_AGENT_PATTERNS
        .iter()
        .find(|pattern| ua.contains(**pattern))
        .map(|p| (*p).to_string())
}

fn is_suspicious_user_agent(user_agent: &str) -> bool {
    let ua = user_agent.trim();
    if ua.is_empty() || ua.len() < 10 {
        return true;
    }
    let lower = ua.to_lowercase();
    if lower.starts_with("curl/")
        || lower.starts_with("wget/")
        || lower.starts_with("python-requests")
        || lower.starts_with("go-http-client")
    {
        return true;
    }
    if lower == "mozilla" || lower == "curl" || lower == "python" || lower == "go-http-client" {
        return true;
    }

    let suspicious = [
        "sqlmap", "nikto", "nmap", "masscan", "acunetix", "zaproxy", "burp",
    ];
    suspicious.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn browser_headers() -> Vec<(String, String)> {
        vec![
            ("Host".into(), "example.com".into()),
            ("Connection".into(), "keep-alive".into()),
            ("User-Agent".into(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".into()),
            ("Accept".into(), "text/html,application/xhtml+xml".into()),
            ("Accept-Encoding".into(), "gzip, deflate, br".into()),
            ("Accept-Language".into(), "en-US,en;q=0.9".into()),
            ("Sec-Fetch-Site".into(), "none".into()),
        ]
    }

    #[test]
    fn parse_ja3_normalizes_and_hashes() {
        let fp = parse_ja3("771, 4865-4866-4867 , 0-23-10,29-23-24,0");
        assert_eq!(fp.raw_string, "771,4865-4866-4867,0-23-10,29-23-24,0");
        assert_eq!(fp.hash.len(), 16);
    }

    #[test]
    fn scanner_is_identified() {
        assert_eq!(is_known_scanner("sqlmap/1.7.2"), Some("sqlmap".to_string()));
    }

    #[test]
    fn legitimate_bot_is_identified() {
        assert_eq!(
            identify_legitimate_bot(
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            ),
            Some("Googlebot".to_string())
        );
    }

    #[test]
    fn header_analysis_detects_missing_and_suspicious_ua() {
        let headers = vec![
            ("Host".into(), "example.com".into()),
            ("User-Agent".into(), "curl/8.5.0".into()),
        ];
        let profile = analyze_headers(&headers);
        assert!(profile.missing_expected_headers.len() >= 2);
        assert!(profile.suspicious_user_agent);
    }

    #[test]
    fn header_order_anomaly_detected() {
        let headers = vec![
            ("Accept-Language".into(), "en-US".into()),
            ("Host".into(), "example.com".into()),
            ("Accept".into(), "*/*".into()),
            ("User-Agent".into(), "Mozilla/5.0".into()),
        ];
        let profile = analyze_headers(&headers);
        assert!(profile.order_anomaly);
    }

    #[test]
    fn automated_timing_detects_regular_intervals() {
        assert!(is_automated_timing(&[1000, 1000, 1000, 1000]));
    }

    #[test]
    fn automated_timing_rejects_human_variance() {
        assert!(!is_automated_timing(&[800, 1450, 2200, 970, 3000]));
    }

    #[test]
    fn credential_stuffing_detected() {
        let paths = vec![
            "/login",
            "/auth/login",
            "/signin",
            "/api/token",
            "/session",
            "/login",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
        assert!(is_credential_stuffing(
            &paths,
            &[700, 900, 800, 850, 700, 880]
        ));
    }

    #[test]
    fn credential_stuffing_not_detected_for_small_sample() {
        let paths = vec!["/login", "/profile", "/home"]
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        assert!(!is_credential_stuffing(&paths, &[1000, 3000]));
    }

    #[test]
    fn known_bot_ja3_match() {
        let fp = parse_ja3("771,4865-4866-4867-49195,0-10-11,29-23-24,0");
        assert_eq!(identify_known_bot_ja3(&fp), Some("curl".to_string()));
    }

    #[test]
    fn known_browser_ja3_match() {
        let fp = parse_ja3("771,4865-4866-4867-49195-49199-52393,0-23-65281-10-11-35,29-23-24,0");
        assert_eq!(identify_browser_ja3(&fp), Some("Chrome".to_string()));
    }

    #[test]
    fn classification_malicious_for_scanner() {
        let headers = vec![("User-Agent".to_string(), "sqlmap/1.7.2".to_string())];
        let profile = analyze_headers(&headers);
        let signals = BotSignals {
            user_agent: "sqlmap/1.7.2".into(),
            header_profile: profile,
            ja3: None,
            known_legitimate_bot: None,
            known_scanner: Some("sqlmap".into()),
            known_bot_ja3: None,
            known_browser_ja3: None,
            timing: Some(RequestTiming {
                intervals_ms: vec![500, 500, 500, 500],
                automated: true,
            }),
            credential_stuffing: true,
            source_reputation: Some(0.95),
        };
        let result = classify_bot_with_confidence(&signals);
        assert_eq!(result.classification, BotClassification::Malicious);
        assert!(result.confidence >= 0.85);
    }

    #[test]
    fn classification_legitimate_for_googlebot() {
        let headers = vec![(
            "User-Agent".to_string(),
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".to_string(),
        )];
        let profile = analyze_headers(&headers);
        let signals = BotSignals {
            user_agent: headers[0].1.clone(),
            header_profile: profile,
            ja3: None,
            known_legitimate_bot: Some("Googlebot".into()),
            known_scanner: None,
            known_bot_ja3: None,
            known_browser_ja3: None,
            timing: None,
            credential_stuffing: false,
            source_reputation: None,
        };
        let result = classify_bot_with_confidence(&signals);
        assert_eq!(result.classification, BotClassification::Legitimate);
    }

    #[test]
    fn classification_human_for_browser_profile() {
        let headers = browser_headers();
        let profile = analyze_headers(&headers);
        let ja3 = parse_ja3("771,4865-4866-4867-49195-49199-52393,0-23-65281-10-11-35,29-23-24,0");
        let signals = BotSignals {
            user_agent: headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            header_profile: profile,
            ja3: Some(ja3.clone()),
            known_legitimate_bot: None,
            known_scanner: None,
            known_bot_ja3: None,
            known_browser_ja3: identify_browser_ja3(&ja3),
            timing: Some(RequestTiming {
                intervals_ms: vec![950, 1500, 2100, 3000],
                automated: false,
            }),
            credential_stuffing: false,
            source_reputation: None,
        };

        let class = classify_bot(&signals);
        assert_eq!(class, BotClassification::Human);
    }

    #[test]
    fn score_bounds_are_clamped() {
        let signals = BotSignals {
            user_agent: "sqlmap".into(),
            header_profile: HeaderProfile {
                missing_expected_headers: vec![
                    "accept".into(),
                    "accept-language".into(),
                    "accept-encoding".into(),
                ],
                order_anomaly: true,
                known_bot_user_agent: Some("sqlmap".into()),
                suspicious_user_agent: true,
                connection_anomaly: true,
                header_count: 1,
            },
            ja3: None,
            known_legitimate_bot: None,
            known_scanner: Some("sqlmap".into()),
            known_bot_ja3: Some("python-requests".into()),
            known_browser_ja3: None,
            timing: Some(RequestTiming {
                intervals_ms: vec![1, 1, 1, 1],
                automated: true,
            }),
            credential_stuffing: true,
            source_reputation: Some(1.0),
        };

        let score = compute_bot_score(&signals);
        assert!((0.0..=1.0).contains(&score));
    }
}
