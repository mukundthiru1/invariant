use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

static LEAKED_PASSWORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(123456|password|qwerty|letmein|welcome123|admin123|changeme|iloveyou|p@ssw0rd)$")
        .unwrap()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapSeverity {
    Critical,
    High,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerLevel {
    AnyRequest,
    PostOnly,
    AuthAttempt,
    ParameterSubmit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapCategory {
    CmsAdmin,
    DebugEndpoint,
    ConfigFile,
    ApiDiscovery,
    CredentialFile,
    BackupFile,
    ScannerTarget,
    PathTraversal,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapType {
    Endpoint,
    Parameter,
    Token,
    Credential,
    Tarpit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamLocation {
    Query,
    Body,
    Cookie,
    Header,
}

#[derive(Debug, Clone)]
pub struct CanaryEndpoint {
    pub path: String,
    pub methods: Vec<String>,
    pub trigger_level: TriggerLevel,
    pub severity: TrapSeverity,
    pub category: TrapCategory,
    pub description: String,
    pub dynamic: bool,
}

#[derive(Debug, Clone)]
pub struct CanaryParameter {
    pub name: String,
    pub value_pattern: Option<Regex>,
    pub locations: Vec<ParamLocation>,
    pub severity: TrapSeverity,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct CanaryToken {
    pub token: String,
    pub embed_location: String,
    pub generated_at: u64,
    pub issued_to: String,
    pub exfil_indicator: bool,
}

#[derive(Debug, Clone)]
pub struct TrapRequestInfo {
    pub method: String,
    pub path: String,
    pub params: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct TrapTrigger {
    pub trap_type: TrapType,
    pub trap_id: String,
    pub source_hash: String,
    pub severity: TrapSeverity,
    pub category: TrapCategory,
    pub timestamp: u64,
    pub request: TrapRequestInfo,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Default)]
pub struct DeceptionConfig {
    pub custom_endpoints: Vec<CanaryEndpoint>,
    pub custom_parameters: Vec<CanaryParameter>,
    pub disable_builtins: bool,
}

#[derive(Debug, Clone)]
pub struct DeceptionStats {
    pub endpoints: usize,
    pub parameters: usize,
    pub active_tokens: usize,
    pub total_triggers: usize,
    pub confirmed_attackers: usize,
}

#[derive(Debug, Clone)]
pub struct DeceptionEngine {
    endpoints: Vec<CanaryEndpoint>,
    parameters: Vec<CanaryParameter>,
    tokens: HashMap<String, CanaryToken>,
    triggers: Vec<TrapTrigger>,
    confirmed_attackers: HashSet<String>,
    max_triggers: usize,
    max_tokens: usize,
    rng_state: u64,
}

impl Default for DeceptionEngine {
    fn default() -> Self {
        Self::new(None)
    }
}

impl DeceptionEngine {
    pub fn new(config: Option<DeceptionConfig>) -> Self {
        let cfg = config.unwrap_or_default();

        let endpoints = if cfg.disable_builtins {
            cfg.custom_endpoints
        } else {
            let mut all = builtin_canary_endpoints();
            all.extend(cfg.custom_endpoints);
            all
        };

        let parameters = if cfg.disable_builtins {
            cfg.custom_parameters
        } else {
            let mut all = builtin_canary_parameters();
            all.extend(cfg.custom_parameters);
            all
        };

        Self {
            endpoints,
            parameters,
            tokens: HashMap::new(),
            triggers: Vec::new(),
            confirmed_attackers: HashSet::new(),
            max_triggers: 10_000,
            max_tokens: 50_000,
            rng_state: now_ms() ^ 0xA24B_AED4_963E_E407,
        }
    }

    #[cfg(test)]
    fn with_limits(max_triggers: usize, max_tokens: usize) -> Self {
        let mut engine = Self::new(None);
        engine.max_triggers = max_triggers;
        engine.max_tokens = max_tokens;
        engine
    }

    pub fn check_request(
        &mut self,
        method: &str,
        path: &str,
        source_hash: &str,
        params: Option<&HashMap<String, String>>,
        headers: Option<&HashMap<String, String>>,
        cookies: Option<&HashMap<String, String>>,
        body: Option<&str>,
    ) -> Vec<TrapTrigger> {
        let mut fired = Vec::new();
        let mut pending_records = Vec::new();
        let timestamp = now_ms();
        let path_lower = path.to_ascii_lowercase();
        let method_upper = method.to_ascii_uppercase();

        for canary in &self.endpoints {
            if !self.match_path(&path_lower, &canary.path) {
                continue;
            }
            if !canary.methods.is_empty() && !canary.methods.iter().any(|m| m == &method_upper) {
                continue;
            }
            if canary.trigger_level == TriggerLevel::PostOnly && method_upper != "POST" {
                continue;
            }

            let trigger = TrapTrigger {
                trap_type: TrapType::Endpoint,
                trap_id: format!("endpoint:{}", canary.path),
                source_hash: source_hash.to_string(),
                severity: canary.severity,
                category: canary.category,
                timestamp,
                request: TrapRequestInfo {
                    method: method.to_string(),
                    path: path.to_string(),
                    params: params.cloned(),
                },
                description: canary.description.clone(),
                confidence: 1.0,
            };
            fired.push(trigger.clone());
            pending_records.push(trigger);
        }

        let mut body_params: HashMap<String, String> = HashMap::new();

        let mut check_param_source = |source: Option<&HashMap<String, String>>, location: ParamLocation, fired: &mut Vec<TrapTrigger>| {
            let Some(source_map) = source else {
                return;
            };
            for canary in &self.parameters {
                if !canary.locations.contains(&location) {
                    continue;
                }
                let Some(value) = source_map.get(&canary.name) else {
                    continue;
                };
                if let Some(re) = &canary.value_pattern {
                    if !re.is_match(value) {
                        continue;
                    }
                }

                let mut trigger_params = HashMap::new();
                trigger_params.insert(canary.name.clone(), value.clone());
                let trigger = TrapTrigger {
                    trap_type: TrapType::Parameter,
                    trap_id: format!(
                        "param:{}:{}",
                        canary.name,
                        match location {
                            ParamLocation::Query => "query",
                            ParamLocation::Body => "body",
                            ParamLocation::Cookie => "cookie",
                            ParamLocation::Header => "header",
                        }
                    ),
                    source_hash: source_hash.to_string(),
                    severity: canary.severity,
                    category: TrapCategory::Custom,
                    timestamp,
                    request: TrapRequestInfo {
                        method: method.to_string(),
                        path: path.to_string(),
                        params: Some(trigger_params),
                    },
                    description: canary.description.clone(),
                    confidence: 1.0,
                };
                fired.push(trigger.clone());
                pending_records.push(trigger);
            }
        };

        check_param_source(params, ParamLocation::Query, &mut fired);
        check_param_source(headers, ParamLocation::Header, &mut fired);
        check_param_source(cookies, ParamLocation::Cookie, &mut fired);

        if let Some(body_text) = body {
            body_params = parse_body_params(body_text);
            if !body_params.is_empty() {
                check_param_source(Some(&body_params), ParamLocation::Body, &mut fired);
            }
        }

        let search_text = format!(
            "{} {} {}",
            path,
            params
                .map(|p| serde_json::to_string(p).unwrap_or_default())
                .unwrap_or_default(),
            body.unwrap_or_default()
        );
        for (token, canary_token) in &self.tokens {
            if !search_text.contains(token) {
                continue;
            }
            let is_exfil = canary_token.issued_to != source_hash;
            let trigger = TrapTrigger {
                trap_type: TrapType::Token,
                trap_id: format!("token:{}", token.chars().take(8).collect::<String>()),
                source_hash: source_hash.to_string(),
                severity: if is_exfil {
                    TrapSeverity::Critical
                } else {
                    TrapSeverity::High
                },
                category: TrapCategory::Custom,
                timestamp,
                request: TrapRequestInfo {
                    method: method.to_string(),
                    path: path.to_string(),
                    params: None,
                },
                description: if is_exfil {
                    format!(
                        "Canary token exfiltration: token issued to {} found in request from {}",
                        canary_token.issued_to, source_hash
                    )
                } else {
                    "Canary token replay: response data being sent back in request".to_string()
                },
                confidence: 1.0,
            };
            fired.push(trigger.clone());
            pending_records.push(trigger);
        }

        let credential_triggers = detect_fake_credentials(method, path, source_hash, params, Some(&body_params), timestamp);
        for trigger in credential_triggers {
            fired.push(trigger.clone());
            pending_records.push(trigger);
        }

        for trigger in pending_records {
            self.record_trigger(trigger);
        }

        if let Some(headers_map) = headers {
            let response_ms = parse_u64_ci(headers_map, "x-response-time-ms");
            let redirect_hops = parse_u64_ci(headers_map, "x-redirect-hops").map(|v| v as u32);
            for trigger in self.check_tarpit_indicators(method, path, source_hash, response_ms, redirect_hops) {
                fired.push(trigger);
            }
        }

        if !fired.is_empty() {
            self.confirmed_attackers.insert(source_hash.to_string());
        }

        fired
    }

    pub fn check_tarpit_indicators(
        &mut self,
        method: &str,
        path: &str,
        source_hash: &str,
        response_time_ms: Option<u64>,
        redirect_hops: Option<u32>,
    ) -> Vec<TrapTrigger> {
        let mut fired = Vec::new();
        let timestamp = now_ms();

        if let Some(ms) = response_time_ms {
            if ms >= 15_000 {
                let trigger = TrapTrigger {
                    trap_type: TrapType::Tarpit,
                    trap_id: "tarpit:slow_response".to_string(),
                    source_hash: source_hash.to_string(),
                    severity: TrapSeverity::Medium,
                    category: TrapCategory::Custom,
                    timestamp,
                    request: TrapRequestInfo {
                        method: method.to_string(),
                        path: path.to_string(),
                        params: None,
                    },
                    description: format!("Tarpit indicator: unusually slow response observed ({}ms)", ms),
                    confidence: 1.0,
                };
                fired.push(trigger.clone());
                self.record_trigger(trigger);
            }
        }

        if let Some(hops) = redirect_hops {
            if hops >= 8 {
                let trigger = TrapTrigger {
                    trap_type: TrapType::Tarpit,
                    trap_id: "tarpit:redirect_chain".to_string(),
                    source_hash: source_hash.to_string(),
                    severity: TrapSeverity::High,
                    category: TrapCategory::Custom,
                    timestamp,
                    request: TrapRequestInfo {
                        method: method.to_string(),
                        path: path.to_string(),
                        params: None,
                    },
                    description: format!("Tarpit indicator: potential infinite redirect chain ({} hops)", hops),
                    confidence: 1.0,
                };
                fired.push(trigger.clone());
                self.record_trigger(trigger);
            }
        }

        if !fired.is_empty() {
            self.confirmed_attackers.insert(source_hash.to_string());
        }

        fired
    }

    pub fn generate_token(&mut self, source_hash: &str, embed_location: &str) -> String {
        if self.tokens.len() >= self.max_tokens {
            let mut entries: Vec<(&String, &CanaryToken)> = self.tokens.iter().collect();
            entries.sort_by_key(|(_, token)| token.generated_at);
            let evict_count = entries.len() / 4;
            let keys: Vec<String> = entries
                .into_iter()
                .take(evict_count)
                .map(|(token, _)| token.clone())
                .collect();
            for token in keys {
                self.tokens.remove(&token);
            }
        }

        let token = generate_realistic_token(&mut self.rng_state);
        self.tokens.insert(
            token.clone(),
            CanaryToken {
                token: token.clone(),
                embed_location: embed_location.to_string(),
                generated_at: now_ms(),
                issued_to: source_hash.to_string(),
                exfil_indicator: true,
            },
        );
        token
    }

    pub fn is_confirmed_attacker(&self, source_hash: &str) -> bool {
        self.confirmed_attackers.contains(source_hash)
    }

    pub fn get_triggers_for_source(&self, source_hash: &str) -> Vec<TrapTrigger> {
        self.triggers
            .iter()
            .filter(|t| t.source_hash == source_hash)
            .cloned()
            .collect()
    }

    pub fn get_recent_triggers(&self, limit: usize) -> Vec<TrapTrigger> {
        let count = self.triggers.len();
        let start = count.saturating_sub(limit);
        self.triggers[start..].to_vec()
    }

    pub fn get_stats(&self) -> DeceptionStats {
        DeceptionStats {
            endpoints: self.endpoints.len(),
            parameters: self.parameters.len(),
            active_tokens: self.tokens.len(),
            total_triggers: self.triggers.len(),
            confirmed_attackers: self.confirmed_attackers.len(),
        }
    }

    fn match_path(&self, request_path: &str, canary_path: &str) -> bool {
        let canary_lower = canary_path.to_ascii_lowercase();
        if request_path == canary_lower {
            return true;
        }
        if canary_path.ends_with('/') && request_path.starts_with(&canary_lower) {
            return true;
        }
        request_path.trim_end_matches('/') == canary_lower.trim_end_matches('/')
    }

    fn record_trigger(&mut self, trigger: TrapTrigger) {
        self.triggers.push(trigger);
        if self.triggers.len() > self.max_triggers {
            let keep = self.max_triggers / 2;
            let start = self.triggers.len().saturating_sub(keep);
            self.triggers = self.triggers[start..].to_vec();
        }
    }
}

fn detect_fake_credentials(
    method: &str,
    path: &str,
    source_hash: &str,
    params: Option<&HashMap<String, String>>,
    body_params: Option<&HashMap<String, String>>,
    timestamp: u64,
) -> Vec<TrapTrigger> {
    let mut merged = HashMap::new();
    if let Some(p) = params {
        for (k, v) in p {
            merged.insert(k.to_ascii_lowercase(), v.clone());
        }
    }
    if let Some(p) = body_params {
        for (k, v) in p {
            merged.insert(k.to_ascii_lowercase(), v.clone());
        }
    }

    let user_keys = ["username", "user", "login", "email"];
    let pass_keys = ["password", "pass", "passwd", "pwd"];

    let username = user_keys.iter().find_map(|k| merged.get(*k)).map(|s| s.to_ascii_lowercase());
    let password = pass_keys.iter().find_map(|k| merged.get(*k)).cloned();

    let mut triggers = Vec::new();

    if let (Some(u), Some(p)) = (username.as_deref(), password.as_deref()) {
        let p_lower = p.to_ascii_lowercase();
        let defaults = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("root", "toor"),
            ("test", "test"),
            ("guest", "guest"),
            ("administrator", "administrator"),
        ];

        if defaults.iter().any(|(du, dp)| *du == u && *dp == p_lower) {
            let mut params = HashMap::new();
            params.insert("username".to_string(), u.to_string());
            params.insert("password".to_string(), p.to_string());
            triggers.push(TrapTrigger {
                trap_type: TrapType::Credential,
                trap_id: "credential:default".to_string(),
                source_hash: source_hash.to_string(),
                severity: TrapSeverity::Critical,
                category: TrapCategory::Custom,
                timestamp,
                request: TrapRequestInfo {
                    method: method.to_string(),
                    path: path.to_string(),
                    params: Some(params),
                },
                description: "Fake credential detection: common default credential pair observed".to_string(),
                confidence: 1.0,
            });
        }
    }

    if let Some(p) = password.as_deref() {
        if LEAKED_PASSWORD_RE.is_match(p) {
            let mut params = HashMap::new();
            params.insert("password".to_string(), p.to_string());
            triggers.push(TrapTrigger {
                trap_type: TrapType::Credential,
                trap_id: "credential:leaked_pattern".to_string(),
                source_hash: source_hash.to_string(),
                severity: TrapSeverity::High,
                category: TrapCategory::Custom,
                timestamp,
                request: TrapRequestInfo {
                    method: method.to_string(),
                    path: path.to_string(),
                    params: Some(params),
                },
                description: "Fake credential detection: password matches leaked/common pattern".to_string(),
                confidence: 1.0,
            });
        }
    }

    triggers
}

fn parse_u64_ci(map: &HashMap<String, String>, key: &str) -> Option<u64> {
    map.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, v)| v.parse::<u64>().ok())
}

fn parse_body_params(body: &str) -> HashMap<String, String> {
    if body.trim().is_empty() {
        return HashMap::new();
    }

    if let Ok(json) = serde_json::from_str::<Value>(body) {
        if let Value::Object(map) = json {
            let mut out = HashMap::new();
            for (k, v) in map {
                let value = match v {
                    Value::String(s) => s,
                    Value::Null => String::new(),
                    _ => v.to_string(),
                };
                out.insert(k, value);
            }
            return out;
        }
    }

    let mut form = HashMap::new();
    for pair in body.split('&') {
        let mut split = pair.splitn(2, '=');
        let Some(k) = split.next() else {
            continue;
        };
        let Some(v) = split.next() else {
            continue;
        };
        form.insert(decode_url_component(k), decode_url_component(v));
    }
    form
}

fn decode_url_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h1 = bytes[i + 1];
                let h2 = bytes[i + 2];
                if let (Some(a), Some(b)) = (hex_val(h1), hex_val(h2)) {
                    out.push((a << 4) | b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn generate_realistic_token(state: &mut u64) -> String {
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let prefixes = ["sk-", "pk-", "api-", "key-", "token-", "sess-", ""];

    let prefix = prefixes[random_index(state, prefixes.len())];
    let length = 32 + random_index(state, 16);

    let mut token = String::from(prefix);
    for _ in 0..length {
        token.push(chars[random_index(state, chars.len())] as char);
    }

    token
}

fn random_index(state: &mut u64, max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    (x as usize) % max
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn builtin_canary_endpoints() -> Vec<CanaryEndpoint> {
    vec![
        CanaryEndpoint { path: "/wp-admin/setup-config.php".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::High, category: TrapCategory::CmsAdmin, description: "WordPress setup page - only accessed during initial install".into(), dynamic: false },
        CanaryEndpoint { path: "/wp-login.php".into(), methods: vec!["POST".into()], trigger_level: TriggerLevel::PostOnly, severity: TrapSeverity::High, category: TrapCategory::CmsAdmin, description: "WordPress login POST - credential stuffing attempt".into(), dynamic: false },
        CanaryEndpoint { path: "/administrator/index.php".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::High, category: TrapCategory::CmsAdmin, description: "Joomla admin - scanner probing for CMS".into(), dynamic: false },
        CanaryEndpoint { path: "/.env".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::ConfigFile, description: "Environment file access - seeking database credentials".into(), dynamic: false },
        CanaryEndpoint { path: "/.git/config".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::ConfigFile, description: "Git config access - seeking source code".into(), dynamic: false },
        CanaryEndpoint { path: "/.git/HEAD".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::ConfigFile, description: "Git HEAD access - source code reconnaissance".into(), dynamic: false },
        CanaryEndpoint { path: "/web.config".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::High, category: TrapCategory::ConfigFile, description: "IIS web.config - seeking connection strings".into(), dynamic: false },
        CanaryEndpoint { path: "/.htpasswd".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::CredentialFile, description: "Apache password file - seeking credentials".into(), dynamic: false },
        CanaryEndpoint { path: "/application.properties".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::ConfigFile, description: "Spring Boot config - seeking database credentials".into(), dynamic: false },
        CanaryEndpoint { path: "/config/database.yml".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::ConfigFile, description: "Rails database config - seeking credentials".into(), dynamic: false },
        CanaryEndpoint { path: "/appsettings.json".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::ConfigFile, description: ".NET config - seeking connection strings and secrets".into(), dynamic: false },
        CanaryEndpoint { path: "/actuator/env".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::DebugEndpoint, description: "Spring actuator env - seeking environment variables".into(), dynamic: false },
        CanaryEndpoint { path: "/actuator/heapdump".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::DebugEndpoint, description: "Spring heap dump - seeking memory contents".into(), dynamic: false },
        CanaryEndpoint { path: "/debug/pprof".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::High, category: TrapCategory::DebugEndpoint, description: "Go pprof debug endpoint".into(), dynamic: false },
        CanaryEndpoint { path: "/__clockwork".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::High, category: TrapCategory::DebugEndpoint, description: "Laravel Clockwork debug - seeking application state".into(), dynamic: false },
        CanaryEndpoint { path: "/telescope".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::High, category: TrapCategory::DebugEndpoint, description: "Laravel Telescope - seeking request/exception logs".into(), dynamic: false },
        CanaryEndpoint { path: "/phpinfo.php".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Medium, category: TrapCategory::ScannerTarget, description: "PHP info page - information disclosure probe".into(), dynamic: false },
        CanaryEndpoint { path: "/server-status".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Medium, category: TrapCategory::ScannerTarget, description: "Apache server-status - information disclosure probe".into(), dynamic: false },
        CanaryEndpoint { path: "/server-info".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Medium, category: TrapCategory::ScannerTarget, description: "Apache server-info - information disclosure probe".into(), dynamic: false },
        CanaryEndpoint { path: "/elmah.axd".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::High, category: TrapCategory::ScannerTarget, description: ".NET ELMAH error log - seeking stack traces".into(), dynamic: false },
        CanaryEndpoint { path: "/swagger.json".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Medium, category: TrapCategory::ApiDiscovery, description: "Swagger/OpenAPI spec - API reconnaissance".into(), dynamic: false },
        CanaryEndpoint { path: "/api-docs".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Medium, category: TrapCategory::ApiDiscovery, description: "API documentation endpoint - reconnaissance".into(), dynamic: false },
        CanaryEndpoint { path: "/backup.sql".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::BackupFile, description: "SQL backup file - seeking database dump".into(), dynamic: false },
        CanaryEndpoint { path: "/db.sql".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::BackupFile, description: "Database backup - seeking credentials and data".into(), dynamic: false },
        CanaryEndpoint { path: "/dump.sql".into(), methods: vec![], trigger_level: TriggerLevel::AnyRequest, severity: TrapSeverity::Critical, category: TrapCategory::BackupFile, description: "Database dump - seeking credentials and data".into(), dynamic: false },
    ]
}

fn builtin_canary_parameters() -> Vec<CanaryParameter> {
    vec![
        CanaryParameter { name: "_debug".into(), value_pattern: None, locations: vec![ParamLocation::Query, ParamLocation::Body], severity: TrapSeverity::High, description: "Debug parameter - no legitimate application should accept this".into() },
        CanaryParameter { name: "_test".into(), value_pattern: None, locations: vec![ParamLocation::Query, ParamLocation::Body], severity: TrapSeverity::Medium, description: "Test parameter - scanner probing for debug paths".into() },
        CanaryParameter { name: "admin".into(), value_pattern: Some(Regex::new(r"(?i)^(true|1|yes)$").unwrap()), locations: vec![ParamLocation::Query, ParamLocation::Body], severity: TrapSeverity::Critical, description: "Admin flag injection - attempting privilege escalation".into() },
        CanaryParameter { name: "is_admin".into(), value_pattern: Some(Regex::new(r"(?i)^(true|1|yes)$").unwrap()), locations: vec![ParamLocation::Query, ParamLocation::Body], severity: TrapSeverity::Critical, description: "Admin flag injection - attempting privilege escalation".into() },
        CanaryParameter { name: "role".into(), value_pattern: Some(Regex::new(r"(?i)^(admin|superadmin|root|super)$").unwrap()), locations: vec![ParamLocation::Query, ParamLocation::Body], severity: TrapSeverity::Critical, description: "Role escalation attempt".into() },
        CanaryParameter { name: "x-middleware-subrequest".into(), value_pattern: None, locations: vec![ParamLocation::Header], severity: TrapSeverity::Critical, description: "Next.js middleware bypass header (CVE-2025-29927)".into() },
        CanaryParameter { name: "x-original-url".into(), value_pattern: None, locations: vec![ParamLocation::Header], severity: TrapSeverity::High, description: "URL rewrite header - bypassing path-based access controls".into() },
        CanaryParameter { name: "x-rewrite-url".into(), value_pattern: None, locations: vec![ParamLocation::Header], severity: TrapSeverity::High, description: "URL rewrite header - bypassing path-based access controls".into() },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(items: &[(&str, &str)]) -> HashMap<String, String> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn endpoint_canary_triggers_on_exact_path() {
        let mut engine = DeceptionEngine::new(None);
        let hits = engine.check_request("GET", "/.env", "src1", None, None, None, None);
        assert!(hits.iter().any(|h| h.trap_type == TrapType::Endpoint));
    }

    #[test]
    fn post_only_endpoint_does_not_trigger_on_get() {
        let mut engine = DeceptionEngine::new(None);
        let hits = engine.check_request("GET", "/wp-login.php", "src1", None, None, None, None);
        assert!(hits.is_empty());
    }

    #[test]
    fn post_only_endpoint_triggers_on_post() {
        let mut engine = DeceptionEngine::new(None);
        let hits = engine.check_request("POST", "/wp-login.php", "src1", None, None, None, None);
        assert!(hits.iter().any(|h| h.trap_id == "endpoint:/wp-login.php"));
    }

    #[test]
    fn endpoint_path_match_ignores_trailing_slash() {
        let mut engine = DeceptionEngine::new(None);
        let hits = engine.check_request("GET", "/api-docs/", "src1", None, None, None, None);
        assert!(!hits.is_empty());
    }

    #[test]
    fn query_parameter_canary_triggers() {
        let mut engine = DeceptionEngine::new(None);
        let params = map(&[("_debug", "1")]);
        let hits = engine.check_request("GET", "/safe", "src1", Some(&params), None, None, None);
        assert!(hits.iter().any(|h| h.trap_type == TrapType::Parameter));
    }

    #[test]
    fn parameter_value_pattern_blocks_non_matching_values() {
        let mut engine = DeceptionEngine::new(None);
        let params = map(&[("admin", "false")]);
        let hits = engine.check_request("GET", "/safe", "src1", Some(&params), None, None, None);
        assert!(hits.is_empty());
    }

    #[test]
    fn body_json_canary_parameter_triggers() {
        let mut engine = DeceptionEngine::new(None);
        let body = r#"{"is_admin":"yes"}"#;
        let hits = engine.check_request("POST", "/safe", "src1", None, None, None, Some(body));
        assert!(hits.iter().any(|h| h.trap_id == "param:is_admin:body"));
    }

    #[test]
    fn body_form_canary_parameter_triggers() {
        let mut engine = DeceptionEngine::new(None);
        let body = "role=admin";
        let hits = engine.check_request("POST", "/safe", "src1", None, None, None, Some(body));
        assert!(hits.iter().any(|h| h.trap_id == "param:role:body"));
    }

    #[test]
    fn token_replay_same_source_is_high_severity() {
        let mut engine = DeceptionEngine::new(None);
        let token = engine.generate_token("src1", "html");
        let hits = engine.check_request("POST", "/x", "src1", None, None, None, Some(&format!("k={token}")));
        assert!(hits.iter().any(|h| h.trap_type == TrapType::Token && h.severity == TrapSeverity::High));
    }

    #[test]
    fn token_exfiltration_other_source_is_critical() {
        let mut engine = DeceptionEngine::new(None);
        let token = engine.generate_token("src1", "html");
        let hits = engine.check_request("POST", "/x", "src2", None, None, None, Some(&format!("k={token}")));
        assert!(hits.iter().any(|h| h.trap_type == TrapType::Token && h.severity == TrapSeverity::Critical));
    }

    #[test]
    fn marks_source_as_confirmed_attacker() {
        let mut engine = DeceptionEngine::new(None);
        engine.check_request("GET", "/.git/config", "src1", None, None, None, None);
        assert!(engine.is_confirmed_attacker("src1"));
    }

    #[test]
    fn get_triggers_for_source_filters_correctly() {
        let mut engine = DeceptionEngine::new(None);
        engine.check_request("GET", "/.env", "src1", None, None, None, None);
        engine.check_request("GET", "/.env", "src2", None, None, None, None);
        let src1 = engine.get_triggers_for_source("src1");
        assert!(src1.iter().all(|t| t.source_hash == "src1"));
    }

    #[test]
    fn get_recent_triggers_applies_limit() {
        let mut engine = DeceptionEngine::new(None);
        for _ in 0..5 {
            engine.check_request("GET", "/.env", "src", None, None, None, None);
        }
        let recent = engine.get_recent_triggers(3);
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn fake_default_credentials_trigger() {
        let mut engine = DeceptionEngine::new(None);
        let params = map(&[("username", "admin"), ("password", "admin")]);
        let hits = engine.check_request("POST", "/login", "src1", Some(&params), None, None, None);
        assert!(hits.iter().any(|h| h.trap_type == TrapType::Credential && h.trap_id == "credential:default"));
    }

    #[test]
    fn leaked_password_pattern_triggers() {
        let mut engine = DeceptionEngine::new(None);
        let body = "password=welcome123";
        let hits = engine.check_request("POST", "/login", "src1", None, None, None, Some(body));
        assert!(hits
            .iter()
            .any(|h| h.trap_type == TrapType::Credential && h.trap_id == "credential:leaked_pattern"));
    }

    #[test]
    fn tarpit_slow_response_triggers() {
        let mut engine = DeceptionEngine::new(None);
        let hits = engine.check_tarpit_indicators("GET", "/safe", "src1", Some(20_000), None);
        assert!(hits.iter().any(|h| h.trap_id == "tarpit:slow_response"));
    }

    #[test]
    fn tarpit_redirect_chain_triggers() {
        let mut engine = DeceptionEngine::new(None);
        let hits = engine.check_tarpit_indicators("GET", "/safe", "src1", None, Some(12));
        assert!(hits.iter().any(|h| h.trap_id == "tarpit:redirect_chain"));
    }

    #[test]
    fn tarpit_headers_in_request_path_trigger() {
        let mut engine = DeceptionEngine::new(None);
        let headers = map(&[("x-response-time-ms", "17000"), ("x-redirect-hops", "9")]);
        let hits = engine.check_request("GET", "/safe", "src1", None, Some(&headers), None, None);
        assert!(hits.iter().any(|h| h.trap_type == TrapType::Tarpit));
    }

    #[test]
    fn token_storage_is_bounded_with_eviction() {
        let mut engine = DeceptionEngine::with_limits(100, 8);
        for i in 0..20 {
            engine.generate_token(&format!("src{i}"), "resp");
        }
        assert!(engine.get_stats().active_tokens <= 8);
    }

    #[test]
    fn trigger_history_is_bounded() {
        let mut engine = DeceptionEngine::with_limits(20, 100);
        for _ in 0..30 {
            engine.check_request("GET", "/.env", "src", None, None, None, None);
        }
        assert!(engine.get_stats().total_triggers <= 20);
    }

    #[test]
    fn stats_report_non_zero_counts_after_activity() {
        let mut engine = DeceptionEngine::new(None);
        engine.check_request("GET", "/.env", "src", None, None, None, None);
        engine.generate_token("src", "html");
        let stats = engine.get_stats();
        assert!(stats.endpoints > 0);
        assert!(stats.parameters > 0);
        assert!(stats.active_tokens > 0);
        assert!(stats.total_triggers > 0);
        assert_eq!(stats.confirmed_attackers, 1);
    }
}
