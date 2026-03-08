use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

// Maximum endpoints to track (LRU eviction beyond this)
const MAX_ENDPOINTS: usize = 2_000;
// Minimum observations before baseline is considered reliable
const MIN_OBSERVATIONS: u64 = 50;
// EMA smoothing factor (higher = more weight on recent data)
const EMA_ALPHA: f64 = 0.05;
// Reservoir sample size for value tracking
const RESERVOIR_SIZE: usize = 100;
// Sigma threshold for anomaly detection
const ANOMALY_SIGMA: f64 = 3.0;
// Maximum parameters to track per endpoint
const MAX_PARAMS_PER_ENDPOINT: usize = 50;

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
});
static NUMERIC_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+(\.\d+)?$").unwrap());
static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^@]+@[^@]+\.[^@]+$").unwrap());
static ALPHA_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z]+$").unwrap());
static ALNUM_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceLocation {
    PathSegment,
    QueryKey,
    QueryValue,
    HeaderValue,
    CookieValue,
    JsonKey,
    JsonValue,
    FormField,
    MultipartField,
    XmlElement,
    XmlAttribute,
    Fragment,
}

impl SurfaceLocation {
    fn as_str(&self) -> &'static str {
        match self {
            SurfaceLocation::PathSegment => "path_segment",
            SurfaceLocation::QueryKey => "query_key",
            SurfaceLocation::QueryValue => "query_value",
            SurfaceLocation::HeaderValue => "header_value",
            SurfaceLocation::CookieValue => "cookie_value",
            SurfaceLocation::JsonKey => "json_key",
            SurfaceLocation::JsonValue => "json_value",
            SurfaceLocation::FormField => "form_field",
            SurfaceLocation::MultipartField => "multipart_field",
            SurfaceLocation::XmlElement => "xml_element",
            SurfaceLocation::XmlAttribute => "xml_attribute",
            SurfaceLocation::Fragment => "fragment",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Surface {
    pub location: SurfaceLocation,
    pub name: String,
    pub raw: String,
    pub normalized: String,
    pub entropy: f64,
    pub has_metachars: bool,
    pub metachar_density: f64,
}

impl Surface {
    pub fn new(location: SurfaceLocation, name: impl Into<String>, raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let normalized = raw.clone();
        let entropy = shannon_entropy(&normalized);
        let (has_metachars, metachar_density) = analyze_metachars(&normalized);
        Self {
            location,
            name: name.into(),
            raw,
            normalized,
            entropy,
            has_metachars,
            metachar_density,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RollingStats {
    pub mean: f64,
    pub variance: f64,
    pub min: f64,
    pub max: f64,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct TypeDistribution {
    pub numeric: f64,
    pub alpha: f64,
    pub alphanumeric: f64,
    pub email: f64,
    pub uuid: f64,
    pub special: f64,
}

impl TypeDistribution {
    fn get_mut(&mut self, vt: ValueType) -> &mut f64 {
        match vt {
            ValueType::Numeric => &mut self.numeric,
            ValueType::Alpha => &mut self.alpha,
            ValueType::Alphanumeric => &mut self.alphanumeric,
            ValueType::Email => &mut self.email,
            ValueType::Uuid => &mut self.uuid,
            ValueType::Special => &mut self.special,
        }
    }

    fn get(&self, vt: ValueType) -> f64 {
        match vt {
            ValueType::Numeric => self.numeric,
            ValueType::Alpha => self.alpha,
            ValueType::Alphanumeric => self.alphanumeric,
            ValueType::Email => self.email,
            ValueType::Uuid => self.uuid,
            ValueType::Special => self.special,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParameterProfile {
    pub name: String,
    pub location: String,
    pub type_distribution: TypeDistribution,
    pub length_stats: RollingStats,
    pub entropy_stats: RollingStats,
    pub metachar_stats: RollingStats,
    pub has_ever_had_metachars: bool,
    pub normal_metachar_rate: f64,
    pub cardinality_estimate: f64,
    pub value_sample: Vec<String>,
    pub observations: u64,
}

#[derive(Debug, Clone)]
pub struct TimingProfile {
    pub request_rate_per_minute: RollingStats,
    pub response_time_ms: RollingStats,
    pub last_seen: u64,
}

#[derive(Debug, Clone)]
pub struct EndpointBaseline {
    pub endpoint_key: String,
    pub parameter_profiles: HashMap<String, ParameterProfile>,
    pub timing: TimingProfile,
    pub body_size_stats: RollingStats,
    pub response_size_stats: RollingStats,
    pub auth_ratio: f64,
    pub observations: u64,
    pub baseline_confidence: f64,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone)]
pub struct ParameterAnomaly {
    pub name: String,
    pub score: f64,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct AnomalyAssessment {
    pub overall_score: f64,
    pub parameter_anomalies: Vec<ParameterAnomaly>,
    pub baseline_reliable: bool,
    pub baseline_observations: u64,
}

#[derive(Debug, Clone)]
pub struct BaselineEngineStats {
    pub endpoints: usize,
    pub total_observations: u64,
    pub reliable_endpoints: usize,
    pub avg_observations_per_endpoint: f64,
}

#[derive(Debug, Clone)]
pub struct AdaptiveBaselineEngine {
    baselines: HashMap<String, EndpointBaseline>,
    lru_order: Vec<String>,
    rng_state: u64,
}

impl Default for AdaptiveBaselineEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveBaselineEngine {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            lru_order: Vec::new(),
            rng_state: now_ms() ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub fn record_observation(
        &mut self,
        method: &str,
        path: &str,
        surfaces: &[Surface],
        response_time_ms: Option<f64>,
        body_size: Option<f64>,
        response_size: Option<f64>,
        is_authenticated: Option<bool>,
    ) {
        let key = self.normalize_endpoint_key(method, path);

        if !self.baselines.contains_key(&key) {
            if self.baselines.len() >= MAX_ENDPOINTS {
                self.evict_lru();
            }
            let baseline = self.create_baseline(&key);
            self.baselines.insert(key.clone(), baseline);
        }

        self.touch_lru(&key);

        let now = now_ms();
        let mut rate_to_update = None;

        {
            let baseline = self.baselines.get_mut(&key).expect("baseline exists");

            for surface in surfaces {
                if surface.location == SurfaceLocation::PathSegment {
                    continue;
                }
                update_parameter_profile(baseline, surface, &mut self.rng_state);
            }

            if baseline.timing.last_seen > 0 {
                let interval_minutes = (now.saturating_sub(baseline.timing.last_seen) as f64) / 60_000.0;
                if interval_minutes > 0.0 && interval_minutes < 60.0 {
                    rate_to_update = Some(1.0 / interval_minutes);
                }
            }
            baseline.timing.last_seen = now;

            if let Some(v) = response_time_ms {
                update_rolling_stats(&mut baseline.timing.response_time_ms, v);
            }
            if let Some(v) = body_size {
                update_rolling_stats(&mut baseline.body_size_stats, v);
            }
            if let Some(v) = response_size {
                update_rolling_stats(&mut baseline.response_size_stats, v);
            }

            if let Some(auth) = is_authenticated {
                let old_weight = baseline.observations as f64 / (baseline.observations as f64 + 1.0);
                baseline.auth_ratio = baseline.auth_ratio * old_weight + if auth { 1.0 } else { 0.0 } * (1.0 - old_weight);
            }

            baseline.observations += 1;
            baseline.last_seen = now;
            baseline.baseline_confidence = (baseline.observations as f64 / MIN_OBSERVATIONS as f64).min(1.0);
        }

        if let Some(rate) = rate_to_update {
            if let Some(baseline) = self.baselines.get_mut(&key) {
                update_rolling_stats(&mut baseline.timing.request_rate_per_minute, rate);
            }
        }
    }

    pub fn assess_anomaly(&self, method: &str, path: &str, surfaces: &[Surface]) -> AnomalyAssessment {
        let key = self.normalize_endpoint_key(method, path);
        let Some(baseline) = self.baselines.get(&key) else {
            return AnomalyAssessment {
                overall_score: 0.0,
                parameter_anomalies: Vec::new(),
                baseline_reliable: false,
                baseline_observations: 0,
            };
        };

        if baseline.observations < MIN_OBSERVATIONS {
            return AnomalyAssessment {
                overall_score: 0.0,
                parameter_anomalies: Vec::new(),
                baseline_reliable: false,
                baseline_observations: baseline.observations,
            };
        }

        let mut anomalies = Vec::new();

        for surface in surfaces {
            if surface.location == SurfaceLocation::PathSegment {
                continue;
            }

            let profile_key = format!("{}:{}", surface.location.as_str(), surface.name);
            let Some(profile) = baseline.parameter_profiles.get(&profile_key) else {
                if baseline.observations >= MIN_OBSERVATIONS * 2 {
                    anomalies.push(ParameterAnomaly {
                        name: surface.name.clone(),
                        score: 0.5,
                        reason: "unknown_parameter".to_string(),
                    });
                }
                continue;
            };

            let length_sigma = sigma_distance(surface.raw.len() as f64, &profile.length_stats);
            if length_sigma > ANOMALY_SIGMA {
                anomalies.push(ParameterAnomaly {
                    name: surface.name.clone(),
                    score: (length_sigma / 10.0).min(1.0),
                    reason: format!("length_anomaly:{length_sigma:.1}σ"),
                });
            }

            let entropy_sigma = sigma_distance(surface.entropy, &profile.entropy_stats);
            if entropy_sigma > ANOMALY_SIGMA {
                anomalies.push(ParameterAnomaly {
                    name: surface.name.clone(),
                    score: (entropy_sigma / 8.0).min(1.0),
                    reason: format!("entropy_anomaly:{entropy_sigma:.1}σ"),
                });
            }

            if surface.has_metachars && profile.normal_metachar_rate < 0.05 {
                let denom = (profile.metachar_stats.mean + profile.metachar_stats.variance * 2.0).max(0.001);
                let intensity = surface.metachar_density / denom;
                anomalies.push(ParameterAnomaly {
                    name: surface.name.clone(),
                    score: (0.7 + intensity * 0.3).min(1.0),
                    reason: format!("metachar_anomaly:rate={:.3}", profile.normal_metachar_rate),
                });
            }

            let value_type = classify_value_type(&surface.normalized);
            let type_rate = profile.type_distribution.get(value_type);
            if type_rate < 0.02 && profile.observations >= MIN_OBSERVATIONS {
                anomalies.push(ParameterAnomaly {
                    name: surface.name.clone(),
                    score: (0.6 + (1.0 - type_rate) * 0.4).min(1.0),
                    reason: format!("type_anomaly:{}_rate={type_rate:.3}", value_type.as_str()),
                });
            }
        }

        let max_anomaly = anomalies.iter().map(|a| a.score).fold(0.0_f64, f64::max);
        let overall_score = max_anomaly * baseline.baseline_confidence;

        AnomalyAssessment {
            overall_score,
            parameter_anomalies: anomalies,
            baseline_reliable: baseline.baseline_confidence >= 1.0,
            baseline_observations: baseline.observations,
        }
    }

    pub fn get_baseline(&self, method: &str, path: &str) -> Option<&EndpointBaseline> {
        self.baselines.get(&self.normalize_endpoint_key(method, path))
    }

    pub fn endpoint_count(&self) -> usize {
        self.baselines.len()
    }

    pub fn get_stats(&self) -> BaselineEngineStats {
        let mut total_obs = 0u64;
        let mut reliable = 0usize;
        for b in self.baselines.values() {
            total_obs += b.observations;
            if b.baseline_confidence >= 1.0 {
                reliable += 1;
            }
        }

        BaselineEngineStats {
            endpoints: self.baselines.len(),
            total_observations: total_obs,
            reliable_endpoints: reliable,
            avg_observations_per_endpoint: if self.baselines.is_empty() {
                0.0
            } else {
                total_obs as f64 / self.baselines.len() as f64
            },
        }
    }

    pub fn normalize_endpoint_key(&self, method: &str, path: &str) -> String {
        let path_only = path.split('?').next().unwrap_or(path);
        let normalized: Vec<String> = path_only
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s.chars().all(|ch| ch.is_ascii_digit()) {
                    "{id}".to_string()
                } else if UUID_RE.is_match(s) {
                    "{id}".to_string()
                } else if s.len() > 20 && ALNUM_RE.is_match(s) {
                    "{slug}".to_string()
                } else {
                    s.to_string()
                }
            })
            .collect();

        format!("{}:/{}", method.to_ascii_uppercase(), normalized.join("/"))
    }

    fn create_baseline(&self, key: &str) -> EndpointBaseline {
        let now = now_ms();
        EndpointBaseline {
            endpoint_key: key.to_string(),
            parameter_profiles: HashMap::new(),
            timing: TimingProfile {
                request_rate_per_minute: create_rolling_stats(),
                response_time_ms: create_rolling_stats(),
                last_seen: 0,
            },
            body_size_stats: create_rolling_stats(),
            response_size_stats: create_rolling_stats(),
            auth_ratio: 0.0,
            observations: 0,
            baseline_confidence: 0.0,
            first_seen: now,
            last_seen: now,
        }
    }

    fn touch_lru(&mut self, key: &str) {
        if let Some(idx) = self.lru_order.iter().position(|k| k == key) {
            self.lru_order.remove(idx);
        }
        self.lru_order.push(key.to_string());
    }

    fn evict_lru(&mut self) {
        if self.lru_order.is_empty() {
            return;
        }
        let evict_key = self.lru_order.remove(0);
        self.baselines.remove(&evict_key);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueType {
    Numeric,
    Alpha,
    Alphanumeric,
    Email,
    Uuid,
    Special,
}

impl ValueType {
    fn as_str(self) -> &'static str {
        match self {
            ValueType::Numeric => "numeric",
            ValueType::Alpha => "alpha",
            ValueType::Alphanumeric => "alphanumeric",
            ValueType::Email => "email",
            ValueType::Uuid => "uuid",
            ValueType::Special => "special",
        }
    }
}

fn create_rolling_stats() -> RollingStats {
    RollingStats {
        mean: 0.0,
        variance: 0.0,
        min: f64::INFINITY,
        max: f64::NEG_INFINITY,
        count: 0,
    }
}

fn update_rolling_stats(stats: &mut RollingStats, value: f64) {
    stats.count += 1;
    if stats.count == 1 {
        stats.mean = value;
        stats.variance = 0.0;
        stats.min = value;
        stats.max = value;
        return;
    }

    let alpha = EMA_ALPHA.max(1.0 / stats.count as f64);
    let delta = value - stats.mean;
    stats.mean += alpha * delta;
    stats.variance = (1.0 - alpha) * (stats.variance + alpha * delta * delta);
    stats.min = stats.min.min(value);
    stats.max = stats.max.max(value);
}

fn sigma_distance(value: f64, stats: &RollingStats) -> f64 {
    if stats.count < 5 {
        return 0.0;
    }
    let stddev = stats.variance.sqrt();
    if stddev < 0.001 {
        if (value - stats.mean).abs() > 0.001 {
            10.0
        } else {
            0.0
        }
    } else {
        (value - stats.mean).abs() / stddev
    }
}

fn classify_value_type(value: &str) -> ValueType {
    if NUMERIC_RE.is_match(value) {
        ValueType::Numeric
    } else if UUID_RE.is_match(value) {
        ValueType::Uuid
    } else if EMAIL_RE.is_match(value) {
        ValueType::Email
    } else if ALPHA_RE.is_match(value) {
        ValueType::Alpha
    } else if ALNUM_RE.is_match(value) {
        ValueType::Alphanumeric
    } else {
        ValueType::Special
    }
}

fn update_parameter_profile(baseline: &mut EndpointBaseline, surface: &Surface, rng_state: &mut u64) {
    let profile_key = format!("{}:{}", surface.location.as_str(), surface.name);
    if !baseline.parameter_profiles.contains_key(&profile_key) {
        if baseline.parameter_profiles.len() >= MAX_PARAMS_PER_ENDPOINT {
            return;
        }
        baseline
            .parameter_profiles
            .insert(profile_key.clone(), create_parameter_profile(&surface.name, surface.location.as_str()));
    }

    let profile = baseline.parameter_profiles.get_mut(&profile_key).expect("profile exists");

    let value_type = classify_value_type(&surface.normalized);
    let type_weight = 1.0 / (profile.observations as f64 + 1.0);
    let old_weight = 1.0 - type_weight;

    profile.type_distribution.numeric *= old_weight;
    profile.type_distribution.alpha *= old_weight;
    profile.type_distribution.alphanumeric *= old_weight;
    profile.type_distribution.email *= old_weight;
    profile.type_distribution.uuid *= old_weight;
    profile.type_distribution.special *= old_weight;
    *profile.type_distribution.get_mut(value_type) += type_weight;

    update_rolling_stats(&mut profile.length_stats, surface.raw.len() as f64);
    update_rolling_stats(&mut profile.entropy_stats, surface.entropy);
    update_rolling_stats(&mut profile.metachar_stats, surface.metachar_density);

    if surface.has_metachars {
        profile.has_ever_had_metachars = true;
    }
    profile.normal_metachar_rate =
        profile.normal_metachar_rate * (1.0 - EMA_ALPHA) + if surface.has_metachars { 1.0 } else { 0.0 } * EMA_ALPHA;

    profile.cardinality_estimate = (profile.cardinality_estimate + 1.0).min(profile.observations as f64 * 0.8);

    if profile.value_sample.len() < RESERVOIR_SIZE {
        profile.value_sample.push(surface.raw.clone());
    } else {
        let replace_idx = random_index(rng_state, profile.observations as usize);
        if replace_idx < RESERVOIR_SIZE {
            profile.value_sample[replace_idx] = surface.raw.clone();
        }
    }

    profile.observations += 1;
}

fn create_parameter_profile(name: &str, location: &str) -> ParameterProfile {
    ParameterProfile {
        name: name.to_string(),
        location: location.to_string(),
        type_distribution: TypeDistribution {
            numeric: 0.0,
            alpha: 0.0,
            alphanumeric: 0.0,
            email: 0.0,
            uuid: 0.0,
            special: 0.0,
        },
        length_stats: create_rolling_stats(),
        entropy_stats: create_rolling_stats(),
        metachar_stats: create_rolling_stats(),
        has_ever_had_metachars: false,
        normal_metachar_rate: 0.0,
        cardinality_estimate: 0.0,
        value_sample: Vec::new(),
        observations: 0,
    }
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

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut len = 0usize;
    for ch in input.chars() {
        *freq.entry(ch).or_insert(0) += 1;
        len += 1;
    }
    let len = len as f64;
    let mut entropy = 0.0;
    for count in freq.values() {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn analyze_metachars(input: &str) -> (bool, f64) {
    if input.is_empty() {
        return (false, 0.0);
    }
    let metachars = "\"';-/*()=<>!|&~^%+@`$\\{}[]";
    let mut count = 0usize;
    let mut total = 0usize;
    for ch in input.chars() {
        total += 1;
        if metachars.contains(ch) {
            count += 1;
        }
    }
    (count > 0, count as f64 / total as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(location: SurfaceLocation, name: &str, raw: &str) -> Surface {
        Surface::new(location, name, raw)
    }

    fn train_baseline(engine: &mut AdaptiveBaselineEngine, n: usize) {
        for _ in 0..n {
            let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "12345")];
            engine.record_observation("GET", "/api/users/123", &surfaces, Some(100.0), Some(300.0), Some(1024.0), Some(true));
        }
    }

    #[test]
    fn normalizes_numeric_path_segments_to_id() {
        let engine = AdaptiveBaselineEngine::new();
        assert_eq!(engine.normalize_endpoint_key("get", "/api/users/123"), "GET:/api/users/{id}");
    }

    #[test]
    fn normalizes_uuid_segments_to_id() {
        let engine = AdaptiveBaselineEngine::new();
        assert_eq!(
            engine.normalize_endpoint_key("POST", "/v1/item/550e8400-e29b-41d4-a716-446655440000"),
            "POST:/v1/item/{id}"
        );
    }

    #[test]
    fn normalizes_long_alnum_segments_to_slug() {
        let engine = AdaptiveBaselineEngine::new();
        assert_eq!(
            engine.normalize_endpoint_key("GET", "/posts/abcdefghijklmnopqrstuvwxyz123456"),
            "GET:/posts/{slug}"
        );
    }

    #[test]
    fn creates_baseline_on_first_observation() {
        let mut engine = AdaptiveBaselineEngine::new();
        let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "42")];
        engine.record_observation("GET", "/health", &surfaces, None, None, None, None);
        assert_eq!(engine.endpoint_count(), 1);
    }

    #[test]
    fn confidence_reaches_one_after_min_observations() {
        let mut engine = AdaptiveBaselineEngine::new();
        train_baseline(&mut engine, MIN_OBSERVATIONS as usize);
        let baseline = engine.get_baseline("GET", "/api/users/99").unwrap();
        assert!((baseline.baseline_confidence - 1.0).abs() < 1e-9);
    }

    #[test]
    fn anomaly_assessment_returns_unreliable_before_training() {
        let mut engine = AdaptiveBaselineEngine::new();
        train_baseline(&mut engine, 10);
        let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "99999")];
        let assessment = engine.assess_anomaly("GET", "/api/users/777", &surfaces);
        assert!(!assessment.baseline_reliable);
        assert_eq!(assessment.overall_score, 0.0);
    }

    #[test]
    fn unknown_parameter_is_flagged_for_mature_baseline() {
        let mut engine = AdaptiveBaselineEngine::new();
        train_baseline(&mut engine, (MIN_OBSERVATIONS * 2) as usize);
        let surfaces = vec![s(SurfaceLocation::QueryValue, "new_param", "abc")];
        let assessment = engine.assess_anomaly("GET", "/api/users/1", &surfaces);
        assert!(assessment.parameter_anomalies.iter().any(|a| a.reason == "unknown_parameter"));
    }

    #[test]
    fn detects_length_anomaly_with_high_sigma() {
        let mut engine = AdaptiveBaselineEngine::new();
        train_baseline(&mut engine, 80);
        let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "1234567890123456789012345678901234567890")];
        let assessment = engine.assess_anomaly("GET", "/api/users/55", &surfaces);
        assert!(assessment.parameter_anomalies.iter().any(|a| a.reason.starts_with("length_anomaly:")));
    }

    #[test]
    fn detects_entropy_anomaly() {
        let mut engine = AdaptiveBaselineEngine::new();
        for _ in 0..80 {
            let surfaces = vec![s(SurfaceLocation::QueryValue, "token", "aaaaaa")];
            engine.record_observation("GET", "/api/token", &surfaces, None, None, None, None);
        }
        let surfaces = vec![s(SurfaceLocation::QueryValue, "token", "a1b2c3d4e5f6g7h8i9j0")];
        let assessment = engine.assess_anomaly("GET", "/api/token", &surfaces);
        assert!(assessment.parameter_anomalies.iter().any(|a| a.reason.starts_with("entropy_anomaly:")));
    }

    #[test]
    fn detects_metachar_anomaly_when_rare() {
        let mut engine = AdaptiveBaselineEngine::new();
        for _ in 0..100 {
            let surfaces = vec![s(SurfaceLocation::QueryValue, "name", "alice")];
            engine.record_observation("GET", "/api/profile", &surfaces, None, None, None, None);
        }
        let surfaces = vec![s(SurfaceLocation::QueryValue, "name", "alice';--")];
        let assessment = engine.assess_anomaly("GET", "/api/profile", &surfaces);
        assert!(assessment.parameter_anomalies.iter().any(|a| a.reason.starts_with("metachar_anomaly:")));
    }

    #[test]
    fn detects_type_anomaly_for_unseen_type() {
        let mut engine = AdaptiveBaselineEngine::new();
        for _ in 0..100 {
            let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "123456")];
            engine.record_observation("GET", "/api/items", &surfaces, None, None, None, None);
        }
        let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "foo@bar.com")];
        let assessment = engine.assess_anomaly("GET", "/api/items", &surfaces);
        assert!(assessment.parameter_anomalies.iter().any(|a| a.reason.starts_with("type_anomaly:")));
    }

    #[test]
    fn stats_report_reliable_endpoint_counts() {
        let mut engine = AdaptiveBaselineEngine::new();
        train_baseline(&mut engine, MIN_OBSERVATIONS as usize);
        let stats = engine.get_stats();
        assert_eq!(stats.endpoints, 1);
        assert_eq!(stats.reliable_endpoints, 1);
        assert!(stats.avg_observations_per_endpoint >= MIN_OBSERVATIONS as f64);
    }

    #[test]
    fn caps_parameter_profiles_per_endpoint() {
        let mut engine = AdaptiveBaselineEngine::new();
        let mut surfaces = Vec::new();
        for i in 0..70 {
            surfaces.push(s(SurfaceLocation::QueryValue, &format!("p{i}"), "x"));
        }
        engine.record_observation("GET", "/api/cap", &surfaces, None, None, None, None);
        let baseline = engine.get_baseline("GET", "/api/cap").unwrap();
        assert_eq!(baseline.parameter_profiles.len(), MAX_PARAMS_PER_ENDPOINT);
    }

    #[test]
    fn updates_timing_and_size_stats() {
        let mut engine = AdaptiveBaselineEngine::new();
        let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "1")];
        engine.record_observation("GET", "/api/timing", &surfaces, Some(120.0), Some(512.0), Some(2048.0), Some(true));
        let baseline = engine.get_baseline("GET", "/api/timing").unwrap();
        assert_eq!(baseline.timing.response_time_ms.count, 1);
        assert_eq!(baseline.body_size_stats.count, 1);
        assert_eq!(baseline.response_size_stats.count, 1);
        assert!(baseline.auth_ratio > 0.0);
    }

    #[test]
    fn overall_score_is_weighted_by_baseline_confidence() {
        let mut engine = AdaptiveBaselineEngine::new();
        train_baseline(&mut engine, MIN_OBSERVATIONS as usize);
        let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "999999999999999999999")];
        let assessment = engine.assess_anomaly("GET", "/api/users/4", &surfaces);
        assert!(assessment.overall_score > 0.0);
        assert!(assessment.overall_score <= 1.0);
    }

    #[test]
    fn lru_eviction_keeps_endpoint_cap() {
        let mut engine = AdaptiveBaselineEngine::new();
        let surfaces = vec![s(SurfaceLocation::QueryValue, "id", "1")];
        for i in 0..(MAX_ENDPOINTS + 1) {
            engine.record_observation("GET", &format!("/e/k{i}"), &surfaces, None, None, None, None);
        }
        assert_eq!(engine.endpoint_count(), MAX_ENDPOINTS);
    }
}
