//! Threat-intelligence ingest and IOC correlation.
//!
//! This module parses a practical subset of STIX 2 bundle objects and exposes
//! runtime lookups used to boost detection confidence and correlate campaigns.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::campaign::AttackPhase;
use crate::types::InvariantClass;

/// STIX indicator object used for IOC matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StixIndicator {
    /// STIX object ID (`indicator--...`).
    pub id: String,
    /// Human-readable indicator name.
    pub name: String,
    /// STIX pattern expression used for matching.
    pub pattern: String,
    /// STIX object creation timestamp (RFC 3339 string).
    pub created: String,
    /// STIX object update timestamp (RFC 3339 string).
    pub modified: String,
    /// Pattern syntax identifier (typically `stix`).
    pub pattern_type: String,
    /// Optional raw YARA rule payload when `pattern_type` is `yara`.
    pub yara_rule: Option<String>,
    /// Optional indicator confidence score in `[0, 100]`.
    pub confidence: Option<u8>,
    /// Optional validity-start timestamp (RFC 3339 string).
    pub valid_from: Option<String>,
    /// Optional validity-end timestamp (RFC 3339 string).
    pub valid_until: Option<String>,
    /// Kill-chain phase names attached to the indicator.
    pub kill_chain_phases: Vec<String>,
    /// Taxonomy labels used for class relevance filtering.
    pub labels: Vec<String>,
}

/// STIX threat-actor object used for campaign attribution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StixThreatActor {
    /// STIX object ID (`threat-actor--...`).
    pub id: String,
    /// Primary actor name.
    pub name: String,
    /// Known aliases or operator handles.
    pub aliases: Vec<String>,
    /// Optional STIX sophistication value.
    pub sophistication: Option<String>,
    /// Optional STIX resource-level value.
    pub resource_level: Option<String>,
    /// Optional primary motivation label.
    pub primary_motivation: Option<String>,
}

/// STIX attack-pattern object used for kill-chain context enrichment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StixAttackPattern {
    /// STIX object ID (`attack-pattern--...`).
    pub id: String,
    /// Human-readable attack-pattern name.
    pub name: String,
    /// External ATT&CK IDs (for example `T1059`).
    pub external_references: Vec<String>,
    /// Kill-chain phase names attached to this pattern.
    pub kill_chain_phases: Vec<String>,
}

/// STIX relationship object linking indicators, campaigns, and actors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StixRelationship {
    /// Source STIX object ID.
    pub source_ref: String,
    /// Target STIX object ID.
    pub target_ref: String,
    /// STIX relationship type (for example `attributed-to`).
    pub relationship_type: String,
}

/// Aggregated kill-chain context derived from detected invariant classes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KillChainContext {
    /// Normalized campaign phase set inferred from class/activity mappings.
    pub phases: Vec<AttackPhase>,
    /// Matching STIX attack-pattern IDs.
    pub attack_pattern_ids: Vec<String>,
    /// Matching MITRE ATT&CK technique IDs.
    pub mitre_attack_ids: Vec<String>,
}

/// In-memory threat-intelligence feed with parsed STIX indexes.
#[derive(Debug, Clone, Default)]
pub struct ThreatIntelFeed {
    /// Loaded STIX indicators used for IOC matching.
    pub indicators: Vec<StixIndicator>,
    /// Loaded threat actors used for campaign attribution.
    pub threat_actors: Vec<StixThreatActor>,
    /// Loaded attack patterns used for ATT&CK/phase correlation.
    pub attack_patterns: Vec<StixAttackPattern>,
    relationships: Vec<StixRelationship>,
    parsed_patterns: Vec<ParsedIndicatorPattern>,
    campaign_actor_map: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct ParsedIndicatorPattern {
    indicator_idx: usize,
    expressions: Vec<PatternExpr>,
    yara_rule: Option<String>,
}

#[derive(Debug, Clone)]
enum PatternExpr {
    Eq(PatternField, String),
    Matches(PatternField, Regex),
}

#[derive(Debug, Clone, Copy)]
enum PatternField {
    Ip,
    Domain,
    Url,
    Email,
    Md5,
    Sha1,
    Sha256,
    CertSha256,
    Ja3,
    Ja3s,
    Asn,
    WalletAddress,
    Generic,
}

#[derive(Default)]
struct InputArtifacts {
    lower_input: String,
    hashes: HashSets,
    ips: HashSet<IpAddr>,
    domains: HashSet<String>,
    urls: HashSet<String>,
    emails: HashSet<String>,
    asns: HashSet<String>,
    ja3: HashSet<String>,
    ja3s: HashSet<String>,
    wallet_addresses: HashSet<String>,
    cert_sha256: HashSet<String>,
}

impl ThreatIntelFeed {
    /// Create an empty threat-intel feed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a STIX bundle JSON payload.
    ///
    /// `json` must be a STIX bundle with an `objects` array. Invalid JSON or
    /// unsupported object shapes are ignored, and parsed objects are merged into
    /// the existing feed. Internal indexes are rebuilt after ingestion.
    pub fn ingest_stix_bundle(&mut self, json: &str) {
        let root: Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return,
        };
        if !is_valid_stix_bundle_root(&root) {
            return;
        }
        let objects = root
            .get("objects")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for obj in objects {
            if !is_valid_stix_object(&obj) {
                continue;
            }

            let obj_type = obj.get("type").and_then(Value::as_str).unwrap_or_default();
            match obj_type {
                "indicator" => {
                    if let Some(ind) = parse_indicator(&obj) {
                        self.indicators.push(ind);
                    }
                }
                "threat-actor" => {
                    if let Some(actor) = parse_threat_actor(&obj) {
                        self.threat_actors.push(actor);
                    }
                }
                "attack-pattern" => {
                    if let Some(pattern) = parse_attack_pattern(&obj) {
                        self.attack_patterns.push(pattern);
                    }
                }
                "relationship" => {
                    if let Some(rel) = parse_relationship(&obj) {
                        self.relationships.push(rel);
                    }
                }
                _ => {}
            }
        }

        self.rebuild_indexes();
    }

    /// Match loaded indicators relevant to a detected class against input text.
    ///
    /// `class` scopes matching to class-relevant indicator labels.
    /// `input` is normalized and compared against parsed STIX expressions.
    ///
    /// Returns deduplicated indicators whose parsed pattern clauses all match.
    pub fn match_detection(&self, class: InvariantClass, input: &str) -> Vec<StixIndicator> {
        self.match_detection_with_yara_matcher(class, input, |_rule, _input| false)
    }

    /// Match loaded indicators with optional YARA integration.
    ///
    /// `yara_matcher` receives the YARA rule and input content for indicators
    /// with `pattern_type: yara`.
    pub fn match_detection_with_yara_matcher<F>(
        &self,
        class: InvariantClass,
        input: &str,
        mut yara_matcher: F,
    ) -> Vec<StixIndicator>
    where
        F: FnMut(&str, &str) -> bool,
    {
        if input.is_empty() {
            return Vec::new();
        }

        let class_tokens = class_match_tokens(class);
        let artifacts = build_input_artifacts(input);
        let now_unix = current_unix_timestamp();

        let mut matches = Vec::new();
        let mut seen = HashSet::new();

        for parsed in &self.parsed_patterns {
            let indicator = match self.indicators.get(parsed.indicator_idx) {
                Some(ind) => ind,
                None => continue,
            };

            if !indicator_relevant_to_class(indicator, &class_tokens) {
                continue;
            }
            if indicator_is_expired(indicator, now_unix) {
                continue;
            }

            if !parsed
                .expressions
                .iter()
                .all(|expr| expr_matches_input(expr, &artifacts))
            {
                continue;
            }

            if let Some(rule) = parsed.yara_rule.as_deref() {
                if !yara_matcher(rule, input) {
                    continue;
                }
            }

            if seen.insert(indicator.id.clone()) {
                matches.push(indicator.clone());
            }
        }

        matches
    }

    /// Resolve a campaign fingerprint or alias to a known threat actor.
    ///
    /// `fingerprint` is normalized and looked up against relationship-derived
    /// mappings, actor IDs, names, and aliases.
    ///
    /// Returns the matching actor when one can be resolved.
    pub fn get_threat_actor_for_campaign(&self, fingerprint: &str) -> Option<StixThreatActor> {
        if fingerprint.trim().is_empty() {
            return None;
        }

        let key = normalize_token(fingerprint);

        if let Some(actor_id) = self.campaign_actor_map.get(&key) {
            return self
                .threat_actors
                .iter()
                .find(|a| a.id == *actor_id)
                .cloned();
        }

        for actor in &self.threat_actors {
            if normalize_token(&actor.id) == key || normalize_token(&actor.name) == key {
                return Some(actor.clone());
            }
            if actor
                .aliases
                .iter()
                .any(|alias| normalize_token(alias) == key)
            {
                return Some(actor.clone());
            }
        }

        None
    }

    /// Derive kill-chain context for a set of detected invariant classes.
    ///
    /// `classes` should contain all classes observed in the current detection
    /// window.
    ///
    /// Returns inferred attack phases plus matching STIX attack-pattern and
    /// ATT&CK technique identifiers.
    pub fn get_kill_chain_context(&self, classes: &[InvariantClass]) -> KillChainContext {
        if classes.is_empty() {
            return KillChainContext::default();
        }

        let mut phase_set = HashSet::new();
        let mut pattern_ids = HashSet::new();
        let mut mitre_ids = HashSet::new();

        let class_tokens: HashSet<String> = classes
            .iter()
            .flat_map(|class| class_match_tokens(*class))
            .collect();

        for class in classes {
            phase_set.insert(class_to_phase(*class));
        }

        for ap in &self.attack_patterns {
            let ap_name = normalize_token(&ap.name);
            let by_name = class_tokens.iter().any(|token| ap_name.contains(token));
            let by_phase = ap
                .kill_chain_phases
                .iter()
                .filter_map(|p| stix_phase_to_attack_phase(p))
                .any(|p| phase_set.contains(&p));

            if by_name || by_phase {
                pattern_ids.insert(ap.id.clone());
                for ext in &ap.external_references {
                    mitre_ids.insert(ext.clone());
                }
            }
        }

        let mut phases: Vec<AttackPhase> = phase_set.into_iter().collect();
        phases.sort();

        let mut attack_pattern_ids: Vec<String> = pattern_ids.into_iter().collect();
        attack_pattern_ids.sort();

        let mut mitre_attack_ids: Vec<String> = mitre_ids.into_iter().collect();
        mitre_attack_ids.sort();

        KillChainContext {
            phases,
            attack_pattern_ids,
            mitre_attack_ids,
        }
    }

    /// Compute a confidence boost from matching indicators-of-compromise.
    ///
    /// `class` and `input` are passed through [`Self::match_detection`].
    ///
    /// Returns a bounded additive boost in `[0.0, 0.2]`.
    pub fn ioc_confidence_boost(&self, class: InvariantClass, input: &str) -> f64 {
        let hits = self.match_detection(class, input);
        let weighted: f64 = hits
            .iter()
            .map(|ind| {
                // Keep baseline boost while scaling up for higher-confidence IOCs.
                let conf = ind.confidence.unwrap_or(50) as f64 / 100.0;
                0.02 + (0.06 * conf)
            })
            .sum();
        weighted.min(0.2)
    }

    fn rebuild_indexes(&mut self) {
        self.parsed_patterns.clear();
        self.campaign_actor_map.clear();

        for (idx, indicator) in self.indicators.iter().enumerate() {
            let expressions = match indicator.pattern_type.as_str() {
                "yara" => indicator
                    .yara_rule
                    .as_ref()
                    .and_then(|rule| (!rule.trim().is_empty()).then_some(Vec::new())),
                _ => {
                    let parsed = parse_stix_pattern_subset(&indicator.pattern);
                    if parsed.is_empty() {
                        None
                    } else {
                        Some(parsed)
                    }
                }
            };

            if let Some(expressions) = expressions {
                self.parsed_patterns.push(ParsedIndicatorPattern {
                    indicator_idx: idx,
                    expressions,
                    yara_rule: indicator
                        .yara_rule
                        .as_ref()
                        .filter(|rule| !rule.trim().is_empty())
                        .map(|rule| rule.clone()),
                });
            }
        }

        let actor_ids: HashSet<String> = self.threat_actors.iter().map(|a| a.id.clone()).collect();

        for rel in &self.relationships {
            let src_actor = actor_ids.contains(&rel.source_ref);
            let dst_actor = actor_ids.contains(&rel.target_ref);

            if src_actor {
                self.campaign_actor_map
                    .insert(normalize_token(&rel.target_ref), rel.source_ref.clone());
            } else if dst_actor {
                self.campaign_actor_map
                    .insert(normalize_token(&rel.source_ref), rel.target_ref.clone());
            }
        }

        for actor in &self.threat_actors {
            self.campaign_actor_map
                .insert(normalize_token(&actor.id), actor.id.clone());
            self.campaign_actor_map
                .insert(normalize_token(&actor.name), actor.id.clone());

            for alias in &actor.aliases {
                self.campaign_actor_map
                    .insert(normalize_token(alias), actor.id.clone());

                let lower = alias.to_ascii_lowercase();
                if let Some(fp) = lower.strip_prefix("fingerprint:") {
                    self.campaign_actor_map
                        .insert(normalize_token(fp), actor.id.clone());
                }
            }
        }
    }
}

fn parse_indicator(obj: &Value) -> Option<StixIndicator> {
    let id = obj.get("id")?.as_str()?;
    if !is_valid_stix_id(id, "indicator") {
        return None;
    }

    let created = obj.get("created")?.as_str()?.to_string();
    if parse_rfc3339_to_unix(&created).is_none() {
        return None;
    }
    let modified = obj.get("modified")?.as_str()?.to_string();
    if parse_rfc3339_to_unix(&modified).is_none() {
        return None;
    }

    let name = obj.get("name")?.as_str()?.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let pattern = obj.get("pattern")?.as_str()?.trim().to_string();
    if pattern.is_empty() {
        return None;
    }

    let pattern_type = obj
        .get("pattern_type")
        .and_then(Value::as_str)
        .unwrap_or("stix")
        .to_ascii_lowercase();
    if !matches!(pattern_type.as_str(), "stix" | "yara") {
        return None;
    }

    if pattern_type == "stix" && parse_stix_pattern_subset(&pattern).is_empty() {
        return None;
    }

    let yara_rule = if pattern_type == "yara" {
        if pattern.is_empty() {
            None
        } else {
            Some(pattern.clone())
        }
    } else {
        None
    };

    Some(StixIndicator {
        id: id.to_string(),
        name,
        created,
        modified,
        pattern,
        pattern_type,
        yara_rule,
        confidence: obj
            .get("confidence")
            .and_then(Value::as_u64)
            .map(|v| v.min(100) as u8),
        valid_from: obj
            .get("valid_from")
            .and_then(Value::as_str)
            .map(str::to_string),
        valid_until: obj
            .get("valid_until")
            .and_then(Value::as_str)
            .map(str::to_string),
        kill_chain_phases: extract_kill_chain_phases(obj),
        labels: extract_string_array(obj.get("labels")),
    })
}

fn parse_threat_actor(obj: &Value) -> Option<StixThreatActor> {
    let id = obj.get("id")?.as_str()?;
    if !is_valid_stix_id(id, "threat-actor") {
        return None;
    }

    let name = obj.get("name")?.as_str()?.trim().to_string();
    if name.is_empty() {
        return None;
    }

    Some(StixThreatActor {
        id: id.to_string(),
        name,
        aliases: extract_string_array(obj.get("aliases")),
        sophistication: obj
            .get("sophistication")
            .and_then(Value::as_str)
            .map(str::to_string),
        resource_level: obj
            .get("resource_level")
            .and_then(Value::as_str)
            .map(str::to_string),
        primary_motivation: obj
            .get("primary_motivation")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn parse_attack_pattern(obj: &Value) -> Option<StixAttackPattern> {
    let id = obj.get("id")?.as_str()?;
    if !is_valid_stix_id(id, "attack-pattern") {
        return None;
    }

    let name = obj.get("name").and_then(Value::as_str)?.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut external_references = Vec::new();

    if let Some(refs) = obj.get("external_references").and_then(Value::as_array) {
        for reference in refs {
            if let Some(external_id) = reference.get("external_id").and_then(Value::as_str) {
                external_references.push(external_id.to_string());
            }
        }
    }

    Some(StixAttackPattern {
        id: id.to_string(),
        name,
        external_references,
        kill_chain_phases: extract_kill_chain_phases(obj),
    })
}

fn parse_relationship(obj: &Value) -> Option<StixRelationship> {
    let source_ref = obj.get("source_ref")?.as_str()?;
    let target_ref = obj.get("target_ref")?.as_str()?;

    if !(is_valid_stix_reference(source_ref) || is_valid_relationship_reference(source_ref))
        || !(is_valid_stix_reference(target_ref) || is_valid_relationship_reference(target_ref))
    {
        return None;
    }

    Some(StixRelationship {
        source_ref: source_ref.to_string(),
        target_ref: target_ref.to_string(),
        relationship_type: obj
            .get("relationship_type")
            .and_then(Value::as_str)
            .unwrap_or("related-to")
            .to_string(),
    })
}

fn extract_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_kill_chain_phases(obj: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(phases) = obj.get("kill_chain_phases").and_then(Value::as_array) {
        for phase in phases {
            if let Some(phase_name) = phase.get("phase_name").and_then(Value::as_str) {
                out.push(phase_name.to_string());
            }
        }
    }
    out
}

fn parse_stix_pattern_subset(pattern: &str) -> Vec<PatternExpr> {
    if pattern.len() > 4096
        || pattern.contains('\0')
        || pattern.contains('\n')
        || pattern.contains('\r')
    {
        return Vec::new();
    }

    if !pattern.starts_with('[') || !pattern.ends_with(']') {
        return Vec::new();
    }

    let inner = pattern
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();

    if inner.is_empty() {
        return Vec::new();
    }

    let and_split = Regex::new(r"(?i)\s+AND\s+").expect("valid AND split regex");
    let mut out = Vec::new();

    for clause in and_split.split(inner) {
        if let Some(expr) = parse_clause(clause.trim()) {
            out.push(expr);
            continue;
        }
        return Vec::new();
    }

    out
}

fn parse_clause(clause: &str) -> Option<PatternExpr> {
    let regex_matcher = Regex::new(r"(?i)^([a-z0-9_:\.\-']+)\s+MATCHES\s+'([^']+)'$")
        .expect("valid stix MATCHES regex parser");
    if let Some(caps) = regex_matcher.captures(clause) {
        let field_raw = caps.get(1)?.as_str();
        let pattern = caps.get(2)?.as_str().trim();
        if pattern.is_empty() || pattern.len() > 512 || pattern.contains('\0') {
            return None;
        }
        let field = classify_pattern_field(field_raw);
        let compiled = match field {
            PatternField::Md5
            | PatternField::Sha1
            | PatternField::Sha256
            | PatternField::CertSha256
            | PatternField::Ja3
            | PatternField::Ja3s
            | PatternField::Asn
            | PatternField::WalletAddress => Regex::new(&format!("(?i:{pattern})")).ok()?,
            _ => Regex::new(pattern).ok()?,
        };
        return Some(PatternExpr::Matches(field, compiled));
    }

    let eq_matcher =
        Regex::new(r"(?i)^([a-z0-9_:\.\-']+)\s*=\s*'([^']+)'$").expect("valid stix = regex parser");
    if let Some(caps) = eq_matcher.captures(clause) {
        let field_raw = caps.get(1)?.as_str();
        let value = caps.get(2)?.as_str().to_string();
        let field = classify_pattern_field(field_raw);
        return Some(PatternExpr::Eq(field, value));
    }

    None
}

fn classify_pattern_field(field: &str) -> PatternField {
    let f = field.to_ascii_lowercase();

    if f.contains("ipv4-addr")
        || f.contains("ipv6-addr")
        || f.contains("src_ref.value")
        || f.contains("dst_ref.value")
    {
        return PatternField::Ip;
    }
    if f.contains("wallet") || f.contains("btc") || f.contains("bitcoin") {
        return PatternField::WalletAddress;
    }
    if f.contains("asn")
        || f.contains("autonomous-system-number")
        || f.contains("autonomous_system_number")
    {
        return PatternField::Asn;
    }
    if f.contains("ja3s") {
        return PatternField::Ja3s;
    }
    if f.contains("ja3") {
        return PatternField::Ja3;
    }
    if f.contains("domain-name") {
        return PatternField::Domain;
    }
    if f.contains("url:value") {
        return PatternField::Url;
    }
    if f.contains("email-addr") {
        return PatternField::Email;
    }
    if f.contains("md5") {
        return PatternField::Md5;
    }
    if f.contains("sha-1") || f.contains("sha1") {
        return PatternField::Sha1;
    }
    if f.contains("sha-256") || f.contains("sha256") {
        if f.contains("x509") || f.contains("certificate") {
            return PatternField::CertSha256;
        }
        return PatternField::Sha256;
    }

    PatternField::Generic
}

fn expr_matches_input(expr: &PatternExpr, artifacts: &InputArtifacts) -> bool {
    match expr {
        PatternExpr::Eq(field, value) => matches_eq(*field, value, artifacts),
        PatternExpr::Matches(field, regex) => match *field {
            PatternField::Md5
            | PatternField::Sha1
            | PatternField::Sha256
            | PatternField::CertSha256 => artifacts.hashes.all.iter().any(|h| regex.is_match(h)),
            PatternField::WalletAddress => artifacts
                .wallet_addresses
                .iter()
                .any(|wallet| regex.is_match(wallet)),
            PatternField::Ja3 => artifacts.ja3.iter().any(|ja3| regex.is_match(ja3)),
            PatternField::Ja3s => artifacts.ja3s.iter().any(|ja3s| regex.is_match(ja3s)),
            PatternField::Asn => artifacts.asns.iter().any(|asn| regex.is_match(asn)),
            PatternField::Ip => {
                artifacts
                    .ips
                    .iter()
                    .any(|ip| regex.is_match(&ip.to_string()))
                    || regex.is_match(&artifacts.lower_input)
            }
            PatternField::Domain => {
                artifacts.domains.iter().any(|d| regex.is_match(d))
                    || regex.is_match(&artifacts.lower_input)
            }
            PatternField::Url => {
                artifacts.urls.iter().any(|u| regex.is_match(u))
                    || regex.is_match(&artifacts.lower_input)
            }
            PatternField::Email => {
                artifacts.emails.iter().any(|e| regex.is_match(e))
                    || regex.is_match(&artifacts.lower_input)
            }
            PatternField::Generic => regex.is_match(&artifacts.lower_input),
        },
    }
}

fn matches_eq(field: PatternField, value: &str, artifacts: &InputArtifacts) -> bool {
    let needle = value.to_ascii_lowercase();
    match field {
        PatternField::Md5 => artifacts.hashes.md5.contains(&needle),
        PatternField::Sha1 => artifacts.hashes.sha1.contains(&needle),
        PatternField::Sha256 => artifacts.hashes.sha256.contains(&needle),
        PatternField::CertSha256 => artifacts.cert_sha256.contains(&needle),
        PatternField::Ja3 => artifacts.ja3.contains(&needle),
        PatternField::Ja3s => artifacts.ja3s.contains(&needle),
        PatternField::Asn => artifacts.asns.contains(&normalize_asn_value(&needle)),
        PatternField::WalletAddress => artifacts
            .wallet_addresses
            .iter()
            .any(|wallet| normalize_wallet_address(wallet) == normalize_wallet_address(&needle)),
        PatternField::Ip => {
            if let Some(cidr) = parse_cidr(&needle) {
                artifacts.ips.iter().any(|ip| ip_in_cidr(*ip, &cidr))
                    || artifacts.lower_input.contains(&needle)
            } else {
                needle
                    .parse::<IpAddr>()
                    .ok()
                    .is_some_and(|ip| artifacts.ips.contains(&ip))
                    || artifacts.lower_input.contains(&needle)
            }
        }
        PatternField::Domain => domain_matches_ioc(&needle, artifacts),
        PatternField::Url => url_matches_ioc(&needle, artifacts),
        PatternField::Email => {
            artifacts.emails.contains(&needle) || artifacts.lower_input.contains(&needle)
        }
        PatternField::Generic => artifacts.lower_input.contains(&needle),
    }
}

fn is_valid_stix_object(obj: &Value) -> bool {
    let obj_type = obj.get("type").and_then(Value::as_str).unwrap_or_default();
    match obj_type {
        "indicator" => is_valid_indicator_object(obj),
        "threat-actor" => is_valid_threat_actor_object(obj),
        "attack-pattern" => is_valid_attack_pattern_object(obj),
        "relationship" => is_valid_relationship_object(obj),
        _ => false,
    }
}

fn is_valid_stix_bundle_root(root: &Value) -> bool {
    if root.get("type").and_then(Value::as_str) != Some("bundle") {
        return false;
    }

    if let Some(id) = root.get("id").and_then(Value::as_str)
        && !is_valid_stix_id(id, "bundle")
    {
        return false;
    }

    root.get("objects").is_some_and(Value::is_array)
}

fn is_valid_indicator_object(obj: &Value) -> bool {
    let id = obj.get("id").and_then(Value::as_str).unwrap_or_default();
    let created = obj
        .get("created")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let modified = obj
        .get("modified")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let pattern = obj
        .get("pattern")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();

    if !is_valid_stix_id(id, "indicator")
        || !is_non_empty_string(name)
        || !is_non_empty_string(pattern)
        || !is_non_empty_string(created)
        || !is_non_empty_string(modified)
        || parse_rfc3339_to_unix(created).is_none()
        || parse_rfc3339_to_unix(modified).is_none()
    {
        return false;
    }

    let pattern_type = obj
        .get("pattern_type")
        .and_then(Value::as_str)
        .unwrap_or("stix")
        .to_ascii_lowercase();

    if !matches!(pattern_type.as_str(), "stix" | "yara") {
        return false;
    }

    if pattern_type == "stix" {
        return !parse_stix_pattern_subset(pattern).is_empty();
    }

    !pattern.is_empty()
}

fn is_valid_threat_actor_object(obj: &Value) -> bool {
    let id = obj.get("id").and_then(Value::as_str).unwrap_or_default();
    let created = obj
        .get("created")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let modified = obj
        .get("modified")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();

    is_valid_stix_id(id, "threat-actor")
        && is_non_empty_string(name)
        && is_non_empty_string(created)
        && is_non_empty_string(modified)
        && parse_rfc3339_to_unix(created).is_some()
        && parse_rfc3339_to_unix(modified).is_some()
}

fn is_valid_attack_pattern_object(obj: &Value) -> bool {
    let id = obj.get("id").and_then(Value::as_str).unwrap_or_default();
    let created = obj
        .get("created")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let modified = obj
        .get("modified")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();

    is_valid_stix_id(id, "attack-pattern")
        && is_non_empty_string(name)
        && is_non_empty_string(created)
        && is_non_empty_string(modified)
        && parse_rfc3339_to_unix(created).is_some()
        && parse_rfc3339_to_unix(modified).is_some()
}

fn is_valid_relationship_object(obj: &Value) -> bool {
    let id = obj.get("id").and_then(Value::as_str).unwrap_or_default();
    let created = obj
        .get("created")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let modified = obj
        .get("modified")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let relation_type = obj
        .get("relationship_type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();

    if !is_valid_stix_id(id, "relationship") {
        return false;
    }

    if !is_non_empty_string(created) || !is_non_empty_string(modified) {
        return false;
    }

    if parse_rfc3339_to_unix(created).is_none() || parse_rfc3339_to_unix(modified).is_none() {
        return false;
    }

    let source_ref = obj.get("source_ref").and_then(Value::as_str);
    let target_ref = obj.get("target_ref").and_then(Value::as_str);

    let source_ref = match source_ref {
        Some(source_ref)
            if is_valid_stix_reference(source_ref)
                || is_valid_relationship_reference(source_ref) =>
        {
            source_ref
        }
        _ => return false,
    };

    let target_ref = match target_ref {
        Some(target_ref)
            if is_valid_stix_reference(target_ref)
                || is_valid_relationship_reference(target_ref) =>
        {
            target_ref
        }
        _ => return false,
    };

    is_non_empty_string(relation_type)
        && is_non_empty_string(source_ref)
        && is_non_empty_string(target_ref)
}

fn is_non_empty_string(value: &str) -> bool {
    !value.trim().is_empty()
}

fn is_valid_stix_reference(value: &str) -> bool {
    is_valid_stix_id(value, "any")
}

fn is_valid_relationship_reference(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':' || c == '.')
}

fn is_valid_stix_id(value: &str, expected_type: &str) -> bool {
    let (actual_type, tail) = match value.split_once("--") {
        Some(parts) => parts,
        None => return false,
    };

    if expected_type != "any" && actual_type != expected_type {
        return false;
    }

    let groups = tail.split('-').collect::<Vec<_>>();
    let uuid_parts = [8, 4, 4, 4, 12];
    if groups.len() != uuid_parts.len() {
        return false;
    }

    for (part, expected_len) in groups.iter().zip(uuid_parts.iter()) {
        if part.len() != *expected_len {
            return false;
        }
        if !part.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return false;
        }
    }

    true
}

fn build_input_artifacts(input: &str) -> InputArtifacts {
    let mut artifacts = InputArtifacts {
        lower_input: input.to_ascii_lowercase(),
        hashes: extract_hashes(input),
        ips: extract_ips(input),
        domains: extract_domains(input),
        urls: extract_normalized_urls(input),
        emails: extract_emails(input),
        asns: extract_asns(input),
        ja3: extract_ja3_hashes(input),
        ja3s: extract_ja3s_hashes(input),
        wallet_addresses: extract_wallet_addresses(input),
        cert_sha256: extract_certificate_hashes(input),
    };

    for url in &artifacts.urls {
        if let Some(host) = extract_host_from_normalized_url(url) {
            artifacts.domains.insert(host);
        }
    }

    artifacts
}

fn indicator_relevant_to_class(ind: &StixIndicator, class_tokens: &HashSet<String>) -> bool {
    if ind.labels.is_empty() {
        return true;
    }

    ind.labels
        .iter()
        .map(|label| normalize_token(label))
        .any(|label| class_tokens.contains(&label))
}

#[derive(Default)]
struct HashSets {
    md5: HashSet<String>,
    sha1: HashSet<String>,
    sha256: HashSet<String>,
    all: HashSet<String>,
}

fn extract_hashes(input: &str) -> HashSets {
    let mut sets = HashSets::default();
    let hex = Regex::new(r"(?i)\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b")
        .expect("valid hash extractor regex");

    for m in hex.find_iter(input) {
        let hash = m.as_str().to_ascii_lowercase();
        match hash.len() {
            32 => {
                sets.md5.insert(hash.clone());
            }
            40 => {
                sets.sha1.insert(hash.clone());
            }
            64 => {
                sets.sha256.insert(hash.clone());
            }
            _ => {}
        }
        sets.all.insert(hash);
    }

    sets
}

#[derive(Debug, Clone, Copy)]
struct CidrRange {
    network: IpAddr,
    prefix: u8,
}

fn parse_cidr(value: &str) -> Option<CidrRange> {
    let (ip_raw, prefix_raw) = value.split_once('/')?;
    let network = normalize_ip_for_cidr(ip_raw.parse::<IpAddr>().ok()?);
    let prefix = prefix_raw.parse::<u8>().ok()?;

    let max = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return None;
    }

    Some(CidrRange { network, prefix })
}

fn ip_in_cidr(ip: IpAddr, cidr: &CidrRange) -> bool {
    let ip = normalize_ip_for_cidr(ip);
    let network = normalize_ip_for_cidr(cidr.network);

    match (ip, network) {
        (IpAddr::V4(ipv4), IpAddr::V4(net4)) => {
            let ip_u = u32::from_be_bytes(ipv4.octets());
            let net_u = u32::from_be_bytes(net4.octets());
            let mask = if cidr.prefix == 0 {
                0
            } else {
                u32::MAX << (32 - cidr.prefix)
            };
            (ip_u & mask) == (net_u & mask)
        }
        (IpAddr::V6(ipv6), IpAddr::V6(net6)) => {
            let ip_u = u128::from_be_bytes(ipv6.octets());
            let net_u = u128::from_be_bytes(net6.octets());
            let mask = if cidr.prefix == 0 {
                0
            } else {
                u128::MAX << (128 - cidr.prefix)
            };
            (ip_u & mask) == (net_u & mask)
        }
        _ => false,
    }
}

fn normalize_ip_for_cidr(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4() {
            return IpAddr::V4(v4);
        }
    }

    ip
}

fn extract_ips(input: &str) -> HashSet<IpAddr> {
    let candidate = Regex::new(r"[A-Fa-f0-9:\.]+").expect("valid ip candidate regex");
    candidate
        .find_iter(input)
        .filter_map(|m| m.as_str().parse::<IpAddr>().ok())
        .collect()
}

fn extract_domains(input: &str) -> HashSet<String> {
    let domain = Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
        .expect("valid domain regex");
    domain
        .find_iter(input)
        .map(|m| m.as_str().to_ascii_lowercase())
        .collect()
}

fn extract_emails(input: &str) -> HashSet<String> {
    let email = Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63}\b")
        .expect("valid email regex");
    email
        .find_iter(input)
        .map(|m| m.as_str().to_ascii_lowercase())
        .collect()
}

fn extract_asns(input: &str) -> HashSet<String> {
    let mut asns = HashSet::new();
    let asn = Regex::new(r"(?i)\b(?:asn|autonomous[-_]system[-_]number)\s*[=:]?\s*([0-9]{1,10})\b")
        .expect("valid ASN regex");
    let bare_asn = Regex::new(r"(?i)\bAS([0-9]{1,10})\b").expect("valid bare ASN regex");

    for m in asn.find_iter(input) {
        if let Some(capture) = asn.captures(m.as_str()) {
            asns.insert(capture[1].to_string());
        }
    }
    for m in bare_asn.find_iter(input) {
        if let Some(capture) = bare_asn.captures(m.as_str()) {
            asns.insert(capture[1].to_string());
        }
    }

    asns
}

fn extract_ja3_hashes(input: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let re = Regex::new(r"(?i)\bja3\s*(?:=|:)\s*([0-9a-f]{32})\b").expect("valid JA3 regex");

    for m in re.find_iter(input) {
        if let Some(capture) = re.captures(m.as_str()) {
            out.insert(capture[1].to_ascii_lowercase());
        }
    }

    out
}

fn extract_ja3s_hashes(input: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let re = Regex::new(r"(?i)\bja3s\s*(?:=|:)\s*([0-9a-f]{32})\b").expect("valid JA3S regex");

    for m in re.find_iter(input) {
        if let Some(capture) = re.captures(m.as_str()) {
            out.insert(capture[1].to_ascii_lowercase());
        }
    }

    out
}

fn extract_wallet_addresses(input: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let bech32 = Regex::new(r"(?i)\bbc1[a-z0-9]{39,59}\b").expect("valid bech32 wallet regex");
    let legacy =
        Regex::new(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b").expect("valid base58 wallet regex");

    for m in bech32.find_iter(input) {
        out.insert(m.as_str().to_ascii_lowercase());
    }
    for m in legacy.find_iter(input) {
        out.insert(normalize_wallet_address(m.as_str()));
    }

    out
}

fn extract_certificate_hashes(input: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let cert = Regex::new(
        r"(?i)\b(?:x509|certificate|cert(?:ificate)?|cert[_-]?sha[_-]?256|sha-?256)\b[^a-z0-9]{0,24}([a-f0-9]{64})\b",
    )
    .expect("valid certificate hash regex");

    for m in cert.find_iter(input) {
        if let Some(capture) = cert.captures(m.as_str()) {
            out.insert(capture[1].to_ascii_lowercase());
        }
    }

    let labeled = Regex::new(
        r"(?i)\b(?:cert_sha256|certificate_sha256|x509_sha256|x509hash)\s*[:=]\s*([a-f0-9]{64})\b",
    )
    .expect("valid labeled certificate hash regex");
    for m in labeled.find_iter(input) {
        if let Some(capture) = labeled.captures(m.as_str()) {
            out.insert(capture[1].to_ascii_lowercase());
        }
    }

    out
}

fn normalize_wallet_address(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_asn_value(value: &str) -> String {
    value
        .trim()
        .trim_start_matches(['a', 'A', 's', 'S'].as_ref())
        .trim()
        .to_string()
}

fn extract_normalized_urls(input: &str) -> HashSet<String> {
    let url = Regex::new(r#"(?i)\bhttps?://[^\s'"<>\)\]]+"#).expect("valid url extractor regex");
    url.find_iter(input)
        .flat_map(|m| {
            let mut urls = Vec::new();
            if let Some(normalized) = normalize_url(m.as_str()) {
                urls.push(normalized);
            }

            let decoded = percent_decode(m.as_str());
            if let Some(normalized) = normalize_url(&decoded) {
                if !urls.contains(&normalized) {
                    urls.push(normalized);
                }
            }

            urls
        })
        .collect()
}

fn normalize_url(value: &str) -> Option<String> {
    let decoded = percent_decode(value);
    let trimmed = decoded
        .trim()
        .trim_matches(|c: char| "'\"<>(),".contains(c));
    let (scheme_raw, rest_raw) = trimmed.split_once("://")?;
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }

    let (authority_raw, suffix_raw) = split_authority_and_suffix(rest_raw);
    let authority_no_user = authority_raw.rsplit('@').next().unwrap_or(authority_raw);

    let (host_raw, port_raw) = split_host_and_port(authority_no_user)?;
    let host = host_raw.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }

    let port = match (scheme.as_str(), port_raw) {
        ("http", Some("80")) | ("https", Some("443")) => None,
        (_, Some(p)) if !p.is_empty() => Some(p),
        _ => None,
    };

    let mut normalized = format!("{scheme}://{host}");
    if let Some(p) = port {
        normalized.push(':');
        normalized.push_str(p);
    }
    normalized.push_str(strip_query_and_fragment(suffix_raw));

    let collapsed = normalized.trim_end_matches('/').to_string();
    Some(if collapsed.is_empty() {
        format!("{scheme}://{host}")
    } else {
        collapsed
    })
}

fn strip_query_and_fragment(input: &str) -> &str {
    for (idx, ch) in input.char_indices() {
        if matches!(ch, '?' | '#') {
            return &input[..idx];
        }
    }

    input
}

fn percent_decode(input: &str) -> String {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] == b'%' && idx + 2 < bytes.len() {
            let high = hex_value(bytes[idx + 1]);
            let low = hex_value(bytes[idx + 2]);
            if let (Some(h), Some(l)) = (high, low) {
                out.push((h << 4 | l) as char);
                idx += 3;
                continue;
            }
        }
        out.push(bytes[idx] as char);
        idx += 1;
    }

    String::from_utf8(out.into_iter().map(|c| c as u8).collect())
        .unwrap_or_else(|_| input.to_string())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn split_authority_and_suffix(rest: &str) -> (&str, &str) {
    for (idx, ch) in rest.char_indices() {
        if matches!(ch, '/' | '?' | '#') {
            return (&rest[..idx], &rest[idx..]);
        }
    }
    (rest, "")
}

fn split_host_and_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[..=end];
        let rest = authority.get(end + 1..).unwrap_or_default();
        if let Some(port) = rest.strip_prefix(':') {
            return Some((host, Some(port)));
        }
        return Some((host, None));
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Some((host, Some(port)));
        }
    }
    Some((authority, None))
}

fn extract_host_from_normalized_url(value: &str) -> Option<String> {
    let (_, rest) = value.split_once("://")?;
    let (authority, _) = split_authority_and_suffix(rest);
    let (host, _) = split_host_and_port(authority)?;
    Some(host.trim_matches(['[', ']']).to_string())
}

fn domain_matches_ioc(needle: &str, artifacts: &InputArtifacts) -> bool {
    if let Some(suffix) = needle.strip_prefix("*.") {
        return artifacts
            .domains
            .iter()
            .any(|d| d.ends_with(&format!(".{suffix}")) && d != suffix);
    }

    artifacts.domains.contains(needle) || artifacts.lower_input.contains(needle)
}

fn url_matches_ioc(needle: &str, artifacts: &InputArtifacts) -> bool {
    if let Some(normalized) = normalize_url(needle) {
        if artifacts.urls.contains(&normalized) {
            return true;
        }

        let decoded = percent_decode(needle);
        if let Some(decoded_norm) = normalize_url(&decoded) {
            if artifacts.urls.contains(&decoded_norm) {
                return true;
            }
        }

        artifacts.lower_input.contains(needle)
    } else {
        artifacts.lower_input.contains(needle)
    }
}

fn indicator_is_expired(indicator: &StixIndicator, now_unix: i64) -> bool {
    indicator
        .valid_until
        .as_deref()
        .and_then(parse_rfc3339_to_unix)
        .is_some_and(|ts| ts <= now_unix)
}

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_rfc3339_to_unix(value: &str) -> Option<i64> {
    let (date, time_and_zone) = value.split_once('T')?;
    let mut tz_split = time_and_zone.rsplitn(2, ['+', '-']);
    let tz_or_z = tz_split.next()?;
    let time_part = if time_and_zone.ends_with('Z') {
        time_and_zone.strip_suffix('Z')?
    } else {
        tz_split.next()?
    };

    let (year, month, day) = parse_ymd(date)?;
    let (hour, minute, second) = parse_hms(time_part)?;
    let offset_seconds = if time_and_zone.ends_with('Z') {
        0
    } else {
        parse_tz_offset(time_and_zone)?
    };

    let days = days_from_civil(year, month, day);
    let seconds =
        days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    let adjusted = seconds - i64::from(offset_seconds);

    if tz_or_z.is_empty() {
        None
    } else {
        Some(adjusted)
    }
}

fn parse_ymd(value: &str) -> Option<(i32, u32, u32)> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    Some((year, month, day))
}

fn parse_hms(value: &str) -> Option<(u32, u32, u32)> {
    let main = value.split('.').next().unwrap_or(value);
    let mut parts = main.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second = parts.next()?.parse::<u32>().ok()?;
    Some((hour, minute, second))
}

fn parse_tz_offset(value: &str) -> Option<i32> {
    let (main, sign) = value
        .rmatch_indices(['+', '-'])
        .next()
        .map(|(idx, s)| (&value[idx + 1..], s.chars().next().unwrap_or('+')))?;
    let (h, m) = main.split_once(':')?;
    let hours = h.parse::<i32>().ok()?;
    let minutes = m.parse::<i32>().ok()?;
    let total = hours * 3600 + minutes * 60;
    Some(if sign == '-' { -total } else { total })
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let m = month as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) as i64
}

fn class_match_tokens(class: InvariantClass) -> HashSet<String> {
    let mut tokens = HashSet::new();

    tokens.insert(to_snake_case(&format!("{:?}", class)));
    tokens.insert(normalize_token(&format!("{:?}", class.category())));

    match class.category() {
        crate::types::AttackCategory::Sqli => {
            tokens.insert("sqli".to_string());
            tokens.insert("sql_injection".to_string());
        }
        crate::types::AttackCategory::Xss => {
            tokens.insert("xss".to_string());
            tokens.insert("cross_site_scripting".to_string());
        }
        crate::types::AttackCategory::PathTraversal => {
            tokens.insert("path_traversal".to_string());
        }
        crate::types::AttackCategory::Cmdi => {
            tokens.insert("command_injection".to_string());
            tokens.insert("cmdi".to_string());
        }
        crate::types::AttackCategory::Ssrf => {
            tokens.insert("ssrf".to_string());
        }
        crate::types::AttackCategory::Deser => {
            tokens.insert("deserialization".to_string());
        }
        crate::types::AttackCategory::Auth => {
            tokens.insert("auth".to_string());
            tokens.insert("authentication".to_string());
        }
        crate::types::AttackCategory::Smuggling => {
            tokens.insert("http_smuggling".to_string());
        }
        crate::types::AttackCategory::Injection => {
            tokens.insert("injection".to_string());
        }
    }

    tokens
}

fn to_snake_case(input: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in input.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    out
}

fn normalize_token(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn class_to_phase(class: InvariantClass) -> AttackPhase {
    match class.category() {
        crate::types::AttackCategory::Sqli
        | crate::types::AttackCategory::Xss
        | crate::types::AttackCategory::PathTraversal
        | crate::types::AttackCategory::Cmdi
        | crate::types::AttackCategory::Ssrf
        | crate::types::AttackCategory::Deser
        | crate::types::AttackCategory::Auth
        | crate::types::AttackCategory::Injection
        | crate::types::AttackCategory::Smuggling => AttackPhase::Exploitation,
    }
}

fn stix_phase_to_attack_phase(phase: &str) -> Option<AttackPhase> {
    let p = normalize_token(phase);
    match p.as_str() {
        "reconnaissance" | "recon" => Some(AttackPhase::Reconnaissance),
        "weaponization" | "weaponize" | "resource_development" => Some(AttackPhase::Weaponization),
        "delivery" | "initial_access" => Some(AttackPhase::Delivery),
        "exploitation" | "execution" | "exploit" => Some(AttackPhase::Exploitation),
        "installation" | "persistence" | "install" => Some(AttackPhase::Installation),
        "command_and_control" | "c2" => Some(AttackPhase::CommandControl),
        "exfiltration" | "actions" | "collection" | "impact" => Some(AttackPhase::Exfiltration),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STIX_BUNDLE: &str = r#"{
      "type": "bundle",
      "id": "bundle--11111111-1111-4111-8111-111111111111",
      "objects": [
        {
          "type": "indicator",
          "id": "indicator--11111111-1111-4111-8111-111111111111",
          "created": "2026-01-01T00:00:00Z",
          "modified": "2026-01-01T00:00:00Z",
          "name": "Known SQLi C2",
          "pattern": "[domain-name:value = 'evil-db.example']",
          "pattern_type": "stix",
          "valid_from": "2026-01-01T00:00:00Z",
          "labels": ["sql_injection", "malicious-activity"],
          "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "exploitation"}]
        },
        {
          "type": "indicator",
          "id": "indicator--22222222-1111-4111-8111-111111111111",
          "created": "2026-01-01T00:00:00Z",
          "modified": "2026-01-01T00:00:00Z",
          "name": "Regex URL",
          "pattern": "[url:value MATCHES 'https?://[^\\s]*evil-db\\.example']",
          "pattern_type": "stix",
          "labels": ["sqli"]
        },
        {
          "type": "indicator",
          "id": "indicator--33333333-1111-4111-8111-111111111111",
          "created": "2026-01-01T00:00:00Z",
          "modified": "2026-01-01T00:00:00Z",
          "name": "SHA256 IOC",
          "pattern": "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
          "pattern_type": "stix",
          "labels": ["command_injection"]
        },
        {
          "type": "threat-actor",
          "id": "threat-actor--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          "created": "2026-01-01T00:00:00Z",
          "modified": "2026-01-01T00:00:00Z",
          "name": "APT Example",
          "aliases": ["Blue Fox", "fingerprint:fp-123"],
          "sophistication": "advanced",
          "resource_level": "organization",
          "primary_motivation": "organizational-gain"
        },
        {
          "type": "attack-pattern",
          "id": "attack-pattern--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          "created": "2026-01-01T00:00:00Z",
          "modified": "2026-01-01T00:00:00Z",
          "name": "SQL Injection over login",
          "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1190"}
          ],
          "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "exploitation"}]
        },
        {
          "type": "relationship",
          "id": "relationship--cccccccc-cccc-4ccc-8ccc-cccccccccccc",
          "created": "2026-01-01T00:00:00Z",
          "modified": "2026-01-01T00:00:00Z",
          "relationship_type": "uses",
          "source_ref": "threat-actor--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          "target_ref": "fp-abc"
        }
      ]
    }"#;

    fn feed() -> ThreatIntelFeed {
        let mut feed = ThreatIntelFeed::new();
        feed.ingest_stix_bundle(STIX_BUNDLE);
        feed
    }

    fn feed_from(bundle: &str) -> ThreatIntelFeed {
        let mut feed = ThreatIntelFeed::new();
        feed.ingest_stix_bundle(bundle);
        feed
    }

    #[test]
    fn parses_stix_bundle_objects() {
        let feed = feed();
        assert_eq!(feed.indicators.len(), 3);
        assert_eq!(feed.threat_actors.len(), 1);
        assert_eq!(feed.attack_patterns.len(), 1);
        assert_eq!(feed.relationships.len(), 1);
    }

    #[test]
    fn parses_attack_pattern_external_refs() {
        let feed = feed();
        assert_eq!(feed.attack_patterns[0].external_references, vec!["T1190"]);
        assert_eq!(
            feed.attack_patterns[0].kill_chain_phases,
            vec!["exploitation"]
        );
    }

    #[test]
    fn matches_domain_ioc_case_insensitive() {
        let feed = feed();
        let hits = feed.match_detection(
            InvariantClass::SqlTautology,
            "POST /login host EVIL-DB.EXAMPLE payload",
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].id,
            "indicator--11111111-1111-4111-8111-111111111111"
        );
    }

    #[test]
    fn matches_regex_ioc() {
        let feed = feed();
        let hits = feed.match_detection(
            InvariantClass::SqlStringTermination,
            "GET https://cdn.evil-db.example/dropper",
        );
        assert!(
            hits.iter()
                .any(|h| h.id == "indicator--22222222-1111-4111-8111-111111111111")
        );
    }

    #[test]
    fn matches_sha256_hash_ioc() {
        let feed = feed();
        let hits = feed.match_detection(
            InvariantClass::CmdSeparator,
            "hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].id,
            "indicator--33333333-1111-4111-8111-111111111111"
        );
    }

    #[test]
    fn class_label_filtering_blocks_unrelated_ioc() {
        let feed = feed();
        let hits = feed.match_detection(
            InvariantClass::XssTagInjection,
            "GET https://evil-db.example/index.html",
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn campaign_actor_lookup_by_relationship() {
        let feed = feed();
        let actor = feed
            .get_threat_actor_for_campaign("fp-abc")
            .expect("actor should resolve");
        assert_eq!(actor.name, "APT Example");
    }

    #[test]
    fn campaign_actor_lookup_by_alias_fingerprint() {
        let feed = feed();
        let actor = feed
            .get_threat_actor_for_campaign("fp-123")
            .expect("actor should resolve");
        assert_eq!(
            actor.id,
            "threat-actor--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
    }

    #[test]
    fn kill_chain_context_maps_classes_and_patterns() {
        let feed = feed();
        let ctx = feed.get_kill_chain_context(&[InvariantClass::SqlUnionExtraction]);
        assert!(ctx.phases.contains(&AttackPhase::Exploitation));
        assert!(
            ctx.attack_pattern_ids
                .iter()
                .any(|id| id.starts_with("attack-pattern--"))
        );
        assert!(ctx.mitre_attack_ids.contains(&"T1190".to_string()));
    }

    #[test]
    fn ioc_confidence_boost_zero_without_match() {
        let feed = feed();
        let boost = feed.ioc_confidence_boost(InvariantClass::SqlTautology, "safe.example");
        assert_eq!(boost, 0.0);
    }

    #[test]
    fn ioc_confidence_boost_positive_with_match() {
        let feed = feed();
        let boost = feed.ioc_confidence_boost(InvariantClass::SqlTautology, "evil-db.example");
        assert!(boost > 0.0);
    }

    #[test]
    fn handles_invalid_bundle_gracefully() {
        let mut feed = ThreatIntelFeed::new();
        feed.ingest_stix_bundle("not-json");
        assert!(feed.indicators.is_empty());
        assert!(feed.threat_actors.is_empty());
    }

    #[test]
    fn matches_cidr_ip_ioc() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"CIDR IOC",
              "pattern":"[ipv4-addr:value = '192.168.0.0/16']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(InvariantClass::SqlTautology, "src_ip=192.168.2.25");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn matches_wildcard_domain_ioc() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Wildcard Domain IOC",
              "pattern":"[domain-name:value = '*.evil.com']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(
            InvariantClass::SqlTautology,
            "host=a.b.c.evil.com method=POST",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn normalizes_url_for_eq_matching() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--cccccccc-1111-4111-8111-cccccccccccc",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--cccccccc-1111-4111-8111-cccccccccccc",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"URL IOC",
              "pattern":"[url:value = 'https://evil.com/login']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(
            InvariantClass::SqlTautology,
            "GET https://EVIL.com:443/login/",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn matches_md5_hash_ioc_from_body() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--dddddddd-1111-4111-8111-dddddddddddd",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--dddddddd-1111-4111-8111-dddddddddddd",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"MD5 IOC",
              "pattern":"[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
              "pattern_type":"stix",
              "labels":["command_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(
            InvariantClass::CmdSeparator,
            "upload_body=hash:d41d8cd98f00b204e9800998ecf8427e",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn matches_email_ioc() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--eeeeeeee-1111-4111-8111-eeeeeeeeeeee",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--eeeeeeee-1111-4111-8111-eeeeeeeeeeee",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Email IOC",
              "pattern":"[email-addr:value = 'bad.actor@evil.com']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(
            InvariantClass::SqlTautology,
            "params=user=alice&email=Bad.Actor@evil.com",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn skips_expired_indicator() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--ffffffff-1111-4111-8111-ffffffffffff",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--ffffffff-1111-4111-8111-ffffffffffff",
              "created":"2024-01-01T00:00:00Z",
              "modified":"2024-01-01T00:00:00Z",
              "name":"Expired IOC",
              "pattern":"[domain-name:value = 'expired.evil.com']",
              "pattern_type":"stix",
              "valid_until":"2024-01-02T00:00:00Z",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(InvariantClass::SqlTautology, "expired.evil.com");
        assert!(hits.is_empty());
    }

    #[test]
    fn stix_validation_skips_objects_missing_required_fields() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--12121212-1111-4111-8111-121212121212",
          "spec_version":"2.1",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--12121212-1111-4111-8111-121212121212",
              "name":"Invalid Missing created/modified",
              "pattern":"[domain-name:value = 'bad.evil.com']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        assert!(feed.indicators.is_empty());
    }

    #[test]
    fn confidence_weighting_favors_high_confidence_iocs() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--13131313-1111-4111-8111-131313131313",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--13131313-1111-4111-8111-131313131313",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Low confidence",
              "pattern":"[domain-name:value = 'low.evil.com']",
              "pattern_type":"stix",
              "confidence": 10,
              "labels":["sql_injection"]
            },
            {
              "type":"indicator",
              "id":"indicator--14141414-1111-4111-8111-141414141414",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"High confidence",
              "pattern":"[domain-name:value = 'high.evil.com']",
              "pattern_type":"stix",
              "confidence": 95,
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let low = feed.ioc_confidence_boost(InvariantClass::SqlTautology, "low.evil.com");
        let high = feed.ioc_confidence_boost(InvariantClass::SqlTautology, "high.evil.com");
        assert!(high > low);
    }

    #[test]
    fn matches_ipv6_mapped_ipv4_cidr() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--aabbccdd-1111-4111-8111-aabbccddeeff",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"IPv4 CIDR",
              "pattern":"[ipv4-addr:value = '203.0.113.0/24']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(InvariantClass::SqlTautology, "src=::ffff:203.0.113.12");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn wildcard_domain_ioc_does_not_match_base_domain() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--bbccddee-1111-4111-8111-bbccddeeff00",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Wildcard Domain IOC",
              "pattern":"[domain-name:value = '*.wild.example']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(InvariantClass::SqlTautology, "GET wild.example");
        assert!(hits.is_empty());
    }

    #[test]
    fn hash_eq_is_case_insensitive() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--cccccccc-1111-4111-8111-cccccccccccc",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--ccddeeff-1111-4111-8111-ccddeeff1122",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"MD5 IOC",
              "pattern":"[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
              "pattern_type":"stix",
              "labels":["command_injection"]
            }
          ]
        }"#;
        assert!(
            !parse_stix_pattern_subset("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")
                .is_empty()
        );
        let feed = feed_from(bundle);
        assert_eq!(feed.indicators.len(), 1);
        assert!(indicator_relevant_to_class(
            &feed.indicators[0],
            &class_match_tokens(InvariantClass::CmdSeparator)
        ));
        let artifacts = build_input_artifacts("value=D41D8CD98F00B204E9800998ECF8427E");
        assert!(
            artifacts
                .hashes
                .md5
                .contains("d41d8cd98f00b204e9800998ecf8427e")
        );
        let hits = feed.match_detection(
            InvariantClass::CmdSeparator,
            "value=D41D8CD98F00B204E9800998ECF8427E",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn hash_matches_regex_case_insensitive() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--dddddddd-1111-4111-8111-dddddddddddd",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--ddeeff00-1111-4111-8111-ddeeff001122",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"MD5 regex",
              "pattern":"[file:hashes.MD5 MATCHES '^[A-F0-9]{32}$']",
              "pattern_type":"stix",
              "labels":["command_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let artifacts = build_input_artifacts("hash=ABCDEF0123456789ABCDEF0123456789");
        assert!(
            artifacts
                .hashes
                .all
                .contains("abcdef0123456789abcdef0123456789")
        );
        let hits = feed.match_detection(
            InvariantClass::CmdSeparator,
            "hash=ABCDEF0123456789ABCDEF0123456789",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn url_ioc_matches_percent_encoded_path() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--eeeeeeee-1111-4111-8111-eeeeeeeeeeee",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--eeff0011-1111-4111-8111-eeff00112233",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Encoded URL",
              "pattern":"[url:value = 'https://evil.example/login']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let artifacts = build_input_artifacts("GET https://evil.example/%6c%6f%67%69%6e?x=1");
        assert!(artifacts.urls.contains("https://evil.example/login"));
        let hits = feed.match_detection(
            InvariantClass::SqlTautology,
            "GET https://evil.example/%6c%6f%67%69%6e?x=1",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn matches_bitcoin_wallet_ioc_legacy_and_bech32() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--ffffffff-1111-4111-8111-ffffffffffff",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--ffaabbcc-1111-4111-8111-ffaabbcc1122",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"BTC Legacy",
              "pattern":"[wallet-address:value = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            },
            {
              "type":"indicator",
              "id":"indicator--1122aabb-1111-4111-8111-1122aabb3344",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"BTC Segwit",
              "pattern":"[wallet-address:value = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let artifacts = build_input_artifacts(
            "wallet=1BoatSLRHtKNngkdXEeobR76b53LETtpyT&wallet=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        );
        assert!(
            artifacts
                .wallet_addresses
                .contains("1boatslrhtknngkdxeeobr76b53lettpyt")
        );
        assert!(
            artifacts
                .wallet_addresses
                .contains("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        );
        let hits1 = feed.match_detection(
            InvariantClass::SqlTautology,
            "wallet=1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        );
        let hits2 = feed.match_detection(
            InvariantClass::SqlTautology,
            "wallet=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        );
        assert_eq!(hits1.len(), 1);
        assert_eq!(hits2.len(), 1);
    }

    #[test]
    fn matches_ja3_and_ja3s_ioc_fields() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--12121212-1111-4111-8111-121212121212",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--11aa22bb-1111-4111-8111-11aa22bb3344",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"JA3 IOC",
              "pattern":"[network-traffic:extensions.'ja3' = 'abcdef0123456789abcdef0123456789']",
              "pattern_type":"stix",
              "labels":["ssrf"]
            },
            {
              "type":"indicator",
              "id":"indicator--11aa22bb-1111-4111-8111-11aa22bb5566",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"JA3S IOC",
              "pattern":"[network-traffic:extensions.'ja3s' = '1234567890abcdef1234567890abcdef']",
              "pattern_type":"stix",
              "labels":["ssrf"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let artifacts = build_input_artifacts("ja3=ABCDEF0123456789ABCDEF0123456789");
        assert!(artifacts.ja3.contains("abcdef0123456789abcdef0123456789"));
        let hits = feed.match_detection(
            InvariantClass::SsrfInternalReach,
            "ja3=ABCDEF0123456789ABCDEF0123456789|ja3s=1234567890abcdef1234567890ABCDEF",
        );
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn matches_asn_ioc_field() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--13131313-1111-4111-8111-131313131313",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--13aa14bb-1111-4111-8111-13aa14bb1523",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"ASN IOC",
              "pattern":"[autonomous-system-number:number = 'AS13335']",
              "pattern_type":"stix",
              "labels":["command_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let artifacts = build_input_artifacts("peer AS13335 connected");
        assert!(artifacts.asns.contains("13335"));
        let hits = feed.match_detection(InvariantClass::CmdSeparator, "peer AS13335 connected");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn matches_certificate_sha256_ioc() {
        let cert_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--14141414-1111-4111-8111-141414141414",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--14aa15bb-1111-4111-8111-14aa15bb1666",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Cert Hash IOC",
              "pattern":"[x509-certificate:hashes.'SHA-256' = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef']",
              "pattern_type":"stix",
              "labels":["command_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let artifacts = build_input_artifacts(&format!("cert_sha256={}", cert_hash));
        assert!(artifacts.cert_sha256.contains(cert_hash));
        let hits = feed.match_detection(
            InvariantClass::CmdSeparator,
            format!("cert_sha256={}", cert_hash).as_str(),
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn yara_rule_matcher_integration_point() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--15151515-1111-4111-8111-151515151515",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--15151515-1111-4111-8111-151515151515",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"YARA IOC",
              "pattern":"rule suspicious { strings: $x = \"suspicious.exe\" condition: $x }",
              "pattern_type":"yara",
              "labels":["command_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);

        let direct = feed.match_detection(
            InvariantClass::CmdSeparator,
            "request contains suspicious.exe indicator",
        );
        assert!(direct.is_empty());

        let with_yara = feed.match_detection_with_yara_matcher(
            InvariantClass::CmdSeparator,
            "request contains suspicious.exe indicator",
            |rule, input| input.contains("suspicious.exe") && rule.contains("suspicious.exe"),
        );
        assert_eq!(with_yara.len(), 1);
    }

    #[test]
    fn rejects_indicator_with_invalid_stix_id_or_pattern() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--16161616-1111-4111-8111-161616161616",
          "objects":[
            {
              "type":"indicator",
              "id":"not-a-valid-id",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Invalid ID IOC",
              "pattern":"[domain-name:value = 'bad.evil.com']",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            },
            {
              "type":"indicator",
              "id":"indicator--17171717-1111-4111-8111-171717171717",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Invalid Pattern IOC",
              "pattern":"[domain-name:value = 'bad.evil.com' AND]"},
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        assert!(feed.indicators.is_empty());
    }

    #[test]
    fn malformed_pattern_clauses_do_not_partially_match() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--18181818-1111-4111-8111-181818181818",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--18181818-1111-4111-8111-181818181818",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Injected IOC",
              "pattern":"[domain-name:value = 'evil.com' AND [x='y'] ]",
              "pattern_type":"stix",
              "labels":["sql_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        let hits = feed.match_detection(InvariantClass::SqlTautology, "host evil.com");
        assert!(hits.is_empty());
    }

    #[test]
    fn rejects_stix_pattern_with_injected_regex() {
        let bundle = r#"{
          "type":"bundle",
          "id":"bundle--19191919-1111-4111-8111-191919191919",
          "objects":[
            {
              "type":"indicator",
              "id":"indicator--19191919-1111-4111-8111-191919191919",
              "created":"2026-01-01T00:00:00Z",
              "modified":"2026-01-01T00:00:00Z",
              "name":"Injected Regex IOC",
              "pattern":"[file:hashes.MD5 MATCHES '(?<=abc)[a-z]{1,10}']",
              "pattern_type":"stix",
              "labels":["command_injection"]
            }
          ]
        }"#;
        let feed = feed_from(bundle);
        assert!(feed.indicators.is_empty());
    }

    #[test]
    fn _debug_stix_pattern_parse() {
        let patterns = [
            "[domain-name:value = '*.evil.com']",
            "[ipv4-addr:value = '192.168.0.0/16']",
            "[url:value = 'https://evil.com/login']",
            "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "[network-traffic:extensions.'ja3' = 'abcdef0123456789abcdef0123456789ab']",
            "[file:hashes.MD5 MATCHES '^[A-F0-9]{32}$']",
            "[wallet-address:value = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT']",
            "[network-traffic:extensions.'ja3s' = '1234567890abcdef1234567890abcdef']",
            "[autonomous-system-number:number = 'AS13335']",
            "[x509-certificate:hashes.'SHA-256' = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef']",
            "[url:value = 'https://evil.example/login']",
        ];

        for pattern in patterns {
            assert!(
                !parse_stix_pattern_subset(pattern).is_empty(),
                "pattern failed to parse: {pattern}"
            );
        }

        let md5_eq =
            parse_stix_pattern_subset("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']");
        assert!(matches!(md5_eq[0], PatternExpr::Eq(PatternField::Md5, _)));

        let md5_matches = parse_stix_pattern_subset("[file:hashes.MD5 MATCHES '^[A-F0-9]{32}$']");
        assert!(matches!(
            md5_matches[0],
            PatternExpr::Matches(PatternField::Md5, _)
        ));

        let wallet = parse_stix_pattern_subset(
            "[wallet-address:value = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT']",
        );
        assert!(matches!(
            wallet[0],
            PatternExpr::Eq(PatternField::WalletAddress, _)
        ));

        let asn = parse_stix_pattern_subset("[autonomous-system-number:number = 'AS13335']");
        assert!(matches!(asn[0], PatternExpr::Eq(PatternField::Asn, _)));

        let cert = parse_stix_pattern_subset(
            "[x509-certificate:hashes.'SHA-256' = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef']",
        );
        assert!(matches!(
            cert[0],
            PatternExpr::Eq(PatternField::CertSha256, _)
        ));
    }
}
