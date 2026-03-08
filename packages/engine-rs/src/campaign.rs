//! Attack Campaign Intelligence
//!
//! Individual attack signals are noise. Campaigns are signal.
//!
//! This module detects coordinated attacks by:
//!   1. Behavioral Fingerprinting — how an attacker behaves (timing, ordering,
//!      encoding preferences) persists across IP changes.
//!   2. Attack Phase Modeling — real attacks follow a progression:
//!      recon → probe → exploit → exfil. We model this state machine.
//!   3. Campaign Correlation — same behavioral fingerprint across multiple
//!      IPs = same actor. Same payload across multiple sensors = campaign.
//!   4. Escalation Signal — when enough evidence accumulates, the system
//!      escalates defense posture automatically.

use std::collections::{HashMap, HashSet};

// ── Types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingPreference {
    Plain,
    UrlSingle,
    UrlDouble,
    Unicode,
    Hex,
    HtmlEntity,
    Base64,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttackPhase {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandControl,
    Exfiltration,
}

impl AttackPhase {
    fn ordinal(self) -> usize {
        match self {
            Self::Reconnaissance => 0,
            Self::Weaponization => 1,
            Self::Delivery => 2,
            Self::Exploitation => 3,
            Self::Installation => 4,
            Self::CommandControl => 5,
            Self::Exfiltration => 6,
        }
    }

    const COUNT: usize = 7;
}

/// A behavioral fingerprint captures HOW an attacker behaves,
/// not just what they send. This persists across IP changes.
#[derive(Debug, Clone)]
pub struct BehavioralFingerprint {
    pub hash: String,
    pub avg_interval_ms: f64,
    pub interval_std_dev: f64,
    pub encoding_preferences: Vec<EncodingPreference>,
    pub technique_ordering: Vec<String>,
    pub tool_signature: Option<String>,
    pub evasion_level: f64,
    pub header_pattern: String,
    pub observations: usize,
}

impl Default for BehavioralFingerprint {
    fn default() -> Self {
        Self {
            hash: String::new(),
            avg_interval_ms: 0.0,
            interval_std_dev: 0.0,
            encoding_preferences: Vec::new(),
            technique_ordering: Vec::new(),
            tool_signature: None,
            evasion_level: 0.0,
            header_pattern: String::new(),
            observations: 0,
        }
    }
}

/// A signal from the detection pipeline.
#[derive(Debug, Clone)]
pub struct CampaignSignal {
    pub signal_type: String,
    pub timestamp: u64,
    pub confidence: f64,
    pub path: String,
    pub source_hash: String,
    pub encoding: EncodingPreference,
}

/// A tracked attacker session with behavioral modeling.
#[derive(Debug, Clone)]
pub struct AttackerSession {
    pub source_hash: String,
    pub associated_hashes: HashSet<String>,
    pub fingerprint: BehavioralFingerprint,
    pub current_phase: AttackPhase,
    pub phase_history: Vec<PhaseEntry>,
    pub signals: Vec<CampaignSignal>,
    pub threat_level: f64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub fingerprint_history: Vec<String>,
    pub false_flag_pressure: f64,
    pub noise_events: usize,
    pub resumed_from_dormancy: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PhaseEntry {
    pub phase: AttackPhase,
    pub timestamp: u64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignType {
    CoordinatedScan,
    DistributedAttack,
    AdaptiveMutation,
    ProgressiveAttack,
    DormantResurgence,
    BruteForce,
    ZeroDayProbe,
    FalseFlagCampaign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CampaignSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// A detected campaign — coordinated attack across sources or sensors.
#[derive(Debug, Clone)]
pub struct Campaign {
    pub id: String,
    pub campaign_type: CampaignType,
    pub fingerprints: Vec<String>,
    pub source_count: usize,
    pub attack_types: Vec<String>,
    pub target_paths: Vec<String>,
    pub start_time: u64,
    pub last_activity: u64,
    pub severity: CampaignSeverity,
    pub description: String,
    pub escalated: bool,
}

/// Campaign intelligence statistics.
#[derive(Debug, Clone)]
pub struct CampaignStats {
    pub active_sessions: usize,
    pub unique_fingerprints: usize,
    pub active_campaigns: usize,
    pub total_signals: usize,
    pub highest_threat_level: f64,
}

// ── Campaign Intelligence Engine ──────────────────────────────────

pub struct CampaignIntelligence {
    sessions: HashMap<String, AttackerSession>,
    fingerprint_index: HashMap<String, HashSet<String>>,
    campaigns: Vec<Campaign>,
    recent_signals: Vec<CampaignSignal>,
    max_signals: usize,
    session_timeout_ms: u64,
    campaign_window_ms: u64,
    dormant_sessions: HashMap<String, DormantCampaignSeed>,
    dormant_window_ms: u64,
    adaptive_mutation_window_ms: u64,
}

#[derive(Debug, Clone)]
struct DormantCampaignSeed {
    fingerprint_hash: String,
    threat_level: f64,
    current_phase: AttackPhase,
    attack_signatures: Vec<String>,
    path_buckets: Vec<String>,
    first_seen: u64,
    last_seen: u64,
}

impl CampaignIntelligence {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            fingerprint_index: HashMap::new(),
            campaigns: Vec::new(),
            recent_signals: Vec::new(),
            max_signals: 10_000,
            session_timeout_ms: 3_600_000,
            campaign_window_ms: 300_000,
            dormant_sessions: HashMap::new(),
            dormant_window_ms: 86_400_000,
            adaptive_mutation_window_ms: 3_000_000,
        }
    }

    /// Record a new signal from the detection pipeline.
    /// This is the main entry point — called for every detection.
    pub fn record_signal(&mut self, signal: CampaignSignal) {
        let source = signal.source_hash.clone();
        let now = signal.timestamp;

        if let Some(session) = self.sessions.get(&source) {
            if now.saturating_sub(session.last_seen) > self.session_timeout_ms {
                self.archive_dormant_session(&source);
            }
        }

        if !self.sessions.contains_key(&source) {
            if let Some(seed) = self.consume_dormant_seed(&source, now) {
                self.sessions
                    .insert(source.clone(), restore_session(&source, &seed, now));
            } else {
                self.sessions
                    .insert(source.clone(), create_session(&source, now));
            }
        }

        let mut reindex_old_fp: Option<String> = None;
        let mut reindex_new_fp: Option<String> = None;
        let mut fingerprint_changed = false;

        {
            let session = self.sessions.get_mut(&source).unwrap();
            if signal.confidence < 0.35 {
                session.false_flag_pressure += 0.5;
                session.noise_events += 1;
            }

            session.signals.push(signal.clone());
            session.last_seen = signal.timestamp;

            let previous_fp = session.fingerprint.hash.clone();
            update_fingerprint(session);
            let new_fp = session.fingerprint.hash.clone();
            let fingerprint_rolled = previous_fp != new_fp;
            if fingerprint_rolled && !previous_fp.is_empty() {
                session.fingerprint_history.push(previous_fp.clone());
                if session.fingerprint_history.len() > 8 {
                    session.fingerprint_history.remove(0);
                }
                reindex_old_fp = Some(previous_fp.clone());
                fingerprint_changed = true;
            }
            if fingerprint_rolled && previous_fp.is_empty() {
                fingerprint_changed = true;
            }
            if !new_fp.is_empty() {
                reindex_new_fp = Some(new_fp.clone());
            }

            advance_phase_model(session, &signal);

            let false_flag_ratio = if session.signals.is_empty() {
                0.0
            } else {
                session.noise_events as f64 / session.signals.len() as f64
            };
            if false_flag_ratio >= 0.6 {
                session.threat_level *= 0.75;
            }
        }

        if fingerprint_changed {
            if let Some(new_fp) = &reindex_new_fp {
                let previous = reindex_old_fp.unwrap_or_else(String::new);
                self.reindex_fingerprint(&source, &previous, new_fp);
            }
        }

        // Buffer for campaign detection
        self.recent_signals.push(signal);
        if self.recent_signals.len() > self.max_signals {
            let half = self.max_signals / 2;
            self.recent_signals = self
                .recent_signals
                .split_off(self.recent_signals.len() - half);
        }

        self.detect_campaigns();
        self.prune_stale_sessions();
    }

    /// Get the threat level for a source.
    pub fn get_threat_level(&self, source_hash: &str) -> f64 {
        self.sessions
            .get(source_hash)
            .map(|s| s.threat_level)
            .unwrap_or(0.0)
    }

    /// Get the current attack phase for a source.
    pub fn get_attack_phase(&self, source_hash: &str) -> Option<AttackPhase> {
        self.sessions.get(source_hash).map(|s| s.current_phase)
    }

    /// Check if a source is part of a known campaign.
    pub fn is_part_of_campaign(&self, source_hash: &str) -> Option<&Campaign> {
        let session = self.sessions.get(source_hash)?;
        self.campaigns
            .iter()
            .find(|c| c.fingerprints.contains(&session.fingerprint.hash))
    }

    /// Get all active campaigns within the detection window.
    pub fn get_active_campaigns(&self, now: u64) -> Vec<&Campaign> {
        self.campaigns
            .iter()
            .filter(|c| now.saturating_sub(c.last_activity) < self.campaign_window_ms)
            .collect()
    }

    /// Cross-sensor signal: same payload detected at another sensor.
    pub fn record_cross_sensor_signal(&mut self, signal_type: &str, now: u64) {
        let matching: Vec<&CampaignSignal> = self
            .recent_signals
            .iter()
            .filter(|s| {
                s.signal_type == signal_type
                    && now.saturating_sub(s.timestamp) < self.campaign_window_ms
            })
            .collect();

        if matching.len() >= 3 {
            let source_set: HashSet<&str> =
                matching.iter().map(|s| s.source_hash.as_str()).collect();
            let path_set: HashSet<&str> = matching.iter().map(|s| s.path.as_str()).collect();
            let start = matching.iter().map(|s| s.timestamp).min().unwrap_or(now);

            let campaign = Campaign {
                id: format!("campaign-{}-{}", now, signal_type),
                campaign_type: CampaignType::DistributedAttack,
                fingerprints: source_set.iter().map(|s| s.to_string()).collect(),
                source_count: source_set.len(),
                attack_types: vec![signal_type.to_string()],
                target_paths: path_set.iter().map(|s| s.to_string()).collect(),
                start_time: start,
                last_activity: now,
                severity: CampaignSeverity::High,
                description: format!(
                    "Distributed {} campaign: {} attacks from {} sources",
                    signal_type,
                    matching.len(),
                    source_set.len()
                ),
                escalated: false,
            };
            self.campaigns.push(campaign);
        }
    }

    /// Get campaign statistics.
    pub fn get_stats(&self, now: u64) -> CampaignStats {
        let highest = self
            .sessions
            .values()
            .map(|s| s.threat_level)
            .fold(0.0_f64, f64::max);

        CampaignStats {
            active_sessions: self.sessions.len(),
            unique_fingerprints: self.fingerprint_index.len(),
            active_campaigns: self.get_active_campaigns(now).len(),
            total_signals: self.recent_signals.len(),
            highest_threat_level: highest,
        }
    }

    // ── Campaign Detection ────────────────────────────────────────

    fn detect_campaigns(&mut self) {
        let now = self.recent_signals.last().map(|s| s.timestamp).unwrap_or(0);
        self.detect_adaptive_mutation_campaigns(now);
        self.detect_dormant_resurgence_campaigns(now);
        self.detect_false_flag_campaigns();

        // Coordinated scans: same fingerprint, multiple IPs
        let fp_snapshot: Vec<(String, Vec<String>)> = self
            .fingerprint_index
            .iter()
            .filter(|(_, sources)| sources.len() >= 3)
            .map(|(hash, sources)| (hash.clone(), sources.iter().cloned().collect()))
            .collect();

        for (fp_hash, sources) in fp_snapshot {
            let already_tracked = self.campaigns.iter().any(|c| {
                c.campaign_type == CampaignType::CoordinatedScan
                    && c.fingerprints.contains(&fp_hash)
            });
            if already_tracked {
                continue;
            }

            let mut attack_types = HashSet::new();
            let mut target_paths = HashSet::new();
            let mut first_seen = u64::MAX;
            let mut last_seen = 0u64;

            for src in &sources {
                if let Some(session) = self.sessions.get(src) {
                    for sig in &session.signals {
                        attack_types.insert(sig.signal_type.clone());
                        target_paths.insert(sig.path.clone());
                    }
                    first_seen = first_seen.min(session.first_seen);
                    last_seen = last_seen.max(session.last_seen);
                }
            }

            let sev = if attack_types
                .iter()
                .any(|t| t.starts_with("sql_") || t.starts_with("deser_"))
            {
                CampaignSeverity::Critical
            } else {
                CampaignSeverity::High
            };

            self.campaigns.push(Campaign {
                id: format!(
                    "campaign-{}-{}",
                    last_seen,
                    &fp_hash[..fp_hash.len().min(8)]
                ),
                campaign_type: CampaignType::CoordinatedScan,
                fingerprints: vec![fp_hash],
                source_count: sources.len(),
                attack_types: attack_types.into_iter().collect(),
                target_paths: target_paths.into_iter().collect(),
                start_time: first_seen,
                last_activity: last_seen,
                severity: sev,
                description: format!(
                    "Coordinated scan from {} sources with identical behavioral fingerprint",
                    sources.len()
                ),
                escalated: false,
            });
        }

        // Brute force: high volume from single source
        let brute_candidates: Vec<(String, String, usize, u64, u64, Vec<String>, Vec<String>)> =
            self.sessions
                .iter()
                .filter_map(|(hash, session)| {
                    let now = session.last_seen;
                    let recent_count = session
                        .signals
                        .iter()
                        .filter(|s| now.saturating_sub(s.timestamp) < self.campaign_window_ms)
                        .count();
                    if recent_count >= 50 {
                        let at: Vec<String> = session
                            .signals
                            .iter()
                            .map(|s| s.signal_type.clone())
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .collect();
                        let tp: Vec<String> = session
                            .signals
                            .iter()
                            .map(|s| s.path.clone())
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .collect();
                        Some((
                            hash.clone(),
                            session.fingerprint.hash.clone(),
                            recent_count,
                            session.first_seen,
                            session.last_seen,
                            at,
                            tp,
                        ))
                    } else {
                        None
                    }
                })
                .collect();

        for (hash, fp_hash, count, first, last, attack_types, target_paths) in brute_candidates {
            let already_tracked = self.campaigns.iter().any(|c| {
                c.campaign_type == CampaignType::BruteForce && c.fingerprints.contains(&fp_hash)
            });
            if already_tracked {
                continue;
            }

            self.campaigns.push(Campaign {
                id: format!("campaign-{}-bf-{}", last, &hash[..hash.len().min(8)]),
                campaign_type: CampaignType::BruteForce,
                fingerprints: vec![fp_hash],
                source_count: 1,
                attack_types,
                target_paths,
                start_time: first,
                last_activity: last,
                severity: CampaignSeverity::High,
                description: format!(
                    "Brute force: {} attacks from {} in {}s",
                    count,
                    &hash[..hash.len().min(8)],
                    self.campaign_window_ms / 1000
                ),
                escalated: false,
            });
        }
    }

    fn detect_adaptive_mutation_campaigns(&mut self, now: u64) {
        for (source, session) in self.sessions.iter() {
            if session.signals.len() < 4 || session.fingerprint_history.len() < 1 {
                continue;
            }
            if now.saturating_sub(session.first_seen) > self.adaptive_mutation_window_ms {
                continue;
            }

            let mut fingerprints = session.fingerprint_history.clone();
            fingerprints.push(session.fingerprint.hash.clone());
            fingerprints.sort_unstable();
            fingerprints.dedup();

            if fingerprints.len() < 2 {
                continue;
            }

            let high_conf = session
                .signals
                .iter()
                .filter(|s| s.confidence >= 0.6)
                .count();
            let low_conf = session
                .signals
                .iter()
                .filter(|s| s.confidence < 0.6)
                .count();
            if low_conf > high_conf {
                continue;
            }

            let already = self.campaigns.iter().any(|c| {
                c.campaign_type == CampaignType::AdaptiveMutation
                    && c.fingerprints.len() == fingerprints.len()
                    && c.fingerprints
                        .iter()
                        .all(|fp| fingerprints.iter().any(|f| f == fp))
            });
            if already {
                continue;
            }

            let attack_types: Vec<String> = session
                .signals
                .iter()
                .filter(|s| s.confidence >= 0.6)
                .map(|s| s.signal_type.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            let target_paths: Vec<String> = session
                .signals
                .iter()
                .map(|s| path_bucket(&s.path))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            self.campaigns.push(Campaign {
                id: format!(
                    "campaign-{}-adaptive-{}",
                    now,
                    &source[..source.len().min(8)]
                ),
                campaign_type: CampaignType::AdaptiveMutation,
                fingerprints,
                source_count: 1,
                attack_types,
                target_paths,
                start_time: session.first_seen,
                last_activity: session.last_seen,
                severity: CampaignSeverity::High,
                description: format!(
                    "Adaptive mutation detected for {} from {} fingerprints",
                    source,
                    session.fingerprint_history.len() + 1
                ),
                escalated: session.threat_level > 65.0,
            });
        }
    }

    fn detect_dormant_resurgence_campaigns(&mut self, now: u64) {
        for (source, session) in self.sessions.iter_mut() {
            let resumed = match session.resumed_from_dormancy {
                Some(ts) => ts,
                None => continue,
            };

            if now.saturating_sub(resumed) > self.dormant_window_ms {
                session.resumed_from_dormancy = None;
                continue;
            }

            if self.campaigns.iter().any(|c| {
                c.campaign_type == CampaignType::DormantResurgence
                    && c.fingerprints.contains(&session.fingerprint.hash)
            }) {
                session.resumed_from_dormancy = None;
                continue;
            }

            let resumed_path = session
                .signals
                .last()
                .map(|s| path_bucket(&s.path))
                .unwrap_or_else(|| "/".into());

            self.campaigns.push(Campaign {
                id: format!(
                    "campaign-{}-resurgence-{}",
                    now,
                    &source[..source.len().min(6)]
                ),
                campaign_type: CampaignType::DormantResurgence,
                fingerprints: vec![session.fingerprint.hash.clone()],
                source_count: 1,
                attack_types: vec!["campaign_resurgence".into()],
                target_paths: vec![resumed_path],
                start_time: session.first_seen,
                last_activity: session.last_seen,
                severity: if session.threat_level >= 65.0 {
                    CampaignSeverity::Critical
                } else {
                    CampaignSeverity::High
                },
                description: format!(
                    "Dormant campaign resumed for {} after {}ms",
                    source,
                    now.saturating_sub(resumed)
                ),
                escalated: true,
            });

            session.resumed_from_dormancy = None;
        }
    }

    fn detect_false_flag_campaigns(&mut self) {
        for (source, session) in self.sessions.iter() {
            let false_ratio = if session.signals.is_empty() {
                0.0
            } else {
                session.noise_events as f64 / session.signals.len() as f64
            };

            if false_ratio < 0.75 || session.signals.len() < 5 {
                continue;
            }

            let already_tracked = self.campaigns.iter().any(|c| {
                c.campaign_type == CampaignType::FalseFlagCampaign
                    && c.fingerprints.contains(&session.fingerprint.hash)
            });
            if already_tracked {
                continue;
            }

            let target_paths = session
                .signals
                .iter()
                .map(|s| path_bucket(&s.path))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            self.campaigns.push(Campaign {
                id: format!(
                    "campaign-{}-false-{}",
                    session.last_seen,
                    &source[..source.len().min(8)]
                ),
                campaign_type: CampaignType::FalseFlagCampaign,
                fingerprints: vec![session.fingerprint.hash.clone()],
                source_count: 1,
                attack_types: vec!["signal_noise".into()],
                target_paths,
                start_time: session.first_seen,
                last_activity: session.last_seen,
                severity: CampaignSeverity::Low,
                description: format!(
                    "False-flag pattern for {}: {:.0}% low-confidence signals",
                    source,
                    false_ratio * 100.0
                ),
                escalated: false,
            });
        }
    }

    fn reindex_fingerprint(&mut self, source: &str, old_hash: &str, new_hash: &str) {
        if !old_hash.is_empty() {
            for sources in self.fingerprint_index.values_mut() {
                sources.remove(source);
            }
        }
        self.fingerprint_index
            .retain(|_, sources| !sources.is_empty());

        if !new_hash.is_empty() {
            self.fingerprint_index
                .entry(new_hash.to_owned())
                .or_default()
                .insert(source.to_owned());
        }
    }

    fn consume_dormant_seed(&mut self, source: &str, now: u64) -> Option<DormantCampaignSeed> {
        if self
            .dormant_sessions
            .get(source)
            .is_some_and(|seed| now.saturating_sub(seed.last_seen) > self.dormant_window_ms)
        {
            self.dormant_sessions.remove(source);
            return None;
        }

        self.dormant_sessions.remove(source)
    }

    fn archive_dormant_session(&mut self, source: &str) {
        if let Some(session) = self.sessions.remove(source) {
            let attack_signatures: Vec<String> = session
                .signals
                .iter()
                .map(|s| s.signal_type.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            let path_buckets: Vec<String> = session
                .signals
                .iter()
                .map(|s| path_bucket(&s.path))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            let seed = DormantCampaignSeed {
                fingerprint_hash: session.fingerprint.hash,
                threat_level: session.threat_level,
                current_phase: session.current_phase,
                attack_signatures,
                path_buckets,
                first_seen: session.first_seen,
                last_seen: session.last_seen,
            };
            self.dormant_sessions.insert(source.to_owned(), seed);

            for sources in self.fingerprint_index.values_mut() {
                sources.remove(source);
            }
            self.fingerprint_index
                .retain(|_, sources| !sources.is_empty());
        }
    }

    fn prune_stale_sessions(&mut self) {
        let now = self.recent_signals.last().map(|s| s.timestamp).unwrap_or(0);
        let timeout = self.session_timeout_ms;

        let stale: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.last_seen) > timeout)
            .map(|(h, _)| h.clone())
            .collect();

        for hash in stale {
            self.archive_dormant_session(&hash);
        }

        self.dormant_sessions.retain(|_, seed| {
            now.saturating_sub(seed.last_seen) <= self.dormant_window_ms.saturating_mul(3)
        });
    }
}

impl Default for CampaignIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

// ── Session Helpers ───────────────────────────────────────────────

fn create_session(source_hash: &str, now: u64) -> AttackerSession {
    let mut associated = HashSet::new();
    associated.insert(source_hash.to_string());

    AttackerSession {
        source_hash: source_hash.to_string(),
        associated_hashes: associated,
        fingerprint: BehavioralFingerprint::default(),
        current_phase: AttackPhase::Reconnaissance,
        phase_history: vec![PhaseEntry {
            phase: AttackPhase::Reconnaissance,
            timestamp: now,
            confidence: 0.5,
        }],
        signals: Vec::new(),
        threat_level: 0.0,
        first_seen: now,
        last_seen: now,
        fingerprint_history: Vec::new(),
        false_flag_pressure: 0.0,
        noise_events: 0,
        resumed_from_dormancy: None,
    }
}

fn restore_session(source_hash: &str, seed: &DormantCampaignSeed, now: u64) -> AttackerSession {
    let mut associated = HashSet::new();
    associated.insert(source_hash.to_string());

    let mut phase_history = Vec::new();
    phase_history.push(PhaseEntry {
        phase: seed.current_phase,
        timestamp: seed.last_seen,
        confidence: 0.8,
    });

    AttackerSession {
        source_hash: source_hash.to_string(),
        associated_hashes: associated,
        fingerprint: BehavioralFingerprint {
            hash: seed.fingerprint_hash.clone(),
            ..BehavioralFingerprint::default()
        },
        current_phase: seed.current_phase,
        phase_history,
        signals: Vec::new(),
        threat_level: seed.threat_level,
        first_seen: seed.first_seen,
        last_seen: now,
        fingerprint_history: Vec::new(),
        false_flag_pressure: 0.0,
        noise_events: 0,
        resumed_from_dormancy: Some(seed.last_seen),
    }
}

fn path_bucket(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }

    let clean = path.trim_end_matches('/');
    if clean.is_empty() {
        return "/".into();
    }

    let mut parts = clean.split('/').filter(|p| !p.is_empty());
    let first = parts.next().unwrap_or("");
    if first.is_empty() {
        "/".into()
    } else {
        format!("/{first}")
    }
}

// ── Fingerprint Construction ──────────────────────────────────────

fn update_fingerprint(session: &mut AttackerSession) {
    if session.signals.len() < 2 {
        return;
    }

    let signals = &session.signals;

    // Timing distribution
    let intervals: Vec<f64> = signals
        .windows(2)
        .map(|w| (w[1].timestamp as f64) - (w[0].timestamp as f64))
        .collect();

    let avg_interval = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let variance = intervals
        .iter()
        .map(|v| (v - avg_interval).powi(2))
        .sum::<f64>()
        / intervals.len() as f64;
    let std_dev = variance.sqrt();

    // Encoding preferences (sorted by frequency)
    let mut encoding_counts: HashMap<EncodingPreference, usize> = HashMap::new();
    for s in signals {
        *encoding_counts.entry(s.encoding).or_insert(0) += 1;
    }
    let mut encoding_prefs: Vec<(EncodingPreference, usize)> =
        encoding_counts.into_iter().collect();
    encoding_prefs.sort_by(|a, b| b.1.cmp(&a.1));
    let encoding_preferences: Vec<EncodingPreference> =
        encoding_prefs.into_iter().map(|(e, _)| e).collect();

    // Technique ordering
    let technique_ordering: Vec<String> = signals.iter().map(|s| s.signal_type.clone()).collect();

    // Evasion sophistication
    let evasion_level = calculate_evasion_level(signals);

    // Build fingerprint hash
    let enc_str: Vec<&str> = encoding_preferences
        .iter()
        .map(|e| match e {
            EncodingPreference::Plain => "plain",
            EncodingPreference::UrlSingle => "url1",
            EncodingPreference::UrlDouble => "url2",
            EncodingPreference::Unicode => "uni",
            EncodingPreference::Hex => "hex",
            EncodingPreference::HtmlEntity => "html",
            EncodingPreference::Base64 => "b64",
            EncodingPreference::Mixed => "mix",
        })
        .collect();

    let fp_data = format!(
        "{}:{}:{}",
        (avg_interval / 100.0) as u64,
        enc_str.join(","),
        (evasion_level * 10.0) as u32
    );
    let hash = simple_hash(&fp_data);

    session.fingerprint = BehavioralFingerprint {
        hash,
        avg_interval_ms: avg_interval,
        interval_std_dev: std_dev,
        encoding_preferences,
        technique_ordering,
        tool_signature: None,
        evasion_level,
        header_pattern: String::new(),
        observations: signals.len(),
    };
}

fn calculate_evasion_level(signals: &[CampaignSignal]) -> f64 {
    let mut level = 0.0_f64;
    let encodings: Vec<EncodingPreference> = signals.iter().map(|s| s.encoding).collect();
    let unique: HashSet<EncodingPreference> = encodings.iter().copied().collect();

    if unique.len() >= 3 {
        level += 0.3;
    } else if unique.len() >= 2 {
        level += 0.15;
    }

    if encodings.iter().any(|e| {
        matches!(
            e,
            EncodingPreference::UrlDouble
                | EncodingPreference::Unicode
                | EncodingPreference::Base64
        )
    }) {
        level += 0.3;
    }

    if encodings
        .iter()
        .any(|e| matches!(e, EncodingPreference::Mixed))
    {
        level += 0.4;
    }

    level.min(1.0)
}

// ── Attack Phase Modeling ─────────────────────────────────────────

fn advance_phase_model(session: &mut AttackerSession, signal: &CampaignSignal) {
    let phase = classify_signal_phase(&signal.signal_type);
    let current_idx = session.current_phase.ordinal();
    let new_idx = phase.ordinal();

    if new_idx > current_idx {
        session.current_phase = phase;
        session.phase_history.push(PhaseEntry {
            phase,
            timestamp: signal.timestamp,
            confidence: signal.confidence,
        });
        session.threat_level =
            ((new_idx as f64) / (AttackPhase::COUNT as f64 - 1.0) * 100.0).min(100.0);
    } else {
        session.threat_level = (session.threat_level + signal.confidence * 5.0).min(100.0);
    }
}

fn classify_signal_phase(signal_type: &str) -> AttackPhase {
    if signal_type.contains("scanner")
        || signal_type.contains("information_disclosure")
        || signal_type.contains("enum")
        || signal_type == "graphql_introspection"
    {
        return AttackPhase::Reconnaissance;
    }

    if signal_type.starts_with("sql_")
        || signal_type.starts_with("xss_")
        || signal_type.starts_with("cmd_")
        || signal_type.starts_with("ssrf_")
        || signal_type.starts_with("ssti_")
        || signal_type.starts_with("xxe_")
        || signal_type.starts_with("deser_")
        || signal_type == "log_jndi"
    {
        return AttackPhase::Delivery;
    }

    if signal_type.contains("file_upload") || signal_type.contains("webshell") {
        return AttackPhase::Installation;
    }

    if signal_type.starts_with("auth_") {
        return AttackPhase::Exploitation;
    }

    AttackPhase::Reconnaissance
}

// ── Hash ──────────────────────────────────────────────────────────

fn simple_hash(input: &str) -> String {
    let mut hash: i32 = 0;
    for b in input.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as i32);
    }
    format!("{:x}", hash.unsigned_abs())
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signal(
        sig_type: &str,
        ts: u64,
        source: &str,
        enc: EncodingPreference,
    ) -> CampaignSignal {
        CampaignSignal {
            signal_type: sig_type.to_string(),
            timestamp: ts,
            confidence: 0.9,
            path: "/api/login".to_string(),
            source_hash: source.to_string(),
            encoding: enc,
        }
    }

    #[test]
    fn session_creation_on_first_signal() {
        let mut ci = CampaignIntelligence::new();
        ci.record_signal(make_signal(
            "sql_tautology",
            1000,
            "src1",
            EncodingPreference::Plain,
        ));
        assert_eq!(ci.sessions.len(), 1);
        assert!(ci.get_threat_level("src1") >= 0.0);
    }

    #[test]
    fn phase_advances_with_signals() {
        let mut ci = CampaignIntelligence::new();
        ci.record_signal(make_signal(
            "scanner_probe",
            1000,
            "src1",
            EncodingPreference::Plain,
        ));
        assert_eq!(
            ci.get_attack_phase("src1"),
            Some(AttackPhase::Reconnaissance)
        );

        ci.record_signal(make_signal(
            "sql_union",
            2000,
            "src1",
            EncodingPreference::UrlSingle,
        ));
        assert_eq!(ci.get_attack_phase("src1"), Some(AttackPhase::Delivery));
    }

    #[test]
    fn fingerprint_updates_after_two_signals() {
        let mut ci = CampaignIntelligence::new();
        ci.record_signal(make_signal(
            "sql_tautology",
            1000,
            "src1",
            EncodingPreference::Plain,
        ));
        ci.record_signal(make_signal(
            "sql_union",
            2000,
            "src1",
            EncodingPreference::UrlSingle,
        ));

        let session = ci.sessions.get("src1").unwrap();
        assert_eq!(session.fingerprint.observations, 2);
        assert!(!session.fingerprint.hash.is_empty());
        assert!(session.fingerprint.avg_interval_ms > 0.0);
    }

    #[test]
    fn evasion_level_increases_with_encoding_variety() {
        let signals = vec![
            make_signal("a", 100, "x", EncodingPreference::Plain),
            make_signal("b", 200, "x", EncodingPreference::UrlDouble),
            make_signal("c", 300, "x", EncodingPreference::Base64),
        ];
        let level = calculate_evasion_level(&signals);
        assert!(
            level >= 0.6,
            "3 encoding types + advanced encodings should yield high evasion: {level}"
        );
    }

    #[test]
    fn coordinated_scan_detected() {
        let mut ci = CampaignIntelligence::new();
        // 3 sources with identical behavior → coordinated scan
        for src in &["src1", "src2", "src3"] {
            ci.record_signal(make_signal(
                "sql_tautology",
                1000,
                src,
                EncodingPreference::Plain,
            ));
            ci.record_signal(make_signal(
                "sql_union",
                2000,
                src,
                EncodingPreference::Plain,
            ));
        }

        let campaigns: Vec<&Campaign> = ci
            .campaigns
            .iter()
            .filter(|c| c.campaign_type == CampaignType::CoordinatedScan)
            .collect();
        assert!(
            !campaigns.is_empty(),
            "should detect coordinated scan from 3 identical-fingerprint sources"
        );
    }

    #[test]
    fn brute_force_detected() {
        let mut ci = CampaignIntelligence::new();
        // 50+ signals from single source within campaign window
        for i in 0..55 {
            ci.record_signal(make_signal(
                "auth_bypass",
                1000 + i * 100,
                "bruter",
                EncodingPreference::Plain,
            ));
        }

        let bf_campaigns: Vec<&Campaign> = ci
            .campaigns
            .iter()
            .filter(|c| c.campaign_type == CampaignType::BruteForce)
            .collect();
        assert!(
            !bf_campaigns.is_empty(),
            "should detect brute force from 55 signals"
        );
    }

    #[test]
    fn threat_level_increases() {
        let mut ci = CampaignIntelligence::new();
        ci.record_signal(make_signal(
            "scanner_probe",
            1000,
            "src1",
            EncodingPreference::Plain,
        ));
        let t1 = ci.get_threat_level("src1");

        ci.record_signal(make_signal(
            "sql_injection",
            2000,
            "src1",
            EncodingPreference::UrlSingle,
        ));
        let t2 = ci.get_threat_level("src1");

        assert!(t2 > t1, "threat should increase with phase progression");
    }

    #[test]
    fn stats_reflect_state() {
        let mut ci = CampaignIntelligence::new();
        ci.record_signal(make_signal(
            "xss_tag",
            1000,
            "src1",
            EncodingPreference::Plain,
        ));
        ci.record_signal(make_signal(
            "xss_tag",
            1500,
            "src2",
            EncodingPreference::Plain,
        ));

        let stats = ci.get_stats(2000);
        assert_eq!(stats.active_sessions, 2);
        assert_eq!(stats.total_signals, 2);
    }

    #[test]
    fn cross_sensor_creates_distributed_campaign() {
        let mut ci = CampaignIntelligence::new();
        // Need 3+ matching signals in the window
        ci.record_signal(make_signal(
            "sql_tautology",
            1000,
            "src1",
            EncodingPreference::Plain,
        ));
        ci.record_signal(make_signal(
            "sql_tautology",
            1100,
            "src2",
            EncodingPreference::Plain,
        ));
        ci.record_signal(make_signal(
            "sql_tautology",
            1200,
            "src3",
            EncodingPreference::Plain,
        ));

        ci.record_cross_sensor_signal("sql_tautology", 1300);

        let dist_campaigns: Vec<&Campaign> = ci
            .campaigns
            .iter()
            .filter(|c| c.campaign_type == CampaignType::DistributedAttack)
            .collect();
        assert!(
            !dist_campaigns.is_empty(),
            "should detect distributed campaign"
        );
    }

    #[test]
    fn classify_signal_phases() {
        assert_eq!(
            classify_signal_phase("scanner_probe"),
            AttackPhase::Reconnaissance
        );
        assert_eq!(classify_signal_phase("sql_union"), AttackPhase::Delivery);
        assert_eq!(
            classify_signal_phase("auth_bypass"),
            AttackPhase::Exploitation
        );
        assert_eq!(
            classify_signal_phase("webshell_upload"),
            AttackPhase::Installation
        );
    }
}
