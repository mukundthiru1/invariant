//! Zero Trust tier system: discrete threat tiers with escalation rules and
//! coordinated attack detection.

use std::collections::HashMap;
use std::collections::HashSet;

// ── Tiers ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum ThreatTier {
    Unknown = 0,
    Monitored = 1,
    Suspicious = 2,
    Hostile = 3,
    Blocked = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierAction {
    Log,
    Challenge,
    RateLimit,
    HardBlock,
}

// ── Engine ────────────────────────────────────────────────────────

pub struct ThreatTierEngine;

impl ThreatTierEngine {
    /// Thresholds: Unknown(<10), Monitored(10-30), Suspicious(30-60), Hostile(60-85), Blocked(>85).
    /// Escalation: chain_matched → at least Suspicious; coordinated → at least Hostile.
    pub fn evaluate_tier(
        threat_level: f64,
        signal_count: usize,
        chain_matched: bool,
        coordinated: bool,
    ) -> ThreatTier {
        let base = Self::tier_from_threat_level(threat_level);

        let tier = if coordinated {
            // coordinated → always at least Hostile
            base.max(ThreatTier::Hostile)
        } else if chain_matched {
            // chain_matched → always at least Suspicious
            base.max(ThreatTier::Suspicious)
        } else {
            base
        };

        tier
    }

    fn tier_from_threat_level(threat_level: f64) -> ThreatTier {
        if threat_level < 10.0 {
            ThreatTier::Unknown
        } else if threat_level < 30.0 {
            ThreatTier::Monitored
        } else if threat_level < 60.0 {
            ThreatTier::Suspicious
        } else if threat_level <= 85.0 {
            ThreatTier::Hostile
        } else {
            ThreatTier::Blocked
        }
    }

    pub fn tier_to_action(tier: ThreatTier) -> TierAction {
        match tier {
            ThreatTier::Unknown => TierAction::Log,
            ThreatTier::Monitored => TierAction::Log,
            ThreatTier::Suspicious => TierAction::Challenge,
            ThreatTier::Hostile => TierAction::RateLimit,
            ThreatTier::Blocked => TierAction::HardBlock,
        }
    }
}

/// Convert a string fingerprint hash to u64 for use with detect_coordinated_scan.
pub fn fingerprint_to_u64(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

// ── Coordinated scan detection ──────────────────────────────────────

/// If 5+ sources share the same fingerprint pattern → coordinated.
/// If 3+ sources hit same class (same fingerprint) in same batch → coordinated.
pub fn detect_coordinated_scan(fingerprints: &[u64], sources: &[&str]) -> bool {
    if fingerprints.len() != sources.len() || fingerprints.is_empty() {
        return false;
    }

    // fingerprint -> set of distinct sources
    let mut by_fp: HashMap<u64, HashSet<&str>> = HashMap::new();
    for (fp, src) in fingerprints.iter().zip(sources.iter()) {
        by_fp.entry(*fp).or_default().insert(*src);
    }

    for sources_with_fp in by_fp.values() {
        let n = sources_with_fp.len();
        if n >= 5 {
            return true;
        }
        if n >= 3 {
            return true;
        }
    }

    false
}

// ── Main exported classifier ───────────────────────────────────────

/// Classify threat from raw threat level and signal types. Does not apply
/// chain_matched or coordinated escalation; use ThreatTierEngine::evaluate_tier
/// when those are available.
pub fn classify_threat(threat_level: f64, _signals: &[&str]) -> ThreatTier {
    ThreatTierEngine::evaluate_tier(threat_level, _signals.len(), false, false)
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_boundaries_unknown_below_10() {
        assert_eq!(
            ThreatTierEngine::evaluate_tier(0.0, 0, false, false),
            ThreatTier::Unknown
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(9.9, 1, false, false),
            ThreatTier::Unknown
        );
    }

    #[test]
    fn tier_boundaries_monitored_10_to_30() {
        assert_eq!(
            ThreatTierEngine::evaluate_tier(10.0, 2, false, false),
            ThreatTier::Monitored
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(29.9, 3, false, false),
            ThreatTier::Monitored
        );
    }

    #[test]
    fn tier_boundaries_suspicious_30_to_60() {
        assert_eq!(
            ThreatTierEngine::evaluate_tier(30.0, 4, false, false),
            ThreatTier::Suspicious
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(59.9, 5, false, false),
            ThreatTier::Suspicious
        );
    }

    #[test]
    fn tier_boundaries_hostile_60_to_85() {
        assert_eq!(
            ThreatTierEngine::evaluate_tier(60.0, 6, false, false),
            ThreatTier::Hostile
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(85.0, 7, false, false),
            ThreatTier::Hostile
        );
    }

    #[test]
    fn tier_boundaries_blocked_above_85() {
        assert_eq!(
            ThreatTierEngine::evaluate_tier(85.1, 8, false, false),
            ThreatTier::Blocked
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(100.0, 10, false, false),
            ThreatTier::Blocked
        );
    }

    #[test]
    fn escalation_chain_matched_at_least_suspicious() {
        // Low base would be Unknown/Monitored; chain_matched bumps to at least Suspicious
        assert_eq!(
            ThreatTierEngine::evaluate_tier(5.0, 1, true, false),
            ThreatTier::Suspicious
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(20.0, 2, true, false),
            ThreatTier::Suspicious
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(50.0, 3, true, false),
            ThreatTier::Suspicious
        );
    }

    #[test]
    fn escalation_coordinated_at_least_hostile() {
        assert_eq!(
            ThreatTierEngine::evaluate_tier(0.0, 0, false, true),
            ThreatTier::Hostile
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(25.0, 2, true, true),
            ThreatTier::Hostile
        );
        assert_eq!(
            ThreatTierEngine::evaluate_tier(90.0, 10, true, true),
            ThreatTier::Blocked
        );
    }

    #[test]
    fn tier_to_action_mapping() {
        assert_eq!(
            ThreatTierEngine::tier_to_action(ThreatTier::Unknown),
            TierAction::Log
        );
        assert_eq!(
            ThreatTierEngine::tier_to_action(ThreatTier::Monitored),
            TierAction::Log
        );
        assert_eq!(
            ThreatTierEngine::tier_to_action(ThreatTier::Suspicious),
            TierAction::Challenge
        );
        assert_eq!(
            ThreatTierEngine::tier_to_action(ThreatTier::Hostile),
            TierAction::RateLimit
        );
        assert_eq!(
            ThreatTierEngine::tier_to_action(ThreatTier::Blocked),
            TierAction::HardBlock
        );
    }

    #[test]
    fn coordinated_scan_5_plus_sources_same_fingerprint() {
        let fp = 42u64;
        let fingerprints = vec![fp, fp, fp, fp, fp];
        let sources = ["a", "b", "c", "d", "e"];
        let src_refs: Vec<&str> = sources.iter().map(|s| *s).collect();
        assert!(detect_coordinated_scan(&fingerprints, &src_refs));
    }

    #[test]
    fn coordinated_scan_3_sources_same_class() {
        let fp = 100u64;
        let fingerprints = vec![fp, fp, fp];
        let sources = ["x", "y", "z"];
        let src_refs: Vec<&str> = sources.iter().map(|s| *s).collect();
        assert!(detect_coordinated_scan(&fingerprints, &src_refs));
    }

    #[test]
    fn coordinated_scan_not_coordinated_two_sources() {
        let fingerprints = vec![1u64, 1u64];
        let sources = ["a", "b"];
        let src_refs: Vec<&str> = sources.iter().map(|s| *s).collect();
        assert!(!detect_coordinated_scan(&fingerprints, &src_refs));
    }

    #[test]
    fn classify_threat_exported() {
        assert_eq!(classify_threat(0.0, &[]), ThreatTier::Unknown);
        assert_eq!(classify_threat(50.0, &["sql_tautology"]), ThreatTier::Suspicious);
    }
}
