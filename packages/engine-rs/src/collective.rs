use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::evaluators::{L2Result, ProofEvidence};
use crate::types::InvariantClass;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovelSignal {
    pub class: InvariantClass,
    pub detection_type: String,
    pub evidence_tokens: Vec<String>,
    pub confidence: f64,
    pub seen_count: u32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub dispatched: bool,
}

pub fn extract_evidence_tokens(evidence: &[ProofEvidence]) -> Vec<String> {
    let mut tokens = Vec::new();

    let double_quote_re = Regex::new(r#""([^"]*)""#).unwrap();
    let single_quote_re = Regex::new(r#"'([^']*)'"#).unwrap();
    let hex_re = Regex::new(r"(?:\\x[0-9a-fA-F]{2})+").unwrap();
    let kw_re = Regex::new(r"\b[a-z_][a-z0-9_]*\b").unwrap();

    for ev in evidence {
        let text = format!("{} {}", ev.matched_input, ev.interpretation);

        for cap in double_quote_re.captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                tokens.push(m.as_str().to_string());
            }
        }

        for cap in single_quote_re.captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                tokens.push(m.as_str().to_string());
            }
        }

        for mat in hex_re.find_iter(&text) {
            tokens.push(mat.as_str().to_string());
        }

        for mat in kw_re.find_iter(&text) {
            tokens.push(mat.as_str().to_string());
        }
    }

    tokens.sort();
    tokens.dedup();
    tokens
}

pub fn synthesize_l1_pattern(signal: &NovelSignal) -> Option<String> {
    let mut unique_tokens = signal.evidence_tokens.clone();
    unique_tokens.sort();
    unique_tokens.dedup();

    let filtered_tokens: Vec<String> = unique_tokens
        .into_iter()
        .filter(|t| t.len() >= 3 && !t.trim().is_empty())
        .collect();

    if filtered_tokens.len() < 2 {
        return None;
    }

    let escaped: Vec<String> = filtered_tokens
        .iter()
        .map(|t| regex::escape(t))
        .collect();

    let pattern_string = if escaped.len() == 1 {
        format!(r"(?i)\b{}\b", escaped[0])
    } else {
        format!("(?i)(?:{})", escaped.join("|"))
    };

    if Regex::new(&pattern_string).is_ok() {
        Some(pattern_string)
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectiveDispatch {
    pub class: InvariantClass,
    pub detection_type: String,
    pub synthesized_pattern: String,
    pub confidence: f64,
    pub seen_count: u32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectiveStats {
    pub total_signals: usize,
    pub synthesized_count: usize,
    pub dispatched_count: usize,
    pub pending_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectiveIntelligence {
    pub signals: HashMap<(InvariantClass, String), NovelSignal>,
    pub synthesized: HashMap<(InvariantClass, String), String>,
    pub min_seen_threshold: u32,
    pub min_confidence: f64,
}

impl Default for CollectiveIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

impl CollectiveIntelligence {
    pub fn new() -> Self {
        Self {
            signals: HashMap::new(),
            synthesized: HashMap::new(),
            min_seen_threshold: 3,
            min_confidence: 0.75,
        }
    }

    pub fn with_thresholds(min_seen: u32, min_confidence: f64) -> Self {
        Self {
            signals: HashMap::new(),
            synthesized: HashMap::new(),
            min_seen_threshold: min_seen,
            min_confidence,
        }
    }

    pub fn ingest(&mut self, result: &L2Result, evidence: &[ProofEvidence], now_ms: u64) {
        let extracted_tokens = extract_evidence_tokens(evidence);
        let key = (result.class, result.detail.clone());

        let signal = self
            .signals
            .entry(key.clone())
            .or_insert_with(|| NovelSignal {
                class: result.class,
                detection_type: result.detail.clone(),
                evidence_tokens: Vec::new(),
                confidence: result.confidence,
                seen_count: 0,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                dispatched: false,
            });

        signal.seen_count += 1;
        signal.last_seen_ms = now_ms;

        if result.confidence > signal.confidence {
            signal.confidence = result.confidence;
        }

        signal.evidence_tokens.extend(extracted_tokens);
        signal.evidence_tokens.sort();
        signal.evidence_tokens.dedup();

        if signal.seen_count >= self.min_seen_threshold
            && signal.confidence >= self.min_confidence
            && !self.synthesized.contains_key(&key)
        {
            if let Some(pattern) = synthesize_l1_pattern(signal) {
                self.synthesized.insert(key.clone(), pattern);
            }
        }
    }

    pub fn pending_dispatches(&self) -> Vec<CollectiveDispatch> {
        let mut pending = Vec::new();
        for (key, pattern) in &self.synthesized {
            if let Some(signal) = self.signals.get(key) {
                if !signal.dispatched {
                    pending.push(CollectiveDispatch {
                        class: signal.class,
                        detection_type: signal.detection_type.clone(),
                        synthesized_pattern: pattern.clone(),
                        confidence: signal.confidence,
                        seen_count: signal.seen_count,
                        first_seen_ms: signal.first_seen_ms,
                        last_seen_ms: signal.last_seen_ms,
                    });
                }
            }
        }
        pending
    }

    pub fn mark_dispatched(&mut self, class: InvariantClass, detection_type: &str) {
        if let Some(signal) = self.signals.get_mut(&(class, detection_type.to_string())) {
            signal.dispatched = true;
        }
    }

    pub fn stats(&self) -> CollectiveStats {
        let mut dispatched_count = 0;
        let mut pending_count = 0;

        for (key, _pattern) in &self.synthesized {
            if let Some(signal) = self.signals.get(key) {
                if signal.dispatched {
                    dispatched_count += 1;
                } else {
                    pending_count += 1;
                }
            }
        }

        CollectiveStats {
            total_signals: self.signals.len(),
            synthesized_count: self.synthesized.len(),
            dispatched_count,
            pending_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluators::EvidenceOperation;

    fn create_evidence(input: &str, interp: &str) -> ProofEvidence {
        ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: input.to_string(),
            interpretation: interp.to_string(),
            offset: 0,
            property: "test_prop".to_string(),
        }
    }

    fn create_l2_result(class: InvariantClass, conf: f64, detail: &str) -> L2Result {
        L2Result {
            class,
            confidence: conf,
            detail: detail.to_string(),
            evidence: vec![],
        }
    }

    #[test]
    fn test_extract_evidence_tokens_quoted() {
        let ev = vec![create_evidence("some 'quoted_string' here", "")];
        let tokens = extract_evidence_tokens(&ev);
        assert!(tokens.contains(&"quoted_string".to_string()));
    }

    #[test]
    fn test_extract_evidence_tokens_hex() {
        let ev = vec![create_evidence(r"\x41\x42\x43", "")];
        let tokens = extract_evidence_tokens(&ev);
        assert!(tokens.contains(&r"\x41\x42\x43".to_string()));
    }

    #[test]
    fn test_extract_evidence_tokens_keyword() {
        let ev = vec![create_evidence("select * from users", "")];
        let tokens = extract_evidence_tokens(&ev);
        assert!(tokens.contains(&"select".to_string()));
        assert!(tokens.contains(&"from".to_string()));
        assert!(tokens.contains(&"users".to_string()));
    }

    #[test]
    fn test_synthesize_l1_pattern_valid() {
        let signal = NovelSignal {
            class: InvariantClass::SqlTautology,
            detection_type: "test".to_string(),
            evidence_tokens: vec!["select".to_string(), "union".to_string()],
            confidence: 0.9,
            seen_count: 3,
            first_seen_ms: 0,
            last_seen_ms: 0,
            dispatched: false,
        };
        let pat = synthesize_l1_pattern(&signal).unwrap();
        assert_eq!(pat, "(?i)(?:select|union)");
    }

    #[test]
    fn test_synthesize_l1_pattern_fewer_than_2() {
        let signal = NovelSignal {
            class: InvariantClass::SqlTautology,
            detection_type: "test".to_string(),
            evidence_tokens: vec!["select".to_string()],
            confidence: 0.9,
            seen_count: 3,
            first_seen_ms: 0,
            last_seen_ms: 0,
            dispatched: false,
        };
        assert!(synthesize_l1_pattern(&signal).is_none());
    }

    #[test]
    fn test_synthesize_l1_pattern_filters_short_tokens() {
        let signal = NovelSignal {
            class: InvariantClass::SqlTautology,
            detection_type: "test".to_string(),
            evidence_tokens: vec!["a".to_string(), "b".to_string(), "select".to_string()],
            confidence: 0.9,
            seen_count: 3,
            first_seen_ms: 0,
            last_seen_ms: 0,
            dispatched: false,
        };
        assert!(synthesize_l1_pattern(&signal).is_none());
    }

    #[test]
    fn test_ingest_single_result_no_synthesize() {
        let mut coll = CollectiveIntelligence::new();
        let res = create_l2_result(InvariantClass::SqlTautology, 0.9, "test_det");
        let ev = vec![create_evidence("select union", "")];
        coll.ingest(&res, &ev, 100);
        assert!(coll.synthesized.is_empty());
    }

    #[test]
    fn test_ingest_three_times_synthesizes() {
        let mut coll = CollectiveIntelligence::new();
        let res = create_l2_result(InvariantClass::SqlTautology, 0.9, "test_det");
        let ev = vec![create_evidence("select union", "")];
        coll.ingest(&res, &ev, 100);
        coll.ingest(&res, &ev, 101);
        coll.ingest(&res, &ev, 102);
        assert!(!coll.synthesized.is_empty());
    }

    #[test]
    fn test_pending_dispatches() {
        let mut coll = CollectiveIntelligence::new();
        let res = create_l2_result(InvariantClass::SqlTautology, 0.9, "test_det");
        let ev = vec![create_evidence("select union", "")];
        coll.ingest(&res, &ev, 100);
        coll.ingest(&res, &ev, 101);
        coll.ingest(&res, &ev, 102);

        let pending = coll.pending_dispatches();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].detection_type, "test_det");
    }

    #[test]
    fn test_mark_dispatched() {
        let mut coll = CollectiveIntelligence::new();
        let res = create_l2_result(InvariantClass::SqlTautology, 0.9, "test_det");
        let ev = vec![create_evidence("select union", "")];
        coll.ingest(&res, &ev, 100);
        coll.ingest(&res, &ev, 101);
        coll.ingest(&res, &ev, 102);

        coll.mark_dispatched(InvariantClass::SqlTautology, "test_det");
        let pending = coll.pending_dispatches();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_stats() {
        let mut coll = CollectiveIntelligence::new();
        let res = create_l2_result(InvariantClass::SqlTautology, 0.9, "test_det");
        let ev = vec![create_evidence("select union", "")];
        coll.ingest(&res, &ev, 100);
        coll.ingest(&res, &ev, 101);
        coll.ingest(&res, &ev, 102);

        let stats = coll.stats();
        assert_eq!(stats.total_signals, 1);
        assert_eq!(stats.synthesized_count, 1);
        assert_eq!(stats.dispatched_count, 0);
        assert_eq!(stats.pending_count, 1);

        coll.mark_dispatched(InvariantClass::SqlTautology, "test_det");
        let stats2 = coll.stats();
        assert_eq!(stats2.dispatched_count, 1);
        assert_eq!(stats2.pending_count, 0);
    }

    #[test]
    fn test_low_confidence_no_synthesize() {
        let mut coll = CollectiveIntelligence::new();
        let res = create_l2_result(InvariantClass::SqlTautology, 0.5, "test_det");
        let ev = vec![create_evidence("select union", "")];
        coll.ingest(&res, &ev, 100);
        coll.ingest(&res, &ev, 101);
        coll.ingest(&res, &ev, 102);
        assert!(coll.synthesized.is_empty());
    }

    #[test]
    fn test_different_classes_tracked_separately() {
        let mut coll = CollectiveIntelligence::new();
        let res1 = create_l2_result(InvariantClass::SqlTautology, 0.9, "test_det");
        let res2 = create_l2_result(InvariantClass::XssTagInjection, 0.9, "test_det");
        let ev = vec![create_evidence("select union", "")];

        coll.ingest(&res1, &ev, 100);
        coll.ingest(&res2, &ev, 101);

        assert_eq!(coll.signals.len(), 2);
        assert_eq!(
            coll.signals
                .get(&(InvariantClass::SqlTautology, "test_det".to_string()))
                .unwrap()
                .seen_count,
            1
        );
        assert_eq!(
            coll.signals
                .get(&(InvariantClass::XssTagInjection, "test_det".to_string()))
                .unwrap()
                .seen_count,
            1
        );
    }

    #[test]
    fn test_seen_count_accumulates() {
        let mut coll = CollectiveIntelligence::new();
        let res = create_l2_result(InvariantClass::SqlTautology, 0.9, "test_det");
        let ev = vec![create_evidence("select union", "")];
        coll.ingest(&res, &ev, 100);
        coll.ingest(&res, &ev, 101);
        let sig = coll
            .signals
            .get(&(InvariantClass::SqlTautology, "test_det".to_string()))
            .unwrap();
        assert_eq!(sig.seen_count, 2);
    }

    #[test]
    fn test_evidence_tokens_merge() {
        let mut coll = CollectiveIntelligence::new();
        let res = create_l2_result(InvariantClass::SqlTautology, 0.9, "test_det");
        let ev1 = vec![create_evidence("select", "")];
        let ev2 = vec![create_evidence("union", "")];
        coll.ingest(&res, &ev1, 100);
        coll.ingest(&res, &ev2, 101);
        let sig = coll
            .signals
            .get(&(InvariantClass::SqlTautology, "test_det".to_string()))
            .unwrap();
        assert!(sig.evidence_tokens.contains(&"select".to_string()));
        assert!(sig.evidence_tokens.contains(&"union".to_string()));
    }

    #[test]
    fn test_with_thresholds_synthesizes_immediately() {
        let mut coll = CollectiveIntelligence::with_thresholds(1, 0.5);
        let res = create_l2_result(InvariantClass::SqlTautology, 0.6, "test_det");
        let ev = vec![create_evidence("select union", "")];
        coll.ingest(&res, &ev, 100);
        assert!(!coll.synthesized.is_empty());
    }

    #[test]
    fn test_synthesized_pattern_matches() {
        let signal = NovelSignal {
            class: InvariantClass::SqlTautology,
            detection_type: "test".to_string(),
            evidence_tokens: vec!["select".to_string(), "union".to_string()],
            confidence: 0.9,
            seen_count: 3,
            first_seen_ms: 0,
            last_seen_ms: 0,
            dispatched: false,
        };
        let pat = synthesize_l1_pattern(&signal).unwrap();
        let re = Regex::new(&pat).unwrap();
        assert!(re.is_match("SELECT something"));
        assert!(re.is_match("UNION all"));
        assert!(!re.is_match("insert"));
    }

    #[test]
    fn test_synthesized_pattern_compiles() {
        let signal = NovelSignal {
            class: InvariantClass::SqlTautology,
            detection_type: "test".to_string(),
            evidence_tokens: vec!["***".to_string(), "+++".to_string()],
            confidence: 0.9,
            seen_count: 3,
            first_seen_ms: 0,
            last_seen_ms: 0,
            dispatched: false,
        };
        let pat = synthesize_l1_pattern(&signal).unwrap();
        let re = Regex::new(&pat);
        assert!(re.is_ok());
    }
}
