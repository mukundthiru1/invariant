use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::classes::all_classes;
use crate::evaluators::all_evaluators;
use crate::types::{InvariantClass, InvariantMatch, Severity};

const DEFAULT_TREND_WINDOW_SECONDS: u64 = 3600;
const DEFAULT_TREND_BUCKET_SECONDS: u64 = 60;
const LATENCY_BUCKETS_US: [u64; 12] = [
    25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000,
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistogramBucket {
    pub le_us: u64,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionMetrics {
    pub total_requests: u64,
    pub total_detections: u64,
    pub detections_by_class: HashMap<InvariantClass, u64>,
    pub detections_by_severity: HashMap<Severity, u64>,
    pub false_positive_rate_estimate: f64,
    pub mean_confidence: f64,
    pub p99_confidence: f64,
    pub detection_latency_us: Vec<HistogramBucket>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageCell {
    pub total_seen: u64,
    pub total_blocked: u64,
    pub avg_confidence: f64,
    pub min_confidence: f64,
    pub max_confidence: f64,
    pub last_seen_timestamp: Option<u64>,
}

pub type CoverageMatrix = HashMap<InvariantClass, CoverageCell>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub total_classes: usize,
    pub detected_classes: usize,
    pub dormant_classes: usize,
    pub coverage_ratio: f64,
    pub active: Vec<InvariantClass>,
    pub dormant: Vec<InvariantClass>,
    pub matrix: CoverageMatrix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Rising,
    Falling,
    Stable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrendEntry {
    pub class: InvariantClass,
    pub current_rate_per_min: f64,
    pub baseline_rate_per_min: f64,
    pub direction: TrendDirection,
    pub spike: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineHealth {
    pub uptime_seconds: u64,
    pub memory_estimate_bytes: u64,
    pub evaluator_count: usize,
    pub chain_count: usize,
    pub knowledge_entries: usize,
}

#[derive(Debug, Clone)]
pub struct Telemetry {
    started_at: Instant,
    started_unix_seconds: u64,
    trend_window_seconds: u64,
    trend_bucket_seconds: u64,

    total_requests: u64,
    total_detections: u64,
    suspected_false_positive_requests: u64,

    detections_by_class: HashMap<InvariantClass, u64>,
    detections_by_severity: HashMap<Severity, u64>,
    confidence_samples: Vec<f64>,

    latency_bucket_counts: Vec<u64>,

    coverage: CoverageMatrix,
    trend_events: HashMap<InvariantClass, VecDeque<u64>>,
    source_activity: HashMap<String, usize>,

    evaluator_count: usize,
    chain_count: usize,
    knowledge_entries: usize,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    pub fn new() -> Self {
        Self::with_trend_window(DEFAULT_TREND_WINDOW_SECONDS)
    }

    pub fn with_trend_window(window_seconds: u64) -> Self {
        let now_secs = unix_seconds_now();
        let bucket_seconds = DEFAULT_TREND_BUCKET_SECONDS.min(window_seconds.max(1));
        Self {
            started_at: Instant::now(),
            started_unix_seconds: now_secs,
            trend_window_seconds: window_seconds.max(1),
            trend_bucket_seconds: bucket_seconds,
            total_requests: 0,
            total_detections: 0,
            suspected_false_positive_requests: 0,
            detections_by_class: HashMap::new(),
            detections_by_severity: HashMap::new(),
            confidence_samples: Vec::new(),
            latency_bucket_counts: vec![0; LATENCY_BUCKETS_US.len() + 1],
            coverage: HashMap::new(),
            trend_events: HashMap::new(),
            source_activity: HashMap::new(),
            evaluator_count: all_evaluators().len(),
            chain_count: 0,
            knowledge_entries: 0,
        }
    }

    pub fn set_health_dimensions(&mut self, chain_count: usize, knowledge_entries: usize) {
        self.chain_count = chain_count;
        self.knowledge_entries = knowledge_entries;
    }

    pub fn record_detection(&mut self, class: InvariantClass, confidence: f64, latency_us: u64) {
        self.record_detection_at(class, confidence, latency_us, unix_seconds_now(), true);
        *self
            .detections_by_severity
            .entry(class.default_severity())
            .or_insert(0) += 1;
        self.total_requests += 1;
    }

    pub fn record_benign(&mut self, latency_us: u64) {
        self.total_requests += 1;
        self.record_latency(latency_us);
    }

    pub fn record_request(
        &mut self,
        matches: &[InvariantMatch],
        blocked: bool,
        latency_us: u64,
        source: &str,
        timestamp_ms: u64,
    ) {
        let ts_sec = timestamp_ms / 1000;
        self.total_requests += 1;
        self.record_latency(latency_us);

        if matches.is_empty() {
            return;
        }

        if !blocked {
            self.suspected_false_positive_requests += 1;
        }

        if !source.is_empty() {
            *self.source_activity.entry(source.to_owned()).or_insert(0) += 1;
        }

        for m in matches {
            self.record_detection_at(m.class, m.confidence, 0, ts_sec, blocked);
            *self
                .detections_by_severity
                .entry(m.severity)
                .or_insert(0) += 1;
        }
    }

    pub fn get_metrics(&self) -> DetectionMetrics {
        let mean_confidence = if self.total_detections == 0 {
            0.0
        } else {
            self.confidence_samples.iter().sum::<f64>() / self.total_detections as f64
        };

        let p99_confidence = percentile_99(&self.confidence_samples);
        let false_positive_rate_estimate = if self.total_requests == 0 {
            0.0
        } else {
            self.suspected_false_positive_requests as f64 / self.total_requests as f64
        };

        DetectionMetrics {
            total_requests: self.total_requests,
            total_detections: self.total_detections,
            detections_by_class: self.detections_by_class.clone(),
            detections_by_severity: self.detections_by_severity.clone(),
            false_positive_rate_estimate,
            mean_confidence,
            p99_confidence,
            detection_latency_us: self
                .latency_bucket_counts
                .iter()
                .enumerate()
                .map(|(idx, count)| HistogramBucket {
                    le_us: if idx < LATENCY_BUCKETS_US.len() {
                        LATENCY_BUCKETS_US[idx]
                    } else {
                        u64::MAX
                    },
                    count: *count,
                })
                .collect(),
        }
    }

    pub fn reset_metrics(&mut self) {
        self.total_requests = 0;
        self.total_detections = 0;
        self.suspected_false_positive_requests = 0;
        self.detections_by_class.clear();
        self.detections_by_severity.clear();
        self.confidence_samples.clear();
        self.latency_bucket_counts.fill(0);
        self.coverage.clear();
        self.trend_events.clear();
        self.source_activity.clear();
        self.started_at = Instant::now();
        self.started_unix_seconds = unix_seconds_now();
    }

    pub fn coverage_report(&self) -> CoverageReport {
        let mut matrix = self.coverage.clone();
        for class in known_classes() {
            matrix.entry(class).or_insert_with(CoverageCell::default);
        }

        let mut active = Vec::new();
        let mut dormant = Vec::new();

        for class in known_classes() {
            if matrix.get(&class).map(|c| c.total_seen).unwrap_or(0) > 0 {
                active.push(class);
            } else {
                dormant.push(class);
            }
        }

        sort_classes(&mut active);
        sort_classes(&mut dormant);

        let total_classes = active.len() + dormant.len();
        let detected_classes = active.len();
        let dormant_classes = dormant.len();
        let coverage_ratio = if total_classes == 0 {
            0.0
        } else {
            detected_classes as f64 / total_classes as f64
        };

        CoverageReport {
            total_classes,
            detected_classes,
            dormant_classes,
            coverage_ratio,
            active,
            dormant,
            matrix,
        }
    }

    pub fn detection_gaps(&self) -> Vec<InvariantClass> {
        self.coverage_report().dormant
    }

    pub fn is_spike(&self, class: InvariantClass) -> bool {
        self.class_trend(class, unix_seconds_now()).spike
    }

    pub fn trend_summary(&self) -> Vec<TrendEntry> {
        let now = unix_seconds_now();
        let mut out = Vec::new();
        for class in known_classes() {
            out.push(self.class_trend(class, now));
        }
        out
    }

    pub fn top_sources(&self, n: usize) -> Vec<(String, usize)> {
        let mut entries: Vec<(String, usize)> = self
            .source_activity
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries.truncate(n);
        entries
    }

    pub fn health_check(&self) -> EngineHealth {
        EngineHealth {
            uptime_seconds: self.started_at.elapsed().as_secs(),
            memory_estimate_bytes: self.memory_estimate_bytes(),
            evaluator_count: self.evaluator_count,
            chain_count: self.chain_count,
            knowledge_entries: self.knowledge_entries,
        }
    }

    pub fn to_prometheus(&self) -> String {
        let metrics = self.get_metrics();
        let mut out = String::new();

        out.push_str("# TYPE invariant_total_requests counter\n");
        out.push_str(&format!("invariant_total_requests {}\n", metrics.total_requests));

        out.push_str("# TYPE invariant_total_detections counter\n");
        out.push_str(&format!(
            "invariant_total_detections {}\n",
            metrics.total_detections
        ));

        out.push_str("# TYPE invariant_false_positive_rate_estimate gauge\n");
        out.push_str(&format!(
            "invariant_false_positive_rate_estimate {:.6}\n",
            metrics.false_positive_rate_estimate
        ));

        out.push_str("# TYPE invariant_mean_confidence gauge\n");
        out.push_str(&format!(
            "invariant_mean_confidence {:.6}\n",
            metrics.mean_confidence
        ));

        out.push_str("# TYPE invariant_p99_confidence gauge\n");
        out.push_str(&format!(
            "invariant_p99_confidence {:.6}\n",
            metrics.p99_confidence
        ));

        out.push_str("# TYPE invariant_detections_by_class counter\n");
        for (class, count) in &metrics.detections_by_class {
            out.push_str(&format!(
                "invariant_detections_by_class{{class=\"{}\"}} {}\n",
                class_label(*class),
                count
            ));
        }

        out.push_str("# TYPE invariant_detections_by_severity counter\n");
        for (severity, count) in &metrics.detections_by_severity {
            out.push_str(&format!(
                "invariant_detections_by_severity{{severity=\"{}\"}} {}\n",
                severity_label(*severity),
                count
            ));
        }

        out.push_str("# TYPE invariant_detection_latency_us histogram\n");
        let mut cumulative = 0_u64;
        for bucket in &metrics.detection_latency_us {
            cumulative = cumulative.saturating_add(bucket.count);
            let le = if bucket.le_us == u64::MAX {
                "+Inf".to_owned()
            } else {
                bucket.le_us.to_string()
            };
            out.push_str(&format!(
                "invariant_detection_latency_us_bucket{{le=\"{}\"}} {}\n",
                le, cumulative
            ));
        }
        out.push_str(&format!(
            "invariant_detection_latency_us_count {}\n",
            metrics.total_requests
        ));

        let health = self.health_check();
        out.push_str("# TYPE invariant_uptime_seconds gauge\n");
        out.push_str(&format!(
            "invariant_uptime_seconds {}\n",
            health.uptime_seconds
        ));
        out.push_str("# TYPE invariant_memory_estimate_bytes gauge\n");
        out.push_str(&format!(
            "invariant_memory_estimate_bytes {}\n",
            health.memory_estimate_bytes
        ));
        out.push_str("# TYPE invariant_evaluator_count gauge\n");
        out.push_str(&format!(
            "invariant_evaluator_count {}\n",
            health.evaluator_count
        ));
        out.push_str("# TYPE invariant_chain_count gauge\n");
        out.push_str(&format!("invariant_chain_count {}\n", health.chain_count));
        out.push_str("# TYPE invariant_knowledge_entries gauge\n");
        out.push_str(&format!(
            "invariant_knowledge_entries {}\n",
            health.knowledge_entries
        ));

        out
    }

    pub fn to_json(&self) -> String {
        let payload = serde_json::json!({
            "metrics": self.get_metrics(),
            "coverage": self.coverage_report(),
            "trends": self.trend_summary(),
            "top_sources": self.top_sources(10),
            "health": self.health_check(),
        });
        serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_owned())
    }

    fn class_trend(&self, class: InvariantClass, now_sec: u64) -> TrendEntry {
        let bins = self.bin_counts_for(class, now_sec);
        if bins.is_empty() {
            return TrendEntry {
                class,
                current_rate_per_min: 0.0,
                baseline_rate_per_min: 0.0,
                direction: TrendDirection::Stable,
                spike: false,
            };
        }

        let latest = *bins.last().unwrap_or(&0) as f64;
        let baseline_slice = &bins[..bins.len().saturating_sub(1)];

        let baseline_mean = if baseline_slice.is_empty() {
            0.0
        } else {
            baseline_slice.iter().sum::<u64>() as f64 / baseline_slice.len() as f64
        };
        let variance = if baseline_slice.len() < 2 {
            0.0
        } else {
            baseline_slice
                .iter()
                .map(|v| {
                    let d = *v as f64 - baseline_mean;
                    d * d
                })
                .sum::<f64>()
                / baseline_slice.len() as f64
        };
        let stddev = variance.sqrt();

        let spike = if baseline_slice.is_empty() {
            latest >= 3.0
        } else {
            latest > baseline_mean + (2.0 * stddev)
        };

        let direction = if latest > baseline_mean + stddev.max(0.5) {
            TrendDirection::Rising
        } else if latest + stddev.max(0.5) < baseline_mean {
            TrendDirection::Falling
        } else {
            TrendDirection::Stable
        };

        let per_min_scale = 60.0 / self.trend_bucket_seconds as f64;
        TrendEntry {
            class,
            current_rate_per_min: latest * per_min_scale,
            baseline_rate_per_min: baseline_mean * per_min_scale,
            direction,
            spike,
        }
    }

    fn bin_counts_for(&self, class: InvariantClass, now_sec: u64) -> Vec<u64> {
        let bins = ((self.trend_window_seconds + self.trend_bucket_seconds - 1)
            / self.trend_bucket_seconds)
            .max(2) as usize;
        let mut counts = vec![0_u64; bins];
        let Some(events) = self.trend_events.get(&class) else {
            return counts;
        };

        let window_start = now_sec.saturating_sub(self.trend_window_seconds);
        for ts in events {
            if *ts < window_start || *ts > now_sec {
                continue;
            }
            let offset = (*ts - window_start) / self.trend_bucket_seconds;
            let idx = (offset as usize).min(bins - 1);
            counts[idx] += 1;
        }
        counts
    }

    fn record_detection_at(
        &mut self,
        class: InvariantClass,
        confidence: f64,
        latency_us: u64,
        timestamp_sec: u64,
        blocked: bool,
    ) {
        self.total_detections += 1;
        self.record_latency(latency_us);

        *self.detections_by_class.entry(class).or_insert(0) += 1;
        self.confidence_samples.push(confidence.clamp(0.0, 1.0));

        let entry = self.coverage.entry(class).or_insert_with(CoverageCell::default);
        entry.total_seen += 1;
        if blocked {
            entry.total_blocked += 1;
        }
        let n = entry.total_seen as f64;
        entry.avg_confidence = ((entry.avg_confidence * (n - 1.0)) + confidence) / n;
        entry.min_confidence = if entry.total_seen == 1 {
            confidence
        } else {
            entry.min_confidence.min(confidence)
        };
        entry.max_confidence = entry.max_confidence.max(confidence);
        entry.last_seen_timestamp = Some(timestamp_sec);

        let events = self.trend_events.entry(class).or_default();
        events.push_back(timestamp_sec);
        self.prune_trend_events(timestamp_sec);
    }

    fn record_latency(&mut self, latency_us: u64) {
        let idx = LATENCY_BUCKETS_US
            .iter()
            .position(|bound| latency_us <= *bound)
            .unwrap_or(LATENCY_BUCKETS_US.len());
        self.latency_bucket_counts[idx] += 1;
    }

    fn prune_trend_events(&mut self, now_sec: u64) {
        let min_ts = now_sec.saturating_sub(self.trend_window_seconds);
        for queue in self.trend_events.values_mut() {
            while let Some(front) = queue.front().copied() {
                if front >= min_ts {
                    break;
                }
                queue.pop_front();
            }
        }
    }

    fn memory_estimate_bytes(&self) -> u64 {
        let mut total = 0_u64;

        total += (self.detections_by_class.len() * std::mem::size_of::<(InvariantClass, u64)>()) as u64;
        total += (self.detections_by_severity.len() * std::mem::size_of::<(Severity, u64)>()) as u64;
        total += (self.confidence_samples.len() * std::mem::size_of::<f64>()) as u64;
        total += (self.latency_bucket_counts.len() * std::mem::size_of::<u64>()) as u64;

        for (source, count) in &self.source_activity {
            total += source.len() as u64;
            total += std::mem::size_of_val(count) as u64;
        }

        total += (self.coverage.len() * std::mem::size_of::<(InvariantClass, CoverageCell)>()) as u64;

        for events in self.trend_events.values() {
            total += (events.len() * std::mem::size_of::<u64>()) as u64;
        }

        total + 1024
    }
}

impl Default for CoverageCell {
    fn default() -> Self {
        Self {
            total_seen: 0,
            total_blocked: 0,
            avg_confidence: 0.0,
            min_confidence: 0.0,
            max_confidence: 0.0,
            last_seen_timestamp: None,
        }
    }
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn percentile_99(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((sorted.len() as f64 * 0.99).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

fn known_classes() -> Vec<InvariantClass> {
    let mut set = HashSet::new();
    for class in all_classes() {
        set.insert(class.id);
    }
    let mut classes: Vec<_> = set.into_iter().collect();
    sort_classes(&mut classes);
    classes
}

fn sort_classes(classes: &mut [InvariantClass]) {
    classes.sort_by_key(|c| format!("{:?}", c));
}

fn class_label(class: InvariantClass) -> String {
    serde_json::to_string(&class)
        .unwrap_or_else(|_| "\"unknown\"".to_owned())
        .trim_matches('"')
        .to_owned()
}

fn severity_label(severity: Severity) -> String {
    serde_json::to_string(&severity)
        .unwrap_or_else(|_| "\"unknown\"".to_owned())
        .trim_matches('"')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_detection_metrics() {
        let mut t = Telemetry::new();
        t.record_detection(InvariantClass::SqlTautology, 0.91, 120);
        let m = t.get_metrics();
        assert_eq!(m.total_requests, 1);
        assert_eq!(m.total_detections, 1);
        assert_eq!(m.detections_by_class[&InvariantClass::SqlTautology], 1);
        assert!(m.mean_confidence > 0.9);
    }

    #[test]
    fn records_benign_metrics() {
        let mut t = Telemetry::new();
        t.record_benign(35);
        let m = t.get_metrics();
        assert_eq!(m.total_requests, 1);
        assert_eq!(m.total_detections, 0);
    }

    #[test]
    fn reset_clears_all_counters() {
        let mut t = Telemetry::new();
        t.record_detection(InvariantClass::SqlTautology, 0.8, 100);
        t.reset_metrics();
        let m = t.get_metrics();
        assert_eq!(m.total_requests, 0);
        assert_eq!(m.total_detections, 0);
        assert!(m.detections_by_class.is_empty());
    }

    #[test]
    fn coverage_tracks_seen_and_blocked() {
        let mut t = Telemetry::new();
        let matches = vec![InvariantMatch {
            class: InvariantClass::SqlTautology,
            confidence: 0.88,
            category: InvariantClass::SqlTautology.category(),
            severity: Severity::High,
            is_novel_variant: false,
            description: "test".to_owned(),
            detection_levels: Default::default(),
            l2_evidence: None,
            proof: None,
            cve_enrichment: None,
        }];

        t.record_request(&matches, true, 300, "src-a", 2_000);
        let report = t.coverage_report();
        let cell = report.matrix.get(&InvariantClass::SqlTautology).unwrap();
        assert_eq!(cell.total_seen, 1);
        assert_eq!(cell.total_blocked, 1);
        assert_eq!(cell.last_seen_timestamp, Some(2));
    }

    #[test]
    fn gaps_include_unseen_classes() {
        let t = Telemetry::new();
        assert!(!t.detection_gaps().is_empty());
    }

    #[test]
    fn top_sources_sorted() {
        let mut t = Telemetry::new();
        let m = vec![InvariantMatch {
            class: InvariantClass::SqlTautology,
            confidence: 0.8,
            category: AttackCategory::Sqli,
            severity: Severity::High,
            is_novel_variant: false,
            description: "x".into(),
            detection_levels: Default::default(),
            l2_evidence: None,
            proof: None,
            cve_enrichment: None,
        }];
        t.record_request(&m, true, 200, "b", 1_000);
        t.record_request(&m, true, 200, "a", 2_000);
        t.record_request(&m, true, 200, "b", 3_000);

        let top = t.top_sources(2);
        assert_eq!(top[0], ("b".to_owned(), 2));
        assert_eq!(top[1], ("a".to_owned(), 1));
    }

    #[test]
    fn trend_detects_spike() {
        let mut t = Telemetry::with_trend_window(600);
        let class = InvariantClass::SqlTautology;

        for minute in 0..9 {
            t.record_detection_at(class, 0.8, 0, minute * 60, true);
        }
        for _ in 0..10 {
            t.record_detection_at(class, 0.9, 0, 9 * 60, true);
        }

        assert!(t.class_trend(class, 9 * 60).spike);
    }

    #[test]
    fn trend_summary_contains_entries() {
        let t = Telemetry::new();
        let entries = t.trend_summary();
        assert!(!entries.is_empty());
    }

    #[test]
    fn health_check_exposes_dimensions() {
        let mut t = Telemetry::new();
        t.set_health_dimensions(33, 400);
        let h = t.health_check();
        assert!(h.evaluator_count >= 20);
        assert_eq!(h.chain_count, 33);
        assert_eq!(h.knowledge_entries, 400);
    }

    #[test]
    fn prometheus_export_contains_core_metrics() {
        let mut t = Telemetry::new();
        t.record_detection(InvariantClass::SqlTautology, 0.8, 100);
        let s = t.to_prometheus();
        assert!(s.contains("invariant_total_requests"));
        assert!(s.contains("invariant_detections_by_class"));
    }

    #[test]
    fn json_export_is_valid() {
        let mut t = Telemetry::new();
        t.record_benign(10);
        let json = t.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("metrics").is_some());
        assert!(parsed.get("coverage").is_some());
    }

    #[test]
    fn p99_confidence_calculates_high_percentile() {
        let mut t = Telemetry::new();
        for i in 1..=100 {
            t.record_detection(InvariantClass::SqlTautology, i as f64 / 100.0, 10);
        }
        let m = t.get_metrics();
        assert!(m.p99_confidence >= 0.99);
    }

    use crate::types::AttackCategory;
}
