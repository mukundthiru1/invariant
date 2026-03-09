//! Race Condition / TOCTOU Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

pub type L2EvalResult = L2Detection;

const EVIDENCE_PREVIEW_LIMIT: usize = 180;

#[inline]
fn preview(input: &str) -> String {
    input.chars().take(EVIDENCE_PREVIEW_LIMIT).collect()
}

#[inline]
fn collect_x_request_ids(decoded: &str) -> Vec<u64> {
    static X_REQUEST_ID_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?im)x-request-id\s*[:=]\s*([a-zA-Z0-9_-]+)").unwrap());

    let mut ids = Vec::new();
    for cap in X_REQUEST_ID_RE.captures_iter(decoded) {
        let Some(raw) = cap.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if let Ok(value) = raw.parse::<u64>() {
            ids.push(value);
        }
    }
    ids
}

#[inline]
fn has_file_system_toctou(decoded: &str) -> Option<(usize, &'static str)> {
    let checks = [
        "stat(",
        "access(",
        "lstat(",
        "file_exists(",
        "path_exists(",
        "check-then-act",
        "check_then_act",
        "file exists",
        "check exists",
    ];
    let actions = [
        "open(", "read(", "write(", "rename(", "delete(", "unlink(", "fopen(", "fopen ", "chmod(",
        "chown(",
    ];

    let mut first_check = None;
    let mut check_pos = 0usize;
    for term in checks {
        if let Some(idx) = decoded.find(term) {
            if first_check.is_none() || idx < check_pos {
                first_check = Some(idx);
                check_pos = idx;
            }
        }
    }
    let Some(check_pos) = first_check else {
        return None;
    };

    for action in actions {
        if let Some(action_pos) = decoded.find(action) {
            if action_pos > check_pos {
                return Some((check_pos, "filesystem check-then-act TOCTOU"));
            }
        }
    }

    None
}

#[inline]
fn has_db_select_update_gap(decoded: &str) -> Option<(usize, &'static str)> {
    let select_pos = decoded.find("select");
    let update_pos = decoded.find("update");
    let (select_pos, _update_pos) = match (select_pos, update_pos) {
        (Some(s), Some(u)) if s < u => (s, u),
        _ => return None,
    };

    if decoded[select_pos..].contains("for update")
        || decoded[select_pos..].contains("for share")
        || decoded[select_pos..].contains("for key share")
        || decoded[select_pos..].contains("lock in share mode")
    {
        return None;
    }

    Some((select_pos, "database select-then-update race"))
}

#[inline]
fn has_upload_access_before_validation(decoded: &str) -> Option<(usize, &'static str)> {
    static UPLOAD_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)(upload|multipart/form-data|/upload)\b").unwrap());
    let upload_pos = UPLOAD_RE.find(decoded).map(|m| m.start())?;

    static ACCESS_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\b(open|read|access)\b").unwrap());
    let access_pos = ACCESS_RE.find(decoded).map(|m| m.start())?;
    if access_pos <= upload_pos {
        return None;
    }

    static VALIDATE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\b(validate|sanitize|scan|verify)\b").unwrap());
    match VALIDATE_RE.find(decoded) {
        Some(validate_match) if validate_match.start() > access_pos => {}
        Some(_) => return None,
        None => {}
    }

    Some((upload_pos, "file upload accessed before validation"))
}

pub fn evaluate_race_condition(input: &str) -> Option<L2EvalResult> {
    let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
    let lower = decoded.to_lowercase();

    let mut signals: Vec<(&'static str, usize)> = Vec::new();
    let mut known_toc = false;

    let ids = collect_x_request_ids(&lower);
    if ids.len() >= 2 {
        let mut sorted_ids = ids;
        sorted_ids.sort_unstable();
        sorted_ids.dedup();
        let has_sequential = sorted_ids.windows(2).any(|pair| pair[1] == pair[0] + 1);
        if has_sequential {
            signals.push(("sequential X-Request-Id values", sorted_ids[0] as usize));
        }
    }

    if lower.contains("if-match:") {
        let lacks_lock = !lower.contains("if-unmodified-since")
            && !lower.contains("if-none-match")
            && !lower.contains("etag")
            && !lower.contains("lock")
            && !lower.contains("for update");
        if lacks_lock {
            signals.push((
                "If-Match without lock/if-unmodified guard",
                lower.find("if-match:").unwrap_or(0),
            ));
        }
    }

    let rapid_markers = [
        "parallel",
        "concurrent",
        "simultaneous",
        "race",
        "burst",
        "immediately",
        "rapid",
        "async",
    ];

    let has_transfer_or_withdraw = lower.contains("transfer") || lower.contains("withdraw");
    let has_amount = lower.contains("amount");
    let has_rate_marker = rapid_markers.iter().any(|m| lower.contains(m));
    if has_transfer_or_withdraw && has_amount && has_rate_marker {
        signals.push((
            "double-spend transfer/withdraw pattern",
            lower
                .find("transfer")
                .or_else(|| lower.find("withdraw"))
                .unwrap_or(0),
        ));
    }

    let has_limit_bypass_target =
        lower.contains("coupon") || lower.contains("voucher") || lower.contains("discount");
    if has_limit_bypass_target && has_rate_marker {
        signals.push((
            "coupon/voucher/discount parallel abuse",
            lower
                .find("coupon")
                .or_else(|| lower.find("voucher"))
                .or_else(|| lower.find("discount"))
                .unwrap_or(0),
        ));
    }

    let has_session_terms = lower.contains("session");
    let has_login =
        lower.contains("login") || lower.contains("sign-in") || lower.contains("signin");
    let has_logout =
        lower.contains("logout") || lower.contains("sign-out") || lower.contains("signout");
    if has_session_terms && has_login && has_logout && has_rate_marker {
        signals.push((
            "session race between login/logout/session-create",
            lower.find("session").unwrap_or(0),
        ));
    }

    if let Some((pos, detail)) = has_db_select_update_gap(&lower) {
        signals.push((detail, pos));
    }

    if let Some((pos, detail)) = has_upload_access_before_validation(&lower) {
        signals.push((detail, pos));
    }

    if let Some((pos, _)) = has_file_system_toctou(&lower) {
        signals.push(("filesystem TOCTOU check-then-act pattern", pos));
        known_toc = true;
    }

    if signals.is_empty() {
        return None;
    }

    signals.sort_by_key(|(_, pos)| *pos);
    let confidence = if known_toc {
        0.85
    } else if signals.len() >= 2 {
        0.75
    } else {
        0.55
    };

    let detection_type = if known_toc {
        "race_condition_toctou"
    } else {
        "race_condition"
    };
    let position = signals.first().map(|(_, pos)| *pos).unwrap_or(0);
    let detail = format!(
        "Race condition indicators: {}",
        signals
            .iter()
            .map(|(label, _)| *label)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let evidence = vec![ProofEvidence {
        operation: EvidenceOperation::SemanticEval,
        matched_input: preview(&decoded),
        interpretation: if known_toc {
            "Filesystem check-then-act behavior indicates TOCTOU race exposure".into()
        } else {
            "Concurrent/ordering signals indicate possible race-condition exploitability".into()
        },
        offset: position,
        property: "Protect critical sections with locks, atomic operations, and strict validation sequencing".into(),
    }];

    Some(L2Detection {
        detection_type: detection_type.into(),
        confidence,
        detail,
        position,
        evidence,
    })
}

pub struct RaceConditionEvaluator;

impl L2Evaluator for RaceConditionEvaluator {
    fn id(&self) -> &'static str {
        "race_condition"
    }

    fn prefix(&self) -> &'static str {
        "L2 Race"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = evaluate_race_condition(input)
            .into_iter()
            .collect::<Vec<_>>();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        static TOCTOU_SESSION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:session\.(?:get|read|fetch)|getSession\s*\(\s*\))[^;{]{0,120}(?:if|assert|check|verify|validate)[^;{]{0,80}(?:session\.(?:set|put|update|write)|setSession\s*\()").unwrap()
        });
        if let Some(m) = TOCTOU_SESSION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "race_toctou_session".into(),
                confidence: 0.84,
                detail: "Check-then-use session validation pattern indicating TOCTOU vulnerability".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Time-of-check to time-of-use (TOCTOU) in session validation: reading a session value and later modifying it without atomic operations creates a race window. Concurrent requests can manipulate the session state between the read and write".into(),
                    offset: m.start(),
                    property: "Session validation and update must use atomic compare-and-swap operations. Never read-check-write session state with non-atomic operations".into(),
                }],
            });
        }

        static LIMIT_BYPASS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:coupon|voucher|promo|discount|credit|balance|limit|quota|allowance)[^;{]{0,80}(?:check|verify|validate|enough|available|sufficient)[^;{]{0,80}(?:use|redeem|apply|consume|deduct|decrement|withdraw)").unwrap()
        });
        if let Some(m) = LIMIT_BYPASS_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "race_limit_bypass_parallel".into(),
                confidence: 0.86,
                detail: "Rate limit or balance check followed by use without atomic operation".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Non-atomic check-then-use patterns for rate limits and balances are vulnerable to parallel request races. Multiple simultaneous requests can all pass the balance check before any deduction occurs, enabling overdraft or limit bypass".into(),
                    offset: m.start(),
                    property: "Balance checks and decrements must use database-level atomic operations (SELECT FOR UPDATE, compare-and-swap, Redis DECR with atomicity guarantees). Never check then update in separate non-atomic steps".into(),
                }],
            });
        }

        // rapid markers similar to evaluate_race_condition
        let rapid_markers = [
            "parallel",
            "concurrent",
            "simultaneous",
            "race",
            "burst",
            "immediately",
            "rapid",
            "async",
        ];

        // Detect OAuth/JWT token reuse across concurrent requests
        static AUTH_BEARER_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?im)authorization\s*:\s*bearer\s+([A-Za-z0-9\-_.=]+)").unwrap()
        });
        let mut tokens: Vec<String> = Vec::new();
        for cap in AUTH_BEARER_RE.captures_iter(&decoded) {
            if let Some(m) = cap.get(1) {
                tokens.push(m.as_str().to_string());
            }
        }
        if tokens.len() >= 2 {
            // count duplicates
            tokens.sort();
            let mut dup_count = 0usize;
            let mut i = 0usize;
            while i + 1 < tokens.len() {
                if tokens[i] == tokens[i + 1] {
                    dup_count += 1;
                    // skip over a group of identical tokens
                    let cur = tokens[i].clone();
                    while i < tokens.len() && tokens[i] == cur {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            let has_nonce_or_timestamp = decoded.to_lowercase().contains("nonce")
                || decoded.to_lowercase().contains("timestamp")
                || rapid_markers
                    .iter()
                    .any(|m| decoded.to_lowercase().contains(m));
            if dup_count >= 1 && has_nonce_or_timestamp {
                dets.push(L2Detection {
                    detection_type: "race_token_reuse".into(),
                    confidence: 0.82,
                    detail: "Repeated bearer token usage across concurrent requests indicates token-reuse race".into(),
                    position: decoded.find("authorization").unwrap_or(0),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: preview(&decoded),
                        interpretation: "Same bearer token appearing in multiple near-simultaneous requests suggests token reuse / replay across concurrent requests, which may allow replay or double-use of privileged tokens".into(),
                        offset: decoded.find("authorization").unwrap_or(0),
                        property: "Short-lived tokens, nonce usage, and strict replay prevention must be enforced; multi-use of bearer tokens must be treated as suspicious".into(),
                    }],
                });
            }
        }

        // Inventory check-then-reserve TOCTOU pattern for limited stock
        static INVENTORY_TOCTOU_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:inventory|stock)[^;{]{0,80}(?:check|available|count|quantity)[^;{]{0,120}(?:reserve|hold|allocate|deduct|decrement|confirm)").unwrap()
        });
        if let Some(m) = INVENTORY_TOCTOU_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "race_inventory_toctou".into(),
                confidence: 0.84,
                detail: "Inventory check-then-reserve pattern indicates TOCTOU risk for limited stock".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Checking inventory availability and then reserving/confirming without atomic reservation creates a race where multiple consumers can all believe stock is available".into(),
                    offset: m.start(),
                    property: "Use atomic reservations (DB transactions with SELECT FOR UPDATE, row-level locks, or inventory decrement primitives) to avoid check-then-confirm races".into(),
                }],
            });
        }

        // Gift card balance rapid-redeem race
        static GIFT_CARD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:gift[_\s-]?card|giftcard)[^;{]{0,80}balance[^;{]{0,80}(?:check|available|sufficient|verify)[^;{]{0,80}(?:redeem|use|apply|deduct|debit|consume)").unwrap()
        });
        if let Some(m) = GIFT_CARD_RE.find(&decoded) {
            // require rapid/concurrent signal to raise confidence
            if rapid_markers
                .iter()
                .any(|p| decoded.to_lowercase().contains(p))
            {
                dets.push(L2Detection {
                    detection_type: "race_gift_card_balance".into(),
                    confidence: 0.78,
                    detail: "Gift card balance check followed by redeem without atomic guard — rapid requests may double-spend balance".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Non-atomic gift-card balance checks followed by redeems in rapid succession create race windows enabling multiple redemptions".into(),
                        offset: m.start(),
                        property: "Treat gift-card balance decrements as atomic operations; use database transactions or ledger entries with idempotency keys".into(),
                    }],
                });
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "race_condition"
            | "race_condition_toctou"
            | "race_toctou_session"
            | "race_limit_bypass_parallel" => Some(InvariantClass::ApiMassEnum),
            "race_token_reuse" | "race_inventory_toctou" | "race_gift_card_balance" => {
                Some(InvariantClass::ApiMassEnum)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_x_request_id_sequence() {
        let input = "GET /api HTTP/1.1\r\nX-Request-Id: 1001\r\nX-Request-Id: 1002\r\n\r\n";
        let det = evaluate_race_condition(input).expect("expected race condition detection");
        assert_eq!(det.detection_type, "race_condition");
        assert_eq!(det.confidence, 0.55);
        assert!(det.detail.contains("sequential X-Request-Id values"));
    }

    #[test]
    fn detects_if_match_without_lock() {
        let input = "PUT /resource/1 HTTP/1.1\r\nIf-Match: \"abc123\"\r\nContent-Type: application/json\r\n";
        let det = evaluate_race_condition(input).expect("expected race condition detection");
        assert_eq!(det.detection_type, "race_condition");
        assert_eq!(det.confidence, 0.55);
        assert!(det
            .detail
            .contains("If-Match without lock/if-unmodified guard"));
    }

    #[test]
    fn detects_double_spend_pattern() {
        let input = "POST /wallet/withdraw amount=500 parallel=true transfer=token";
        let det = evaluate_race_condition(input).expect("expected double-spend detection");
        assert_eq!(det.confidence, 0.55);
        assert!(det
            .detail
            .contains("double-spend transfer/withdraw pattern"));
    }

    #[test]
    fn detects_file_system_toctou() {
        let input =
            "if (stat('/tmp/session')) { open('/tmp/session'); write('/tmp/session', payload); }";
        let det = evaluate_race_condition(input).expect("expected TOCTOU detection");
        assert_eq!(det.detection_type, "race_condition_toctou");
        assert_eq!(det.confidence, 0.85);
        assert!(det.detail.contains("filesystem TOCTOU"));
    }

    #[test]
    fn detects_limit_bypass_coupon_concurrent_signal() {
        let input = "POST /checkout coupon=SPRING2026 concurrent=true\r\nX-Request-Id: 10\r\nX-Request-Id: 11\r\n";
        let det = evaluate_race_condition(input).expect("expected limit bypass race detection");
        assert_eq!(det.confidence, 0.75);
        assert!(det
            .detail
            .contains("coupon/voucher/discount parallel abuse"));
    }

    #[test]
    fn detects_session_race_pattern() {
        let input = "POST /auth simultaneous=true login session-id=abc logout session-id=abc";
        let det = evaluate_race_condition(input).expect("expected session race detection");
        assert_eq!(det.confidence, 0.55);
        assert!(det
            .detail
            .contains("session race between login/logout/session-create"));
    }

    #[test]
    fn detects_database_race_pattern() {
        let input = "BEGIN; SELECT balance FROM accounts WHERE id=1; UPDATE accounts SET balance=0 WHERE id=1;";
        let det = evaluate_race_condition(input).expect("expected database race detection");
        assert_eq!(det.confidence, 0.55);
        assert!(det.detail.contains("database select-then-update race"));
    }

    #[test]
    fn detects_file_upload_race_pattern() {
        let input = "POST /upload multipart/form-data upload=file.jpg access('/tmp/file.jpg'); scan later()";
        let det = evaluate_race_condition(input).expect("expected upload race detection");
        assert_eq!(det.confidence, 0.55);
        assert!(det
            .detail
            .contains("file upload accessed before validation"));
    }

    #[test]
    fn detects_multiple_correlated_patterns() {
        let input = "POST /wallet parallel=true X-Request-Id: 2001 X-Request-Id: 2002 transfer=1 amount=10 withdrawal=0";
        let det = evaluate_race_condition(input).expect("expected correlated race detection");
        assert_eq!(det.confidence, 0.75);
        assert!(det.detail.contains("sequential X-Request-Id values"));
        assert!(det
            .detail
            .contains("double-spend transfer/withdraw pattern"));
    }

    #[test]
    fn no_race_condition_detections_for_benign_input() {
        assert!(evaluate_race_condition("GET /api/products").is_none());
    }

    #[test]
    fn no_detection_for_validly_locked_update() {
        let input = "BEGIN; SELECT balance FROM accounts WHERE id=1 FOR UPDATE; UPDATE accounts SET balance=0 WHERE id=1;";
        assert!(evaluate_race_condition(input).is_none());
    }

    #[test]
    fn evaluates_to_multiple_evidence_entries_for_tocou() {
        let input = "if access('/tmp/x') { open('/tmp/x') }";
        let det = evaluate_race_condition(input).expect("expected detection");
        assert!(!det.evidence.is_empty());
        assert_eq!(det.evidence[0].operation, EvidenceOperation::SemanticEval);
    }

    #[test]
    fn evaluator_wrapper_returns_race_condition_detection() {
        let eval = RaceConditionEvaluator;
        let dets = eval.detect("GET /api X-Request-Id: 1");
        assert_eq!(dets.len(), 0);

        let dets = eval.detect("GET /api X-Request-Id: 1\r\nX-Request-Id: 2");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].detection_type, "race_condition");
    }

    #[test]
    fn evaluator_maps_to_api_mass_enum() {
        let eval = RaceConditionEvaluator;
        assert_eq!(
            eval.map_class("race_condition"),
            Some(InvariantClass::ApiMassEnum)
        );
        assert_eq!(
            eval.map_class("race_condition_toctou"),
            Some(InvariantClass::ApiMassEnum)
        );
        assert_eq!(eval.map_class("unknown_race"), None);
    }

    #[test]
    fn detects_race_toctou_session() {
        let eval = RaceConditionEvaluator;
        let dets = eval.detect("session.get('user') if check(s) session.set('user', s)");
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "race_toctou_session"));
        assert_eq!(
            eval.map_class("race_toctou_session"),
            Some(InvariantClass::ApiMassEnum)
        );
    }

    #[test]
    fn detects_race_limit_bypass_parallel() {
        let eval = RaceConditionEvaluator;
        let dets = eval.detect("balance check enough then deduct");
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "race_limit_bypass_parallel"));
        assert_eq!(
            eval.map_class("race_limit_bypass_parallel"),
            Some(InvariantClass::ApiMassEnum)
        );
    }

    #[test]
    fn detects_token_reuse_race() {
        let eval = RaceConditionEvaluator;
        let input = "POST /api Authorization: Bearer ABC.DEF.GHI\r\nAuthorization: Bearer ABC.DEF.GHI\r\nnonce=123 parallel=true";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "race_token_reuse"));
    }

    #[test]
    fn detects_inventory_toctou() {
        let eval = RaceConditionEvaluator;
        let input = "POST /checkout inventory check available then reserve item";
        let dets = eval.detect(input);
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "race_inventory_toctou"));
    }

    #[test]
    fn detects_gift_card_balance_race() {
        let eval = RaceConditionEvaluator;
        let input = "POST /redeem gift_card balance check redeem parallel=true";
        let dets = eval.detect(input);
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "race_gift_card_balance"));
    }
}
