//! Property Proof Constructor — Constructive Verification Engine
//!
//! Builds machine-verifiable proofs that an input violates a mathematical
//! property. Each proof step is independently verifiable. The complete proof
//! shows the full exploitation algebra:
//!
//!   context_escape ∘ payload_inject ∘ syntax_repair
//!
//! Proof construction is per-domain: SQL, HTML, Shell, Path, URL, XML, SSTI.

use regex::Regex;

use crate::tokenizers::html::{HtmlTokenType, HtmlTokenizer};
use crate::tokenizers::path::{PathTokenType, PathTokenizer};
use crate::tokenizers::shell::ShellTokenType;
use crate::tokenizers::sql::{SqlTokenType, SqlTokenizer, detect_tautologies};
use crate::tokenizers::url::{UrlTokenType, UrlTokenizer};
use crate::tokenizers::Token;
use crate::types::{
    DetectionResult, ProofOperation, ProofStep, ProofVerificationLevel, PropertyProof,
};

// ── Helpers ──────────────────────────────────────────────────────

fn evidence_steps_from_l2(l2: &DetectionResult, input_len: usize) -> Vec<ProofStep> {
    l2.structured_evidence
        .iter()
        .filter_map(|ev| {
            if ev.matched_input.trim().is_empty()
                && ev.interpretation.trim().is_empty()
                && ev.property.trim().is_empty()
            {
                return None;
            }
            Some(ProofStep {
                operation: ev.operation,
                input: ev.matched_input.clone(),
                output: ev.interpretation.clone(),
                property: ev.property.clone(),
                offset: ev.offset.min(input_len),
                confidence: normalize_confidence(l2.confidence),
                verified: false,
                verification_method: None,
            })
        })
        .collect()
}

fn dedupe_non_semantic_steps_by_offset(steps: Vec<ProofStep>) -> Vec<ProofStep> {
    let mut semantic = Vec::new();
    let mut by_offset = std::collections::HashMap::new();
    for step in steps {
        if step.operation == ProofOperation::SemanticEval {
            semantic.push(step);
        } else {
            let key = (step.operation, step.offset);
            let existing_conf = by_offset.get(&key).map(|s: &ProofStep| s.confidence).unwrap_or(-1.0);
            if step.confidence > existing_conf {
                by_offset.insert(key, step);
            }
        }
    }
    let mut out: Vec<ProofStep> = by_offset.into_values().chain(semantic).collect();
    out.sort_by_key(|s| s.offset);
    out
}

fn normalize_confidence(conf: f64) -> f64 {
    if conf.is_finite() { conf.clamp(0.0, 1.0) } else { 0.0 }
}

fn normalize_ratio(v: f64) -> f64 {
    if v.is_finite() { v.clamp(0.0, 1.0) } else { 0.0 }
}

fn ordered_chain(steps: &[ProofStep]) -> bool {
    let esc = steps.iter().enumerate().find(|(_, s)| s.operation == ProofOperation::ContextEscape);
    let pay = steps.iter().enumerate().find(|(_, s)| s.operation == ProofOperation::PayloadInject);
    let rep = steps.iter().enumerate().find(|(_, s)| s.operation == ProofOperation::SyntaxRepair);
    match (esc, pay, rep) {
        (Some((ei, e)), Some((pi, p)), Some((ri, r))) => {
            ei < pi && pi < ri && e.offset < p.offset && p.offset < r.offset
        }
        _ => false,
    }
}

fn calculate_proof_metrics(steps: &[ProofStep], l2: Option<&DetectionResult>) -> (bool, f64) {
    let has_escape = steps.iter().any(|s| s.operation == ProofOperation::ContextEscape);
    let has_payload = steps.iter().any(|s| s.operation == ProofOperation::PayloadInject);
    let has_repair = steps.iter().any(|s| s.operation == ProofOperation::SyntaxRepair);
    let is_complete = has_escape && has_payload && has_repair && ordered_chain(steps);

    let non_semantic: Vec<&ProofStep> = steps.iter()
        .filter(|s| s.operation != ProofOperation::SemanticEval)
        .collect();
    let avg_step_conf = if non_semantic.is_empty() {
        0.30
    } else {
        non_semantic.iter().map(|s| normalize_confidence(s.confidence)).sum::<f64>() / non_semantic.len() as f64
    };
    let structural = (if has_escape { 0.20 } else { 0.0 })
        + (if has_payload { 0.25 } else { 0.0 })
        + (if has_repair { 0.20 } else { 0.0 })
        + (if steps.iter().any(|s| s.operation == ProofOperation::EncodingDecode) { 0.05 } else { 0.0 })
        + (if ordered_chain(steps) { 0.10 } else { 0.0 });
    let verified = if steps.is_empty() { 0.0 } else {
        steps.iter().filter(|s| s.verified).count() as f64 / steps.len() as f64
    };
    let sem_bonus = if l2.map_or(false, |r| r.detected && r.structured_evidence.is_empty()) { 0.03 } else { 0.0 };
    let conf = (avg_step_conf * 0.60) + structural + (verified * 0.12) + sem_bonus;
    (is_complete, conf.min(0.99))
}

fn truncate_utf8_safe(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

fn safe_prefix(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_owned();
    }
    let mut out = truncate_utf8_safe(input, max_bytes).to_owned();
    out.push('…');
    out
}

fn witness(input: &str) -> String {
    safe_prefix(input, 200)
}

fn apply_structured_evidence(mut proof: PropertyProof, l2: Option<&DetectionResult>, input_len: usize) -> PropertyProof {
    let l2 = match l2 {
        Some(r) if r.detected && !r.structured_evidence.is_empty() => r,
        _ => return proof,
    };
    let l2_steps = evidence_steps_from_l2(l2, input_len);
    if l2_steps.is_empty() {
        return proof;
    }
    let merged = dedupe_non_semantic_steps_by_offset(
        proof.steps.into_iter().chain(l2_steps).collect()
    );
    let (ic, pc) = calculate_proof_metrics(&merged, Some(l2));
    proof.steps = merged;
    proof.is_complete = ic;
    proof.proof_confidence = pc;
    proof.recompute_verification();
    proof
}

fn l2_semantic_step(l2: Option<&DetectionResult>, input: &str) -> Option<ProofStep> {
    let l2r = l2.filter(|r| r.detected)?;
    Some(ProofStep {
        operation: ProofOperation::SemanticEval,
        input: l2r.evidence.clone().unwrap_or_else(|| safe_prefix(input, 100)),
        output: l2r.explanation.clone(),
        property: l2r.explanation.clone(),
        offset: 0,
        confidence: normalize_confidence(l2r.confidence),
        verified: false,
        verification_method: None,
    })
}

fn make_proof(property: &str, steps: Vec<ProofStep>, domain: &str, impact: &str, input: &str, l2: Option<&DetectionResult>) -> Option<PropertyProof> {
    if steps.is_empty() { return None; }
    let mut sorted: Vec<ProofStep> = steps.into_iter().map(|mut s| {
        s.confidence = normalize_confidence(s.confidence);
        s.offset = s.offset.min(input.len());
        s
    }).collect();
    sorted.sort_by_key(|s| s.offset);
    let (ic, pc) = calculate_proof_metrics(&sorted, l2);
    let mut proof = PropertyProof {
        property: property.into(), witness: witness(input), steps: sorted,
        is_complete: ic, domain: domain.into(), impact: impact.into(),
        proof_confidence: pc, verified_steps: 0, verification_coverage: 0.0,
        verification_level: ProofVerificationLevel::None,
    };
    proof.recompute_verification();
    seal_proof_chain(&mut proof);
    Some(proof)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;
    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn hex_32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn strip_chain_annotation(m: &str) -> String {
    m.split('|')
        .filter(|s| !s.starts_with("chain:"))
        .collect::<Vec<_>>()
        .join("|")
}

fn split_chain_annotation(m: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(raw) = m else { return (None, None); };
    let mut base_parts = Vec::new();
    let mut chain_parts = Vec::new();
    for part in raw.split('|') {
        if part.starts_with("chain:") {
            chain_parts.push(part.to_owned());
        } else if !part.is_empty() {
            base_parts.push(part.to_owned());
        }
    }
    let base = if base_parts.is_empty() { None } else { Some(base_parts.join("|")) };
    let chain = if chain_parts.len() == 1 { Some(chain_parts.remove(0)) } else { None };
    (base, chain)
}

fn operation_code(op: ProofOperation) -> u8 {
    match op {
        ProofOperation::ContextEscape => 0,
        ProofOperation::PayloadInject => 1,
        ProofOperation::SyntaxRepair => 2,
        ProofOperation::EncodingDecode => 3,
        ProofOperation::TypeCoerce => 4,
        ProofOperation::SemanticEval => 5,
    }
}

fn verification_level_code(level: ProofVerificationLevel) -> u8 {
    match level {
        ProofVerificationLevel::None => 0,
        ProofVerificationLevel::Structural => 1,
        ProofVerificationLevel::Verified => 2,
        ProofVerificationLevel::FormallyVerified => 3,
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
}

fn proof_chain_root_material_bytes(proof: &PropertyProof) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, proof.domain.as_bytes());
    push_len_prefixed(&mut out, proof.property.as_bytes());
    push_len_prefixed(&mut out, proof.witness.as_bytes());
    push_len_prefixed(&mut out, proof.impact.as_bytes());
    out.push(u8::from(proof.is_complete));
    out.extend_from_slice(&normalize_confidence(proof.proof_confidence).to_bits().to_be_bytes());
    out.extend_from_slice(&proof.verified_steps.to_be_bytes());
    out.extend_from_slice(&normalize_ratio(proof.verification_coverage).to_bits().to_be_bytes());
    out.push(verification_level_code(proof.verification_level));
    out.extend_from_slice(&(proof.steps.len() as u64).to_be_bytes());
    out
}

fn proof_chain_step_material_bytes(
    rolling: &[u8; 32],
    idx: usize,
    step: &ProofStep,
    base_method: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(rolling);
    out.extend_from_slice(&(idx as u64).to_be_bytes());
    out.push(operation_code(step.operation));
    push_len_prefixed(&mut out, step.input.as_bytes());
    push_len_prefixed(&mut out, step.output.as_bytes());
    push_len_prefixed(&mut out, step.property.as_bytes());
    out.extend_from_slice(&(step.offset as u64).to_be_bytes());
    out.extend_from_slice(&normalize_confidence(step.confidence).to_bits().to_be_bytes());
    out.push(u8::from(step.verified));
    push_len_prefixed(&mut out, base_method.unwrap_or("").as_bytes());
    out
}

fn seal_proof_chain(proof: &mut PropertyProof) {
    let mut rolling = sha256(&proof_chain_root_material_bytes(proof));
    for (idx, step) in proof.steps.iter_mut().enumerate() {
        let base_method = step.verification_method.as_deref().map(strip_chain_annotation).filter(|m| !m.is_empty());
        let material = proof_chain_step_material_bytes(&rolling, idx, step, base_method.as_deref());
        rolling = sha256(&material);
        let chain = format!("chain:{}", hex_32(&rolling));
        step.verification_method = Some(match base_method {
            Some(m) if !m.is_empty() => format!("{m}|{chain}"),
            _ => chain,
        });
    }
}

fn verify_proof_chain(proof: &PropertyProof) -> bool {
    if proof.steps.is_empty() {
        return false;
    }
    let mut rolling = sha256(&proof_chain_root_material_bytes(proof));
    for (idx, step) in proof.steps.iter().enumerate() {
        let (base_method, chain_method) = split_chain_annotation(step.verification_method.as_deref());
        let expected_material = proof_chain_step_material_bytes(&rolling, idx, step, base_method.as_deref());
        rolling = sha256(&expected_material);
        let expected_chain = format!("chain:{}", hex_32(&rolling));
        if chain_method.as_deref() != Some(expected_chain.as_str()) {
            return false;
        }
    }
    true
}

// ── SQL ─────────────────────────────────────────────────────────

struct SqlVariant { tokens: Vec<Token<SqlTokenType>>, base_offset: usize }

fn sql_variants(input: &str, base: &[Token<SqlTokenType>]) -> Vec<SqlVariant> {
    let filtered: Vec<_> = base.iter().filter(|t| t.token_type != SqlTokenType::Whitespace).cloned().collect();
    let mut variants = vec![SqlVariant { tokens: filtered, base_offset: 0 }];
    let first = match input.find(|c: char| !c.is_whitespace()) { Some(i) => i, None => return variants };
    let trimmed = &input[first..];
    let prefixes = [
        Regex::new(r#"^['"`]+\)?\s*"#).unwrap(),
        Regex::new(r"^\)+\s*").unwrap(),
        Regex::new(r#"^['"`]?\)\s*"#).unwrap(),
    ];
    let tok = SqlTokenizer;
    for p in &prefixes {
        if let Some(m) = p.find(trimmed) {
            let rest = &trimmed[m.end()..];
            if rest.is_empty() { continue; }
            let rt: Vec<_> = tok.tokenize(rest).all().iter()
                .filter(|t| t.token_type != SqlTokenType::Whitespace).cloned().collect();
            if !rt.is_empty() {
                variants.push(SqlVariant { tokens: rt, base_offset: first + m.end() });
            }
        }
    }
    variants
}

fn sql_escape(input: &str, variants: &[SqlVariant]) -> Option<ProofStep> {
    for v in variants {
        for i in 0..v.tokens.len().saturating_sub(1) {
            let cur = &v.tokens[i]; let nxt = &v.tokens[i + 1];
            if cur.token_type == SqlTokenType::String
                && matches!(nxt.token_type, SqlTokenType::BooleanOp | SqlTokenType::Keyword | SqlTokenType::Separator) {
                return Some(ProofStep {
                    operation: ProofOperation::ContextEscape,
                    input: cur.value.clone(),
                    output: format!("String context terminated before SQL {:?}: {}", nxt.token_type, nxt.value),
                    property: "escape(sqli): SQL string boundary closed before injected operators".into(),
                    offset: v.base_offset + cur.start, confidence: 0.90,
                    verified: false, verification_method: None,
                });
            }
        }
    }
    let f = input.find(|c: char| !c.is_whitespace())?;
    let ch = input.as_bytes()[f];
    if matches!(ch, b'\'' | b'"' | b'`') {
        let rest = &input[f + 1..];
        let stream = SqlTokenizer.tokenize(rest);
        let rm: Vec<_> = stream.all().iter().filter(|t| t.token_type != SqlTokenType::Whitespace).cloned().collect();
        if let Some(first) = rm.first() {
            if matches!(first.token_type, SqlTokenType::BooleanOp | SqlTokenType::Keyword | SqlTokenType::Separator) {
                return Some(ProofStep {
                    operation: ProofOperation::ContextEscape,
                    input: String::from(ch as char),
                    output: format!("Leading quote terminates host SQL string; {:?}: {} follows", first.token_type, first.value),
                    property: "escape(sqli): leading delimiter escapes SQL string context".into(),
                    offset: f, confidence: 0.88, verified: false, verification_method: None,
                });
            }
        }
    }
    None
}

fn sql_payload(input: &str, variants: &[SqlVariant]) -> Option<ProofStep> {
    let tautologies = detect_tautologies(input);
    let tok = SqlTokenizer;
    for taut in &tautologies {
        let et: Vec<_> = tok.tokenize(&taut.expression).all().iter()
            .filter(|t| !matches!(t.token_type, SqlTokenType::Whitespace | SqlTokenType::Separator | SqlTokenType::Unknown))
            .cloned().collect();
        if et.is_empty() { continue; }
        for v in variants {
            if v.tokens.len() < et.len() { continue; }
            for i in 0..=v.tokens.len() - et.len() {
                let ok = (0..et.len()).all(|j| v.tokens[i + j].token_type == et[j].token_type
                    && v.tokens[i + j].value.eq_ignore_ascii_case(&et[j].value));
                if ok {
                    return Some(ProofStep {
                        operation: ProofOperation::PayloadInject,
                        input: taut.expression.clone(),
                        output: format!("Tautology evaluates to {} by expression evaluation", taut.value),
                        property: "payload(sqli): boolean tautology forces conditional clause to TRUE".into(),
                        offset: v.base_offset + v.tokens[i].start, confidence: 0.95,
                        verified: false, verification_method: None,
                    });
                }
            }
        }
    }
    // UNION SELECT
    for v in variants {
        for i in 0..v.tokens.len() {
            let t = &v.tokens[i];
            if t.token_type == SqlTokenType::Keyword && t.value.eq_ignore_ascii_case("UNION") {
                let mut j = i + 1;
                if j < v.tokens.len() && v.tokens[j].value.eq_ignore_ascii_case("ALL") { j += 1; }
                if j < v.tokens.len() && v.tokens[j].value.eq_ignore_ascii_case("SELECT") {
                    let e = &v.tokens[j];
                    let s = v.base_offset + t.start;
                    let end = (v.base_offset + e.start + e.value.len()).min(input.len());
                    return Some(ProofStep {
                        operation: ProofOperation::PayloadInject,
                        input: input[s..end].to_owned(),
                        output: "UNION SELECT appends attacker-controlled result set".into(),
                        property: "payload(sqli): UNION-based extraction modifies query projection".into(),
                        offset: s, confidence: 0.93, verified: false, verification_method: None,
                    });
                }
            }
        }
    }
    // Stacked
    let destructive = ["DROP","DELETE","INSERT","UPDATE","ALTER","CREATE","EXEC","EXECUTE","TRUNCATE"];
    for v in variants {
        for i in 0..v.tokens.len().saturating_sub(1) {
            let t = &v.tokens[i]; let n = &v.tokens[i + 1];
            if t.token_type == SqlTokenType::Separator && t.value == ";"
                && n.token_type == SqlTokenType::Keyword && destructive.contains(&n.value.to_uppercase().as_str()) {
                let s = v.base_offset + t.start;
                let end = (v.base_offset + n.start + n.value.len()).min(input.len());
                return Some(ProofStep {
                    operation: ProofOperation::PayloadInject,
                    input: input[s..end].to_owned(),
                    output: format!("Stacked query starts new {} statement", n.value.to_uppercase()),
                    property: "payload(sqli): stacked query introduces second SQL statement".into(),
                    offset: s, confidence: 0.92, verified: false, verification_method: None,
                });
            }
        }
    }
    // Time functions
    let time_fns = ["SLEEP","WAITFOR","BENCHMARK","PG_SLEEP","DELAY"];
    for v in variants {
        for i in 0..v.tokens.len() {
            let t = &v.tokens[i]; let u = t.value.to_uppercase();
            if matches!(t.token_type, SqlTokenType::Identifier | SqlTokenType::Keyword) && u == "WAITFOR" {
                if let Some(n) = v.tokens.get(i + 1) {
                    if n.value.eq_ignore_ascii_case("DELAY") {
                        let s = v.base_offset + t.start;
                        let end = (v.base_offset + n.start + n.value.len()).min(input.len());
                        return Some(ProofStep {
                            operation: ProofOperation::PayloadInject, input: input[s..end].to_owned(),
                            output: "WAITFOR DELAY introduces timing oracle".into(),
                            property: "payload(sqli): time-delay enables blind extraction".into(),
                            offset: s, confidence: 0.91, verified: false, verification_method: None,
                        });
                    }
                }
            }
            if matches!(t.token_type, SqlTokenType::Identifier | SqlTokenType::Keyword) && time_fns.contains(&u.as_str()) {
                if let Some(n) = v.tokens.get(i + 1) {
                    if n.token_type == SqlTokenType::ParenOpen {
                        let s = v.base_offset + t.start;
                        return Some(ProofStep {
                            operation: ProofOperation::PayloadInject,
                            input: input[s..(s + t.value.len() + 1).min(input.len())].to_owned(),
                            output: format!("{}() introduces timing oracle", u),
                            property: "payload(sqli): time-based function modifies execution timing".into(),
                            offset: s, confidence: 0.90, verified: false, verification_method: None,
                        });
                    }
                }
            }
        }
    }
    None
}

fn sql_repair(variants: &[SqlVariant]) -> Option<ProofStep> {
    for v in variants {
        for i in 0..v.tokens.len() {
            let t = &v.tokens[i];
            if t.token_type != SqlTokenType::Separator { continue; }
            if !(t.value.starts_with("--") || t.value.starts_with('#')) { continue; }
            if !v.tokens[i + 1..].iter().any(|x| x.token_type != SqlTokenType::Whitespace) {
                return Some(ProofStep {
                    operation: ProofOperation::SyntaxRepair,
                    input: t.value.clone(),
                    output: "Comment separator truncates trailing host SQL".into(),
                    property: "repair(sqli): comment suppresses remaining query syntax".into(),
                    offset: v.base_offset + t.start, confidence: 0.86,
                    verified: false, verification_method: None,
                });
            }
        }
    }
    None
}

/// Construct a SQL-injection property proof from tokenizer evidence.
///
/// `input` is the untrusted payload to analyze. `l2` optionally contributes
/// semantic evidence from structural evaluators.
///
/// Returns `Some(PropertyProof)` when at least one proof step is recoverable;
/// returns `None` for empty/non-tokenizable SQL input.
pub fn construct_sql_proof(input: &str, l2: Option<&DetectionResult>) -> Option<PropertyProof> {
    let stream = SqlTokenizer.tokenize(input);
    let tokens = stream.all();
    if tokens.is_empty() { return None; }
    let variants = sql_variants(input, tokens);
    let mut steps = Vec::new();
    if let Some(s) = sql_escape(input, &variants) { steps.push(s); }
    if let Some(s) = sql_payload(input, &variants) { steps.push(s); }
    if let Some(s) = sql_repair(&variants) { steps.push(s); }
    if let Some(s) = l2_semantic_step(l2, input) { steps.push(s); }
    let mut proof = make_proof(
        l2.map(|r| r.explanation.as_str()).unwrap_or("SQL property violation"),
        steps, "sqli", "SQL injection alters query semantics", input, l2,
    )?;
    verify_sql_proof(&mut proof, input);
    seal_proof_chain(&mut proof);
    Some(proof)
}

fn verify_sql_proof(proof: &mut PropertyProof, input: &str) {
    let stream = SqlTokenizer.tokenize(input);
    let tokens = stream.all().to_vec();
    let tautologies = detect_tautologies(input);
    let taut_set: std::collections::HashSet<String> = tautologies.iter()
        .map(|t| t.expression.trim().replace(char::is_whitespace, " ").to_uppercase()).collect();
    let variants = sql_variants(input, &tokens);

    for step in &mut proof.steps {
        match step.operation {
            ProofOperation::PayloadInject => {
                let norm = step.input.trim().replace(char::is_whitespace, " ").to_uppercase();
                if !norm.is_empty() && taut_set.contains(&norm) {
                    step.verified = true;
                    step.verification_method = Some("ast_evaluation".into());
                }
            }
            ProofOperation::ContextEscape => {
                for v in &variants {
                    for (i, tok) in v.tokens.iter().enumerate() {
                        if v.base_offset + tok.start == step.offset && tok.token_type == SqlTokenType::String {
                            if let Some(nxt) = v.tokens.get(i + 1) {
                                if nxt.token_type != SqlTokenType::String {
                                    step.verified = true;
                                    step.verification_method = Some("tokenizer_parse".into());
                                }
                            }
                        }
                    }
                }
            }
            ProofOperation::SyntaxRepair => {
                for v in &variants {
                    for (i, tok) in v.tokens.iter().enumerate() {
                        if v.base_offset + tok.start == step.offset
                            && tok.token_type == SqlTokenType::Separator
                            && (tok.value.starts_with("--") || tok.value.starts_with('#'))
                            && !v.tokens[i + 1..].iter().any(|t| t.token_type != SqlTokenType::Whitespace)
                        {
                            step.verified = true;
                            step.verification_method = Some("tokenizer_parse".into());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    proof.recompute_verification();
}

// ── XSS ─────────────────────────────────────────────────────────

const XSS_EXEC_TAGS: &[&str] = &["script", "svg", "iframe"];
const XSS_PROTO_ATTRS: &[&str] = &["href", "src", "action", "formaction", "xlink:href", "data"];

/// Construct an XSS property proof using HTML tokenization and syntax signals.
///
/// `input` is the raw payload and `l2` can supply additional semantic evidence.
///
/// Returns `Some(PropertyProof)` when executable HTML/JS structure is found,
/// otherwise `None`.
pub fn construct_xss_proof(input: &str, l2: Option<&DetectionResult>) -> Option<PropertyProof> {
    let stream = HtmlTokenizer.tokenize(input);
    let tokens = stream.all();
    if tokens.is_empty() { return None; }
    let mut steps = Vec::new();
    let mut payload_off = 0usize;

    // Escape: look for TagOpen preceded by text with quote
    for i in 0..tokens.len() {
        if tokens[i].token_type != HtmlTokenType::TagOpen { continue; }
        if i > 0 {
            for j in (0..i).rev() {
                if tokens[j].value.trim().is_empty() { continue; }
                if tokens[j].token_type == HtmlTokenType::Text {
                    if let Some(qi) = tokens[j].value.rfind(|c: char| c == '"' || c == '\'') {
                        steps.push(ProofStep {
                            operation: ProofOperation::ContextEscape,
                            input: tokens[j].value[qi..qi + 1].to_owned(),
                            output: "Quoted HTML context terminated before injected tag".into(),
                            property: "escape(xss): attacker closes host HTML boundary".into(),
                            offset: tokens[j].start + qi, confidence: 0.90,
                            verified: false, verification_method: None,
                        });
                        break;
                    }
                }
                break;
            }
        }
        if !steps.is_empty() { break; }
    }

    // Payload: script-capable tag
    let event_re = Regex::new(r"(?i)^on[a-z0-9_:-]+$").unwrap();
    for i in 0..tokens.len() {
        if tokens[i].token_type == HtmlTokenType::TagName
            && XSS_EXEC_TAGS.contains(&tokens[i].value.to_lowercase().as_str()) {
            if i > 0 && tokens[i - 1].token_type == HtmlTokenType::TagOpen {
                payload_off = tokens[i - 1].start;
                steps.push(ProofStep {
                    operation: ProofOperation::PayloadInject,
                    input: input[tokens[i - 1].start..tokens[i].end].to_owned(),
                    output: format!("Script-capable <{}> injected", tokens[i].value.to_lowercase()),
                    property: "payload(xss): executable HTML tag introduces JS execution".into(),
                    offset: payload_off, confidence: 0.94,
                    verified: false, verification_method: None,
                });
                break;
            }
        }
        if tokens[i].token_type == HtmlTokenType::AttrName && event_re.is_match(&tokens[i].value) {
            payload_off = tokens[i].start;
            steps.push(ProofStep {
                operation: ProofOperation::PayloadInject,
                input: tokens[i].value.clone(),
                output: format!("Event handler {} binds JS to browser event", tokens[i].value),
                property: "payload(xss): event-handler enables script execution".into(),
                offset: payload_off, confidence: 0.93,
                verified: false, verification_method: None,
            });
            break;
        }
        if tokens[i].token_type == HtmlTokenType::AttrValue {
            let attr_name = (0..i).rev().find_map(|j| {
                if tokens[j].token_type == HtmlTokenType::AttrName { Some(tokens[j].value.to_lowercase()) }
                else if matches!(tokens[j].token_type, HtmlTokenType::TagOpen | HtmlTokenType::TagEndOpen) { None }
                else { None }
            });
            if let Some(an) = attr_name {
                if XSS_PROTO_ATTRS.contains(&an.as_str()) && tokens[i].value.trim().to_lowercase().starts_with("javascript:") {
                    payload_off = tokens[i].start;
                    steps.push(ProofStep {
                        operation: ProofOperation::PayloadInject,
                        input: tokens[i].value.clone(),
                        output: format!("javascript: protocol in {} executes script", an),
                        property: "payload(xss): protocol handler injects executable URI".into(),
                        offset: payload_off, confidence: 0.93,
                        verified: false, verification_method: None,
                    });
                    break;
                }
            }
        }
    }

    // Repair: closing tag or self-close after payload
    for i in 0..tokens.len() {
        if tokens[i].token_type == HtmlTokenType::TagEndOpen && tokens[i].start >= payload_off {
            if let Some(close) = tokens[i + 1..].iter().find(|t| t.token_type == HtmlTokenType::TagClose) {
                steps.push(ProofStep {
                    operation: ProofOperation::SyntaxRepair,
                    input: input[tokens[i].start..close.end].to_owned(),
                    output: "Closing tag repairs HTML tree".into(),
                    property: "repair(xss): closing markup finalizes attacker DOM subtree".into(),
                    offset: tokens[i].start, confidence: 0.88,
                    verified: false, verification_method: None,
                });
                break;
            }
        }
        if tokens[i].token_type == HtmlTokenType::TagSelfClose && tokens[i].start >= payload_off {
            steps.push(ProofStep {
                operation: ProofOperation::SyntaxRepair,
                input: tokens[i].value.clone(),
                output: "Self-closing syntax finalizes injected element".into(),
                property: "repair(xss): self-closing tag repairs HTML after payload".into(),
                offset: tokens[i].start, confidence: 0.86,
                verified: false, verification_method: None,
            });
            break;
        }
        if tokens[i].token_type == HtmlTokenType::TagClose && tokens[i].start >= payload_off {
            steps.push(ProofStep {
                operation: ProofOperation::SyntaxRepair,
                input: tokens[i].value.clone(),
                output: "Tag close completes injected element".into(),
                property: "repair(xss): injected element closed into valid HTML".into(),
                offset: tokens[i].start, confidence: 0.84,
                verified: false, verification_method: None,
            });
            break;
        }
    }

    if let Some(s) = l2_semantic_step(l2, input) { steps.push(s); }
    make_proof(l2.map(|r| r.explanation.as_str()).unwrap_or("XSS property violation"),
        steps, "xss", "XSS payload introduces executable browser context", input, l2)
}

// ── CMD ─────────────────────────────────────────────────────────

const CMD_DANGEROUS: &[&str] = &[
    "cat","ls","id","whoami","pwd","uname","hostname","env","printenv","echo",
    "curl","wget","nc","ncat","nmap","netcat","socat","bash","sh","zsh",
    "python","python2","python3","perl","ruby","php","node","awk","sed","grep",
    "find","xargs","ps","kill","sudo","su","rm","chmod","chown","passwd",
    "cmd","powershell","certutil",
];

/// Construct a command-injection proof from shell token boundaries.
///
/// `input` is interpreted as shell-like text. `l2` adds optional semantic
/// evidence from structural evaluators.
///
/// Returns `Some(PropertyProof)` when command-boundary or execution steps are
/// detected; otherwise returns `None`.
pub fn construct_cmd_proof(input: &str, l2: Option<&DetectionResult>) -> Option<PropertyProof> {
    let stream = crate::tokenizers::shell::ShellTokenizer.tokenize(input);
    let tokens = stream.all();
    if tokens.is_empty() { return None; }
    let mut steps = Vec::new();
    let mut escape_off = 0usize;

    // Escape
    for tok in tokens {
        if matches!(tok.token_type, ShellTokenType::Separator | ShellTokenType::Pipe |
            ShellTokenType::AndChain | ShellTokenType::OrChain | ShellTokenType::Newline |
            ShellTokenType::CmdSubstOpen | ShellTokenType::BacktickSubst) {
            escape_off = tok.start;
            let ctx = if matches!(tok.token_type, ShellTokenType::CmdSubstOpen | ShellTokenType::BacktickSubst) {
                "Command substitution opens nested shell context".to_owned()
            } else {
                format!("Shell token {} starts new command boundary", tok.value)
            };
            steps.push(ProofStep {
                operation: ProofOperation::ContextEscape, input: tok.value.clone(), output: ctx,
                property: "escape(cmdi): shell control escapes host argument context".into(),
                offset: tok.start, confidence: 0.90, verified: false, verification_method: None,
            });
            break;
        }
    }

    // Payload: word after separator
    for (i, tok) in tokens.iter().enumerate() {
        if tok.token_type == ShellTokenType::CmdSubstOpen {
            if let Some(cw) = tokens[i + 1..].iter().find(|t| t.token_type == ShellTokenType::Word) {
                let danger = CMD_DANGEROUS.contains(&cw.value.to_lowercase().as_str());
                steps.push(ProofStep {
                    operation: ProofOperation::PayloadInject, input: cw.value.clone(),
                    output: format!("$() executes {}{}", cw.value, if danger { " (dangerous)" } else { "" }),
                    property: "payload(cmdi): command substitution executes attacker command".into(),
                    offset: cw.start, confidence: if danger { 0.94 } else { 0.90 },
                    verified: false, verification_method: None,
                });
                break;
            }
        }
        if tok.token_type == ShellTokenType::BacktickSubst {
            let inner = tok.value.trim_matches('`').trim().split_whitespace().next().unwrap_or("");
            let danger = CMD_DANGEROUS.contains(&inner.to_lowercase().as_str());
            steps.push(ProofStep {
                operation: ProofOperation::PayloadInject, input: tok.value.clone(),
                output: format!("Backtick executes {}{}", inner, if danger { " (dangerous)" } else { "" }),
                property: "payload(cmdi): backtick executes attacker shell command".into(),
                offset: tok.start, confidence: if danger { 0.93 } else { 0.89 },
                verified: false, verification_method: None,
            });
            break;
        }
        if matches!(tok.token_type, ShellTokenType::Separator | ShellTokenType::Pipe |
            ShellTokenType::AndChain | ShellTokenType::OrChain | ShellTokenType::Newline) {
            if let Some(cw) = tokens[i + 1..].iter().find(|t| t.token_type == ShellTokenType::Word) {
                let danger = CMD_DANGEROUS.contains(&cw.value.to_lowercase().as_str());
                steps.push(ProofStep {
                    operation: ProofOperation::PayloadInject,
                    input: input[cw.start..cw.end].to_owned(),
                    output: format!("{} executes after boundary break{}", cw.value, if danger { " (dangerous)" } else { "" }),
                    property: "payload(cmdi): command token after separator".into(),
                    offset: cw.start, confidence: if danger { 0.93 } else { 0.88 },
                    verified: false, verification_method: None,
                });
                break;
            }
        }
    }
    // Fallback word
    if !steps.iter().any(|s| s.operation == ProofOperation::PayloadInject) {
        if let Some(w) = tokens.iter().find(|t| t.token_type == ShellTokenType::Word && t.start >= escape_off) {
            steps.push(ProofStep {
                operation: ProofOperation::PayloadInject, input: w.value.clone(),
                output: format!("{} in executable position", w.value),
                property: "payload(cmdi): command token in shell stream".into(),
                offset: w.start, confidence: 0.84, verified: false, verification_method: None,
            });
        }
    }

    // Repair
    if let Some(c) = tokens.iter().find(|t| t.token_type == ShellTokenType::Comment) {
        steps.push(ProofStep {
            operation: ProofOperation::SyntaxRepair, input: c.value.clone(),
            output: "Shell comment truncates trailing text".into(),
            property: "repair(cmdi): comment suppresses remaining host syntax".into(),
            offset: c.start, confidence: 0.86, verified: false, verification_method: None,
        });
    } else if let Some(last) = tokens.iter().filter(|t| t.token_type != ShellTokenType::Whitespace).last() {
        steps.push(ProofStep {
            operation: ProofOperation::SyntaxRepair, input: last.value.clone(),
            output: "Command terminates naturally at input boundary".into(),
            property: "repair(cmdi): natural termination leaves payload parseable".into(),
            offset: last.start, confidence: 0.82, verified: false, verification_method: None,
        });
    }

    if let Some(s) = l2_semantic_step(l2, input) { steps.push(s); }
    make_proof(l2.map(|r| r.explanation.as_str()).unwrap_or("Command-injection property violation"),
        steps, "cmdi", "Shell metacharacters introduce unintended command execution", input, l2)
}

// ── Path ────────────────────────────────────────────────────────

/// Construct a path-traversal proof from normalized path tokens.
///
/// `input` is the candidate file/path payload. `l2` adds optional semantic
/// evidence.
///
/// Returns `Some(PropertyProof)` when traversal or sensitive-target signals
/// exist; returns `None` when no path tokens are available.
pub fn construct_path_proof(input: &str, l2: Option<&DetectionResult>) -> Option<PropertyProof> {
    let stream = PathTokenizer.tokenize(input);
    let tokens = stream.all();
    if tokens.is_empty() { return None; }
    let mut steps = Vec::new();

    let trav: Vec<_> = tokens.iter().filter(|t| t.token_type == PathTokenType::Traversal).collect();
    if !trav.is_empty() {
        let chain: String = trav.iter().map(|t| t.value.as_str()).collect::<Vec<_>>().join("/");
        steps.push(ProofStep {
            operation: ProofOperation::ContextEscape, input: chain,
            output: format!("{} traversal(s) escape directory boundary", trav.len()),
            property: format!("escape(path): {}x traversal escapes webroot", trav.len()),
            offset: trav[0].start, confidence: (0.80 + trav.len() as f64 * 0.05).min(0.99),
            verified: true, verification_method: Some("tokenizer_structural".into()),
        });
    }
    if let Some(enc) = tokens.iter().find(|t| t.token_type == PathTokenType::EncodingLayer) {
        steps.push(ProofStep {
            operation: ProofOperation::EncodingDecode, input: enc.value.clone(),
            output: "Multi-layer encoding detected".into(),
            property: "escape(path): Encoding layers bypass WAF normalization".into(),
            offset: enc.start, confidence: 0.92, verified: true,
            verification_method: Some("tokenizer_decode".into()),
        });
    }
    if let Some(target) = tokens.iter().find(|t| t.token_type == PathTokenType::SensitiveTarget) {
        steps.push(ProofStep {
            operation: ProofOperation::PayloadInject, input: target.value.clone(),
            output: format!("Targets sensitive file: {}", target.value),
            property: "payload(path): Request targets file outside allowed scope".into(),
            offset: target.start, confidence: 0.95, verified: true,
            verification_method: Some("sensitive_path_match".into()),
        });
    }
    if let Some(nb) = tokens.iter().find(|t| t.token_type == PathTokenType::NullByte) {
        steps.push(ProofStep {
            operation: ProofOperation::SyntaxRepair, input: nb.value.clone(),
            output: "Null byte truncates extension validation".into(),
            property: "repair(path): Null byte bypasses file type check".into(),
            offset: nb.start, confidence: 0.93, verified: true,
            verification_method: Some("null_byte_detection".into()),
        });
    }
    if let Some(s) = l2_semantic_step(l2, input) { steps.push(s); }
    make_proof("Path traversal violates directory confinement invariant",
        steps, "path_traversal", "Directory traversal allows reading arbitrary files", input, l2)
}

// ── SSRF ────────────────────────────────────────────────────────

/// Construct an SSRF proof from URL parsing artifacts.
///
/// `input` is expected to contain a URL-like payload. `l2` contributes optional
/// semantic evidence.
///
/// Returns `Some(PropertyProof)` when outbound-request boundary/payload signals
/// are present; returns `None` for empty or non-URL-tokenizable input.
pub fn construct_ssrf_proof(input: &str, l2: Option<&DetectionResult>) -> Option<PropertyProof> {
    let stream = UrlTokenizer.tokenize(input);
    let tokens = stream.all();
    if tokens.is_empty() { return None; }
    let mut steps = Vec::new();

    if let Some(s) = tokens.iter().find(|t| t.token_type == UrlTokenType::Scheme) {
        let name = s.value.trim_end_matches(':').to_lowercase();
        let danger = ["gopher","file","dict","ftp","ldap","tftp"];
        steps.push(ProofStep {
            operation: ProofOperation::ContextEscape, input: s.value.clone(),
            output: format!("URL scheme \"{}\" initiates server-side request", name),
            property: format!("escape(ssrf): {}:// triggers outbound request", name),
            offset: s.start, confidence: if danger.contains(&name.as_str()) { 0.95 } else { 0.85 },
            verified: true, verification_method: Some("scheme_parse".into()),
        });
    }
    if let Some(m) = tokens.iter().find(|t| t.token_type == UrlTokenType::HostMetadata) {
        steps.push(ProofStep {
            operation: ProofOperation::PayloadInject, input: m.value.clone(),
            output: format!("Cloud metadata: {} — exposes IAM credentials", m.value),
            property: "payload(ssrf): targets cloud metadata (credential theft)".into(),
            offset: m.start, confidence: 0.98, verified: true,
            verification_method: Some("metadata_host_match".into()),
        });
    } else if let Some(i) = tokens.iter().find(|t| t.token_type == UrlTokenType::HostInternal) {
        steps.push(ProofStep {
            operation: ProofOperation::PayloadInject, input: i.value.clone(),
            output: format!("Internal host: {}", i.value),
            property: "payload(ssrf): targets internal network".into(),
            offset: i.start, confidence: 0.94, verified: true,
            verification_method: Some("private_ip_match".into()),
        });
    } else if let Some(o) = tokens.iter().find(|t| t.token_type == UrlTokenType::HostObfuscated) {
        steps.push(ProofStep {
            operation: ProofOperation::PayloadInject, input: o.value.clone(),
            output: format!("Obfuscated IP: {}", o.value),
            property: "payload(ssrf): IP obfuscation bypasses SSRF filter".into(),
            offset: o.start, confidence: 0.96, verified: true,
            verification_method: Some("ip_obfuscation_decode".into()),
        });
    }
    let paths: Vec<_> = tokens.iter().filter(|t| t.token_type == UrlTokenType::PathSegment).collect();
    if !paths.is_empty() {
        let full: String = paths.iter().map(|t| t.value.as_str()).collect();
        let sens = ["/latest/meta-data","/latest/api/token","/metadata/instance","/computeMetadata"];
        if sens.iter().any(|p| full.contains(p)) {
            steps.push(ProofStep {
                operation: ProofOperation::SyntaxRepair, input: full,
                output: "Path targets sensitive metadata API".into(),
                property: "repair(ssrf): path completes credential-exfiltration request".into(),
                offset: paths[0].start, confidence: 0.95, verified: true,
                verification_method: Some("sensitive_path_match".into()),
            });
        } else {
            steps.push(ProofStep {
                operation: ProofOperation::SyntaxRepair, input: paths[0].value.clone(),
                output: "Path completes valid HTTP request".into(),
                property: "repair(ssrf): URL path produces valid request".into(),
                offset: paths[0].start, confidence: 0.80, verified: false, verification_method: None,
            });
        }
    }
    if let Some(s) = l2_semantic_step(l2, input) { steps.push(s); }
    make_proof("SSRF violates network boundary confinement invariant",
        steps, "ssrf", "SSRF allows accessing internal services and cloud metadata", input, l2)
}

// ── XXE ─────────────────────────────────────────────────────────

/// Construct an XXE proof from XML entity declarations and usage.
///
/// `input` is the XML payload candidate. `l2` can append semantic evaluator
/// evidence.
///
/// Returns `Some(PropertyProof)` when DOCTYPE/entity signals indicate external
/// entity abuse; otherwise returns `None`.
pub fn construct_xxe_proof(input: &str, l2: Option<&DetectionResult>) -> Option<PropertyProof> {
    let mut steps = Vec::new();
    let doctype = Regex::new(r"(?is)<!DOCTYPE\b[^>]*?(?:\[[\s\S]*?\])?>").unwrap();
    if let Some(m) = doctype.find(input) {
        steps.push(ProofStep {
            operation: ProofOperation::ContextEscape, input: m.as_str().to_owned(),
            output: "DOCTYPE declaration enables DTD definitions".into(),
            property: "escape(xxe): DOCTYPE enables attacker DTD".into(),
            offset: m.start(), confidence: 0.90, verified: true,
            verification_method: Some("doctype_parse".into()),
        });
    }
    let entity = Regex::new(r#"(?i)<!ENTITY\s+(?:%\s+)?([a-zA-Z_][\w.-]*)\s+(SYSTEM|PUBLIC)\s+['"]([^'"]+)['"][^>]*>"#).unwrap();
    let decls: Vec<_> = entity.captures_iter(input).collect();
    if !decls.is_empty() {
        let c = &decls[0];
        steps.push(ProofStep {
            operation: ProofOperation::PayloadInject, input: c[0].to_owned(),
            output: format!("Entity \"{}\" via {}", &c[1], c[2].to_uppercase()),
            property: "payload(xxe): ENTITY introduces external resource".into(),
            offset: c.get(0).unwrap().start(), confidence: (0.90 + decls.len() as f64 * 0.02).min(0.99),
            verified: true, verification_method: Some("entity_reference_check".into()),
        });
    }
    let ext = Regex::new(r#"(?i)\b(?:SYSTEM|PUBLIC)\b\s+['"]((?:file|https?|ftp|gopher|expect|php)://[^'"]+)['"]"#).unwrap();
    if let Some(c) = ext.captures(input) {
        let uri = &c[1];
        steps.push(ProofStep {
            operation: ProofOperation::PayloadInject, input: uri.to_owned(),
            output: format!("External reference: {}", uri),
            property: "payload(xxe): external URI crosses trust boundary".into(),
            offset: c.get(1).unwrap().start(),
            confidence: if uri.to_lowercase().starts_with("file://") { 0.98 } else { 0.94 },
            verified: true, verification_method: Some("protocol_analysis".into()),
        });
    }
    let names: Vec<String> = decls.iter().map(|c| c[1].to_owned()).collect();
    let usage = Regex::new(r"&([a-zA-Z_][\w.-]*);").unwrap();
    for c in usage.captures_iter(input) {
        let name = &c[1];
        if names.is_empty() || names.iter().any(|n| n == name) {
            steps.push(ProofStep {
                operation: ProofOperation::SyntaxRepair, input: c[0].to_owned(),
                output: format!("Entity {} triggers expansion", &c[0]),
                property: "repair(xxe): entity usage completes expansion path".into(),
                offset: c.get(0).unwrap().start(),
                confidence: if names.iter().any(|n| n == name) { 0.95 } else { 0.82 },
                verified: true, verification_method: Some("entity_reference_check".into()),
            });
            break;
        }
    }
    if let Some(s) = l2_semantic_step(l2, input) { steps.push(s); }
    make_proof("XXE violates XML entity confinement invariant",
        steps, "xxe", "External entity enables file read, SSRF, and parser resource access", input, l2)
}

// ── SSTI ────────────────────────────────────────────────────────

/// Construct an SSTI proof from template delimiters and execution primitives.
///
/// `input` is the template payload candidate. `l2` can provide semantic
/// evidence.
///
/// Returns `Some(PropertyProof)` when delimiter/expression execution signals
/// are present; otherwise returns `None`.
pub fn construct_ssti_proof(input: &str, l2: Option<&DetectionResult>) -> Option<PropertyProof> {
    let mut steps = Vec::new();
    let delim = Regex::new(r"(?:\{\{|\$\{|#\{|<%=?|[{]%)").unwrap();
    let delims: Vec<_> = delim.find_iter(input).collect();
    if !delims.is_empty() {
        steps.push(ProofStep {
            operation: ProofOperation::ContextEscape, input: delims[0].as_str().to_owned(),
            output: format!("{} template delimiter(s) open eval context", delims.len()),
            property: "escape(ssti): delimiter escapes literal into expression eval".into(),
            offset: delims[0].start(), confidence: (0.84 + delims.len() as f64 * 0.03).min(0.97),
            verified: true, verification_method: Some("delimiter_match".into()),
        });
    }
    let expr = Regex::new(r"(?:\{\{|\$\{|#\{|<%=|<%|[{]%)([\s\S]*?)(?:\}\}|%>|\}|%\})").unwrap();
    if let Some(c) = expr.captures(input) {
        let e = c[1].trim();
        steps.push(ProofStep {
            operation: ProofOperation::PayloadInject, input: e[..e.len().min(120)].to_owned(),
            output: format!("Expression \"{}\" parsed for evaluation", &e[..e.len().min(60)]),
            property: "payload(ssti): expression enters template eval pipeline".into(),
            offset: c.get(0).unwrap().start(), confidence: 0.90,
            verified: true, verification_method: Some("expression_parse".into()),
        });
    }
    let trav = Regex::new(r"(?i)(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|constructor\s*\.\s*constructor|getClass|getRuntime|forName|ProcessBuilder)").unwrap();
    if let Some(m) = trav.find(input) {
        steps.push(ProofStep {
            operation: ProofOperation::PayloadInject, input: m.as_str().to_owned(),
            output: format!("Object traversal \"{}\" reaches privileged objects", m.as_str()),
            property: "payload(ssti): traversal accesses execution-capable internals".into(),
            offset: m.start(), confidence: 0.96, verified: true,
            verification_method: Some("traversal_chain_analysis".into()),
        });
    }
    let exec = Regex::new(r"(?i)(?:\bexec\s*\(|\beval\s*\(|\bsystem\s*\(|\bpopen\s*\(|__import__\s*\(|Runtime\s*\.\s*getRuntime\s*\(\)\s*\.\s*exec\s*\()").unwrap();
    if let Some(m) = exec.find(input) {
        steps.push(ProofStep {
            operation: ProofOperation::SyntaxRepair, input: m.as_str().to_owned(),
            output: format!("Execution primitive \"{}\"", m.as_str()),
            property: "repair(ssti): expression resolves to code execution".into(),
            offset: m.start(), confidence: 0.97, verified: true,
            verification_method: Some("execution_detection".into()),
        });
    }
    if let Some(s) = l2_semantic_step(l2, input) { steps.push(s); }
    make_proof("SSTI violates template evaluation confinement invariant",
        steps, "ssti", "Template injection enables object traversal and code execution", input, l2)
}

// ── Main Entry Point ────────────────────────────────────────────

/// Contract for swappable proof-construction subsystems.
pub trait ProofSubsystem: Send + Sync {
    /// Construct a property proof from a detection context.
    ///
    /// `category` is the proof domain key (for example `sqli`, `xss`, `cmdi`).
    /// `module_id` is the class/module identifier used for domain routing.
    /// `formal_property` is the invariant statement to embed in the proof.
    /// `description` is the impact narrative for downstream consumers.
    /// `input` is the untrusted payload under analysis.
    /// `l2` is optional structural-evaluator output used to enrich proof steps.
    ///
    /// Returns `Some(PropertyProof)` when a domain constructor can build at
    /// least one meaningful step, otherwise returns `None`.
    fn construct_proof(
        &self,
        category: &str,
        module_id: &str,
        formal_property: &str,
        description: &str,
        input: &str,
        l2: Option<&DetectionResult>,
    ) -> Option<PropertyProof>;
}

/// Default proof subsystem backed by built-in tokenizers and domain constructors.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultProofSubsystem;

impl ProofSubsystem for DefaultProofSubsystem {
    fn construct_proof(
        &self,
        category: &str,
        module_id: &str,
        formal_property: &str,
        description: &str,
        input: &str,
        l2: Option<&DetectionResult>,
    ) -> Option<PropertyProof> {
        construct_proof(category, module_id, formal_property, description, input, l2)
    }
}

/// Construct a [`PropertyProof`] for a detection context.
///
/// `category`, `module_id`, `formal_property`, `description`, and `input`
/// describe the detection context. `l2` optionally contributes structured
/// semantic evidence from L2 evaluators.
///
/// Returns a domain-specific proof when a supported constructor can recover
/// proof steps. If the domain is unknown but `l2.detected` is true, returns
/// a minimal semantic proof; otherwise returns `None`.
pub fn construct_proof(
    category: &str, module_id: &str, formal_property: &str, description: &str,
    input: &str, l2: Option<&DetectionResult>,
) -> Option<PropertyProof> {
    let domain = if module_id.starts_with("xxe_") { "xxe" }
        else if module_id.starts_with("ssti_") { "ssti" }
        else { match category { "sqli" => "sqli", "xss" => "xss", "cmdi" => "cmdi",
            "path_traversal" => "path_traversal", "ssrf" => "ssrf", "injection" => "sqli", c => c } };

    let mut proof = match domain {
        "sqli" => {
            let s = SqlTokenizer.tokenize(input);
            if !s.all().is_empty() { construct_sql_proof(input, l2) } else { None }
        }
        "xss" => construct_xss_proof(input, l2),
        "cmdi" => construct_cmd_proof(input, l2),
        "path_traversal" => construct_path_proof(input, l2),
        "ssrf" => construct_ssrf_proof(input, l2),
        "xxe" => construct_xxe_proof(input, l2),
        "ssti" => construct_ssti_proof(input, l2),
        _ => None,
    };

    if let Some(ref mut p) = proof {
        p.property = formal_property.to_owned();
        p.impact = description.to_owned();
        let mut enriched = apply_structured_evidence(proof.take().unwrap(), l2, input.len());
        seal_proof_chain(&mut enriched);
        return Some(enriched);
    }

    // Minimal proof from L2 for unknown domains
    let l2r = l2.filter(|r| r.detected)?;
    let minimal = PropertyProof {
        property: formal_property.into(), witness: witness(input),
        steps: vec![ProofStep {
            operation: ProofOperation::SemanticEval,
            input: l2r.evidence.clone().unwrap_or_else(|| safe_prefix(input, 100)),
            output: l2r.explanation.clone(), property: formal_property.into(),
            offset: 0, confidence: normalize_confidence(l2r.confidence), verified: false, verification_method: None,
        }],
        is_complete: false, domain: category.into(), impact: description.into(),
        proof_confidence: normalize_confidence(l2r.confidence) * 0.85, verified_steps: 0,
        verification_coverage: 0.0, verification_level: ProofVerificationLevel::None,
    };
    let mut minimal = apply_structured_evidence(minimal, l2, input.len());
    seal_proof_chain(&mut minimal);
    Some(minimal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn sql_proof_three_phases() {
        let proof = construct_sql_proof("' OR 1=1 --", None).unwrap();
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::ContextEscape));
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::PayloadInject));
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::SyntaxRepair));
        assert!(proof.is_complete);
        assert!(proof.proof_confidence >= 0.90);
    }

    #[test]
    fn xss_proof_script_tag() {
        let proof = construct_xss_proof("<script>alert(1)</script>", None).unwrap();
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::PayloadInject));
    }

    #[test]
    fn cmd_proof_semicolon() {
        let proof = construct_cmd_proof("; cat /etc/passwd", None).unwrap();
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::ContextEscape));
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::PayloadInject));
    }

    #[test]
    fn path_proof_traversal() {
        let proof = construct_path_proof("../../etc/passwd", None).unwrap();
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::ContextEscape));
    }

    #[test]
    fn ssrf_proof_metadata() {
        let proof = construct_ssrf_proof("http://169.254.169.254/latest/meta-data/", None).unwrap();
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::PayloadInject));
    }

    #[test]
    fn xxe_proof_entity() {
        let input = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#;
        let proof = construct_xxe_proof(input, None).unwrap();
        assert!(proof.is_complete);
    }

    #[test]
    fn ssti_proof_jinja() {
        let proof = construct_ssti_proof("{{config.__class__.__init__.__globals__}}", None).unwrap();
        assert!(proof.steps.iter().any(|s| s.operation == ProofOperation::PayloadInject));
    }

    #[test]
    fn confidence_increases_with_steps() {
        let one = vec![ProofStep {
            operation: ProofOperation::PayloadInject, input: "x".into(),
            output: "x".into(), property: "x".into(), offset: 0,
            confidence: 0.90, verified: false, verification_method: None,
        }];
        let (_, c1) = calculate_proof_metrics(&one, None);
        let mut two = one.clone();
        two.push(ProofStep {
            operation: ProofOperation::ContextEscape, input: "y".into(),
            output: "y".into(), property: "y".into(), offset: 0,
            confidence: 0.90, verified: false, verification_method: None,
        });
        let (_, c2) = calculate_proof_metrics(&two, None);
        assert!(c2 > c1);
    }

    #[test]
    fn dedupe_keeps_distinct_operations_on_same_offset() {
        let steps = vec![
            ProofStep {
                operation: ProofOperation::ContextEscape,
                input: "'".into(),
                output: "escape".into(),
                property: "x".into(),
                offset: 5,
                confidence: 0.8,
                verified: false,
                verification_method: None,
            },
            ProofStep {
                operation: ProofOperation::PayloadInject,
                input: "OR 1=1".into(),
                output: "payload".into(),
                property: "y".into(),
                offset: 5,
                confidence: 0.9,
                verified: false,
                verification_method: None,
            },
        ];
        let out = dedupe_non_semantic_steps_by_offset(steps);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn witness_does_not_panic_on_utf8_boundary() {
        let s = "é".repeat(250);
        let w = witness(&s);
        assert!(w.ends_with('…'));
        assert!(w.is_char_boundary(w.len()));
    }

    #[test]
    fn truncate_utf8_safe_handles_multibyte_cut() {
        let s = "Aé🙂Z";
        let cut = truncate_utf8_safe(s, 2);
        assert_eq!(cut, "A");
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
    }

    #[test]
    fn completeness_requires_ordered_chain() {
        let steps = vec![
            ProofStep {
                operation: ProofOperation::PayloadInject,
                input: "x".into(),
                output: "x".into(),
                property: "x".into(),
                offset: 1,
                confidence: 0.9,
                verified: false,
                verification_method: None,
            },
            ProofStep {
                operation: ProofOperation::ContextEscape,
                input: "x".into(),
                output: "x".into(),
                property: "x".into(),
                offset: 2,
                confidence: 0.9,
                verified: false,
                verification_method: None,
            },
            ProofStep {
                operation: ProofOperation::SyntaxRepair,
                input: "x".into(),
                output: "x".into(),
                property: "x".into(),
                offset: 3,
                confidence: 0.9,
                verified: false,
                verification_method: None,
            },
        ];
        let (complete, _) = calculate_proof_metrics(&steps, None);
        assert!(!complete);
    }

    #[test]
    fn completeness_requires_strict_chain_order() {
        let steps = vec![
            ProofStep {
                operation: ProofOperation::ContextEscape,
                input: "x".into(),
                output: "x".into(),
                property: "x".into(),
                offset: 1,
                confidence: 0.9,
                verified: false,
                verification_method: None,
            },
            ProofStep {
                operation: ProofOperation::PayloadInject,
                input: "x".into(),
                output: "x".into(),
                property: "x".into(),
                offset: 1,
                confidence: 0.9,
                verified: false,
                verification_method: None,
            },
            ProofStep {
                operation: ProofOperation::SyntaxRepair,
                input: "x".into(),
                output: "x".into(),
                property: "x".into(),
                offset: 2,
                confidence: 0.9,
                verified: false,
                verification_method: None,
            },
        ];
        assert!(!ordered_chain(&steps));
        let (complete, _) = calculate_proof_metrics(&steps, None);
        assert!(!complete);
    }

    #[test]
    fn proof_steps_are_chain_sealed() {
        let p = construct_sql_proof("' OR 1=1 --", None).unwrap();
        assert!(!p.steps.is_empty());
        assert!(p.steps.iter().all(|s| s.verification_method.as_deref().unwrap_or("").contains("chain:")));
        assert!(verify_proof_chain(&p));
    }

    #[test]
    fn chain_uses_sha256_length_hex() {
        let p = construct_sql_proof("' OR 1=1 --", None).unwrap();
        for step in &p.steps {
            let (_, chain) = split_chain_annotation(step.verification_method.as_deref());
            let chain = chain.unwrap();
            assert!(chain.starts_with("chain:"));
            assert_eq!(chain.len(), "chain:".len() + 64);
            assert!(chain["chain:".len()..].chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn sha256_matches_known_vector() {
        let digest = sha256(b"abc");
        assert_eq!(
            hex_32(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn empty_whitespace_and_null_only_inputs_do_not_panic() {
        assert!(construct_sql_proof("", None).is_none());
        assert!(construct_sql_proof("   \n\t", None).is_none());
        let null_only = "\0\0\0";
        let path = construct_path_proof(null_only, None);
        assert!(path.is_some());
        let xss = construct_xss_proof(null_only, None);
        assert!(xss.is_none() || !xss.unwrap().steps.is_empty());
    }

    #[test]
    fn handles_extremely_long_input_without_panic() {
        let mut payload = String::from("' OR 1=1 --");
        payload.push_str(&"A".repeat(1_048_576));
        let proof = construct_sql_proof(&payload, None);
        assert!(proof.is_some());
        assert!(proof.unwrap().witness.len() <= 203);
    }

    #[test]
    fn special_characters_in_matched_input_roundtrip_and_chain_verify() {
        let special = "\\\"line\n\r\t\u{0008}\u{000C}\0";
        let l2 = DetectionResult {
            detected: true,
            confidence: 0.91,
            explanation: "semantic".into(),
            evidence: Some(special.into()),
            structured_evidence: vec![crate::types::StructuredEvidence {
                operation: ProofOperation::PayloadInject,
                matched_input: special.into(),
                interpretation: "interp".into(),
                offset: 0,
                property: "prop".into(),
            }],
        };
        let proof = construct_proof("unknown", "mod", "formal", "impact", special, Some(&l2)).unwrap();
        assert!(verify_proof_chain(&proof));
        let json = serde_json::to_string(&proof).unwrap();
        let de: PropertyProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, de);
    }

    #[test]
    fn proof_serialization_roundtrip_identity() {
        let proof = construct_sql_proof("' OR 1=1 --", None).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let de: PropertyProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, de);
    }

    #[test]
    fn chain_verification_fails_when_top_level_fields_change() {
        let proof = construct_sql_proof("' OR 1=1 --", None).unwrap();
        assert!(verify_proof_chain(&proof));

        let mut tampered = proof.clone();
        tampered.witness.push('x');
        assert!(!verify_proof_chain(&tampered));

        let mut tampered = proof.clone();
        tampered.impact.push('x');
        assert!(!verify_proof_chain(&tampered));

        let mut tampered = proof.clone();
        tampered.proof_confidence = (tampered.proof_confidence - 0.1).max(0.0);
        assert!(!verify_proof_chain(&tampered));
    }

    #[test]
    fn chain_verification_fails_when_step_fields_change() {
        let proof = construct_sql_proof("' OR 1=1 --", None).unwrap();
        assert!(!proof.steps.is_empty());
        assert!(verify_proof_chain(&proof));

        let mut tampered = proof.clone();
        tampered.steps[0].input.push('x');
        assert!(!verify_proof_chain(&tampered));

        let mut tampered = proof.clone();
        tampered.steps[0].offset = tampered.steps[0].offset.saturating_add(1);
        assert!(!verify_proof_chain(&tampered));

        let mut tampered = proof.clone();
        tampered.steps[0].verified = !tampered.steps[0].verified;
        assert!(!verify_proof_chain(&tampered));
    }

    #[test]
    fn chain_verification_fails_on_step_reordering() {
        let proof = construct_sql_proof("' OR 1=1 --", None).unwrap();
        assert!(proof.steps.len() >= 2);
        assert!(verify_proof_chain(&proof));
        let mut tampered = proof.clone();
        tampered.steps.swap(0, 1);
        assert!(!verify_proof_chain(&tampered));
    }

    #[test]
    fn chain_verification_fails_on_corrupted_hash_annotation() {
        let proof = construct_sql_proof("' OR 1=1 --", None).unwrap();
        assert!(verify_proof_chain(&proof));
        let mut tampered = proof.clone();
        let vm = tampered.steps[0].verification_method.clone().unwrap();
        let corrupted = vm.replacen('a', "b", 1);
        tampered.steps[0].verification_method = Some(corrupted);
        assert!(!verify_proof_chain(&tampered));
    }

    #[test]
    fn chain_verification_fails_with_missing_chain_annotation() {
        let proof = construct_sql_proof("' OR 1=1 --", None).unwrap();
        assert!(verify_proof_chain(&proof));
        let mut tampered = proof.clone();
        tampered.steps[0].verification_method = Some("tokenizer_parse".into());
        assert!(!verify_proof_chain(&tampered));
    }

    #[test]
    fn chain_verification_fails_for_empty_step_list() {
        let proof = PropertyProof {
            property: "p".into(),
            witness: "w".into(),
            steps: vec![],
            is_complete: false,
            domain: "d".into(),
            impact: "i".into(),
            proof_confidence: 0.0,
            verified_steps: 0,
            verification_coverage: 0.0,
            verification_level: ProofVerificationLevel::None,
        };
        assert!(!verify_proof_chain(&proof));
    }

    #[test]
    fn field_boundary_rebinding_attempt_breaks_chain() {
        let proof = construct_sql_proof("' OR 1=1 --", None).unwrap();
        assert!(verify_proof_chain(&proof));
        let mut tampered = proof.clone();
        let original_output = tampered.steps[0].output.clone();
        tampered.steps[0].input = format!("{}|{}", tampered.steps[0].input, original_output);
        tampered.steps[0].output = String::new();
        assert!(!verify_proof_chain(&tampered));
    }

    #[test]
    fn malformed_json_deserialization_is_error_not_panic() {
        let malformed = r#"{"property":"x","steps":[{"operation":"payload_inject""#;
        let res = std::panic::catch_unwind(|| serde_json::from_str::<PropertyProof>(malformed));
        assert!(res.is_ok());
        assert!(res.unwrap().is_err());
    }

    #[test]
    fn missing_required_json_fields_are_rejected() {
        let minimal = r#"{"property":"x"}"#;
        let parsed = serde_json::from_str::<PropertyProof>(minimal);
        assert!(parsed.is_err());
    }

    #[test]
    fn unicode_roundtrip_all_proof_fields() {
        let mut proof = PropertyProof {
            property: "σύνθεση🧪".into(),
            witness: "証拠🙂".into(),
            steps: vec![ProofStep {
                operation: ProofOperation::PayloadInject,
                input: "入力Δ".into(),
                output: "выходΩ".into(),
                property: "属性λ".into(),
                offset: 3,
                confidence: 0.7777777777777,
                verified: true,
                verification_method: Some("méthode|検証".into()),
            }],
            is_complete: true,
            domain: "δοκιμή".into(),
            impact: "影響🚨".into(),
            proof_confidence: 0.987654321,
            verified_steps: 1,
            verification_coverage: 1.0,
            verification_level: ProofVerificationLevel::Verified,
        };
        seal_proof_chain(&mut proof);
        assert!(verify_proof_chain(&proof));
        let json = serde_json::to_string(&proof).unwrap();
        let de: PropertyProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, de);
    }

    #[test]
    fn concurrent_proof_generation_chain_is_consistent() {
        let workers = 12usize;
        let iters = 60usize;
        let mut handles = Vec::new();
        for _ in 0..workers {
            handles.push(std::thread::spawn(move || {
                for _ in 0..iters {
                    let p = construct_sql_proof("' OR 1=1 --", None).unwrap();
                    assert!(verify_proof_chain(&p));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn maximum_chain_length_is_verifiable() {
        let mut proof = PropertyProof {
            property: "max-len".into(),
            witness: "w".into(),
            steps: (0..4096)
                .map(|i| ProofStep {
                    operation: if i % 3 == 0 {
                        ProofOperation::ContextEscape
                    } else if i % 3 == 1 {
                        ProofOperation::PayloadInject
                    } else {
                        ProofOperation::SyntaxRepair
                    },
                    input: format!("in{i}"),
                    output: format!("out{i}"),
                    property: format!("prop{i}"),
                    offset: i,
                    confidence: 0.9,
                    verified: i % 2 == 0,
                    verification_method: Some("tokenizer_parse".into()),
                })
                .collect(),
            is_complete: true,
            domain: "bulk".into(),
            impact: "stress".into(),
            proof_confidence: 0.9,
            verified_steps: 0,
            verification_coverage: 0.0,
            verification_level: ProofVerificationLevel::None,
        };
        proof.recompute_verification();
        seal_proof_chain(&mut proof);
        assert!(verify_proof_chain(&proof));
    }

    #[test]
    fn undetected_l2_structured_evidence_is_ignored() {
        let spoof = DetectionResult {
            detected: false,
            confidence: 0.99,
            explanation: "spoof".into(),
            evidence: Some("spoof".into()),
            structured_evidence: vec![
                crate::types::StructuredEvidence {
                    operation: ProofOperation::ContextEscape,
                    matched_input: "X".into(),
                    interpretation: "Y".into(),
                    offset: 0,
                    property: "spoof_escape".into(),
                },
                crate::types::StructuredEvidence {
                    operation: ProofOperation::PayloadInject,
                    matched_input: "X".into(),
                    interpretation: "Y".into(),
                    offset: 1,
                    property: "spoof_payload".into(),
                },
                crate::types::StructuredEvidence {
                    operation: ProofOperation::SyntaxRepair,
                    matched_input: "X".into(),
                    interpretation: "Y".into(),
                    offset: 2,
                    property: "spoof_repair".into(),
                },
            ],
        };
        let p = construct_proof("sqli", "sqli_mod", "f", "i", "' OR 1=1 --", Some(&spoof)).unwrap();
        assert!(p.steps.iter().all(|s| !s.property.starts_with("spoof_")));
    }

    #[test]
    fn empty_structured_evidence_fields_are_dropped() {
        let l2 = DetectionResult {
            detected: true,
            confidence: 0.91,
            explanation: "semantic".into(),
            evidence: Some("e".into()),
            structured_evidence: vec![
                crate::types::StructuredEvidence {
                    operation: ProofOperation::PayloadInject,
                    matched_input: "   ".into(),
                    interpretation: "".into(),
                    offset: 0,
                    property: "\n\t".into(),
                },
                crate::types::StructuredEvidence {
                    operation: ProofOperation::PayloadInject,
                    matched_input: "real".into(),
                    interpretation: "i".into(),
                    offset: 0,
                    property: "p".into(),
                },
            ],
        };
        let p = construct_proof("unknown", "mod", "f", "i", "real", Some(&l2)).unwrap();
        assert!(p.steps.iter().any(|s| s.input == "real"));
        assert!(!p.steps.iter().any(|s| s.input.trim().is_empty() && s.output.trim().is_empty() && s.property.trim().is_empty()));
    }

    #[test]
    fn structured_evidence_offset_is_clamped_to_input_len() {
        let l2 = DetectionResult {
            detected: true,
            confidence: 0.87,
            explanation: "semantic".into(),
            evidence: None,
            structured_evidence: vec![crate::types::StructuredEvidence {
                operation: ProofOperation::PayloadInject,
                matched_input: "abc".into(),
                interpretation: "interp".into(),
                offset: 9_999_999,
                property: "p".into(),
            }],
        };
        let input = "abcd";
        let p = construct_proof("unknown", "mod", "f", "i", input, Some(&l2)).unwrap();
        assert!(p.steps.iter().all(|s| s.offset <= input.len()));
    }
}
