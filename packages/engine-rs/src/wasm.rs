#![cfg(feature = "wasm")]

use std::cell::RefCell;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

use crate::runtime::{DefenseAction, DetectedTech, UnifiedRequest, UnifiedResponse, UnifiedRuntime};
use crate::types::{AnalysisRequest, InputContext, InvariantClass};

const STREAM_TAIL_BYTES: usize = 1024;
const STREAM_BUFFER_BYTES: usize = crate::types::MAX_TOKENIZER_INPUT;

// Keep this compile-time guard explicit for wasm builds.
#[cfg(target_arch = "wasm32")]
const _: () = assert!(std::mem::size_of::<usize>() == 4);

thread_local! {
    static SHARED_RUNTIME: RefCell<UnifiedRuntime> = RefCell::new(UnifiedRuntime::new());
}

fn with_shared_runtime<R>(handler: impl FnOnce(&mut UnifiedRuntime) -> R) -> R {
    SHARED_RUNTIME.with(|runtime| {
        let mut runtime = runtime.borrow_mut();
        handler(&mut runtime)
    })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WasmDetectedTech {
    vendor: String,
    product: String,
    framework: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WasmUnifiedRequest {
    input: String,
    source_hash: Option<String>,
    method: Option<String>,
    path: Option<String>,
    content_type: Option<String>,
    known_context: Option<InputContext>,
    headers: Option<Vec<(String, String)>>,
    user_agent: Option<String>,
    ja3: Option<String>,
    source_reputation: Option<f64>,
    detected_tech: Option<WasmDetectedTech>,
    param_name: Option<String>,
    response_status: Option<u16>,
    response_headers: Option<Vec<(String, String)>>,
    response_body: Option<String>,
    recent_paths: Option<Vec<String>>,
    recent_intervals_ms: Option<Vec<u64>>,
    timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WasmStreamConfig {
    source_hash: Option<String>,
    method: Option<String>,
    path: Option<String>,
    content_type: Option<String>,
    known_context: Option<InputContext>,
    headers: Option<Vec<(String, String)>>,
    user_agent: Option<String>,
    ja3: Option<String>,
    source_reputation: Option<f64>,
    detected_tech: Option<WasmDetectedTech>,
    param_name: Option<String>,
    response_status: Option<u16>,
    response_headers: Option<Vec<(String, String)>>,
    response_body: Option<String>,
    recent_paths: Option<Vec<String>>,
    recent_intervals_ms: Option<Vec<u64>>,
    timestamp: Option<u64>,
    max_buffered_bytes: Option<usize>,
    allow_truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
struct WasmStreamMetadata {
    chunks_processed: u32,
    total_bytes: usize,
    buffered_bytes: usize,
    max_buffered_bytes: usize,
    truncated: bool,
    allow_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
struct WasmBinaryResponseMeta {
    codec: &'static str,
    transport: &'static str,
    version: &'static str,
}

impl WasmStreamConfig {
    fn into_request(self, input: String) -> WasmUnifiedRequest {
        WasmUnifiedRequest {
            input,
            source_hash: self.source_hash,
            method: Some(self.method.unwrap_or_else(|| "GET".to_owned())),
            path: Some(self.path.unwrap_or_else(|| "/".to_owned())),
            content_type: self.content_type,
            known_context: self.known_context,
            headers: self.headers,
            user_agent: self.user_agent,
            ja3: self.ja3,
            source_reputation: self.source_reputation,
            detected_tech: self.detected_tech,
            param_name: self.param_name,
            response_status: self.response_status,
            response_headers: self.response_headers,
            response_body: self.response_body,
            recent_paths: self.recent_paths,
            recent_intervals_ms: self.recent_intervals_ms,
            timestamp: self.timestamp,
        }
    }

    fn max_buffered_bytes(&self) -> usize {
        self.max_buffered_bytes
            .unwrap_or(STREAM_BUFFER_BYTES)
            .clamp(STREAM_TAIL_BYTES, STREAM_BUFFER_BYTES.saturating_mul(4))
    }
}

impl From<WasmDetectedTech> for DetectedTech {
    fn from(value: WasmDetectedTech) -> Self {
        Self {
            vendor: value.vendor,
            product: value.product,
            framework: value.framework,
            version: value.version,
        }
    }
}

impl From<WasmUnifiedRequest> for UnifiedRequest {
    fn from(value: WasmUnifiedRequest) -> Self {
        Self {
            input: value.input,
            source_hash: value.source_hash.unwrap_or_else(|| "wasm".to_owned()),
            method: value.method.unwrap_or_else(|| "GET".to_owned()),
            path: value.path.unwrap_or_else(|| "/".to_owned()),
            content_type: value.content_type,
            known_context: value.known_context,
            headers: value.headers.unwrap_or_default(),
            user_agent: value.user_agent,
            ja3: value.ja3,
            source_reputation: value.source_reputation,
            detected_tech: value.detected_tech.map(Into::into),
            param_name: value.param_name,
            rasp_context: None,
            response_status: value.response_status,
            response_headers: value.response_headers,
            response_body: value.response_body,
            recent_paths: value.recent_paths.unwrap_or_default(),
            recent_intervals_ms: value.recent_intervals_ms.unwrap_or_default(),
            timestamp: value.timestamp.unwrap_or(0),
        }
    }
}

#[inline]
fn serialize_to_js<T: Serialize>(value: &T) -> JsValue {
    match serde_json::to_string(value) {
        Ok(json_str) => JsValue::from_str(&json_str),
        Err(err) => error_js(&format!("serialization_error: {err}")),
    }
}

#[inline]
fn to_binary<T: Serialize>(value: &T) -> Vec<u8> {
    match serde_json::to_vec(value) {
        Ok(bytes) => bytes,
        Err(_) => b"{}".to_vec(),
    }
}

#[inline]
fn error_js(message: &str) -> JsValue {
    let payload = json!({ "error": message });
    match serde_json::to_string(&payload) {
        Ok(json_str) => JsValue::from_str(&json_str),
        Err(_) => JsValue::from_str("{\"error\":\"unknown_error\"}"),
    }
}

fn to_decision_action(action: DefenseAction) -> &'static str {
    match action {
        DefenseAction::Allow => "allow",
        DefenseAction::Monitor => "monitor",
        DefenseAction::Throttle => "throttle",
        DefenseAction::Challenge => "challenge",
        DefenseAction::Block => "block",
        DefenseAction::Lockdown => "lockdown",
    }
}

fn process_response_to_json(response: &UnifiedResponse) -> Value {
    let chain_matches: Vec<Value> = response.chain_matches.iter().map(|chain| {
        let step_matches: Vec<Value> = chain.step_matches.iter().map(|step| {
            json!({
                "step_index": step.step_index,
                "description": step.description,
                "matched_class": step.matched_class,
                "confidence": step.confidence,
                "timestamp": step.timestamp,
                "path": step.path,
            })
        }).collect();

        json!({
            "chain_id": chain.chain_id,
            "name": chain.name,
            "steps_matched": chain.steps_matched,
            "total_steps": chain.total_steps,
            "completion": chain.completion,
            "confidence": chain.confidence,
            "severity": chain.severity.as_str(),
            "description": chain.description,
            "recommended_action": chain.recommended_action.as_str(),
            "step_matches": step_matches,
            "duration_seconds": chain.duration_seconds,
            "source_hash": chain.source_hash,
        })
    }).collect();

    let active_campaign = response.active_campaign.as_ref().map(|campaign| {
        json!({
            "id": campaign.id,
            "campaign_type": format!("{:?}", campaign.campaign_type),
            "fingerprints": campaign.fingerprints,
            "source_count": campaign.source_count,
            "attack_types": campaign.attack_types,
            "target_paths": campaign.target_paths,
            "start_time": campaign.start_time,
            "last_activity": campaign.last_activity,
            "severity": format!("{:?}", campaign.severity),
            "description": campaign.description,
            "escalated": campaign.escalated,
        })
    });

    let effect_simulation = response.effect_simulation.as_ref().map(|effect| {
        let chain: Vec<Value> = effect.chain.iter().map(|step| {
            json!({
                "step": step.step,
                "description": step.description,
                "output": step.output,
            })
        }).collect();

        json!({
            "operation": format!("{:?}", effect.operation),
            "proof": {
                "statement": effect.proof.statement,
                "derivation": effect.proof.derivation,
                "is_complete": effect.proof.is_complete,
                "certainty": effect.proof.certainty,
            },
            "impact": {
                "confidentiality": effect.impact.confidentiality,
                "integrity": effect.impact.integrity,
                "availability": effect.impact.availability,
                "exposure_estimate": effect.impact.exposure_estimate,
                "base_score": effect.impact.base_score,
            },
            "preconditions": effect.preconditions,
            "chain": chain,
        })
    });

    let adversary_fingerprint = response.adversary_fingerprint.as_ref().map(|fp| {
        json!({
            "tool": fp.tool,
            "confidence": fp.confidence,
            "indicators": fp.indicators,
            "skill_level": format!("{:?}", fp.skill_level),
            "automated": fp.automated,
        })
    });

    let shape_validation = response.shape_validation.as_ref().map(|shape| {
        let violations: Vec<Value> = shape.violations.iter().map(|violation| {
            json!({
                "constraint": violation.constraint,
                "expected": violation.expected,
                "found": violation.found,
                "severity": violation.severity,
            })
        }).collect();

        json!({
            "matches": shape.matches,
            "deviation": shape.deviation,
            "violations": violations,
            "confidence_boost": shape.confidence_boost,
            "detail": shape.detail,
        })
    });

    let response_plan = response.response_plan.as_ref().map(|plan| {
        let recommendations: Vec<Value> = plan.recommendations.iter().map(|recommendation| {
            json!({
                "id": recommendation.id,
                "urgency": format!("{:?}", recommendation.urgency),
                "category": format!("{:?}", recommendation.category),
                "action": recommendation.action,
                "rationale": recommendation.rationale,
                "steps": recommendation.steps,
                "triggered_by": recommendation.triggered_by,
            })
        }).collect();

        json!({
            "severity": format!("{:?}", plan.severity),
            "recommendations": recommendations,
            "summary": plan.summary,
            "blast_radius": plan.blast_radius,
            "requires_human": plan.requires_human,
        })
    });

    json!({
        "analysis": response.analysis,
        "highest_severity": response.highest_severity,
        "chain_matches": chain_matches,
        "active_campaign": active_campaign,
        "attack_phase": response.attack_phase.map(|phase| format!("{:?}", phase)),
        "threat_level": response.threat_level,
        "bot_score": response.bot_score,
        "bot_classification": response.bot_classification,
        "linked_cve_count": response.linked_cve_count,
        "actively_exploited_cves": response.actively_exploited_cves,
        "highest_epss": response.highest_epss,
        "decision": {
            "action": to_decision_action(response.decision.action),
            "reason": response.decision.reason,
            "confidence": response.decision.confidence,
            "contributors": response.decision.contributors,
            "alert": response.decision.alert,
        },
        "mitre_techniques": response.mitre_techniques,
        "compliance_mappings": response.compliance_mappings,
        "effect_simulation": effect_simulation,
        "adversary_fingerprint": adversary_fingerprint,
        "shape_validation": shape_validation,
        "response_plan": response_plan,
        "total_processing_time_us": response.total_processing_time_us,
    })
}

fn process_response_to_json_with_stream(
    response: &UnifiedResponse,
    stream_info: Option<&WasmStreamMetadata>,
) -> Value {
    let mut payload = process_response_to_json(response);
    if let Some(meta) = stream_info {
        if let Value::Object(map) = &mut payload {
            let meta_value = serde_json::to_value(meta).unwrap_or_else(|_| json!({
                "error": "stream_metadata_serialize_failed",
            }));
            map.insert("streaming".to_string(), meta_value);
        }
    }
    payload
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn detect(input: &str) -> JsValue {
    with_shared_runtime(|runtime| {
        let matches = runtime.engine.detect(input);
        serialize_to_js(&matches)
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn analyze(input_json: &str) -> JsValue {
    with_shared_runtime(|runtime| {
        let request: AnalysisRequest = match serde_json::from_str(input_json) {
            Ok(request) => request,
            Err(err) => return error_js(&format!("invalid_analysis_request_json: {err}")),
        };
        let result = runtime.engine.analyze(&request);
        serialize_to_js(&result)
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn process_batch(requests_json: &str) -> JsValue {
    let requests: Vec<WasmUnifiedRequest> = match serde_json::from_str(requests_json) {
        Ok(requests) => requests,
        Err(err) => return error_js(&format!("invalid_unified_batch_json: {err}")),
    };

    with_shared_runtime(|runtime| {
        let responses: Vec<Value> = requests
            .into_iter()
            .map(|request| {
                let request = request.into();
                let response = runtime.process(&request);
                process_response_to_json_with_stream(&response, None)
            })
            .collect();

        serialize_to_js(&responses)
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn process(request_json: &str) -> JsValue {
    with_shared_runtime(|runtime| {
        let request: WasmUnifiedRequest = match serde_json::from_str(request_json) {
            Ok(request) => request,
            Err(err) => return error_js(&format!("invalid_unified_request_json: {err}")),
        };

        let request: UnifiedRequest = request.into();
        let response = runtime.process(&request);
        serialize_to_js(&process_response_to_json_with_stream(&response, None))
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn process_binary(request_json: &str) -> Vec<u8> {
    let request: WasmUnifiedRequest = match serde_json::from_str(request_json) {
        Ok(request) => request,
        Err(_) => return to_binary(&WasmBinaryResponseMeta {
            codec: "application/json",
            transport: "json-binary",
            version: "1.0",
        }),
    };

    let response = with_shared_runtime(|runtime| {
        let request: UnifiedRequest = request.into();
        runtime.process(&request)
    });

    to_binary(&process_response_to_json_with_stream(&response, None))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn create_runtime() -> WasmRuntime {
    WasmRuntime {
        runtime: UnifiedRuntime::new(),
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[wasm_bindgen]
pub struct WasmRuntime {
    runtime: UnifiedRuntime,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmRuntime {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmRuntime {
        create_runtime()
    }

    pub fn detect(&self, input: &str) -> JsValue {
        let matches = self.runtime.engine.detect(input);
        serialize_to_js(&matches)
    }

    pub fn analyze(&self, input_json: &str) -> JsValue {
        let request: AnalysisRequest = match serde_json::from_str(input_json) {
            Ok(request) => request,
            Err(err) => return error_js(&format!("invalid_analysis_request_json: {err}")),
        };

        let result = self.runtime.engine.analyze(&request);
        serialize_to_js(&result)
    }

    pub fn process(&mut self, request_json: &str) -> JsValue {
        let request: WasmUnifiedRequest = match serde_json::from_str(request_json) {
            Ok(request) => request,
            Err(err) => return error_js(&format!("invalid_unified_request_json: {err}")),
        };

        let request: UnifiedRequest = request.into();
        let response = self.runtime.process(&request);
        serialize_to_js(&process_response_to_json_with_stream(&response, None))
    }

    pub fn process_batch(&mut self, requests_json: &str) -> JsValue {
        let requests: Vec<WasmUnifiedRequest> = match serde_json::from_str(requests_json) {
            Ok(requests) => requests,
            Err(err) => return error_js(&format!("invalid_unified_batch_json: {err}")),
        };

        let responses: Vec<Value> = requests
            .into_iter()
            .map(|request| {
                let request: UnifiedRequest = request.into();
                let response = self.runtime.process(&request);
                process_response_to_json_with_stream(&response, None)
            })
            .collect();
        serialize_to_js(&responses)
    }

    pub fn process_binary(&mut self, request_json: &str) -> Vec<u8> {
        let request: WasmUnifiedRequest = match serde_json::from_str(request_json) {
            Ok(request) => request,
            Err(_) => return to_binary(&WasmBinaryResponseMeta {
                codec: "application/json",
                transport: "json-binary",
                version: "1.0",
            }),
        };

        let request: UnifiedRequest = request.into();
        let response = self.runtime.process(&request);
        to_binary(&process_response_to_json_with_stream(&response, None))
    }
}

fn trim_prefix_keep_suffix(text: &mut String, max_len: usize) {
    if max_len == 0 {
        text.clear();
        return;
    }

    if text.len() <= max_len {
        return;
    }

    let mut cut = text.len() - max_len;
    while cut < text.len() && !text.is_char_boundary(cut) {
        cut += 1;
    }
    if cut < text.len() {
        text.drain(..cut);
    } else {
        text.clear();
    }
}

#[wasm_bindgen]
pub struct WasmStreamProcessor {
    runtime: UnifiedRuntime,
    request_template: WasmUnifiedRequest,
    tail: String,
    buffer: String,
    observed_matches: HashMap<InvariantClass, f64>,
    total_chunks: u32,
    total_bytes: usize,
    max_buffered_bytes: usize,
    allow_truncated: bool,
    finalized: bool,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmStreamProcessor {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmStreamProcessor {
        WasmStreamProcessor {
            runtime: UnifiedRuntime::new(),
            request_template: WasmUnifiedRequest {
                input: String::new(),
                source_hash: Some("stream".to_owned()),
                method: Some("GET".to_owned()),
                path: Some("/".to_owned()),
                content_type: None,
                known_context: None,
                headers: None,
                user_agent: None,
                ja3: None,
                source_reputation: None,
                detected_tech: None,
                param_name: None,
                response_status: None,
                response_headers: None,
                response_body: None,
                recent_paths: None,
                recent_intervals_ms: None,
                timestamp: None,
            },
            tail: String::new(),
            buffer: String::new(),
            observed_matches: HashMap::new(),
            total_chunks: 0,
            total_bytes: 0,
            max_buffered_bytes: STREAM_BUFFER_BYTES,
            allow_truncated: true,
            finalized: false,
        }
    }

    pub fn configure(&mut self, config_json: &str) -> JsValue {
        let config: WasmStreamConfig = match serde_json::from_str(config_json) {
            Ok(config) => config,
            Err(err) => return error_js(&format!("invalid_stream_config_json: {err}")),
        };

        self.tail.clear();
        self.buffer.clear();
        self.observed_matches.clear();
        self.total_chunks = 0;
        self.total_bytes = 0;
        self.max_buffered_bytes = config.max_buffered_bytes();
        self.allow_truncated = config.allow_truncated.unwrap_or(true);
        self.request_template = config.into_request(String::new());
        self.finalized = false;

        serialize_to_js(&json!({
            "status": "ok",
            "max_buffered_bytes": self.max_buffered_bytes,
            "allow_truncated": self.allow_truncated,
        }))
    }

    pub fn push_chunk(&mut self, chunk: &str) -> JsValue {
        if self.finalized {
            return error_js("stream_processor_finalized");
        }

        let chunk_len = chunk.len();
        self.total_chunks = self.total_chunks.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(chunk_len);

        if chunk.is_empty() {
            let snapshot = json!({
                "status": "ok",
                "chunks_processed": self.total_chunks,
                "total_bytes": self.total_bytes,
                "running_matches": self.observed_matches.len(),
                "tail_bytes": self.tail.len(),
                "buffer_bytes": self.buffer.len(),
                "truncated": self.buffer.len() > self.max_buffered_bytes,
            });
            return serialize_to_js(&snapshot);
        }

        let mut lookahead = String::with_capacity(self.tail.len() + chunk.len());
        lookahead.push_str(&self.tail);
        lookahead.push_str(chunk);

        let matches = self.runtime.engine.detect(&lookahead);
        for m in matches {
            self.observed_matches
                .entry(m.class)
                .and_modify(|e| {
                    if m.confidence > *e {
                        *e = m.confidence;
                    }
                })
                .or_insert(m.confidence);
        }

        self.tail.push_str(chunk);
        trim_prefix_keep_suffix(&mut self.tail, STREAM_TAIL_BYTES);

        self.buffer.push_str(chunk);
        if self.buffer.len() > self.max_buffered_bytes {
            trim_prefix_keep_suffix(&mut self.buffer, self.max_buffered_bytes);
        }

        let observed_count = self.observed_matches.len();
        let top_confidence = self
            .observed_matches
            .iter()
            .map(|(_, conf)| *conf)
            .fold(0.0_f64, f64::max);

        let snapshot = json!({
            "status": "ok",
            "chunks_processed": self.total_chunks,
            "total_bytes": self.total_bytes,
            "running_matches": observed_count,
            "max_confidence": top_confidence,
            "tail_bytes": self.tail.len(),
            "buffer_bytes": self.buffer.len(),
            "truncated": self.buffer.len() > self.max_buffered_bytes,
            "detected_classes": self
                .observed_matches
                .iter()
                .map(|(class, confidence)| json!({
                    "class": format!("{:?}", class),
                    "confidence": confidence,
                }))
                .collect::<Vec<_>>(),
        });
        serialize_to_js(&snapshot)
    }

    pub fn finalize(&mut self) -> JsValue {
        if self.finalized {
            return error_js("stream_processor_finalized");
        }
        self.finalized = true;

        let truncated = self.total_bytes > self.max_buffered_bytes;
        if truncated && !self.allow_truncated {
            return error_js("stream_data_truncated_and_dropped");
        }

        let request_data = std::mem::replace(&mut self.buffer, String::new());
        self.request_template.input = request_data;
        let request: UnifiedRequest = self.request_template.clone().into();
        let response = self.runtime.process(&request);

        let metadata = WasmStreamMetadata {
            chunks_processed: self.total_chunks,
            total_bytes: self.total_bytes,
            buffered_bytes: self.request_template.input.len(),
            max_buffered_bytes: self.max_buffered_bytes,
            truncated,
            allow_truncated: self.allow_truncated,
        };
        serialize_to_js(&process_response_to_json_with_stream(&response, Some(&metadata)))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "wasm")]
    use super::*;

    #[cfg(feature = "wasm")]
    #[test]
    fn returns_error_json_on_invalid_request() {
        let value = process("{invalid-json");
        let s = value.as_string().unwrap_or_default();
        assert!(s.contains("error"));
    }
}
