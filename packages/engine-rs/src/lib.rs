//! INVARIANT Detection Engine
//!
//! A zero-dependency security detection engine that produces mathematical
//! proofs of exploit viability. Runs at the CDN edge via WebAssembly.
//!
//! Architecture:
//!   L1: Compiled regex multi-pattern scan (all 66 classes in one DFA pass)
//!   L2: Structural evaluators (tokenizer-based property analysis)
//!   L3: Input decomposition pipeline (multi-layer decode → context → properties)
//!
//! Every detection produces a PropertyProof — a machine-verifiable chain
//! showing exactly how the input violates a mathematical invariant.

pub mod adaptive_baseline;
pub mod api_schema;
pub mod body_parser;
pub mod bot_detect;
pub mod campaign;
pub mod chain;
pub mod class_registry;
pub mod classes;
pub mod compliance;
pub mod deception;
pub mod defense_validator;
pub mod effect;
pub mod encoding;
pub mod engine;
pub mod entropy;
pub mod evaluators;
pub mod file_analysis;
pub mod intent;
pub mod knowledge;
pub mod mitre;
pub mod normalizer;
pub mod polyglot;
pub mod proof;
pub mod rasp;
pub mod request_decomposer;
pub mod response;
pub mod response_analysis;
pub mod runtime;
pub mod shape;
pub mod telemetry;
pub mod threat_intel;
pub mod tiers;
pub mod tokenizers;
pub mod types;
pub mod zero_trust;
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn classify_zero_trust_tier(threat_level: f64) -> u8 {
    tiers::ZeroTrustTier::from_threat_level(threat_level).numeric_value()
}
