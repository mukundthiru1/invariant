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

pub mod types;
pub mod encoding;
pub mod tokenizers;
pub mod classes;
pub mod evaluators;
pub mod proof;
pub mod chain;
pub mod mitre;
pub mod compliance;
pub mod engine;
pub mod entropy;
pub mod file_analysis;
pub mod normalizer;
pub mod polyglot;
pub mod intent;
pub mod shape;
pub mod effect;
pub mod response;
pub mod response_analysis;
pub mod api_schema;
pub mod campaign;
pub mod knowledge;
pub mod threat_intel;
pub mod telemetry;
pub mod bot_detect;
pub mod runtime;
pub mod rasp;
pub mod body_parser;
pub mod request_decomposer;
pub mod defense_validator;
pub mod adaptive_baseline;
pub mod deception;
#[cfg(feature = "wasm")]
pub mod wasm;
