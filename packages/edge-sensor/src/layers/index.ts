/**
 * Edge Sensor — Layers Barrel Export
 *
 * All detection layers and utilities re-exported from a single entry point.
 */

// Types
export type { Env, Signal, SignatureRule, RequestContext, ClientClass } from './types.js'

// Encoding
export { safeDecode, deepDecode } from './encoding.js'

// L1: Static Signatures
export { SIGNATURES } from './l1-signatures.js'

// L2: Behavioral Analysis
export { BehaviorTracker } from './l2-behavior.js'

// L3: Client Fingerprinting
export { classifyClient } from './l3-fingerprint.js'

// L4: Technology Detection
export { detectTechnology } from './l4-tech-detect.js'

// Signal Buffer
export { SignalBuffer } from './signal-buffer.js'

// Utilities
export { hashSource, detectHeaderAnomalies, blockResponse, normalizePath } from './utils.js'
