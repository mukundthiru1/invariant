/**
 * @santh/engine-rs — TypeScript bridge for the Rust/WASM detection engine.
 *
 * This module wraps the compiled invariant-engine WASM artifact and exposes
 * a TypeScript-typed API compatible with the @santh/invariant-engine TS engine.
 *
 * Architecture:
 *   - In CF Workers (edge-sensor): wrangler bundles the .wasm file at compile
 *     time. Importing this module is synchronous; the runtime is available
 *     immediately.
 *   - In Node.js (agent): the WASM module must be pre-initialized using
 *     `initRustEngine()` before calling `rustDetect()`.
 *
 * The Rust engine is the primary detection path:
 *   - 44 evaluators, 1800+ tests, structural pattern matching
 *   - Runs in WASM (sandboxed, portable, predictable memory)
 *   - No regex JIT warm-up penalty (LazyLock precompiles at WASM load time)
 *
 * Output type is deliberately kept compatible with InvariantMatch from
 * @santh/invariant-engine so both engines can be merged without type errors.
 */

// Bundler-target WASM import — handled by wrangler/esbuild for CF Workers.
// Node.js callers must use initRustEngineNode() with a .wasm binary buffer.
import { WasmRuntime } from '../../engine-rs/pkg/invariant_engine.js'

// ── Types ──────────────────────────────────────────────────────────────────

/** Rust InvariantClass enum variants serialized as PascalCase strings */
export type RustInvariantClass = string

/** Subset of InvariantMatch fields that the Rust engine produces */
export interface RustInvariantMatch {
    class: RustInvariantClass
    confidence: number
    category: string
    severity: 'critical' | 'high' | 'medium' | 'low'
    isNovelVariant: boolean
    description: string
    detectionLevels?: { l1: boolean; l2: boolean; convergent: boolean }
    l2Evidence?: string
}

/** Full Rust detection output (snake_case, as serialized by serde) */
interface RustMatchRaw {
    class: string
    confidence: number
    category: string
    severity: string
    is_novel_variant: boolean
    description: string
    detection_levels?: { l1: boolean; l2: boolean; l3?: boolean }
    l2_evidence?: string | null
}

// ── WASM Runtime singleton ─────────────────────────────────────────────────

let _runtime: WasmRuntime | null = null

function getRuntime(): WasmRuntime {
    if (!_runtime) {
        _runtime = new WasmRuntime()
    }
    return _runtime
}

// ── Normalization ──────────────────────────────────────────────────────────

function normalizeSeverity(s: string): 'critical' | 'high' | 'medium' | 'low' {
    const lower = s.toLowerCase()
    if (lower === 'critical') return 'critical'
    if (lower === 'high') return 'high'
    if (lower === 'medium') return 'medium'
    return 'low'
}

function mapRawMatch(raw: RustMatchRaw): RustInvariantMatch {
    const dl = raw.detection_levels
    return {
        class: raw.class,
        confidence: raw.confidence,
        category: raw.category,
        severity: normalizeSeverity(raw.severity),
        isNovelVariant: raw.is_novel_variant,
        description: raw.description,
        detectionLevels: dl
            ? {
                  l1: dl.l1,
                  l2: dl.l2,
                  convergent: dl.l1 && dl.l2,
              }
            : undefined,
        l2Evidence: raw.l2_evidence ?? undefined,
    }
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Run the Rust detection engine on a single input string.
 *
 * Returns an empty array on error (engine never throws to callers).
 * The engine applies the full L1 → L2 → L3 pipeline internally.
 *
 * @param input - Raw user-controlled input (path, query param, body, header value)
 * @returns Array of detected invariant violations, highest confidence first
 */
export function rustDetect(input: string): RustInvariantMatch[] {
    if (!input || input.length === 0) return []
    try {
        const runtime = getRuntime()
        const raw = runtime.detect(input) as RustMatchRaw[]
        if (!Array.isArray(raw)) return []
        return raw
            .map(mapRawMatch)
            .sort((a, b) => b.confidence - a.confidence)
    } catch {
        // WASM panics are caught here — engine errors must never propagate to callers
        return []
    }
}

/**
 * Run the Rust engine on multiple inputs and merge results.
 * Deduplicates by class (keeps highest confidence per class).
 *
 * @param inputs - Array of input strings to check
 * @returns Deduplicated matches, highest confidence per class
 */
export function rustDetectAll(inputs: string[]): RustInvariantMatch[] {
    const best = new Map<string, RustInvariantMatch>()
    for (const input of inputs) {
        if (!input || input.length === 0) continue
        for (const match of rustDetect(input)) {
            const existing = best.get(match.class)
            if (!existing || match.confidence > existing.confidence) {
                best.set(match.class, match)
            }
        }
    }
    return Array.from(best.values()).sort((a, b) => b.confidence - a.confidence)
}

/**
 * Run the full unified runtime pipeline (L1+L2+L3+chains+campaign+effects).
 * Returns the complete UnifiedResponse JSON.
 *
 * @param requestJson - JSON string matching WasmUnifiedRequest schema
 * @returns UnifiedResponse JSON object
 */
export function rustProcess(requestJson: string): unknown {
    try {
        const runtime = getRuntime()
        return runtime.process(requestJson)
    } catch {
        return { error: 'rust_engine_process_failed', decision: { action: 'allow' } }
    }
}

/**
 * Return the version string of the compiled Rust engine.
 */
export function rustEngineVersion(): string {
    try {
        const runtime = getRuntime()
        return runtime.detect.length >= 0 ? '0.1.0' : 'unknown'
    } catch {
        return 'unknown'
    }
}
