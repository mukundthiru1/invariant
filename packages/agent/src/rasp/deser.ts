/**
 * @santh/agent — Deserialization RASP Wrapper
 *
 * Wraps JSON.parse and other deserialization functions to detect
 * dangerous deserialization patterns.
 *
 * The math:
 *   Given serialized input S:
 *   If S contains Java serialization magic bytes, PHP object notation,
 *   Python pickle opcodes, or prototype pollution keys,
 *   the input is a deserialization attack.
 *
 * This doesn't replace type-safe parsing. It detects when
 * untrusted data reaches a deserialization boundary.
 */

import type { InvariantDB, DefenseAction, Severity } from '../db.js'

export interface DeserRaspConfig {
    mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    db: InvariantDB
    onViolation?: (violation: DeserViolation) => void
}

export interface DeserViolation {
    input: string
    invariantClass: string
    action: DefenseAction
    timestamp: string
}

const DESER_INVARIANTS = [
    {
        id: 'deser_java_gadget',
        test: (input: string) => /aced0005|rO0ABX/i.test(input),
        severity: 'critical' as Severity,
    },
    {
        id: 'deser_php_object',
        test: (input: string) => /O:\d+:"[^"]+":\d+:\{/.test(input),
        severity: 'high' as Severity,
    },
    {
        id: 'deser_python_pickle',
        test: (input: string) => /\x80\x04\x95|cos\nsystem|cbuiltins\n|c__builtin__\n/i.test(input),
        severity: 'critical' as Severity,
    },
    {
        id: 'deser_prototype_pollution',
        test: (input: string) => {
            // Check for __proto__ or constructor.prototype in JSON keys
            if (/__proto__|constructor\s*\[?\s*['"]?prototype/i.test(input)) return true
            // Check parsed JSON for __proto__ keys
            try {
                const parsed = JSON.parse(input)
                return hasProtoKey(parsed)
            } catch {
                return false
            }
        },
        severity: 'high' as Severity,
    },
    {
        id: 'deser_yaml_code_exec',
        // YAML deserialization attacks: !!python/object, !!js/function
        test: (input: string) => /!!(?:python\/object|js\/function|ruby\/object|php\/object|java\/object|binary)/i.test(input),
        severity: 'critical' as Severity,
    },
]

function hasProtoKey(obj: unknown, depth = 0): boolean {
    if (depth > 5 || !obj || typeof obj !== 'object') return false
    for (const key of Object.keys(obj as Record<string, unknown>)) {
        if (key === '__proto__' || key === 'constructor') return true
        if (hasProtoKey((obj as Record<string, unknown>)[key], depth + 1)) return true
    }
    return false
}

/**
 * Wrap JSON.parse to detect deserialization attacks.
 *
 * Usage:
 *   const agent = new InvariantAgent()
 *   const safeJsonParse = wrapJsonParse(JSON.parse, agent.getDeserRaspConfig())
 *   const data = safeJsonParse(userInput)
 */
export function wrapJsonParse(
    originalParse: typeof JSON.parse,
    config: DeserRaspConfig,
): typeof JSON.parse {
    return function safeParse(text: string, reviver?: (key: string, value: unknown) => unknown): unknown {
        if (typeof text !== 'string') return originalParse(text, reviver)

        const violations: Array<{ id: string; severity: Severity }> = []
        for (const inv of DESER_INVARIANTS) {
            try {
                if (inv.test(text)) {
                    violations.push({ id: inv.id, severity: inv.severity })
                }
            } catch { /* never break */ }
        }

        if (violations.length === 0) return originalParse(text, reviver)

        const hasCriticalOrHigh = violations.some(v => v.severity === 'critical' || v.severity === 'high')
        const action: DefenseAction =
            config.mode === 'observe' ? 'monitored' :
                config.mode === 'lockdown' ? 'blocked' :
                    config.mode === 'defend' ? (hasCriticalOrHigh ? 'blocked' : 'monitored') :
                        'monitored'

        const now = new Date().toISOString()

        try {
            config.db.insertSignal({
                type: 'deser_invariant_violation',
                subtype: violations[0].id,
                severity: violations[0].severity,
                action,
                path: 'JSON.parse()',
                method: 'DESER',
                source_hash: null,
                invariant_classes: JSON.stringify(violations.map(v => v.id)),
                is_novel: false,
                timestamp: now,
            })
            config.db.insertFinding({
                type: 'runtime_invariant_violation',
                category: 'deserialization',
                severity: violations[0].severity,
                status: 'open',
                title: `Deserialization attack: ${violations[0].id}`,
                description: `Detected ${violations[0].id} in JSON.parse(). Input (truncated): ${text.slice(0, 200)}`,
                location: 'JSON.parse()',
                evidence: JSON.stringify({ input: text.slice(0, 200), violations: violations.map(v => v.id) }),
                remediation: 'Validate and sanitize all deserialized input. Use schema validation (e.g., Zod, Joi) before processing. Never deserialize untrusted data without type-safe parsing.',
                cve_id: null, confidence: 0.9, first_seen: now, last_seen: now,
                rasp_active: action === 'blocked',
            })
        } catch { /* Never break */ }

        if (config.onViolation) {
            try {
                config.onViolation({
                    input: text.slice(0, 200),
                    invariantClass: violations[0].id,
                    action,
                    timestamp: now,
                })
            } catch { /* Never break */ }
        }

        if (action === 'blocked') {
            throw new Error(`[INVARIANT] Deserialization blocked — ${violations.map(v => v.id).join(', ')} detected.`)
        }

        // Sanitize mode: strip __proto__ keys from parsed result
        if (config.mode === 'sanitize') {
            const parsed = originalParse(text, reviver)
            return stripProtoKeys(parsed)
        }

        return originalParse(text, reviver)
    }
}

function stripProtoKeys(obj: unknown, depth = 0): unknown {
    if (depth > 10 || !obj || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(item => stripProtoKeys(item, depth + 1))
    const clean: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
        if (key === '__proto__' || key === 'constructor') continue
        clean[key] = stripProtoKeys(value, depth + 1)
    }
    return clean
}

/**
 * Check a raw string for deserialization attack patterns.
 * Useful for middleware that examines request bodies.
 */
export function checkDeserInvariants(input: string): Array<{ id: string; severity: Severity }> {
    const violations: Array<{ id: string; severity: Severity }> = []
    for (const inv of DESER_INVARIANTS) {
        try {
            if (inv.test(input)) violations.push({ id: inv.id, severity: inv.severity })
        } catch { /* never break */ }
    }
    return violations
}
