/**
 * INVARIANT Engine — Core Detection Engine (v2, Modular)
 *
 * The fundamental concept:
 *   One payload discovered → decompose into invariant property →
 *   generate defense pattern matching ALL expressions of that property →
 *   block payloads that haven't been written yet.
 *
 * A WAF matches signatures: ' OR 1=1--  →  MATCH
 *                           ' OR 2=2--  →  MISS
 *
 * INVARIANT matches the class: ' OR 1=1--  →  MATCH (tautology)
 *                              ' OR 2=2--  →  MATCH (tautology)
 *                              [novel]     →  MATCH (tautology)
 *
 * v2 CHANGES:
 *   - Classes decomposed into individual modules under classes/
 *   - InvariantRegistry provides dynamic registration
 *   - Calibration system for per-environment confidence tuning
 *   - Backward-compatible API: InvariantEngine.detect() unchanged
 *
 * MIGRATION:
 *   The old monolithic type exports (InvariantClass, InvariantDefinition,
 *   InvariantMatch) are re-exported from here for backward compatibility.
 *   New code should import from classes/types.js directly.
 */

import {
    InvariantRegistry,
    ALL_CLASS_MODULES,
    deepDecode,
} from './classes/index.js'

import type {
    InvariantClass,
    InvariantClassModule,
    InvariantMatch,
    Severity,
} from './classes/types.js'

// ── Backward Compatibility ────────────────────────────────────────
// Re-export the old InvariantDefinition type as an alias for InvariantClassModule
export type InvariantDefinition = InvariantClassModule

// Re-export types for backward compatibility
export type { InvariantClass, InvariantMatch }
export { deepDecode }


// ── Engine ────────────────────────────────────────────────────────

/**
 * The INVARIANT Engine.
 *
 * Detects attack payloads by matching invariant CLASSES,
 * not specific signatures. This catches novel variants
 * that have never been seen before.
 *
 * v2: Uses the modular InvariantRegistry instead of a static array.
 */
export class InvariantEngine {
    readonly registry: InvariantRegistry

    constructor() {
        this.registry = new InvariantRegistry()
        this.registry.registerAll(ALL_CLASS_MODULES)
    }

    /**
     * Analyze request input against all invariant classes.
     * Returns every matching class — a single payload may
     * express multiple invariants (e.g., SQL string termination + tautology).
     *
     * @param input The decoded request content to analyze (path + query + relevant headers)
     * @param staticRuleIds IDs of static signature rules that already matched.
     *                      Used to determine if this is a NOVEL variant.
     * @param environment Optional environment hint for calibration (e.g., 'wordpress', 'api_json')
     */
    detect(input: string, staticRuleIds: string[], environment?: string): InvariantMatch[] {
        const matches: InvariantMatch[] = []

        for (const module of this.registry.all()) {
            try {
                if (module.detect(input)) {
                    // Is this a novel variant?
                    // Novel = invariant engine catches it, but NO static signature did
                    const isNovel = staticRuleIds.length === 0

                    // Compute calibrated confidence
                    const confidence = this.registry.computeConfidence(
                        module.id,
                        input,
                        environment,
                        !isNovel,
                    )

                    matches.push({
                        class: module.id,
                        confidence,
                        category: module.category,
                        severity: module.severity,
                        isNovelVariant: isNovel,
                        description: module.description,
                    })
                }
            } catch {
                // Never let a detection failure break the engine
            }
        }

        return matches
    }

    /**
     * Check headers specifically for auth bypass invariants
     * that can't be detected from path/query alone.
     */
    detectHeaderInvariants(headers: Headers): InvariantMatch[] {
        const matches: InvariantMatch[] = []

        // Auth header spoof: multiple forwarding headers = spoofing attempt
        const forwardHeaders = [
            'x-forwarded-for', 'x-real-ip', 'x-originating-ip',
            'x-remote-ip', 'x-client-ip', 'x-custom-ip-authorization',
        ]
        const forwardCount = forwardHeaders.filter(h => headers.has(h)).length
        if (forwardCount >= 3) {
            const authSpoof = this.registry.get('auth_header_spoof')
            matches.push({
                class: 'auth_header_spoof',
                confidence: 0.8,
                category: 'auth',
                severity: 'medium',
                isNovelVariant: false,
                description: authSpoof?.description ?? 'Spoof proxy/forwarding headers to bypass IP-based access controls',
            })
        }

        // URL rewrite bypass headers
        if (headers.has('x-original-url') || headers.has('x-rewrite-url')) {
            matches.push({
                class: 'auth_header_spoof',
                confidence: 0.85,
                category: 'auth',
                severity: 'high',
                isNovelVariant: false,
                description: 'URL rewrite header used to bypass path-based access controls',
            })
        }

        // JWT alg:none in Authorization header
        const auth = headers.get('authorization') ?? ''
        if (auth.startsWith('Bearer ')) {
            const jwtModule = this.registry.get('auth_none_algorithm')
            if (jwtModule?.detect(auth.slice(7))) {
                matches.push({
                    class: 'auth_none_algorithm',
                    confidence: 0.95,
                    category: 'auth',
                    severity: 'critical',
                    isNovelVariant: false,
                    description: jwtModule.description,
                })
            }
        }

        return matches
    }

    /**
     * Should this request be blocked? Returns true if any invariant
     * match has sufficient confidence.
     */
    shouldBlock(matches: InvariantMatch[]): boolean {
        return matches.some(m => m.confidence >= 0.7)
    }

    /**
     * Get the highest severity from a set of matches.
     */
    highestSeverity(matches: InvariantMatch[]): 'critical' | 'high' | 'medium' | 'low' | 'info' {
        const order = ['info', 'low', 'medium', 'high', 'critical'] as const
        let max = 0
        for (const m of matches) {
            const idx = order.indexOf(m.severity)
            if (idx > max) max = idx
        }
        return order[max] ?? 'info'
    }

    /**
     * Generate variant payloads for a given invariant class.
     * Used for self-testing and internal probing.
     */
    generateVariants(cls: InvariantClass, count: number): string[] {
        const module = this.registry.get(cls)
        if (!module) return []
        return module.generateVariants(count)
    }

    /** Number of registered invariant classes */
    get classCount(): number {
        return this.registry.size
    }

    /** All registered class identifiers */
    get classes(): InvariantClass[] {
        return this.registry.classIds()
    }
}
