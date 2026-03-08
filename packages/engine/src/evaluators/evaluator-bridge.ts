/**
 * Evaluator Bridge — Connects Level 2 Evaluators to the InvariantEngine
 *
 * This module bridges the InvariantEngine (regex-based Level 1) with
 * expression/context evaluators (Level 2) for ALL invariant classes.
 *
 * Architecture (v2 — registry-driven):
 *   The bridge iterates the L2 Evaluator Registry instead of hardcoding
 *   per-evaluator detection blocks. Adding a new evaluator requires only
 *   adding a descriptor to l2-evaluator-registry.ts — zero changes here.
 *
 * The bridge provides:
 *   - Unified detection interface (L1 + L2 combined)
 *   - Drop-in replacement for current detect() calls
 *   - Performance tracking (L1 vs L2 detection rates)
 *   - Novel variant identification (L2 catches that L1 missed)
 */

import type { InvariantMatch, InvariantClass } from '../classes/types.js'
import {
    L2_EVALUATOR_DESCRIPTORS,
    lookupCategory,
    lookupSeverity,
} from './l2-evaluator-registry.js'


// ── Level 2 Evaluation Stats ─────────────────────────────────────

export interface L2Stats {
    totalEvaluations: number
    l2OnlyDetections: number       // Caught by L2 but NOT L1
    convergentDetections: number   // Caught by BOTH L1 and L2
    l2MissButL1Caught: number      // Caught by L1 but not L2 (coverage gap)
    falseRejectionsAvoided: number // Would have been missed without L2
}


// ── Bridge Interface ─────────────────────────────────────────────

export interface L2DetectionResult {
    /** Class of invariant detected */
    class: InvariantClass
    /** Confidence from L2 evaluator */
    confidence: number
    /** Whether this detection is novel (L1 missed it) */
    novelByL2: boolean
    /** Human-readable explanation */
    detail: string
}


/**
 * Run Level 2 evaluators on input.
 * Returns additional detections beyond what Level 1 (regex) catches.
 *
 * This is called AFTER the main InvariantEngine.detect() to augment
 * its results with deeper analysis. It runs in ctx.waitUntil() to
 * avoid adding latency to the critical path.
 *
 * Iterates the L2 Evaluator Registry — no per-evaluator hardcoding.
 *
 * @param input The decoded request content
 * @param l1Matches Classes already matched by Level 1
 * @returns Additional/upgraded matches from Level 2
 */
export function runL2Evaluators(
    input: string,
    l1Matches: Set<InvariantClass>,
): L2DetectionResult[] {
    const results: L2DetectionResult[] = []

    for (const descriptor of L2_EVALUATOR_DESCRIPTORS) {
        try {
            const detections = descriptor.detect(input)
            for (const detection of detections) {
                const cls = descriptor.typeToClass[detection.type]
                if (cls) {
                    const alreadyCaught = l1Matches.has(cls)
                    results.push({
                        class: cls,
                        confidence: detection.confidence,
                        novelByL2: !alreadyCaught,
                        detail: `${descriptor.prefix}: ${detection.detail}`,
                    })
                }
            }
        } catch { /* Never let L2 failure affect main pipeline */ }
    }

    return results
}


/**
 * Merge L2 results into the L1 InvariantMatch array.
 * Deduplicates by class and upgrades confidence when convergent.
 */
export function mergeL2Results(
    l1Matches: InvariantMatch[],
    l2Results: L2DetectionResult[],
): InvariantMatch[] {
    const merged = [...l1Matches]
    const existingClasses = new Set(l1Matches.map(m => m.class))

    for (const l2 of l2Results) {
        if (existingClasses.has(l2.class)) {
            // Convergent detection — upgrade confidence
            const existing = merged.find(m => m.class === l2.class)
            if (existing && l2.confidence > existing.confidence) {
                existing.confidence = Math.min(0.99, l2.confidence + 0.05)
                existing.description = `${existing.description} [confirmed by L2: ${l2.detail}]`
            }
        } else {
            // Novel L2 detection — add to results
            merged.push({
                class: l2.class,
                confidence: l2.confidence,
                category: lookupCategory(l2.class),
                severity: lookupSeverity(l2.class),
                isNovelVariant: true,
                description: l2.detail,
            })
            existingClasses.add(l2.class)
        }
    }

    return merged
}
