/**
 * INVARIANT — Rule Sync Engine
 *
 * Bridges the intel pipeline → sensor gap.
 * Fetches detection rules from intel.santh.io and caches
 * them in KV for the sensor to apply on every request.
 *
 * Runs on the 5-minute cron cycle:
 *   1. Check version hash (lightweight GET)
 *   2. If version changed → fetch full rule set
 *   3. Store in KV via SensorStateManager
 *   4. Rules applied on next request
 *
 * Also handles the dynamic rule matching engine that
 * runs these fetched rules against incoming requests.
 */

import { SensorStateManager, type DynamicRule, type DynamicRulePattern } from './sensor-state'


// ── Rule Sync ────────────────────────────────────────────────────

export interface RuleSyncResult {
    synced: boolean
    rulesLoaded: number
    version: string | null
    error: string | null
    skippedReason: string | null
}

/**
 * Sync detection rules from intel pipeline.
 *
 * Strategy:
 *   1. GET /v1/rules/version → lightweight version check
 *   2. Compare against cached version in state manager
 *   3. If same → skip (nothing to do)
 *   4. If different → GET /v1/rules/sensor → full rule set
 *   5. Store in state manager → persisted to KV
 */
export async function syncRulesFromIntel(
    state: SensorStateManager,
): Promise<RuleSyncResult> {
    const rulesFetchUrl = state.config.rulesFetchUrl
    if (!rulesFetchUrl) {
        return {
            synced: false,
            rulesLoaded: 0,
            version: null,
            error: null,
            skippedReason: 'no_rules_url_configured',
        }
    }

    try {
        // Step 1: Check version
        const versionUrl = rulesFetchUrl.replace('/sensor', '/version')
        const versionRes = await fetch(versionUrl, {
            headers: { 'User-Agent': 'INVARIANT-Sensor/5.0' },
            signal: AbortSignal.timeout(5000),
        })

        if (!versionRes.ok) {
            return {
                synced: false,
                rulesLoaded: state.rules?.rules.length ?? 0,
                version: state.rules?.version ?? null,
                error: `version check failed: ${versionRes.status}`,
                skippedReason: null,
            }
        }

        const versionData = await versionRes.json() as {
            version: string
            ruleCount: number
        }

        // Step 2: Compare versions
        if (state.rules?.version === versionData.version) {
            return {
                synced: false,
                rulesLoaded: state.rules.rules.length,
                version: versionData.version,
                error: null,
                skippedReason: 'version_unchanged',
            }
        }

        // Step 3: Fetch full rule set
        const rulesRes = await fetch(rulesFetchUrl, {
            headers: { 'User-Agent': 'INVARIANT-Sensor/5.0' },
            signal: AbortSignal.timeout(15000),
        })

        if (!rulesRes.ok) {
            return {
                synced: false,
                rulesLoaded: state.rules?.rules.length ?? 0,
                version: state.rules?.version ?? null,
                error: `rules fetch failed: ${rulesRes.status}`,
                skippedReason: null,
            }
        }

        const rulesData = await rulesRes.json() as {
            version: string
            rules: DynamicRule[]
            ruleCount: number
        }

        // Step 4: Validate response
        if (!Array.isArray(rulesData.rules)) {
            return {
                synced: false,
                rulesLoaded: 0,
                version: null,
                error: 'invalid rules response: not an array',
                skippedReason: null,
            }
        }

        // Step 5: Store
        state.updateRules(rulesData.rules, rulesData.version, rulesFetchUrl)

        return {
            synced: true,
            rulesLoaded: rulesData.rules.length,
            version: rulesData.version,
            error: null,
            skippedReason: null,
        }
    } catch (err) {
        return {
            synced: false,
            rulesLoaded: state.rules?.rules.length ?? 0,
            version: state.rules?.version ?? null,
            error: err instanceof Error ? err.message : String(err),
            skippedReason: null,
        }
    }
}


// ═══════════════════════════════════════════════════════════════════
// DYNAMIC RULE MATCHER
//
// Runs the fetched rules against incoming requests.
// Designed for the hot path — no allocations, early exits.
// ═══════════════════════════════════════════════════════════════════

export interface DynamicRuleMatch {
    ruleId: string
    name: string
    signalType: string
    signalSubtype: string | null
    confidence: number
    linkedCves: string[]
    linkedTechniques: string[]
    matchedPatterns: string[]
}

/**
 * Match a request against all dynamic rules.
 *
 * @param rules - The dynamic rules to evaluate
 * @param request - Request context
 * @returns Array of matches (may be empty)
 */
export function matchDynamicRules(
    rules: DynamicRule[],
    request: {
        path: string
        query: string
        method: string
        headers: Record<string, string>
        userAgent: string
    },
): DynamicRuleMatch[] {
    const matches: DynamicRuleMatch[] = []

    for (const rule of rules) {
        if (!rule.enabled) continue

        const matchedPatterns: string[] = []
        let allPatternsMatch = true

        for (const pattern of rule.patterns) {
            const matched = evaluatePattern(pattern, request)
            if (matched) {
                matchedPatterns.push(`${pattern.field}:${pattern.value}`)
            } else if (rule.matchType === 'combo') {
                // Combo rules require ALL patterns to match
                allPatternsMatch = false
                break
            }
        }

        // For non-combo rules, at least one pattern must match
        if (rule.matchType === 'combo') {
            if (allPatternsMatch && matchedPatterns.length > 0) {
                matches.push({
                    ruleId: rule.ruleId,
                    name: rule.name,
                    signalType: rule.signalType,
                    signalSubtype: rule.signalSubtype,
                    confidence: rule.baseConfidence,
                    linkedCves: rule.linkedCves,
                    linkedTechniques: rule.linkedTechniques,
                    matchedPatterns,
                })
            }
        } else if (matchedPatterns.length > 0) {
            matches.push({
                ruleId: rule.ruleId,
                name: rule.name,
                signalType: rule.signalType,
                signalSubtype: rule.signalSubtype,
                confidence: rule.baseConfidence,
                linkedCves: rule.linkedCves,
                linkedTechniques: rule.linkedTechniques,
                matchedPatterns,
            })
        }
    }

    return matches
}


// ── Pattern Evaluator ────────────────────────────────────────────

function evaluatePattern(
    pattern: DynamicRulePattern,
    request: {
        path: string
        query: string
        method: string
        headers: Record<string, string>
        userAgent: string
    },
): boolean {
    // Resolve the field value
    let fieldValue: string
    switch (pattern.field) {
        case 'path':
            fieldValue = request.path
            break
        case 'query':
            fieldValue = request.query
            break
        case 'method':
            fieldValue = request.method
            break
        case 'user_agent':
            fieldValue = request.userAgent
            break
        case 'header':
            fieldValue = pattern.headerName
                ? (request.headers[pattern.headerName.toLowerCase()] ?? '')
                : ''
            break
        default:
            return false
    }

    if (!fieldValue) return false

    // Evaluate the operator
    const value = pattern.value
    switch (pattern.operator) {
        case 'contains':
            return fieldValue.toLowerCase().includes(value.toLowerCase())
        case 'exact':
            return fieldValue.toLowerCase() === value.toLowerCase()
        case 'starts_with':
            return fieldValue.toLowerCase().startsWith(value.toLowerCase())
        case 'not_contains':
            return !fieldValue.toLowerCase().includes(value.toLowerCase())
        case 'regex':
            try {
                return new RegExp(value, 'i').test(fieldValue)
            } catch {
                return false
            }
        default:
            return false
    }
}
