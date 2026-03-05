/**
 * Prototype Pollution Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for prototype pollution is:
 *   ∃ key_path ∈ parse(input) :
 *     key_path TRAVERSES {__proto__, constructor.prototype, prototype}
 *     ∧ key_path ASSIGNS value
 *     → attacker modifies Object.prototype affecting all instances
 *
 * Unlike regex matching __proto__, this evaluator:
 *   1. Parses JSON to extract actual key paths
 *   2. Detects nested prototype traversal chains
 *   3. Identifies URL parameter bracket notation
 *   4. Catches constructor.prototype chains
 *   5. Analyzes the pollution target (what property is set)
 *
 * Covers:
 *   - proto_pollution: prototype chain modification via any vector
 */


// ── Result Type ──────────────────────────────────────────────────

export interface ProtoPollutionDetection {
    type: 'proto_direct' | 'constructor_chain' | 'bracket_notation' | 'json_merge'
    detail: string
    path: string
    pollutedProperty: string
    confidence: number
}


// ── Dangerous Proto Paths ────────────────────────────────────────

const PROTO_KEYS = new Set(['__proto__', 'prototype'])
const CONSTRUCTOR_KEY = 'constructor'


// ── JSON Deep Key Analyzer ───────────────────────────────────────
//
// Walk JSON objects recursively, tracking the key path.
// If any path segment is __proto__ or constructor.prototype,
// it's a pollution attempt.

function analyzeJsonKeys(obj: unknown, path: string[] = []): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []

    if (typeof obj !== 'object' || obj === null) return detections

    if (Array.isArray(obj)) {
        for (let i = 0; i < obj.length; i++) {
            detections.push(...analyzeJsonKeys(obj[i], [...path, `[${i}]`]))
        }
    } else {
        for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
            const currentPath = [...path, key]

            if (PROTO_KEYS.has(key)) {
                // Direct __proto__ or prototype key
                if (typeof val === 'object' && val !== null) {
                    for (const [prop, propVal] of Object.entries(val as Record<string, unknown>)) {
                        detections.push({
                            type: 'proto_direct',
                            detail: `Prototype pollution: ${currentPath.join('.')}.${prop} = ${JSON.stringify(propVal)}`,
                            path: currentPath.join('.'),
                            pollutedProperty: prop,
                            confidence: 0.94,
                        })
                    }
                } else {
                    detections.push({
                        type: 'proto_direct',
                        detail: `Prototype key "${key}" in JSON payload`,
                        path: currentPath.join('.'),
                        pollutedProperty: key,
                        confidence: 0.88,
                    })
                }
            } else if (key === CONSTRUCTOR_KEY) {
                // constructor.prototype chain
                if (typeof val === 'object' && val !== null && 'prototype' in (val as Record<string, unknown>)) {
                    const prototype = (val as Record<string, unknown>).prototype
                    if (typeof prototype === 'object' && prototype !== null) {
                        for (const [prop, propVal] of Object.entries(prototype as Record<string, unknown>)) {
                            detections.push({
                                type: 'constructor_chain',
                                detail: `Constructor chain pollution: constructor.prototype.${prop} = ${JSON.stringify(propVal)}`,
                                path: `${currentPath.join('.')}.prototype`,
                                pollutedProperty: prop,
                                confidence: 0.96,
                            })
                        }
                    }
                }
            }

            // Recurse
            detections.push(...analyzeJsonKeys(val, currentPath))
        }
    }

    return detections
}


// ── URL Parameter Bracket Notation ───────────────────────────────
//
// __proto__[isAdmin]=true
// constructor[prototype][isAdmin]=true
// a[__proto__][b]=c

function detectBracketNotation(input: string): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []

    // __proto__[prop]=value
    const protoPattern = /__proto__\[([^\]]+)\]=([^&]*)/g
    let match: RegExpExecArray | null
    while ((match = protoPattern.exec(input)) !== null) {
        detections.push({
            type: 'bracket_notation',
            detail: `URL parameter pollution: __proto__[${match[1]}]=${match[2]}`,
            path: `__proto__[${match[1]}]`,
            pollutedProperty: match[1],
            confidence: 0.94,
        })
    }

    // constructor[prototype][prop]=value
    const ctorPattern = /constructor\[prototype\]\[([^\]]+)\]=([^&]*)/g
    while ((match = ctorPattern.exec(input)) !== null) {
        detections.push({
            type: 'bracket_notation',
            detail: `URL parameter constructor chain: constructor[prototype][${match[1]}]=${match[2]}`,
            path: `constructor[prototype][${match[1]}]`,
            pollutedProperty: match[1],
            confidence: 0.96,
        })
    }

    // field[__proto__][prop]=value (nested bracket)
    const nestedPattern = /(\w+)\[__proto__\]\[([^\]]+)\]=([^&]*)/g
    while ((match = nestedPattern.exec(input)) !== null) {
        detections.push({
            type: 'bracket_notation',
            detail: `Nested bracket pollution: ${match[1]}[__proto__][${match[2]}]=${match[3]}`,
            path: `${match[1]}.__proto__[${match[2]}]`,
            pollutedProperty: match[2],
            confidence: 0.92,
        })
    }

    return detections
}


// ── Dot Notation Detection ───────────────────────────────────────

function detectDotNotation(input: string): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []

    // __proto__.prop=value or constructor.prototype.prop=value
    const dotPattern = /(?:__proto__|constructor\.prototype)\.(\w+)\s*=\s*(\S+)/g
    let match: RegExpExecArray | null
    while ((match = dotPattern.exec(input)) !== null) {
        detections.push({
            type: 'proto_direct',
            detail: `Dot notation pollution: ${match[0]}`,
            path: match[0].split('=')[0].trim(),
            pollutedProperty: match[1],
            confidence: 0.92,
        })
    }

    return detections
}


// ── Public API ───────────────────────────────────────────────────

export function detectPrototypePollution(input: string): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []

    // Quick bail
    if (input.length < 8) return detections
    const lower = input.toLowerCase()
    if (!lower.includes('proto') && !lower.includes('constructor') && !lower.includes('prototype')) {
        return detections
    }

    // Multi-layer decode
    let decoded = input
    try {
        let prev = ''
        for (let i = 0; i < 3 && decoded !== prev; i++) {
            prev = decoded
            try { decoded = decodeURIComponent(decoded) } catch { break }
        }
    } catch { /* use original */ }

    // Strategy 1: Parse as JSON
    try {
        const obj = JSON.parse(decoded)
        detections.push(...analyzeJsonKeys(obj))
    } catch {
        // Not JSON — try extracting JSON fragments
        const braceStart = decoded.indexOf('{')
        if (braceStart >= 0) {
            let depth = 0
            let end = -1
            for (let i = braceStart; i < decoded.length; i++) {
                if (decoded[i] === '{') depth++
                if (decoded[i] === '}') { depth--; if (depth === 0) { end = i; break } }
            }
            if (end > braceStart) {
                try {
                    const obj = JSON.parse(decoded.substring(braceStart, end + 1))
                    detections.push(...analyzeJsonKeys(obj))
                } catch { /* not parseable */ }
            }
        }
    }

    // Strategy 2: Bracket notation (URL params)
    try { detections.push(...detectBracketNotation(decoded)) } catch { /* safe */ }

    // Strategy 3: Dot notation
    try { detections.push(...detectDotNotation(decoded)) } catch { /* safe */ }

    return detections
}
