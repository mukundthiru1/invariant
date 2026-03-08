/**
 * API Abuse Evaluator — Level 2 Invariant Detection
 *
 * Structural analysis of API logic attacks:
 *   - bola_idor:      Parse API paths, extract object IDs, detect authorization context mismatch
 *   - api_mass_enum:  Detect sequential ID patterns, range query operators, bulk access patterns
 *
 * Goes beyond regex by:
 *   - Parsing URL structure to identify resource IDs and authorization context
 *   - Analyzing sequences of API calls for sequential patterns (sliding window)
 *   - Computing numeric ranges from query operator expressions
 */


// ── Result Type ──────────────────────────────────────────────────

export interface APIAbuseDetection {
    type: 'bola_idor' | 'api_mass_enum'
    detail: string
    confidence: number
}


// ── BOLA/IDOR Analysis ──────────────────────────────────────────

function analyzeBOLA(input: string): APIAbuseDetection | null {
    // Must contain an API path with a resource identifier
    if (!/\/api\//i.test(input)) return null

    const signals: string[] = []

    // Extract all numeric IDs from API paths
    const apiPaths = [...input.matchAll(/\/api\/[a-z_]+\/(\d+)/gi)]
    const hasNumericId = apiPaths.length > 0

    if (hasNumericId) {
        // Check for authorization context mismatch
        const authMismatch = /(?:token[_\s]*for[_\s]*user|bearer\s+<|as\s+user\s+\d|impersonat|other[_\s]*user)/i.test(input)
        if (authMismatch) signals.push('authorization context mismatch')

        // Check for enumeration/scanning context
        const scanContext = /(?:sequential|probe|enumerate|brute|scan|fuzz)/i.test(input)
        if (scanContext) signals.push('enumeration context')

        // Multiple different numeric IDs in same request (fishing for accessible ones)
        const uniqueIds = new Set(apiPaths.map(m => m[1]))
        if (uniqueIds.size >= 3) {
            signals.push(`${uniqueIds.size} different resource IDs`)
        }
    }

    // Path traversal in API path targeting admin/sensitive resources
    if (/\/api\/.*\.\.\//.test(input)) {
        const targetsSensitive = /(?:admin|config|internal|private|secret|\.env|settings)/i.test(input)
        if (targetsSensitive) signals.push('path traversal to sensitive resource')
    }

    // Numeric ID combined with path traversal
    if (/\/\d+\/\.\./.test(input)) {
        signals.push('ID-based path escape')
    }

    if (signals.length === 0) return null

    return {
        type: 'bola_idor',
        detail: `IDOR indicators: ${signals.join(', ')}`,
        confidence: signals.length >= 2 ? 0.92 : 0.82,
    }
}


// ── Mass Enumeration Analysis ───────────────────────────────────

function analyzeMassEnum(input: string): APIAbuseDetection | null {
    const signals: string[] = []

    // Pattern 1: Multiple sequential API calls with incrementing IDs
    const apiCalls = [...input.matchAll(/\/api\/\w+\/(\d+)/gi)]
    if (apiCalls.length >= 4) {
        const ids = apiCalls.map(c => parseInt(c[1], 10)).filter(n => !isNaN(n))
        if (ids.length >= 4) {
            let sequential = 0
            for (let i = 1; i < ids.length; i++) {
                if (ids[i] === ids[i - 1] + 1) sequential++
            }
            if (sequential >= 3) {
                signals.push(`${sequential + 1} sequential IDs (${ids.slice(0, 5).join(',')})`)
            }
        }
    }

    // Pattern 2: Range query operators with wide range
    const gteMatch = input.match(/(?:id|_id)\s*\[?\s*(?:gte|gt)\s*\]?\s*[=:]\s*(\d+)/i)
    const lteMatch = input.match(/(?:id|_id)\s*\[?\s*(?:lte|lt)\s*\]?\s*[=:]\s*(\d+)/i)
    if (gteMatch && lteMatch) {
        const start = parseInt(gteMatch[1], 10)
        const end = parseInt(lteMatch[1], 10)
        if (!isNaN(start) && !isNaN(end) && end - start > 100) {
            signals.push(`range query: ${start}..${end} (${end - start} IDs)`)
        }
    }

    // Pattern 3: Absurdly large limit
    const limitMatch = input.match(/\blimit\s*[=:]\s*(\d+)/i)
    if (limitMatch) {
        const limit = parseInt(limitMatch[1], 10)
        if (!isNaN(limit) && limit > 50000) {
            signals.push(`excessive limit: ${limit}`)
        }
    }

    // Pattern 4: filter=id>0 (get everything)
    if (/\bfilter\s*=\s*(?:id|_id)\s*[>]=?\s*0\b/i.test(input)) {
        signals.push('unbound filter (id>=0)')
    }

    // Pattern 5: offset-based walking with large jumps
    const offsets = [...input.matchAll(/\boffset\s*[=:]\s*(\d+)/gi)]
    if (offsets.length >= 3) {
        const vals = offsets.map(m => parseInt(m[1], 10)).filter(n => !isNaN(n))
        // Check for arithmetic progression (walking through pages)
        if (vals.length >= 3) {
            const diffs = vals.slice(1).map((v, i) => v - vals[i])
            const consistent = diffs.every(d => d === diffs[0] && d > 0)
            if (consistent) signals.push(`page walking: offset increments of ${diffs[0]}`)
        }
    }

    if (signals.length === 0) return null

    return {
        type: 'api_mass_enum',
        detail: `Mass enumeration: ${signals.join(', ')}`,
        confidence: signals.length >= 2 ? 0.90 : 0.80,
    }
}


// ── Public API ───────────────────────────────────────────────────

export function detectAPIAbuse(input: string): APIAbuseDetection[] {
    const detections: APIAbuseDetection[] = []

    if (input.length < 10) return detections

    try {
        const bola = analyzeBOLA(input)
        if (bola) detections.push(bola)
    } catch { /* safe */ }

    try {
        const massEnum = analyzeMassEnum(input)
        if (massEnum) detections.push(massEnum)
    } catch { /* safe */ }

    return detections
}
