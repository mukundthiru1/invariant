/**
 * NoSQL Injection Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for NoSQL injection is:
 *   ∃ operator ∈ parse(input, JSON_GRAMMAR) :
 *     operator.key STARTS_WITH '$'
 *     ∧ operator.key ∈ MONGODB_OPERATORS
 *     → attacker injects query operators into NoSQL query
 *
 *   ∨ ∃ expression ∈ input :
 *     expression CONTAINS function() { ... }
 *     ∧ context = MONGODB_WHERE
 *     → attacker injects JavaScript into $where clause
 *
 * This evaluator parses JSON structure to find MongoDB operator
 * injection (not just "$" followed by letters via regex) and
 * analyzes JavaScript expressions in $where contexts.
 *
 * Covers:
 *   - nosql_operator_injection:  $-prefixed operator keys in JSON
 *   - nosql_js_injection:        JavaScript in $where / mapReduce
 */


// ── Result Type ──────────────────────────────────────────────────

export interface NoSQLDetection {
    type: 'operator_injection' | 'js_injection'
    detail: string
    operator: string
    confidence: number
}


// ── MongoDB Operator Taxonomy ────────────────────────────────────
//
// These are the MongoDB query and update operators. When they
// appear as JSON keys in user input, it indicates operator injection.

const MONGO_QUERY_OPERATORS = new Set([
    // Comparison
    '$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
    // Logical
    '$and', '$or', '$not', '$nor',
    // Element
    '$exists', '$type',
    // Evaluation
    '$regex', '$where', '$expr', '$jsonSchema', '$mod', '$text',
    // Array
    '$all', '$elemMatch', '$size',
    // Geospatial
    '$geoWithin', '$geoIntersects', '$near', '$nearSphere',
])

const MONGO_UPDATE_OPERATORS = new Set([
    '$set', '$unset', '$inc', '$push', '$pull', '$addToSet',
    '$pop', '$rename', '$mul', '$min', '$max', '$currentDate',
])

const MONGO_DANGEROUS_OPERATORS = new Set([
    '$where',       // JavaScript execution
    '$regex',       // ReDoS potential
    '$expr',        // Aggregation expression evaluation
    '$function',    // Arbitrary JavaScript (4.4+)
    '$accumulator', // Custom JS in aggregation
])

const BSON_EXTENDED_OPERATORS = new Set([
    '$oid', '$date', '$binary', '$ref', '$timestamp', '$undefined', 
    '$minKey', '$maxKey', '$numberLong', '$numberDecimal', '$numberInt', 
    '$numberDouble', '$symbol', '$dbPointer', '$code', '$scope'
])

const ALL_MONGO_OPERATORS = new Set([
    ...MONGO_QUERY_OPERATORS,
    ...MONGO_UPDATE_OPERATORS,
    ...MONGO_DANGEROUS_OPERATORS,
    ...BSON_EXTENDED_OPERATORS,
])


// ── JSON Key Extractor ───────────────────────────────────────────
//
// Extract keys from JSON-like structures in the input.
// This is NOT a full JSON parser — it handles malformed/partial
// JSON that attackers inject.


// Walk a parsed JSON object recursively to find ALL keys at any depth.
// This handles nested operator injection like:
//   {"$or": [{"password": {"$ne": ""}}]}
function extractKeysRecursive(
    obj: unknown,
    position: number,
    keys: Array<{ key: string; value: string; position: number }>,
): void {
    if (typeof obj !== 'object' || obj === null) return

    if (Array.isArray(obj)) {
        for (const item of obj) {
            extractKeysRecursive(item, position, keys)
        }
    } else {
        for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
            keys.push({
                key,
                value: typeof val === 'string' ? val : JSON.stringify(val),
                position,
            })
            extractKeysRecursive(val, position, keys)
        }
    }
}


// Extract JSON substrings from input using brace-depth counting.
// Unlike /\{[^{}]*\}/ this handles nested objects.
function extractJsonFragments(input: string): Array<{ text: string; position: number }> {
    const fragments: Array<{ text: string; position: number }> = []
    let depth = 0
    let start = -1

    for (let i = 0; i < input.length; i++) {
        if (input[i] === '{') {
            if (depth === 0) start = i
            depth++
        } else if (input[i] === '}') {
            depth--
            if (depth === 0 && start >= 0) {
                fragments.push({
                    text: input.substring(start, i + 1),
                    position: start,
                })
                start = -1
            }
        }
    }

    return fragments
}


function extractJsonKeys(input: string): Array<{ key: string; value: string; position: number }> {
    const keys: Array<{ key: string; value: string; position: number }> = []

    // Strategy 1: Parse actual JSON (handles nested objects)
    if (input.includes('{')) {
        // Try parsing the entire input as JSON first
        try {
            const obj = JSON.parse(input)
            if (typeof obj === 'object' && obj !== null) {
                extractKeysRecursive(obj, 0, keys)
            }
        } catch {
            // Find JSON objects using brace-depth matching
            const jsonFragments = extractJsonFragments(input)
            for (const frag of jsonFragments) {
                try {
                    const obj = JSON.parse(frag.text)
                    if (typeof obj === 'object' && obj !== null) {
                        extractKeysRecursive(obj, frag.position, keys)
                    }
                } catch {
                    extractKeysFromMalformed(frag.text, frag.position, keys)
                }
            }
        }
    }

    // Strategy 2: Direct key-value patterns (fallback)
    // Handles: {"$gt": ""} or {$ne: 1} or [$ne] (bracket notation)
    // Validate against known operators to prevent FPs from $50, $variable, etc.
    const kvPattern = /["']?(\$[a-zA-Z]+)["']?\s*[:\]]/g
    let kvMatch: RegExpExecArray | null
    while ((kvMatch = kvPattern.exec(input)) !== null) {
        const key = kvMatch[1]
        const pos = kvMatch.index
        // Only accept known MongoDB operators to avoid FPs
        if (ALL_MONGO_OPERATORS.has(key.toLowerCase())) {
            if (!keys.some(k => k.key === key && k.position === pos)) {
                keys.push({
                    key,
                    value: '',
                    position: pos,
                })
            }
        }
    }

    // Strategy 3: URL parameter injection
    // Handles: username[$ne]=&password[$gt]=
    const paramPattern = /([a-zA-Z_]+)\[(\$[a-zA-Z]+)\]/g
    let paramMatch: RegExpExecArray | null
    while ((paramMatch = paramPattern.exec(input)) !== null) {
        keys.push({
            key: paramMatch[2],
            value: paramMatch[1],
            position: paramMatch.index,
        })
    }

    // Strategy 4: Dot notation injection
    // Handles: username.$ne=admin
    const dotPattern = /([a-zA-Z_]+)\.(\$[a-zA-Z]+)/g
    let dotMatch: RegExpExecArray | null
    while ((dotMatch = dotPattern.exec(input)) !== null) {
        keys.push({
            key: dotMatch[2],
            value: dotMatch[1],
            position: dotMatch.index,
        })
    }

    return keys
}

function extractKeysFromMalformed(fragment: string, basePos: number, keys: Array<{ key: string; value: string; position: number }>): void {
    // Extract "$key" patterns from malformed JSON
    const keyPattern = /["']?(\$[a-zA-Z]+)["']?\s*:/g
    let match
    while ((match = keyPattern.exec(fragment)) !== null) {
        keys.push({
            key: match[1],
            value: '',
            position: basePos + match.index,
        })
    }
}


// ── JavaScript Detection ─────────────────────────────────────────
//
// For $where and mapReduce, MongoDB evaluates JavaScript.
// Detect JS code patterns in the input.

const JS_CODE_PATTERNS = [
    /function\s*\([^)]*\)\s*\{/,           // function() { ... }
    /=>\s*\{/,                              // () => { ... }
    /this\.[a-zA-Z]+/,                      // this.field
    /return\s+/,                            // return statement
    /\bsleep\s*\(\d+\)/,                   // sleep(5000) — DoS
    /\bwhile\s*\(true\)/,                  // while(true) — DoS
    /\bdb\.[a-zA-Z]+/,                     // db.collection
    /\bprocess\b/,                         // Node.js process
    /\brequire\s*\(/,                      // require()
]

function containsJavaScript(value: string): { isJS: boolean; pattern: string } {
    for (const pattern of JS_CODE_PATTERNS) {
        if (pattern.test(value)) {
            return { isJS: true, pattern: pattern.source }
        }
    }
    return { isJS: false, pattern: '' }
}


// ── Detection Logic ──────────────────────────────────────────────

function detectOperatorInjection(keys: Array<{ key: string; value: string; position: number }>): NoSQLDetection[] {
    const detections: NoSQLDetection[] = []
    const seen = new Set<string>()

    for (const entry of keys) {
        const normalized = entry.key.toLowerCase()

        if (ALL_MONGO_OPERATORS.has(normalized) && !seen.has(normalized)) {
            seen.add(normalized)

            const isDangerous = MONGO_DANGEROUS_OPERATORS.has(normalized)

            detections.push({
                type: 'operator_injection',
                detail: `MongoDB operator ${entry.key} injected${isDangerous ? ' (DANGEROUS — enables code execution)' : ''}`,
                operator: entry.key,
                confidence: isDangerous ? 0.94 : 0.88,
            })
        }
    }

    return detections
}

function detectJSInjection(input: string): NoSQLDetection[] {
    const detections: NoSQLDetection[] = []

    // Check if input contains $where context
    const hasWhereContext = /\$where/i.test(input) ||
        /\$function/i.test(input) ||
        /mapReduce/i.test(input) ||
        /\$accumulator/i.test(input)

    // Check for JavaScript code in the input
    const jsCheck = containsJavaScript(input)

    if (jsCheck.isJS) {
        detections.push({
            type: 'js_injection',
            detail: `JavaScript code detected${hasWhereContext ? ' in $where context' : ''}: ${jsCheck.pattern}`,
            operator: hasWhereContext ? '$where' : 'js_expression',
            confidence: hasWhereContext ? 0.92 : 0.75,
        })
    }

    return detections
}


// ── Public API ───────────────────────────────────────────────────

/**
 * Detect NoSQL injection vectors by parsing JSON structure for
 * operator injection and analyzing JavaScript expressions.
 */
export function detectNoSQLInjection(input: string): NoSQLDetection[] {
    const detections: NoSQLDetection[] = []

    // Quick bail: must contain $ or { to be relevant
    if (!input.includes('$') && !input.includes('{') && !input.includes('[')) {
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

    try {
        const keys = extractJsonKeys(decoded)
        detections.push(...detectOperatorInjection(keys))
    } catch { /* never crash */ }

    try {
        detections.push(...detectJSInjection(decoded))
    } catch { /* never crash */ }

    return detections
}
