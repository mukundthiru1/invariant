/**
 * HTTP Parameter Pollution (HPP) Evaluator — Level 2 Invariant Detection
 *
 * Detects when the same parameter appears multiple times with different
 * values (e.g. ?role=user&role=admin) or JSON bodies with duplicate keys,
 * which can lead to access control bypass or backend parsing confusion.
 */

export interface HppDetection {
    type: 'duplicate_query_param' | 'duplicate_json_key'
    detail: string
    paramName?: string
    values?: string[]
    confidence: number
}

function decodeQuerySegment(input: string): string {
    try {
        return decodeURIComponent(input.replace(/\+/g, ' '))
    } catch {
        return input
    }
}

/**
 * Parse query string and return map of param name -> list of values (order preserved).
 */
function parseQueryParams(queryString: string): Map<string, string[]> {
    const params = new Map<string, string[]>()
    if (!queryString) return params
    const rest = (queryString.startsWith('?') ? queryString.slice(1) : queryString).split('&')
    for (const pair of rest) {
        const eq = pair.indexOf('=')
        const name = eq >= 0 ? decodeQuerySegment(pair.slice(0, eq)) : decodeQuerySegment(pair)
        const value = eq >= 0 ? decodeQuerySegment(pair.slice(eq + 1)) : ''
        if (!name) continue
        const existing = params.get(name) ?? []
        existing.push(value)
        params.set(name, existing)
    }
    return params
}

/**
 * Detect duplicate keys in a JSON object (first level only; sufficient for common HPP in body).
 * Returns the first duplicate key name found, or null.
 */
function findDuplicateJsonKeys(jsonStr: string): { key: string; count: number } | null {
    const trimmed = jsonStr.trim()
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) === false) return null
    const inner = trimmed.slice(1, -1)
    const keyPattern = /"([^"\\]*(?:\\.[^"\\]*)*)"\s*:/g
    const seen = new Map<string, number>()
    let m: RegExpExecArray | null
    while ((m = keyPattern.exec(inner)) !== null) {
        const key = m[1].replace(/\\"/g, '"')
        seen.set(key, (seen.get(key) ?? 0) + 1)
    }
    for (const [key, count] of seen) {
        if (count > 1) return { key, count }
    }
    return null
}

/**
 * Detect HTTP Parameter Pollution: same param multiple times with different values
 * (e.g. ?role=user&role=admin) or JSON body with duplicate keys.
 */
export function detectHttpParameterPollution(input: string): HppDetection | null {
    if (!input || input.length < 3) return null

    const trimmed = input.trim()

    // Query string: ?foo=a&foo=b or role=user&role=admin
    const queryMatch = trimmed.match(/\?[^#\s]+/) ?? (trimmed.includes('=') && trimmed.includes('&') ? [trimmed] : null)
    if (queryMatch) {
        const params = parseQueryParams(queryMatch[0])
        for (const [name, values] of params) {
            if (values.length > 1) {
                const uniqueValues = [...new Set(values)]
                if (uniqueValues.length > 1 || values.length > 1) {
                    return {
                        type: 'duplicate_query_param',
                        detail: `HTTP parameter pollution: duplicate param "${name}" with ${values.length} value(s)`,
                        paramName: name,
                        values,
                        confidence: 0.89,
                    }
                }
            }
        }
    }

    // JSON body: duplicate keys
    try {
        const dup = findDuplicateJsonKeys(trimmed)
        if (dup) {
            return {
                type: 'duplicate_json_key',
                detail: `HTTP parameter pollution: duplicate JSON key "${dup.key}" (${dup.count} times)`,
                paramName: dup.key,
                confidence: 0.89,
            }
        }
    } catch {
        // not valid JSON or not object shape
    }

    return null
}
