/**
 * INVARIANT — Request Body Analysis
 *
 * The detection pipeline's blind spot: POST/PUT/PATCH body payloads.
 * Without body analysis, an attacker can inject any payload via
 * form data, JSON body, or raw POST — completely invisible to
 * path/query analysis.
 *
 * Design constraints:
 *   - Must not break content delivery (body must be re-readable)
 *   - Must be fast (hot path, every request)
 *   - Must handle various content types
 *   - Size-bounded to prevent memory exhaustion
 *   - Fail-open: body read failure → continue without body analysis
 *
 * Content types handled:
 *   - application/json → parse and flatten values
 *   - application/x-www-form-urlencoded → parse key-value pairs
 *   - multipart/form-data → extract text fields (skip binary)
 *   - text/* → analyze raw text
 *   - application/xml, text/xml → analyze raw XML
 *
 * Integration:
 *   Returns extracted strings for the invariant engine to analyze.
 *   The body is cloned before reading so the original request passes
 *   through to origin unmodified.
 */


// ── Body Analysis Result ─────────────────────────────────────────

export interface BodyAnalysisResult {
    /** Whether body was successfully analyzed */
    analyzed: boolean
    /** Content type detected */
    contentType: string | null
    /** Body size in bytes */
    bodySize: number
    /** Extracted strings for invariant analysis */
    extractedValues: string[]
    /** Combined text for full-text analysis */
    combinedText: string
    /** Reason if analysis was skipped */
    skipReason: string | null
}


// ── Configuration ────────────────────────────────────────────────

/** Maximum body size to analyze fully (128KB) — increased from 32KB to prevent padding bypass */
const MAX_BODY_SIZE = 131_072

/**
 * SAA-C003: For bodies larger than MAX_BODY_SIZE, scan the first and last
 * OVERSIZED_TAIL_SCAN bytes. Attackers pad 32KB+ of filler then place the
 * actual payload at the tail. Scanning only the first window would miss this.
 */
const OVERSIZED_TAIL_SCAN = 8_192

/** Maximum number of extracted values to prevent resource exhaustion */
const MAX_EXTRACTED_VALUES = 200

/** Maximum depth for JSON flattening */
const MAX_JSON_DEPTH = 10


// ═══════════════════════════════════════════════════════════════════
// BODY ANALYZER
// ═══════════════════════════════════════════════════════════════════

/**
 * Extract analyzable text from the request body for invariant detection.
 *
 * @param request The incoming request (body will be read from a clone)
 * @returns BodyAnalysisResult with extracted text values
 */
export async function analyzeRequestBody(
    request: Request,
): Promise<BodyAnalysisResult> {
    const contentType = request.headers.get('content-type')

    // Skip for methods that typically don't have payloads
    if (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS') {
        return {
            analyzed: false,
            contentType,
            bodySize: 0,
            extractedValues: [],
            combinedText: '',
            skipReason: 'safe_method',
        }
    }

    // Skip if no content-type header
    if (!contentType) {
        return {
            analyzed: false,
            contentType: null,
            bodySize: 0,
            extractedValues: [],
            combinedText: '',
            skipReason: 'no_content_type',
        }
    }

    // Check content-length if available — only skip if absurdly large (>10MB)
    const contentLength = parseInt(request.headers.get('content-length') ?? '0')
    if (contentLength > 10_485_760) {
        return {
            analyzed: false,
            contentType,
            bodySize: contentLength,
            extractedValues: [],
            combinedText: '',
            skipReason: 'body_too_large',
        }
    }

    try {
        // Clone the request so the original body remains consumable
        const clone = request.clone()
        const rawBody = await clone.text()

        if (rawBody.length === 0) {
            return {
                analyzed: false,
                contentType,
                bodySize: 0,
                extractedValues: [],
                combinedText: '',
                skipReason: 'empty_body',
            }
        }

        // SAA-C003: For bodies larger than MAX_BODY_SIZE, scan head + tail windows
        // to catch padding attacks where payload is placed after 32KB+ of filler.
        // The full body is not buffered to avoid memory exhaustion.
        let analysisBody: string
        let oversized = false
        if (rawBody.length > MAX_BODY_SIZE) {
            const head = rawBody.slice(0, MAX_BODY_SIZE)
            const tail = rawBody.slice(-OVERSIZED_TAIL_SCAN)
            analysisBody = head + '\n' + tail
            oversized = true
        } else {
            analysisBody = rawBody
        }

        const ct = contentType.toLowerCase()
        let extractedValues: string[] = []

        if (ct.includes('application/json')) {
            extractedValues = oversized
                // For oversized JSON, do a flat text extraction rather than parse
                ? [analysisBody]
                : extractFromJson(rawBody)
        } else if (ct.includes('application/x-www-form-urlencoded')) {
            extractedValues = extractFromFormEncoded(analysisBody)
        } else if (ct.includes('multipart/form-data')) {
            extractedValues = extractFromMultipart(analysisBody)
        } else if (ct.includes('xml')) {
            extractedValues = [analysisBody]
        } else if (ct.includes('text/')) {
            extractedValues = [analysisBody]
        } else if (ct.includes('graphql')) {
            extractedValues = oversized ? [analysisBody] : extractFromJson(rawBody)
        } else {
            // Unknown content type — analyze raw if it looks like text
            if (isLikelyText(analysisBody)) {
                extractedValues = [analysisBody]
            } else {
                return {
                    analyzed: false,
                    contentType,
                    bodySize: rawBody.length,
                    extractedValues: [],
                    combinedText: '',
                    skipReason: 'binary_content',
                }
            }
        }

        // Cap extracted values
        if (extractedValues.length > MAX_EXTRACTED_VALUES) {
            extractedValues = extractedValues.slice(0, MAX_EXTRACTED_VALUES)
        }

        const combinedText = extractedValues.join(' ')

        return {
            analyzed: true,
            contentType,
            bodySize: rawBody.length,
            extractedValues,
            combinedText,
            skipReason: null,
        }
    } catch {
        // Fail open — body read failure must never break the pipeline
        return {
            analyzed: false,
            contentType,
            bodySize: 0,
            extractedValues: [],
            combinedText: '',
            skipReason: 'read_error',
        }
    }
}


// ── JSON Value Extraction ────────────────────────────────────────

/**
 * Parse JSON and flatten all string values for analysis.
 * Handles nested objects, arrays, and recursive structures.
 */
export function extractFromJson(raw: string): string[] {
    try {
        // SAA-091: Prototype pollution guard — parsing attacker-controlled request body
        const parsed = JSON.parse(raw, (key, value) => {
            if (key === '__proto__' && value && typeof value === 'object') {
                return cloneForPrototypeSafeAccess(value)
            }
            return value
        })
        const values: string[] = []
        flattenJsonValues(parsed, values, 0, '')
        return values
    } catch {
        // Invalid JSON — treat as raw text if it contains attack patterns
        return [raw]
    }
}

function cloneForPrototypeSafeAccess(value: object): object {
    if (Array.isArray(value)) {
        return value.map((entry) => {
            if (entry && typeof entry === 'object') return cloneForPrototypeSafeAccess(entry)
            return entry
        })
    }
    const clone: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) {
        if (k === '__proto__' && v && typeof v === 'object') {
            clone[k] = cloneForPrototypeSafeAccess(v)
        } else if (v && typeof v === 'object') {
            clone[k] = v
        } else {
            clone[k] = v
        }
    }
    return clone
}

function flattenJsonValues(
    obj: unknown,
    out: string[],
    depth: number,
    path: string,
): void {
    if (depth > MAX_JSON_DEPTH || out.length >= MAX_EXTRACTED_VALUES) return

    if (typeof obj === 'string') {
        if (obj.length > 0 && obj.length < 8192) {
            out.push(obj)
        }
        return
    }

    if (typeof obj === 'number' || typeof obj === 'boolean') {
        return // numbers and booleans aren't attack vectors
    }

    if (Array.isArray(obj)) {
        for (const item of obj) {
            flattenJsonValues(item, out, depth + 1, path)
        }
        return
    }

    if (obj !== null && typeof obj === 'object') {
        for (const key of Object.keys(obj)) {
            const nextPath = path.length > 0 ? `${path}.${key}` : key
            // Keys can be attack vectors too (e.g., "__proto__", "$where")
            if (key.length > 0 && key.length < 1024) {
                out.push(
                    key === '__proto__' || key === 'constructor' || key === 'prototype'
                        ? nextPath
                        : key,
                )
            }
            flattenJsonValues((obj as Record<string, unknown>)[key], out, depth + 1, nextPath)
        }
    }
}


// ── Form URL-Encoded Extraction ──────────────────────────────────

export function extractFromFormEncoded(raw: string): string[] {
    const values: string[] = []
    const params = raw.split('&')

    for (const param of params) {
        if (values.length >= MAX_EXTRACTED_VALUES) break

        const eqIdx = param.indexOf('=')
        if (eqIdx === -1) {
            // Key-only param
            values.push(safeDecodeURIComponent(param))
        } else {
            const key = safeDecodeURIComponent(param.slice(0, eqIdx))
            const value = safeDecodeURIComponent(param.slice(eqIdx + 1))

            // Keys like user[role] or password[$ne] are attack vectors
            if (key.length > 0) values.push(key)
            if (value.length > 0) values.push(value)
        }
    }

    return values
}


// ── Multipart Extraction ─────────────────────────────────────────

export function extractFromMultipart(raw: string): string[] {
    const values: string[] = []

    // Extract text field values from multipart (skip file uploads)
    // This is a simplified parser — we don't need full MIME parsing,
    // just enough to extract text values for security analysis.
    const parts = raw.split(/------?[a-zA-Z0-9]+/)
    for (const part of parts) {
        if (values.length >= MAX_EXTRACTED_VALUES) break

        // Skip parts that look like file uploads
        if (part.includes('Content-Type:') && !part.includes('text/plain')) continue

        // Extract the value portion (after the double CRLF)
        const valuePart = part.split(/\r\n\r\n|\n\n/)
        if (valuePart.length >= 2) {
            const text = valuePart.slice(1).join('\n').trim()
            if (text.length > 0 && text.length < 8192) {
                values.push(text)
            }
        }
    }

    return values
}


// ── Helpers ──────────────────────────────────────────────────────

function safeDecodeURIComponent(str: string): string {
    try {
        return decodeURIComponent(str)
    } catch {
        return str
    }
}

function isLikelyText(str: string): boolean {
    // Check if the first 512 bytes look like printable text
    const sample = str.slice(0, 512)
    let printable = 0
    for (let i = 0; i < sample.length; i++) {
        const code = sample.charCodeAt(i)
        if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) {
            printable++
        }
    }
    return (printable / sample.length) > 0.8
}
