/**
 * CRLF Injection Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for CRLF injection is:
 *   ∃ sequence ∈ decode(input) :
 *     sequence = \r\n (0x0D 0x0A)
 *     ∧ ∃ header_name : input[after(sequence)] MATCHES /^[A-Za-z-]+:/
 *     → attacker injects HTTP headers via CRLF
 *
 *   ∨ sequence = \r\n\r\n
 *     → attacker splits response (HTTP response splitting)
 *
 * Unlike regex matching %0d%0a, this evaluator:
 *   1. Decodes through all encoding layers
 *   2. Identifies the injected header name/value
 *   3. Classifies the attack (header injection, response split, log forge)
 *   4. Detects double-CRLF (response body injection)
 *
 * Covers:
 *   - crlf_header_injection: CRLF + HTTP header pattern
 *   - crlf_log_injection:    CRLF + log entry forgery pattern
 */


// ── Result Type ──────────────────────────────────────────────────

export interface CRLFDetection {
    type: 'header_injection' | 'response_split' | 'log_injection'
    detail: string
    injectedHeader: string | null
    confidence: number
}


// ── Security-Relevant Headers ────────────────────────────────────

const DANGEROUS_HEADERS = new Set([
    'set-cookie', 'location', 'content-type', 'content-length',
    'transfer-encoding', 'x-forwarded-for', 'x-forwarded-host',
    'access-control-allow-origin', 'access-control-allow-credentials',
    'x-xss-protection', 'content-security-policy', 'x-frame-options',
    'www-authenticate', 'authorization', 'proxy-authorization',
    'cookie', 'host', 'referer', 'origin',
])


// ── Multi-Layer CRLF Decoder ─────────────────────────────────────
//
// Attackers encode CRLF through multiple layers:
//   %0d%0a           → \r\n (standard URL encoding)
//   %250d%250a       → %0d%0a → \r\n (double encoding)
//   %0D%0A           → \r\n (uppercase)
//   \r\n             → literal (some frameworks)
//   %E5%98%8A%E5%98%8D → \r\n (Unicode encoding on some parsers)

function decodeCRLF(input: string): { decoded: string; layers: number } {
    let current = input
    let layers = 0

    for (let i = 0; i < 4; i++) {
        let next = current

        // URL decode
        try {
            next = decodeURIComponent(next)
        } catch {
            next = next.replace(/%([0-9a-fA-F]{2})/g, (_, hex) =>
                String.fromCharCode(parseInt(hex, 16))
            )
        }

        // Backslash escape sequences
        next = next.replace(/\\r\\n/g, '\r\n')
        next = next.replace(/\\n/g, '\n')
        next = next.replace(/\\r/g, '\r')

        if (next === current) break
        current = next
        layers++
    }

    return { decoded: current, layers }
}


// ── CRLF Sequence Finder ─────────────────────────────────────────

interface CRLFSequence {
    position: number
    isDoubleCRLF: boolean  // \r\n\r\n = response split
    after: string          // Content after the CRLF
}

function findCRLFSequences(decoded: string): CRLFSequence[] {
    const sequences: CRLFSequence[] = []
    let searchFrom = 0

    while (searchFrom < decoded.length) {
        // Find \r\n or standalone \n
        const crlfIdx = decoded.indexOf('\r\n', searchFrom)
        const lfIdx = decoded.indexOf('\n', searchFrom)
        const idx = crlfIdx >= 0 ? crlfIdx : lfIdx
        if (idx < 0) break

        const isCRLF = crlfIdx >= 0 && crlfIdx === idx
        const step = isCRLF ? 2 : 1
        const afterPos = idx + step

        // Check for double CRLF
        let isDouble = false
        if (isCRLF && decoded.startsWith('\r\n', afterPos)) {
            isDouble = true
        } else if (!isCRLF && decoded[afterPos] === '\n') {
            isDouble = true
        }

        const after = decoded.substring(afterPos + (isDouble ? step : 0)).trimStart()

        sequences.push({
            position: idx,
            isDoubleCRLF: isDouble,
            after,
        })

        searchFrom = afterPos + 1
    }

    return sequences
}


// ── Detection Functions ──────────────────────────────────────────

function detectHeaderInjection(sequences: CRLFSequence[]): CRLFDetection[] {
    const detections: CRLFDetection[] = []

    for (const seq of sequences) {
        if (seq.isDoubleCRLF) continue // handled by response split

        // Check if content after CRLF matches HTTP header pattern
        const headerMatch = seq.after.match(/^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)/)
        if (headerMatch) {
            const headerName = headerMatch[1].toLowerCase()
            const headerValue = headerMatch[2].substring(0, 100)
            const isDangerous = DANGEROUS_HEADERS.has(headerName)

            detections.push({
                type: 'header_injection',
                detail: `CRLF + header injection: ${headerMatch[1]}: ${headerValue}${isDangerous ? ' (SECURITY-CRITICAL HEADER)' : ''}`,
                injectedHeader: headerMatch[1],
                confidence: isDangerous ? 0.95 : 0.88,
            })
        }
    }

    return detections
}

function detectResponseSplit(sequences: CRLFSequence[]): CRLFDetection[] {
    const detections: CRLFDetection[] = []

    for (const seq of sequences) {
        if (!seq.isDoubleCRLF) continue

        // Double CRLF = response body injection
        const hasContent = seq.after.length > 0
        const hasHTML = /<[a-z]/i.test(seq.after)
        const hasScript = /<script/i.test(seq.after)

        detections.push({
            type: 'response_split',
            detail: `HTTP response splitting (double CRLF)${hasScript ? ' + script injection' : hasHTML ? ' + HTML injection' : hasContent ? ' + body content' : ''}`,
            injectedHeader: null,
            confidence: hasScript ? 0.96 : hasHTML ? 0.93 : hasContent ? 0.90 : 0.85,
        })
    }

    return detections
}

function detectLogInjection(decoded: string, sequences: CRLFSequence[]): CRLFDetection[] {
    const detections: CRLFDetection[] = []

    if (sequences.length === 0) return detections

    // Log injection: CRLF followed by log-like content
    const logPatterns = [
        /^\d{4}-\d{2}-\d{2}/,                       // Date prefix
        /^\[\d{2}\/\w{3}\/\d{4}/,                   // Apache log date
        /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s/,   // IP prefix
        /^(INFO|WARN|ERROR|DEBUG|TRACE)\s*[:\-]/i,   // Log level
        /^\[\w+\]\s*/,                                // Bracketed tag
        /^200 OK|^304 Not Modified|^403 Forbidden/i,  // HTTP status
    ]

    for (const seq of sequences) {
        if (seq.isDoubleCRLF) continue // that's response split
        const matchesLogPattern = logPatterns.some(p => p.test(seq.after))
        if (matchesLogPattern) {
            detections.push({
                type: 'log_injection',
                detail: `CRLF + log entry forgery: "${seq.after.substring(0, 80)}"`,
                injectedHeader: null,
                confidence: 0.88,
            })
        }
    }

    return detections
}


// ── Public API ───────────────────────────────────────────────────

export function detectCRLFInjection(input: string): CRLFDetection[] {
    const detections: CRLFDetection[] = []

    // Quick bail: must contain CRLF-like sequences
    if (input.length < 4) return detections
    const hasEncodedCRLF = /%0[dD]|%0[aA]|%25|\\r|\\n/i.test(input)
    const hasLiteralCRLF = input.includes('\r') || input.includes('\n')
    if (!hasEncodedCRLF && !hasLiteralCRLF) return detections

    const { decoded } = decodeCRLF(input)
    const sequences = findCRLFSequences(decoded)

    if (sequences.length === 0) return detections

    try { detections.push(...detectHeaderInjection(sequences)) } catch { /* safe */ }
    try { detections.push(...detectResponseSplit(sequences)) } catch { /* safe */ }
    try { detections.push(...detectLogInjection(decoded, sequences)) } catch { /* safe */ }

    return detections
}
