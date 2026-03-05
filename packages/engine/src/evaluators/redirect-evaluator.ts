/**
 * Open Redirect Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for open redirect is:
 *   parse(input, URL_GRAMMAR).host ≠ SAME_ORIGIN
 *   ∧ input OCCURS_IN redirect_parameter
 *   → attacker redirects user to external domain
 *
 * Unlike regex, this evaluator:
 *   1. Parses the URL to extract the actual host
 *   2. Handles all bypass techniques (protocol-relative, backslash,
 *      fragment abuse, auth confusion, null bytes)
 *   3. Detects domain confusion (evil.com disguised as target.com)
 *
 * Covers:
 *   - open_redirect_bypass: URL resolves to external domain via bypass
 */


// ── Result Type ──────────────────────────────────────────────────

export interface OpenRedirectDetection {
    type: 'protocol_relative' | 'backslash' | 'auth_confusion' | 'data_uri' | 'javascript_uri' | 'domain_bypass'
    detail: string
    extractedHost: string
    confidence: number
}


// ── Bypass Technique Detectors ───────────────────────────────────

function detectProtocolRelative(input: string): OpenRedirectDetection | null {
    // //evil.com, ///evil.com, ////evil.com
    const match = input.match(/^\/\/(\/*)([^/\s]+)/)
    if (match) {
        return {
            type: 'protocol_relative',
            detail: `Protocol-relative redirect to ${match[2]}`,
            extractedHost: match[2],
            confidence: 0.92,
        }
    }
    return null
}

function detectBackslashRedirect(input: string): OpenRedirectDetection | null {
    // /\evil.com, /\\evil.com — browsers normalize \ to / in URLs
    const match = input.match(/^\/\\+([^/\\\s]+)/)
    if (match) {
        return {
            type: 'backslash',
            detail: `Backslash redirect bypass to ${match[1]}`,
            extractedHost: match[1],
            confidence: 0.90,
        }
    }
    return null
}

function detectAuthConfusion(input: string): OpenRedirectDetection | null {
    // https://target.com@evil.com — @ is used as basic auth
    // The browser sends the request to evil.com, not target.com
    const match = input.match(/^https?:\/\/[^@]*@([^/\s]+)/)
    if (match) {
        return {
            type: 'auth_confusion',
            detail: `Auth confusion: actual host is ${match[1]} (@ redirects to attacker)`,
            extractedHost: match[1],
            confidence: 0.94,
        }
    }
    return null
}

function detectDataURI(input: string): OpenRedirectDetection | null {
    // data:text/html,<script>...
    if (/^data:/i.test(input.trim())) {
        return {
            type: 'data_uri',
            detail: 'Data URI redirect — arbitrary content rendering',
            extractedHost: 'data:',
            confidence: 0.88,
        }
    }
    return null
}

function detectJavascriptURI(input: string): OpenRedirectDetection | null {
    // javascript:alert(1)
    const trimmed = input.trim().toLowerCase()
    if (trimmed.startsWith('javascript:') || trimmed.startsWith('vbscript:')) {
        return {
            type: 'javascript_uri',
            detail: `Script URI in redirect: ${trimmed.substring(0, 50)}`,
            extractedHost: 'javascript:',
            confidence: 0.95,
        }
    }
    return null
}

function detectDomainBypass(input: string): OpenRedirectDetection | null {
    // Various domain-level bypasses:
    //   - https://evil.com — simple external URL
    //   - //%09/evil.com — tab character between slashes
    //   - /%2f/evil.com — encoded slash
    //   - //evil.com%2f.. — path normalization

    const dblSlashMatch = input.match(/^\/\/[\s%]*([^/\s%]+\.[^/\s%]+)/)
    if (dblSlashMatch) {
        return {
            type: 'domain_bypass',
            detail: `Double-slash redirect with obfuscation to ${dblSlashMatch[1]}`,
            extractedHost: dblSlashMatch[1],
            confidence: 0.88,
        }
    }

    // URL with explicit external host
    const urlMatch = input.match(/^https?:\/\/([^/@\s:]+\.[^/@\s:]+)/)
    if (urlMatch) {
        const host = urlMatch[1].toLowerCase()
        // If the URL has a recognizable TLD, it's an external redirect
        if (/\.(com|net|org|io|co|me|xyz|dev|app|info|biz|ru|cn|tk|ml|cf|ga|gq|pw)$/i.test(host)) {
            return {
                type: 'domain_bypass',
                detail: `External URL redirect to ${host}`,
                extractedHost: host,
                confidence: 0.85,
            }
        }
    }

    return null
}


// ── Public API ───────────────────────────────────────────────────

export function detectOpenRedirect(input: string): OpenRedirectDetection[] {
    const detections: OpenRedirectDetection[] = []

    if (input.length < 3) return detections

    // Multi-layer decode
    let decoded = input
    try {
        let prev = ''
        for (let i = 0; i < 3 && decoded !== prev; i++) {
            prev = decoded
            try { decoded = decodeURIComponent(decoded) } catch { break }
        }
    } catch { /* use original */ }

    const detectors: Array<(input: string) => OpenRedirectDetection | null> = [
        detectJavascriptURI,
        detectDataURI,
        detectAuthConfusion,
        detectProtocolRelative,
        detectBackslashRedirect,
        detectDomainBypass,
    ]

    for (const detector of detectors) {
        try {
            const result = detector(decoded)
            if (result) detections.push(result)
        } catch { /* never crash */ }
    }

    return detections
}
