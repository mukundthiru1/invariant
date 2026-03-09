export type VerbTunnelingHit =
    | 'x_http_method_override_delete_on_get'
    | 'x_method_override_unusual_verb'
    | 'form_method_override_delete'

const STANDARD_HTTP_METHODS = new Set([
    'GET',
    'HEAD',
    'POST',
    'PUT',
    'DELETE',
    'CONNECT',
    'OPTIONS',
    'TRACE',
    'PATCH',
])

const TRAILER_SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'host'])

function hasNullByte(value: string): boolean {
    return value.includes('\0') || /%00/i.test(value)
}

function hasAuthorityPortManipulation(authority: string): boolean {
    const trimmed = authority.trim()
    if (trimmed.length === 0) return false
    if (hasNullByte(trimmed)) return true
    if (/[/?#@\\\s]/.test(trimmed)) return true

    // Multiple explicit ports (example.com:80:443).
    if (/:[0-9]{1,5}:[0-9]{1,5}/.test(trimmed)) return true

    // Reject malformed host:port that cannot be normalized.
    try {
        const url = new URL(`https://${trimmed}`)
        if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
            return true
        }
        if (url.port) {
            const port = Number.parseInt(url.port, 10)
            if (!Number.isInteger(port) || port < 1 || port > 65535) return true
        }
    } catch {
        return true
    }

    return false
}

export function detectH2PseudoHeaderAbuse(headers: Headers): boolean {
    const pseudoPath = headers.get(':path')
    if (pseudoPath && hasNullByte(pseudoPath)) return true

    const pseudoAuthority = headers.get(':authority')
    if (pseudoAuthority && hasAuthorityPortManipulation(pseudoAuthority)) return true

    const pseudoMethod = headers.get(':method')
    if (pseudoMethod) {
        const normalized = pseudoMethod.trim().toUpperCase()
        if (!STANDARD_HTTP_METHODS.has(normalized)) return true
    }

    return false
}

export function detectTrailerInjection(request: Request): boolean {
    const trailerHeader = request.headers.get('trailer')
    if (!trailerHeader) return false

    const trailerFields = trailerHeader
        .split(',')
        .map(field => field.trim().toLowerCase())
        .filter(Boolean)

    return trailerFields.some(field => TRAILER_SENSITIVE_HEADERS.has(field))
}

function hasSuspiciousWebSocketProtocolValue(protocolValue: string): boolean {
    if (protocolValue.length > 256) return true
    if (/[\r\n\0]/.test(protocolValue)) return true

    const values = protocolValue.split(',').map(v => v.trim()).filter(Boolean)
    if (values.length > 5) return true
    if (values.length === 0) return false

    const tokenPattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
    return values.some(value => !tokenPattern.test(value))
}

export function detectWebSocketUpgradeAbuse(request: Request): boolean {
    const upgrade = request.headers.get('upgrade')
    if (!upgrade || upgrade.toLowerCase() !== 'websocket') return false

    const protocolValue = request.headers.get('sec-websocket-protocol') ?? ''
    if (protocolValue && hasSuspiciousWebSocketProtocolValue(protocolValue)) {
        return true
    }

    const secFetchSite = (request.headers.get('sec-fetch-site') ?? '').toLowerCase()
    const origin = request.headers.get('origin')
    if (secFetchSite === 'cross-site' && !origin) {
        return true
    }

    return false
}

export function detectHttpVerbTunneling(
    request: Request,
    body: { contentType: string | null; combinedText: string } | null,
): VerbTunnelingHit[] {
    const hits: VerbTunnelingHit[] = []

    const override = request.headers.get('x-http-method-override')
    if (request.method.toUpperCase() === 'GET' && override?.trim().toUpperCase() === 'DELETE') {
        hits.push('x_http_method_override_delete_on_get')
    }

    const methodOverride = request.headers.get('x-method-override')
    if (methodOverride) {
        const normalized = methodOverride.trim().toUpperCase()
        if (!STANDARD_HTTP_METHODS.has(normalized)) {
            hits.push('x_method_override_unusual_verb')
        }
    }

    if (
        body
        && body.contentType
        && body.contentType.toLowerCase().includes('application/x-www-form-urlencoded')
        && /(?:^|[&\s])_method(?:=|\s+)(delete)(?:$|[&\s])/i.test(body.combinedText)
    ) {
        hits.push('form_method_override_delete')
    }

    return hits
}
