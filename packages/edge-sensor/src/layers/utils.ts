/**
 * Edge Sensor — Utility Functions
 *
 * IP hashing, header anomaly detection, block response generation,
 * and path normalization.
 */

// ── IP Anonymization ──────────────────────────────────────────────

/**
 * Daily deterministic salt for IP hashing.
 *
 * SAA-060: Previously used crypto.getRandomValues() per isolate.
 * Cloudflare spawns N concurrent isolates → same IP hashes to N
 * different sourceHashes → reputation splits, chain correlation
 * breaks, behavioral thresholds double.
 *
 * Fix: derive salt from HMAC(SENSOR_API_KEY, date). All isolates
 * with same env produce same salt. Still unguessable externally
 * (requires knowing the API key). Falls back to random salt if
 * no API key is configured (single-isolate degradation).
 */
let _dailySaltCache: { date: string; salt: Uint8Array } | null = null
let _sensorApiKey: string | null = null

export function setSaltKey(apiKey: string): void {
    _sensorApiKey = apiKey
}

async function getDailySalt(): Promise<Uint8Array> {
    const today = new Date().toISOString().slice(0, 10)
    if (_dailySaltCache?.date === today) return _dailySaltCache.salt

    let salt: Uint8Array
    if (_sensorApiKey && _sensorApiKey.length >= 16) {
        // Deterministic: HMAC(apiKey, date) — consistent across all isolates
        const encoder = new TextEncoder()
        const key = await crypto.subtle.importKey(
            'raw', encoder.encode(_sensorApiKey),
            { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        )
        const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(`ip-salt:${today}`))
        salt = new Uint8Array(mac)
    } else {
        // Fallback: random per-isolate (acceptable for single-isolate deployments)
        salt = crypto.getRandomValues(new Uint8Array(32))
    }

    _dailySaltCache = { date: today, salt }
    return salt
}

export async function hashSource(ip: string): Promise<string> {
    const encoder = new TextEncoder()
    const salt = await getDailySalt()
    // Concatenate: salt || ip
    const ipBytes = encoder.encode(ip)
    const combined = new Uint8Array(salt.length + ipBytes.length)
    combined.set(salt)
    combined.set(ipBytes, salt.length)
    const hash = await crypto.subtle.digest('SHA-256', combined)
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}


// ── Header Anomaly Detection ──────────────────────────────────────

export function detectHeaderAnomalies(headers: Headers): boolean {
    const ua = headers.get('user-agent') ?? ''
    if (ua.length > 500) return true
    if (!headers.has('host')) return true
    const accept = headers.get('accept') ?? ''
    if (accept.length > 400) return true
    if (headers.has('x-forwarded-for') && headers.has('x-real-ip')) {
        const xff = headers.get('x-forwarded-for') ?? ''
        const xri = headers.get('x-real-ip') ?? ''
        if (xff.split(',').length > 5 && xri !== xff.split(',')[0].trim()) return true
    }
    return false
}


// ── Block Response ────────────────────────────────────────────────

export function blockResponse(severity: string, _requestOrigin?: string | null): Response {
    return new Response(JSON.stringify({
        error: 'Request blocked by security policy',
        code: 'INVARIANT_DEFENSE',
    }), {
        status: 403,
        headers: {
            'Content-Type': 'application/json',
            // SAA-062: No X-Invariant-Action header — it confirms sensor presence.
            'Cache-Control': 'no-store',
            // SECURITY: No CORS headers on block responses.
            // Reflecting the Origin header with Allow-Credentials was a credential-leaking
            // CORS misconfiguration (SAA-003). Blocked requests have no reason to be
            // readable by cross-origin scripts. Legitimate CORS frontends get proper
            // CORS from origin responses that pass the sensor.
        },
    })
}


// ── Path Normalization ────────────────────────────────────────────

export function normalizePath(path: string): string {
    return path
        .toLowerCase()
        .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '{uuid}')
        .replace(/[0-9a-f]{32,64}/g, '{hash}')
        .replace(/\/\d{4,}/g, '/{id}')
        .replace(/\/\d+(?=\/|$)/g, '/{id}')
        .replace(/=([^&]+)/g, '={val}')
        .replace(/\/$/, '')
        || '/'
}


// ── Timing-Safe Comparison ────────────────────────────────────────

/**
 * Constant-time string comparison using HMAC.
 * Prevents timing side-channel attacks on secret comparisons.
 *
 * Uses a random session key — we don't need to persist it since
 * we only need the equality property, not the MAC itself.
 */
const _hmacKey = crypto.getRandomValues(new Uint8Array(32))

export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
        'raw', _hmacKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    )
    const [macA, macB] = await Promise.all([
        crypto.subtle.sign('HMAC', key, encoder.encode(a)),
        crypto.subtle.sign('HMAC', key, encoder.encode(b)),
    ])
    const viewA = new Uint8Array(macA)
    const viewB = new Uint8Array(macB)
    if (viewA.length !== viewB.length) return false
    let diff = 0
    for (let i = 0; i < viewA.length; i++) {
        diff |= viewA[i] ^ viewB[i]
    }
    return diff === 0
}
