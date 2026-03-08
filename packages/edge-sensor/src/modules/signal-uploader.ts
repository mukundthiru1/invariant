import type {
    EncryptedSignalBundle,
    SignalBundle,
    SignalProductCategory,
    SignalUploadBatch,
} from '../../../engine/src/crypto/types.js'
import { encryptSignal } from '../crypto/signals.js'
import { hashPayload, type SignalDeduplicator } from './signal-dedup.js'
import { computeCampaignFingerprint } from './campaign-fingerprint.js'

export interface PendingSignal {
    bundle: SignalBundle
    queuedAt: number
}

export function isDuplicateSignal(signal: PendingSignal, deduplicator: SignalDeduplicator): boolean {
    const payloadHash = hashPayload(
        signal.bundle.invariantClass,
        signal.bundle.evidence ?? signal.bundle.payload ?? '',
    )
    return deduplicator.isDuplicate(payloadHash)
}

export class SignalBuffer {
    private readonly maxSize = 500
    private readonly buffer: PendingSignal[] = []

    push(signal: PendingSignal): void {
        if (signal.bundle.detectionLevel !== 'l2' && signal.bundle.detectionLevel !== 'l3') {
            return
        }

        if (this.buffer.length >= this.maxSize) {
            this.buffer.shift()
        }

        this.buffer.push(signal)
    }

    drain(): PendingSignal[] {
        if (this.buffer.length === 0) {
            return []
        }

        const drained = this.buffer.slice()
        this.buffer.length = 0
        return drained
    }

    get size(): number {
        return this.buffer.length
    }

    get isEmpty(): boolean {
        return this.buffer.length === 0
    }
}

/**
 * Generate a daily anonymous token from a sensor ID.
 * hash(sensorId + YYYY-MM-DD) — rotates daily, not linkable across days.
 * Central can deduplicate within a day but cannot build a profile over time.
 */
export async function generateAnonToken(sensorId: string): Promise<string> {
    const day = new Date().toISOString().slice(0, 10) // YYYY-MM-DD
    const data = new TextEncoder().encode(sensorId + ':' + day)
    const hash = await crypto.subtle.digest('SHA-256', data)
    const bytes = new Uint8Array(hash)
    // Take first 16 bytes → 22-char base64url (enough for dedup, not reversible)
    let b64 = ''
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    for (let i = 0; i < 16; i++) {
        b64 += alphabet[bytes[i] % 64]
    }
    return b64
}

export async function flushSignalBuffer(
    buffer: SignalBuffer,
    centralPublicKeyB64: string,
    ingestUrl: string,
    sensorId: string,
): Promise<{ uploaded: number; failed: boolean }> {
    try {
        const signals = buffer.drain()
        if (signals.length === 0) {
            return { uploaded: 0, failed: false }
        }

        const anonToken = await generateAnonToken(sensorId)

        const encrypted: EncryptedSignalBundle[] = []
        for (const signal of signals) {
            encrypted.push(await encryptSignal(signal.bundle, centralPublicKeyB64))
        }

        const batch: SignalUploadBatch = {
            signals: encrypted,
            batchId: crypto.randomUUID(),
            sentAt: Date.now(),
            campaignFingerprint: computeCampaignFingerprint(signals),
            anonToken,
            v: 2,
        }

        const response = await fetch(ingestUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Invariant-Version': '2',
            },
            body: JSON.stringify(batch),
        })

        if (!response.ok) {
            return { uploaded: 0, failed: true }
        }

        return { uploaded: signals.length, failed: false }
    } catch {
        return { uploaded: 0, failed: true }
    }
}

export function makeSignalBundle(
    match: {
        class: string
        confidence: number
        detectionLevel?: { l1: boolean; l2: boolean }
        detectionLevels?: { l1: boolean; l2: boolean }
        l2Evidence?: string
    },
    request: { method: string; pathname: string },
    encodingDepth: number,
    options?: {
        /** Raw input that triggered detection — will be sanitized before inclusion */
        rawPayload?: string
        /** Where in the request the payload was found */
        surface?: SignalBundle['surface']
        /** Product category from `invariant init` */
        category?: SignalProductCategory
        /** Auto-detected framework */
        framework?: string
    },
): SignalBundle {
    const l2Detected = match.detectionLevel?.l2 ?? match.detectionLevels?.l2 ?? false
    const l1Detected = match.detectionLevel?.l1 ?? match.detectionLevels?.l1

    const detectionLevel: SignalBundle['detectionLevel'] = l2Detected
        ? 'l2'
        : !l1Detected
            ? 'l3'
            : 'l1'

    const evidence = sanitizeEvidence(match.l2Evidence)
    const payload = options?.rawPayload ? sanitizePayload(options.rawPayload) : undefined

    return {
        invariantClass: match.class,
        detectionLevel,
        confidence: match.confidence,
        encodingDepth,
        method: request.method,
        surface: options?.surface ?? 'unknown',
        payload,
        category: options?.category,
        framework: options?.framework,
        // Round timestamp to nearest hour for anonymity
        timestamp: Math.floor(Date.now() / 3_600_000) * 3_600_000,
        evidence,
        v: 2,
    }
}


// ── Payload Sanitizer ──────────────────────────────────────────────
//
// Goal: keep the raw attack TECHNIQUE, strip anything that could
// identify WHO was attacked. The payload is what the attacker sent —
// it reveals the attacker's methods, not the target's identity.
//
// KEEPS: SQL syntax, XSS tags/events, shell operators, encoding
//        layers, traversal sequences, JNDI lookups, gadget chains.
//
// STRIPS: internal hostnames, email addresses, API keys/tokens,
//         private domain names, app-specific file paths, IP addresses
//         in RFC1918/link-local ranges, cookie values, auth tokens.

/** Maximum payload length to prevent abuse (4KB) */
const MAX_PAYLOAD_LENGTH = 4096

export function sanitizePayload(raw: string): string | undefined {
    if (!raw || raw.length === 0) return undefined

    let p = raw.length > MAX_PAYLOAD_LENGTH ? raw.slice(0, MAX_PAYLOAD_LENGTH) : raw

    // Strip email addresses
    p = p.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[email]')

    // Strip Authorization header values (must fire BEFORE generic bearer/token regex)
    p = p.replace(/(Authorization\s*:\s*(?:Basic|Digest|Bearer)\s+)\S+/gi, '$1[redacted]')

    // Strip API keys / bearer tokens / long hex/base64 secrets (32+ chars)
    p = p.replace(/(?:Bearer\s+|token[=:]\s*|key[=:]\s*|api[_-]?key[=:]\s*)[A-Za-z0-9_\-./+=]{20,}/gi, '[token]')
    p = p.replace(/\b[A-Za-z0-9_\-]{40,}\b/g, '[secret]')

    // Strip RFC1918 / link-local / loopback IP addresses (these reveal internal network structure)
    p = p.replace(/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, '[internal-ip]')

    // Strip internal/private hostnames (*.local, *.internal, *.corp, *.lan, *.private)
    p = p.replace(/\b[a-zA-Z0-9][\w.-]*\.(?:local|internal|corp|lan|private|intranet)\b/gi, '[internal-host]')

    // Strip domain names in SSRF-style URLs — keep the protocol + path structure, mask the domain
    // Only strip in URL-like contexts, not in SQL/XSS payloads
    p = p.replace(/(https?:\/\/)([a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,})(\/[^\s'"]*)?/g, (_, proto, _domain, path) => {
        // Keep known attack-relevant domains (metadata endpoints, localhost)
        const domain = _domain.toLowerCase()
        if (domain === 'localhost' || domain === '169.254.169.254' || domain === 'metadata.google.internal') {
            return proto + _domain + (path ?? '')
        }
        return proto + '[domain]' + (path ?? '')
    })

    // Strip app-specific paths after common webroot prefixes — keep traversal structure
    p = p.replace(/((?:\.\.\/)+(?:var\/www|home|opt|srv|app)\/)[^\s\/'"]+/g, '$1[app]')

    // Strip cookie values (keep cookie name structure for technique analysis)
    p = p.replace(/((?:Cookie|Set-Cookie)\s*[:=]\s*\w+=)[^\s;]+/gi, '$1[value]')

    return p.length > 0 ? p : undefined
}


// ── Internal helpers ───────────────────────────────────────────────

function sanitizeEvidence(evidence?: string): string | undefined {
    if (!evidence) {
        return undefined
    }

    const stripped = evidence
        .replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '$1[redacted]$1')
        .replace(/\b([A-Za-z_][\w-]*)=([^\s,;]+)/g, '$1=[redacted]')
        .trim()

    return stripped.length > 0 ? stripped : undefined
}
