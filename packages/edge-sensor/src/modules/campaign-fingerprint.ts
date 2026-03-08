import type { PendingSignal } from './signal-uploader.js'

export interface CampaignFingerprint {
    attackClasses: string[]
    encodingPattern: string
    timingBucket: number
    surfacePattern: string
}

const FNV_PRIME = 0x01000193
const FNV_OFFSET_BASIS = 0x811c9dc5
const encoder = new TextEncoder()

function fnv1a32(input: string): number {
    const bytes = encoder.encode(input)
    let hash = FNV_OFFSET_BASIS >>> 0

    for (let i = 0; i < bytes.length; i++) {
        hash ^= bytes[i]
        hash = Math.imul(hash, FNV_PRIME) >>> 0
    }

    return hash >>> 0
}

function extractEncodingTechniques(text: string): Set<string> {
    const techniques = new Set<string>()

    if (/%(?:25)?[0-9a-f]{2}/i.test(text)) techniques.add('url')
    if (/(?:\\u[0-9a-f]{4}|&#x?[0-9a-f]+;)/i.test(text)) techniques.add('unicode')
    if (/\b[A-Za-z0-9+/]{16,}={0,2}\b/.test(text)) techniques.add('base64')
    if (/\\x[0-9a-f]{2}/i.test(text)) techniques.add('hex')

    return techniques
}

function buildCampaignFingerprint(signals: PendingSignal[]): CampaignFingerprint {
    const classes = new Set<string>()
    const encodings = new Set<string>()
    const surfaces = new Set<string>()

    let latestTimestamp = 0

    for (const signal of signals) {
        classes.add(signal.bundle.invariantClass)
        surfaces.add(signal.bundle.surface)

        if (signal.bundle.timestamp > latestTimestamp) {
            latestTimestamp = signal.bundle.timestamp
        }

        if (signal.bundle.encodingDepth > 0) {
            encodings.add('encoded')
        }

        const payloadText = `${signal.bundle.payload ?? ''} ${signal.bundle.evidence ?? ''}`
        for (const technique of extractEncodingTechniques(payloadText)) {
            encodings.add(technique)
        }
    }

    return {
        attackClasses: [...classes].sort(),
        encodingPattern: encodings.size > 0 ? [...encodings].sort().join('+') : 'plain',
        timingBucket: Math.floor(latestTimestamp / 3_600_000) * 3_600_000,
        surfacePattern: surfaces.size > 0 ? [...surfaces].sort().join('+') : 'unknown',
    }
}

export function computeCampaignFingerprint(signals: PendingSignal[]): string {
    const fingerprint = buildCampaignFingerprint(signals)
    const material = [
        fingerprint.attackClasses.join(','),
        fingerprint.encodingPattern,
        fingerprint.surfacePattern,
    ].join('|')

    return fnv1a32(material).toString(16).padStart(8, '0')
}
