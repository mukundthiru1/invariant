/**
 * Edge Sensor — Signal Buffer
 *
 * Batched, deduplication-aware signal accumulator.
 * Flushes to the SANTH Intel ingest endpoint.
 *
 * SAA-073: Includes PoW challenge solving before signal submission.
 * The sensor acquires a challenge from /v1/challenge, solves it locally
 * (finding SHA-256 with N leading zero bits), and includes the solution
 * in the POST body. Solved challenges are cached until expiry.
 */

import type { Signal } from './types.js'


// ── PoW Helpers ───────────────────────────────────────────────────

interface ChallengeResponse {
    challenge: string
    difficulty: number
    expires_at: number
}

interface PowSolution {
    challenge: string
    solution: string
}

/**
 * Count leading zero bits in a SHA-256 hash (as Uint8Array).
 */
function countLeadingZeroBits(hash: Uint8Array): number {
    let count = 0
    for (const byte of hash) {
        if (byte === 0) {
            count += 8
        } else {
            let mask = 0x80
            while (mask > 0 && (byte & mask) === 0) {
                count++
                mask >>= 1
            }
            break
        }
    }
    return count
}

/**
 * Solve a PoW challenge by brute-forcing SHA-256 until
 * the hash has enough leading zero bits.
 *
 * For difficulty 18 (~260K hashes), this takes ~10-40ms
 * on a Cloudflare Worker isolate. Well within CPU budget.
 */
async function solveChallenge(challenge: string, difficulty: number): Promise<string> {
    if (difficulty > 26 || difficulty < 1) {
        throw new Error(`Invalid PoW difficulty: ${difficulty} (must be 1-26)`)
    }

    const encoder = new TextEncoder()
    let nonce = 0

    // Use a random prefix to avoid collision with other solvers
    const prefix = Math.random().toString(36).slice(2, 8)

    while (true) {
        const candidate = `${prefix}${nonce}`
        const input = `${challenge}:${candidate}`
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(input))
        const hashBytes = new Uint8Array(hashBuffer)

        if (countLeadingZeroBits(hashBytes) >= difficulty) {
            return candidate
        }

        nonce++

        // Safety: don't burn infinite CPU. At difficulty 26
        // (~67M hashes), bail after 100M attempts.
        if (nonce > 100_000_000) {
            throw new Error(`PoW solve exceeded max iterations (difficulty=${difficulty})`)
        }
    }
}


// ── Signal Buffer ─────────────────────────────────────────────────

export class SignalBuffer {
    private signals: Signal[] = []
    private readonly batchSize: number
    private readonly ingestUrl: string
    private readonly apiKey: string
    private dedup = new Map<string, { count: number; lastSeen: number }>()
    private static readonly MAX_BUFFER = 500
    private static readonly DEDUP_WINDOW_MS = 60_000
    /** Cap dedup map to prevent unbounded memory growth under sustained attack */
    private static readonly MAX_DEDUP_ENTRIES = 5_000

    /** Cached PoW solution — reused until challenge expires */
    private cachedPow: PowSolution | null = null
    private cachedPowExpiry = 0

    constructor(batchSize: number, ingestUrl: string, apiKey: string) {
        this.batchSize = batchSize
        this.ingestUrl = ingestUrl
        this.apiKey = apiKey
    }

    add(signal: Signal): void {
        const now = Date.now()
        const dedupKey = `${signal.sourceHash}:${signal.type}:${signal.method}:${signal.path}`
        const existing = this.dedup.get(dedupKey)

        if (existing && (now - existing.lastSeen) < SignalBuffer.DEDUP_WINDOW_MS) {
            existing.count++
            existing.lastSeen = now
            return
        }

        this.dedup.set(dedupKey, { count: 1, lastSeen: now })

        if (this.signals.length >= SignalBuffer.MAX_BUFFER) {
            this.signals.shift()
        }

        this.signals.push(signal)
    }

    shouldFlush(): boolean {
        return this.signals.length >= this.batchSize
    }

    /**
     * Acquire a PoW solution for the next signal submission.
     * Uses cached solution if still valid; otherwise fetches
     * a new challenge and solves it.
     */
    private async acquirePow(): Promise<PowSolution | null> {
        // Use cached solution if not expired (with 30s margin)
        if (this.cachedPow && Date.now() < this.cachedPowExpiry - 30_000) {
            return this.cachedPow
        }

        try {
            // Derive challenge URL from ingest URL
            const baseUrl = this.ingestUrl.replace(/\/v1\/.*$/, '')
            const challengeUrl = `${baseUrl}/v1/challenge`

            const resp = await fetch(challengeUrl, {
                headers: { 'Authorization': `Bearer ${this.apiKey}` },
            })

            if (!resp.ok) {
                console.error(`[signal-buffer] Challenge fetch failed: ${resp.status}`)
                return null
            }

            const data = await resp.json() as ChallengeResponse
            if (!data.challenge || !data.difficulty) {
                console.error('[signal-buffer] Invalid challenge response')
                return null
            }

            // Solve the challenge
            const solution = await solveChallenge(data.challenge, data.difficulty)

            this.cachedPow = { challenge: data.challenge, solution }
            this.cachedPowExpiry = data.expires_at

            return this.cachedPow
        } catch (err) {
            console.error(`[signal-buffer] PoW acquisition failed: ${err instanceof Error ? err.message : String(err)}`)
            return null
        }
    }

    async flush(): Promise<void> {
        if (this.signals.length === 0 || !this.ingestUrl) return

        const batch = this.signals.splice(0, this.batchSize)

        try {
            if (!this.apiKey) {
                console.error('[signal-buffer] No API key configured — signal flush skipped')
                this.signals.unshift(...batch.slice(0, 50))
                return
            }

            // Acquire PoW solution before submitting
            const pow = await this.acquirePow()

            const body: Record<string, unknown> = {
                signals: batch,
                sensorVersion: '8.0.0',
                timestamp: new Date().toISOString(),
            }

            // Include PoW if acquired; server may reject without it
            if (pow) {
                body.pow = pow
                // Invalidate cached solution — each solution is single-use
                this.cachedPow = null
                this.cachedPowExpiry = 0
            }

            const resp = await fetch(this.ingestUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.apiKey}`,
                },
                body: JSON.stringify(body),
            })
            if (!resp.ok) {
                console.error(`[signal-buffer] Flush rejected: ${resp.status}`)
                this.signals.unshift(...batch.slice(0, 50))
            }
        } catch {
            // Re-add failed signals to front of buffer
            this.signals.unshift(...batch.slice(0, 50))
        }

        // Clean old dedup entries + enforce max size
        const cutoff = Date.now() - SignalBuffer.DEDUP_WINDOW_MS
        for (const [key, val] of this.dedup) {
            if (val.lastSeen < cutoff) this.dedup.delete(key)
        }
        // Hard cap: if dedup map still exceeds max, evict oldest entries
        if (this.dedup.size > SignalBuffer.MAX_DEDUP_ENTRIES) {
            const entries = [...this.dedup.entries()].sort((a, b) => a[1].lastSeen - b[1].lastSeen)
            const evictCount = this.dedup.size - SignalBuffer.MAX_DEDUP_ENTRIES
            for (let i = 0; i < evictCount; i++) {
                this.dedup.delete(entries[i][0])
            }
        }
    }

    getCount(): number { return this.signals.length }
}
