/**
 * Edge Sensor — Signal Buffer
 *
 * Batched, deduplication-aware signal accumulator.
 * Flushes to the SANTH Intel ingest endpoint.
 */

import type { Signal } from './types.js'

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

    async flush(): Promise<void> {
        if (this.signals.length === 0 || !this.ingestUrl) return

        const batch = this.signals.splice(0, this.batchSize)

        try {
            if (!this.apiKey) {
                console.error('[signal-buffer] No API key configured — signal flush skipped')
                this.signals.unshift(...batch.slice(0, 50))
                return
            }
            const resp = await fetch(this.ingestUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.apiKey}`,
                },
                body: JSON.stringify({ signals: batch, sensorVersion: '8.0.0', timestamp: new Date().toISOString() }),
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
