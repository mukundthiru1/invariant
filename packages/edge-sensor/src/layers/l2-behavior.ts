/**
 * Edge Sensor — Layer 2: Behavioral Analysis
 *
 * Tracks per-source-hash request patterns to detect:
 * - Rate anomalies (burst requests)
 * - Path enumeration (spray attacks)
 * - Method probing (diversity threshold)
 * - Unusual HTTP methods (WebDAV, TRACE, etc.)
 * - High error rates (scanner fingerprint)
 */

export class BehaviorTracker {
    private ipCounts = new Map<string, { count: number; firstSeen: number; paths: Set<string>; methods: Set<string>; statusCodes: Map<number, number> }>()
    private readonly WINDOW_MS = 60_000
    private readonly BURST_THRESHOLD = 30
    private readonly PATH_SPRAY_THRESHOLD = 15
    private readonly METHOD_DIVERSITY_THRESHOLD = 4
    private readonly UNUSUAL_METHODS = new Set(['TRACE', 'TRACK', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'PATCH'])
    private readonly MAX_ENTRIES = 10_000

    track(sourceHash: string, path: string, method: string): string | null {
        const now = Date.now()
        let entry = this.ipCounts.get(sourceHash)

        if (!entry || (now - entry.firstSeen) > this.WINDOW_MS) {
            entry = { count: 0, firstSeen: now, paths: new Set(), methods: new Set(), statusCodes: new Map() }
            this.ipCounts.set(sourceHash, entry)
        }

        entry.count++
        entry.paths.add(path)
        entry.methods.add(method)

        if (this.ipCounts.size > this.MAX_ENTRIES) {
            const cutoff = now - this.WINDOW_MS
            for (const [key, val] of this.ipCounts) {
                if (val.firstSeen < cutoff) this.ipCounts.delete(key)
            }
        }

        if (entry.count > this.BURST_THRESHOLD) return 'rate_anomaly'
        if (entry.paths.size > this.PATH_SPRAY_THRESHOLD) return 'path_enumeration'
        // Method diversity: legitimate users don't use 4+ HTTP methods in 60s
        if (entry.methods.size >= this.METHOD_DIVERSITY_THRESHOLD) return 'method_probing'
        // Unusual methods: TRACE, TRACK, WebDAV, etc.
        if (this.UNUSUAL_METHODS.has(method.toUpperCase())) return 'unusual_method'
        return null
    }

    recordResponseCode(sourceHash: string, status: number): void {
        const entry = this.ipCounts.get(sourceHash)
        if (entry) {
            entry.statusCodes.set(status, (entry.statusCodes.get(status) ?? 0) + 1)
        }
    }

    getRequestCount(sourceHash: string): number {
        return this.ipCounts.get(sourceHash)?.count ?? 0
    }

    /** Check if source is exhibiting scanner-like error ratio */
    hasHighErrorRate(sourceHash: string): boolean {
        const entry = this.ipCounts.get(sourceHash)
        if (!entry || entry.count < 5) return false
        let errorCount = 0
        for (const [code, count] of entry.statusCodes) {
            if (code >= 400) errorCount += count
        }
        return (errorCount / entry.count) > 0.5
    }
}
