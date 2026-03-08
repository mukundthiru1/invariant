import type { InvariantDB } from './db.js'

export interface RuntimeHealthSnapshot {
    uptimeMs: number
    runtimeErrors: number
    lastErrorAt: string | null
    wrappedIntegrations: string[]
    memoryRss: number
    memoryHeapUsed: number
}

export class RuntimeHealthMonitor {
    private readonly startedAt = Date.now()
    private readonly wrappedIntegrations = new Set<string>()
    private runtimeErrors = 0
    private lastErrorAt: number | null = null
    private readonly db: InvariantDB | null
    private readonly verbose: boolean

    constructor(db: InvariantDB | null, verbose = false) {
        this.db = db
        this.verbose = verbose
    }

    markIntegrationWrapped(name: string): void {
        this.wrappedIntegrations.add(name)
    }

    recordInternalError(context: string, error: unknown): void {
        this.runtimeErrors++
        this.lastErrorAt = Date.now()

        if (this.verbose) {
            console.warn(`[invariant] internal error in ${context}:`, error)
        }

        if (!this.db) return
        try {
            this.db.insertSignal({
                type: 'agent_internal_error',
                subtype: context,
                severity: 'medium',
                action: 'monitored',
                path: context,
                method: 'INTERNAL',
                source_hash: null,
                invariant_classes: '[]',
                is_novel: false,
                timestamp: new Date(this.lastErrorAt).toISOString(),
            })
        } catch {
            // Never allow health logging failures to propagate.
        }
    }

    snapshot(): RuntimeHealthSnapshot {
        const mem = process.memoryUsage()
        return {
            uptimeMs: Date.now() - this.startedAt,
            runtimeErrors: this.runtimeErrors,
            lastErrorAt: this.lastErrorAt ? new Date(this.lastErrorAt).toISOString() : null,
            wrappedIntegrations: [...this.wrappedIntegrations].sort(),
            memoryRss: mem.rss,
            memoryHeapUsed: mem.heapUsed,
        }
    }
}
