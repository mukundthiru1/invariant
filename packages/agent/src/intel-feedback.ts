interface SignalEvent {
    class_id: string
    payload_hash: string
    confidence: number
    ts: number
}

const BUFFER_LIMIT = 50
const FLUSH_INTERVAL_MS = 60_000

let signalBuffer: SignalEvent[] = []
let flushTimer: ReturnType<typeof setInterval> | null = null
let flushInFlight = false

function normalizeBaseUrl(url: string): string {
    return url.endsWith('/') ? url.slice(0, -1) : url
}

function ensureFlushTimer(): void {
    if (flushTimer) return
    flushTimer = setInterval(() => {
        void flushSignals()
    }, FLUSH_INTERVAL_MS)
    if (flushTimer.unref) flushTimer.unref()
}

function buildEndpoint(): { url: string; apiKey: string } | null {
    const url = process.env.SANTH_INTEL_URL
    const apiKey = process.env.SANTH_API_KEY
    if (!url || !apiKey) return null
    return { url: normalizeBaseUrl(url), apiKey }
}

async function postSignal(signal: SignalEvent, endpoint: string, apiKey: string): Promise<void> {
    await fetch(`${endpoint}/v1/signal`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify(signal),
    })
}

export function queueSignal(classId: string, payloadHash: string, confidence: number): void {
    const endpoint = buildEndpoint()
    if (!endpoint) return

    ensureFlushTimer()
    signalBuffer.push({
        class_id: classId,
        payload_hash: payloadHash,
        confidence,
        ts: Date.now(),
    })

    if (signalBuffer.length >= BUFFER_LIMIT) {
        void flushSignals()
    }
}

export async function flushSignals(): Promise<void> {
    if (flushInFlight || signalBuffer.length === 0) return

    const endpoint = buildEndpoint()
    if (!endpoint) {
        signalBuffer = []
        return
    }

    const batch = signalBuffer.splice(0, BUFFER_LIMIT)
    flushInFlight = true

    try {
        await Promise.allSettled(batch.map(signal => postSignal(signal, endpoint.url, endpoint.apiKey)))
    } catch {
        // Never throw into app/runtime path.
    } finally {
        flushInFlight = false
        if (signalBuffer.length >= BUFFER_LIMIT) {
            void flushSignals()
        }
    }
}
