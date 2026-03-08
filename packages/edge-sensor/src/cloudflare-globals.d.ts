declare global {
    var crypto: Crypto

    interface GlobalThis {
        crypto: Crypto
    }

    interface ExecutionContext {
        waitUntil(promise: Promise<unknown>): void
        passThroughOnException?(): void
    }

    interface ScheduledEvent {
        scheduledTime: number
        cron: string
    }

    interface KVNamespace {
        get<T = string>(key: string, type?: 'text' | 'json' | 'arrayBuffer' | 'stream'): Promise<T | string | null>
        put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
    }

    interface Ai {}
}

export {}
