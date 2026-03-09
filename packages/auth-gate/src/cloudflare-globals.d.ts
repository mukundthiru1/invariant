/// <reference types="@cloudflare/workers-types" />

interface KVNamespace {
    get<T = string>(key: string, options?: unknown): Promise<T | null>
    put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
    delete(key: string): Promise<void>
}

declare const Crypto: {
    getRandomValues<T extends ArrayBufferView>(array: T): T
}
