/**
 * @santh/agent — HTTP Outbound RASP Wrapper
 *
 * Wraps outbound HTTP requests (fetch, http.request) to detect SSRF.
 *
 * The math:
 *   Given URL U:
 *   resolve(U) must not reach internal network addresses.
 *   If resolve(U) ∈ INTERNAL_ADDRESSES, U is an SSRF.
 */

import type { InvariantDB, DefenseAction, Severity } from '../db.js'
import { recordRaspEvent } from './request-session.js'

export interface HttpRaspConfig {
    mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    db: InvariantDB
    allowedDomains?: string[]
    onViolation?: (violation: HttpViolation) => void
}

export interface HttpViolation {
    url: string
    invariantClass: string
    action: DefenseAction
    confidence: number
    timestamp: string
}

const SSRF_INVARIANTS = [
    {
        id: 'ssrf_internal_ip',
        test: (url: string) => {
            try {
                const u = new URL(url)
                const host = u.hostname
                return /^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.|localhost$|\[::1?\]$|0x7f)/i.test(host)
            } catch { return false }
        },
        severity: 'high' as Severity,
    },
    {
        id: 'ssrf_cloud_metadata',
        test: (url: string) => /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.azure\.com/i.test(url),
        severity: 'critical' as Severity,
    },
    {
        id: 'ssrf_protocol_smuggle',
        test: (url: string) => /^(?:file|gopher|dict|ldap|tftp|jar|phar):/i.test(url),
        severity: 'critical' as Severity,
    },
    {
        id: 'ssrf_redirect_chain',
        test: (url: string) => {
            try {
                const u = new URL(url)
                // Suspicious: URL contains another URL as parameter (potential redirect)
                return /(?:url|redirect|next|continue|goto|target|dest|return)=/i.test(u.search) &&
                    /https?:\/\//i.test(u.search)
            } catch { return false }
        },
        severity: 'medium' as Severity,
    },
]

export function checkUrlInvariants(url: string): Array<{ id: string; severity: Severity }> {
    const violations: Array<{ id: string; severity: Severity }> = []
    for (const inv of SSRF_INVARIANTS) {
        try {
            if (inv.test(url)) {
                violations.push({ id: inv.id, severity: inv.severity })
            }
        } catch { /* never break */ }
    }
    return violations
}

export function wrapFetch(
    originalFetch: typeof globalThis.fetch,
    config: HttpRaspConfig,
): typeof globalThis.fetch {
    return async function wrappedFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url
        if (!url) return originalFetch(input, init)

        const violations = checkUrlInvariants(url)
        if (violations.length === 0) return originalFetch(input, init)

        const hasCritical = violations.some(v => v.severity === 'critical')
        const action: DefenseAction =
            config.mode === 'observe' ? 'monitored' :
                (hasCritical || config.mode === 'defend' || config.mode === 'lockdown') ? 'blocked' : 'monitored'
        if (violations.length > 0) {
            recordRaspEvent('http', url, violations.map(v => v.id), hasCritical ? 0.95 : 0.85, action === 'blocked')
        }

        const now = new Date().toISOString()

        // Record
        try {
            config.db.insertSignal({
                type: 'ssrf_invariant_violation',
                subtype: violations[0].id,
                severity: violations[0].severity,
                action,
                path: url.slice(0, 200),
                method: init?.method ?? 'GET',
                source_hash: null,
                invariant_classes: JSON.stringify(violations.map(v => v.id)),
                is_novel: false,
                timestamp: now,
            })
        } catch { /* Never break */ }

        if (config.onViolation) {
            try {
                config.onViolation({
                    url,
                    invariantClass: violations[0].id,
                    action,
                    confidence: action === 'blocked' ? 0.95 : 0.85,
                    timestamp: now,
                })
            } catch { /* Never break */ }
        }

        if (action === 'blocked') {
            throw new Error(`[INVARIANT] Outbound request blocked — ${violations.map(v => v.id).join(', ')} detected. URL: ${url.slice(0, 100)}`)
        }

        return originalFetch(input, init)
    }
}

type NodeRequestOptions = {
    protocol?: unknown
    host?: unknown
    hostname?: unknown
    port?: unknown
    path?: unknown
    method?: unknown
}

function isNodeRequestOptions(value: unknown): value is NodeRequestOptions {
    return typeof value === 'object' && value !== null
}

function extractMethodFromRequestArgs(args: unknown[]): string {
    const first = args[0]
    const second = args[1]
    if (isNodeRequestOptions(first) && typeof first.method === 'string') return first.method
    if (isNodeRequestOptions(second) && typeof second.method === 'string') return second.method
    return 'GET'
}

function normalizeProtocol(input: unknown, fallback: 'http:' | 'https:'): 'http:' | 'https:' {
    if (typeof input !== 'string') return fallback
    const v = input.toLowerCase()
    if (v === 'http:' || v === 'http') return 'http:'
    if (v === 'https:' || v === 'https') return 'https:'
    return fallback
}

function normalizePath(input: unknown): string {
    if (typeof input !== 'string' || input.length === 0) return '/'
    return input.startsWith('/') ? input : `/${input}`
}

function extractHostAndPort(options: NodeRequestOptions): { host: string; port: string } | null {
    if (typeof options.hostname === 'string' && options.hostname.length > 0) {
        const p = typeof options.port === 'number' || typeof options.port === 'string' ? String(options.port) : ''
        return { host: options.hostname, port: p }
    }
    if (typeof options.host === 'string' && options.host.length > 0) {
        if (options.host.startsWith('[')) {
            const closeIdx = options.host.indexOf(']')
            if (closeIdx > 0) {
                const host = options.host.slice(0, closeIdx + 1)
                const rest = options.host.slice(closeIdx + 1)
                const port = rest.startsWith(':') ? rest.slice(1) : ''
                return { host, port }
            }
        }
        const idx = options.host.lastIndexOf(':')
        if (idx > -1 && options.host.indexOf(':') === idx) {
            return { host: options.host.slice(0, idx), port: options.host.slice(idx + 1) }
        }
        return { host: options.host, port: '' }
    }
    return null
}

function buildRequestUrlFromOptions(options: NodeRequestOptions, fallbackProtocol: 'http:' | 'https:'): string | null {
    const hostAndPort = extractHostAndPort(options)
    if (!hostAndPort || hostAndPort.host.length === 0) return null
    const protocol = normalizeProtocol(options.protocol, fallbackProtocol)
    const path = normalizePath(options.path)
    const portSuffix = hostAndPort.port.length > 0 ? `:${hostAndPort.port}` : ''
    return `${protocol}//${hostAndPort.host}${portSuffix}${path}`
}

function extractNodeRequestUrl(args: unknown[], fallbackProtocol: 'http:' | 'https:'): string | null {
    const first = args[0]
    const second = args[1]
    if (first instanceof URL) {
        return first.toString()
    }
    if (typeof first === 'string') {
        try {
            if (/^https?:\/\//i.test(first)) return new URL(first).toString()
            if (isNodeRequestOptions(second)) {
                const maybe = buildRequestUrlFromOptions(second, fallbackProtocol)
                if (maybe) return new URL(first, maybe).toString()
            }
            return new URL(first, `${fallbackProtocol}//localhost`).toString()
        } catch {
            return null
        }
    }
    if (isNodeRequestOptions(first)) {
        return buildRequestUrlFromOptions(first, fallbackProtocol)
    }
    return null
}

function inspectAndHandleNodeRequest(
    url: string | null,
    method: string,
    config: HttpRaspConfig,
): void {
    if (!url) return

    const violations = checkUrlInvariants(url)
    if (violations.length === 0) return

    const hasCritical = violations.some(v => v.severity === 'critical')
    const action: DefenseAction =
        config.mode === 'observe' ? 'monitored' :
            (hasCritical || config.mode === 'defend' || config.mode === 'lockdown') ? 'blocked' : 'monitored'
    if (violations.length > 0) {
        recordRaspEvent('http', url, violations.map(v => v.id), hasCritical ? 0.95 : 0.85, action === 'blocked')
    }

    const now = new Date().toISOString()

    try {
        config.db.insertSignal({
            type: 'ssrf_invariant_violation',
            subtype: violations[0].id,
            severity: violations[0].severity,
            action,
            path: url.slice(0, 200),
            method,
            source_hash: null,
            invariant_classes: JSON.stringify(violations.map(v => v.id)),
            is_novel: false,
            timestamp: now,
        })
    } catch { /* Never break */ }

    if (config.onViolation) {
        try {
            config.onViolation({
                url,
                invariantClass: violations[0].id,
                action,
                confidence: action === 'blocked' ? 0.95 : 0.85,
                timestamp: now,
            })
        } catch { /* Never break */ }
    }

    if (action === 'blocked') {
        throw new Error(`[INVARIANT] Outbound request blocked — ${violations.map(v => v.id).join(', ')} detected. URL: ${url.slice(0, 100)}`)
    }
}

export function wrapNodeHttpRequest<T extends (...args: unknown[]) => unknown>(
    originalRequest: T,
    config: HttpRaspConfig,
    protocol: 'http:' | 'https:',
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const url = extractNodeRequestUrl(args, protocol)
        const method = extractMethodFromRequestArgs(args)
        inspectAndHandleNodeRequest(url, method, config)
        return originalRequest.apply(this, args)
    }
    return wrapped as unknown as T
}

export function wrapNodeHttpGet<T extends (...args: unknown[]) => unknown>(
    originalGet: T,
    config: HttpRaspConfig,
    protocol: 'http:' | 'https:',
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const url = extractNodeRequestUrl(args, protocol)
        inspectAndHandleNodeRequest(url, 'GET', config)
        return originalGet.apply(this, args)
    }
    return wrapped as unknown as T
}
