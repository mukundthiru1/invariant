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
