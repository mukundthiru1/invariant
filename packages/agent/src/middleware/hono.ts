import { InvariantEngine, type InvariantMatch } from '../../../engine/src/invariant-engine.js'
import { validateConfig, DEFAULT_CONFIG, type InvariantConfig } from '../../../engine/src/config.js'

// @ts-ignore
import type { Context, MiddlewareHandler, Next } from 'hono'

interface ExceptionRule {
    path?: string | RegExp
    method?: string | string[]
    ip?: string | RegExp
    surface?: Surface
    key?: string | RegExp
    class?: string | string[]
}

interface MiddlewareOptions {
    mode?: 'monitor' | 'sanitize' | 'defend' | 'lockdown'
    configPath?: string
    verbose?: boolean
    exceptionRules?: ExceptionRule[]
    onBlock?: (ctx: Context, match: DetectionEvent) => void
    onDetect?: (ctx: Context, match: DetectionEvent) => void
}

type Surface = 'query_param' | 'body_param' | 'header' | 'cookie' | 'path' | 'ip'

interface DetectionEvent {
    surface: Surface
    key: string
    value: string
    matches: InvariantMatch[]
}

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
    'x-invariant-protected': '1',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'cross-origin-resource-policy': 'same-origin',
}

async function loadConfig(configPath?: string, verbose = false): Promise<InvariantConfig> {
    if (typeof process === 'undefined' || typeof process.cwd !== 'function') {
        return DEFAULT_CONFIG
    }

    const resolvedPath = configPath ?? `${process.cwd()}/invariant.config.json`
    try {
        // @ts-ignore
        const fs = await import('node:fs')
        if (!fs.existsSync(resolvedPath)) {
            return DEFAULT_CONFIG
        }
        const raw = JSON.parse(fs.readFileSync(resolvedPath, 'utf8'))
        return validateConfig(raw)
    } catch (error) {
        if (verbose) {
            console.warn(`[invariant] Invalid config at ${resolvedPath}, using defaults`, error)
        }
        return DEFAULT_CONFIG
    }
}

function resolveMode(config: InvariantConfig, explicitMode?: MiddlewareOptions['mode']): NonNullable<MiddlewareOptions['mode']> {
    if (explicitMode) return explicitMode
    return config.mode === 'enforce' ? 'defend' : 'monitor'
}

function toStringValue(value: unknown): string {
    if (typeof value === 'string') return value
    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
        return String(value)
    }
    if (value == null) return ''
    try {
        return JSON.stringify(value)
    } catch {
        return String(value)
    }
}

function sanitizeString(value: string): string {
    return value
        .replace(/[\u0000-\u001F\u007F]/g, '')
        .replace(/(\.\.\/|\.\.\\)/g, '')
        .replace(/[<>"'`;]/g, '')
}

function collectInputs(
    value: unknown,
    prefix: string,
    surface: Surface,
    out: Array<{ surface: Surface; key: string; value: string }>,
): void {
    if (value == null) return

    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
            collectInputs(value[i], `${prefix}[${i}]`, surface, out)
        }
        return
    }

    if (typeof value === 'object') {
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
            const nextKey = prefix ? `${prefix}.${k}` : k
            collectInputs(v, nextKey, surface, out)
        }
        return
    }

    out.push({ surface, key: prefix, value: toStringValue(value) })
}

function toHeaders(input: Record<string, unknown>): Headers {
    const headers = new Headers()
    for (const [key, value] of Object.entries(input)) {
        if (Array.isArray(value)) {
            for (const item of value) {
                headers.append(key, toStringValue(item))
            }
        } else {
            headers.set(key, toStringValue(value))
        }
    }
    return headers
}

function toCookieRecord(cookieHeader: string): Record<string, unknown> {
    const cookieMap: Record<string, unknown> = {}
    if (!cookieHeader) return cookieMap

    for (const pair of cookieHeader.split(';')) {
        const idx = pair.indexOf('=')
        if (idx === -1) continue
        const name = pair.slice(0, idx).trim()
        const value = pair.slice(idx + 1).trim()
        if (!name) continue

        const existing = cookieMap[name]
        if (existing === undefined) {
            cookieMap[name] = value
            continue
        }
        if (Array.isArray(existing)) {
            existing.push(value)
            continue
        }
        cookieMap[name] = [existing as string, value]
    }

    return cookieMap
}

function applySecurityHeaders(ctx: Context): void {
    for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
        ctx.header(key, value)
    }
}

function contextForSurface(surface: Surface): string {
    switch (surface) {
        case 'body_param': return 'json'
        case 'path': return 'url'
        case 'query_param': return 'url'
        case 'header': return 'http'
        case 'cookie': return 'http'
        case 'ip': return 'url'
        default: return 'json'
    }
}

function matchesPattern(pattern: string | RegExp | undefined, value: string): boolean {
    if (pattern === undefined) return true
    return typeof pattern === 'string' ? pattern === value : pattern.test(value)
}

function matchesMethod(pattern: string | string[] | undefined, value: string): boolean {
    if (pattern === undefined) return true
    if (Array.isArray(pattern)) return pattern.some(method => method.toUpperCase() === value.toUpperCase())
    return pattern.toUpperCase() === value.toUpperCase()
}

function requestExceptionMatched(
    rules: ExceptionRule[] | undefined,
    method: string,
    path: string,
    ip: string,
): boolean {
    if (!rules || rules.length === 0) return false
    return rules.some(rule =>
        matchesMethod(rule.method, method)
        && matchesPattern(rule.path, path)
        && matchesPattern(rule.ip, ip)
    )
}

function detectionExceptionMatched(
    rules: ExceptionRule[] | undefined,
    detection: DetectionEvent,
): boolean {
    if (!rules || rules.length === 0) return false
    return rules.some((rule) => {
        if (rule.surface && rule.surface !== detection.surface) return false
        if (rule.key && !matchesPattern(rule.key, detection.key)) return false
        if (rule.class) {
            const expected = Array.isArray(rule.class) ? rule.class : [rule.class]
            if (!detection.matches.some(match => expected.includes(match.class))) {
                return false
            }
        }
        return true
    })
}

function shouldBlock(mode: NonNullable<MiddlewareOptions['mode']>, matches: InvariantMatch[]): boolean {
    if (matches.length === 0) return false
    if (mode === 'lockdown') return true

    const hasCritical = matches.some(match => match.severity === 'critical')
    const hasHigh = matches.some(match => match.severity === 'high')

    if (mode === 'sanitize') return hasCritical
    if (mode === 'defend') return hasCritical || hasHigh
    return false
}

function logDetections(verbose: boolean | undefined, ctx: Context, detections: DetectionEvent[]): void {
    if (!verbose || detections.length === 0) return
    console.warn(`[invariant] detected ${detections.length} signal(s) on ${ctx.req.method} ${new URL(ctx.req.url).pathname}`)
}

async function readBody(c: Context): Promise<unknown> {
    if ((c.req.method ?? 'GET').toUpperCase() === 'GET') return ''
    try {
        const text = await c.req.raw.clone().text()
        const normalized = modeSanitizeBody(text)
        if (!normalized) return ''

        const contentType = c.req.header('content-type') ?? ''
        if (contentType.includes('application/json')) {
            try {
                const parsed = JSON.parse(normalized)
                if (parsed !== null && typeof parsed === 'object') {
                    return parsed
                }
                return normalized
            } catch {
                return normalized
            }
        }

        return normalized
    } catch {
        return ''
    }
}

function modeSanitizeBody(value: string): string {
    return value.trim()
}

function getClientIp(c: Context): string {
    const forwarded = c.req.header('x-forwarded-for')
    if (forwarded) return forwarded.split(',')[0]?.trim() ?? ''
    const realIp = c.req.header('x-real-ip')
    if (realIp) return realIp
    const cfIp = c.req.header('cf-connecting-ip')
    if (cfIp) return cfIp
    return ''
}

export function invariantHono(options: MiddlewareOptions = {}): MiddlewareHandler {
    const engine = new InvariantEngine()
    const configPromise = loadConfig(options.configPath, options.verbose)

    return async (c: Context, next: Next): Promise<Response | void> => {
        applySecurityHeaders(c)

        const config = await configPromise
        const mode = resolveMode(config, options.mode)
        const method = c.req.method ?? 'GET'
        const path = new URL(c.req.url).pathname
        const ip = getClientIp(c)

        if (requestExceptionMatched(options.exceptionRules, method, path, ip)) {
            await next()
            applySecurityHeaders(c)
            return
        }

        const detections: DetectionEvent[] = []
        const collected: Array<{ surface: Surface; key: string; value: string }> = []

        const url = new URL(c.req.url)
        const queryMap: Record<string, unknown> = {}
        for (const [key, value] of url.searchParams.entries()) {
            const existing = queryMap[key]
            if (existing === undefined) {
                queryMap[key] = value
            } else if (Array.isArray(existing)) {
                existing.push(value)
            } else {
                queryMap[key] = [existing as string, value]
            }
        }

        const rawBody = await readBody(c)
        const body = mode === 'sanitize' ? sanitizeUnknown(rawBody) : rawBody

        collectInputs(queryMap, '', 'query_param', collected)
        collectInputs(body, '', 'body_param', collected)
        collectInputs(c.req.raw.headers ? Object.fromEntries(c.req.raw.headers.entries()) : {}, '', 'header', collected)
        collectInputs(toCookieRecord(c.req.header('cookie') ?? ''), '', 'cookie', collected)
        collectInputs(path, 'path', 'path', collected)
        collectInputs(ip, 'ip', 'ip', collected)

        for (const input of collected) {
            const deep = engine.detectDeep(input.value, [], contextForSurface(input.surface))
            if (deep.matches.length === 0) continue

            const detection: DetectionEvent = {
                surface: input.surface,
                key: input.key,
                value: input.value,
                matches: deep.matches,
            }

            if (detectionExceptionMatched(options.exceptionRules, detection)) {
                continue
            }

            detections.push(detection)
            options.onDetect?.(c, detection)
        }

        const headerMatches = engine.detectHeaderInvariants(toHeaders(Object.fromEntries(c.req.raw.headers.entries())))
        if (headerMatches.length > 0) {
            const headerDetection: DetectionEvent = {
                surface: 'header',
                key: 'headers',
                value: '[header-invariants]',
                matches: headerMatches,
            }

            if (!detectionExceptionMatched(options.exceptionRules, headerDetection)) {
                detections.push(headerDetection)
                options.onDetect?.(c, headerDetection)
            }
        }

        logDetections(options.verbose, c, detections)

        const allMatches = detections.flatMap(detection => detection.matches)
        if (shouldBlock(mode, allMatches)) {
            options.onBlock?.(c, detections[0]!)
            applySecurityHeaders(c)
            return c.json({ error: 'blocked' }, 403)
        }

        await next()
        applySecurityHeaders(c)
    }
}

function sanitizeUnknown(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(sanitizeUnknown)
    if (!value || typeof value !== 'object') {
        return typeof value === 'string' ? sanitizeString(value) : value
    }

    const sanitized: Record<string, unknown> = {}
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
        if (key === '__proto__' || key === 'prototype' || key === 'constructor') continue
        sanitized[key] = sanitizeUnknown(entry)
    }
    return sanitized
}
