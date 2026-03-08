import { InvariantEngine, type InvariantMatch } from '../../../engine/src/invariant-engine.js'
import { validateConfig, DEFAULT_CONFIG, type InvariantConfig } from '../../../engine/src/config.js'

// @ts-ignore
import type { FastifyReply, FastifyRequest, onRequestHookHandler, preHandlerHookHandler } from 'fastify'

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
    onBlock?: (req: FastifyRequest, match: DetectionEvent) => void
    onDetect?: (req: FastifyRequest, match: DetectionEvent) => void
}

type Surface = 'query_param' | 'body_param' | 'header' | 'cookie' | 'path' | 'ip'

interface DetectionEvent {
    surface: Surface
    key: string
    value: string
    matches: InvariantMatch[]
}

interface RequestState {
    collected: Array<{ surface: Surface; key: string; value: string }>
    detections: DetectionEvent[]
}

interface FastifyInvariantHooks {
    onRequest: onRequestHookHandler
    preHandler: preHandlerHookHandler
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

function applySecurityHeaders(reply: FastifyReply): void {
    for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
        reply.header(key, value)
    }
}

function toClientIp(req: FastifyRequest): string {
    const direct = (req as { ip?: unknown }).ip
    if (typeof direct === 'string' && direct) return direct
    const forwarded = req.headers['x-forwarded-for']
    if (typeof forwarded === 'string') return forwarded.split(',')[0]?.trim() ?? ''
    return ''
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

function logDetections(verbose: boolean | undefined, req: FastifyRequest, detections: DetectionEvent[]): void {
    if (!verbose || detections.length === 0) return
    const path = (req as { routerPath?: string }).routerPath ?? req.url
    console.warn(`[invariant] detected ${detections.length} signal(s) on ${req.method} ${path}`)
}

export function invariantFastify(options: MiddlewareOptions = {}): FastifyInvariantHooks {
    const engine = new InvariantEngine()
    const configPromise = loadConfig(options.configPath, options.verbose)
    const stateKey = Symbol('invariant-fastify-state')

    const onRequest: onRequestHookHandler = async (req: FastifyRequest, reply: FastifyReply) => {
        try {
            applySecurityHeaders(reply)

            const method = req.method ?? 'GET'
            const path = (req as { routerPath?: string }).routerPath ?? req.url ?? ''
            const ip = toClientIp(req)

            const state: RequestState = { collected: [], detections: [] }
            collectInputs(req.query ?? {}, '', 'query_param', state.collected)
            collectInputs(req.params ?? {}, '', 'path', state.collected)
            collectInputs(req.headers ?? {}, '', 'header', state.collected)
            collectInputs(toCookieRecord(toStringValue(req.headers.cookie ?? '')), '', 'cookie', state.collected)
            collectInputs(path, 'path', 'path', state.collected)
            collectInputs(ip, 'ip', 'ip', state.collected)

            ;(req as Record<symbol, RequestState>)[stateKey] = state

            if (requestExceptionMatched(options.exceptionRules, method, path, ip)) {
                ;(req as Record<symbol, RequestState>)[stateKey]!.collected = []
            }
        } catch (error) {
            if (options.verbose) {
                console.warn('[invariant] fastify onRequest fail-open due to internal error', error)
            }
        }
    }

    const preHandler: preHandlerHookHandler = async (req: FastifyRequest, reply: FastifyReply) => {
        try {
            applySecurityHeaders(reply)

            const state = (req as Record<symbol, RequestState | undefined>)[stateKey]
            if (!state) return

            const config = await configPromise
            const mode = resolveMode(config, options.mode)

            if (mode === 'sanitize') {
                if (req.query && typeof req.query === 'object') {
                    ;(req as { query: unknown }).query = sanitizeUnknown(req.query)
                }
                if (req.body && typeof req.body === 'object') {
                    ;(req as { body: unknown }).body = sanitizeUnknown(req.body)
                }
                if (req.params && typeof req.params === 'object') {
                    ;(req as { params: unknown }).params = sanitizeUnknown(req.params)
                }
            }

            collectInputs(req.body ?? {}, '', 'body_param', state.collected)

            for (const input of state.collected) {
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

                state.detections.push(detection)
                options.onDetect?.(req, detection)
            }

            const headerMatches = engine.detectHeaderInvariants(toHeaders(req.headers as Record<string, unknown>))
            if (headerMatches.length > 0) {
                const headerDetection: DetectionEvent = {
                    surface: 'header',
                    key: 'headers',
                    value: '[header-invariants]',
                    matches: headerMatches,
                }

                if (!detectionExceptionMatched(options.exceptionRules, headerDetection)) {
                    state.detections.push(headerDetection)
                    options.onDetect?.(req, headerDetection)
                }
            }

            logDetections(options.verbose, req, state.detections)

            const allMatches = state.detections.flatMap(detection => detection.matches)
            if (shouldBlock(mode, allMatches)) {
                options.onBlock?.(req, state.detections[0]!)
                reply.code(403).send({ error: 'blocked' })
            }
        } catch (error) {
            if (options.verbose) {
                console.warn('[invariant] fastify preHandler fail-open due to internal error', error)
            }
        }
    }

    return { onRequest, preHandler }
}
