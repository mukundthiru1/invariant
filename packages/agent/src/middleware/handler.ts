import { InvariantEngine, type InvariantMatch } from '../../../engine/src/invariant-engine.js'
import { validateConfig, DEFAULT_CONFIG, type InvariantConfig } from '../../../engine/src/config.js'

interface HandlerOptions {
    mode?: 'monitor' | 'enforce'
    configPath?: string
    verbose?: boolean
    onBlock?: (req: Request, match: unknown) => void
    onDetect?: (req: Request, match: unknown) => void
}

type Surface = 'query_param' | 'body_param' | 'header' | 'cookie' | 'path'

interface DetectionEvent {
    surface: Surface
    key: string
    value: string
    matches: InvariantMatch[]
}

type NextLikeHandler = (request: Request) => Response | Promise<Response>

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

function resolveMode(config: InvariantConfig, explicitMode?: 'monitor' | 'enforce'): 'monitor' | 'enforce' {
    return explicitMode ?? (config.mode === 'enforce' ? 'enforce' : 'monitor')
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

function toHeaderRecord(headers: Headers): Record<string, unknown> {
    const headerMap: Record<string, unknown> = {}
    for (const [key, value] of headers.entries()) {
        const existing = headerMap[key]
        if (existing === undefined) {
            headerMap[key] = value
            continue
        }
        if (Array.isArray(existing)) {
            existing.push(value)
            continue
        }
        headerMap[key] = [existing as string, value]
    }
    return headerMap
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

function appendMapValue(input: Record<string, unknown>, key: string, value: string): void {
    const existing = input[key]
    if (existing === undefined) {
        input[key] = value
        return
    }
    if (Array.isArray(existing)) {
        existing.push(value)
        return
    }
    input[key] = [existing as string, value]
}

async function readBodyIfPost(request: Request): Promise<unknown> {
    if (request.method.toUpperCase() !== 'POST') return ''
    try {
        const bodyText = await request.clone().text()
        const normalized = bodyText.trim()
        if (!normalized) return ''

        const contentType = request.headers.get('content-type') ?? ''
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

async function collectRequestInputs(request: Request): Promise<Array<{ surface: Surface; key: string; value: string }>> {
    const url = new URL(request.url, 'http://localhost')
    const collected: Array<{ surface: Surface; key: string; value: string }> = []

    const queryMap: Record<string, unknown> = {}
    for (const [key, value] of url.searchParams.entries()) {
        appendMapValue(queryMap, key, value)
    }
    collectInputs(queryMap, '', 'query_param', collected)

    collectInputs(await readBodyIfPost(request), '', 'body_param', collected)
    collectInputs(url.pathname, 'path', 'path', collected)

    collectInputs(toCookieRecord(request.headers.get('cookie') ?? ''), '', 'cookie', collected)
    collectInputs(toHeaderRecord(request.headers), '', 'header', collected)

    return collected
}

export function createInvariantHandler(options: HandlerOptions = {}) {
    const engine = new InvariantEngine()
    const configPromise = loadConfig(options.configPath, options.verbose)

    return async (request: Request, next: NextLikeHandler): Promise<Response> => {
        try {
            const config = await configPromise
            const mode: 'monitor' | 'enforce' = resolveMode(config, options.mode)
            const detections: DetectionEvent[] = []
            const collected = await collectRequestInputs(request)

            for (const input of collected) {
                const matches = engine.detect(input.value, [], input.surface)
                if (matches.length > 0) {
                    const detection: DetectionEvent = {
                        surface: input.surface,
                        key: input.key,
                        value: input.value,
                        matches,
                    }
                    detections.push(detection)
                    options.onDetect?.(request, detection)
                }
            }

            const headerMatches = engine.detectHeaderInvariants(request.headers)
            if (headerMatches.length > 0) {
                const detection: DetectionEvent = {
                    surface: 'header',
                    key: 'headers',
                    value: '[header-invariants]',
                    matches: headerMatches,
                }
                detections.push(detection)
                options.onDetect?.(request, detection)
            }

            const allMatches = detections.flatMap(d => d.matches)
            const shouldBlock = allMatches.length > 0 && engine.shouldBlock(allMatches)

            if (shouldBlock && mode === 'enforce') {
                options.onBlock?.(request, detections[0]!)
                return Response.json({ error: 'blocked' }, { status: 403 })
            }

            return next(request)
        } catch (error) {
            if (options.verbose) {
                console.warn('[invariant] generic handler fail-open due to internal error', error)
            }
            return next(request)
        }
    }
}
