import { InvariantEngine, type InvariantMatch } from '../../../engine/src/invariant-engine.js'
import { validateConfig, DEFAULT_CONFIG, type InvariantConfig } from '../../../engine/src/config.js'
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

interface MiddlewareOptions {
    mode?: 'monitor' | 'enforce'
    configPath?: string
    verbose?: boolean
    onBlock?: (req: any, match: any) => void
    onDetect?: (req: any, match: any) => void
}

type Surface = 'query_param' | 'body_param' | 'header' | 'cookie' | 'path'

interface DetectionEvent {
    surface: Surface
    key: string
    value: string
    matches: InvariantMatch[]
}

function loadConfig(configPath?: string, verbose = false): InvariantConfig {
    const resolvedPath = configPath ?? join(process.cwd(), 'invariant.config.json')

    if (!existsSync(resolvedPath)) {
        return DEFAULT_CONFIG
    }

    try {
        const raw = JSON.parse(readFileSync(resolvedPath, 'utf8'))
        return validateConfig(raw)
    } catch (error) {
        if (verbose) {
            console.warn(`[invariant] Invalid config at ${resolvedPath}, using defaults`, error)
        }
        return DEFAULT_CONFIG
    }
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

function collectInputs(value: unknown, prefix: string, surface: Surface, out: Array<{ surface: Surface; key: string; value: string }>): void {
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

export function invariantMiddleware(options: MiddlewareOptions = {}) {
    const config = loadConfig(options.configPath, options.verbose)
    const mode: 'monitor' | 'enforce' = options.mode ?? (config.mode === 'enforce' ? 'enforce' : 'monitor')
    const engine = new InvariantEngine()

    return (req: any, res: any, next: any) => {
        const detections: DetectionEvent[] = []

        const collected: Array<{ surface: Surface; key: string; value: string }> = []
        collectInputs(req?.query ?? {}, '', 'query_param', collected)
        collectInputs(req?.body ?? {}, '', 'body_param', collected)
        collectInputs(req?.params ?? {}, '', 'path', collected)
        collectInputs(req?.headers ?? {}, '', 'header', collected)
        collectInputs(req?.cookies ?? {}, '', 'cookie', collected)
        collectInputs(req?.path ?? '', 'path', 'path', collected)

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
                options.onDetect?.(req, detection)
            }
        }

        const headerMatches = engine.detectHeaderInvariants(toHeaders(req?.headers ?? {}))
        if (headerMatches.length > 0) {
            const detection: DetectionEvent = {
                surface: 'header',
                key: 'headers',
                value: '[header-invariants]',
                matches: headerMatches,
            }
            detections.push(detection)
            options.onDetect?.(req, detection)
        }

        const allMatches = detections.flatMap(d => d.matches)
        const shouldBlock = allMatches.length > 0 && engine.shouldBlock(allMatches)

        if (shouldBlock && mode === 'enforce') {
            options.onBlock?.(req, detections[0])
            return res.status(403).json({ error: 'blocked' })
        }

        return next()
    }
}
