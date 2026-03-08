/**
 * @santh/agent — Request-session context for within-request RASP signal aggregation
 */

import * as asyncHooks from 'node:async_hooks'

export type RaspSurface = 'sql' | 'http' | 'exec' | 'fs' | 'deser'

export interface RaspEvent {
    surface: RaspSurface
    context: string
    matches: string[]
    confidence: number
    blocked: boolean
    timestamp: number
}

export interface CompoundDetection {
    isCompound: boolean
    surfaces: RaspSurface[]
    compoundConfidence: number
    reason: string
    events: RaspEvent[]
}

export interface RequestSessionData {
    events: RaspEvent[]
    sourceHash: string | null
    method: string | null
    path: string | null
    startedAt: number
}

interface AsyncLocalStorageLike<T> {
    run<R>(store: T, callback: () => R): R
    enterWith(store: T): void
    getStore(): T | undefined
}

type AsyncLocalStorageCtor = {
    AsyncLocalStorage?: new <T>() => AsyncLocalStorageLike<T>
}

const ALS = (asyncHooks as AsyncLocalStorageCtor).AsyncLocalStorage
const sessionStorage = ALS ? new ALS<RequestSessionData>() : null

export function startRequestSession(meta: { sourceHash?: string, method?: string, path?: string }): void {
    if (!sessionStorage) return

    sessionStorage.enterWith({
        events: [],
        sourceHash: meta.sourceHash ?? null,
        method: meta.method ?? null,
        path: meta.path ?? null,
        startedAt: Date.now(),
    })
}

export function getCurrentSession(): RequestSessionData | undefined {
    return sessionStorage?.getStore()
}

export function recordRaspEvent(
    surface: RaspSurface,
    context: string,
    matches: string[],
    confidence: number,
    blocked: boolean,
): void {
    const session = sessionStorage?.getStore()
    if (!session) return

    session.events.push({
        surface,
        context,
        matches,
        confidence,
        blocked,
        timestamp: Date.now(),
    })
}

export function finalizeRequestSession(): CompoundDetection | null {
    const session = sessionStorage?.getStore()
    if (!session || session.events.length === 0) return null

    const attackingEvents = session.events.filter(e => e.matches.length > 0 || e.blocked)
    if (attackingEvents.length === 0) return null

    const surfaces = [...new Set(attackingEvents.map(e => e.surface))]

    if (surfaces.length < 2) return null

    const compoundConfidence = surfaces.length >= 3 ? 0.99 : 0.95

    return {
        isCompound: true,
        surfaces,
        compoundConfidence,
        reason: `multi_surface_attack:${surfaces.join('+')}`,
        events: attackingEvents,
    }
}

export function runWithSession<T>(
    meta: { sourceHash?: string, method?: string, path?: string },
    fn: () => T,
): T {
    const data: RequestSessionData = {
        events: [],
        sourceHash: meta.sourceHash ?? null,
        method: meta.method ?? null,
        path: meta.path ?? null,
        startedAt: Date.now(),
    }

    if (!sessionStorage) return fn()
    return sessionStorage.run(data, fn)
}
