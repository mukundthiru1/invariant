import type { DynamicRule, SensorStateManager } from './sensor-state.js'
import { validateDynamicRules } from './rule-sync.js'

export interface RuleStreamStatus {
    active: boolean
    connected: boolean
    lastError: string | null
}

export interface RuleStreamOptions {
    fetchImpl?: typeof fetch
    reconnectDelayMs?: number
    maxReconnectDelayMs?: number
    onConnect?: () => void
    onDisconnect?: () => void
}

const DEFAULT_RECONNECT_DELAY_MS = 1_000
const DEFAULT_MAX_RECONNECT_DELAY_MS = 30_000

type RuleState = Pick<SensorStateManager, 'updateRules' | 'rules'>

const streamState: RuleStreamStatus = {
    active: false,
    connected: false,
    lastError: null,
}

let stopController: AbortController | null = null
let streamTask: Promise<void> | null = null

function getAuthHeaders(apiKey?: string): Record<string, string> {
    const headers: Record<string, string> = {
        'Accept': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'User-Agent': 'INVARIANT-Sensor/5.0',
    }
    if (apiKey) {
        headers['Authorization'] = `Bearer ${apiKey}`
    }
    return headers
}

function buildRuleVersion(rules: DynamicRule[]): string {
    const base = rules
        .map(rule => `${rule.ruleId}:${rule.baseConfidence}:${rule.enabled ? 1 : 0}`)
        .sort()
        .join('|')
    let hash = 2166136261
    for (let i = 0; i < base.length; i++) {
        hash ^= base.charCodeAt(i)
        hash = Math.imul(hash, 16777619)
    }
    return `stream-${(hash >>> 0).toString(36)}`
}

function maybeApplyRuleUpdate(state: RuleState, streamUrl: string, payload: unknown): boolean {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false

    const message = payload as { type?: string; rules?: DynamicRule[]; version?: string }
    if (message.type !== 'rule_update' || !Array.isArray(message.rules)) return false

    const validRules = validateDynamicRules(message.rules)
    if (validRules.length === 0 && message.rules.length > 0) return false

    const version = typeof message.version === 'string' && message.version.length > 0
        ? message.version
        : buildRuleVersion(validRules)

    state.updateRules(validRules, version, streamUrl)
    return true
}

export async function consumeRuleEventStream(
    response: Response,
    state: RuleState,
    streamUrl: string,
): Promise<void> {
    if (!response.body) throw new Error('stream body missing')

    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    let eventData = ''

    while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() ?? ''

        for (const line of lines) {
            const normalized = line.endsWith('\r') ? line.slice(0, -1) : line

            if (normalized === '') {
                if (eventData.length > 0) {
                    try {
                        const parsed = JSON.parse(eventData)
                        maybeApplyRuleUpdate(state, streamUrl, parsed)
                    } catch {
                        // Ignore malformed SSE payloads and keep stream alive.
                    }
                    eventData = ''
                }
                continue
            }

            if (normalized.startsWith(':')) continue
            if (normalized.startsWith('data:')) {
                eventData += normalized.slice(5).trimStart()
            }
        }
    }
}

async function runRuleStreamLoop(
    state: RuleState,
    intelBaseUrl: string,
    apiKey: string | undefined,
    options: RuleStreamOptions,
): Promise<void> {
    const fetchImpl = options.fetchImpl ?? fetch
    let reconnectDelay = options.reconnectDelayMs ?? DEFAULT_RECONNECT_DELAY_MS
    const maxReconnectDelay = options.maxReconnectDelayMs ?? DEFAULT_MAX_RECONNECT_DELAY_MS
    const streamUrl = `${intelBaseUrl.replace(/\/$/, '')}/v1/stream`

    while (streamState.active && stopController && !stopController.signal.aborted) {
        try {
            const response = await fetchImpl(streamUrl, {
                method: 'GET',
                headers: getAuthHeaders(apiKey),
                signal: stopController.signal,
            })

            if (!response.ok) {
                throw new Error(`rule stream connect failed: ${response.status}`)
            }

            streamState.connected = true
            streamState.lastError = null
            reconnectDelay = options.reconnectDelayMs ?? DEFAULT_RECONNECT_DELAY_MS
            options.onConnect?.()

            await consumeRuleEventStream(response, state, streamUrl)
            if (stopController.signal.aborted) break
            throw new Error('rule stream disconnected')
        } catch (err) {
            streamState.connected = false
            streamState.lastError = err instanceof Error ? err.message : String(err)
            options.onDisconnect?.()

            if (!streamState.active || !stopController || stopController.signal.aborted) {
                break
            }

            await new Promise(resolve => setTimeout(resolve, reconnectDelay))
            reconnectDelay = Math.min(Math.floor(reconnectDelay * 1.5), maxReconnectDelay)
        }
    }

    streamState.connected = false
}

export function startRuleStream(
    state: RuleState,
    intelBaseUrl: string,
    apiKey?: string,
    options: RuleStreamOptions = {},
): Promise<void> | null {
    if (!intelBaseUrl) return null
    if (streamTask) return streamTask

    stopController = new AbortController()
    streamState.active = true
    streamState.connected = false
    streamState.lastError = null

    streamTask = runRuleStreamLoop(state, intelBaseUrl, apiKey, options)
        .catch(err => {
            streamState.lastError = err instanceof Error ? err.message : String(err)
        })
        .finally(() => {
            streamState.active = false
            streamState.connected = false
            streamTask = null
            stopController = null
        })

    return streamTask
}

export function getRuleStreamStatus(): RuleStreamStatus {
    return { ...streamState }
}

export function stopRuleStream(): void {
    streamState.active = false
    streamState.connected = false
    stopController?.abort()
}
