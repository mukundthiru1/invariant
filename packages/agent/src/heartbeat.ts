import { createHash, createHmac } from 'node:crypto'
import { execSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'

export interface HeartbeatConfig {
    intervalMs: number
    endpoint: string
    sensorId: string
    secret: string
}

export interface HeartbeatHandle {
    stop: () => void
}

export const DEFAULT_HEARTBEAT_CONFIG: HeartbeatConfig = {
    intervalMs: 30000,
    endpoint: '',
    sensorId: '',
    secret: '',
}

type HeartbeatStatus = 'alive' | 'dying' | 'tampered'

interface HeartbeatPayload {
    sensorId: string
    timestamp: string
    pid: number
    uptime: number
    nodeVersion: string
    status: HeartbeatStatus
    reason?: string
}

const LAST_BREATH_REGISTERED = Symbol.for('santh.rasp.lastBreath.registered')

const __filename = fileURLToPath(import.meta.url)

function normalizeEndpoint(endpoint: string): string {
    return endpoint.trim().replace(/\/+$/, '')
}

function heartbeatUrl(endpoint: string): string {
    return `${normalizeEndpoint(endpoint)}/v1/heartbeat`
}

function signPayload(payload: HeartbeatPayload, secret: string): string {
    return createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex')
}

function buildPayload(config: HeartbeatConfig, status: HeartbeatStatus, reason?: string): HeartbeatPayload {
    const payload: HeartbeatPayload = {
        sensorId: config.sensorId,
        timestamp: new Date().toISOString(),
        pid: process.pid,
        uptime: process.uptime(),
        nodeVersion: process.version,
        status,
    }
    if (reason) payload.reason = reason
    return payload
}

async function postHeartbeat(config: HeartbeatConfig, payload: HeartbeatPayload): Promise<void> {
    if (!config.endpoint) return
    const signature = signPayload(payload, config.secret)
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 5000)
    try {
        const response = await fetch(heartbeatUrl(config.endpoint), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-santh-signature': signature,
            },
            body: JSON.stringify(payload),
            signal: controller.signal,
        })
        if (!response.ok) {
            throw new Error(`Heartbeat rejected (${response.status})`)
        }
    } finally {
        clearTimeout(timeout)
    }
}

async function sendWithRetries(config: HeartbeatConfig, payload: HeartbeatPayload): Promise<void> {
    const maxRetries = 3
    let backoffMs = 500
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            await postHeartbeat(config, payload)
            return
        } catch (error) {
            if (attempt === maxRetries) {
                throw error
            }
            await new Promise<void>((resolve) => setTimeout(resolve, backoffMs))
            backoffMs *= 2
        }
    }
}

function postSyncWithCurl(config: HeartbeatConfig, payload: HeartbeatPayload): void {
    if (!config.endpoint) {
        console.log('[santh-rasp] Last breath alert sent')
        return
    }

    const url = heartbeatUrl(config.endpoint)
    const body = JSON.stringify(payload)
    const signature = signPayload(payload, config.secret)
    const escapedBody = body.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    const escapedSignature = signature.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    const escapedUrl = url.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    const cmd = `curl -sS -X POST --max-time 5 -H "Content-Type: application/json" -H "x-santh-signature: ${escapedSignature}" -d "${escapedBody}" "${escapedUrl}" >/dev/null`
    try {
        execSync(cmd, { stdio: 'ignore' })
        console.log('[santh-rasp] Last breath alert sent')
    } catch (error) {
        console.error('[santh-rasp] Last breath delivery failed', error)
    }
}

function installHashFilePath(): string {
    return join(homedir(), '.santh', 'agent.sha256')
}

function hashCurrentAgentFile(): string {
    const fileBytes = readFileSync(__filename)
    return createHash('sha256').update(fileBytes).digest('hex')
}

export function startHeartbeat(config: HeartbeatConfig): HeartbeatHandle {
    let stopped = false
    const intervalMs = Math.max(1000, config.intervalMs)

    const tick = (): void => {
        if (stopped) return
        const payload = buildPayload(config, 'alive')
        void sendWithRetries(config, payload).catch((error) => {
            console.error('[santh-rasp] Heartbeat failed', error)
        })
    }

    tick()
    const timer = setInterval(tick, intervalMs)
    if (timer.unref) timer.unref()

    return {
        stop: () => {
            stopped = true
            clearInterval(timer)
        },
    }
}

export function registerLastBreath(config: HeartbeatConfig): void {
    const processWithFlag = process as NodeJS.Process & Record<symbol, boolean | undefined>
    if (processWithFlag[LAST_BREATH_REGISTERED]) return
    let lastBreathSent = false

    const sendLastBreath = (reason: string): void => {
        if (lastBreathSent) return
        lastBreathSent = true
        const payload = buildPayload(config, 'dying', reason)
        postSyncWithCurl(config, payload)
    }

    process.on('SIGTERM', () => {
        sendLastBreath('SIGTERM')
        process.exit(143)
    })
    process.on('SIGINT', () => {
        sendLastBreath('SIGINT')
        process.exit(130)
    })
    process.on('beforeExit', (code) => sendLastBreath(`beforeExit:${code}`))
    process.on('uncaughtException', (error) => {
        sendLastBreath(`uncaughtException:${error.message}`)
        process.exit(1)
    })
    processWithFlag[LAST_BREATH_REGISTERED] = true
}

export function detectTamper(): boolean {
    const hashPath = installHashFilePath()
    const dir = dirname(hashPath)
    const currentHash = hashCurrentAgentFile()

    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true })
    }

    if (!existsSync(hashPath)) {
        writeFileSync(hashPath, currentHash, 'utf8')
        return false
    }

    const expectedHash = readFileSync(hashPath, 'utf8').trim()
    if (expectedHash === currentHash) {
        return false
    }

    console.error('[santh-rasp] Tamper detected: agent hash mismatch')
    const endpoint = process.env.SANTH_SENSOR_URL?.trim() ?? ''
    if (endpoint) {
        const config: HeartbeatConfig = {
            intervalMs: DEFAULT_HEARTBEAT_CONFIG.intervalMs,
            endpoint,
            sensorId: process.env.SANTH_SENSOR_ID?.trim() || `${process.pid}`,
            secret: process.env.SANTH_SENSOR_SECRET ?? '',
        }
        const payload = buildPayload(config, 'tampered', 'agent_hash_mismatch')
        postSyncWithCurl(config, payload)
    }
    return true
}
