const fs = require('fs')

let indexTs = fs.readFileSync('packages/edge-sensor/src/index.ts', 'utf8')

// 1. Replay Attacks
if (!indexTs.includes('seenRequestIds')) {
    indexTs = indexTs.replace(
        'let rulesInitialized = false',
        `let rulesInitialized = false\nconst seenRequestIds = new Set<string>()\n`
    )

    indexTs = indexTs.replace(
        'async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {',
        `async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {\n        const requestId = request.headers.get('cf-ray') || request.headers.get('x-request-id')\n        if (requestId) {\n            if (seenRequestIds.has(requestId)) {\n                return new Response('Replay detected', { status: 409 })\n            }\n            seenRequestIds.add(requestId)\n            if (seenRequestIds.size > 10000) seenRequestIds.delete(seenRequestIds.keys().next().value as string)\n        }`
    )
}

// 2. Sensor Poisoning (fail closed on exception)
indexTs = indexTs.replace(
    /try \{ return rule\.check\(reqCtx\) \}\s*catch \{ return false \}/g,
    `try { return rule.check(reqCtx) } catch { return true }`
)

indexTs = indexTs.replace(
    /try \{\s*if \(rule\.check\(bodyCtx\)\) \{\s*signatureMatches\.push\(rule\)\s*\}\s*\} catch \{ \/\* body signature failure is non-fatal \*\/ \}/g,
    `try { if (rule.check(bodyCtx)) signatureMatches.push(rule) } catch { signatureMatches.push(rule) }`
)


// 3. Timing Side-Channels
indexTs = indexTs.replace(
    /const jitterMs = 5 \+ Math\.floor\(Math\.random\(\) \* 45\)/g,
    `const jitterMs = 50 + Math.floor(Math.random() * 150)`
)

// 4. KV Race Condition (posture snapshot TOCTOU)
indexTs = indexTs.replace(
    /const previousPosture = await env\.SENSOR_STATE\.get\('posture_snapshot', 'json'\) as import\('\.\/modules\/drift-detector\.js'\)\.PostureSnapshot \| null/,
    `// Moved down to reduce TOCTOU window`
)

indexTs = indexTs.replace(
    /if \(previousPosture && signalBuffer\) \{/,
    `const previousPosture = await env.SENSOR_STATE.get('posture_snapshot', 'json') as import('./modules/drift-detector.js').PostureSnapshot | null;\n                if (previousPosture && signalBuffer) {`
)

// 5. WebSocket Security (binary frames & JSON bypass)
indexTs = indexTs.replace(
    /if \(typeof event\.data === 'string'\) \{\s*const matches = analyzeWebSocketFrameBody\(event\.data, engine\)\s*if \(matches\.length > 0\) \{\s*server\.close\(1008, 'Policy Violation'\)\s*ws\.close\(1008, 'Policy Violation'\)\s*return\s*\}\s*\}/,
    `if (typeof event.data === 'string' || event.data instanceof ArrayBuffer) {
                        const matches = analyzeWebSocketFrameBody(event.data, engine)
                        if (matches.length > 0) {
                            server.close(1008, 'Policy Violation')
                            ws.close(1008, 'Policy Violation')
                            return
                        }
                    }`
)

fs.writeFileSync('packages/edge-sensor/src/index.ts', indexTs)

let wsTs = fs.readFileSync('packages/edge-sensor/src/layers/ws-interceptor.ts', 'utf8')
wsTs = wsTs.replace(
    /try \{\s*parsed = JSON\.parse\(data\)\s*\} catch \{\s*return \{\s*parsedJson: false,\s*matches: \[\],\s*\}\s*\}/,
    `try {
        parsed = JSON.parse(data)
    } catch {
        return {
            parsedJson: false,
            matches: engine.detect(data, []),
        }
    }`
)

wsTs = wsTs.replace(
    /export function analyzeWebSocketFrameBody\(body: string, engine: InvariantEngine\): InvariantMatch\[\] \{\s*return engine\.detect\(body, \[\]\)\s*\}/,
    `export function analyzeWebSocketFrameBody(body: string | ArrayBuffer, engine: InvariantEngine): InvariantMatch[] {
    if (typeof body !== 'string') {
        if (body.byteLength > 65536) return [{ class: 'ws_oversized_frame', confidence: 1.0 } as InvariantMatch]
        return []
    }
    if (body.length > 65536) return [{ class: 'ws_oversized_frame', confidence: 1.0 } as InvariantMatch]
    return engine.detect(body, [])
}`
)
fs.writeFileSync('packages/edge-sensor/src/layers/ws-interceptor.ts', wsTs)


let stateTs = fs.readFileSync('packages/edge-sensor/src/modules/sensor-state.ts', 'utf8')
const oldMergeStr = `if (this._model && this.requestsSinceLastPersist >= this._config.modelPersistInterval) {
            writes.push(
                this.safeWrite(KV_KEYS.model(this.sensorId), this._model, 86400 * 7)
                    .then(() => { written.push('model') })
                    .catch(e => { errors.push(\`model: \${e}\`) }),
            )
            this.requestsSinceLastPersist = 0
        }`

const newMergeStr = `if (this._model && this.requestsSinceLastPersist >= this._config.modelPersistInterval) {
            writes.push((async () => {
                try {
                    const raw = await this.kv.get(KV_KEYS.model(this.sensorId))
                    const existing = safeParse(raw) // TypeScript will infer type
                    if (existing && typeof existing === 'object' && 'endpoints' in existing) {
                        const ex = existing as PersistedModelState
                        this._model.totalRequests += ex.totalRequests
                        const mergedEndpoints = new Map<string, PersistedEndpoint>()
                        for (const ep of ex.endpoints) mergedEndpoints.set(ep.pattern, ep)
                        for (const ep of this._model.endpoints) {
                            const ext = mergedEndpoints.get(ep.pattern)
                            if (ext) {
                                ext.requestCount += ep.requestCount
                                ext.lastSeen = Math.max(ext.lastSeen, ep.lastSeen)
                                for (const [m, c] of Object.entries(ep.methods)) ext.methods[m] = (ext.methods[m] || 0) + c
                                for (const [a, c] of Object.entries(ep.auth)) ext.auth[a] = (ext.auth[a] || 0) + c
                                ext.sensitive = ext.sensitive || ep.sensitive
                            } else {
                                mergedEndpoints.set(ep.pattern, ep)
                            }
                        }
                        this._model.endpoints = Array.from(mergedEndpoints.values())
                    }
                    await this.safeWrite(KV_KEYS.model(this.sensorId), this._model, 86400 * 7)
                    written.push('model')
                } catch (e) {
                    errors.push(\`model: \${e}\`)
                }
            })())
            this.requestsSinceLastPersist = 0
        }`

stateTs = stateTs.replace(oldMergeStr, newMergeStr)
fs.writeFileSync('packages/edge-sensor/src/modules/sensor-state.ts', stateTs)
console.log("Done")
