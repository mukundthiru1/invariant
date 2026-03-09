/**
 * @santh/agent
 *
 * Backend defense agent for INVARIANT.
 * RASP + dependency scanning + configuration auditing.
 *
 * Usage:
 *   import { InvariantAgent } from '@santh/agent'
 *
 *   const agent = new InvariantAgent({
 *       projectDir: process.cwd(),
 *       mode: 'observe',  // Start in observe mode
 *   })
 *
 *   await agent.start()
 *
 *   // Or with Express:
 *   import { invariantMiddleware } from '@santh/agent/middleware/express'
 *   app.use(invariantMiddleware({ mode: 'observe' }))
 */

import { InvariantDB, type DefenseMode } from './db.js'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import { createHash } from 'node:crypto'
import { scanDependencies, type ScanResult } from './scanner/deps.js'
import { auditConfiguration } from './scanner/config.js'
import { type SqlRaspConfig, wrapPgModule, wrapMysqlModule } from './rasp/sql.js'
import { type FsRaspConfig, wrapFsOperation } from './rasp/fs.js'
import { type HttpRaspConfig, wrapFetch, wrapNodeHttpGet, wrapNodeHttpRequest } from './rasp/http.js'
import { type ExecRaspConfig, installVmRuntimeHooks, uninstallVmRuntimeHooks, hookIntegrityCheck, wrapExec, wrapExecFile, wrapFork } from './rasp/exec.js'
import { type DeserRaspConfig, wrapJsonParse } from './rasp/deser.js'
import { type WebSocketRaspConfig, wrapWebSocketSend } from './rasp/websocket.js'
import { type GrpcRaspConfig, wrapGrpcClient } from './rasp/grpc.js'
import { AutonomousDefenseController, type DefenseDecision } from './autonomous-defense.js'
import { AdaptiveCalibrator, type CalibrationReport } from './calibration.js'
import { RuntimeHealthMonitor, type RuntimeHealthSnapshot } from './runtime.js'
import { evaluateAgentLaws, type AgentLawReport } from './laws.js'
import { flushSignals, queueSignal } from './intel-feedback.js'
import { recordRaspEvent } from './rasp/request-session.js'
import { DEFAULT_HEARTBEAT_CONFIG, type HeartbeatConfig, type HeartbeatHandle, detectTamper, registerLastBreath, startHeartbeat } from './heartbeat.js'

// ── Types ────────────────────────────────────────────────────────

export interface AgentConfig {
    /** Path to the project root */
    projectDir?: string
    /** Path to the SQLite database file */
    dbPath?: string
    /** Initial defense mode */
    mode?: DefenseMode
    /** Run dependency scan on startup */
    scanOnStart?: boolean
    /** Run config audit on startup */
    auditOnStart?: boolean
    /** Daily rescan interval (hours, 0 to disable) */
    rescanInterval?: number
    /** Verbose logging */
    verbose?: boolean
    /** Automatically configure built-in runtime hooks (fetch/fs/exec/JSON.parse). */
    autoConfigure?: boolean
    /** Capture internal runtime errors and keep the agent fail-open. */
    captureRuntimeExceptions?: boolean
    /** Enable runtime health snapshots and wrapped integration tracking. */
    healthMonitoring?: boolean
    /** Called on internal agent errors (never throws back to app). */
    onInternalError?: (error: unknown, context: string) => void
}

export interface AgentStatus {
    mode: DefenseMode
    uptime: number
    findings: { total: number; critical: number; high: number; open: number }
    signals: { total: number; blocked: number }
    lastScan: string | null
}

export type { AgentLawReport }

export class AgentPublicError extends Error {
    readonly code: string

    constructor(code: string, message: string) {
        super(message)
        this.name = 'AgentPublicError'
        this.code = code
    }
}

// ── Agent ────────────────────────────────────────────────────────

export class InvariantAgent {
    private db: InvariantDB
    private config: Required<AgentConfig>
    private startTime: number
    private scanTimer: ReturnType<typeof setInterval> | null = null
    private started = false
    private defenseController: AutonomousDefenseController
    private calibrator: AdaptiveCalibrator
    private healthMonitor: RuntimeHealthMonitor
    private wrapped = new Set<string>()
    private processErrorHandlersInstalled = false
    private hookTamperTimer: ReturnType<typeof setInterval> | null = null
    private hookTamperReported = new Set<string>()
    private heartbeatHandle: HeartbeatHandle | null = null
    private lastBreathRegistered = false
    private lawReport: AgentLawReport = { stage: 'init', results: [], violations: [] }

    constructor(config: AgentConfig = {}) {
        const projectDir = config.projectDir ?? process.cwd()
        const dbPath = config.dbPath ?? join(projectDir, 'invariant.db')

        this.config = {
            projectDir,
            dbPath,
            mode: config.mode ?? 'observe',
            scanOnStart: config.scanOnStart ?? true,
            auditOnStart: config.auditOnStart ?? true,
            rescanInterval: config.rescanInterval ?? 24,
            verbose: config.verbose ?? false,
            autoConfigure: config.autoConfigure ?? true,
            captureRuntimeExceptions: config.captureRuntimeExceptions ?? true,
            healthMonitoring: config.healthMonitoring ?? true,
            onInternalError: config.onInternalError ?? (() => {}),
        }
        this.db = new InvariantDB(this.config.dbPath)
        this.startTime = Date.now()
        this.defenseController = new AutonomousDefenseController(this.config.mode, this.db)
        this.calibrator = new AdaptiveCalibrator(this.db)
        this.healthMonitor = new RuntimeHealthMonitor(this.db, this.config.verbose)

        // Store config
        this.db.setConfig('mode', this.config.mode)
        this.db.setConfig('project_dir', this.config.projectDir)
    }

    async start(): Promise<void> {
        try {
            if (this.started) return
            this.started = true

            this.log('INVARIANT agent starting...')
            this.log(`Mode: ${this.config.mode}`)
            this.log(`Project: ${this.config.projectDir}`)
            this.installHeartbeatGuards()

            if (this.config.captureRuntimeExceptions) {
                this.installProcessErrorHandlers()
            }

            if (this.config.autoConfigure) {
                await this.autoConfigureRuntime()
            }

            // Run initial scans
            if (this.config.auditOnStart) {
                this.log('Running configuration audit...')
                const audit = auditConfiguration(this.config.projectDir, this.db)
                this.log(`Config audit: ${audit.total} checks, ${audit.findings} findings`)
            }

            if (this.config.scanOnStart) {
                this.log('Scanning dependencies...')
                try {
                    await scanDependencies(this.config.projectDir, this.db)
                    this.log('Dependency scan completed')
                } catch (error) {
                    this.handleInternalError('start.scanDependencies', error)
                    this.log('Dependency scan failed')
                }
            }

            // Set up periodic rescan
            if (this.config.rescanInterval > 0) {
                const intervalMs = this.config.rescanInterval * 60 * 60 * 1000
                this.scanTimer = setInterval(async () => {
                    try {
                        await scanDependencies(this.config.projectDir, this.db)
                        auditConfiguration(this.config.projectDir, this.db)
                    } catch (error) {
                        this.handleInternalError('start.periodicRescan', error)
                    }
                }, intervalMs)
                // Don't prevent process exit
                if (this.scanTimer.unref) this.scanTimer.unref()
            }

            // Calculate and store initial posture
            this.updatePosture()
            this.enforceLaws('start')

            this.log('INVARIANT agent ready')
        } catch (error) {
            this.started = false
            throw this.toPublicError('start', 'Failed to start INVARIANT agent', error)
        }
    }

    // ── RASP Setup ───────────────────────────────────────────────

    /** Get SQL RASP config for wrapping database modules */
    getSqlRaspConfig(): SqlRaspConfig {
        return {
            mode: this.config.mode,
            db: this.db,
            onViolation: (violation) => {
                this.reportViolation('sql', violation.query, violation.invariantClass, violation.confidence, violation.action, violation.timestamp)
            },
        }
    }

    /** Get FS RASP config for wrapping filesystem operations */
    getFsRaspConfig(allowedRoots?: string[]): FsRaspConfig {
        return {
            mode: this.config.mode,
            db: this.db,
            allowedRoots: allowedRoots ?? [this.config.projectDir],
            onViolation: (violation) => {
                this.reportViolation('fs', violation.path, violation.invariantClass, violation.confidence, violation.action, violation.timestamp)
            },
        }
    }

    /** Get HTTP RASP config for wrapping outbound requests */
    getHttpRaspConfig(): HttpRaspConfig {
        return {
            mode: this.config.mode,
            db: this.db,
            onViolation: (violation) => {
                this.reportViolation('http', violation.url, violation.invariantClass, violation.confidence, violation.action, violation.timestamp)
            },
        }
    }

    /** Get exec RASP config for wrapping child_process */
    getExecRaspConfig(): ExecRaspConfig {
        return {
            mode: this.config.mode,
            db: this.db,
            onViolation: (violation) => {
                const isVmRuntimeViolation =
                    violation.invariantClass === 'vm_code_execution' ||
                    violation.invariantClass === 'worker_eval_execution' ||
                    violation.invariantClass === 'native_binding_access' ||
                    violation.invariantClass === 'process_binding_access' ||
                    violation.invariantClass === 'process_dlopen_suspicious_path' ||
                    violation.invariantClass.startsWith('inspector_')
                this.reportViolation(
                    isVmRuntimeViolation ? 'vm_code_execution' : 'exec',
                    violation.command,
                    violation.invariantClass,
                    violation.confidence,
                    violation.action,
                    violation.timestamp,
                )
            },
        }
    }

    /** Get deserialization RASP config */
    getDeserRaspConfig(): DeserRaspConfig {
        return {
            mode: this.config.mode,
            db: this.db,
            onViolation: (violation) => {
                this.reportViolation('deser', violation.input, violation.invariantClass, violation.confidence, violation.action, violation.timestamp)
            },
        }
    }

    /**
     * Wrap JSON.parse with deserialization attack detection.
     * Call this once at startup.
     */
    wrapJsonParse(): void {
        if (this.wrapped.has('json.parse')) return
        const config = this.getDeserRaspConfig()
        JSON.parse = wrapJsonParse(JSON.parse, config)
        this.wrapped.add('json.parse')
        this.healthMonitor.markIntegrationWrapped('json.parse')
        this.log('JSON.parse wrapped with deserialization detection')
    }

    /**
     * Wrap global fetch with SSRF detection.
     * Call this once at startup.
     */
    wrapGlobalFetch(): void {
        if (this.wrapped.has('global.fetch')) return
        const config = this.getHttpRaspConfig()
        globalThis.fetch = wrapFetch(globalThis.fetch, config)
        const require = createRequire(import.meta.url)
        const nodeHttp = require('node:http') as Record<string, unknown>
        const nodeHttps = require('node:https') as Record<string, unknown>
        if (typeof nodeHttp.request === 'function') {
            nodeHttp.request = wrapNodeHttpRequest(nodeHttp.request as (...args: unknown[]) => unknown, config, 'http:')
        }
        if (typeof nodeHttp.get === 'function') {
            nodeHttp.get = wrapNodeHttpGet(nodeHttp.get as (...args: unknown[]) => unknown, config, 'http:')
        }
        if (typeof nodeHttps.request === 'function') {
            nodeHttps.request = wrapNodeHttpRequest(nodeHttps.request as (...args: unknown[]) => unknown, config, 'https:')
        }
        if (typeof nodeHttps.get === 'function') {
            nodeHttps.get = wrapNodeHttpGet(nodeHttps.get as (...args: unknown[]) => unknown, config, 'https:')
        }
        this.wrapped.add('global.fetch')
        this.healthMonitor.markIntegrationWrapped('global.fetch')
        this.log('Global fetch wrapped with SSRF detection')
    }

    /**
     * Wrap a loaded pg module with SQL injection detection.
     */
    wrapPg(pgModule: Record<string, unknown>): void {
        wrapPgModule(pgModule, this.getSqlRaspConfig())
        this.healthMonitor.markIntegrationWrapped('pg')
        this.log('pg module wrapped with SQL injection detection')
    }

    /**
     * Wrap a loaded mysql2 module with SQL injection detection.
     */
    wrapMysql(mysqlModule: Record<string, unknown>): void {
        wrapMysqlModule(mysqlModule, this.getSqlRaspConfig())
        this.healthMonitor.markIntegrationWrapped('mysql2')
        this.log('mysql2 module wrapped with SQL injection detection')
    }

    /** Auto-wrap child_process APIs (exec/execSync/spawn/spawnSync/execFile/execFileSync/fork). */
    wrapChildProcess(): void {
        if (this.wrapped.has('child_process')) return
        const require = createRequire(import.meta.url)
        const childProcess = require('node:child_process') as Record<string, unknown>
        const cfg = this.getExecRaspConfig()
        for (const fn of ['exec', 'execSync', 'spawn', 'spawnSync']) {
            const original = childProcess[fn]
            if (typeof original !== 'function') continue
            childProcess[fn] = wrapExec(original as (...args: unknown[]) => unknown, cfg, fn)
        }
        for (const fn of ['execFile', 'execFileSync'] as const) {
            const original = childProcess[fn]
            if (typeof original !== 'function') continue
            childProcess[fn] = wrapExecFile(original as (...args: unknown[]) => unknown, cfg, fn)
        }
        if (typeof childProcess.fork === 'function') {
            childProcess.fork = wrapFork(childProcess.fork as (...args: unknown[]) => unknown, cfg)
        }
        this.wrapped.add('child_process')
        this.healthMonitor.markIntegrationWrapped('child_process')
        this.log('child_process module wrapped with command injection detection')
        this.startHookTamperMonitor()
    }

    /** Hook VM, Worker, inspector, and native binding bypass vectors. */
    wrapRuntimeEscapes(): void {
        if (this.wrapped.has('runtime_execution')) return
        const require = createRequire(import.meta.url)
        const vm = require('node:vm') as Record<string, unknown>
        installVmRuntimeHooks(this.getExecRaspConfig(), vm)
        this.wrapped.add('runtime_execution')
        this.healthMonitor.markIntegrationWrapped('runtime_execution')
        this.log('runtime execution bypass controls activated for vm/worker_threads/inspector/_linkedBinding')
        this.startHookTamperMonitor()
    }

    /** Auto-wrap core filesystem APIs for path traversal detection. */
    wrapFsModule(allowedRoots?: string[]): void {
        if (this.wrapped.has('fs')) return
        const require = createRequire(import.meta.url)
        const fs = require('node:fs') as Record<string, unknown>
        const cfg = this.getFsRaspConfig(allowedRoots)
        for (const fn of ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'open', 'openSync', 'createReadStream', 'createWriteStream']) {
            const original = fs[fn]
            if (typeof original !== 'function') continue
            fs[fn] = wrapFsOperation(original as (...args: unknown[]) => unknown, cfg, fn)
        }
        this.wrapped.add('fs')
        this.healthMonitor.markIntegrationWrapped('fs')
        this.log('fs module wrapped with path traversal detection')
    }

    /** Wrap a loaded ws module (WebSocket/WebSocketServer). */
    wrapWebSocket(wsModule: Record<string, unknown>): void {
        const cfg: WebSocketRaspConfig = {
            mode: this.config.mode,
            db: this.db,
            onViolation: (violation) => {
                this.reportViolation('deser', violation.direction, violation.invariantClass, violation.confidence, violation.action, violation.timestamp)
            },
        }
        const wsClass = wsModule.WebSocket as { prototype?: Record<string, unknown> } | undefined
        if (wsClass?.prototype?.send && typeof wsClass.prototype.send === 'function') {
            wsClass.prototype.send = wrapWebSocketSend(wsClass.prototype.send as (...args: unknown[]) => unknown, cfg)
            this.healthMonitor.markIntegrationWrapped('ws.send')
        }
    }

    /** Wrap a loaded gRPC client object/module. */
    wrapGrpc(grpcClient: Record<string, unknown>): void {
        const cfg: GrpcRaspConfig = {
            mode: this.config.mode,
            db: this.db,
            onViolation: (violation) => {
                this.reportViolation('deser', violation.method, violation.invariantClass, violation.confidence, violation.action, violation.timestamp)
            },
        }
        wrapGrpcClient(grpcClient, cfg)
        this.healthMonitor.markIntegrationWrapped('grpc')
    }

    /** Runtime health information for dashboards and liveness checks. */
    getHealthStatus(): RuntimeHealthSnapshot {
        return this.healthMonitor.snapshot()
    }

    /** Most recent laws report for runtime compliance visibility. */
    getLawReport(): AgentLawReport {
        return this.lawReport
    }

    // ── Status ───────────────────────────────────────────────────

    getStatus(): AgentStatus {
        const findingStats = this.db.getFindingStats()
        const signalStats = this.db.getSignalStats()
        return {
            mode: this.config.mode,
            uptime: Date.now() - this.startTime,
            findings: {
                total: findingStats.total,
                critical: findingStats.critical,
                high: findingStats.high,
                open: findingStats.open,
            },
            signals: {
                total: signalStats.total,
                blocked: signalStats.blocked,
            },
            lastScan: this.db.getAsset('deps.last_scan'),
        }
    }

    /** Set defense mode */
    setMode(mode: DefenseMode): void {
        this.config.mode = mode
        this.db.setConfig('mode', mode)
        this.log(`Defense mode changed to: ${mode}`)
    }

    /**
     * Upload recent signals to a central server in batches.
     * Marks uploaded signals in the database.
     */
    async uploadSignalsToServer(ingestUrl: string, sensorToken?: string): Promise<void> {
        try {
            const signals = this.db.getUnuploadedSignals(100)
            if (signals.length === 0) return

            const batchSize = 50
            for (let i = 0; i < signals.length; i += batchSize) {
                const batch = signals.slice(i, i + batchSize)
                const payload = {
                    timestamp: new Date().toISOString(),
                    source_hash: 'agent_batch',
                    detections: batch.map(s => ({
                        class: s.type,
                        confidence: 1.0,
                        surface: 'agent_db',
                        key: s.path
                    }))
                }

                const headers: Record<string, string> = { 'Content-Type': 'application/json' }
                if (sensorToken) {
                    headers['Authorization'] = `Bearer ${sensorToken}`
                }

                const abortController = new AbortController()
                const timeout = setTimeout(() => abortController.abort(), 5000)

                try {
                    await fetch(ingestUrl, {
                        method: 'POST',
                        headers,
                        body: JSON.stringify(payload),
                        signal: abortController.signal as any
                    })

                    const ids = batch.map(s => s.id!).filter(id => id !== undefined)
                    this.db.markSignalsUploaded(ids)
                } catch (error) {
                    this.handleInternalError('uploadSignalsToServer.fetch', error)
                } finally {
                    clearTimeout(timeout)
                }
            }
        } catch (error) {
            throw this.toPublicError('uploadSignalsToServer', 'Failed to upload signals', error)
        }
    }

    /** Get the database instance for direct access (dashboard uses this) */
    getDB(): InvariantDB {
        return this.db
    }

    /** Get the autonomous defense controller */
    getDefenseController(): AutonomousDefenseController {
        return this.defenseController
    }

    /**
     * Process an invariant signal through the autonomous defense system.
     * Called by middleware and RASP wrappers when they detect something.
     * Returns the defense decision (block, monitor, challenge, etc.)
     */
    processInvariantSignal(
        sourceHash: string,
        classes: string[],
        behaviors: string[],
        confidence: number,
        severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
        path: string,
        method: string,
    ): DefenseDecision {
        return this.defenseController.processSignal(
            sourceHash, classes, behaviors, confidence, severity, path, method,
        )
    }

    /** Record whether a detected class was confirmed as a real attack or false positive. */
    recordAttackOutcome(classId: string, wasAttack: boolean): void {
        this.calibrator.recordOutcome(classId, wasAttack)
    }

    /** Get calibration quality and uncertainty report across tracked classes. */
    getCalibrationReport(): CalibrationReport {
        return this.calibrator.getCalibrationReport()
    }

    /** Run a manual dependency scan */
    async rescan(): Promise<ScanResult> {
        try {
            return await scanDependencies(this.config.projectDir, this.db)
        } catch (error) {
            throw this.toPublicError('rescan', 'Dependency rescan failed', error)
        }
    }

    /** Best-effort auto-configuration for runtime interception. */
    async autoConfigureRuntime(): Promise<void> {
        try {
            this.safeRun('autoConfigure.wrapJsonParse', () => this.wrapJsonParse())
            this.safeRun('autoConfigure.wrapGlobalFetch', () => this.wrapGlobalFetch())
            this.safeRun('autoConfigure.wrapChildProcess', () => this.wrapChildProcess())
            this.safeRun('autoConfigure.wrapFsModule', () => this.wrapFsModule())
            this.safeRun('autoConfigure.wrapRuntimeEscapes', () => this.wrapRuntimeEscapes())
        } catch (error) {
            throw this.toPublicError('autoConfigureRuntime', 'Runtime auto-configuration failed', error)
        }
    }

    // ── Posture ──────────────────────────────────────────────────

    private updatePosture(): void {
        const stats = this.db.getFindingStats()
        let score = 100

        // Deduct points based on findings
        score -= stats.critical * 20
        score -= stats.high * 10
        score -= stats.medium * 5
        score -= stats.low * 2
        score = Math.max(0, Math.min(100, score))

        let grade = 'A'
        if (score < 90) grade = 'B'
        if (score < 75) grade = 'C'
        if (score < 60) grade = 'D'
        if (score < 40) grade = 'F'

        this.db.insertPosture(grade, score, {
            critical: stats.critical,
            high: stats.high,
            medium: stats.medium,
            low: stats.low,
            open: stats.open,
            resolved: stats.resolved,
        })
    }

    // ── Cleanup ──────────────────────────────────────────────────

    stop(): void {
        if (this.scanTimer) {
            clearInterval(this.scanTimer)
            this.scanTimer = null
        }
        if (this.hookTamperTimer) {
            clearInterval(this.hookTamperTimer)
            this.hookTamperTimer = null
        }
        if (this.heartbeatHandle) {
            this.heartbeatHandle.stop()
            this.heartbeatHandle = null
        }
        void flushSignals()
        this.removeProcessErrorHandlers()
        this.db.close()
        this.started = false
        this.log('INVARIANT agent stopped')
    }

    private log(msg: string): void {
        if (this.config.verbose) {
            console.log(`[invariant] ${msg}`)
        }
    }

    private safeRun(context: string, fn: () => void): void {
        try {
            fn()
        } catch (error) {
            this.handleInternalError(context, error)
        }
    }

    private handleInternalError(context: string, error: unknown): void {
        this.healthMonitor.recordInternalError(context, error)
        try {
            this.config.onInternalError(error, context)
        } catch (callbackError) {
            this.healthMonitor.recordInternalError('onInternalError.callback', callbackError)
            this.log(`Internal error callback failed for context: ${context}`)
        }
    }

    private toPublicError(context: string, message: string, error: unknown): AgentPublicError {
        this.handleInternalError(`public.${context}`, error)
        return new AgentPublicError(`AGENT_${context.toUpperCase()}_FAILED`, message)
    }

    private installProcessErrorHandlers(): void {
        if (this.processErrorHandlersInstalled || typeof process?.on !== 'function') return

        process.on('unhandledRejection', this.onUnhandledRejection)
        process.on('uncaughtExceptionMonitor', this.onUncaughtExceptionMonitor)
        this.processErrorHandlersInstalled = true
    }

    private removeProcessErrorHandlers(): void {
        if (!this.processErrorHandlersInstalled || typeof process?.off !== 'function') return
        process.off('unhandledRejection', this.onUnhandledRejection)
        process.off('uncaughtExceptionMonitor', this.onUncaughtExceptionMonitor)
        this.processErrorHandlersInstalled = false
    }

    private readonly onUnhandledRejection = (reason: unknown): void => {
        this.handleInternalError('process.unhandledRejection', reason)
    }

    private readonly onUncaughtExceptionMonitor = (error: Error): void => {
        this.handleInternalError('process.uncaughtExceptionMonitor', error)
    }

    private reportViolation(
        _surface: 'sql' | 'http' | 'exec' | 'fs' | 'deser' | 'vm_code_execution',
        context: string,
        invariantClass: string,
        confidence: number,
        action: string,
        _timestamp: string,
    ): void {
        if (action !== 'blocked') return

        queueSignal(invariantClass, this.hashPayload(context), confidence)
    }

    private hashPayload(input: string): string {
        return createHash('sha256').update(input).digest('hex').slice(0, 32)
    }

    private startHookTamperMonitor(): void {
        if (this.hookTamperTimer) return
        this.hookTamperTimer = setInterval(() => {
            this.safeRun('hookTamperMonitor', () => this.checkHookTampering())
        }, 5000)
        if (this.hookTamperTimer.unref) this.hookTamperTimer.unref()
    }

    private checkHookTampering(): void {
        if (!this.wrapped.has('child_process') && !this.wrapped.has('runtime_execution')) return
        const require = createRequire(import.meta.url)
        const vm = require('node:vm') as Record<string, unknown>
        const childProcess = require('node:child_process') as Record<string, unknown>
        const removedHooks: string[] = []

        const isNativeCode = (value: unknown): boolean => {
            if (typeof value !== 'function') return false
            try {
                return Function.prototype.toString.call(value).includes('[native code]')
            } catch {
                return false
            }
        }

        const wrappedFunctions: Array<[string, unknown]> = [
            ['vm.runInContext', vm.runInContext],
            ['vm.runInNewContext', vm.runInNewContext],
            ['vm.runInThisContext', vm.runInThisContext],
            ['vm.compileFunction', vm.compileFunction],
            ['process.dlopen', (process as unknown as { dlopen?: (...args: unknown[]) => unknown }).dlopen],
            ['child_process.execSync', childProcess.execSync],
        ]
        for (const [name, fn] of wrappedFunctions) {
            if (isNativeCode(fn)) {
                removedHooks.push(`${name}:native`)
            }
        }

        const integrity = hookIntegrityCheck(vm)
        for (const [name, active] of Object.entries(integrity)) {
            if (!active) removedHooks.push(`${name}:mismatch`)
        }

        if (removedHooks.length === 0) return
        const fingerprint = removedHooks.sort().join('|')
        if (this.hookTamperReported.has(fingerprint)) return
        this.hookTamperReported.add(fingerprint)
        this.fireHookTamperAlert(removedHooks)
    }

    private fireHookTamperAlert(details: string[]): void {
        const now = new Date().toISOString()
        const detail = details.join(', ').slice(0, 200)
        try {
            recordRaspEvent('vm_code_execution', detail, ['HOOK_TAMPER'], 0.99, true)
        } catch { /* Never break */ }
        try {
            this.db.insertSignal({
                type: 'runtime_invariant_violation',
                subtype: 'HOOK_TAMPER',
                severity: 'critical',
                action: 'blocked',
                path: 'runtime.hook_integrity',
                method: 'VM',
                source_hash: null,
                invariant_classes: JSON.stringify(['HOOK_TAMPER']),
                is_novel: true,
                timestamp: now,
            })
            this.db.insertFinding({
                type: 'runtime_invariant_violation',
                category: 'runtime_tamper',
                severity: 'critical',
                status: 'open',
                title: 'Runtime hook tampering detected',
                description: `Detected RASP hook tampering: ${detail}`,
                location: 'runtime.hook_integrity',
                evidence: JSON.stringify({ details }),
                remediation: 'Reinstall runtime hooks and investigate prototype-chain or direct reassignment tampering paths.',
                cve_id: null,
                confidence: 0.99,
                first_seen: now,
                last_seen: now,
                rasp_active: true,
            })
            queueSignal('HOOK_TAMPER', this.hashPayload(detail), 0.99)
        } catch (error) {
            this.handleInternalError('fireHookTamperAlert', error)
        }
    }

    private installHeartbeatGuards(): void {
        const heartbeatConfig = this.resolveHeartbeatConfig()

        if (!this.lastBreathRegistered) {
            registerLastBreath(heartbeatConfig)
            this.lastBreathRegistered = true
        }

        const tampered = detectTamper()
        if (tampered) {
            this.log('Agent tamper detection triggered on startup')
        }

        if (!heartbeatConfig.endpoint || this.heartbeatHandle) {
            return
        }

        this.heartbeatHandle = startHeartbeat(heartbeatConfig)
    }

    private resolveHeartbeatConfig(): HeartbeatConfig {
        return {
            intervalMs: Number.parseInt(process.env.SANTH_HEARTBEAT_INTERVAL_MS ?? '', 10) || DEFAULT_HEARTBEAT_CONFIG.intervalMs,
            endpoint: process.env.SANTH_SENSOR_URL?.trim() ?? '',
            sensorId: process.env.SANTH_SENSOR_ID?.trim() || `${process.pid}`,
            secret: process.env.SANTH_SENSOR_SECRET ?? '',
        }
    }

    private enforceLaws(stage: string): void {
        const report = evaluateAgentLaws(stage, {
            autoConfigure: this.config.autoConfigure,
            captureRuntimeExceptions: this.config.captureRuntimeExceptions,
            wrappedIntegrations: this.wrapped.size,
            hasCoreControllers: !!this.db && !!this.defenseController && !!this.healthMonitor,
            rescanInterval: this.config.rescanInterval,
        })

        this.lawReport = report

        try {
            this.db.setAsset('agent.laws.report', JSON.stringify(report))
        } catch (error) {
            this.handleInternalError('laws.persist', error)
        }

        if (report.violations.length > 0) {
            this.handleInternalError(
                `laws.${stage}`,
                new Error(`Law violations: ${report.violations.map((law) => `L${law.law}`).join(', ')}`),
            )
        }
    }
}

// ── Re-exports ───────────────────────────────────────────────────

export { InvariantDB } from './db.js'
export type { DefenseMode, Finding, Signal, Severity } from './db.js'
export { scanDependencies } from './scanner/deps.js'
export { auditConfiguration } from './scanner/config.js'
export { wrapSqlQuery, wrapPgModule, wrapMysqlModule } from './rasp/sql.js'
export { wrapFsOperation } from './rasp/fs.js'
export { wrapFetch, checkUrlInvariants, wrapNodeHttpRequest, wrapNodeHttpGet } from './rasp/http.js'
export { wrapExec, wrapExecFile, wrapFork, installVmRuntimeHooks, uninstallVmRuntimeHooks, hookIntegrityCheck } from './rasp/exec.js'
export { wrapJsonParse, checkDeserInvariants } from './rasp/deser.js'
export { wrapWebSocketServer, wrapWebSocketSend } from './rasp/websocket.js'
export { wrapGrpcClient, wrapGrpcClientMethod } from './rasp/grpc.js'
export { RuntimeHealthMonitor, type RuntimeHealthSnapshot } from './runtime.js'
export { AutonomousDefenseController, type DefenseDecision, type DefenseLevel, type SourceReputation } from './autonomous-defense.js'
export { ChainCorrelator, ATTACK_CHAINS, type ChainMatch, type ChainSignal } from '../../engine/src/chain-detector.js'
export { BehavioralAnalyzer, type BehaviorSignal, type BehaviorResult, type RequestContext } from './behavioral.js'
export { type RequestSessionData, type RaspEvent, type CompoundDetection, recordRaspEvent, startRequestSession, finalizeRequestSession, getCurrentSession, runWithSession } from './rasp/request-session.js'
export { AdaptiveCalibrator, type ClassCalibrationState, type CalibrationReport } from './calibration.js'
export { queueSignal, flushSignals } from './intel-feedback.js'
export {
    type HeartbeatConfig,
    type HeartbeatHandle,
    DEFAULT_HEARTBEAT_CONFIG,
    startHeartbeat,
    registerLastBreath,
    detectTamper,
} from './heartbeat.js'
export { invariantFastify } from './middleware/fastify.js'
export { invariantKoa } from './middleware/koa.js'
export { invariantHono } from './middleware/hono.js'
export { invariantNextjs } from './middleware/nextjs.js'
