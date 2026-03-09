/**
 * @santh/agent — SQL RASP Wrapper
 *
 * Wraps SQL database drivers (mysql2, pg, better-sqlite3, mysql)
 * to detect invariant violations at runtime.
 */

import type { InvariantDB, DefenseAction, Severity } from '../db.js'
import { recordRaspEvent } from './request-session.js'
import { InvariantEngine } from '../../../engine/src/invariant-engine.js'

const engine = new InvariantEngine()

// ── Types ────────────────────────────────────────────────────────

export interface SqlRaspConfig {
    mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    db: InvariantDB
    onViolation?: (violation: SqlViolation) => void
}

export interface SqlViolation {
    query: string
    invariantClass: string
    action: DefenseAction
    confidence: number
    severity: Severity
    location: string
    timestamp: string
}

// ── Pattern Tracking ─────────────────────────────────────────────

const patternCache = new Map<string, { count: number, start: number }>()
const PATTERN_WINDOW_MS = 60_000
const PATTERN_LIMIT = 100

function logSqlRaspError(context: string, error: unknown): void {
    const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error)
    console.warn('[invariant] SQL RASP internal error', {
        context,
        error: message,
    })
}

function abstractQuery(sql: string): string {
    return sql.replace(/['"][^'"]*['"]/g, '?').replace(/\b\d+\b/g, '?').replace(/\s+/g, ' ').trim().toLowerCase()
}

function trackQueryPattern(sql: string, config: SqlRaspConfig): void {
    const pattern = abstractQuery(sql)
    const now = Date.now()
    
    let state = patternCache.get(pattern)
    if (!state) {
        state = { count: 1, start: now }
        patternCache.set(pattern, state)
        return
    }
    
    if (now - state.start > PATTERN_WINDOW_MS) {
        state.count = 1
        state.start = now
        return
    }
    
    state.count++
    if (state.count === PATTERN_LIMIT) {
        const msg = `[INVARIANT] SCANNING DETECTED: Query pattern executed ${PATTERN_LIMIT}x/minute: ${pattern.slice(0, 100)}`
        console.warn(msg)
        try {
            config.db.insertSignal({
                type: 'behavioral_anomaly',
                subtype: 'sql_scanning',
                severity: 'high',
                action: 'monitored',
                path: 'sql_pattern_tracker',
                method: 'QUERY',
                source_hash: null,
                invariant_classes: JSON.stringify(['sql_scanning']),
                is_novel: false,
                timestamp: new Date().toISOString()
            })
        } catch (error) {
            logSqlRaspError('trackQueryPattern.insertSignal', error)
        }
    }
}

// ── Parameterized Check ──────────────────────────────────────────

function checkNonParameterized(sql: string, args: unknown[]): void {
    const hasParams = args.length > 1 && (Array.isArray(args[1]) || (args[1] != null && typeof args[1] === 'object'))
    const hasInlineData = /=\s*['"][^'"]*['"]|=\s*\d+/.test(sql) || /\b(?:IN|VALUES)\s*\([^)]+['"]/.test(sql)
    const hasPlaceholders = /\$\d+|\?|:[a-zA-Z_]+/.test(sql)
    
    if (hasInlineData && !hasPlaceholders && !hasParams) {
        console.warn(`[INVARIANT] WARNING: Non-parameterized query detected. Consider using prepared statements: ${sql.slice(0, 100)}`)
    }
}

// ── SQL Invariant Checks ─────────────────────────────────────────

function checkQueryInvariants(sql: string): Array<{ id: string; severity: Severity }> {
    const matches = engine.detectDeep(sql, [], 'sql').matches
    return matches.map(m => ({ id: m.class, severity: m.severity as Severity }))
}

function resolveAction(violations: Array<{ severity: Severity }>, mode: SqlRaspConfig['mode']): DefenseAction {
    if (mode === 'observe') return 'monitored'

    const hasCritical = violations.some(v => v.severity === 'critical')
    const hasHigh = violations.some(v => v.severity === 'high')

    switch (mode) {
        case 'sanitize':
            return hasCritical ? 'blocked' : 'monitored'
        case 'defend':
            return (hasCritical || hasHigh) ? 'blocked' : 'monitored'
        case 'lockdown':
            return 'blocked'
        default:
            return 'monitored'
    }
}

// ── Module Wrapper ───────────────────────────────────────────────

export function wrapSqlQuery<T extends (...args: unknown[]) => unknown>(
    originalFn: T,
    config: SqlRaspConfig,
    driverName: string,
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const sql = typeof args[0] === 'string' ? args[0] : ''
        if (!sql) return originalFn.apply(this, args)

        checkNonParameterized(sql, args)
        trackQueryPattern(sql, config)

        const violations = checkQueryInvariants(sql)
        if (violations.length === 0) return originalFn.apply(this, args)

        const action = resolveAction(violations, config.mode)
        const now = new Date().toISOString()
        if (violations.length > 0) {
            recordRaspEvent('sql', sql.slice(0, 200), violations.map(v => v.id), action === 'blocked' ? 0.95 : 0.85, action === 'blocked')
        }

        // Record the finding
        for (const v of violations) {
            const violation: SqlViolation = {
                query: sql.length > 500 ? sql.slice(0, 500) + '...' : sql,
                invariantClass: v.id,
                action,
                confidence: action === 'blocked' ? 0.95 : 0.85,
                severity: v.severity,
                location: `${driverName}.query()`,
                timestamp: now,
            }

            if (config.onViolation) {
                try {
                    config.onViolation(violation)
                } catch (error) {
                    logSqlRaspError('wrapSqlQuery.onViolation', error)
                }
            }

            try {
                config.db.insertSignal({
                    type: 'sql_invariant_violation',
                    subtype: v.id,
                    severity: v.severity,
                    action,
                    path: `${driverName}.query()`,
                    method: 'QUERY',
                    source_hash: null,
                    invariant_classes: JSON.stringify(violations.map(vv => vv.id)),
                    is_novel: false,
                    timestamp: now,
                })
            } catch (error) {
                logSqlRaspError('wrapSqlQuery.insertSignal', error)
            }

            try {
                config.db.insertFinding({
                    type: 'runtime_invariant_violation',
                    category: 'sqli',
                    severity: v.severity,
                    status: 'open',
                    title: `SQL invariant violation: ${v.id}`,
                    description: `Detected ${v.id} in query via ${driverName}. Query: ${sql.slice(0, 200)}...`,
                    location: `${driverName}.query()`,
                    evidence: JSON.stringify({ invariantClass: v.id, queryPrefix: sql.slice(0, 200) }),
                    remediation: 'Use parameterized queries instead of string concatenation. Replace: db.query("SELECT * FROM users WHERE id = " + id) with: db.query("SELECT * FROM users WHERE id = $1", [id])',
                    cve_id: null,
                    confidence: 0.85,
                    first_seen: now,
                    last_seen: now,
                    rasp_active: action === 'blocked',
                })
            } catch (error) {
                logSqlRaspError('wrapSqlQuery.insertFinding', error)
            }
        }

        if (action === 'blocked') {
            throw new Error(`[INVARIANT] Query blocked — ${violations.map(v => v.id).join(', ')} detected. Use parameterized queries.`)
        }

        return originalFn.apply(this, args)
    }

    return wrapped as unknown as T
}

export function wrapPgModule(pg: Record<string, unknown>, config: SqlRaspConfig): void {
    const Client = pg.Client as { prototype: Record<string, unknown> } | undefined
    if (Client?.prototype?.query) {
        Client.prototype.query = wrapSqlQuery(
            Client.prototype.query as (...args: unknown[]) => unknown,
            config,
            'pg',
        )
    }

    const Pool = pg.Pool as { prototype: Record<string, unknown> } | undefined
    if (Pool?.prototype?.query) {
        Pool.prototype.query = wrapSqlQuery(
            Pool.prototype.query as (...args: unknown[]) => unknown,
            config,
            'pg.Pool',
        )
    }
}

export function wrapMysqlModule(mysql: Record<string, unknown>, config: SqlRaspConfig): void {
    const Connection = mysql.Connection as { prototype: Record<string, unknown> } | undefined
    if (Connection?.prototype?.query) {
        Connection.prototype.query = wrapSqlQuery(
            Connection.prototype.query as (...args: unknown[]) => unknown,
            config,
            'mysql2',
        )
    }
}

export function wrapBetterSqlite3Module(bs3: Record<string, unknown>, config: SqlRaspConfig): void {
    const Database = bs3.Database as { prototype: Record<string, unknown> } | undefined
    if (Database?.prototype?.prepare) {
        Database.prototype.prepare = wrapSqlQuery(
            Database.prototype.prepare as (...args: unknown[]) => unknown,
            config,
            'better-sqlite3',
        )
    }
}
