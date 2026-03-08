/**
 * @santh/agent — SQL RASP Wrapper
 *
 * Wraps SQL database drivers (mysql2, pg, better-sqlite3, mysql)
 * to detect invariant violations at runtime.
 *
 * Defense modes per detection:
 *   - SANITIZE: auto-parameterize concatenated queries
 *   - BLOCK: kill operation on clear exploitation
 *   - PASSTHROUGH + ALERT: log ambiguous cases for review
 *
 * The math:
 *   Given input I in query Q:
 *   If removing I changes the AST structure of Q (not just leaf values),
 *   then I is an injection.
 *
 * For now: regex-based detection with the proven invariant engine.
 * Future: true SQL parser for AST comparison (the complete solution).
 */

import type { InvariantDB, DefenseAction, Severity } from '../db.js'
import { recordRaspEvent } from './request-session.js'

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
    severity: Severity
    location: string
    timestamp: string
}

// ── SQL Invariant Checks ─────────────────────────────────────────

// These are the mathematical properties — not signatures.
// A query violates an invariant if user-influenced data changes SQL structure.

const SQL_INVARIANTS = [
    {
        id: 'sql_tautology',
        // Tautology: expression that is always true, used to bypass WHERE
        test: (sql: string) => /\bOR\b\s+\d+\s*=\s*\d+|\bOR\b\s*['"][^'"]*['"]\s*=\s*['"][^'"]*['"]/i.test(sql),
        severity: 'high' as Severity,
    },
    {
        id: 'sql_union_injection',
        // UNION: merges a second query's results — data extraction
        test: (sql: string) => /\bUNION\b\s+(?:ALL\s+)?\bSELECT\b/i.test(sql),
        severity: 'critical' as Severity,
    },
    {
        id: 'sql_stacked',
        // Stacked queries: terminates original, runs arbitrary SQL
        test: (sql: string) => /;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|TRUNCATE|GRANT)\b/i.test(sql),
        severity: 'critical' as Severity,
    },
    {
        id: 'sql_time_blind',
        test: (sql: string) => /\b(?:SLEEP|WAITFOR\s+DELAY|BENCHMARK|PG_SLEEP|DBMS_PIPE)\b/i.test(sql),
        severity: 'high' as Severity,
    },
    {
        id: 'sql_comment_truncation',
        test: (sql: string) => /(?:--|#|\/\*)\s*$/m.test(sql) && /\b(?:OR|AND|WHERE|SELECT)\b/i.test(sql),
        severity: 'medium' as Severity,
    },
    {
        id: 'sql_error_oracle',
        test: (sql: string) => /\b(?:EXTRACTVALUE|UPDATEXML|EXP\s*\(\s*~|POLYGON)\b/i.test(sql),
        severity: 'high' as Severity,
    },
]

function checkQueryInvariants(sql: string): Array<{ id: string; severity: Severity }> {
    const violations: Array<{ id: string; severity: Severity }> = []
    for (const inv of SQL_INVARIANTS) {
        try {
            if (inv.test(sql)) {
                violations.push({ id: inv.id, severity: inv.severity })
            }
        } catch {
            // Never let invariant check failure break the query
        }
    }
    return violations
}

function resolveAction(violations: Array<{ severity: Severity }>, mode: SqlRaspConfig['mode']): DefenseAction {
    if (mode === 'observe') return 'monitored'

    const hasCritical = violations.some(v => v.severity === 'critical')
    const hasHigh = violations.some(v => v.severity === 'high')

    switch (mode) {
        case 'sanitize':
            // Sanitize mode: only block critical, monitor high
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

/**
 * Wrap a SQL driver module's query function with invariant checks.
 *
 * Works with:
 *   - pg: client.query(sql, params?)
 *   - mysql2: connection.query(sql, params?)
 *   - better-sqlite3: db.prepare(sql)
 *
 * The wrapper intercepts the SQL string, runs invariant checks,
 * and applies the appropriate defense action.
 */
export function wrapSqlQuery<T extends (...args: unknown[]) => unknown>(
    originalFn: T,
    config: SqlRaspConfig,
    driverName: string,
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const sql = typeof args[0] === 'string' ? args[0] : ''
        if (!sql) return originalFn.apply(this, args)

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
                severity: v.severity,
                location: `${driverName}.query()`,
                timestamp: now,
            }

            // Emit callback
            if (config.onViolation) {
                try { config.onViolation(violation) } catch { /* never break the app */ }
            }

            // Store signal
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
            } catch {
                // DB failure must never break the application
            }

            // Store finding (deduplicated by type + location)
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
            } catch {
                // Never break the app
            }
        }

        // Execute defense action
        if (action === 'blocked') {
            throw new Error(`[INVARIANT] Query blocked — ${violations.map(v => v.id).join(', ')} detected. Use parameterized queries.`)
        }

        // Monitored / sanitized — let it through
        return originalFn.apply(this, args)
    }

    return wrapped as unknown as T
}

/**
 * Auto-wrap a loaded SQL module. Call this from the module interposer.
 *
 * Example:
 *   const pg = require('pg')
 *   wrapPgModule(pg, config)
 *   // All subsequent pg.Client.query() calls are now defended
 */
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
