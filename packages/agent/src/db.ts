/**
 * @santh/agent — Local Database
 *
 * All INVARIANT data lives in a single SQLite file in the project directory.
 * No cloud. No network. No attack surface. Just a file.
 *
 * Schema:
 *   findings — vulnerabilities found (deps, code, config)
 *   signals  — attack signals from edge sensor + agent
 *   assets   — application model (framework, deps, data classification)
 *   posture  — security posture snapshots over time
 *   config   — agent configuration and defense mode
 */

import Database from 'better-sqlite3'
import { dirname, join } from 'node:path'
import { mkdirSync, existsSync } from 'node:fs'

// ── Types ────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive' | 'risk_accepted'
export type DefenseAction = 'blocked' | 'sanitized' | 'rewritten' | 'normalized' | 'monitored' | 'challenged' | 'passed'
export type DefenseMode = 'observe' | 'sanitize' | 'defend' | 'lockdown'

export interface Finding {
    id?: number
    type: string
    category: string
    severity: Severity
    status: FindingStatus
    title: string
    description: string
    location: string | null
    evidence: string | null
    remediation: string | null
    cve_id: string | null
    confidence: number
    first_seen: string
    last_seen: string
    rasp_active: boolean
}

export interface Signal {
    id?: number
    type: string
    subtype: string | null
    severity: Severity
    action: DefenseAction
    path: string
    method: string
    source_hash: string | null
    invariant_classes: string
    is_novel: boolean
    timestamp: string
}

export interface Asset {
    id?: number
    key: string
    value: string
    updated_at: string
}

export interface PostureSnapshot {
    id?: number
    grade: string
    score: number
    breakdown: string
    timestamp: string
}

// ── Database ─────────────────────────────────────────────────────

const SCHEMA = `
-- v1: Core schema
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    location TEXT,
    evidence TEXT,
    remediation TEXT,
    cve_id TEXT,
    confidence REAL NOT NULL DEFAULT 0.5,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    rasp_active INTEGER NOT NULL DEFAULT 0,
    resolved_at TEXT,
    resolved_by TEXT,
    resolution_notes TEXT,
    UNIQUE(type, location, cve_id)
);

CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    subtype TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    action TEXT NOT NULL DEFAULT 'monitored',
    path TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    source_ip TEXT,
    source_hash TEXT,
    user_agent TEXT,
    invariant_classes TEXT NOT NULL DEFAULT '[]',
    is_novel INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS posture (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grade TEXT NOT NULL,
    score INTEGER NOT NULL,
    breakdown TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- v2: Remediation tracking
CREATE TABLE IF NOT EXISTS remediation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'agent',
    notes TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- v3: Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    migrated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO schema_version (version) VALUES (3);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp);
CREATE INDEX IF NOT EXISTS idx_signals_type ON signals(type);
CREATE INDEX IF NOT EXISTS idx_signals_action ON signals(action);
CREATE INDEX IF NOT EXISTS idx_signals_severity ON signals(severity);
CREATE INDEX IF NOT EXISTS idx_signals_path ON signals(path);
CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediation_log(finding_id);
`

export class InvariantDB {
    private db: Database.Database

    constructor(dbPath?: string) {
        const resolvedPath = dbPath ?? join(process.cwd(), 'invariant.db')
        const dir = dirname(resolvedPath)
        if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true })
        }

        this.db = new Database(resolvedPath)
        this.db.pragma('journal_mode = WAL')
        this.db.pragma('synchronous = NORMAL')
        this.db.pragma('foreign_keys = ON')
        this.db.exec(SCHEMA)
    }

    // ── Findings ─────────────────────────────────────────────────

    insertFinding(finding: Omit<Finding, 'id'>): number {
        const stmt = this.db.prepare(`
            INSERT INTO findings (type, category, severity, status, title, description, location, evidence, remediation, cve_id, confidence, first_seen, last_seen, rasp_active)
            VALUES (@type, @category, @severity, @status, @title, @description, @location, @evidence, @remediation, @cve_id, @confidence, @first_seen, @last_seen, @rasp_active)
            ON CONFLICT(type, location, cve_id) DO UPDATE SET
                last_seen = @last_seen,
                severity = @severity,
                confidence = @confidence,
                rasp_active = @rasp_active
        `)
        const result = stmt.run({
            ...finding,
            rasp_active: finding.rasp_active ? 1 : 0,
        })
        return Number(result.lastInsertRowid)
    }

    getFindings(filters?: { severity?: Severity; status?: FindingStatus; type?: string; limit?: number }): Finding[] {
        let sql = 'SELECT * FROM findings WHERE 1=1'
        const params: Record<string, unknown> = {}

        if (filters?.severity) {
            sql += ' AND severity = @severity'
            params.severity = filters.severity
        }
        if (filters?.status) {
            sql += ' AND status = @status'
            params.status = filters.status
        }
        if (filters?.type) {
            sql += ' AND type = @type'
            params.type = filters.type
        }
        sql += ' ORDER BY CASE severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 ELSE 4 END'
        if (filters?.limit) {
            sql += ' LIMIT @limit'
            params.limit = filters.limit
        }
        return this.db.prepare(sql).all(params) as Finding[]
    }

    getFindingStats(): { total: number; critical: number; high: number; medium: number; low: number; open: number; resolved: number } {
        const row = this.db.prepare(`
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved
            FROM findings
        `).get() as Record<string, number>
        return {
            total: row.total ?? 0,
            critical: row.critical ?? 0,
            high: row.high ?? 0,
            medium: row.medium ?? 0,
            low: row.low ?? 0,
            open: row.open ?? 0,
            resolved: row.resolved ?? 0,
        }
    }

    updateFindingStatus(id: number, status: FindingStatus, notes?: string): void {
        const now = new Date().toISOString()
        this.db.prepare(`
            UPDATE findings SET status = ?, resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE resolved_at END
            WHERE id = ?
        `).run(status, status, now, id)

        // Log the remediation action
        this.db.prepare(`
            INSERT INTO remediation_log (finding_id, action, actor, notes)
            VALUES (?, ?, 'agent', ?)
        `).run(id, `status_change:${status}`, notes ?? null)
    }

    getFinding(id: number): Finding | null {
        return this.db.prepare('SELECT * FROM findings WHERE id = ?').get(id) as Finding | null
    }

    getRemediationLog(findingId: number): Array<{ action: string; actor: string; notes: string | null; timestamp: string }> {
        return this.db.prepare(
            'SELECT action, actor, notes, timestamp FROM remediation_log WHERE finding_id = ? ORDER BY timestamp DESC'
        ).all(findingId) as Array<{ action: string; actor: string; notes: string | null; timestamp: string }>
    }

    // ── Signals ──────────────────────────────────────────────────

    insertSignal(signal: Omit<Signal, 'id'>): number {
        const stmt = this.db.prepare(`
            INSERT INTO signals (type, subtype, severity, action, path, method, source_hash, invariant_classes, is_novel, timestamp)
            VALUES (@type, @subtype, @severity, @action, @path, @method, @source_hash, @invariant_classes, @is_novel, @timestamp)
        `)
        const result = stmt.run({
            ...signal,
            is_novel: signal.is_novel ? 1 : 0,
        })
        return Number(result.lastInsertRowid)
    }

    getSignals(limit = 100): Signal[] {
        return this.db.prepare('SELECT * FROM signals ORDER BY timestamp DESC LIMIT ?').all(limit) as Signal[]
    }

    getSignalsByTimeRange(startTime: string, endTime: string): Signal[] {
        return this.db.prepare(
            'SELECT * FROM signals WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC'
        ).all(startTime, endTime) as Signal[]
    }

    /** Get signal counts per hour for the last N hours — for timeline charts */
    getSignalTimeline(hours = 24): Array<{ hour: string; total: number; blocked: number; novel: number }> {
        const since = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()
        return this.db.prepare(`
            SELECT
                strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                COUNT(*) as total,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN is_novel = 1 THEN 1 ELSE 0 END) as novel
            FROM signals
            WHERE timestamp >= ?
            GROUP BY hour
            ORDER BY hour ASC
        `).all(since) as Array<{ hour: string; total: number; blocked: number; novel: number }>
    }

    /** Get top attacked paths — for heatmap */
    getTopAttackedPaths(limit = 20): Array<{ path: string; count: number; blocked: number }> {
        return this.db.prepare(`
            SELECT
                path,
                COUNT(*) as count,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked
            FROM signals
            GROUP BY path
            ORDER BY count DESC
            LIMIT ?
        `).all(limit) as Array<{ path: string; count: number; blocked: number }>
    }

    /** Get invariant class distribution — for breakdown charts */
    getInvariantClassDistribution(): Array<{ type: string; count: number }> {
        return this.db.prepare(`
            SELECT type, COUNT(*) as count
            FROM signals
            GROUP BY type
            ORDER BY count DESC
        `).all() as Array<{ type: string; count: number }>
    }

    getSignalStats(sinceHours = 24): { total: number; blocked: number; monitored: number; novel: number } {
        const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString()
        const row = this.db.prepare(`
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN action = 'monitored' THEN 1 ELSE 0 END) as monitored,
                SUM(CASE WHEN is_novel = 1 THEN 1 ELSE 0 END) as novel
            FROM signals WHERE timestamp >= ?
        `).get(since) as Record<string, number>
        return {
            total: row.total ?? 0,
            blocked: row.blocked ?? 0,
            monitored: row.monitored ?? 0,
            novel: row.novel ?? 0,
        }
    }

    // ── Assets ───────────────────────────────────────────────────

    setAsset(key: string, value: string): void {
        this.db.prepare(`
            INSERT INTO assets (key, value, updated_at) VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')
        `).run(key, value, value)
    }

    getAsset(key: string): string | null {
        const row = this.db.prepare('SELECT value FROM assets WHERE key = ?').get(key) as { value: string } | undefined
        return row?.value ?? null
    }

    getAllAssets(): Record<string, string> {
        const rows = this.db.prepare('SELECT key, value FROM assets').all() as Array<{ key: string; value: string }>
        const result: Record<string, string> = {}
        for (const row of rows) {
            result[row.key] = row.value
        }
        return result
    }

    // ── Posture ──────────────────────────────────────────────────

    insertPosture(grade: string, score: number, breakdown: Record<string, unknown>): void {
        this.db.prepare(`
            INSERT INTO posture (grade, score, breakdown) VALUES (?, ?, ?)
        `).run(grade, score, JSON.stringify(breakdown))
    }

    getLatestPosture(): PostureSnapshot | null {
        return this.db.prepare('SELECT * FROM posture ORDER BY timestamp DESC LIMIT 1').get() as PostureSnapshot | null
    }

    getPostureHistory(limit = 30): PostureSnapshot[] {
        return this.db.prepare('SELECT * FROM posture ORDER BY timestamp DESC LIMIT ?').all(limit) as PostureSnapshot[]
    }

    // ── Config ───────────────────────────────────────────────────

    setConfig(key: string, value: string): void {
        this.db.prepare(`
            INSERT INTO config (key, value, updated_at) VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')
        `).run(key, value, value)
    }

    getConfig(key: string): string | null {
        const row = this.db.prepare('SELECT value FROM config WHERE key = ?').get(key) as { value: string } | undefined
        return row?.value ?? null
    }

    // ── Cleanup ──────────────────────────────────────────────────

    /** Remove signals older than N days to prevent unbounded growth */
    pruneSignals(retentionDays: number): number {
        const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString()
        const result = this.db.prepare('DELETE FROM signals WHERE timestamp < ?').run(cutoff)
        return result.changes
    }

    close(): void {
        this.db.close()
    }
}
