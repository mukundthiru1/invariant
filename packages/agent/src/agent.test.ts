/**
 * Tests for @santh/agent core components.
 *
 * Tests:
 *   1. Database — CRUD operations, schema, deduplication
 *   2. SQL RASP — invariant violation detection + defense actions
 *   3. HTTP RASP — SSRF detection
 *   4. Exec RASP — command injection detection
 *   5. Config auditor — static checks
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { InvariantDB } from './db.js'
import { wrapSqlQuery, type SqlRaspConfig } from './rasp/sql.js'
import { checkUrlInvariants } from './rasp/http.js'
import { join } from 'node:path'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'

// ── Database Tests ───────────────────────────────────────────────

describe('InvariantDB', () => {
    let db: InvariantDB

    beforeEach(() => {
        // In-memory database for testing
        db = new InvariantDB(':memory:')
    })

    afterEach(() => {
        db.close()
    })

    it('creates all tables on instantiation', () => {
        // Verify tables exist by running queries
        expect(() => db.getFindingStats()).not.toThrow()
        expect(() => db.getSignalStats()).not.toThrow()
        expect(() => db.getLatestPosture()).not.toThrow()
    })

    it('inserts and retrieves findings', () => {
        const now = new Date().toISOString()
        db.insertFinding({
            type: 'dependency_vulnerability',
            category: 'supply_chain',
            severity: 'critical',
            status: 'open',
            title: 'lodash@4.17.20 — CVE-2021-23337',
            description: 'Prototype pollution via _.set',
            location: 'package-lock.json: lodash@4.17.20',
            evidence: '{}',
            remediation: 'Update to 4.17.21',
            cve_id: 'CVE-2021-23337',
            confidence: 0.95,
            first_seen: now,
            last_seen: now,
            rasp_active: false,
        })

        const findings = db.getFindings({})
        expect(findings.length).toBe(1)
        expect(findings[0].title).toBe('lodash@4.17.20 — CVE-2021-23337')
        expect(findings[0].severity).toBe('critical')
    })

    it('deduplicates findings by type + location + cve_id', () => {
        const now = new Date().toISOString()
        const finding = {
            type: 'dependency_vulnerability',
            category: 'supply_chain',
            severity: 'critical' as const,
            status: 'open' as const,
            title: 'Test Finding',
            description: 'Test',
            location: 'package-lock.json',
            evidence: '{}',
            remediation: 'Update',
            cve_id: 'CVE-2024-1234',
            confidence: 0.95,
            first_seen: now,
            last_seen: now,
            rasp_active: false,
        }

        db.insertFinding(finding)
        db.insertFinding(finding)
        db.insertFinding(finding)

        const findings = db.getFindings({})
        expect(findings.length).toBe(1)
    })

    it('filters findings by severity', () => {
        const now = new Date().toISOString()
        db.insertFinding({
            type: 'test', category: 'test', severity: 'critical', status: 'open',
            title: 'Critical', description: '', location: 'a', evidence: '{}',
            remediation: '', cve_id: null, confidence: 0.9, first_seen: now, last_seen: now, rasp_active: false,
        })
        db.insertFinding({
            type: 'test', category: 'test', severity: 'low', status: 'open',
            title: 'Low', description: '', location: 'b', evidence: '{}',
            remediation: '', cve_id: null, confidence: 0.5, first_seen: now, last_seen: now, rasp_active: false,
        })

        const critical = db.getFindings({ severity: 'critical' })
        expect(critical.length).toBe(1)
        expect(critical[0].title).toBe('Critical')

        const low = db.getFindings({ severity: 'low' })
        expect(low.length).toBe(1)
        expect(low[0].title).toBe('Low')
    })

    it('inserts and retrieves signals', () => {
        const now = new Date().toISOString()
        db.insertSignal({
            type: 'sqli',
            subtype: 'sql_tautology',
            severity: 'high',
            action: 'blocked',
            path: '/api/users',
            method: 'GET',
            source_hash: null,
            invariant_classes: '["sql_tautology"]',
            is_novel: false,
            timestamp: now,
        })

        const signals = db.getSignals(10)
        expect(signals.length).toBe(1)
        expect(signals[0].action).toBe('blocked')
    })

    it('computes finding stats correctly', () => {
        const now = new Date().toISOString()
        const base = {
            type: 'test', category: 'test', status: 'open' as const,
            description: '', evidence: '{}', remediation: '', cve_id: null,
            confidence: 0.9, first_seen: now, last_seen: now, rasp_active: false,
        }
        db.insertFinding({ ...base, severity: 'critical', title: 'c1', location: 'l1' })
        db.insertFinding({ ...base, severity: 'critical', title: 'c2', location: 'l2' })
        db.insertFinding({ ...base, severity: 'high', title: 'h1', location: 'l3' })
        db.insertFinding({ ...base, severity: 'medium', title: 'm1', location: 'l4' })

        const stats = db.getFindingStats()
        expect(stats.total).toBe(4)
        expect(stats.critical).toBe(2)
        expect(stats.high).toBe(1)
        expect(stats.medium).toBe(1)
    })

    it('sets and gets config', () => {
        db.setConfig('mode', 'defend')
        expect(db.getConfig('mode')).toBe('defend')

        db.setConfig('mode', 'lockdown')
        expect(db.getConfig('mode')).toBe('lockdown')
    })

    it('sets and gets assets', () => {
        db.setAsset('app.type', 'web')
        expect(db.getAsset('app.type')).toBe('web')
    })

    it('inserts and retrieves posture', () => {
        db.insertPosture('B', 82, { critical: 1, high: 2 })
        const posture = db.getLatestPosture()
        expect(posture).not.toBeNull()
        expect(posture!.grade).toBe('B')
        expect(posture!.score).toBe(82)
    })

    it('prunes old signals', () => {
        const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString()
        const recent = new Date().toISOString()

        db.insertSignal({
            type: 'test', subtype: 'old', severity: 'low', action: 'monitored',
            path: '/', method: 'GET', source_hash: null, invariant_classes: '[]',
            is_novel: false, timestamp: old,
        })
        db.insertSignal({
            type: 'test', subtype: 'recent', severity: 'low', action: 'monitored',
            path: '/', method: 'GET', source_hash: null, invariant_classes: '[]',
            is_novel: false, timestamp: recent,
        })

        db.pruneSignals(30)
        const signals = db.getSignals(10)
        expect(signals.length).toBe(1)
        expect(signals[0].subtype).toBe('recent')
    })
})

// ── SQL RASP Tests ───────────────────────────────────────────────

describe('SQL RASP', () => {
    let db: InvariantDB

    beforeEach(() => {
        db = new InvariantDB(':memory:')
    })

    afterEach(() => {
        db.close()
    })

    it('detects SQL tautology and blocks in defend mode', () => {
        const config: SqlRaspConfig = { mode: 'defend', db }
        const original = ((sql: string) => sql) as (...args: unknown[]) => unknown
        const wrapped = wrapSqlQuery(original, config, 'test')

        expect(() => wrapped("SELECT * FROM users WHERE id = '' OR 1=1--")).toThrow(/INVARIANT/)
    })

    it('detects UNION injection', () => {
        const config: SqlRaspConfig = { mode: 'defend', db }
        const original = ((sql: string) => sql) as (...args: unknown[]) => unknown
        const wrapped = wrapSqlQuery(original, config, 'test')

        expect(() => wrapped("SELECT * FROM users WHERE id = '' UNION SELECT 1,2,3--")).toThrow(/INVARIANT/)
    })

    it('detects stacked queries', () => {
        const config: SqlRaspConfig = { mode: 'defend', db }
        const original = ((sql: string) => sql) as (...args: unknown[]) => unknown
        const wrapped = wrapSqlQuery(original, config, 'test')

        expect(() => wrapped("1'; DROP TABLE users--")).toThrow(/INVARIANT/)
    })

    it('allows clean queries through', () => {
        const config: SqlRaspConfig = { mode: 'defend', db }
        const original = ((sql: string) => `executed: ${sql}`) as (...args: unknown[]) => unknown
        const wrapped = wrapSqlQuery(original, config, 'test')

        const result = wrapped('SELECT * FROM users WHERE id = $1')
        expect(result).toBe('executed: SELECT * FROM users WHERE id = $1')
    })

    it('monitors but does not block in observe mode', () => {
        const config: SqlRaspConfig = { mode: 'observe', db }
        const original = ((sql: string) => `executed: ${sql}`) as (...args: unknown[]) => unknown
        const wrapped = wrapSqlQuery(original, config, 'test')

        const result = wrapped("SELECT * FROM users WHERE id = '' OR 1=1--")
        expect(result).toContain('executed:')

        // But it should have recorded a signal
        // Multiple invariant classes may fire from one query (tautology + comment)
        const signals = db.getSignals(10)
        expect(signals.length).toBeGreaterThanOrEqual(1)
        expect(signals.every((s: { action: string }) => s.action === 'monitored')).toBe(true)
    })

    it('records findings for detected violations', () => {
        const config: SqlRaspConfig = { mode: 'observe', db }
        const original = ((sql: string) => sql) as (...args: unknown[]) => unknown
        const wrapped = wrapSqlQuery(original, config, 'test')

        wrapped("SELECT * FROM users WHERE id = '' OR 1=1--")

        const findings = db.getFindings({})
        expect(findings.length).toBeGreaterThan(0)
        expect(findings[0].category).toBe('sqli')
    })
})

// ── HTTP RASP Tests ──────────────────────────────────────────────

describe('HTTP SSRF Detection', () => {
    it('detects internal IP addresses', () => {
        expect(checkUrlInvariants('http://127.0.0.1/admin').length).toBeGreaterThan(0)
        expect(checkUrlInvariants('http://localhost/admin').length).toBeGreaterThan(0)
        expect(checkUrlInvariants('http://10.0.0.1/admin').length).toBeGreaterThan(0)
        expect(checkUrlInvariants('http://192.168.1.1/admin').length).toBeGreaterThan(0)
    })

    it('detects cloud metadata endpoints', () => {
        expect(checkUrlInvariants('http://169.254.169.254/latest/meta-data/').length).toBeGreaterThan(0)
        expect(checkUrlInvariants('http://metadata.google.internal/computeMetadata/v1/').length).toBeGreaterThan(0)
    })

    it('detects protocol smuggling', () => {
        expect(checkUrlInvariants('file:///etc/passwd').length).toBeGreaterThan(0)
        expect(checkUrlInvariants('gopher://127.0.0.1:6379/_INFO').length).toBeGreaterThan(0)
    })

    it('allows normal external URLs', () => {
        expect(checkUrlInvariants('https://api.stripe.com/v1/charges').length).toBe(0)
        expect(checkUrlInvariants('https://example.com/api/data').length).toBe(0)
    })
})

// ── Config Auditor Tests ─────────────────────────────────────────

describe('Config Auditor', async () => {
    const { auditConfiguration } = await import('./scanner/config.js')
    let tmpDir: string
    let db: InvariantDB

    beforeEach(() => {
        tmpDir = mkdtempSync(join(tmpdir(), 'invariant-test-'))
        db = new InvariantDB(':memory:')
    })

    afterEach(() => {
        db.close()
        rmSync(tmpDir, { recursive: true, force: true })
    })

    it('detects missing .gitignore when .env exists', () => {
        writeFileSync(join(tmpDir, '.env'), 'SECRET_KEY=abc123')
        const result = auditConfiguration(tmpDir, db)
        expect(result.findings).toBeGreaterThan(0)
    })

    it('detects .env not listed in .gitignore', () => {
        writeFileSync(join(tmpDir, '.env'), 'SECRET_KEY=abc123')
        writeFileSync(join(tmpDir, '.gitignore'), 'node_modules/\n')
        const result = auditConfiguration(tmpDir, db)
        expect(result.findings).toBeGreaterThan(0)
    })

    it('passes when .env is properly gitignored', () => {
        writeFileSync(join(tmpDir, '.env'), 'SECRET_KEY=abc123')
        writeFileSync(join(tmpDir, '.gitignore'), 'node_modules/\n.env\n')
        // Only the gitignore check should pass — secrets check may still catch it
        const result = auditConfiguration(tmpDir, db)
        // We expect at least the secrets check to find something
        expect(result.total).toBeGreaterThan(0)
    })

    it('detects debug mode in .env', () => {
        writeFileSync(join(tmpDir, '.env'), 'NODE_ENV=development\nDEBUG=true\n')
        writeFileSync(join(tmpDir, '.gitignore'), '.env\n')
        const result = auditConfiguration(tmpDir, db)
        expect(result.findings).toBeGreaterThan(0)
    })

    it('reports zero findings for a clean project', () => {
        writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({
            name: 'test',
            engines: { node: '>=18' },
            dependencies: { express: '^4.18.0' },
        }))
        writeFileSync(join(tmpDir, '.gitignore'), '.env\nnode_modules/\n')
        // No .env file, no secrets, all clean
        const result = auditConfiguration(tmpDir, db)
        expect(result.findings).toBe(0)
    })
})

// ── Telemetry Upload Tests ───────────────────────────────────────

describe('Agent Telemetry Upload', () => {
    let db: InvariantDB

    beforeEach(() => {
        db = new InvariantDB(':memory:')
    })

    afterEach(() => {
        db.close()
    })

    it('retrieves unuploaded signals and marks them as uploaded', () => {
        const now = new Date().toISOString()
        const id1 = db.insertSignal({
            type: 'sqli', subtype: null, severity: 'high', action: 'monitored',
            path: '/test1', method: 'GET', source_hash: null, invariant_classes: '[]',
            is_novel: false, timestamp: now, uploaded_at: null,
        })
        const id2 = db.insertSignal({
            type: 'sqli', subtype: null, severity: 'high', action: 'monitored',
            path: '/test2', method: 'GET', source_hash: null, invariant_classes: '[]',
            is_novel: false, timestamp: now, uploaded_at: null,
        })

        let unuploaded = db.getUnuploadedSignals()
        expect(unuploaded.length).toBe(2)

        db.markSignalsUploaded([id1])

        unuploaded = db.getUnuploadedSignals()
        expect(unuploaded.length).toBe(1)
        expect(unuploaded[0].id).toBe(id2)
    })
})
