/**
 * Tests for extended database features:
 *   - Signal timeline / histogram
 *   - Top attacked paths
 *   - Invariant class distribution
 *   - Posture history
 *   - Remediation log
 *   - Finding resolution workflow
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { InvariantDB } from './db.js'

describe('InvariantDB — Extended Features', () => {
    let db: InvariantDB

    beforeEach(() => {
        db = new InvariantDB(':memory:')
    })

    afterEach(() => {
        db.close()
    })

    // Helper: insert N signals for testing
    function insertSignals(count: number, overrides: Partial<{
        type: string; severity: string; action: string; path: string;
        is_novel: boolean; timestamp: string; method: string;
    }> = {}) {
        for (let i = 0; i < count; i++) {
            db.insertSignal({
                type: overrides.type ?? 'sqli',
                subtype: `test_${i}`,
                severity: (overrides.severity as 'high') ?? 'high',
                action: (overrides.action as 'blocked') ?? 'blocked',
                path: overrides.path ?? `/api/endpoint_${i}`,
                method: overrides.method ?? 'GET',
                source_hash: `hash_${i}`,
                invariant_classes: '["sql_tautology"]',
                is_novel: overrides.is_novel ?? false,
                timestamp: overrides.timestamp ?? new Date().toISOString(),
            })
        }
    }

    // ── Signal Timeline ──────────────────────────────────────────

    describe('getSignalTimeline', () => {
        it('returns empty array when no signals', () => {
            const timeline = db.getSignalTimeline(24)
            expect(timeline).toEqual([])
        })

        it('groups signals by hour', () => {
            // Insert signals at the current hour
            insertSignals(5)
            const timeline = db.getSignalTimeline(24)
            expect(timeline.length).toBeGreaterThanOrEqual(1)
            expect(timeline[0].total).toBe(5)
        })

        it('counts blocked signals separately', () => {
            insertSignals(3, { action: 'blocked' })
            insertSignals(2, { action: 'monitored' })
            const timeline = db.getSignalTimeline(24)
            expect(timeline.length).toBeGreaterThanOrEqual(1)
            const total = timeline.reduce((s, t) => s + t.total, 0)
            const blocked = timeline.reduce((s, t) => s + t.blocked, 0)
            expect(total).toBe(5)
            expect(blocked).toBe(3)
        })
    })

    // ── Top Attacked Paths ───────────────────────────────────────

    describe('getTopAttackedPaths', () => {
        it('returns empty array when no signals', () => {
            const paths = db.getTopAttackedPaths()
            expect(paths).toEqual([])
        })

        it('ranks paths by count', () => {
            insertSignals(5, { path: '/api/users' })
            insertSignals(3, { path: '/api/admin' })
            insertSignals(1, { path: '/api/login' })

            const paths = db.getTopAttackedPaths(10)
            expect(paths.length).toBe(3)
            expect(paths[0].path).toBe('/api/users')
            expect(paths[0].count).toBe(5)
            expect(paths[1].path).toBe('/api/admin')
            expect(paths[2].path).toBe('/api/login')
        })

        it('respects limit', () => {
            insertSignals(3, { path: '/a' })
            insertSignals(2, { path: '/b' })
            insertSignals(1, { path: '/c' })

            const paths = db.getTopAttackedPaths(2)
            expect(paths.length).toBe(2)
        })
    })

    // ── Invariant Class Distribution ─────────────────────────────

    describe('getInvariantClassDistribution', () => {
        it('returns empty array when no signals', () => {
            const dist = db.getInvariantClassDistribution()
            expect(dist).toEqual([])
        })

        it('counts signals by type', () => {
            insertSignals(4, { type: 'sqli' })
            insertSignals(2, { type: 'xss' })
            insertSignals(1, { type: 'ssrf' })

            const dist = db.getInvariantClassDistribution()
            expect(dist.length).toBe(3)
            expect(dist[0].type).toBe('sqli')
            expect(dist[0].count).toBe(4)
        })
    })

    // ── Posture History ──────────────────────────────────────────

    describe('getPostureHistory', () => {
        it('returns empty array when no posture snapshots', () => {
            const history = db.getPostureHistory()
            expect(history).toEqual([])
        })

        it('returns all posture snapshots', () => {
            db.insertPosture('A', 100, { critical: 0 })
            db.insertPosture('B', 85, { critical: 1 })
            db.insertPosture('C', 70, { critical: 2 })

            const history = db.getPostureHistory(10)
            expect(history.length).toBe(3)
            // All grades should be present
            const grades = history.map(h => h.grade)
            expect(grades).toContain('A')
            expect(grades).toContain('B')
            expect(grades).toContain('C')
        })

        it('respects limit', () => {
            for (let i = 0; i < 10; i++) {
                db.insertPosture('B', 80, {})
            }
            const history = db.getPostureHistory(5)
            expect(history.length).toBe(5)
        })
    })

    // ── Remediation Log ──────────────────────────────────────────

    describe('Remediation workflow', () => {
        it('logs status changes', () => {
            const now = new Date().toISOString()
            const id = db.insertFinding({
                type: 'test', category: 'test', severity: 'high', status: 'open',
                title: 'Test', description: '', location: 'loc', evidence: '{}',
                remediation: '', cve_id: null, confidence: 0.9,
                first_seen: now, last_seen: now, rasp_active: false,
            })

            db.updateFindingStatus(id, 'acknowledged', 'Investigating this finding')
            db.updateFindingStatus(id, 'resolved', 'Fixed in v2.1.0')

            const log = db.getRemediationLog(id)
            expect(log.length).toBe(2)
            // Both entries should be present
            const notes = log.map(l => l.notes)
            expect(notes).toContain('Fixed in v2.1.0')
            expect(notes).toContain('Investigating this finding')
        })

        it('sets resolved_at when status becomes resolved', () => {
            const now = new Date().toISOString()
            const id = db.insertFinding({
                type: 'test', category: 'test', severity: 'high', status: 'open',
                title: 'Test', description: '', location: 'loc2', evidence: '{}',
                remediation: '', cve_id: null, confidence: 0.9,
                first_seen: now, last_seen: now, rasp_active: false,
            })

            db.updateFindingStatus(id, 'resolved')
            const finding = db.getFinding(id)
            expect(finding).not.toBeNull()
            expect(finding!.status).toBe('resolved')
        })

        it('getFinding returns falsy for nonexistent ID', () => {
            const result = db.getFinding(999)
            expect(result).toBeFalsy()
        })
    })

    // ── Signal Time Range ────────────────────────────────────────

    describe('getSignalsByTimeRange', () => {
        it('filters signals by time range', () => {
            const t1 = '2026-03-01T10:00:00.000Z'
            const t2 = '2026-03-01T12:00:00.000Z'
            const t3 = '2026-03-01T14:00:00.000Z'

            insertSignals(1, { timestamp: t1 })
            insertSignals(1, { timestamp: t2 })
            insertSignals(1, { timestamp: t3 })

            const signals = db.getSignalsByTimeRange(
                '2026-03-01T11:00:00.000Z',
                '2026-03-01T13:00:00.000Z',
            )
            expect(signals.length).toBe(1)
        })
    })
})
