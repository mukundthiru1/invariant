/**
 * Tests for behavioral analysis engine.
 *
 * Tests scanner detection, sensitive file access, rate anomaly,
 * path spray, auth brute force, recon detection, directory enumeration.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { BehavioralAnalyzer, type RequestContext } from './behavioral.js'

function makeCtx(overrides: Partial<RequestContext> = {}): RequestContext {
    return {
        path: '/api/test',
        method: 'GET',
        sourceHash: 'test_source',
        userAgent: 'Mozilla/5.0',
        timestamp: Date.now(),
        ...overrides,
    }
}

describe('BehavioralAnalyzer', () => {
    let analyzer: BehavioralAnalyzer

    beforeEach(() => {
        analyzer = new BehavioralAnalyzer({
            rateThreshold: 10,
            pathSprayThreshold: 5,
            authFailureThreshold: 3,
        })
    })

    // ── Scanner Detection ────────────────────────────────────────

    it('detects nuclei scanner', () => {
        const result = analyzer.analyze(makeCtx({ userAgent: 'Nuclei/2.9.1' }))
        expect(result.behaviors).toContain('scanner_detected')
    })

    it('detects sqlmap scanner', () => {
        const result = analyzer.analyze(makeCtx({ userAgent: 'sqlmap/1.7' }))
        expect(result.behaviors).toContain('scanner_detected')
    })

    it('detects nmap scanner', () => {
        const result = analyzer.analyze(makeCtx({ userAgent: 'Nmap Scripting Engine' }))
        expect(result.behaviors).toContain('scanner_detected')
    })

    it('does not flag normal browsers', () => {
        const result = analyzer.analyze(makeCtx({
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }))
        expect(result.behaviors).not.toContain('scanner_detected')
    })

    // ── Sensitive File Access ────────────────────────────────────

    it('detects .env access', () => {
        const result = analyzer.analyze(makeCtx({ path: '/.env' }))
        expect(result.behaviors).toContain('path_sensitive_file')
    })

    it('detects /etc/passwd access', () => {
        const result = analyzer.analyze(makeCtx({ path: '/etc/passwd' }))
        expect(result.behaviors).toContain('path_sensitive_file')
    })

    it('detects .git/config access', () => {
        const result = analyzer.analyze(makeCtx({ path: '/.git/config' }))
        expect(result.behaviors).toContain('path_sensitive_file')
    })

    it('detects AWS credentials access', () => {
        const result = analyzer.analyze(makeCtx({ path: '/.aws/credentials' }))
        expect(result.behaviors).toContain('path_sensitive_file')
    })

    it('does not flag normal API paths', () => {
        const result = analyzer.analyze(makeCtx({ path: '/api/users' }))
        expect(result.behaviors).not.toContain('path_sensitive_file')
    })

    // ── Recon Detection ──────────────────────────────────────────

    it('detects robots.txt probing', () => {
        const result = analyzer.analyze(makeCtx({ path: '/robots.txt' }))
        expect(result.behaviors).toContain('recon_probe')
    })

    it('detects swagger probing', () => {
        const result = analyzer.analyze(makeCtx({ path: '/swagger-ui.html' }))
        expect(result.behaviors).toContain('recon_probe')
    })

    it('detects actuator endpoints', () => {
        const result = analyzer.analyze(makeCtx({ path: '/actuator/health' }))
        expect(result.behaviors).toContain('recon_probe')
    })

    // ── Rate Anomaly ─────────────────────────────────────────────

    it('detects rate anomaly after threshold', () => {
        const now = Date.now()
        for (let i = 0; i < 10; i++) {
            analyzer.analyze(makeCtx({ timestamp: now + i * 100 }))
        }
        const result = analyzer.analyze(makeCtx({ timestamp: now + 1000 }))
        expect(result.behaviors).toContain('rate_anomaly')
    })

    // ── Path Spray ───────────────────────────────────────────────

    it('detects path spray', () => {
        const now = Date.now()
        for (let i = 0; i < 5; i++) {
            analyzer.analyze(makeCtx({ path: `/path_${i}`, timestamp: now + i }))
        }
        const result = analyzer.analyze(makeCtx({ path: '/path_extra', timestamp: now + 100 }))
        expect(result.behaviors).toContain('path_spray')
    })

    // ── Auth Brute Force ─────────────────────────────────────────

    it('detects auth brute force', () => {
        const now = Date.now()
        for (let i = 0; i < 3; i++) {
            analyzer.analyze(makeCtx({
                path: '/api/login',
                statusCode: 401,
                timestamp: now + i * 100,
            }))
        }
        const result = analyzer.analyze(makeCtx({
            path: '/api/login',
            statusCode: 401,
            timestamp: now + 1000,
        }))
        expect(result.behaviors).toContain('auth_brute_force')
    })

    // ── Compound Behaviors ───────────────────────────────────────

    it('detects multiple behaviors simultaneously', () => {
        const now = Date.now()
        // Build up rate + path spray
        for (let i = 0; i < 10; i++) {
            analyzer.analyze(makeCtx({
                path: `/scan_${i}`,
                userAgent: 'Nuclei/2.9.1',
                timestamp: now + i * 100,
            }))
        }
        const result = analyzer.analyze(makeCtx({
            path: '/.env',
            userAgent: 'Nuclei/2.9.1',
            timestamp: now + 2000,
        }))

        expect(result.behaviors).toContain('scanner_detected')
        expect(result.behaviors).toContain('path_sensitive_file')
        expect(result.behaviors).toContain('rate_anomaly')
        expect(result.behaviors).toContain('path_spray')
    })

    // ── Static Methods ───────────────────────────────────────────

    it('static isSensitivePath works', () => {
        expect(BehavioralAnalyzer.isSensitivePath('/.env')).toBe(true)
        expect(BehavioralAnalyzer.isSensitivePath('/api/users')).toBe(false)
    })

    it('static isScanner works', () => {
        expect(BehavioralAnalyzer.isScanner('sqlmap/1.7')).toBe(true)
        expect(BehavioralAnalyzer.isScanner('Mozilla/5.0')).toBe(false)
    })

    // ── Source Isolation ─────────────────────────────────────────

    it('isolates source windows', () => {
        const now = Date.now()
        // Source A gets many requests
        for (let i = 0; i < 10; i++) {
            analyzer.analyze(makeCtx({
                sourceHash: 'src_a',
                path: `/a_${i}`,
                timestamp: now + i,
            }))
        }

        // Source B sends one request
        const result = analyzer.analyze(makeCtx({
            sourceHash: 'src_b',
            path: '/api/test',
            timestamp: now + 100,
        }))

        // Source B should NOT have rate anomaly or path spray
        expect(result.behaviors).not.toContain('rate_anomaly')
        expect(result.behaviors).not.toContain('path_spray')
    })
})
