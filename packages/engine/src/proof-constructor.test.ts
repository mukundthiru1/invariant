/**
 * Property Proof Constructor — Tests
 *
 * Verifies that the proof constructor correctly extracts the three phases
 * of the exploitation algebra (escape, payload, repair) from malicious inputs
 * and produces machine-verifiable PropertyProof objects.
 */

import { describe, it, expect } from 'vitest'
import { constructProof } from './proof-constructor.js'
import type { InvariantClassModule, DetectionLevelResult } from './classes/types.js'

// ── Test Helpers ─────────────────────────────────────────────

function makeModule(overrides: Partial<InvariantClassModule>): InvariantClassModule {
    return {
        id: 'sql_tautology',
        description: 'Test module',
        category: 'sqli',
        severity: 'critical',
        detect: () => true,
        generateVariants: () => [],
        knownPayloads: [],
        knownBenign: [],
        ...overrides,
    } as InvariantClassModule
}

function makeL2Result(overrides: Partial<DetectionLevelResult> = {}): DetectionLevelResult {
    return {
        detected: true,
        confidence: 0.92,
        explanation: 'Tautological expression evaluates to TRUE',
        evidence: "1=1",
        ...overrides,
    }
}

// ── SQL Injection Proofs ─────────────────────────────────────

describe('Proof Constructor: SQL Injection', () => {
    const sqlModule = makeModule({ id: 'sql_tautology', category: 'sqli' })

    it('constructs complete proof for classic SQLi', () => {
        const input = "' OR 1=1 --"
        const proof = constructProof(sqlModule, input, makeL2Result())

        expect(proof).not.toBeNull()
        expect(proof!.domain).toBe('sqli')
        expect(proof!.isComplete).toBe(true)
        expect(proof!.steps.length).toBeGreaterThanOrEqual(3)

        const ops = proof!.steps.map(s => s.operation)
        expect(ops).toContain('context_escape')
        expect(ops).toContain('payload_inject')
        expect(ops).toContain('syntax_repair')
    })

    it('includes semantic_eval step when L2 fires', () => {
        const input = "' OR 1=1 --"
        const proof = constructProof(sqlModule, input, makeL2Result())

        const semanticStep = proof!.steps.find(s => s.operation === 'semantic_eval')
        expect(semanticStep).toBeDefined()
        expect(semanticStep!.confidence).toBe(0.92)
    })

    it('verifies OR 1=1 payload with AST evaluation', () => {
        const input = "' OR 1=1 --"
        const proof = constructProof(sqlModule, input, null)

        expect(proof).not.toBeNull()
        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.verified).toBe(true)
        expect(payload!.verificationMethod).toBe('ast_evaluation')

        expect(proof!.verifiedSteps).toBe(3)
        expect(proof!.verificationCoverage).toBe(1)
        expect(proof!.proofVerificationLevel).toBe('verified')
    })

    it('produces proof without L2 (structural only)', () => {
        const input = "' OR 1=1 --"
        const proof = constructProof(sqlModule, input, null)

        expect(proof).not.toBeNull()
        expect(proof!.steps.some(s => s.operation === 'semantic_eval')).toBe(false)
        // Still has structural steps
        expect(proof!.steps.length).toBeGreaterThanOrEqual(2)
    })

    it('extracts correct escape character offset', () => {
        const input = "' OR 1=1 --"
        const proof = constructProof(sqlModule, input, null)
        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape).toBeDefined()
        expect(escape!.offset).toBe(0) // single quote at start
    })

    it('handles UNION SELECT injection', () => {
        const input = "' UNION SELECT username, password FROM users --"
        const unionModule = makeModule({ id: 'sql_union_extraction', category: 'sqli' })
        const proof = constructProof(unionModule, input, null)

        expect(proof).not.toBeNull()
        expect(proof!.isComplete).toBe(true)
        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/UNION\s+SELECT/i)

        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape?.verified).toBe(true)
        expect(escape?.verificationMethod).toBe('tokenizer_parse')

        const repair = proof!.steps.find(s => s.operation === 'syntax_repair')
        expect(repair?.verified).toBe(true)
        expect(repair?.verificationMethod).toBe('tokenizer_parse')

        expect(proof!.verifiedSteps).toBe(2)
        expect(proof!.verificationCoverage).toBeCloseTo(2 / 3, 6)
        expect(proof!.proofVerificationLevel).toBe('verified')
    })

    it('handles stacked query injection', () => {
        const input = "'; DROP TABLE users --"
        const stackedModule = makeModule({ id: 'sql_stacked_execution', category: 'sqli' })
        const proof = constructProof(stackedModule, input, null)

        expect(proof).not.toBeNull()
        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/DROP/i)
    })
})

// ── XSS Proofs ───────────────────────────────────────────────

describe('Proof Constructor: XSS', () => {
    const xssModule = makeModule({ id: 'xss_tag_injection', category: 'xss' })

    it('constructs proof for script injection', () => {
        const input = '"><script>alert(1)</script>'
        const proof = constructProof(xssModule, input, null)

        expect(proof).not.toBeNull()
        expect(proof!.domain).toBe('xss')
        expect(proof!.steps.some(s => s.operation === 'context_escape')).toBe(true)
        expect(proof!.steps.some(s => s.operation === 'payload_inject')).toBe(true)
        expect(proof!.steps.some(s => s.operation === 'syntax_repair')).toBe(true)

        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/<script/i)
    })

    it('detects event handler XSS', () => {
        const input = '" onmouseover="alert(1)"'
        const eventModule = makeModule({ id: 'xss_event_handler', category: 'xss' })
        const proof = constructProof(eventModule, input, null)

        expect(proof).not.toBeNull()
        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape).toBeDefined()

        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/onmouseover/i)
    })
})

// ── Command Injection Proofs ─────────────────────────────────

describe('Proof Constructor: Command Injection', () => {
    const cmdModule = makeModule({ id: 'cmd_separator', category: 'cmdi' })

    it('constructs proof for separator + command injection', () => {
        const input = '; cat /etc/passwd'
        const proof = constructProof(cmdModule, input, null)

        expect(proof).not.toBeNull()
        expect(proof!.domain).toBe('cmdi')

        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape).toBeDefined()
        expect(escape!.input).toMatch(/;/)

        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/cat/i)
    })

    it('constructs proof for command substitution', () => {
        const input = '$(whoami)'
        const proof = constructProof(cmdModule, input, null)

        expect(proof).not.toBeNull()
        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape).toBeDefined()
        expect(escape!.input).toMatch(/\$\(/)

        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/whoami/i)
    })
})

// ── Path Traversal Proofs ────────────────────────────────────

describe('Proof Constructor: Path Traversal (tokenizer-based)', () => {
    const pathModule = makeModule({ id: 'path_dotdot_escape', category: 'path_traversal' })

    it('constructs proof for directory traversal', () => {
        const input = '../../../etc/passwd'
        const proof = constructProof(pathModule, input, null)

        expect(proof).not.toBeNull()
        expect(proof!.domain).toBe('path_traversal')

        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape).toBeDefined()
        expect(escape!.input).toMatch(/\.\./)
        expect(escape!.verified).toBe(true)
        expect(escape!.verificationMethod).toBe('tokenizer_structural')

        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/etc\/passwd/i)
        expect(payload!.verified).toBe(true)
        expect(payload!.verificationMethod).toBe('sensitive_path_match')
    })

    it('detects null byte termination in repair', () => {
        const input = '../../../etc/passwd%00.jpg'
        const proof = constructProof(pathModule, input, null)

        expect(proof).not.toBeNull()
        const repair = proof!.steps.find(s => s.operation === 'syntax_repair')
        expect(repair).toBeDefined()
        expect(repair!.verified).toBe(true)
        expect(repair!.verificationMethod).toBe('null_byte_detection')
    })

    it('counts traversal depth in proof', () => {
        const input = '../../../../../../../../etc/shadow'
        const proof = constructProof(pathModule, input, null)
        expect(proof).not.toBeNull()
        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape).toBeDefined()
        // Multiple traversal sequences should be identified
        expect(escape!.output).toMatch(/\d+.*traversal/)
    })

    it('produces complete proof with traversal + target + null byte', () => {
        const input = '../../../etc/passwd%00.jpg'
        const proof = constructProof(pathModule, input, null)
        expect(proof).not.toBeNull()
        expect(proof!.isComplete).toBe(true)
        expect(proof!.proofConfidence).toBeGreaterThan(0.85)
    })

    it('targets Windows system files', () => {
        const input = '..\\..\\..\\windows\\win.ini'
        const proof = constructProof(pathModule, input, null)
        expect(proof).not.toBeNull()
        expect(proof!.steps.some(s => s.operation === 'payload_inject')).toBe(true)
    })

    it('detects proc filesystem access', () => {
        const input = '../../../proc/self/environ'
        const proof = constructProof(pathModule, input, null)
        expect(proof).not.toBeNull()
        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/proc\/self\/environ/)
    })
})

// ── SSRF Proofs ──────────────────────────────────────────────

describe('Proof Constructor: SSRF (tokenizer-based)', () => {
    const ssrfModule = makeModule({ id: 'ssrf_internal_reach', category: 'ssrf' })

    it('constructs proof for metadata endpoint access', () => {
        const input = 'http://169.254.169.254/latest/meta-data/'
        const proof = constructProof(ssrfModule, input, null)

        expect(proof).not.toBeNull()
        expect(proof!.domain).toBe('ssrf')

        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape).toBeDefined()
        expect(escape!.input).toMatch(/https?:/i)
        expect(escape!.verified).toBe(true)
        expect(escape!.verificationMethod).toBe('scheme_parse')

        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/169\.254\.169\.254/i)
        expect(payload!.verified).toBe(true)
        expect(payload!.verificationMethod).toBe('metadata_host_match')
    })

    it('detects localhost targeting with port', () => {
        const input = 'http://127.0.0.1:6379/'
        const proof = constructProof(ssrfModule, input, null)

        expect(proof).not.toBeNull()
        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
        expect(payload!.input).toMatch(/127\.0\.0\.1/)
        expect(payload!.verificationMethod).toBe('private_ip_match')
    })

    it('detects private network ranges (10.x, 192.168.x)', () => {
        for (const ip of ['10.0.0.1', '192.168.1.1', '172.16.0.1']) {
            const proof = constructProof(ssrfModule, `http://${ip}/admin`, null)
            expect(proof).not.toBeNull()
            const payload = proof!.steps.find(s => s.operation === 'payload_inject')
            expect(payload).toBeDefined()
            expect(payload!.input).toBe(ip)
        }
    })

    it('detects dangerous schemes (gopher, file)', () => {
        const input = 'gopher://127.0.0.1:25/_HELO'
        const proof = constructProof(ssrfModule, input, null)
        expect(proof).not.toBeNull()
        const escape = proof!.steps.find(s => s.operation === 'context_escape')
        expect(escape).toBeDefined()
        expect(escape!.confidence).toBeGreaterThanOrEqual(0.95) // dangerous scheme boost
    })

    it('produces complete proof for metadata with sensitive path', () => {
        const input = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        const proof = constructProof(ssrfModule, input, null)
        expect(proof).not.toBeNull()
        expect(proof!.isComplete).toBe(true)
        expect(proof!.proofConfidence).toBeGreaterThan(0.90)
    })

    it('detects protocol-relative URLs', () => {
        const input = '//169.254.169.254/latest/meta-data/'
        const proof = constructProof(ssrfModule, input, null)
        expect(proof).not.toBeNull()
        const payload = proof!.steps.find(s => s.operation === 'payload_inject')
        expect(payload).toBeDefined()
    })
})

// ── XXE Proofs ───────────────────────────────────────────────

describe('Proof Constructor: XXE', () => {
    it('constructs proof for external entity', () => {
        const xxeModule = makeModule({ id: 'xxe_entity_expansion', category: 'injection' })
        const input = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        // XXE uses 'injection' category which falls back to sqli in CATEGORY_TO_DOMAIN
        // but xxe patterns are keyed separately, so let's test with a module that has category mapped
        const proof = constructProof(
            makeModule({ id: 'xxe_entity_expansion', category: 'injection' }),
            input,
            makeL2Result({ explanation: 'External entity references local file system' }),
        )

        // Falls back to minimal proof since 'injection' maps to 'sqli' domain
        // and the XXE input doesn't match SQL patterns well
        expect(proof).not.toBeNull()
    })
})

// ── Proof Confidence ─────────────────────────────────────────

describe('Proof Confidence Model', () => {
    const sqlModule = makeModule({ id: 'sql_tautology', category: 'sqli' })

    it('complete proof (3 phases + L2) has highest confidence', () => {
        const input = "' OR 1=1 --"
        const proof = constructProof(sqlModule, input, makeL2Result())

        expect(proof).not.toBeNull()
        expect(proof!.isComplete).toBe(true)
        // 3 structural steps = 0.40 + 3*0.20 = min(0.90, 1.00) = 0.90
        // + completeness bonus 0.05 + semantic bonus 0.04 = 0.99
        expect(proof!.proofConfidence).toBeGreaterThanOrEqual(0.95)
    })

    it('incomplete proof has lower confidence', () => {
        // Input with payload but weak escape/repair
        const input = "SELECT * FROM users"
        const proof = constructProof(sqlModule, input, makeL2Result())

        // May or may not construct a proof depending on pattern matches
        // but if it does, it shouldn't be marked complete
        if (proof) {
            // Without all 3 phases, no completeness bonus
            expect(proof.proofConfidence).toBeLessThan(0.99)
        }
    })

    it('L2 semantic step adds confidence bonus', () => {
        const input = "' OR 1=1 --"
        const withL2 = constructProof(sqlModule, input, makeL2Result())
        const withoutL2 = constructProof(sqlModule, input, null)

        expect(withL2).not.toBeNull()
        expect(withoutL2).not.toBeNull()
        expect(withL2!.proofConfidence).toBeGreaterThan(withoutL2!.proofConfidence)
    })

    it('path traversal proofs have verified verification level', () => {
        const pathModule = makeModule({ id: 'path_dotdot_escape', category: 'path_traversal' })
        const proof = constructProof(pathModule, '../../../etc/passwd', null)
        expect(proof).not.toBeNull()
        expect(proof!.verifiedSteps).toBeGreaterThan(0)
        expect(proof!.verificationCoverage).toBeGreaterThan(0)
        expect(proof!.proofVerificationLevel).toBe('verified')
    })

    it('SSRF proofs have verified verification level', () => {
        const ssrfModule = makeModule({ id: 'ssrf_internal_reach', category: 'ssrf' })
        const proof = constructProof(ssrfModule, 'http://169.254.169.254/latest/meta-data/', null)
        expect(proof).not.toBeNull()
        expect(proof!.verifiedSteps).toBeGreaterThan(0)
        expect(proof!.verificationCoverage).toBeGreaterThan(0)
        expect(proof!.proofVerificationLevel).toBe('verified')
    })
})

// ── Minimal Proofs ───────────────────────────────────────────

describe('Minimal Proofs (unknown domain)', () => {
    it('constructs minimal proof from L2 evidence for unknown domain', () => {
        const unknownModule = makeModule({
            id: 'proto_pollution',
            category: 'injection',
            description: 'Prototype pollution via __proto__',
        })
        // 'injection' maps to 'sqli' in CATEGORY_TO_DOMAIN, so this actually
        // uses SQL patterns. Let's test with a category that truly has no patterns.
        const weirdModule = makeModule({
            id: 'deser_java_gadget' as any,
            category: 'deser' as any,
            description: 'Java deserialization gadget chain',
        })

        const proof = constructProof(weirdModule, 'rO0ABXNyAA...', makeL2Result({
            explanation: 'Java serialization magic bytes detected',
            confidence: 0.88,
        }))

        expect(proof).not.toBeNull()
        expect(proof!.isComplete).toBe(false)
        expect(proof!.steps.length).toBe(1)
        expect(proof!.steps[0].operation).toBe('semantic_eval')
        // Minimal proof confidence = L2 confidence * 0.85
        expect(proof!.proofConfidence).toBeCloseTo(0.88 * 0.85, 2)
    })

    it('returns null for unknown domain with no L2 evidence', () => {
        const weirdModule = makeModule({
            id: 'deser_java_gadget' as any,
            category: 'deser' as any,
        })

        const proof = constructProof(weirdModule, 'some input', null)
        expect(proof).toBeNull()
    })
})

// ── Integration: Proof in detectDeep ─────────────────────────

describe('Proof Integration with detectDeep', () => {
    // Import here to avoid circular — test that proofs appear on matches
    it('detectDeep attaches proofs to SQL injection matches', async () => {
        const { InvariantEngine } = await import('./invariant-engine.js')
        const engine = new InvariantEngine()
        const result = engine.detectDeep("' OR 1=1 --", [])

        const sqlMatches = result.matches.filter(m => m.category === 'sqli')
        expect(sqlMatches.length).toBeGreaterThan(0)

        // At least one SQL match should have a proof
        const withProof = sqlMatches.filter(m => m.proof != null)
        expect(withProof.length).toBeGreaterThan(0)

        const proof = withProof[0].proof!
        expect(proof.domain).toBe('sqli')
        expect(proof.steps.length).toBeGreaterThan(0)
        expect(proof.witness).toContain("' OR 1=1 --")
    })

    it('detectDeep attaches proofs to XSS matches', async () => {
        const { InvariantEngine } = await import('./invariant-engine.js')
        const engine = new InvariantEngine()
        const result = engine.detectDeep('<script>alert(1)</script>', [])

        const xssMatches = result.matches.filter(m => m.category === 'xss')
        expect(xssMatches.length).toBeGreaterThan(0)

        const withProof = xssMatches.filter(m => m.proof != null)
        expect(withProof.length).toBeGreaterThan(0)

        const proof = withProof[0].proof!
        expect(proof.domain).toBe('xss')
    })

    it('detectDeep attaches proofs to path traversal matches', async () => {
        const { InvariantEngine } = await import('./invariant-engine.js')
        const engine = new InvariantEngine()
        const result = engine.detectDeep('../../etc/passwd', [])

        const pathMatches = result.matches.filter(m => m.category === 'path_traversal')
        expect(pathMatches.length).toBeGreaterThan(0)

        const withProof = pathMatches.filter(m => m.proof != null)
        expect(withProof.length).toBeGreaterThan(0)
    })

    it('complete proof acts as confidence floor', async () => {
        const { InvariantEngine } = await import('./invariant-engine.js')
        const engine = new InvariantEngine()
        // Classic SQL injection with all 3 algebraic phases
        const result = engine.detectDeep("' OR 1=1 --", [])

        const sqlWithCompleteProof = result.matches.filter(
            m => m.category === 'sqli' && m.proof?.isComplete,
        )

        for (const match of sqlWithCompleteProof) {
            // Confidence must be at least as high as the proof's structural confidence
            expect(match.confidence).toBeGreaterThanOrEqual(match.proof!.proofConfidence * 0.99)
        }
    })

    it('proof steps are sorted by offset', async () => {
        const { InvariantEngine } = await import('./invariant-engine.js')
        const engine = new InvariantEngine()
        const result = engine.detectDeep("' OR 1=1 --", [])

        const withProof = result.matches.filter(m => m.proof != null)
        for (const match of withProof) {
            const offsets = match.proof!.steps.map(s => s.offset)
            for (let i = 1; i < offsets.length; i++) {
                expect(offsets[i]).toBeGreaterThanOrEqual(offsets[i - 1])
            }
        }
    })
})
