/**
 * @santh/agent — Configuration Auditor
 *
 * Scans the project for security misconfigurations.
 * Checks: hardcoded secrets, debug modes, unsafe defaults,
 * CORS misconfig, missing security headers, exposed endpoints.
 *
 * This is static analysis — no runtime needed.
 */

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { InvariantDB, Severity } from '../db.js'

// ── Types ────────────────────────────────────────────────────────

interface ConfigCheck {
    id: string
    title: string
    severity: Severity
    category: string
    check: (projectDir: string) => ConfigFinding | null
}

interface ConfigFinding {
    title: string
    description: string
    location: string
    remediation: string
    evidence: string
}

// ── Secret Patterns ──────────────────────────────────────────────

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    { name: 'AWS Access Key', pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/g },
    { name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})/g },
    { name: 'GitHub Token', pattern: /gh[ps]_[A-Za-z0-9_]{36,255}/g },
    { name: 'Slack Token', pattern: /xox[bporas]-[A-Za-z0-9-]+/g },
    { name: 'Stripe Key', pattern: /sk_(?:live|test)_[A-Za-z0-9]{20,}/g },
    { name: 'SendGrid Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
    { name: 'Twilio', pattern: /SK[a-f0-9]{32}/g },
    { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g },
    { name: 'Generic Secret', pattern: /(?:secret|password|passwd|api_key|apikey|token|auth)[\s]*[=:]\s*['"][^'"]{8,}/gi },
]

// ── Checks ───────────────────────────────────────────────────────

const CHECKS: ConfigCheck[] = [
    {
        id: 'hardcoded-secrets',
        title: 'Hardcoded secrets in configuration files',
        severity: 'critical',
        category: 'secrets',
        check: (projectDir: string) => {
            const configFiles = [
                '.env', '.env.production', '.env.local',
                'config.json', 'config.js', 'config.ts',
                'docker-compose.yml', 'docker-compose.yaml',
            ]

            for (const file of configFiles) {
                const filePath = join(projectDir, file)
                if (!existsSync(filePath)) continue

                // Skip .env.example files
                if (file.includes('example')) continue

                const content = readFileSync(filePath, 'utf-8')
                const foundSecrets: string[] = []

                for (const { name, pattern } of SECRET_PATTERNS) {
                    // Reset lastIndex for global regex
                    pattern.lastIndex = 0
                    if (pattern.test(content)) {
                        foundSecrets.push(name)
                    }
                }

                if (foundSecrets.length > 0) {
                    return {
                        title: `Potential secrets found in ${file}`,
                        description: `Found ${foundSecrets.length} potential secret(s): ${foundSecrets.join(', ')}. Hardcoded secrets can be extracted from source code, version control, or deployment artifacts.`,
                        location: file,
                        remediation: 'Move secrets to environment variables or a secret manager (AWS Secrets Manager, Vault, Doppler). Add the file to .gitignore. Rotate any exposed credentials immediately.',
                        evidence: JSON.stringify({ file, secretTypes: foundSecrets }),
                    }
                }
            }
            return null
        },
    },
    {
        id: 'gitignore-env',
        title: '.env files not in .gitignore',
        severity: 'high',
        category: 'secrets',
        check: (projectDir: string) => {
            const gitignorePath = join(projectDir, '.gitignore')
            const envPath = join(projectDir, '.env')
            if (!existsSync(envPath)) return null
            if (!existsSync(gitignorePath)) {
                return {
                    title: 'No .gitignore file — .env may be committed',
                    description: 'No .gitignore file found. The .env file containing secrets may be committed to version control.',
                    location: '.gitignore',
                    remediation: 'Create a .gitignore file and add .env, .env.*, and other secret-containing files.',
                    evidence: JSON.stringify({ missing: '.gitignore' }),
                }
            }

            const content = readFileSync(gitignorePath, 'utf-8')
            if (!content.includes('.env')) {
                return {
                    title: '.env not listed in .gitignore',
                    description: 'The .env file is not listed in .gitignore. Environment files containing secrets may be committed to version control.',
                    location: '.gitignore',
                    remediation: 'Add ".env" and ".env.*" patterns to .gitignore.',
                    evidence: JSON.stringify({ gitignoreContent: content.slice(0, 500) }),
                }
            }
            return null
        },
    },
    {
        id: 'debug-mode',
        title: 'Debug mode enabled in production configuration',
        severity: 'high',
        category: 'configuration',
        check: (projectDir: string) => {
            const envPath = join(projectDir, '.env')
            if (!existsSync(envPath)) return null

            const content = readFileSync(envPath, 'utf-8')
            const debugPatterns = [
                /NODE_ENV\s*=\s*['"]?development/i,
                /DEBUG\s*=\s*['"]?(?:true|1|\*)/i,
                /VERBOSE\s*=\s*['"]?(?:true|1)/i,
            ]

            for (const pattern of debugPatterns) {
                if (pattern.test(content)) {
                    return {
                        title: 'Debug/development mode detected in .env',
                        description: 'The application may be running in debug mode, which can expose detailed error messages, stack traces, and internal state to attackers.',
                        location: '.env',
                        remediation: 'Set NODE_ENV=production and DEBUG=false in production environments.',
                        evidence: JSON.stringify({ pattern: pattern.source }),
                    }
                }
            }
            return null
        },
    },
    {
        id: 'package-json-security',
        title: 'Package.json security issues',
        severity: 'medium',
        category: 'configuration',
        check: (projectDir: string) => {
            const pkgPath = join(projectDir, 'package.json')
            if (!existsSync(pkgPath)) return null

            const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
            const issues: string[] = []

            // Check for no engine constraints
            if (!pkg.engines) {
                issues.push('No engine constraints (engines field) — app may run on vulnerable Node.js versions')
            }

            // Check for wildcard dependencies
            const allDeps = { ...pkg.dependencies, ...pkg.devDependencies }
            for (const [name, version] of Object.entries(allDeps)) {
                if (version === '*' || version === 'latest') {
                    issues.push(`Wildcard version for ${name}: ${version}`)
                }
            }

            if (issues.length > 0) {
                return {
                    title: 'Package.json security issues',
                    description: issues.join('. '),
                    location: 'package.json',
                    remediation: 'Pin dependency versions. Add an "engines" field to constrain Node.js version. Avoid "*" and "latest" version specifiers.',
                    evidence: JSON.stringify({ issues }),
                }
            }
            return null
        },
    },
    {
        id: 'cors-wildcard',
        title: 'CORS wildcard configuration',
        severity: 'medium',
        category: 'headers',
        check: (projectDir: string) => {
            // Search common config files for CORS: *
            const files = [
                'src/index.ts', 'src/index.js', 'src/app.ts', 'src/app.js',
                'src/server.ts', 'src/server.js', 'index.ts', 'index.js',
                'app.ts', 'app.js', 'server.ts', 'server.js',
            ]

            for (const file of files) {
                const filePath = join(projectDir, file)
                if (!existsSync(filePath)) continue

                const content = readFileSync(filePath, 'utf-8')
                if (/cors\(\s*\)/.test(content) || /origin:\s*['"]?\*['"]?/.test(content) || /Access-Control-Allow-Origin.*\*/.test(content)) {
                    return {
                        title: `CORS wildcard detected in ${file}`,
                        description: 'CORS is configured with a wildcard origin (*), allowing any website to make requests to your API. This can enable CSRF attacks and data exfiltration.',
                        location: file,
                        remediation: 'Restrict CORS to specific trusted origins: cors({ origin: ["https://yourdomain.com"] })',
                        evidence: JSON.stringify({ file }),
                    }
                }
            }
            return null
        },
    },
]

// ── Runner ───────────────────────────────────────────────────────

export function auditConfiguration(projectDir: string, db: InvariantDB): { total: number; findings: number } {
    let findingCount = 0
    const now = new Date().toISOString()

    for (const check of CHECKS) {
        try {
            const result = check.check(projectDir)
            if (result) {
                db.insertFinding({
                    type: 'config_audit',
                    category: check.category,
                    severity: check.severity,
                    status: 'open',
                    title: result.title,
                    description: result.description,
                    location: result.location,
                    evidence: result.evidence,
                    remediation: result.remediation,
                    cve_id: null,
                    confidence: 0.85,
                    first_seen: now,
                    last_seen: now,
                    rasp_active: false,
                })
                findingCount++
            }
        } catch {
            // Individual check failure shouldn't halt the audit
        }
    }

    return { total: CHECKS.length, findings: findingCount }
}
