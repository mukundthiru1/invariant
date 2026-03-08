/**
 * INVARIANT — Response Security Audit (Layer 7)
 *
 * After fetching from origin, inspect the response for:
 *   - Missing/weak security headers
 *   - Version information leaks
 *   - Insecure cookie configurations
 *   - CORS misconfigurations
 *
 * This is the instant-value feature: deploy INVARIANT,
 * immediately see what's wrong with your security posture.
 */

// ── Posture Finding ───────────────────────────────────────────────

export interface PostureFinding {
    /** What was found */
    finding: string
    /** Severity level */
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    /** Category for grouping */
    category: 'header' | 'version_leak' | 'cookie' | 'cors' | 'content'
    /** Specific remediation advice */
    remediation: string
}

export interface PostureReport {
    /** Subscriber domain */
    domain: string
    /** Overall posture score (0-100, higher = more secure) */
    score: number
    /** Letter grade */
    grade: 'A' | 'B' | 'C' | 'D' | 'F'
    /** Grouped findings by severity */
    findings: {
        critical: string[]
        high: string[]
        medium: string[]
        low: string[]
        info: string[]
    }
    /** Top remediation actions */
    recommendations: string[]
    /** When the last audit was performed */
    lastAudit: string
    /** How many unique path patterns were sampled */
    sampledPaths: number
}


// ── Security Header Checks ───────────────────────────────────────

interface HeaderCheck {
    header: string
    category: PostureFinding['category']
    check: (value: string | null) => PostureFinding | null
}

const HEADER_CHECKS: HeaderCheck[] = [
    // ── Strict-Transport-Security ──────────────────────────────
    {
        header: 'strict-transport-security',
        category: 'header',
        check: (value) => {
            if (!value) {
                return {
                    finding: 'Missing Strict-Transport-Security header — browsers will accept HTTP connections',
                    severity: 'critical',
                    category: 'header',
                    remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                }
            }
            const maxAge = parseInt(value.match(/max-age=(\d+)/i)?.[1] ?? '0')
            if (maxAge < 31536000) {
                return {
                    finding: `HSTS max-age too short (${maxAge}s, need ≥31536000)`,
                    severity: 'medium',
                    category: 'header',
                    remediation: 'Set max-age to at least 31536000 (1 year)',
                }
            }
            if (!/includeSubDomains/i.test(value)) {
                return {
                    finding: 'HSTS missing includeSubDomains — subdomains not protected',
                    severity: 'medium',
                    category: 'header',
                    remediation: 'Add includeSubDomains to HSTS header',
                }
            }
            return null
        },
    },

    // ── Content-Security-Policy ────────────────────────────────
    {
        header: 'content-security-policy',
        category: 'header',
        check: (value) => {
            if (!value) {
                return {
                    finding: 'No Content-Security-Policy — XSS attacks have no browser mitigation',
                    severity: 'high',
                    category: 'header',
                    remediation: "Add Content-Security-Policy with at minimum default-src 'self'",
                }
            }
            const issues: string[] = []
            if (/unsafe-inline/i.test(value) && !/nonce-/i.test(value)) {
                issues.push("CSP allows 'unsafe-inline' without nonce (XSS bypass)")
            }
            if (/unsafe-eval/i.test(value)) {
                issues.push("CSP allows 'unsafe-eval' (code injection vector)")
            }
            if (/\*\s/i.test(value) || /default-src\s+\*/i.test(value)) {
                issues.push('CSP uses wildcard (*) — overly permissive')
            }
            if (issues.length > 0) {
                return {
                    finding: issues.join('; '),
                    severity: 'medium',
                    category: 'header',
                    remediation: 'Tighten CSP: remove unsafe-inline/eval, use nonces, restrict sources',
                }
            }
            return null
        },
    },

    // ── X-Frame-Options ────────────────────────────────────────
    {
        header: 'x-frame-options',
        category: 'header',
        check: (value) => {
            if (!value) {
                return {
                    finding: 'No X-Frame-Options — vulnerable to clickjacking',
                    severity: 'medium',
                    category: 'header',
                    remediation: 'Add X-Frame-Options: DENY (or SAMEORIGIN if framing needed)',
                }
            }
            return null
        },
    },

    // ── X-Content-Type-Options ─────────────────────────────────
    {
        header: 'x-content-type-options',
        category: 'header',
        check: (value) => {
            if (!value || value.toLowerCase() !== 'nosniff') {
                return {
                    finding: 'No X-Content-Type-Options: nosniff — MIME sniffing attacks possible',
                    severity: 'medium',
                    category: 'header',
                    remediation: 'Add X-Content-Type-Options: nosniff',
                }
            }
            return null
        },
    },

    // ── Referrer-Policy ────────────────────────────────────────
    {
        header: 'referrer-policy',
        category: 'header',
        check: (value) => {
            if (!value) {
                return {
                    finding: 'No Referrer-Policy — full URLs may leak to third parties',
                    severity: 'low',
                    category: 'header',
                    remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin',
                }
            }
            if (/^unsafe-url$/i.test(value)) {
                return {
                    finding: 'Referrer-Policy set to unsafe-url — full URLs sent with all requests',
                    severity: 'medium',
                    category: 'header',
                    remediation: 'Change Referrer-Policy to strict-origin-when-cross-origin or no-referrer',
                }
            }
            return null
        },
    },

    // ── Permissions-Policy ─────────────────────────────────────
    {
        header: 'permissions-policy',
        category: 'header',
        check: (value) => {
            if (!value) {
                return {
                    finding: 'No Permissions-Policy — browser features not restricted',
                    severity: 'low',
                    category: 'header',
                    remediation: 'Add Permissions-Policy to restrict camera, microphone, geolocation, etc.',
                }
            }
            return null
        },
    },

    // ── Server header (version leak) ───────────────────────────
    {
        header: 'server',
        category: 'version_leak',
        check: (value) => {
            if (!value) return null
            // Check if it contains version numbers
            if (/\d+\.\d+/i.test(value)) {
                return {
                    finding: `Server header leaks version: "${value}"`,
                    severity: 'high',
                    category: 'version_leak',
                    remediation: 'Remove or genericize Server header — remove version numbers',
                }
            }
            return null
        },
    },

    // ── X-Powered-By (version leak) ───────────────────────────
    {
        header: 'x-powered-by',
        category: 'version_leak',
        check: (value) => {
            if (!value) return null
            return {
                finding: `X-Powered-By header leaks technology: "${value}"`,
                severity: 'medium',
                category: 'version_leak',
                remediation: 'Remove X-Powered-By header entirely',
            }
        },
    },

    // ── X-AspNet-Version ──────────────────────────────────────
    {
        header: 'x-aspnet-version',
        category: 'version_leak',
        check: (value) => {
            if (!value) return null
            return {
                finding: `X-AspNet-Version header leaks: "${value}"`,
                severity: 'medium',
                category: 'version_leak',
                remediation: 'Remove X-AspNet-Version via web.config: <httpRuntime enableVersionHeader="false"/>',
            }
        },
    },

    // ── X-AspNetMvc-Version ───────────────────────────────────
    {
        header: 'x-aspnetmvc-version',
        category: 'version_leak',
        check: (value) => {
            if (!value) return null
            return {
                finding: `X-AspNetMvc-Version header leaks: "${value}"`,
                severity: 'medium',
                category: 'version_leak',
                remediation: 'Remove via MvcHandler.DisableMvcResponseHeader = true in Application_Start',
            }
        },
    },

    // ── CORS: Access-Control-Allow-Origin ──────────────────────
    {
        header: 'access-control-allow-origin',
        category: 'cors',
        check: (value) => {
            if (!value) return null
            if (value === '*') {
                return {
                    finding: 'CORS allows all origins (Access-Control-Allow-Origin: *)',
                    severity: 'high',
                    category: 'cors',
                    remediation: 'Restrict CORS to specific trusted origins, not wildcard',
                }
            }
            return null
        },
    },
]


// ── Cookie Security Audit ─────────────────────────────────────────

interface CookieFinding {
    name: string
    issues: string[]
}

function auditCookies(headers: Headers): PostureFinding[] {
    const findings: PostureFinding[] = []
    const setCookies = typeof (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie === 'function'
        ? (headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
        : []

    // Fallback: some implementations don't support getAll
    if (setCookies.length === 0) {
        const single = headers.get('set-cookie')
        if (single) setCookies.push(single)
    }

    const cookieIssues: CookieFinding[] = []

    for (const cookie of setCookies) {
        const nameMatch = cookie.match(/^([^=]+)=/)
        if (!nameMatch) continue
        const name = nameMatch[1].trim()
        const lower = cookie.toLowerCase()
        const issues: string[] = []

        if (!lower.includes('secure')) {
            issues.push('missing Secure flag')
        }
        if (!lower.includes('httponly')) {
            // Session/auth cookies without HttpOnly are critical
            const isSession = /sess|token|auth|jwt|sid|login|remember/i.test(name)
            if (isSession) {
                issues.push('missing HttpOnly (session cookie)')
            } else {
                issues.push('missing HttpOnly')
            }
        }
        if (!lower.includes('samesite')) {
            issues.push('missing SameSite')
        }

        if (issues.length > 0) {
            cookieIssues.push({ name, issues })
        }
    }

    if (cookieIssues.length > 0) {
        // Group by issue type for cleaner reporting
        const noSecure = cookieIssues.filter(c => c.issues.some(i => i.includes('Secure')))
        const noHttpOnly = cookieIssues.filter(c => c.issues.some(i => i.includes('HttpOnly')))
        const noSameSite = cookieIssues.filter(c => c.issues.some(i => i.includes('SameSite')))
        const sessionIssues = cookieIssues.filter(c => c.issues.some(i => i.includes('session')))

        if (sessionIssues.length > 0) {
            findings.push({
                finding: `${sessionIssues.length} session cookie(s) missing HttpOnly: ${sessionIssues.map(c => c.name).join(', ')} — vulnerable to XSS cookie theft`,
                severity: 'critical',
                category: 'cookie',
                remediation: 'Set HttpOnly flag on all session/auth cookies',
            })
        }
        if (noSecure.length > 0) {
            findings.push({
                finding: `${noSecure.length} cookie(s) missing Secure flag`,
                severity: 'high',
                category: 'cookie',
                remediation: 'Set Secure flag on all cookies to prevent transmission over HTTP',
            })
        }
        if (noHttpOnly.length > noHttpOnly.filter(c => c.issues.some(i => i.includes('session'))).length) {
            const nonSession = noHttpOnly.filter(c => !c.issues.some(i => i.includes('session')))
            if (nonSession.length > 0) {
                findings.push({
                    finding: `${nonSession.length} cookie(s) missing HttpOnly flag`,
                    severity: 'medium',
                    category: 'cookie',
                    remediation: 'Set HttpOnly flag on cookies not needed by JavaScript',
                })
            }
        }
        if (noSameSite.length > 0) {
            findings.push({
                finding: `${noSameSite.length} cookie(s) missing SameSite attribute`,
                severity: 'medium',
                category: 'cookie',
                remediation: 'Set SameSite=Lax or SameSite=Strict on all cookies',
            })
        }
    }

    return findings
}


// ═══════════════════════════════════════════════════════════════════
// RESPONSE AUDITOR
// ═══════════════════════════════════════════════════════════════════

/**
 * Audits an HTTP response for security posture issues.
 * Lightweight — header inspection only, no body parsing.
 * Designed to run on every response without measurable latency impact.
 */
export class ResponseAuditor {
    /** Accumulated findings across all audited responses, keyed by finding string for dedup */
    private allFindings = new Map<string, PostureFinding>()
    /** Unique path patterns sampled */
    private sampledPaths = new Set<string>()
    /** Last audit timestamp */
    private lastAudit = ''
    /** Maximum unique findings to store (prevent unbounded growth) */
    private static readonly MAX_FINDINGS = 200
    /** Maximum unique paths to track */
    private static readonly MAX_PATHS = 500

    /**
     * Audit a response's security headers and cookies.
     * Call this after every fetch(origin) response.
     *
     * @param response The response from origin
     * @param normalizedPath The normalized request path (for dedup)
     * @returns Array of NEW findings discovered in this response
     */
    audit(response: Response, normalizedPath: string): PostureFinding[] {
        // Track paths for sampling count
        if (this.sampledPaths.size < ResponseAuditor.MAX_PATHS) {
            this.sampledPaths.add(normalizedPath)
        }

        this.lastAudit = new Date().toISOString()

        if (this.allFindings.size >= ResponseAuditor.MAX_FINDINGS) {
            return [] // Already have enough findings
        }

        const newFindings: PostureFinding[] = []
        const headers = response.headers

        // Run header checks
        for (const check of HEADER_CHECKS) {
            const value = headers.get(check.header)
            const finding = check.check(value)
            if (finding && !this.allFindings.has(finding.finding)) {
                this.allFindings.set(finding.finding, finding)
                newFindings.push(finding)
            }
        }

        // Audit cookies
        const cookieFindings = auditCookies(headers)
        for (const finding of cookieFindings) {
            if (!this.allFindings.has(finding.finding)) {
                this.allFindings.set(finding.finding, finding)
                newFindings.push(finding)
            }
        }

        // Check for CORS credential misconfiguration
        const corsOrigin = headers.get('access-control-allow-origin')
        const corsCredentials = headers.get('access-control-allow-credentials')
        if (corsOrigin && corsOrigin !== '*' && corsCredentials === 'true') {
            // Dynamic origin reflection with credentials is dangerous if not validated
            const finding: PostureFinding = {
                finding: 'CORS reflects origin with credentials enabled — verify origin validation',
                severity: 'medium',
                category: 'cors',
                remediation: 'Ensure Access-Control-Allow-Origin is validated against an allowlist, not reflected from request',
            }
            if (!this.allFindings.has(finding.finding)) {
                this.allFindings.set(finding.finding, finding)
                newFindings.push(finding)
            }
        }

        // Check for missing Content-Type
        if (!headers.get('content-type') && response.status === 200) {
            const finding: PostureFinding = {
                finding: 'Response missing Content-Type header — MIME sniffing risk',
                severity: 'low',
                category: 'content',
                remediation: 'Always set explicit Content-Type header on responses',
            }
            if (!this.allFindings.has(finding.finding)) {
                this.allFindings.set(finding.finding, finding)
                newFindings.push(finding)
            }
        }

        return newFindings
    }

    /**
     * Calculate posture score from accumulated findings.
     * Score starts at 100 and is reduced by findings.
     */
    calculateScore(): { score: number; grade: PostureReport['grade'] } {
        let score = 100

        for (const finding of this.allFindings.values()) {
            switch (finding.severity) {
                case 'critical': score -= 20; break
                case 'high': score -= 12; break
                case 'medium': score -= 6; break
                case 'low': score -= 3; break
                case 'info': score -= 1; break
            }
        }

        score = Math.max(0, Math.min(100, score))

        let grade: PostureReport['grade']
        if (score >= 90) grade = 'A'
        else if (score >= 75) grade = 'B'
        else if (score >= 60) grade = 'C'
        else if (score >= 40) grade = 'D'
        else grade = 'F'

        return { score, grade }
    }

    /**
     * Generate full posture report for the subscriber dashboard.
     */
    generateReport(domain: string): PostureReport {
        const { score, grade } = this.calculateScore()

        const findings: PostureReport['findings'] = {
            critical: [], high: [], medium: [], low: [], info: [],
        }

        for (const finding of this.allFindings.values()) {
            findings[finding.severity].push(finding.finding)
        }

        // Top recommendations: highest severity findings first
        const recommendations: string[] = []
        const sorted = [...this.allFindings.values()].sort((a, b) => {
            const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
            return order[a.severity] - order[b.severity]
        })
        for (const finding of sorted.slice(0, 10)) {
            recommendations.push(finding.remediation)
        }

        return {
            domain,
            score,
            grade,
            findings,
            recommendations,
            lastAudit: this.lastAudit || new Date().toISOString(),
            sampledPaths: this.sampledPaths.size,
        }
    }

    /**
     * Get all findings as a flat array for signal reporting.
     */
    getFindings(): PostureFinding[] {
        return [...this.allFindings.values()]
    }

    /** Number of unique findings */
    get findingCount(): number {
        return this.allFindings.size
    }
}
