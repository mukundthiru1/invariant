/**
 * INVARIANT v4 — Reactivation Engine (Phase 6)
 *
 * Core insight: Security teams patch the DELIVERY MECHANISM or
 * revoke the PRIVILEGE, but rarely fix the underlying vulnerability.
 * Misconfigurations REACTIVATE "patched" vulnerabilities by
 * providing alternative delivery mechanisms or privilege paths.
 *
 * This engine cross-references posture findings (L7) with
 * vulnerability classes (CWE) to identify reactivation vectors.
 *
 * Example:
 *   Missing CSP header + CWE-79 (XSS) in any dependency
 *   = The browser has no script execution restriction
 *   = XSS vulnerabilities that were "mitigated by CSP" are now exploitable
 *   = Severity upgrade: medium → high
 *
 * The engine is STATELESS and DETERMINISTIC — given the same
 * posture findings and tech stack, it always produces the same
 * reactivation analysis. No AI, no network calls, pure logic.
 */


// ── Posture Condition ────────────────────────────────────────────
// These map directly to what L7 ResponseAuditor detects.
// Each condition is a CONCRETE misconfiguration, not a CWE.

export type PostureCondition =
    | 'missing_hsts'
    | 'weak_hsts'
    | 'missing_csp'
    | 'weak_csp_unsafe_inline'
    | 'weak_csp_unsafe_eval'
    | 'weak_csp_wildcard'
    | 'missing_x_frame_options'
    | 'missing_x_content_type_options'
    | 'missing_referrer_policy'
    | 'missing_permissions_policy'
    | 'version_leak_server'
    | 'version_leak_powered_by'
    | 'version_leak_aspnet'
    | 'cors_wildcard'
    | 'cors_credentials_reflect'
    | 'cookie_missing_secure'
    | 'cookie_missing_httponly'
    | 'cookie_missing_httponly_session'
    | 'cookie_missing_samesite'
    | 'missing_content_type'


// ── Reactivation Rule ────────────────────────────────────────────

export interface ReactivationRule {
    /** Unique rule identifier */
    readonly id: string

    /** The misconfiguration that enables reactivation */
    readonly condition: PostureCondition

    /** CWE classes that this misconfiguration reactivates */
    readonly reactivates_cwes: string[]

    /** Broader vulnerability categories affected (for sensors without CWE data) */
    readonly reactivates_categories: string[]

    /**
     * WHY this reactivation works — the causal chain.
     * Not "what" but "why the patch stops working."
     */
    readonly mechanism: string

    /**
     * How much worse the misconfiguration makes matching vulnerabilities.
     * Used to upgrade severity in advisories.
     */
    readonly severity_boost: 'critical_upgrade' | 'high_upgrade' | 'context_upgrade'

    /**
     * What an attacker gains from this reactivation.
     * Concrete, not abstract.
     */
    readonly attacker_gains: string

    /**
     * The ACTUAL fix — not "add the header" but what
     * the header protects against and why it matters.
     */
    readonly root_fix: string
}


// ── Reactivation Match ───────────────────────────────────────────

export interface ReactivationMatch {
    /** Which rule triggered */
    rule_id: string
    /** The misconfiguration that enables this */
    condition: PostureCondition
    /** Which CWEs are reactivated */
    reactivated_cwes: string[]
    /** Broader categories */
    reactivated_categories: string[]
    /** The causal mechanism */
    mechanism: string
    /** Severity impact */
    severity_boost: ReactivationRule['severity_boost']
    /** What the attacker gains */
    attacker_gains: string
    /** How to actually fix it */
    root_fix: string
}


// ═══════════════════════════════════════════════════════════════════
// REACTIVATION RULES
//
// Each rule encodes a CAUSAL relationship:
//   misconfiguration → enables → vulnerability class
//
// Ordered by severity of reactivation impact.
// ═══════════════════════════════════════════════════════════════════

const REACTIVATION_RULES: ReactivationRule[] = [

    // ── HSTS ──────────────────────────────────────────────────────

    {
        id: 'react-hsts-tls-downgrade',
        condition: 'missing_hsts',
        reactivates_cwes: ['CWE-319', 'CWE-523', 'CWE-757'],
        reactivates_categories: ['tls_downgrade', 'credential_theft', 'mitm'],
        mechanism:
            'Without HSTS, the browser accepts HTTP connections for the first visit ' +
            'and on every cache expiry. An active network attacker (public WiFi, ' +
            'compromised router, BGP hijack) can intercept the initial HTTP request ' +
            'before the 301→HTTPS redirect and serve a malicious response or ' +
            'downgrade the connection entirely. TLS-related CVEs that require ' +
            'MitM position become exploitable because the attacker already has it.',
        severity_boost: 'critical_upgrade',
        attacker_gains:
            'Session cookies on first HTTP request, credential interception, ' +
            'response injection, MitM position for TLS downgrade attacks',
        root_fix:
            'Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. ' +
            'Submit to the HSTS preload list (hstspreload.org) to protect first visits.',
    },

    {
        id: 'react-hsts-cookie-theft',
        condition: 'missing_hsts',
        reactivates_cwes: ['CWE-614', 'CWE-311'],
        reactivates_categories: ['session_hijack', 'cookie_theft'],
        mechanism:
            'Even with Secure flag on cookies, the initial HTTP request (before redirect) ' +
            'can be intercepted. If any cookie lacks the Secure flag, it transmits over ' +
            'HTTP. Combined with missing HSTS, the attacker forces an HTTP connection ' +
            'to capture session tokens. Session fixation CVEs in the application become ' +
            'exploitable because the attacker can set cookies via HTTP response.',
        severity_boost: 'high_upgrade',
        attacker_gains:
            'Session tokens, authentication cookies, CSRF tokens visible in plaintext',
        root_fix:
            'Deploy HSTS AND set Secure flag on ALL cookies. Neither alone is sufficient.',
    },

    // ── CSP ───────────────────────────────────────────────────────

    {
        id: 'react-csp-xss',
        condition: 'missing_csp',
        reactivates_cwes: ['CWE-79', 'CWE-80', 'CWE-83', 'CWE-87'],
        reactivates_categories: ['xss', 'html_injection', 'script_injection'],
        mechanism:
            'Without Content-Security-Policy, the browser places no restrictions on ' +
            'script execution sources. Any XSS vulnerability — reflected, stored, or ' +
            'DOM-based — executes with full capability: exfiltrate cookies, redirect to ' +
            'phishing, crypto-mine, install keyloggers. CSP is the browser-side ' +
            'containment layer. Without it, every XSS CVE in every dependency ' +
            '(jQuery, React, lodash template, etc.) has maximum impact.',
        severity_boost: 'critical_upgrade',
        attacker_gains:
            'Unrestricted script execution in victim browser: cookie theft, ' +
            'credential harvesting, session riding, cryptojacking, DOM manipulation',
        root_fix:
            "Deploy Content-Security-Policy with default-src 'self'; script-src 'self' " +
            "with nonces for inline scripts. Never use 'unsafe-inline' without nonces.",
    },

    {
        id: 'react-csp-inline-xss',
        condition: 'weak_csp_unsafe_inline',
        reactivates_cwes: ['CWE-79', 'CWE-80'],
        reactivates_categories: ['xss', 'script_injection'],
        mechanism:
            "CSP with 'unsafe-inline' without nonces is equivalent to no CSP for XSS. " +
            "The attacker's injected <script> tag or event handler executes because " +
            "the policy explicitly allows inline scripts. This is the most common CSP " +
            "misconfiguration — teams add CSP for compliance but 'unsafe-inline' " +
            'negates its XSS protection entirely.',
        severity_boost: 'high_upgrade',
        attacker_gains: 'Inline script execution despite CSP deployment',
        root_fix:
            "Remove 'unsafe-inline' from script-src. Use nonces or hashes for " +
            'legitimate inline scripts. Refactor inline event handlers to addEventListener.',
    },

    {
        id: 'react-csp-eval-injection',
        condition: 'weak_csp_unsafe_eval',
        reactivates_cwes: ['CWE-94', 'CWE-95'],
        reactivates_categories: ['code_injection', 'template_injection'],
        mechanism:
            "CSP with 'unsafe-eval' allows eval(), Function(), setTimeout(string), " +
            'and new Function(). Any code injection vulnerability that constructs ' +
            'JavaScript strings for evaluation succeeds. Template injection (SSTI) ' +
            'attacks that compile to eval() calls bypass the CSP entirely.',
        severity_boost: 'high_upgrade',
        attacker_gains: 'Dynamic code execution via eval/Function despite CSP',
        root_fix:
            "Remove 'unsafe-eval' from script-src. Replace eval() with JSON.parse() or " +
            'structured alternatives. Use template literal functions instead of string compilation.',
    },

    // ── X-Frame-Options ───────────────────────────────────────────

    {
        id: 'react-xfo-clickjack',
        condition: 'missing_x_frame_options',
        reactivates_cwes: ['CWE-1021', 'CWE-451'],
        reactivates_categories: ['clickjacking', 'ui_redress'],
        mechanism:
            'Without X-Frame-Options (or CSP frame-ancestors), the page can be ' +
            'embedded in an attacker-controlled iframe. The attacker overlays ' +
            'invisible buttons/forms over the framed page, tricking users into ' +
            'clicking actions they cannot see. State-changing actions (password ' +
            'change, fund transfer, permission grants) are exploitable without ' +
            'the user knowing.',
        severity_boost: 'high_upgrade',
        attacker_gains:
            'User performs actions on the real site while believing they are ' +
            'interacting with an unrelated page. One-click account takeover ' +
            'if combined with password reset flow.',
        root_fix:
            'Set X-Frame-Options: DENY (or SAMEORIGIN if iframing is needed). ' +
            "Prefer CSP frame-ancestors 'none' for modern browsers.",
    },

    // ── X-Content-Type-Options ────────────────────────────────────

    {
        id: 'react-xcto-mime-sniff',
        condition: 'missing_x_content_type_options',
        reactivates_cwes: ['CWE-430', 'CWE-79'],
        reactivates_categories: ['mime_sniffing', 'xss'],
        mechanism:
            'Without X-Content-Type-Options: nosniff, the browser may MIME-sniff ' +
            'responses and interpret non-script content as JavaScript. An attacker ' +
            'who controls uploaded content (images, text files, CSVs) can craft ' +
            'files that the browser interprets as scripts. File upload ' +
            'vulnerabilities that were "safe because they only allow images" ' +
            'become XSS vectors.',
        severity_boost: 'context_upgrade',
        attacker_gains: 'Script execution through uploaded non-script files',
        root_fix: 'Set X-Content-Type-Options: nosniff on all responses.',
    },

    // ── CORS ──────────────────────────────────────────────────────

    {
        id: 'react-cors-wildcard-data-theft',
        condition: 'cors_wildcard',
        reactivates_cwes: ['CWE-346', 'CWE-942'],
        reactivates_categories: ['data_theft', 'csrf', 'cross_origin'],
        mechanism:
            'CORS Access-Control-Allow-Origin: * allows any website to make ' +
            'cross-origin requests and read the response. API endpoints that ' +
            'return user-specific data (profile, settings, tokens) are now ' +
            'readable from any malicious site the user visits. CSRF protections ' +
            'that rely on same-origin policy are bypassed.',
        severity_boost: 'high_upgrade',
        attacker_gains:
            'Read user data cross-origin, extract tokens, CSRF bypass, ' +
            'data exfiltration from authenticated API endpoints',
        root_fix:
            'Restrict Access-Control-Allow-Origin to specific trusted domains. ' +
            'Never use wildcard (*) on endpoints that return user-specific data.',
    },

    {
        id: 'react-cors-creds-takeover',
        condition: 'cors_credentials_reflect',
        reactivates_cwes: ['CWE-346', 'CWE-352'],
        reactivates_categories: ['account_takeover', 'csrf', 'data_theft'],
        mechanism:
            'CORS with credentials: true and a reflected origin means any site ' +
            'can make authenticated requests and read responses. This is ' +
            'effectively universal CSRF + data theft. The browser sends cookies ' +
            'and the response is readable cross-origin. Any endpoint that ' +
            'changes state or returns sensitive data is exploitable.',
        severity_boost: 'critical_upgrade',
        attacker_gains:
            'Full authenticated API access from any malicious site. ' +
            'Read all user data, perform state-changing actions, account takeover.',
        root_fix:
            'Validate the Origin header against a strict allowlist. Never reflect ' +
            'the Origin header into Access-Control-Allow-Origin without validation.',
    },

    // ── Cookie Flags ──────────────────────────────────────────────

    {
        id: 'react-cookie-httponly-xss',
        condition: 'cookie_missing_httponly_session',
        reactivates_cwes: ['CWE-79', 'CWE-1004'],
        reactivates_categories: ['session_hijack', 'xss', 'cookie_theft'],
        mechanism:
            'Session cookies without HttpOnly are readable by JavaScript. Any XSS ' +
            'vulnerability — even a minor reflected XSS in a non-critical page — ' +
            'becomes a session hijacking vector. The attacker injects ' +
            'document.cookie and exfiltrates the session token. Even "low-severity" ' +
            'XSS CVEs become critical when session cookies are accessible to scripts.',
        severity_boost: 'critical_upgrade',
        attacker_gains:
            'Session token theft via any XSS → full account takeover. ' +
            'Converts low-severity XSS into critical session hijacking.',
        root_fix:
            'Set HttpOnly flag on ALL session and authentication cookies. ' +
            'No legitimate client-side JavaScript needs to read session tokens.',
    },

    {
        id: 'react-cookie-samesite-csrf',
        condition: 'cookie_missing_samesite',
        reactivates_cwes: ['CWE-352'],
        reactivates_categories: ['csrf', 'session_riding'],
        mechanism:
            'Without SameSite attribute, cookies are sent with all cross-origin ' +
            'requests (top-level navigations AND subresource requests in older ' +
            'browsers). CSRF attacks that were "mitigated" by not having direct ' +
            'form submission vectors become exploitable again because the browser ' +
            'still attaches cookies to cross-origin form posts and navigations.',
        severity_boost: 'high_upgrade',
        attacker_gains:
            'Cross-site request forgery for any state-changing endpoint. ' +
            'Fund transfers, password changes, admin actions via crafted pages.',
        root_fix:
            'Set SameSite=Lax (minimum) or SameSite=Strict on all cookies. ' +
            'Additionally implement CSRF tokens — SameSite alone has edge cases.',
    },

    {
        id: 'react-cookie-secure-interception',
        condition: 'cookie_missing_secure',
        reactivates_cwes: ['CWE-614', 'CWE-319'],
        reactivates_categories: ['credential_theft', 'session_hijack'],
        mechanism:
            'Cookies without the Secure flag transmit over HTTP connections. ' +
            'Combined with missing HSTS (or even with HSTS before preload ' +
            'list inclusion), the initial HTTP request before redirect sends ' +
            'cookies in plaintext. Network-level attackers intercept sessions ' +
            'on any unencrypted hop.',
        severity_boost: 'high_upgrade',
        attacker_gains:
            'Cookie interception on any HTTP connection — public WiFi, ' +
            'compromised network, HTTP→HTTPS redirect window',
        root_fix:
            'Set Secure flag on ALL cookies. Deploy HSTS with preload.',
    },

    // ── Version Leaks ─────────────────────────────────────────────

    {
        id: 'react-version-targeted-exploit',
        condition: 'version_leak_server',
        reactivates_cwes: ['CWE-200', 'CWE-497'],
        reactivates_categories: ['reconnaissance', 'targeted_exploit'],
        mechanism:
            'Server header with version number tells the attacker exactly which ' +
            'CVEs apply. Without the version, the attacker must fingerprint or ' +
            'try exploits blindly (noisy, detectable). With the version, they ' +
            'select the exact exploit for that release. Version-specific CVEs ' +
            'that would require guessing become directly targetable.',
        severity_boost: 'context_upgrade',
        attacker_gains:
            'Precise version identification → targeted CVE selection → ' +
            'single-shot exploitation instead of noisy scanning',
        root_fix:
            'Remove version numbers from Server header. ' +
            'Configure web server to send generic identifier only.',
    },

    {
        id: 'react-poweredby-stack-fingerprint',
        condition: 'version_leak_powered_by',
        reactivates_cwes: ['CWE-200', 'CWE-497'],
        reactivates_categories: ['reconnaissance', 'targeted_exploit'],
        mechanism:
            'X-Powered-By reveals the backend technology and often the version. ' +
            'Attackers use this to select technology-specific payloads: PHP ' +
            'deserialization for PHP apps, JNDI injection for Java apps, ' +
            'template injection for Python apps. Reduces attack surface ' +
            'enumeration from hours to seconds.',
        severity_boost: 'context_upgrade',
        attacker_gains:
            'Backend technology identification → technology-specific ' +
            'attack selection → skips irrelevant payloads',
        root_fix:
            'Remove X-Powered-By header entirely. In Express: app.disable("x-powered-by"). ' +
            'In PHP: expose_php = Off in php.ini.',
    },
]


// ═══════════════════════════════════════════════════════════════════
// POSTURE CONDITION DETECTOR
//
// Maps the human-readable L7 finding strings to machine-readable
// PostureCondition identifiers. This is the bridge between
// ResponseAuditor output and the reactivation engine.
// ═══════════════════════════════════════════════════════════════════

/**
 * Detect posture conditions from L7 findings.
 *
 * The ResponseAuditor produces PostureFinding objects with
 * human-readable `finding` strings. We need to classify those
 * into machine-readable PostureCondition identifiers.
 *
 * Implementation: regex matching on finding strings.
 * This is intentionally loose — if the finding text changes
 * slightly in the ResponseAuditor, we still match.
 */
export function detectConditions(findings: Array<{ finding: string; severity: string; category: string }>): PostureCondition[] {
    const conditions: PostureCondition[] = []

    for (const f of findings) {
        const fl = f.finding.toLowerCase()

        // HSTS
        if (fl.includes('no hsts') || fl.includes('no strict-transport-security')) {
            conditions.push('missing_hsts')
        } else if (fl.includes('hsts') && (fl.includes('too short') || fl.includes('missing includesubdomains'))) {
            conditions.push('weak_hsts')
        }

        // CSP
        if (fl.includes('no content-security-policy') || (fl.includes('csp') === false && fl.includes('no csp'))) {
            conditions.push('missing_csp')
        }
        if (fl.includes('unsafe-inline') && !fl.includes('uses nonce') && !fl.includes('with nonce')) {
            conditions.push('weak_csp_unsafe_inline')
        }
        if (fl.includes('unsafe-eval')) {
            conditions.push('weak_csp_unsafe_eval')
        }
        if (fl.includes('wildcard') && fl.includes('csp')) {
            conditions.push('weak_csp_wildcard')
        }

        // X-Frame-Options
        if (fl.includes('no x-frame-options') || fl.includes('clickjacking')) {
            conditions.push('missing_x_frame_options')
        }

        // X-Content-Type-Options
        if (fl.includes('x-content-type-options') && fl.includes('nosniff')) {
            conditions.push('missing_x_content_type_options')
        }

        // Referrer-Policy
        if (fl.includes('no referrer-policy') || fl.includes('unsafe-url')) {
            conditions.push('missing_referrer_policy')
        }

        // Permissions-Policy
        if (fl.includes('no permissions-policy')) {
            conditions.push('missing_permissions_policy')
        }

        // Version leaks
        if (fl.includes('server header') && fl.includes('leak')) {
            conditions.push('version_leak_server')
        }
        if (fl.includes('x-powered-by') && fl.includes('leak')) {
            conditions.push('version_leak_powered_by')
        }
        if (fl.includes('x-aspnet') && fl.includes('leak')) {
            conditions.push('version_leak_aspnet')
        }

        // CORS
        if (fl.includes('cors') && fl.includes('all origins') && fl.includes('*')) {
            conditions.push('cors_wildcard')
        }
        if (fl.includes('cors') && fl.includes('credentials') && fl.includes('reflect')) {
            conditions.push('cors_credentials_reflect')
        }

        // Cookies
        if (fl.includes('cookie') && fl.includes('secure flag')) {
            conditions.push('cookie_missing_secure')
        }
        if (fl.includes('session cookie') && fl.includes('httponly')) {
            conditions.push('cookie_missing_httponly_session')
        } else if (fl.includes('cookie') && fl.includes('httponly')) {
            conditions.push('cookie_missing_httponly')
        }
        if (fl.includes('cookie') && fl.includes('samesite')) {
            conditions.push('cookie_missing_samesite')
        }

        // Content-Type
        if (fl.includes('missing content-type')) {
            conditions.push('missing_content_type')
        }
    }

    // Deduplicate
    return [...new Set(conditions)]
}


// ═══════════════════════════════════════════════════════════════════
// REACTIVATION ENGINE
// ═══════════════════════════════════════════════════════════════════

export class ReactivationEngine {
    private readonly rules: ReactivationRule[]

    constructor() {
        this.rules = REACTIVATION_RULES
    }

    /**
     * Given a set of posture conditions (from L7 findings),
     * compute all reactivation vectors.
     *
     * Pure function: no side effects, deterministic output.
     *
     * @param conditions - PostureConditions detected from L7 findings
     * @returns All matching reactivation vectors
     */
    analyze(conditions: PostureCondition[]): ReactivationMatch[] {
        const conditionSet = new Set(conditions)
        const matches: ReactivationMatch[] = []

        for (const rule of this.rules) {
            if (conditionSet.has(rule.condition)) {
                matches.push({
                    rule_id: rule.id,
                    condition: rule.condition,
                    reactivated_cwes: rule.reactivates_cwes,
                    reactivated_categories: rule.reactivates_categories,
                    mechanism: rule.mechanism,
                    severity_boost: rule.severity_boost,
                    attacker_gains: rule.attacker_gains,
                    root_fix: rule.root_fix,
                })
            }
        }

        return matches
    }

    /**
     * Cross-reference reactivation matches with a list of CVEs
     * affecting the subscriber's tech stack.
     *
     * This is Phase 6 + Phase 3 integration:
     *   reactivation rules × subscriber CVEs = concrete reactivated vulnerabilities
     *
     * @param matches - Reactivation matches from analyze()
     * @param subscriberCWEs - CWE IDs from CVEs affecting the subscriber's stack
     * @returns Reactivation matches that have concrete CVEs in the subscriber's stack
     */
    crossReference(
        matches: ReactivationMatch[],
        subscriberCWEs: string[],
    ): Array<ReactivationMatch & { matching_cwes: string[] }> {
        const cweSet = new Set(subscriberCWEs)
        const results: Array<ReactivationMatch & { matching_cwes: string[] }> = []

        for (const match of matches) {
            const matching = match.reactivated_cwes.filter(cwe => cweSet.has(cwe))
            if (matching.length > 0) {
                results.push({ ...match, matching_cwes: matching })
            }
        }

        return results
    }

    /**
     * Generate a human-readable reactivation report.
     * Used in advisories and posture reports.
     */
    generateReport(
        conditions: PostureCondition[],
        subscriberCWEs?: string[],
    ): ReactivationReport {
        const allMatches = this.analyze(conditions)

        const criticalUpgrades = allMatches.filter(m => m.severity_boost === 'critical_upgrade')
        const highUpgrades = allMatches.filter(m => m.severity_boost === 'high_upgrade')
        const contextUpgrades = allMatches.filter(m => m.severity_boost === 'context_upgrade')

        // If we have subscriber CVEs, cross-reference for concrete matches
        let concreteMatches: Array<ReactivationMatch & { matching_cwes: string[] }> = []
        if (subscriberCWEs && subscriberCWEs.length > 0) {
            concreteMatches = this.crossReference(allMatches, subscriberCWEs)
        }

        return {
            total_reactivations: allMatches.length,
            critical_upgrades: criticalUpgrades.length,
            high_upgrades: highUpgrades.length,
            context_upgrades: contextUpgrades.length,
            concrete_cve_matches: concreteMatches.length,
            reactivations: allMatches,
            concrete_matches: concreteMatches,
            summary: this.buildSummary(allMatches, concreteMatches),
        }
    }

    private buildSummary(
        allMatches: ReactivationMatch[],
        concreteMatches: Array<ReactivationMatch & { matching_cwes: string[] }>,
    ): string {
        if (allMatches.length === 0) {
            return 'No reactivation vectors detected. Posture configuration does not enable known vulnerability reactivation patterns.'
        }

        const parts: string[] = []

        const critCount = allMatches.filter(m => m.severity_boost === 'critical_upgrade').length
        const highCount = allMatches.filter(m => m.severity_boost === 'high_upgrade').length

        if (critCount > 0) {
            parts.push(
                `${critCount} misconfiguration(s) critically reactivate vulnerability classes. ` +
                'Patched vulnerabilities in these classes may be exploitable through alternative delivery mechanisms.'
            )
        }
        if (highCount > 0) {
            parts.push(
                `${highCount} misconfiguration(s) provide high-severity reactivation vectors.`
            )
        }
        if (concreteMatches.length > 0) {
            const uniqueCWEs = new Set(concreteMatches.flatMap(m => m.matching_cwes))
            parts.push(
                `${concreteMatches.length} reactivation(s) match ${uniqueCWEs.size} CWE(s) ` +
                'in your stack — these are concrete, exploitable reactivation vectors.'
            )
        }

        return parts.join(' ')
    }

    /** Number of registered reactivation rules */
    get ruleCount(): number {
        return this.rules.length
    }

    /** All unique conditions that have reactivation rules */
    get coveredConditions(): PostureCondition[] {
        return [...new Set(this.rules.map(r => r.condition))]
    }
}


// ── Report Type ──────────────────────────────────────────────────

export interface ReactivationReport {
    total_reactivations: number
    critical_upgrades: number
    high_upgrades: number
    context_upgrades: number
    concrete_cve_matches: number
    reactivations: ReactivationMatch[]
    concrete_matches: Array<ReactivationMatch & { matching_cwes: string[] }>
    summary: string
}
