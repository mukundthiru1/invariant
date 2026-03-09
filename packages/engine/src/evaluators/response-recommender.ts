/**
 * Incident Response Recommender
 *
 * Given detection results, generates specific, actionable containment
 * and remediation recommendations. This is the capability that turns
 * INVARIANT from a detection system into an automated SOC analyst.
 *
 * CrowdStrike: "SQL injection detected" → analyst manually investigates
 * INVARIANT: "SQL injection detected → block source → rotate DB creds →
 *   audit query in /api/login handler → add parameterized query →
 *   check access logs for same source in last 24h"
 *
 * The recommendations are:
 *   1. CONTAIN — immediate actions to stop the attack
 *   2. INVESTIGATE — what to look at to understand scope
 *   3. REMEDIATE — code/config changes to fix the root cause
 *   4. HARDEN — long-term improvements to prevent recurrence
 */

import type { InvariantMatch } from '../classes/types.js'
import type { ExploitEffect } from './effect-simulator.js'
import type { AdversaryFingerprint } from './effect-simulator.js'
import type { ChainMatch } from '../chain-detector.js'

// ── Types ────────────────────────────────────────────────────────

export interface IncidentRecommendation {
    /** Unique ID for deduplication */
    id: string
    /** Urgency: how quickly must this be done? */
    urgency: 'immediate' | 'within_1h' | 'within_24h' | 'next_sprint'
    /** Category of action */
    category: 'contain' | 'investigate' | 'remediate' | 'harden'
    /** Human-readable action */
    action: string
    /** Why this action matters */
    rationale: string
    /** Specific commands, code changes, or steps */
    steps?: string[]
    /** Which detection triggered this */
    triggeredBy: string
}

export interface ResponsePlan {
    /** Severity of the incident */
    severity: 'critical' | 'high' | 'medium' | 'low'
    /** All recommendations, ordered by urgency then category */
    recommendations: IncidentRecommendation[]
    /** Summary for the alert */
    summary: string
    /** Estimated blast radius */
    blastRadius: string
    /** Whether this requires immediate human attention */
    requiresHuman: boolean
}

// ── Recommender ──────────────────────────────────────────────────

export function generateResponsePlan(
    matches: InvariantMatch[],
    effect: ExploitEffect | null,
    adversary: AdversaryFingerprint | null,
    chains: ChainMatch[],
    requestContext: { method: string; path: string; sourceHash: string },
): ResponsePlan {
    const recommendations: IncidentRecommendation[] = []
    const classSet = new Set(matches.map(m => m.class))
    const highestSeverity = getHighestSeverity(matches)

    // ── Containment (immediate) ──

    // Always: block the source
    if (matches.length > 0) {
        recommendations.push({
            id: 'contain_block_source',
            urgency: highestSeverity === 'critical' ? 'immediate' : 'within_1h',
            category: 'contain',
            action: `Block source ${requestContext.sourceHash} at WAF/load balancer`,
            rationale: 'Prevent further exploitation attempts from this source',
            steps: [
                `Add ${requestContext.sourceHash} to IP denylist`,
                'If behind CDN: add to Cloudflare/AWS WAF IP block rule',
                'Monitor for same behavioral fingerprint from different IPs',
            ],
            triggeredBy: matches[0].class,
        })
    }

    // SQL injection containment
    if (hasSqlDetection(classSet)) {
        recommendations.push({
            id: 'contain_db_audit',
            urgency: 'immediate',
            category: 'contain',
            action: 'Audit database for unauthorized access',
            rationale: 'SQL injection may have already extracted or modified data',
            steps: [
                `Check query logs for ${requestContext.path} endpoint in last 24h`,
                'Look for queries returning unusually large result sets',
                'Check for DROP, DELETE, UPDATE, INSERT from non-application sources',
                'If UNION SELECT detected: check for data exfiltration in response bodies',
            ],
            triggeredBy: 'sql_*',
        })

        if (effect?.operation === 'steal_credentials') {
            recommendations.push({
                id: 'contain_rotate_creds',
                urgency: 'immediate',
                category: 'contain',
                action: 'Rotate database credentials and API keys',
                rationale: 'Credential theft detected — assume credentials are compromised',
                steps: [
                    'Rotate database password immediately',
                    'Rotate all API keys stored in the same database',
                    'Invalidate all active sessions',
                    'If password hashes extracted: force password reset for all users',
                ],
                triggeredBy: effect.operation,
            })
        }
    }

    // Command injection containment
    if (hasCmdDetection(classSet)) {
        recommendations.push({
            id: 'contain_cmd_audit',
            urgency: 'immediate',
            category: 'contain',
            action: 'Check for active reverse shells or unauthorized processes',
            rationale: 'Command injection may have established persistent access',
            steps: [
                'Run: netstat -tlnp | grep ESTABLISHED (look for unexpected outbound connections)',
                'Run: ps aux | grep -v "\\[" (look for unexpected processes)',
                'Check crontab -l for all users (persistence via cron)',
                'Check /tmp and /var/tmp for dropped files',
                'If reverse shell detected: isolate the server from the network immediately',
            ],
            triggeredBy: 'cmd_*',
        })
    }

    // XSS containment
    if (hasXssDetection(classSet)) {
        recommendations.push({
            id: 'contain_xss_csp',
            urgency: 'within_1h',
            category: 'contain',
            action: 'Deploy strict Content-Security-Policy header',
            rationale: 'XSS injection detected — CSP prevents script execution even if stored',
            steps: [
                "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
                'If stored XSS possible: scan database for injected HTML/script content',
                'Purge CDN cache for affected paths',
            ],
            triggeredBy: 'xss_*',
        })
    }

    // Path traversal containment
    if (hasPathDetection(classSet)) {
        recommendations.push({
            id: 'contain_path_audit',
            urgency: 'within_1h',
            category: 'contain',
            action: 'Audit accessed files and check for sensitive data exposure',
            rationale: 'Path traversal may have read sensitive configuration or credential files',
            steps: [
                `Check access logs for ${requestContext.path} — look for 200 responses with large bodies`,
                'If .env, credentials, or key files were readable: rotate all secrets in those files',
                'Verify file permissions: application should not have read access to /etc/shadow, ~/.ssh, etc.',
            ],
            triggeredBy: 'path_*',
        })
    }

    // SSRF containment
    if (hasSsrfDetection(classSet)) {
        recommendations.push({
            id: 'contain_ssrf_metadata',
            urgency: 'immediate',
            category: 'contain',
            action: 'Rotate cloud IAM credentials if metadata service was accessed',
            rationale: 'SSRF to cloud metadata exposes temporary IAM credentials',
            steps: [
                'AWS: Rotate IAM role credentials, check CloudTrail for unusual API calls',
                'GCP: Revoke service account tokens, check Cloud Audit Logs',
                'Azure: Rotate managed identity tokens, check Activity Log',
                'Enable IMDSv2 (AWS) or equivalent to prevent future metadata access',
            ],
            triggeredBy: 'ssrf_*',
        })
    }

    // Chain-based escalation
    if (chains.length > 0) {
        const mostComplete = chains.reduce((a, b) => a.completion > b.completion ? a : b)
        recommendations.push({
            id: 'contain_chain_escalation',
            urgency: 'immediate',
            category: 'contain',
            action: `Active attack chain detected: ${mostComplete.name} (${(mostComplete.completion * 100).toFixed(0)}% complete)`,
            rationale: 'Multi-step attack in progress — attacker is advancing through kill chain',
            steps: [
                `Chain: ${mostComplete.name} at ${(mostComplete.completion * 100).toFixed(0)}% completion`,
                'Block the source IP/session immediately',
                'Review all requests from this source in the last hour',
                'Escalate to security team — this is an active, sophisticated attack',
            ],
            triggeredBy: `chain:${mostComplete.chainId}`,
        })
    }

    // ── Investigation ──

    if (matches.length > 0) {
        recommendations.push({
            id: 'investigate_source_history',
            urgency: 'within_1h',
            category: 'investigate',
            action: `Review all requests from source ${requestContext.sourceHash} in the last 24 hours`,
            rationale: 'Attack reconnaissance typically precedes exploitation — look for earlier probing',
            steps: [
                `grep access logs for source hash: ${requestContext.sourceHash}`,
                'Plot request timeline — look for scanning patterns (many paths, rapid succession)',
                'Check if source accessed any sensitive endpoints before this attack',
                'Cross-reference with other sources that appeared around the same time',
            ],
            triggeredBy: matches[0].class,
        })
    }

    if (adversary?.automated) {
        recommendations.push({
            id: 'investigate_tool_campaign',
            urgency: 'within_1h',
            category: 'investigate',
            action: `Automated tool detected: ${adversary.tool} — check for broader campaign`,
            rationale: 'Automated tools typically scan multiple targets — you may not be the only victim',
            steps: [
                `Tool identified: ${adversary.tool} (${adversary.skillLevel} skill level)`,
                'Check threat intel feeds for this tool being used in active campaigns',
                'Review other applications on the same infrastructure for similar probing',
                `Indicators: ${adversary.indicators.join('; ')}`,
            ],
            triggeredBy: 'adversary_fingerprint',
        })
    }

    // ── Remediation ──

    if (hasSqlDetection(classSet)) {
        recommendations.push({
            id: 'remediate_sql_parameterize',
            urgency: 'within_24h',
            category: 'remediate',
            action: `Fix SQL injection in ${requestContext.method} ${requestContext.path}`,
            rationale: 'The root cause is string concatenation in SQL queries',
            steps: [
                `Locate the query handler for ${requestContext.method} ${requestContext.path}`,
                'Replace string concatenation with parameterized queries / prepared statements',
                'If using an ORM: ensure raw query mode is not used with user input',
                'Add input validation for expected parameter types (integer, UUID, etc.)',
                'Run the INVARIANT codescan to find all similar patterns: npx @santh/invariant codescan',
            ],
            triggeredBy: 'sql_*',
        })
    }

    if (hasXssDetection(classSet)) {
        recommendations.push({
            id: 'remediate_xss_encode',
            urgency: 'within_24h',
            category: 'remediate',
            action: `Fix XSS vulnerability in ${requestContext.method} ${requestContext.path}`,
            rationale: 'User input is rendered in HTML without proper encoding',
            steps: [
                'Apply context-aware output encoding (HTML encode for body, JS encode for scripts, URL encode for hrefs)',
                'If using a template engine: ensure auto-escaping is enabled globally',
                'Never use innerHTML/dangerouslySetInnerHTML with user-controlled data',
                'Add Content-Security-Policy header to prevent inline script execution',
            ],
            triggeredBy: 'xss_*',
        })
    }

    if (hasCmdDetection(classSet)) {
        recommendations.push({
            id: 'remediate_cmd_eliminate',
            urgency: 'within_24h',
            category: 'remediate',
            action: `Eliminate shell command execution in ${requestContext.method} ${requestContext.path}`,
            rationale: 'Any code path that passes user input to a shell is fundamentally unsafe',
            steps: [
                'Replace shell execution with native library calls (e.g., use fs.readFile instead of cat)',
                'If shell execution is unavoidable: use execFile with argument arrays, never exec with string interpolation',
                'Whitelist allowed commands and arguments',
                'Run as a least-privilege user (not root)',
            ],
            triggeredBy: 'cmd_*',
        })
    }

    if (hasPathDetection(classSet)) {
        recommendations.push({
            id: 'remediate_path_sandbox',
            urgency: 'within_24h',
            category: 'remediate',
            action: `Fix path traversal in ${requestContext.method} ${requestContext.path}`,
            rationale: 'User input is used in file system paths without proper sanitization',
            steps: [
                'Use path.resolve() then verify the result starts with the allowed base directory',
                'Reject any input containing "..", null bytes, or URL-encoded equivalents',
                'Use a whitelist of allowed filenames/paths if possible',
                'Set filesystem permissions: application user should only read application files',
            ],
            triggeredBy: 'path_*',
        })
    }

    // ── Hardening ──

    recommendations.push({
        id: 'harden_waf_rules',
        urgency: 'next_sprint',
        category: 'harden',
        action: 'Deploy INVARIANT edge sensor for real-time blocking',
        rationale: 'Detection without prevention means attacks are logged but not stopped',
        steps: [
            'npx @santh/invariant deploy  — deploys CF Worker edge sensor',
            'Set mode to enforce for blocking (start with monitor for tuning)',
            'Configure alert channels for critical/high severity detections',
        ],
        triggeredBy: 'general',
    })

    if (matches.some(m => m.severity === 'critical' || m.severity === 'high')) {
        recommendations.push({
            id: 'harden_input_validation',
            urgency: 'next_sprint',
            category: 'harden',
            action: 'Add input shape validation at every entry point',
            rationale: 'Shape validation catches zero-day attacks by rejecting inputs that deviate from expected format',
            steps: [
                "import { autoValidateShape } from '@santh/invariant-engine'",
                'For each API parameter: validate shape before processing',
                'Email fields: validateShape(input, "email")',
                'Integer fields: validateShape(input, "integer")',
                'UUIDs: validateShape(input, "uuid")',
                'This catches attacks that bypass signature-based detection',
            ],
            triggeredBy: 'general',
        })
    }

    // Sort: immediate > within_1h > within_24h > next_sprint, then contain > investigate > remediate > harden
    const urgencyOrder = { immediate: 0, within_1h: 1, within_24h: 2, next_sprint: 3 }
    const categoryOrder = { contain: 0, investigate: 1, remediate: 2, harden: 3 }
    recommendations.sort((a, b) => {
        const ud = urgencyOrder[a.urgency] - urgencyOrder[b.urgency]
        if (ud !== 0) return ud
        return categoryOrder[a.category] - categoryOrder[b.category]
    })

    // Deduplicate by id
    const seen = new Set<string>()
    const deduped = recommendations.filter(r => {
        if (seen.has(r.id)) return false
        seen.add(r.id)
        return true
    })

    // Compute blast radius
    const blastRadius = computeBlastRadius(matches, effect, chains)

    // Compute summary
    const attackTypes = [...new Set(matches.map(m => m.category))].join(', ')
    const summary = matches.length === 0
        ? 'No detections — no action required'
        : `${matches.length} detection(s) across ${attackTypes}. ` +
          `Highest severity: ${highestSeverity}. ` +
          (effect ? `Effect: ${effect.operation} (impact ${effect.impact.baseScore.toFixed(1)}/10). ` : '') +
          (adversary ? `Adversary: ${adversary.tool} (${adversary.skillLevel}). ` : '') +
          (chains.length > 0 ? `Active chain: ${chains[0].name}.` : '')

    return {
        severity: highestSeverity,
        recommendations: deduped,
        summary,
        blastRadius,
        requiresHuman: highestSeverity === 'critical' || chains.some(c => c.completion >= 0.66),
    }
}

// ── Helpers ──────────────────────────────────────────────────────

function getHighestSeverity(matches: InvariantMatch[]): 'critical' | 'high' | 'medium' | 'low' {
    const order = ['low', 'medium', 'high', 'critical'] as const
    let max = 0
    for (const m of matches) {
        const idx = order.indexOf(m.severity as typeof order[number])
        if (idx > max) max = idx
    }
    return order[max] ?? 'low'
}

function hasSqlDetection(classSet: Set<string>): boolean {
    return ['sql_tautology', 'sql_union_extraction', 'sql_stacked_execution',
            'sql_time_oracle', 'sql_error_oracle', 'sql_string_termination',
            'sql_comment_truncation', 'sql_json_bypass'].some(c => classSet.has(c))
}

function hasCmdDetection(classSet: Set<string>): boolean {
    return ['cmd_separator', 'cmd_substitution', 'cmd_argument_injection'].some(c => classSet.has(c))
}

function hasXssDetection(classSet: Set<string>): boolean {
    return ['xss_tag_injection', 'xss_event_handler', 'xss_protocol_handler',
            'xss_attribute_escape', 'xss_template_expression'].some(c => classSet.has(c))
}

function hasPathDetection(classSet: Set<string>): boolean {
    return ['path_dotdot_escape', 'path_encoding_bypass', 'path_null_terminate',
            'path_normalization_bypass', 'path_windows_traversal'].some(c => classSet.has(c))
}

function hasSsrfDetection(classSet: Set<string>): boolean {
    return ['ssrf_internal_reach', 'ssrf_cloud_metadata', 'ssrf_protocol_smuggle'].some(c => classSet.has(c))
}

function computeBlastRadius(
    matches: InvariantMatch[],
    effect: ExploitEffect | null,
    chains: ChainMatch[],
): string {
    if (chains.some(c => c.completion >= 0.8)) {
        return 'CRITICAL — Active multi-stage attack near completion. Assume full compromise of targeted system.'
    }
    if (effect && effect.impact.baseScore !== undefined && effect.impact.baseScore >= 9.0) {
        return `HIGH — ${(effect as any).impact.exposureEstimate}. Potential for full data breach.`
    }
    if (effect && effect.impact.baseScore !== undefined && effect.impact.baseScore >= 7.0) {
        return `MEDIUM — ${(effect as any).impact.exposureEstimate}. Limited to targeted resource.`
    }
    if (matches.some(m => m.severity === 'critical')) {
        return 'HIGH — Critical-severity vulnerability targeted. Exploitation may allow system-level access.'
    }
    if (matches.some(m => m.severity === 'high')) {
        return 'MEDIUM — High-severity vulnerability targeted. Exploitation may expose sensitive data.'
    }
    return 'LOW — Reconnaissance or low-severity probing. Limited immediate impact.'
}
