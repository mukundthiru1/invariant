/**
 * @santh/invariant-engine — Attack Chain Detection
 *
 * Detects multi-step attack sequences by correlating individual invariant
 * signals over time from the same source. Individual payloads may be
 * low-confidence. Chains compound confidence.
 *
 * The fundamental insight:
 *   A single `path_dotdot_escape` at 0.6 confidence is ambiguous.
 *   `path_dotdot_escape` → `path_sensitive_file` → `credential_extraction`
 *   from the same source within 60 seconds is a confirmed LFI attack chain.
 *
 * Chain definitions encode the structure of real-world attacks:
 *   1. Reconnaissance → Probing → Exploitation → Impact
 *   2. Each step maps to invariant classes or behavioral patterns
 *   3. Confidence compounds: P(chain) > max(P(individual steps))
 *   4. Partial chain matches trigger early defense escalation
 *
 * This is what makes INVARIANT fundamentally different from a WAF.
 * A WAF sees requests. INVARIANT sees attack narratives.
 */

import type { InvariantClass, InvariantMatch } from './invariant-engine.js'

// ── Chain Types ──────────────────────────────────────────────────

export interface ChainStep {
    /** Invariant classes that satisfy this step (OR — any match advances the chain) */
    classes: InvariantClass[]
    /** Behavioral patterns that satisfy this step (non-invariant signals) */
    behaviors?: string[]
    /** Minimum confidence required for this step to count */
    minConfidence?: number
    /** Description of what the attacker is doing at this step */
    description: string
    /** What defense action should trigger at this step */
    defense?: 'alert' | 'throttle' | 'challenge' | 'block'
}

export interface ChainDefinition {
    /** Unique chain identifier */
    id: string
    /** Human-readable name */
    name: string
    /** Description of the full attack narrative */
    description: string
    /** MITRE ATT&CK technique IDs (when applicable) */
    mitre?: string[]
    /** Severity when the full chain completes */
    severity: 'critical' | 'high' | 'medium'
    /** Chain steps in order. Steps may be skipped (attackers don't always follow the textbook) */
    steps: ChainStep[]
    /** Maximum time window (seconds) for the entire chain to complete */
    windowSeconds: number
    /**
     * Minimum number of steps that must match to consider
     * the chain detected (allows partial matches).
     * Default: all steps must match.
     */
    minimumSteps?: number
    /** Confidence boost when this chain is detected (added to base confidence) */
    confidenceBoost: number
}

export interface ChainSignal {
    /** Source identifier (hashed IP, session ID, etc.) */
    sourceHash: string
    /** Which invariant classes were matched */
    classes: InvariantClass[]
    /** Behavioral labels (e.g., 'recon', 'path_spray', 'rate_anomaly') */
    behaviors: string[]
    /** Confidence of the individual detection */
    confidence: number
    /** Path of the request */
    path: string
    /** HTTP method */
    method: string
    /** Timestamp (ISO string or epoch ms) */
    timestamp: number
}

export interface ChainMatch {
    /** Which chain was detected */
    chainId: string
    /** Chain name */
    name: string
    /** How many steps matched out of total */
    stepsMatched: number
    totalSteps: number
    /** Completion ratio (0-1) */
    completion: number
    /** Compounded confidence */
    confidence: number
    /** Chain severity */
    severity: 'critical' | 'high' | 'medium'
    /** Description */
    description: string
    /** Recommended defense action */
    recommendedAction: 'monitor' | 'throttle' | 'challenge' | 'block' | 'lockdown'
    /** Individual step matches with timestamps */
    stepMatches: Array<{
        stepIndex: number
        description: string
        matchedClass: string
        confidence: number
        timestamp: number
        path: string
    }>
    /** Time span of the attack in seconds */
    durationSeconds: number
    /** Source identifier */
    sourceHash: string
}

// ═══════════════════════════════════════════════════════════════════
// CHAIN DEFINITIONS — Real-world attack sequences
// ═══════════════════════════════════════════════════════════════════

export const ATTACK_CHAINS: ChainDefinition[] = [

    // ── 1. LFI → Credential Extraction → Pivot ─────────────────
    {
        id: 'lfi_credential_theft',
        name: 'LFI → Credential Extraction',
        description: 'Path traversal to read sensitive files (e.g., .env, /etc/shadow, SSH keys), extract credentials, then use them to access protected resources.',
        mitre: ['T1083', 'T1552.001'],
        severity: 'critical',
        steps: [
            {
                classes: ['path_dotdot_escape', 'path_encoding_bypass'],
                description: 'Probe for path traversal vulnerability',
                defense: 'alert',
            },
            {
                classes: ['path_dotdot_escape', 'path_null_terminate', 'path_encoding_bypass'],
                behaviors: ['path_sensitive_file'],
                description: 'Attempt to read sensitive files (.env, /etc/passwd, SSH keys)',
                defense: 'block',
            },
            {
                classes: ['auth_header_spoof'],
                behaviors: ['auth_change', 'privilege_escalation'],
                description: 'Use extracted credentials to access protected resources',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 2,
        confidenceBoost: 0.3,
    },

    // ── 2. SQLi → Data Extraction → Privilege Escalation ────────
    {
        id: 'sqli_data_exfil',
        name: 'SQLi → Data Exfiltration',
        description: 'SQL injection to extract data, enumerate the database schema, dump sensitive tables, and escalate privileges.',
        mitre: ['T1190', 'T1005'],
        severity: 'critical',
        steps: [
            {
                classes: ['sql_string_termination', 'sql_error_oracle', 'sql_time_oracle'],
                description: 'Probe for SQL injection vulnerability (error/time-based detection)',
                defense: 'alert',
            },
            {
                classes: ['sql_tautology', 'sql_union_extraction'],
                description: 'Extract data via UNION SELECT or boolean-based blind SQLi',
                defense: 'block',
            },
            {
                classes: ['sql_stacked_execution'],
                description: 'Execute additional SQL statements (data modification, privilege grants)',
                defense: 'block',
            },
        ],
        windowSeconds: 600,
        minimumSteps: 2,
        confidenceBoost: 0.25,
    },

    // ── 3. Recon → SSRF → Cloud Credential Theft ────────────────
    {
        id: 'ssrf_cloud_credential_theft',
        name: 'SSRF → Cloud Credential Theft',
        description: 'Server-side request forgery to reach cloud metadata endpoints (169.254.169.254), extract IAM credentials, then use them for cloud API access.',
        mitre: ['T1552.005', 'T1078.004'],
        severity: 'critical',
        steps: [
            {
                classes: ['ssrf_internal_reach'],
                description: 'Probe for SSRF by targeting internal IP addresses',
                defense: 'alert',
            },
            {
                classes: ['ssrf_cloud_metadata'],
                description: 'Reach cloud metadata endpoint (AWS/GCP/Azure) to extract IAM credentials',
                defense: 'block',
            },
            {
                classes: ['ssrf_protocol_smuggle'],
                behaviors: ['credential_extraction'],
                description: 'Use extracted credentials or smuggle to internal services',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 2,
        confidenceBoost: 0.35,
    },

    // ── 4. XSS → Session Hijack → Admin Takeover ────────────────
    {
        id: 'xss_session_hijack',
        name: 'XSS → Session Hijack → Admin Takeover',
        description: 'Cross-site scripting to steal session cookies, then use hijacked session to access administrative endpoints.',
        mitre: ['T1189', 'T1539'],
        severity: 'critical',
        steps: [
            {
                classes: ['xss_tag_injection', 'xss_event_handler', 'xss_attribute_escape', 'xss_protocol_handler'],
                description: 'Inject XSS payload via multiple vectors',
                defense: 'alert',
            },
            {
                classes: ['xss_template_expression'],
                behaviors: ['cookie_exfil', 'dom_manipulation'],
                description: 'Escalate to template expression injection or cookie exfiltration',
                defense: 'block',
            },
            {
                classes: ['auth_header_spoof'],
                behaviors: ['privilege_escalation', 'admin_access'],
                description: 'Use stolen session to access admin endpoints',
                defense: 'block',
            },
        ],
        windowSeconds: 1800,
        minimumSteps: 2,
        confidenceBoost: 0.25,
    },

    // ── 5. Deserialization → Gadget Chain → RCE ─────────────────
    {
        id: 'deser_rce',
        name: 'Deserialization → RCE',
        description: 'Untrusted deserialization leading to gadget chain execution and remote code execution. The most devastating single-step attack class.',
        mitre: ['T1059', 'T1203'],
        severity: 'critical',
        steps: [
            {
                classes: ['deser_java_gadget', 'deser_php_object', 'deser_python_pickle'],
                description: 'Inject serialized object with gadget chain for code execution',
                defense: 'block',
            },
            {
                classes: ['cmd_separator', 'cmd_substitution'],
                behaviors: ['reverse_shell', 'outbound_connection'],
                description: 'Execute system commands via deserialized code',
                defense: 'block',
            },
        ],
        windowSeconds: 60,
        minimumSteps: 1, // Even single-step deser is critical
        confidenceBoost: 0.4,
    },

    // ── 6. Prototype Pollution → Property Injection → RCE ───────
    {
        id: 'proto_pollution_rce',
        name: 'Prototype Pollution → RCE',
        description: 'Pollute Object.prototype to inject properties that propagate to child_process options or template rendering, achieving remote code execution.',
        mitre: ['T1059.007'],
        severity: 'critical',
        steps: [
            {
                classes: ['proto_pollution'],
                description: 'Inject __proto__ or constructor.prototype to pollute Object prototype',
                defense: 'block',
            },
            {
                classes: ['cmd_separator', 'cmd_substitution', 'cmd_argument_injection'],
                behaviors: ['property_injection'],
                description: 'Polluted properties trigger command execution via child_process',
                defense: 'block',
            },
        ],
        windowSeconds: 30,
        minimumSteps: 1,
        confidenceBoost: 0.35,
    },

    // ── 7. Log4Shell → JNDI → RCE ──────────────────────────────
    {
        id: 'log4shell_rce',
        name: 'Log4Shell → JNDI Lookup → RCE',
        description: 'Exploit Log4j JNDI lookup to fetch and execute malicious code from an attacker-controlled server.',
        mitre: ['T1190', 'T1059'],
        severity: 'critical',
        steps: [
            {
                classes: ['log_jndi_lookup'],
                description: 'Inject JNDI lookup string (${jndi:ldap://...}) to trigger Log4j vulnerability',
                defense: 'block',
            },
            {
                classes: ['ssrf_internal_reach', 'ssrf_protocol_smuggle'],
                behaviors: ['outbound_connection', 'class_loading'],
                description: 'Log4j resolves JNDI lookup and fetches remote class',
                defense: 'block',
            },
        ],
        windowSeconds: 30,
        minimumSteps: 1,
        confidenceBoost: 0.4,
    },

    // ── 8. Scanner → Vuln Discovery → Targeted Exploit ──────────
    {
        id: 'automated_attack_pipeline',
        name: 'Automated Scanner → Targeted Exploit',
        description: 'Automated vulnerability scanner (Nuclei, Nikto, etc.) probing the application, discovering a vulnerability, then switching to targeted exploitation.',
        mitre: ['T1595.002', 'T1190'],
        severity: 'high',
        steps: [
            {
                classes: [],
                behaviors: ['scanner_detected', 'path_spray', 'rate_anomaly'],
                description: 'Automated scanner fingerprinting the application',
                defense: 'throttle',
            },
            {
                classes: ['sql_string_termination', 'xss_tag_injection', 'path_dotdot_escape', 'cmd_separator', 'ssrf_internal_reach', 'log_jndi_lookup'],
                description: 'Targeted payload after reconnaissance',
                defense: 'block',
            },
        ],
        windowSeconds: 3600,
        minimumSteps: 2,
        confidenceBoost: 0.2,
    },

    // ── 9. Multi-vector SQLi chain ──────────────────────────────
    {
        id: 'sqli_multi_vector',
        name: 'Multi-Vector SQL Injection Campaign',
        description: 'Attacker systematically tests multiple SQLi techniques against different endpoints: error-based for detection, UNION for extraction, stacked for modification.',
        mitre: ['T1190'],
        severity: 'critical',
        steps: [
            {
                classes: ['sql_error_oracle', 'sql_time_oracle'],
                description: 'Blind SQLi probing — detect injectable parameters via errors or timing',
                defense: 'alert',
            },
            {
                classes: ['sql_tautology', 'sql_comment_truncation', 'sql_string_termination'],
                description: 'Confirm injection — bypass authentication or extract boolean conditions',
                defense: 'block',
            },
            {
                classes: ['sql_union_extraction'],
                description: 'Extract data — UNION-based exfiltration of database contents',
                defense: 'block',
            },
            {
                classes: ['sql_stacked_execution'],
                description: 'Modify data — execute additional statements (INSERT, UPDATE, DROP)',
                defense: 'block',
            },
        ],
        windowSeconds: 1800,
        minimumSteps: 2,
        confidenceBoost: 0.3,
    },

    // ── 10. SSTI → Template RCE ─────────────────────────────────
    {
        id: 'ssti_rce',
        name: 'SSTI → Template Engine RCE',
        description: 'Server-side template injection escalating from expression evaluation to code execution via template engine internals.',
        mitre: ['T1059'],
        severity: 'critical',
        steps: [
            {
                classes: ['ssti_jinja_twig', 'ssti_el_expression', 'xss_template_expression'],
                description: 'Inject template expression to test for SSTI (e.g., {{7*7}}, ${7*7})',
                defense: 'alert',
            },
            {
                classes: ['ssti_jinja_twig', 'ssti_el_expression'],
                behaviors: ['class_traversal', 'code_execution'],
                description: 'Escalate to code execution via template engine class hierarchy',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 1,
        confidenceBoost: 0.3,
    },

    // ── 11. XXE → SSRF → Internal Network Scan ──────────────────
    {
        id: 'xxe_ssrf_chain',
        name: 'XXE → SSRF → Internal Pivot',
        description: 'XML external entity injection to make server-side requests, scan internal network, and exfiltrate data via out-of-band channels.',
        mitre: ['T1190', 'T1018'],
        severity: 'critical',
        steps: [
            {
                classes: ['xxe_entity_expansion', 'xml_injection'],
                description: 'Inject XML with external entity references (DTD expansion)',
                defense: 'block',
            },
            {
                classes: ['ssrf_internal_reach', 'ssrf_protocol_smuggle'],
                description: 'Entity resolution triggers SSRF to internal network',
                defense: 'block',
            },
        ],
        windowSeconds: 120,
        minimumSteps: 1,
        confidenceBoost: 0.3,
    },

    // ── 12. Auth Bypass → Privilege Escalation ───────────────────
    {
        id: 'auth_bypass_privesc',
        name: 'Auth Bypass → Privilege Escalation',
        description: 'Bypass authentication via JWT alg:none, header spoofing, or mass assignment to gain unauthorized access, then escalate privileges.',
        mitre: ['T1078', 'T1548'],
        severity: 'critical',
        steps: [
            {
                classes: ['auth_none_algorithm', 'auth_header_spoof'],
                description: 'Bypass authentication (JWT alg:none, IP spoofing, header injection)',
                defense: 'block',
            },
            {
                classes: ['mass_assignment', 'proto_pollution'],
                behaviors: ['privilege_escalation', 'role_change'],
                description: 'Escalate privileges via mass assignment or prototype pollution',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 1,
        confidenceBoost: 0.3,
    },
]

// ═══════════════════════════════════════════════════════════════════
// CHAIN CORRELATOR
// ═══════════════════════════════════════════════════════════════════

/**
 * The chain correlator maintains a sliding window of signals per source
 * and continuously evaluates them against chain definitions.
 *
 * Memory-bounded: each source window is capped, oldest signals evicted.
 * Time-bounded: signals older than the longest chain window are pruned.
 */
export class ChainCorrelator {
    private sourceWindows: Map<string, ChainSignal[]> = new Map()
    private readonly maxSignalsPerSource: number
    private readonly chainDefs: ChainDefinition[]
    private lastPrune: number = Date.now()

    constructor(
        chains: ChainDefinition[] = ATTACK_CHAINS,
        maxSignalsPerSource = 200,
    ) {
        this.chainDefs = chains
        this.maxSignalsPerSource = maxSignalsPerSource
    }

    /**
     * Ingest a new signal and evaluate all chains.
     * Returns any chain matches detected.
     *
     * This is the hot path — called on every request that produces
     * an invariant match or behavioral signal.
     */
    ingest(signal: ChainSignal): ChainMatch[] {
        // Store the signal
        let window = this.sourceWindows.get(signal.sourceHash)
        if (!window) {
            window = []
            this.sourceWindows.set(signal.sourceHash, window)
        }
        window.push(signal)

        // Evict excess signals (LRU)
        if (window.length > this.maxSignalsPerSource) {
            window.splice(0, window.length - this.maxSignalsPerSource)
        }

        // Periodic prune of stale sources (every 60s)
        if (Date.now() - this.lastPrune > 60_000) {
            this.pruneStaleWindows()
        }

        // Evaluate all chains against this source's signals
        return this.evaluateChains(signal.sourceHash, window)
    }

    /**
     * Evaluate all chain definitions against a source's signal window.
     * Returns all chains where sufficient steps match.
     */
    private evaluateChains(sourceHash: string, signals: ChainSignal[]): ChainMatch[] {
        const matches: ChainMatch[] = []

        for (const chain of this.chainDefs) {
            const match = this.evaluateChain(chain, sourceHash, signals)
            if (match) matches.push(match)
        }

        return matches
    }

    /**
     * Evaluate a single chain against a source's signals.
     *
     * Algorithm:
     *   For each step in the chain, find the earliest signal that satisfies it.
     *   Steps must be in chronological order (but gaps are allowed — attackers
     *   don't always follow the textbook exactly).
     *   Chain must complete within the time window.
     *   Partial matches count if >= minimumSteps.
     */
    private evaluateChain(
        chain: ChainDefinition,
        sourceHash: string,
        signals: ChainSignal[],
    ): ChainMatch | null {
        const now = Date.now()
        const windowStart = now - (chain.windowSeconds * 1000)

        // Filter signals within the chain's time window
        const relevantSignals = signals.filter(s => s.timestamp >= windowStart)
        if (relevantSignals.length === 0) return null

        // Sort by timestamp (defensive — should already be ordered)
        relevantSignals.sort((a, b) => a.timestamp - b.timestamp)

        // Try to match each step
        const stepMatches: ChainMatch['stepMatches'] = []
        let lastMatchTime = 0

        for (let stepIndex = 0; stepIndex < chain.steps.length; stepIndex++) {
            const step = chain.steps[stepIndex]
            const minConf = step.minConfidence ?? 0.3

            // Find the first signal after the last match that satisfies this step
            for (const signal of relevantSignals) {
                if (signal.timestamp <= lastMatchTime && stepMatches.length > 0) continue

                // Check if this signal satisfies the step
                const classMatch = step.classes.length === 0 ||
                    step.classes.some(c => signal.classes.includes(c))
                const behaviorMatch = !step.behaviors || step.behaviors.length === 0 ||
                    step.behaviors.some(b => signal.behaviors.includes(b))

                if ((classMatch || behaviorMatch) && signal.confidence >= minConf) {
                    const matchedClass = step.classes.find(c => signal.classes.includes(c)) ??
                        step.behaviors?.find(b => signal.behaviors.includes(b)) ??
                        'behavioral'

                    stepMatches.push({
                        stepIndex,
                        description: step.description,
                        matchedClass,
                        confidence: signal.confidence,
                        timestamp: signal.timestamp,
                        path: signal.path,
                    })
                    lastMatchTime = signal.timestamp
                    break // Move to next step
                }
            }
        }

        // Check if enough steps matched
        const minSteps = chain.minimumSteps ?? chain.steps.length
        if (stepMatches.length < minSteps) return null

        // Calculate compounded confidence
        const baseConfidence = stepMatches.reduce((sum, m) => sum + m.confidence, 0) / stepMatches.length
        const completionRatio = stepMatches.length / chain.steps.length
        const compoundedConfidence = Math.min(0.99,
            baseConfidence + (chain.confidenceBoost * completionRatio)
        )

        // Determine recommended action based on completion and severity
        const recommendedAction = this.determineAction(chain, completionRatio, compoundedConfidence)

        // Calculate duration
        const firstMatch = stepMatches[0].timestamp
        const lastMatch = stepMatches[stepMatches.length - 1].timestamp
        const durationSeconds = Math.round((lastMatch - firstMatch) / 1000)

        return {
            chainId: chain.id,
            name: chain.name,
            stepsMatched: stepMatches.length,
            totalSteps: chain.steps.length,
            completion: completionRatio,
            confidence: compoundedConfidence,
            severity: chain.severity,
            description: chain.description,
            recommendedAction,
            stepMatches,
            durationSeconds,
            sourceHash,
        }
    }

    /**
     * Determine defense action based on chain completion and confidence.
     *
     * Decision matrix:
     *   100% completion + critical severity → lockdown
     *   100% completion + high severity → block
     *   ≥66% completion + critical → block
     *   ≥50% completion + any → challenge
     *   <50% completion → throttle (if critical) or monitor
     */
    private determineAction(
        chain: ChainDefinition,
        completion: number,
        confidence: number,
    ): ChainMatch['recommendedAction'] {
        if (completion >= 1.0 && chain.severity === 'critical') return 'lockdown'
        if (completion >= 1.0) return 'block'
        if (completion >= 0.66 && chain.severity === 'critical') return 'block'
        if (completion >= 0.66 && confidence >= 0.8) return 'block'
        if (completion >= 0.5) return 'challenge'
        if (chain.severity === 'critical') return 'throttle'
        return 'monitor'
    }

    /**
     * Remove source windows where all signals are older than the
     * longest chain window. Prevents unbounded memory growth.
     */
    private pruneStaleWindows(): void {
        const maxWindow = Math.max(...this.chainDefs.map(c => c.windowSeconds)) * 1000
        const cutoff = Date.now() - maxWindow

        for (const [source, signals] of this.sourceWindows.entries()) {
            const latest = signals[signals.length - 1]?.timestamp ?? 0
            if (latest < cutoff) {
                this.sourceWindows.delete(source)
            }
        }
        this.lastPrune = Date.now()
    }

    /**
     * Get all active chains for a given source.
     * Used by the dashboard to show in-progress attack sequences.
     */
    getActiveChains(sourceHash: string): ChainMatch[] {
        const window = this.sourceWindows.get(sourceHash)
        if (!window || window.length === 0) return []
        return this.evaluateChains(sourceHash, window)
    }

    /**
     * Get all sources with active chain matches.
     * Used by the autonomous defense system to decide mode escalation.
     */
    getAllActiveChains(): ChainMatch[] {
        const allMatches: ChainMatch[] = []
        for (const [sourceHash, signals] of this.sourceWindows.entries()) {
            const matches = this.evaluateChains(sourceHash, signals)
            allMatches.push(...matches)
        }
        return allMatches
    }

    /** Number of active source windows */
    get activeSourceCount(): number {
        return this.sourceWindows.size
    }

    /** Total signals across all sources */
    get totalSignals(): number {
        let total = 0
        for (const signals of this.sourceWindows.values()) {
            total += signals.length
        }
        return total
    }

    /** Registered chain count */
    get chainCount(): number {
        return this.chainDefs.length
    }
}
