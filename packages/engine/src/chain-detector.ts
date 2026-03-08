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

interface ChainStateNode {
    chainId: string
    sourceHash: string
    satisfiedSteps: Map<number, { signal: ChainSignal, confidence: number }>
    startTime: number
    lastUpdate: number
    status: 'in_progress' | 'completed' | 'expired'
    completedAt?: number
    stepsMatched: number
}

class ChainStateStore {
    // outer key = sourceHash, inner key = chainId
    private states: Map<string, Map<string, ChainStateNode>> = new Map()
    private readonly maxSources: number

    constructor(maxSources = 5_000) {
        this.maxSources = maxSources
    }

    getOrCreate(sourceHash: string, chainId: string, windowSeconds: number): ChainStateNode {
        if (!this.states.has(sourceHash)) this.states.set(sourceHash, new Map())
        const bySource = this.states.get(sourceHash)!
        if (!bySource.has(chainId)) {
            const now = Date.now()
            bySource.set(chainId, {
                chainId,
                sourceHash,
                satisfiedSteps: new Map(),
                startTime: now,
                lastUpdate: now,
                status: 'in_progress',
                stepsMatched: 0,
            })
        }
        const state = bySource.get(chainId)!
        const now = Date.now()

        // Check expiry: if started > windowSeconds ago with no completion, expire it
        if (state.status === 'in_progress' && now - state.startTime > windowSeconds * 1000) {
            state.status = 'expired'
        }
        return state
    }

    advance(
        sourceHash: string,
        chainId: string,
        stepIndex: number,
        signal: ChainSignal,
        windowSeconds: number,
    ): void {
        const state = this.getOrCreate(sourceHash, chainId, windowSeconds)
        if (state.status !== 'in_progress') return

        // If this is the first step, record its signal timestamp as the chain start.
        // All subsequent steps are checked against this signal-space start time,
        // not wall-clock time, so tests using explicit timestamps work correctly.
        if (state.satisfiedSteps.size === 0) {
            state.startTime = signal.timestamp
        } else {
            // Expire if the incoming signal's timestamp is beyond the chain window
            // relative to the first signal's timestamp.
            if (signal.timestamp - state.startTime > windowSeconds * 1000) {
                state.status = 'expired'
                return
            }
        }

        if (state.satisfiedSteps.has(stepIndex)) return // already satisfied
        state.satisfiedSteps.set(stepIndex, { signal, confidence: signal.confidence })
        state.stepsMatched = state.satisfiedSteps.size
        state.lastUpdate = signal.timestamp
    }

    complete(sourceHash: string, chainId: string): void {
        const state = this.states.get(sourceHash)?.get(chainId)
        if (state) {
            state.status = 'completed'
            state.completedAt = Date.now()
            state.lastUpdate = state.completedAt
        }
    }

    getState(sourceHash: string, chainId: string): ChainStateNode | undefined {
        return this.states.get(sourceHash)?.get(chainId)
    }

    getAllForSource(sourceHash: string): ChainStateNode[] {
        return Array.from(this.states.get(sourceHash)?.values() ?? [])
    }

    getAllSources(): string[] {
        return Array.from(this.states.keys())
    }

    removeSource(sourceHash: string): void {
        this.states.delete(sourceHash)
    }

    pruneExpired(maxWindowSeconds: number): void {
        const cutoff = Date.now() - maxWindowSeconds * 1000 * 2 // 2x window to keep completed chains for forensics
        for (const [sourceHash, byChain] of this.states) {
            let allExpired = true
            for (const [chainId, state] of byChain) {
                if (state.lastUpdate < cutoff) {
                    byChain.delete(chainId)
                } else {
                    allExpired = false
                }
            }
            if (allExpired || byChain.size === 0) this.states.delete(sourceHash)
        }
        // Hard cap: evict oldest sources if over max
        if (this.states.size > this.maxSources) {
            const sorted = [...this.states.entries()]
                .map(([k, v]) => ({
                    k,
                    latest: Math.max(...[...v.values()].map(s => s.lastUpdate)),
                }))
                .sort((a, b) => a.latest - b.latest)
            const evict = this.states.size - this.maxSources
            for (let i = 0; i < evict; i++) this.states.delete(sorted[i].k)
        }
    }

    get sourceCount(): number {
        return this.states.size
    }
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

    // ═══════════════════════════════════════════════════════════════
    // NATION-STATE / APT ATTACK CHAINS
    // These model sophisticated multi-phase attacks observed in
    // real-world APT campaigns (APT28, APT29, Lazarus, Hafnium, etc.)
    // ═══════════════════════════════════════════════════════════════

    // ── 13. Supply Chain: Deser → SSRF → Cloud Pivot ─────────────
    {
        id: 'supply_chain_pivot',
        name: 'Supply Chain Exploit → Cloud Pivot',
        description: 'Exploit deserialization vulnerability in a dependency to gain initial access, use SSRF to reach cloud metadata, extract IAM credentials, and pivot to cloud infrastructure. Modeled after SolarWinds/Log4Shell patterns.',
        mitre: ['T1195.002', 'T1190', 'T1552.005'],
        severity: 'critical',
        steps: [
            {
                classes: ['deser_java_gadget', 'deser_php_object', 'deser_python_pickle', 'log_jndi_lookup'],
                description: 'Initial access via deserialization or JNDI injection in third-party component',
                defense: 'block',
            },
            {
                classes: ['cmd_separator', 'cmd_substitution'],
                behaviors: ['outbound_connection', 'class_loading'],
                description: 'Establish execution capability via command injection or class loading',
                defense: 'block',
            },
            {
                classes: ['ssrf_cloud_metadata', 'ssrf_internal_reach'],
                behaviors: ['credential_extraction'],
                description: 'Reach cloud metadata endpoint to extract IAM credentials for lateral movement',
                defense: 'block',
            },
        ],
        windowSeconds: 600,
        minimumSteps: 2,
        confidenceBoost: 0.4,
    },

    // ── 14. DNS Rebinding → SSRF → Internal Service Access ───────
    {
        id: 'dns_rebinding_ssrf',
        name: 'DNS Rebinding → SSRF → Internal Access',
        description: 'Use DNS rebinding to bypass same-origin and SSRF filters. Initial request resolves to allowed IP, TTL expires, second resolution points to internal IP (169.254.169.254, 10.x, etc.).',
        mitre: ['T1557', 'T1210'],
        severity: 'critical',
        steps: [
            {
                classes: ['ssrf_internal_reach'],
                description: 'Probe SSRF with external URL (DNS rebinding setup)',
                defense: 'alert',
            },
            {
                classes: ['ssrf_cloud_metadata', 'ssrf_protocol_smuggle'],
                description: 'Rebinding resolves to internal target — cloud metadata or internal service',
                defense: 'block',
            },
            {
                classes: ['auth_header_spoof'],
                behaviors: ['credential_extraction', 'admin_access'],
                description: 'Use extracted credentials to access internal services',
                defense: 'block',
            },
        ],
        windowSeconds: 120,
        minimumSteps: 2,
        confidenceBoost: 0.35,
    },

    // ── 15. HTTP Desync → Request Smuggling → Auth Bypass ────────
    {
        id: 'http_desync_auth_bypass',
        name: 'HTTP Desync → Request Smuggling → Auth Bypass',
        description: 'Exploit CL.TE or H2 downgrade desync to smuggle a second request through reverse proxy, bypassing authentication applied at the proxy layer. Used by APT groups to bypass WAF + auth in one step.',
        mitre: ['T1557', 'T1190', 'T1078'],
        severity: 'critical',
        steps: [
            {
                classes: ['http_smuggle_cl_te', 'http_smuggle_h2'],
                description: 'Exploit Transfer-Encoding/Content-Length desync or H2→H1 downgrade',
                defense: 'block',
            },
            {
                classes: ['auth_header_spoof', 'auth_none_algorithm'],
                behaviors: ['admin_access', 'privilege_escalation'],
                description: 'Smuggled request reaches upstream with forged identity, bypassing proxy auth',
                defense: 'block',
            },
        ],
        windowSeconds: 60,
        minimumSteps: 1,
        confidenceBoost: 0.4,
    },

    // ── 16. SSRF → Cloud IAM → Cross-Account Pivot ──────────────
    {
        id: 'cloud_iam_escalation',
        name: 'SSRF → Cloud IAM → Cross-Account Escalation',
        description: 'Use SSRF to extract IAM temporary credentials from instance metadata, then assume roles across AWS accounts using sts:AssumeRole. Modeled after Capital One breach and Pacu framework TTPs.',
        mitre: ['T1552.005', 'T1078.004', 'T1550.001'],
        severity: 'critical',
        steps: [
            {
                classes: ['ssrf_cloud_metadata'],
                description: 'Extract IAM credentials from cloud metadata endpoint (169.254.169.254)',
                defense: 'block',
            },
            {
                classes: ['ssrf_internal_reach', 'ssrf_protocol_smuggle'],
                behaviors: ['credential_extraction'],
                description: 'Use extracted credentials to enumerate and access internal cloud services',
                defense: 'block',
            },
            {
                classes: [],
                behaviors: ['outbound_connection', 'admin_access'],
                description: 'Pivot to additional cloud accounts using assumed role credentials',
                defense: 'block',
            },
        ],
        windowSeconds: 900,
        minimumSteps: 2,
        confidenceBoost: 0.4,
    },

    // ── 17. Multi-Stage Web Shell Deployment ─────────────────────
    {
        id: 'webshell_deployment',
        name: 'Vuln Exploit → File Write → Web Shell → C2',
        description: 'Exploit any RCE-class vulnerability to write a web shell, then use it for persistent command execution. Modeled after Hafnium Exchange attacks (ProxyShell → China Chopper).',
        mitre: ['T1190', 'T1505.003', 'T1059'],
        severity: 'critical',
        steps: [
            {
                classes: ['sql_stacked_execution', 'ssti_jinja_twig', 'ssti_el_expression',
                    'deser_java_gadget', 'deser_php_object', 'log_jndi_lookup'],
                description: 'Exploit RCE-class vulnerability for initial code execution',
                defense: 'block',
            },
            {
                classes: ['cmd_separator', 'cmd_substitution', 'cmd_argument_injection'],
                behaviors: ['code_execution', 'reverse_shell'],
                description: 'Use RCE to write web shell file to web-accessible directory',
                defense: 'block',
            },
            {
                classes: ['path_dotdot_escape', 'path_encoding_bypass'],
                behaviors: ['outbound_connection'],
                description: 'Verify web shell access and establish persistent C2 channel',
                defense: 'block',
            },
        ],
        windowSeconds: 1800,
        minimumSteps: 2,
        confidenceBoost: 0.35,
    },

    // ── 18. OOB Data Exfiltration Chain ──────────────────────────
    {
        id: 'oob_data_exfil',
        name: 'Blind Injection → OOB Exfiltration',
        description: 'Use blind injection (SQLi time oracle, XXE, SSRF) with out-of-band exfiltration via DNS or HTTP to attacker-controlled server. Bypasses all output-based detection because data never appears in the response.',
        mitre: ['T1190', 'T1048'],
        severity: 'critical',
        steps: [
            {
                classes: ['sql_time_oracle', 'sql_error_oracle', 'xxe_entity_expansion'],
                description: 'Detect blind injection point via timing or error side channels',
                defense: 'alert',
            },
            {
                classes: ['ssrf_internal_reach', 'ssrf_protocol_smuggle'],
                behaviors: ['outbound_connection'],
                description: 'Use injection to trigger outbound connection to attacker DNS or HTTP callback',
                minConfidence: 0.4,
                defense: 'block',
            },
            {
                classes: ['sql_union_extraction', 'sql_stacked_execution'],
                description: 'Full data exfiltration via OOB channel (DNS encoding, HTTP body)',
                defense: 'block',
            },
        ],
        windowSeconds: 1200,
        minimumSteps: 2,
        confidenceBoost: 0.3,
    },

    // ── 19. CORS + XSS → Credential Theft ───────────────────────
    {
        id: 'cors_credential_theft',
        name: 'CORS Abuse → XSS → Credential Harvest',
        description: 'Exploit permissive CORS policy to enable cross-origin XSS, then steal authentication tokens and session cookies. The attacker never directly touches the target — the victim\'s browser does the work.',
        mitre: ['T1189', 'T1539', 'T1557'],
        severity: 'critical',
        steps: [
            {
                classes: ['cors_origin_abuse'],
                description: 'Detect permissive CORS policy allowing arbitrary cross-origin access',
                defense: 'alert',
            },
            {
                classes: ['xss_tag_injection', 'xss_event_handler', 'xss_protocol_handler'],
                description: 'Inject XSS payload that executes in the permissive CORS context',
                defense: 'block',
            },
            {
                classes: ['auth_header_spoof'],
                behaviors: ['cookie_exfil', 'privilege_escalation'],
                description: 'Stolen credentials used for authenticated access',
                defense: 'block',
            },
        ],
        windowSeconds: 3600,
        minimumSteps: 2,
        confidenceBoost: 0.25,
    },

    // ── 20. Slow SQLi Reconnaissance Campaign ───────────────────
    {
        id: 'slow_sqli_recon',
        name: 'Low-and-Slow SQLi Reconnaissance',
        description: 'Patient, distributed SQL injection reconnaissance: one probe per minute across many parameters over hours. Each individual request is low-confidence. The campaign model detects the pattern.',
        mitre: ['T1190', 'T1595.002'],
        severity: 'high',
        steps: [
            {
                classes: ['sql_string_termination'],
                minConfidence: 0.3,
                description: 'Single-quote probing across multiple parameters',
                defense: 'alert',
            },
            {
                classes: ['sql_error_oracle', 'sql_time_oracle'],
                minConfidence: 0.3,
                description: 'Error/timing detection on discovered injectable parameters',
                defense: 'alert',
            },
            {
                classes: ['sql_tautology', 'sql_comment_truncation'],
                description: 'Confirm injection with boolean-based or comment-based techniques',
                defense: 'block',
            },
            {
                classes: ['sql_union_extraction'],
                description: 'Begin data extraction after confirming injection',
                defense: 'block',
            },
        ],
        windowSeconds: 7200, // 2 hours — nation-state patience
        minimumSteps: 3,
        confidenceBoost: 0.25,
    },

    // ── Chain 21: JWT Forgery Pipeline ────────────────────────
    {
        id: 'jwt_forgery_pipeline',
        name: 'JWT Forgery Pipeline',
        description: 'Multi-step JWT attack: alg:none probing → kid injection → JWK embedding to achieve authentication bypass with forged tokens.',
        mitre: ['T1550.001'],
        severity: 'critical',
        steps: [
            {
                classes: ['auth_none_algorithm' as InvariantClass],
                description: 'alg:none probing to test signature bypass',
                defense: 'alert',
            },
            {
                classes: ['jwt_kid_injection' as InvariantClass],
                description: 'kid header injection to control key resolution',
                defense: 'block',
            },
            {
                classes: ['jwt_jwk_embedding' as InvariantClass, 'jwt_confusion' as InvariantClass],
                description: 'Self-signed key injection or algorithm confusion for signature forgery',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 2,
        confidenceBoost: 0.20,
    },

    // ── Chain 22: Supply Chain Compromise Pipeline ────────────
    {
        id: 'supply_chain_full_compromise',
        name: 'Supply Chain Full Compromise',
        description: 'Complete supply chain attack: dependency confusion → malicious postinstall → credential exfiltration. The attacker plants a package, executes code on install, and steals secrets.',
        mitre: ['T1195.001', 'T1059.006', 'T1114'],
        severity: 'critical',
        steps: [
            {
                classes: ['dependency_confusion' as InvariantClass],
                description: 'Dependency confusion / typosquat package planted',
                defense: 'alert',
            },
            {
                classes: ['postinstall_injection' as InvariantClass],
                description: 'Malicious lifecycle script executes on install',
                defense: 'block',
            },
            {
                classes: ['env_exfiltration' as InvariantClass],
                description: 'Environment variables exfiltrated to attacker server',
                defense: 'block',
            },
        ],
        windowSeconds: 600,
        minimumSteps: 2,
        confidenceBoost: 0.25,
    },

    // ── Chain 23: LLM Jailbreak Escalation ──────────────────
    {
        id: 'llm_jailbreak_escalation',
        name: 'LLM Jailbreak Escalation',
        description: 'Progressive LLM jailbreak: prompt injection → role override → data exfiltration. Attacker first hijacks the model, then extracts confidential data.',
        mitre: ['T1059.003'],
        severity: 'critical',
        steps: [
            {
                classes: ['llm_prompt_injection' as InvariantClass],
                description: 'Prompt boundary crossing / instruction override',
                defense: 'alert',
            },
            {
                classes: ['llm_jailbreak' as InvariantClass],
                description: 'Known jailbreak framework (DAN/STAN/DUDE) applied',
                defense: 'block',
            },
            {
                classes: ['llm_data_exfiltration' as InvariantClass],
                description: 'Confidential data extraction after jailbreak',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 2,
        confidenceBoost: 0.20,
    },

    // ── Chain 24: Cache Poisoning to XSS ────────────────────
    {
        id: 'cache_poison_xss',
        name: 'Cache Poisoning to Stored XSS',
        description: 'Web cache poisoning chain: manipulate unkeyed headers to inject XSS payload, then serve poisoned response from cache to all visitors.',
        mitre: ['T1557', 'T1189'],
        severity: 'critical',
        steps: [
            {
                classes: ['cache_poisoning' as InvariantClass],
                description: 'Unkeyed header manipulation to poison cache entry',
                defense: 'alert',
            },
            {
                classes: ['xss_tag_injection', 'xss_event_handler', 'xss_protocol_handler'],
                description: 'XSS payload injected via poisoned cache response',
                defense: 'block',
            },
        ],
        windowSeconds: 120,
        minimumSteps: 2,
        confidenceBoost: 0.20,
    },

    // ── Chain 25: API IDOR to Mass Exfiltration ──────────────
    {
        id: 'api_idor_mass_exfil',
        name: 'API IDOR to Mass Data Exfiltration',
        description: 'BOLA/IDOR exploitation followed by mass enumeration to exfiltrate all user records from the API.',
        mitre: ['T1078', 'T1087', 'T1530'],
        severity: 'critical',
        steps: [
            {
                classes: ['bola_idor' as InvariantClass],
                description: 'IDOR probing to test authorization boundary',
                defense: 'alert',
            },
            {
                classes: ['api_mass_enum' as InvariantClass],
                description: 'Mass enumeration / bulk extraction after IDOR confirmed',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 2,
        confidenceBoost: 0.20,
    },

    // ── Chain 26: JWT Forgery to IDOR Escalation ────────────
    {
        id: 'jwt_idor_escalation',
        name: 'JWT Forgery to IDOR Privilege Escalation',
        description: 'Attacker forges JWT token (via algorithm confusion, kid injection, or JWK embedding) then uses the forged identity to access other users\' resources via IDOR.',
        mitre: ['T1550.001', 'T1078'],
        severity: 'critical',
        steps: [
            {
                classes: ['jwt_kid_injection', 'jwt_jwk_embedding', 'jwt_confusion', 'auth_none_algorithm'],
                description: 'JWT manipulation to forge authentication token',
                defense: 'alert',
            },
            {
                classes: ['bola_idor' as InvariantClass],
                description: 'IDOR exploitation using forged identity',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 2,
        confidenceBoost: 0.25,
    },

    // ── Chain 27: Cache Deception to Session Hijack ─────────
    {
        id: 'cache_deception_session_theft',
        name: 'Cache Deception to Session Theft',
        description: 'Attacker tricks CDN into caching authenticated response (cache deception), then accesses the cached page to steal session tokens or PII visible in the response.',
        mitre: ['T1557', 'T1539'],
        severity: 'critical',
        steps: [
            {
                classes: ['cache_deception' as InvariantClass],
                description: 'Cache deception: append static extension to dynamic endpoint',
                defense: 'alert',
            },
            {
                classes: ['cache_poisoning' as InvariantClass],
                description: 'Cache poisoning to serve stolen content to other users',
                defense: 'block',
            },
        ],
        windowSeconds: 180,
        minimumSteps: 1,
        confidenceBoost: 0.15,
    },

    // ── Chain 28: LLM Jailbreak to Supply Chain Pivot ──────
    {
        id: 'llm_supply_chain_pivot',
        name: 'LLM Jailbreak to Supply Chain Compromise',
        description: 'Attacker jailbreaks an AI coding assistant to inject malicious dependencies or postinstall scripts into generated code, pivoting from LLM compromise to supply chain attack.',
        mitre: ['T1059.003', 'T1195.001'],
        severity: 'critical',
        steps: [
            {
                classes: ['llm_jailbreak' as InvariantClass, 'llm_prompt_injection' as InvariantClass],
                description: 'Jailbreak or prompt injection targeting AI assistant',
                defense: 'alert',
            },
            {
                classes: ['dependency_confusion' as InvariantClass, 'postinstall_injection' as InvariantClass],
                description: 'Malicious dependency or postinstall script in generated output',
                defense: 'block',
            },
        ],
        windowSeconds: 600,
        minimumSteps: 2,
        confidenceBoost: 0.20,
    },

    // ── Chain 29: SSRF to API Mass Enumeration ─────────────
    {
        id: 'ssrf_api_exfil',
        name: 'SSRF to Internal API Mass Exfiltration',
        description: 'Attacker uses SSRF to reach internal APIs, then mass-enumerates internal endpoints to exfiltrate data that is not exposed to the public internet.',
        mitre: ['T1090', 'T1087', 'T1530'],
        severity: 'critical',
        steps: [
            {
                classes: ['ssrf_internal_reach'],
                description: 'SSRF to reach internal network or API',
                defense: 'alert',
            },
            {
                classes: ['api_mass_enum' as InvariantClass, 'bola_idor' as InvariantClass],
                description: 'Mass enumeration or IDOR on internal API endpoints',
                defense: 'block',
            },
        ],
        windowSeconds: 300,
        minimumSteps: 2,
        confidenceBoost: 0.20,
    },

    // ── Chain 30: SQLi Probe to LFI to Credential Exfil ────
    {
        id: 'sqli_lfi_credential_theft',
        name: 'SQLi Probe to LFI Credential Extraction',
        description: 'Attacker probes SQL injection to map the application, discovers path traversal, then extracts credential files (passwd, shadow, .env) via LFI — a common dual-vector attack on PHP apps.',
        mitre: ['T1190', 'T1005', 'T1552.001'],
        severity: 'critical',
        steps: [
            {
                classes: ['sql_error_oracle', 'sql_tautology', 'sql_string_termination'],
                description: 'SQL injection probing to map application',
                defense: 'alert',
            },
            {
                classes: ['path_dotdot_escape', 'path_encoding_bypass'],
                description: 'Path traversal to access server files',
                defense: 'throttle',
            },
            {
                classes: ['path_dotdot_escape', 'path_encoding_bypass'],
                behaviors: ['path_sensitive_file'],
                description: 'Credential file extraction via LFI',
                defense: 'block',
            },
        ],
        windowSeconds: 600,
        minimumSteps: 2,
        confidenceBoost: 0.25,
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
    private readonly chainById: Map<string, ChainDefinition>
    private readonly stateStore: ChainStateStore
    private lastPrune: number = Date.now()
    // SECURITY (SAA-044): Cap source count to prevent memory exhaustion
    // under distributed botnet attacks (10k+ unique IPs)
    private readonly maxSources: number

    constructor(
        chains: ChainDefinition[] = ATTACK_CHAINS,
        maxSignalsPerSource = 200,
        maxSources = 5_000,
    ) {
        this.chainDefs = chains
        this.chainById = new Map(chains.map(chain => [chain.id, chain]))
        this.maxSignalsPerSource = maxSignalsPerSource
        this.maxSources = maxSources
        this.stateStore = new ChainStateStore(maxSources)
    }

    /**
     * Ingest a new signal and evaluate all chains.
     * Returns any chain matches detected.
     *
     * This is the hot path — called on every request that produces
     * an invariant match or behavioral signal.
     */
    ingest(signal: ChainSignal): ChainMatch[] {
        // Store signal window for metrics + stale source eviction.
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

        // Hard cap: if sources exceed max, force prune + evict oldest
        if (this.sourceWindows.size > this.maxSources) {
            this.pruneStaleWindows()
            // If still over, evict oldest sources
            if (this.sourceWindows.size > this.maxSources) {
                const sortedSources = [...this.sourceWindows.entries()]
                    .map(([key, signals]) => ({
                        key,
                        latest: signals[signals.length - 1]?.timestamp ?? 0,
                    }))
                    .sort((a, b) => a.latest - b.latest)
                const evictCount = this.sourceWindows.size - this.maxSources
                for (let i = 0; i < evictCount; i++) {
                    const sourceHash = sortedSources[i].key
                    this.sourceWindows.delete(sourceHash)
                    this.stateStore.removeSource(sourceHash)
                }
            }
        }

        const touchedChainIds = new Set<string>()

        // Find all chain/step pairs this signal satisfies (out-of-order allowed).
        for (const chain of this.chainDefs) {
            for (let stepIndex = 0; stepIndex < chain.steps.length; stepIndex++) {
                const step = chain.steps[stepIndex]
                const minConf = step.minConfidence ?? 0.3
                const classSatisfied = step.classes.length === 0 ||
                    step.classes.some(c => signal.classes.includes(c))
                const behaviorSatisfied = step.behaviors?.some(b => signal.behaviors.includes(b)) ?? false

                if ((classSatisfied || behaviorSatisfied) && signal.confidence >= minConf) {
                    this.stateStore.advance(
                        signal.sourceHash,
                        chain.id,
                        stepIndex,
                        signal,
                        chain.windowSeconds,
                    )
                    // Only track this chain if the state is still active after advance()
                    // (advance() is a no-op on expired/completed states)
                    const advancedState = this.stateStore.getState(signal.sourceHash, chain.id)
                    if (!advancedState || advancedState.status === 'expired') continue
                    touchedChainIds.add(chain.id)

                    const minSteps = chain.minimumSteps ?? chain.steps.length
                    const state = this.stateStore.getState(signal.sourceHash, chain.id)
                    if (state && state.status === 'in_progress' && state.stepsMatched >= minSteps) {
                        this.stateStore.complete(signal.sourceHash, chain.id)
                    }
                }
            }
        }

        // Only return states touched by this signal to avoid repeated chain re-fire spam.
        const matches: ChainMatch[] = []
        for (const chainId of touchedChainIds) {
            const chain = this.chainById.get(chainId)
            if (!chain) continue
            const state = this.stateStore.getState(signal.sourceHash, chainId)
            if (!state) continue
            const match = this.stateToChainMatch(state, chain)
            if (match) matches.push(match)
        }
        return matches
    }

    /**
     * Evaluate all chain definitions against a source's signal window.
     * Returns all chains where sufficient steps match.
     */
    private evaluateChains(sourceHash: string, _signals: ChainSignal[]): ChainMatch[] {
        const matches: ChainMatch[] = []
        const states = this.stateStore.getAllForSource(sourceHash)
        for (const state of states) {
            const chain = this.chainById.get(state.chainId)
            if (!chain) continue
            const match = this.stateToChainMatch(state, chain)
            if (match) {
                matches.push(match)
            }
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
        _signals: ChainSignal[],
    ): ChainMatch | null {
        const state = this.stateStore.getState(sourceHash, chain.id)
        if (!state) return null
        return this.stateToChainMatch(state, chain)
    }

    private stateToChainMatch(state: ChainStateNode, chain: ChainDefinition): ChainMatch | null {
        if (state.status === 'expired') return null
        if (state.stepsMatched < 1) return null

        const minSteps = chain.minimumSteps ?? chain.steps.length
        if (state.stepsMatched < minSteps) return null

        const stepMatches: ChainMatch['stepMatches'] = Array.from(state.satisfiedSteps.entries())
            .map(([stepIndex, { signal, confidence }]) => ({
                stepIndex,
                description: chain.steps[stepIndex]?.description ?? '',
                matchedClass: signal.classes[0] ?? 'behavioral',
                confidence,
                timestamp: signal.timestamp,
                path: signal.path,
            }))
            .sort((a, b) => a.stepIndex - b.stepIndex)

        const baseConfidence = stepMatches.reduce((sum, step) => sum + step.confidence, 0) / stepMatches.length
        const completionRatio = state.stepsMatched / chain.steps.length
        const compoundedConfidence = Math.min(
            0.99,
            baseConfidence + chain.confidenceBoost * completionRatio,
        )

        let recommendedAction = this.determineAction(chain, completionRatio, compoundedConfidence)
        if (state.status === 'completed' && (recommendedAction === 'monitor' || recommendedAction === 'throttle' || recommendedAction === 'challenge')) {
            recommendedAction = 'block'
        }

        const timestamps = stepMatches.map(match => match.timestamp)
        const firstStepTimestamp = Math.min(...timestamps)
        const lastStepTimestamp = Math.max(...timestamps)
        const durationSeconds = Math.round((lastStepTimestamp - firstStepTimestamp) / 1000)

        return {
            chainId: chain.id,
            name: chain.name,
            stepsMatched: state.stepsMatched,
            totalSteps: chain.steps.length,
            completion: completionRatio,
            confidence: compoundedConfidence,
            severity: chain.severity,
            description: chain.description,
            recommendedAction,
            stepMatches,
            durationSeconds,
            sourceHash: state.sourceHash,
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
        const maxWindowSeconds = Math.max(...this.chainDefs.map(c => c.windowSeconds))
        const cutoff = Date.now() - maxWindowSeconds * 1000 * 2
        this.stateStore.pruneExpired(maxWindowSeconds)

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
        return this.evaluateChains(sourceHash, [])
    }

    /**
     * Get all sources with active chain matches.
     * Used by the autonomous defense system to decide mode escalation.
     */
    getAllActiveChains(): ChainMatch[] {
        const allMatches: ChainMatch[] = []
        for (const sourceHash of this.stateStore.getAllSources()) {
            const matches = this.evaluateChains(sourceHash, [])
            allMatches.push(...matches)
        }
        return allMatches
    }

    /** Number of active source windows */
    get activeSourceCount(): number {
        return this.stateStore.sourceCount
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

    getAttackGraphInference(
        classes: string[],
        behaviors: string[],
    ): Array<{ chainId: string, name: string, probability: number, description: string }> {
        const scored = this.chainDefs
            .map(chain => {
                let satisfied = 0
                for (const step of chain.steps) {
                    const classOverlap = step.classes.some(c => classes.includes(c))
                    const behaviorOverlap = step.behaviors?.some(b => behaviors.includes(b)) ?? false
                    if (classOverlap || behaviorOverlap) {
                        satisfied++
                    }
                }
                return {
                    chainId: chain.id,
                    name: chain.name,
                    probability: satisfied / chain.steps.length,
                    description: chain.description,
                }
            })
            .filter(inference => inference.probability > 0.1)
            .sort((a, b) => b.probability - a.probability)

        return scored.slice(0, 5)
    }

    getChainVelocity(sourceHash: string): Array<{ chainId: string, stepsPerMinute: number, latestStep: number }> {
        const now = Date.now()
        const states = this.stateStore.getAllForSource(sourceHash)
        const velocities = states
            .filter(state => state.status === 'in_progress' && state.stepsMatched > 0)
            .map(state => {
                const elapsedMinutes = Math.max((now - state.startTime) / 60_000, 1 / 60)
                return {
                    chainId: state.chainId,
                    stepsPerMinute: state.stepsMatched / elapsedMinutes,
                    latestStep: state.stepsMatched,
                }
            })
            .filter(velocity => velocity.stepsPerMinute > 2.0)
            .sort((a, b) => b.stepsPerMinute - a.stepsPerMinute)

        return velocities
    }
}
