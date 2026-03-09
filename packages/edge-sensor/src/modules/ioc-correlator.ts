/**
 * @santh/edge-sensor — IOC Feed Correlator
 *
 * Cross-references live traffic signals against threat intelligence:
 *   - IP reputation lists (Tor exits, known botnets, scanners)
 *   - Domain blocklists (C2 domains appearing in SSRF targets)
 *   - Payload hash IOCs (known exploit payload signatures)
 *   - CVE-to-exploit mapping (link detected patterns to CVEs)
 *
 * Concept from Axiom Drift's ThreatIntelService and IOC tracking,
 * adapted for edge-level real-time correlation without backend deps.
 *
 * IOC feeds are synced from the intel pipeline via KV stored rules.
 * The correlator operates in-memory for O(1) lookups per request.
 */


// ── Types ─────────────────────────────────────────────────────────

export type IOCType =
    | 'ip_reputation'      // Known bad IP ranges
    | 'domain_blocklist'   // Known C2 / malicious domains
    | 'payload_hash'       // SHA-256 hash of known exploit payloads
    | 'user_agent_sig'     // Known malicious User-Agent fingerprints
    | 'cve_pattern'        // Regex patterns tied to specific CVEs

export interface IOCEntry {
    type: IOCType
    value: string               // The indicator value (IP, domain, hash, regex)
    threat: string              // Threat name / campaign
    severity: 'critical' | 'high' | 'medium' | 'low'
    confidence: number          // 0.0 - 1.0
    linkedCves: string[]        // Associated CVEs
    source: string              // Feed source (e.g., 'santh_intel', 'abuse_ch')
    lastUpdated: string         // ISO timestamp
    ttl: number                 // Seconds until expiry (0 = permanent)
}

export interface IOCMatch {
    iocType: IOCType
    indicator: string
    threat: string
    severity: IOCEntry['severity']
    confidence: number
    linkedCves: string[]
    source: string
    matchContext: string        // Where the match occurred
}


// ── IOC Correlator ────────────────────────────────────────────────

export class IOCCorrelator {
    private ipSet = new Map<string, IOCEntry>()
    private domainSet = new Map<string, IOCEntry>()
    private payloadHashes = new Map<string, IOCEntry>()
    private uaSignatures: Array<{ pattern: RegExp; entry: IOCEntry }> = []
    private cvePatterns: Array<{ pattern: RegExp; entry: IOCEntry }> = []
    private lastSync = 0
    private readonly cloudMetadataIndicators: Array<{ indicator: string; pattern: RegExp; threat: string }> = [
        { indicator: '169.254.169.254/latest/meta-data', pattern: /https?:\/\/169\.254\.169\.254\/latest\/meta-data(?:[/?#]|$)/i, threat: 'aws_imds_access' },
        { indicator: '169.254.169.254/latest/api/token', pattern: /https?:\/\/169\.254\.169\.254\/latest\/api\/token(?:[/?#]|$)/i, threat: 'aws_imdsv2_token_access' },
        { indicator: 'metadata.google.internal', pattern: /https?:\/\/metadata\.google\.internal(?:[/:?#]|$)/i, threat: 'gcp_metadata_access' },
        { indicator: '169.254.169.254/computeMetadata', pattern: /https?:\/\/169\.254\.169\.254\/computeMetadata(?:[/?#]|$)/i, threat: 'gcp_metadata_access' },
        { indicator: '169.254.169.254/metadata/identity', pattern: /https?:\/\/169\.254\.169\.254\/metadata\/identity(?:[/?#]|$)/i, threat: 'azure_imds_access' },
        { indicator: '169.254.169.254/metadata/instance', pattern: /https?:\/\/169\.254\.169\.254\/metadata\/instance(?:[/?#]|$)/i, threat: 'azure_imds_access' },
        { indicator: 'metadata.digitalocean.com', pattern: /https?:\/\/metadata\.digitalocean\.com(?:[/:?#]|$)/i, threat: 'digitalocean_metadata_access' },
        { indicator: '169.254.169.254/opc', pattern: /https?:\/\/169\.254\.169\.254\/opc(?:[/?#]|$)/i, threat: 'oracle_cloud_metadata_access' },
    ]

    /**
     * Load IOC feed data. Called during rule sync from intel pipeline.
     * Replaces existing entries (full refresh).
     */
    loadFeed(entries: IOCEntry[]): void {
        this.ipSet.clear()
        this.domainSet.clear()
        this.payloadHashes.clear()
        this.uaSignatures = []
        this.cvePatterns = []

        const now = Date.now()

        for (const entry of entries) {
            // Skip expired entries
            if (entry.ttl > 0) {
                const expiry = new Date(entry.lastUpdated).getTime() + entry.ttl * 1000
                if (now > expiry) continue
            }

            switch (entry.type) {
                case 'ip_reputation':
                    this.ipSet.set(entry.value, entry)
                    break
                case 'domain_blocklist':
                    this.domainSet.set(entry.value.toLowerCase(), entry)
                    break
                case 'payload_hash':
                    this.payloadHashes.set(entry.value.toLowerCase(), entry)
                    break
                case 'user_agent_sig': {
                    // SECURITY (SAA-042): Validate regex before accepting into hot path.
                    // Malicious IOC feed entry with ReDoS regex runs on every request.
                    const safeRegex = this.compileRegexSafe(entry.value)
                    if (safeRegex) {
                        this.uaSignatures.push({ pattern: safeRegex, entry })
                    }
                    break
                }
                case 'cve_pattern': {
                    const safeRegex = this.compileRegexSafe(entry.value)
                    if (safeRegex) {
                        this.cvePatterns.push({ pattern: safeRegex, entry })
                    }
                    break
                }
            }
        }

        this.lastSync = now
    }

    /**
     * Compile regex with safety checks.
     * Rejects patterns that:
     *   - Fail to compile
     *   - Are excessively long (> 200 chars — no legitimate IOC needs this)
     *   - Contain catastrophic backtracking patterns
     */
    private compileRegexSafe(pattern: string): RegExp | null {
        // Length limit — legitimate IOC patterns are short
        if (pattern.length > 200) return null

        // SAA-093: Comprehensive ReDoS defense (matches rule-sync isRegexSafe)
        // Nested quantifiers: (a+)+, (a*)+, (a+)*, (a+){n,m}
        if (/(\+|\*|\{[0-9,]+\})\s*\)(\+|\*|\{[0-9,]+\}|\?)/.test(pattern)) return null
        // Alternation with quantified groups: (a|b+)+
        if (/\([^)]*\|[^)]*(\+|\*)\)\s*(\+|\*)/.test(pattern)) return null
        // Backreferences: exponential backtracking risk
        if (/\\[1-9]/.test(pattern)) return null
        // Lookahead/lookbehind with quantifiers inside
        if (/\(\?[<=!][^)]*(\+|\*|\{)/.test(pattern)) return null

        try {
            return new RegExp(pattern, 'i')
        } catch {
            return null
        }
    }

    /**
     * Correlate a request against loaded IOC feeds.
     * Returns all matches found.
     */
    correlate(context: {
        sourceHash: string
        sourceIp?: string
        userAgent: string
        url: string
        decodedInput: string
        payloadHash?: string
    }): IOCMatch[] {
        const matches: IOCMatch[] = []
        const combinedInput = `${context.url}\n${context.decodedInput}`

        // 1. IP reputation check
        if (context.sourceIp) {
            const ipEntry = this.ipSet.get(context.sourceIp)
            if (ipEntry) {
                matches.push({
                    iocType: 'ip_reputation',
                    indicator: context.sourceIp,
                    threat: ipEntry.threat,
                    severity: ipEntry.severity,
                    confidence: ipEntry.confidence,
                    linkedCves: ipEntry.linkedCves,
                    source: ipEntry.source,
                    matchContext: 'source_ip',
                })
            }
        }

        // 2. Domain extraction from URL/input and blocklist check
        const domains = this.extractDomains(context.decodedInput)
        for (const domain of domains) {
            const domainEntry = this.domainSet.get(domain)
            if (domainEntry) {
                matches.push({
                    iocType: 'domain_blocklist',
                    indicator: domain,
                    threat: domainEntry.threat,
                    severity: domainEntry.severity,
                    confidence: domainEntry.confidence,
                    linkedCves: domainEntry.linkedCves,
                    source: domainEntry.source,
                    matchContext: 'request_input',
                })
            }
        }

        // 2b. Built-in cloud metadata endpoint correlation
        for (const indicator of this.cloudMetadataIndicators) {
            if (indicator.pattern.test(combinedInput)) {
                matches.push({
                    iocType: 'domain_blocklist',
                    indicator: indicator.indicator,
                    threat: indicator.threat,
                    severity: 'critical',
                    confidence: 0.95,
                    linkedCves: [],
                    source: 'built_in_cloud_metadata',
                    matchContext: 'request_input',
                })
            }
        }

        // 3. Payload hash check
        if (context.payloadHash) {
            const hashEntry = this.payloadHashes.get(context.payloadHash.toLowerCase())
            if (hashEntry) {
                matches.push({
                    iocType: 'payload_hash',
                    indicator: context.payloadHash,
                    threat: hashEntry.threat,
                    severity: hashEntry.severity,
                    confidence: hashEntry.confidence,
                    linkedCves: hashEntry.linkedCves,
                    source: hashEntry.source,
                    matchContext: 'payload',
                })
            }
        }

        // 4. User-Agent signature check
        for (const { pattern, entry } of this.uaSignatures) {
            if (pattern.test(context.userAgent)) {
                matches.push({
                    iocType: 'user_agent_sig',
                    indicator: context.userAgent.slice(0, 100),
                    threat: entry.threat,
                    severity: entry.severity,
                    confidence: entry.confidence,
                    linkedCves: entry.linkedCves,
                    source: entry.source,
                    matchContext: 'user_agent',
                })
                break // One UA match is sufficient
            }
        }

        // 5. CVE pattern check against decoded input
        for (const { pattern, entry } of this.cvePatterns) {
            if (pattern.test(context.decodedInput)) {
                matches.push({
                    iocType: 'cve_pattern',
                    indicator: entry.linkedCves[0] ?? entry.value,
                    threat: entry.threat,
                    severity: entry.severity,
                    confidence: entry.confidence,
                    linkedCves: entry.linkedCves,
                    source: entry.source,
                    matchContext: 'request_input',
                })
            }
        }

        return matches
    }

    /**
     * Extract domains from input text (URLs, SSRF targets, etc.)
     */
    private extractDomains(input: string): string[] {
        const domains = new Set<string>()
        // Match URLs
        const urlMatch = input.matchAll(/https?:\/\/([^\/\s:?#]+)/gi)
        for (const m of urlMatch) {
            domains.add(m[1].toLowerCase())
        }
        // Match bare domains
        const domainMatch = input.matchAll(/(?:^|[\s\/"'])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:[a-z]{2,}))/gi)
        for (const m of domainMatch) {
            domains.add(m[1].toLowerCase())
        }
        return [...domains]
    }

    /** Number of loaded indicators */
    get indicatorCount(): number {
        return this.ipSet.size + this.domainSet.size + this.payloadHashes.size +
            this.uaSignatures.length + this.cvePatterns.length
    }

    /** Time since last sync in seconds */
    get syncAge(): number {
        return this.lastSync === 0 ? Infinity : (Date.now() - this.lastSync) / 1000
    }

    /** Summary of loaded indicators by type */
    get summary(): Record<IOCType, number> {
        return {
            ip_reputation: this.ipSet.size,
            domain_blocklist: this.domainSet.size,
            payload_hash: this.payloadHashes.size,
            user_agent_sig: this.uaSignatures.length,
            cve_pattern: this.cvePatterns.length,
        }
    }
}
