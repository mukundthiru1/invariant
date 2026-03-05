/**
 * INVARIANT — Attack Campaign Intelligence
 *
 * Individual attack signals are noise. Campaigns are signal.
 *
 * This module detects coordinated attacks by:
 *   1. Behavioral Fingerprinting: How an attacker behaves (timing, ordering,
 *      encoding preferences, tool signatures) persists across IP changes.
 *   2. Attack Phase Modeling: Real attacks follow a progression:
 *      recon → probe → exploit → exfil. We model this state machine.
 *   3. Campaign Correlation: Same behavioral fingerprint across multiple
 *      IPs = same actor. Same payload across multiple sensors = campaign.
 *   4. Escalation Signal: When enough evidence accumulates, the system
 *      escalates defense posture automatically.
 */


// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

/**
 * A behavioral fingerprint captures HOW an attacker behaves,
 * not just what they send. This persists across IP changes.
 */
export interface BehavioralFingerprint {
    /** Hash of the fingerprint for comparison */
    hash: string
    /** Average time between requests */
    avgIntervalMs: number
    /** Standard deviation of request intervals */
    intervalStdDev: number
    /** Preferred encoding techniques */
    encodingPreferences: EncodingPreference[]
    /** Attack technique ordering pattern */
    techniqueOrdering: string[]
    /** Tool fingerprint (if detectable) */
    toolSignature: string | null
    /** Evasion sophistication level (0-1) */
    evasionLevel: number
    /** Request header fingerprint */
    headerPattern: string
    /** Number of observations contributing to this fingerprint */
    observations: number
}

export type EncodingPreference =
    | 'plain'
    | 'url_single'
    | 'url_double'
    | 'unicode'
    | 'hex'
    | 'html_entity'
    | 'base64'
    | 'mixed'

/**
 * Attack phase in the kill chain progression.
 */
export type AttackPhase =
    | 'reconnaissance'     // Scanning, enumeration, fingerprinting
    | 'weaponization'      // Crafting attack payloads  
    | 'delivery'           // Sending exploit payloads
    | 'exploitation'       // Successful exploitation attempt
    | 'installation'       // Webshell upload, backdoor
    | 'command_control'    // C2 communication
    | 'exfiltration'       // Data theft

/**
 * A tracked attacker session with behavioral modeling.
 */
export interface AttackerSession {
    /** Source hash (hashed IP) */
    sourceHash: string
    /** All IPs associated with this behavioral fingerprint */
    associatedHashes: Set<string>
    /** Behavioral fingerprint */
    fingerprint: BehavioralFingerprint
    /** Current attack phase */
    currentPhase: AttackPhase
    /** Phase progression history */
    phaseHistory: { phase: AttackPhase; timestamp: number; confidence: number }[]
    /** All signals received from this actor */
    signals: CampaignSignal[]
    /** Overall threat assessment */
    threatLevel: number
    /** First seen timestamp */
    firstSeen: number
    /** Last seen timestamp */
    lastSeen: number
}

export interface CampaignSignal {
    /** Signal type (invariant class or signature ID) */
    type: string
    /** When it was detected */
    timestamp: number
    /** Detection confidence */
    confidence: number
    /** Target path */
    path: string
    /** Source hash */
    sourceHash: string
    /** Encoding used */
    encoding: EncodingPreference
}

/**
 * A detected campaign — coordinated attack across sources or sensors.
 */
export interface Campaign {
    /** Campaign ID */
    id: string
    /** Campaign type */
    type: CampaignType
    /** Behavioral fingerprints involved */
    fingerprints: string[]
    /** Number of distinct sources */
    sourceCount: number
    /** Attack types used */
    attackTypes: string[]
    /** Target paths */
    targetPaths: string[]
    /** Campaign start time */
    startTime: number
    /** Campaign last activity */
    lastActivity: number
    /** Overall severity */
    severity: 'critical' | 'high' | 'medium' | 'low'
    /** Description */
    description: string
    /** Whether defense escalation was triggered */
    escalated: boolean
}

export type CampaignType =
    | 'coordinated_scan'    // Same fingerprint, multiple IPs
    | 'distributed_attack'  // Same payload, multiple sensors
    | 'progressive_attack'  // Kill chain progression from single source
    | 'brute_force'         // High-volume credential/path guessing
    | 'zero_day_probe'      // Novel payload appearing across sensors


// ═══════════════════════════════════════════════════════════════════
// CAMPAIGN INTELLIGENCE ENGINE
// ═══════════════════════════════════════════════════════════════════

export class CampaignIntelligence {
    /** Active attacker sessions indexed by source hash */
    private sessions: Map<string, AttackerSession> = new Map()
    /** Behavioral fingerprint index: fingerprint hash → source hashes */
    private fingerprintIndex: Map<string, Set<string>> = new Map()
    /** Detected campaigns */
    private campaigns: Campaign[] = []
    /** Signal buffer for campaign detection */
    private recentSignals: CampaignSignal[] = []
    /** Maximum signal buffer size */
    private readonly MAX_SIGNALS = 10_000
    /** Session timeout (1 hour) */
    private readonly SESSION_TIMEOUT_MS = 3_600_000
    /** Campaign detection window (5 minutes) */
    private readonly CAMPAIGN_WINDOW_MS = 300_000

    /**
     * Record a new signal from the detection pipeline.
     * This is the main entry point — called for every detection.
     */
    recordSignal(signal: CampaignSignal): void {
        // Get or create session
        let session = this.sessions.get(signal.sourceHash)
        if (!session) {
            session = this.createSession(signal.sourceHash)
            this.sessions.set(signal.sourceHash, session)
        }

        // Update session
        session.signals.push(signal)
        session.lastSeen = signal.timestamp

        // Update fingerprint
        this.updateFingerprint(session)

        // Advance attack phase model
        this.advancePhaseModel(session, signal)

        // Buffer for campaign detection
        this.recentSignals.push(signal)
        if (this.recentSignals.length > this.MAX_SIGNALS) {
            this.recentSignals = this.recentSignals.slice(-this.MAX_SIGNALS / 2)
        }

        // Detect campaigns
        this.detectCampaigns()

        // Prune stale sessions
        this.pruneStaleSessions()
    }

    /**
     * Get the threat level for a source.
     * Used by the defense decision layer.
     */
    getThreatLevel(sourceHash: string): number {
        const session = this.sessions.get(sourceHash)
        if (!session) return 0
        return session.threatLevel
    }

    /**
     * Get the current attack phase for a source.
     */
    getAttackPhase(sourceHash: string): AttackPhase | null {
        return this.sessions.get(sourceHash)?.currentPhase ?? null
    }

    /**
     * Check if a source is part of a known campaign.
     */
    isPartOfCampaign(sourceHash: string): Campaign | null {
        const session = this.sessions.get(sourceHash)
        if (!session) return null

        return this.campaigns.find(c =>
            c.fingerprints.includes(session.fingerprint.hash)) ?? null
    }

    /**
     * Get all active campaigns.
     */
    getActiveCampaigns(): Campaign[] {
        const now = Date.now()
        return this.campaigns.filter(c => now - c.lastActivity < this.CAMPAIGN_WINDOW_MS)
    }

    /**
     * Cross-sensor signal: same payload detected at another sensor.
     * Used by the intel pipeline to correlate across the fleet.
     */
    recordCrossSensorSignal(signalType: string, payloadHash: string, sensorId: string): void {
        // Track novel payload distribution
        const matchingSameWindow = this.recentSignals.filter(s =>
            s.type === signalType &&
            Date.now() - s.timestamp < this.CAMPAIGN_WINDOW_MS
        )

        if (matchingSameWindow.length >= 3) {
            // Same payload type appearing across sources in same window = campaign
            const campaign: Campaign = {
                id: `campaign-${Date.now()}-${signalType}`,
                type: 'distributed_attack',
                fingerprints: [...new Set(matchingSameWindow.map(s => s.sourceHash))],
                sourceCount: new Set(matchingSameWindow.map(s => s.sourceHash)).size,
                attackTypes: [signalType],
                targetPaths: [...new Set(matchingSameWindow.map(s => s.path))],
                startTime: Math.min(...matchingSameWindow.map(s => s.timestamp)),
                lastActivity: Date.now(),
                severity: 'high',
                description: `Distributed ${signalType} campaign: ${matchingSameWindow.length} attacks from ${new Set(matchingSameWindow.map(s => s.sourceHash)).size} sources`,
                escalated: false,
            }
            this.campaigns.push(campaign)
        }
    }

    // ── Session Management ───────────────────────────────────────

    private createSession(sourceHash: string): AttackerSession {
        const now = Date.now()
        return {
            sourceHash,
            associatedHashes: new Set([sourceHash]),
            fingerprint: {
                hash: '',
                avgIntervalMs: 0,
                intervalStdDev: 0,
                encodingPreferences: [],
                techniqueOrdering: [],
                toolSignature: null,
                evasionLevel: 0,
                headerPattern: '',
                observations: 0,
            },
            currentPhase: 'reconnaissance',
            phaseHistory: [{ phase: 'reconnaissance', timestamp: now, confidence: 0.5 }],
            signals: [],
            threatLevel: 0,
            firstSeen: now,
            lastSeen: now,
        }
    }

    // ── Fingerprint Construction ─────────────────────────────────

    private updateFingerprint(session: AttackerSession): void {
        if (session.signals.length < 2) return

        const signals = session.signals

        // Calculate timing distribution
        const intervals: number[] = []
        for (let i = 1; i < signals.length; i++) {
            intervals.push(signals[i].timestamp - signals[i - 1].timestamp)
        }
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length
        const variance = intervals.reduce((sum, v) => sum + (v - avgInterval) ** 2, 0) / intervals.length
        const stdDev = Math.sqrt(variance)

        // Encoding preferences
        const encodingCounts = new Map<EncodingPreference, number>()
        for (const s of signals) {
            encodingCounts.set(s.encoding, (encodingCounts.get(s.encoding) ?? 0) + 1)
        }
        const encodingPreferences = [...encodingCounts.entries()]
            .sort((a, b) => b[1] - a[1])
            .map(([pref]) => pref)

        // Technique ordering
        const techniqueOrdering = signals.map(s => s.type)

        // Evasion sophistication
        const evasionLevel = this.calculateEvasionLevel(signals)

        // Build fingerprint hash
        const fpData = `${Math.round(avgInterval / 100)}:${encodingPreferences.join(',')}:${Math.round(evasionLevel * 10)}`
        const hash = this.simpleHash(fpData)

        session.fingerprint = {
            hash,
            avgIntervalMs: avgInterval,
            intervalStdDev: stdDev,
            encodingPreferences,
            techniqueOrdering,
            toolSignature: null, // Derived from UA in main pipeline
            evasionLevel,
            headerPattern: '',
            observations: signals.length,
        }

        // Update fingerprint index
        if (!this.fingerprintIndex.has(hash)) {
            this.fingerprintIndex.set(hash, new Set())
        }
        this.fingerprintIndex.get(hash)!.add(session.sourceHash)
    }

    private calculateEvasionLevel(signals: CampaignSignal[]): number {
        let level = 0
        const encodings = signals.map(s => s.encoding)
        const uniqueEncodings = new Set(encodings)

        // Multiple encoding types = more sophisticated
        if (uniqueEncodings.size >= 3) level += 0.3
        else if (uniqueEncodings.size >= 2) level += 0.15

        // Non-plain encodings = deliberate evasion
        if (encodings.some(e => e === 'url_double' || e === 'unicode' || e === 'base64')) level += 0.3

        // Mixed encoding in single payload = high sophistication
        if (encodings.some(e => e === 'mixed')) level += 0.4

        return Math.min(level, 1.0)
    }

    // ── Attack Phase Modeling ────────────────────────────────────

    private advancePhaseModel(session: AttackerSession, signal: CampaignSignal): void {
        const phase = this.classifySignalPhase(signal)

        // Only advance — don't go backwards in the kill chain
        const phaseOrder: AttackPhase[] = [
            'reconnaissance', 'weaponization', 'delivery',
            'exploitation', 'installation', 'command_control', 'exfiltration',
        ]

        const currentIdx = phaseOrder.indexOf(session.currentPhase)
        const newIdx = phaseOrder.indexOf(phase)

        if (newIdx > currentIdx) {
            session.currentPhase = phase
            session.phaseHistory.push({
                phase,
                timestamp: signal.timestamp,
                confidence: signal.confidence,
            })

            // Escalate threat level based on phase progression
            session.threatLevel = Math.min(
                (newIdx / (phaseOrder.length - 1)) * 100,
                100,
            )
        } else {
            // Same phase — increase confidence
            session.threatLevel = Math.min(
                session.threatLevel + signal.confidence * 5,
                100,
            )
        }
    }

    private classifySignalPhase(signal: CampaignSignal): AttackPhase {
        const type = signal.type

        // Reconnaissance: information gathering
        if (type.includes('scanner') || type.includes('information_disclosure') ||
            type.includes('enum') || type === 'graphql_introspection') {
            return 'reconnaissance'
        }

        // Delivery: exploit delivery
        if (type.includes('sql_') || type.includes('xss_') || type.includes('cmd_') ||
            type.includes('ssrf_') || type.includes('ssti_') || type.includes('xxe_') ||
            type.includes('deser_') || type.includes('log_jndi')) {
            return 'delivery'
        }

        // Installation: webshell, backdoor
        if (type.includes('file_upload') || type.includes('webshell')) {
            return 'installation'
        }

        // Auth bypass = potential exploitation
        if (type.includes('auth_')) {
            return 'exploitation'
        }

        return 'reconnaissance'
    }

    // ── Campaign Detection ───────────────────────────────────────

    private detectCampaigns(): void {
        // Detect coordinated scans: same fingerprint, multiple IPs
        for (const [fpHash, sources] of this.fingerprintIndex) {
            if (sources.size >= 3) {
                const existingCampaign = this.campaigns.find(c =>
                    c.type === 'coordinated_scan' && c.fingerprints.includes(fpHash))

                if (!existingCampaign) {
                    // Gather campaign details from sessions
                    const sessions = [...sources].map(h => this.sessions.get(h)).filter(Boolean) as AttackerSession[]
                    const attackTypes = [...new Set(sessions.flatMap(s => s.signals.map(sig => sig.type)))]
                    const targetPaths = [...new Set(sessions.flatMap(s => s.signals.map(sig => sig.path)))]

                    this.campaigns.push({
                        id: `campaign-${Date.now()}-${fpHash.slice(0, 8)}`,
                        type: 'coordinated_scan',
                        fingerprints: [fpHash],
                        sourceCount: sources.size,
                        attackTypes,
                        targetPaths,
                        startTime: Math.min(...sessions.map(s => s.firstSeen)),
                        lastActivity: Math.max(...sessions.map(s => s.lastSeen)),
                        severity: attackTypes.some(t => t.includes('sql_') || t.includes('deser_')) ? 'critical' : 'high',
                        description: `Coordinated scan from ${sources.size} sources with identical behavioral fingerprint`,
                        escalated: false,
                    })
                }
            }
        }

        // Detect brute force: high volume from single source
        for (const [hash, session] of this.sessions) {
            const recentCount = session.signals.filter(s =>
                Date.now() - s.timestamp < this.CAMPAIGN_WINDOW_MS).length

            if (recentCount >= 50) {
                const existingCampaign = this.campaigns.find(c =>
                    c.type === 'brute_force' && c.fingerprints.includes(session.fingerprint.hash))

                if (!existingCampaign) {
                    this.campaigns.push({
                        id: `campaign-${Date.now()}-bf-${hash.slice(0, 8)}`,
                        type: 'brute_force',
                        fingerprints: [session.fingerprint.hash],
                        sourceCount: 1,
                        attackTypes: [...new Set(session.signals.map(s => s.type))],
                        targetPaths: [...new Set(session.signals.map(s => s.path))],
                        startTime: session.firstSeen,
                        lastActivity: session.lastSeen,
                        severity: 'high',
                        description: `Brute force: ${recentCount} attacks from ${hash.slice(0, 8)} in ${this.CAMPAIGN_WINDOW_MS / 1000}s`,
                        escalated: false,
                    })
                }
            }
        }
    }

    // ── Maintenance ──────────────────────────────────────────────

    private pruneStaleSessions(): void {
        const now = Date.now()
        for (const [hash, session] of this.sessions) {
            if (now - session.lastSeen > this.SESSION_TIMEOUT_MS) {
                this.sessions.delete(hash)
                // Remove from fingerprint index
                for (const [fpHash, sources] of this.fingerprintIndex) {
                    sources.delete(hash)
                    if (sources.size === 0) this.fingerprintIndex.delete(fpHash)
                }
            }
        }
    }

    private simpleHash(input: string): string {
        let hash = 0
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i)
            hash = ((hash << 5) - hash) + char
            hash = hash & hash // Convert to 32bit integer
        }
        return Math.abs(hash).toString(36)
    }

    // ── Statistics ────────────────────────────────────────────────

    getStats(): {
        activeSessions: number
        uniqueFingerprints: number
        activeCampaigns: number
        totalSignals: number
        highestThreatLevel: number
    } {
        return {
            activeSessions: this.sessions.size,
            uniqueFingerprints: this.fingerprintIndex.size,
            activeCampaigns: this.getActiveCampaigns().length,
            totalSignals: this.recentSignals.length,
            highestThreatLevel: Math.max(0, ...[...this.sessions.values()].map(s => s.threatLevel)),
        }
    }
}
