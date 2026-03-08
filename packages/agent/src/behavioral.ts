/**
 * @santh/agent — Behavioral Analysis Engine
 *
 * Detects attack patterns that can't be caught by individual payload
 * analysis. These are temporal, volumetric, and contextual signals:
 *
 *   1. Rate anomaly detection — burst requests from same source
 *   2. Scanner fingerprinting — known scanner user-agents and patterns
 *   3. Path spray detection — rapid probing of many different paths
 *   4. Sensitive file access — access to .env, /etc/passwd, etc.
 *   5. Authentication anomalies — rapid auth failures, credential stuffing
 *   6. Recon patterns — robots.txt, sitemap, swagger, GraphQL introspection
 *
 * Each behavioral signal feeds into the ChainCorrelator alongside
 * invariant matches, enabling compound detection.
 */

// ── Types ────────────────────────────────────────────────────────

export interface RequestContext {
    path: string
    method: string
    sourceHash: string
    userAgent: string
    statusCode?: number
    timestamp: number
    bodySize?: number
    contentType?: string
}

export type BehaviorSignal =
    | 'scanner_detected'
    | 'path_spray'
    | 'rate_anomaly'
    | 'path_sensitive_file'
    | 'recon_probe'
    | 'auth_brute_force'
    | 'credential_stuffing'
    | 'directory_enumeration'
    | 'technology_fingerprint'
    | 'error_rate_anomaly'

export interface BehaviorResult {
    behaviors: BehaviorSignal[]
    confidence: number
    details: Record<string, unknown>
}

// ── Constants ────────────────────────────────────────────────────

/**
 * Known scanner and attack tool user-agent patterns.
 * These are self-identified — trivially spoofable but most scanners
 * don't bother changing their defaults.
 */
const SCANNER_PATTERNS = [
    /nuclei/i, /nikto/i, /nessus/i, /openvas/i, /qualys/i,
    /burp\s*suite/i, /zaproxy/i, /owasp\s*zap/i, /acunetix/i,
    /netsparker/i, /sqlmap/i, /w3af/i, /arachni/i, /skipfish/i,
    /masscan/i, /nmap/i, /dirbuster/i, /gobuster/i, /ffuf/i,
    /wfuzz/i, /feroxbuster/i, /httpx/i, /subfinder/i,
    /whatweb/i, /wpscan/i, /joomscan/i, /droopescan/i,
    /python-requests/i, /Go-http-client/i, /curl\//i,
    /wget\//i, /axios\//i, /node-fetch/i, /httpie/i,
]

/**
 * Sensitive file paths that indicate credential or config theft.
 */
const SENSITIVE_PATHS = [
    /\.env(?:\.|$)/i, /\.env\.local/i, /\.env\.production/i,
    /\/etc\/(?:passwd|shadow|hosts|group|sudoers)/i,
    /\/proc\/self\/(?:environ|cmdline|maps|status)/i,
    /(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pub)?$/i,
    /\.ssh\/(?:authorized_keys|known_hosts|config)/i,
    /wp-config\.php/i, /config\.php/i, /database\.yml/i,
    /credentials/i, /\.npmrc/i, /\.pypirc/i,
    /\.aws\/credentials/i, /\.docker\/config\.json/i,
    /\.git\/config/i, /\.git\/HEAD/i,
    /\.htpasswd/i, /\.htaccess/i,
    /web\.config/i, /appsettings\.json/i,
    /secrets\.ya?ml/i, /vault\.ya?ml/i,
]

/**
 * Reconnaissance paths — indicate an attacker mapping the application.
 */
const RECON_PATHS = [
    /robots\.txt$/i, /sitemap\.xml$/i, /\.well-known\//i,
    /swagger/i, /api-docs/i, /openapi/i, /graphql/i,
    /phpinfo/i, /server-status/i, /server-info/i,
    /debug/i, /trace/i, /actuator/i, /health/i,
    /adminer/i, /phpmyadmin/i, /wp-admin/i, /wp-login/i,
    /\.git\//i, /\.svn\//i, /\.hg\//i,
    /backup/i, /test/i, /staging/i, /dev/i,
    /cgi-bin/i, /scripts/i, /admin/i, /console/i,
]

// ── Behavioral Analyzer ──────────────────────────────────────────

interface SourceWindow {
    requests: RequestContext[]
    uniquePaths: Set<string>
    authFailures: number
    errorCount: number
}

export class BehavioralAnalyzer {
    private sources: Map<string, SourceWindow> = new Map()
    private readonly windowMs: number
    private readonly rateThreshold: number
    private readonly pathSprayThreshold: number
    private readonly authFailureThreshold: number

    constructor(options?: {
        windowMs?: number          // Time window for analysis (default: 60s)
        rateThreshold?: number     // Requests per window to flag (default: 50)
        pathSprayThreshold?: number // Unique paths per window (default: 20)
        authFailureThreshold?: number // Auth failures to flag (default: 5)
    }) {
        this.windowMs = options?.windowMs ?? 60_000
        this.rateThreshold = options?.rateThreshold ?? 50
        this.pathSprayThreshold = options?.pathSprayThreshold ?? 20
        this.authFailureThreshold = options?.authFailureThreshold ?? 5
    }

    /**
     * Analyze a request and return behavioral signals.
     *
     * This is lightweight — designed to run on EVERY request, not just
     * ones that trigger invariant matches. The behavioral signals provide
     * context that elevates chain detection confidence.
     */
    analyze(ctx: RequestContext): BehaviorResult {
        const source = this.getOrCreateWindow(ctx.sourceHash, ctx.timestamp)

        // Add request to window
        source.requests.push(ctx)
        source.uniquePaths.add(ctx.path)
        if (ctx.statusCode && ctx.statusCode === 401) source.authFailures++
        if (ctx.statusCode && ctx.statusCode >= 500) source.errorCount++

        // Prune old requests
        this.pruneWindow(source, ctx.timestamp)

        // Analyze
        const behaviors: BehaviorSignal[] = []
        const details: Record<string, unknown> = {}
        let confidence = 0

        // 1. Scanner detection (user-agent)
        if (isScanner(ctx.userAgent)) {
            behaviors.push('scanner_detected')
            details.scannerAgent = ctx.userAgent
            confidence = Math.max(confidence, 0.8)
        }

        // 2. Sensitive file access
        if (isSensitivePath(ctx.path)) {
            behaviors.push('path_sensitive_file')
            details.sensitivePath = ctx.path
            confidence = Math.max(confidence, 0.85)
        }

        // 3. Recon probing
        if (isReconPath(ctx.path)) {
            behaviors.push('recon_probe')
            details.reconPath = ctx.path
            confidence = Math.max(confidence, 0.5)
        }

        // 4. Rate anomaly
        if (source.requests.length >= this.rateThreshold) {
            behaviors.push('rate_anomaly')
            details.requestRate = source.requests.length
            details.windowSeconds = this.windowMs / 1000
            confidence = Math.max(confidence, 0.7)
        }

        // 5. Path spray
        if (source.uniquePaths.size >= this.pathSprayThreshold) {
            behaviors.push('path_spray')
            details.uniquePaths = source.uniquePaths.size
            confidence = Math.max(confidence, 0.75)
        }

        // 6. Auth brute force
        if (source.authFailures >= this.authFailureThreshold) {
            behaviors.push('auth_brute_force')
            details.authFailures = source.authFailures
            confidence = Math.max(confidence, 0.8)
        }

        // 7. Directory enumeration (many 404s on structured paths)
        const notFoundCount = source.requests.filter(r => r.statusCode === 404).length
        if (notFoundCount >= 10 && source.uniquePaths.size >= 10) {
            behaviors.push('directory_enumeration')
            details.notFoundCount = notFoundCount
            confidence = Math.max(confidence, 0.7)
        }

        // 8. Error rate anomaly (many 500s)
        if (source.errorCount >= 5) {
            behaviors.push('error_rate_anomaly')
            details.errorCount = source.errorCount
            confidence = Math.max(confidence, 0.6)
        }

        return { behaviors, confidence, details }
    }

    /** Check if a path targets sensitive files */
    static isSensitivePath(path: string): boolean {
        return isSensitivePath(path)
    }

    /** Check if a user-agent is a known scanner */
    static isScanner(ua: string): boolean {
        return isScanner(ua)
    }

    /** Get the source window for inspection */
    getSourceWindow(sourceHash: string): SourceWindow | undefined {
        return this.sources.get(sourceHash)
    }

    /** Active source count */
    get activeSourceCount(): number {
        return this.sources.size
    }

    private getOrCreateWindow(sourceHash: string, now: number): SourceWindow {
        let window = this.sources.get(sourceHash)
        if (!window) {
            window = {
                requests: [],
                uniquePaths: new Set(),
                authFailures: 0,
                errorCount: 0,
            }
            this.sources.set(sourceHash, window)
        }
        return window
    }

    private pruneWindow(window: SourceWindow, now: number): void {
        const cutoff = now - this.windowMs
        window.requests = window.requests.filter(r => r.timestamp >= cutoff)
        // Keep uniquePaths aligned to the active window only.
        window.uniquePaths = new Set(window.requests.map(r => r.path))
        window.authFailures = window.requests.filter(r => r.statusCode === 401).length
        window.errorCount = window.requests.filter(r => (r.statusCode ?? 0) >= 500).length
    }
}

// ── Helpers ──────────────────────────────────────────────────────

function isScanner(ua: string): boolean {
    if (!ua) return false
    return SCANNER_PATTERNS.some(p => p.test(ua))
}

function isSensitivePath(path: string): boolean {
    return SENSITIVE_PATHS.some(p => p.test(path))
}

function isReconPath(path: string): boolean {
    return RECON_PATHS.some(p => p.test(path))
}
