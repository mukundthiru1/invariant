/**
 * INVARIANT — Internal Probing (Layer 8)
 *
 * On cron trigger, probes the subscriber's own origin for:
 *   - Exposed sensitive files (.env, .git/config, etc.)
 *   - Accessible admin panels
 *   - Debug/status endpoints
 *   - API documentation exposure
 *
 * The sensor probes FROM Cloudflare TO origin, which means it tests
 * exactly what an external attacker would see. Rate-limited to
 * avoid overwhelming the origin.
 */

// ── Probe Target Definition ───────────────────────────────────────

export interface ProbeTarget {
    /** Path to probe */
    path: string
    /** What it means if accessible */
    finding: string
    /** Risk severity */
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    /** Category for grouping */
    category: 'sensitive_file' | 'admin_panel' | 'debug_endpoint' | 'api_docs' | 'config_leak'
    /** HTTP status codes that indicate the resource is exposed */
    exposedStatuses: number[]
    /** Optional: response body pattern that confirms exposure (not full body read — first 512 bytes) */
    confirmPattern?: RegExp
}

// ── Probe Targets ─────────────────────────────────────────────────

const PROBE_TARGETS: ProbeTarget[] = [
    // ── Sensitive Files ───────────────────────────────────────────
    {
        path: '/.env',
        finding: 'Environment file exposed — may contain database credentials, API keys, secrets',
        severity: 'critical',
        category: 'sensitive_file',
        exposedStatuses: [200],
        confirmPattern: /(?:DB_|DATABASE_|API_KEY|SECRET|PASSWORD|TOKEN|AWS_)/i,
    },
    {
        path: '/.git/config',
        finding: 'Git config exposed — repository structure and remote URLs visible',
        severity: 'critical',
        category: 'sensitive_file',
        exposedStatuses: [200],
        confirmPattern: /\[(?:core|remote|branch)\]/i,
    },
    {
        path: '/.git/HEAD',
        finding: 'Git HEAD exposed — confirms .git directory is accessible, full source code download possible',
        severity: 'critical',
        category: 'sensitive_file',
        exposedStatuses: [200],
        confirmPattern: /ref:\s+refs\//i,
    },
    {
        path: '/.htaccess',
        finding: 'Apache .htaccess file exposed — may reveal rewrite rules and internal paths',
        severity: 'medium',
        category: 'sensitive_file',
        exposedStatuses: [200],
        confirmPattern: /(?:RewriteEngine|RewriteRule|AuthType|Require)/i,
    },
    {
        path: '/web.config',
        finding: 'IIS web.config exposed — may contain connection strings and auth config',
        severity: 'high',
        category: 'config_leak',
        exposedStatuses: [200],
        confirmPattern: /\<configuration\>/i,
    },
    {
        path: '/wp-config.php.bak',
        finding: 'WordPress config backup exposed — contains database credentials',
        severity: 'critical',
        category: 'sensitive_file',
        exposedStatuses: [200],
    },
    {
        path: '/wp-config.php~',
        finding: 'WordPress config backup (editor swap) exposed',
        severity: 'critical',
        category: 'sensitive_file',
        exposedStatuses: [200],
    },
    {
        path: '/.DS_Store',
        finding: 'macOS .DS_Store exposed — reveals directory listing',
        severity: 'low',
        category: 'sensitive_file',
        exposedStatuses: [200],
    },
    {
        path: '/crossdomain.xml',
        finding: 'Flash crossdomain.xml found — check for overly permissive policy',
        severity: 'low',
        category: 'config_leak',
        exposedStatuses: [200],
        confirmPattern: /allow-access-from/i,
    },
    {
        path: '/robots.txt',
        finding: 'robots.txt reveals disallowed paths (reconnaissance aid)',
        severity: 'info',
        category: 'config_leak',
        exposedStatuses: [200],
        confirmPattern: /(?:Disallow|Sitemap):/i,
    },

    // ── Admin Panels ──────────────────────────────────────────────
    {
        path: '/phpmyadmin/',
        finding: 'phpMyAdmin accessible — database management interface exposed to internet',
        severity: 'critical',
        category: 'admin_panel',
        exposedStatuses: [200, 301, 302],
    },
    {
        path: '/adminer.php',
        finding: 'Adminer accessible — single-file database manager exposed',
        severity: 'critical',
        category: 'admin_panel',
        exposedStatuses: [200],
    },
    {
        path: '/wp-admin/',
        finding: 'WordPress admin panel accessible (consider restricting by IP)',
        severity: 'low',
        category: 'admin_panel',
        exposedStatuses: [200, 302],
    },
    {
        path: '/administrator/',
        finding: 'Joomla administrator panel accessible',
        severity: 'low',
        category: 'admin_panel',
        exposedStatuses: [200, 302],
    },
    {
        path: '/admin/',
        finding: 'Admin panel accessible at /admin/',
        severity: 'medium',
        category: 'admin_panel',
        exposedStatuses: [200, 302],
    },

    // ── Debug / Status Endpoints ──────────────────────────────────
    {
        path: '/phpinfo.php',
        finding: 'phpinfo() exposed — reveals full PHP config, extensions, environment variables',
        severity: 'high',
        category: 'debug_endpoint',
        exposedStatuses: [200],
        confirmPattern: /phpinfo\(\)|PHP Version/i,
    },
    {
        path: '/server-status',
        finding: 'Apache server-status exposed — reveals active connections and request details',
        severity: 'high',
        category: 'debug_endpoint',
        exposedStatuses: [200],
        confirmPattern: /Apache Server Status/i,
    },
    {
        path: '/server-info',
        finding: 'Apache server-info exposed — reveals full server configuration',
        severity: 'high',
        category: 'debug_endpoint',
        exposedStatuses: [200],
    },
    {
        path: '/actuator',
        finding: 'Spring Boot Actuator exposed — may reveal env, beans, health data',
        severity: 'high',
        category: 'debug_endpoint',
        exposedStatuses: [200],
        confirmPattern: /\{.*"_links"/i,
    },
    {
        path: '/actuator/env',
        finding: 'Spring Actuator /env exposed — environment variables and secrets visible',
        severity: 'critical',
        category: 'debug_endpoint',
        exposedStatuses: [200],
    },
    {
        path: '/actuator/heapdump',
        finding: 'Spring Actuator heap dump accessible — memory dump with credentials',
        severity: 'critical',
        category: 'debug_endpoint',
        exposedStatuses: [200],
    },
    {
        path: '/_debug',
        finding: 'Debug endpoint accessible',
        severity: 'high',
        category: 'debug_endpoint',
        exposedStatuses: [200],
    },
    {
        path: '/__debug__/',
        finding: 'Django debug toolbar accessible',
        severity: 'high',
        category: 'debug_endpoint',
        exposedStatuses: [200],
    },
    {
        path: '/telescope',
        finding: 'Laravel Telescope debug dashboard accessible',
        severity: 'high',
        category: 'debug_endpoint',
        exposedStatuses: [200, 302],
    },
    {
        path: '/elmah.axd',
        finding: 'ELMAH error log exposed — may contain stack traces and request data',
        severity: 'high',
        category: 'debug_endpoint',
        exposedStatuses: [200],
    },

    // ── API Documentation ─────────────────────────────────────────
    {
        path: '/swagger-ui.html',
        finding: 'Swagger UI exposed — full API documentation available',
        severity: 'medium',
        category: 'api_docs',
        exposedStatuses: [200],
    },
    {
        path: '/swagger-ui/',
        finding: 'Swagger UI exposed at /swagger-ui/',
        severity: 'medium',
        category: 'api_docs',
        exposedStatuses: [200, 301],
    },
    {
        path: '/api-docs',
        finding: 'API documentation endpoint exposed',
        severity: 'medium',
        category: 'api_docs',
        exposedStatuses: [200],
    },
    {
        path: '/graphiql',
        finding: 'GraphiQL interactive query interface exposed',
        severity: 'medium',
        category: 'api_docs',
        exposedStatuses: [200],
    },
    {
        path: '/graphql',
        finding: 'GraphQL endpoint accessible — check for introspection',
        severity: 'low',
        category: 'api_docs',
        exposedStatuses: [200, 400], // GraphQL returns 400 for GET sometimes but is still accessible
    },
    {
        path: '/openapi.json',
        finding: 'OpenAPI specification exposed',
        severity: 'low',
        category: 'api_docs',
        exposedStatuses: [200],
    },
]


// ── Probe Result ──────────────────────────────────────────────────

export interface ProbeResult {
    /** Probed path */
    path: string
    /** HTTP status code returned */
    status: number
    /** Whether the resource is exposed */
    exposed: boolean
    /** Finding description */
    finding: string
    /** Severity */
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    /** Category */
    category: string
    /** Whether confirmation pattern matched (if applicable) */
    confirmed: boolean
    /** Response headers worth noting (Server, X-Powered-By, etc.) */
    responseHeaders: Record<string, string>
    /** Probe timestamp */
    timestamp: string
}


// ═══════════════════════════════════════════════════════════════════
// INTERNAL PROBER
// ═══════════════════════════════════════════════════════════════════

export class InternalProber {
    /** All probe results, keyed by path */
    private results = new Map<string, ProbeResult>()
    /** Paths that returned 404 — don't re-probe for 24 hours */
    private notFoundCache = new Map<string, number>()
    /** Index into PROBE_TARGETS for round-robin probing */
    private probeIndex = 0
    /** How many probes per cron tick (rate limiting) */
    private static readonly PROBES_PER_TICK = 5
    /** Cache duration for 404 results (24 hours) */
    private static readonly NOT_FOUND_TTL_MS = 24 * 60 * 60 * 1000

    /**
     * Run a batch of probes. Called on each cron tick.
     * Rate-limited to PROBES_PER_TICK per invocation.
     *
     * @param originBase The origin URL base (e.g., "https://example.com")
     * @returns Array of probe results from this tick
     */
    async probe(originBase: string): Promise<ProbeResult[]> {
        const results: ProbeResult[] = []
        const now = Date.now()

        // Clean expired 404 cache entries
        for (const [path, timestamp] of this.notFoundCache) {
            if (now - timestamp > InternalProber.NOT_FOUND_TTL_MS) {
                this.notFoundCache.delete(path)
            }
        }

        let probed = 0
        while (probed < InternalProber.PROBES_PER_TICK) {
            // Wrap around when all targets have been probed
            if (this.probeIndex >= PROBE_TARGETS.length) {
                this.probeIndex = 0
                break // Full cycle complete, stop until next cron
            }

            const target = PROBE_TARGETS[this.probeIndex]
            this.probeIndex++

            // Skip if in 404 cache
            if (this.notFoundCache.has(target.path)) continue

            // Skip if already found exposed (don't re-probe known findings)
            const existing = this.results.get(target.path)
            if (existing?.exposed) continue

            try {
                const result = await this.probeTarget(originBase, target)
                results.push(result)
                this.results.set(target.path, result)

                if (!result.exposed) {
                    this.notFoundCache.set(target.path, now)
                }
            } catch {
                // Network error — skip, will retry next tick
            }

            probed++
        }

        return results
    }

    /**
     * Probe a single target path.
     */
    private async probeTarget(originBase: string, target: ProbeTarget): Promise<ProbeResult> {
        const url = `${originBase.replace(/\/$/, '')}${target.path}`
        const timestamp = new Date().toISOString()

        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), 5000) // 5 second timeout

        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'User-Agent': 'INVARIANT-InternalProbe/1.0',
                    'X-Invariant-Probe': 'true',
                },
                redirect: 'manual', // Don't follow redirects — we want to see them
                signal: controller.signal,
            })

            clearTimeout(timeout)

            const exposed = target.exposedStatuses.includes(response.status)
            let confirmed = false

            // If exposed and has confirmation pattern, read first 512 bytes
            if (exposed && target.confirmPattern) {
                try {
                    const reader = response.body?.getReader()
                    if (reader) {
                        const { value } = await reader.read()
                        if (value) {
                            const text = new TextDecoder().decode(value.slice(0, 512))
                            confirmed = target.confirmPattern.test(text)
                        }
                        reader.cancel()
                    }
                } catch {
                    // Body read failed — still report as exposed based on status
                }
            } else if (exposed) {
                confirmed = true // No pattern required, status is sufficient
            }

            // Capture interesting response headers
            const responseHeaders: Record<string, string> = {}
            for (const header of ['server', 'x-powered-by', 'x-aspnet-version', 'content-type']) {
                const val = response.headers.get(header)
                if (val) responseHeaders[header] = val
            }

            return {
                path: target.path,
                status: response.status,
                exposed: exposed && confirmed,
                finding: target.finding,
                severity: target.severity,
                category: target.category,
                confirmed,
                responseHeaders,
                timestamp,
            }
        } catch (err) {
            clearTimeout(timeout)
            return {
                path: target.path,
                status: 0,
                exposed: false,
                finding: target.finding,
                severity: target.severity,
                category: target.category,
                confirmed: false,
                responseHeaders: {},
                timestamp,
            }
        }
    }

    /**
     * Get all exposed findings (for signal reporting and dashboard).
     */
    getExposedFindings(): ProbeResult[] {
        return [...this.results.values()].filter(r => r.exposed)
    }

    /**
     * Get all results (exposed + not-found).
     */
    getAllResults(): ProbeResult[] {
        return [...this.results.values()]
    }

    /** Number of probed paths */
    get probedCount(): number {
        return this.results.size
    }

    /** Number of exposed findings */
    get exposedCount(): number {
        return this.getExposedFindings().length
    }

    /** Whether a full probe cycle has completed */
    get cycleComplete(): boolean {
        return this.probeIndex >= PROBE_TARGETS.length
    }
}
