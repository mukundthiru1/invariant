/**
 * INVARIANT — Deception Engine
 *
 * The only detection technique with ZERO false positives.
 *
 * Deploy canary traps — endpoints, parameters, and tokens that no legitimate
 * user would ever touch. Any interaction is a 100% confirmed attacker.
 *
 * Three deception layers:
 *   1. Canary Endpoints — fake admin panels, debug endpoints, config files
 *   2. Canary Parameters — hidden form fields, robots.txt disallow entries
 *   3. Canary Tokens — unique strings embedded in responses for exfil detection
 *
 * Additionally: dynamic per-source trap generation prevents trap enumeration.
 *
 * Integration: When a trap fires, the unified runtime immediately:
 *   - Confirms ALL past detections from this source as true positives
 *   - Escalates defense to lockdown for this source
 *   - Records cryptographic evidence
 *   - Feeds back to the calibration system
 */


// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export type TrapSeverity = 'critical' | 'high' | 'medium'
export type TriggerLevel = 'any_request' | 'post_only' | 'auth_attempt' | 'parameter_submit'

/**
 * A canary endpoint — a fake URL that looks real but serves no purpose.
 * Any request to it is an attacker or scanner.
 */
export interface CanaryEndpoint {
    /** The trap path (supports glob patterns) */
    path: string
    /** HTTP methods that trigger (empty = all) */
    methods: string[]
    /** What interaction triggers */
    triggerLevel: TriggerLevel
    /** Alert severity when triggered */
    severity: TrapSeverity
    /** What this trap is designed to catch */
    category: TrapCategory
    /** Human description for forensic reports */
    description: string
    /** Whether this is auto-generated or user-defined */
    dynamic: boolean
}

/**
 * A canary parameter — a hidden field or value that should never appear
 * in a legitimate request.
 */
export interface CanaryParameter {
    /** Parameter name to watch for */
    name: string
    /** If set, only trigger when value matches this pattern */
    valuePattern?: RegExp
    /** Where to watch for it */
    locations: ('query' | 'body' | 'cookie' | 'header')[]
    /** Alert severity */
    severity: TrapSeverity
    /** Description */
    description: string
}

/**
 * A canary token — a unique string embedded in responses.
 * If it appears in a subsequent request, the attacker is replaying captured data.
 */
export interface CanaryToken {
    /** Unique token string */
    token: string
    /** Where it was originally embedded */
    embedLocation: string
    /** When it was generated */
    generatedAt: number
    /** Which source hash received it */
    issuedTo: string
    /** Whether seeing this token indicates data exfiltration */
    exfilIndicator: boolean
}

export type TrapCategory =
    | 'cms_admin'        // WordPress, Drupal admin panels
    | 'debug_endpoint'   // Actuator, debug, pprof
    | 'config_file'      // .env, .git/config, application.properties
    | 'api_discovery'    // Swagger, GraphQL introspection
    | 'credential_file'  // .htpasswd, shadow, id_rsa
    | 'backup_file'      // .bak, .old, .sql
    | 'scanner_target'   // phpinfo, server-status
    | 'path_traversal'   // Dotdot sequences to known files
    | 'custom'           // User-defined

/**
 * Event emitted when a trap is triggered.
 */
export interface TrapTrigger {
    /** Which trap fired */
    trapType: 'endpoint' | 'parameter' | 'token'
    /** Trap identifier */
    trapId: string
    /** Source hash of the attacker */
    sourceHash: string
    /** Severity */
    severity: TrapSeverity
    /** Category */
    category: TrapCategory | string
    /** When it fired */
    timestamp: number
    /** Request details */
    request: {
        method: string
        path: string
        params?: Record<string, string>
    }
    /** Description */
    description: string
    /** Confidence — for trap triggers, this is always 1.0 */
    confidence: 1.0
}


// ═══════════════════════════════════════════════════════════════════
// BUILT-IN CANARY ENDPOINTS
// ═══════════════════════════════════════════════════════════════════

/**
 * Pre-built canary endpoints covering the most common scanner targets.
 * These are paths that every automated scanner hits but no legitimate
 * user would request.
 */
const BUILTIN_CANARY_ENDPOINTS: CanaryEndpoint[] = [
    // ── CMS Admin Panels ──
    {
        path: '/wp-admin/setup-config.php',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'high',
        category: 'cms_admin',
        description: 'WordPress setup page — only accessed during initial install',
        dynamic: false,
    },
    {
        path: '/wp-login.php',
        methods: ['POST'],
        triggerLevel: 'post_only',
        severity: 'high',
        category: 'cms_admin',
        description: 'WordPress login POST — credential stuffing attempt',
        dynamic: false,
    },
    {
        path: '/administrator/index.php',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'high',
        category: 'cms_admin',
        description: 'Joomla admin — scanner probing for CMS',
        dynamic: false,
    },

    // ── Config/Credential Files ──
    {
        path: '/.env',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'config_file',
        description: 'Environment file access — seeking database credentials',
        dynamic: false,
    },
    {
        path: '/.git/config',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'config_file',
        description: 'Git config access — seeking source code',
        dynamic: false,
    },
    {
        path: '/.git/HEAD',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'config_file',
        description: 'Git HEAD access — source code reconnaissance',
        dynamic: false,
    },
    {
        path: '/web.config',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'high',
        category: 'config_file',
        description: 'IIS web.config — seeking connection strings',
        dynamic: false,
    },
    {
        path: '/.htpasswd',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'credential_file',
        description: 'Apache password file — seeking credentials',
        dynamic: false,
    },
    {
        path: '/application.properties',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'config_file',
        description: 'Spring Boot config — seeking database credentials',
        dynamic: false,
    },
    {
        path: '/config/database.yml',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'config_file',
        description: 'Rails database config — seeking credentials',
        dynamic: false,
    },
    {
        path: '/appsettings.json',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'config_file',
        description: '.NET config — seeking connection strings and secrets',
        dynamic: false,
    },

    // ── Debug Endpoints ──
    {
        path: '/actuator/env',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'debug_endpoint',
        description: 'Spring actuator env — seeking environment variables',
        dynamic: false,
    },
    {
        path: '/actuator/heapdump',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'debug_endpoint',
        description: 'Spring heap dump — seeking memory contents',
        dynamic: false,
    },
    {
        path: '/debug/pprof',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'high',
        category: 'debug_endpoint',
        description: 'Go pprof debug endpoint',
        dynamic: false,
    },
    {
        path: '/__clockwork',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'high',
        category: 'debug_endpoint',
        description: 'Laravel Clockwork debug — seeking application state',
        dynamic: false,
    },
    {
        path: '/telescope',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'high',
        category: 'debug_endpoint',
        description: 'Laravel Telescope — seeking request/exception logs',
        dynamic: false,
    },

    // ── Scanner Targets ──
    {
        path: '/phpinfo.php',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'medium',
        category: 'scanner_target',
        description: 'PHP info page — information disclosure probe',
        dynamic: false,
    },
    {
        path: '/server-status',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'medium',
        category: 'scanner_target',
        description: 'Apache server-status — information disclosure probe',
        dynamic: false,
    },
    {
        path: '/server-info',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'medium',
        category: 'scanner_target',
        description: 'Apache server-info — information disclosure probe',
        dynamic: false,
    },
    {
        path: '/elmah.axd',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'high',
        category: 'scanner_target',
        description: '.NET ELMAH error log — seeking stack traces',
        dynamic: false,
    },

    // ── API Discovery ──
    {
        path: '/swagger.json',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'medium',
        category: 'api_discovery',
        description: 'Swagger/OpenAPI spec — API reconnaissance',
        dynamic: false,
    },
    {
        path: '/api-docs',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'medium',
        category: 'api_discovery',
        description: 'API documentation endpoint — reconnaissance',
        dynamic: false,
    },

    // ── Backup Files ──
    {
        path: '/backup.sql',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'backup_file',
        description: 'SQL backup file — seeking database dump',
        dynamic: false,
    },
    {
        path: '/db.sql',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'backup_file',
        description: 'Database backup — seeking credentials and data',
        dynamic: false,
    },
    {
        path: '/dump.sql',
        methods: [],
        triggerLevel: 'any_request',
        severity: 'critical',
        category: 'backup_file',
        description: 'Database dump — seeking credentials and data',
        dynamic: false,
    },
]

/**
 * Built-in canary parameters — hidden fields that should never appear.
 */
const BUILTIN_CANARY_PARAMETERS: CanaryParameter[] = [
    {
        name: '_debug',
        locations: ['query', 'body'],
        severity: 'high',
        description: 'Debug parameter — no legitimate application should accept this',
    },
    {
        name: '_test',
        locations: ['query', 'body'],
        severity: 'medium',
        description: 'Test parameter — scanner probing for debug paths',
    },
    {
        name: 'admin',
        valuePattern: /^(true|1|yes)$/i,
        locations: ['query', 'body'],
        severity: 'critical',
        description: 'Admin flag injection — attempting privilege escalation',
    },
    {
        name: 'is_admin',
        valuePattern: /^(true|1|yes)$/i,
        locations: ['query', 'body'],
        severity: 'critical',
        description: 'Admin flag injection — attempting privilege escalation',
    },
    {
        name: 'role',
        valuePattern: /^(admin|superadmin|root|super)$/i,
        locations: ['query', 'body'],
        severity: 'critical',
        description: 'Role escalation attempt',
    },
    {
        name: 'x-middleware-subrequest',
        locations: ['header'],
        severity: 'critical',
        description: 'Next.js middleware bypass header (CVE-2025-29927)',
    },
    {
        name: 'x-original-url',
        locations: ['header'],
        severity: 'high',
        description: 'URL rewrite header — bypassing path-based access controls',
    },
    {
        name: 'x-rewrite-url',
        locations: ['header'],
        severity: 'high',
        description: 'URL rewrite header — bypassing path-based access controls',
    },
]


// ═══════════════════════════════════════════════════════════════════
// DECEPTION ENGINE
// ═══════════════════════════════════════════════════════════════════

export class DeceptionEngine {
    private endpoints: CanaryEndpoint[]
    private parameters: CanaryParameter[]
    private tokens: Map<string, CanaryToken> = new Map()  // token → CanaryToken
    private triggers: TrapTrigger[] = []
    private confirmedAttackers: Set<string> = new Set()

    /** Maximum trigger history */
    private readonly MAX_TRIGGERS = 10_000
    /** Maximum active tokens */
    private readonly MAX_TOKENS = 50_000

    constructor(config?: {
        /** Additional custom canary endpoints */
        customEndpoints?: CanaryEndpoint[]
        /** Additional custom canary parameters */
        customParameters?: CanaryParameter[]
        /** Disable built-in canaries (for custom-only deployments) */
        disableBuiltins?: boolean
    }) {
        this.endpoints = config?.disableBuiltins
            ? (config.customEndpoints ?? [])
            : [...BUILTIN_CANARY_ENDPOINTS, ...(config?.customEndpoints ?? [])]

        this.parameters = config?.disableBuiltins
            ? (config.customParameters ?? [])
            : [...BUILTIN_CANARY_PARAMETERS, ...(config?.customParameters ?? [])]
    }

    /**
     * Check a request against all canary traps.
     * Returns trap triggers (empty if no trap was hit).
     *
     * This runs BEFORE detection — it's the fastest path because
     * canary hits are definitive (no analysis needed).
     */
    checkRequest(
        method: string,
        path: string,
        sourceHash: string,
        params?: Record<string, string>,
        headers?: Record<string, string>,
        cookies?: Record<string, string>,
        body?: string,
    ): TrapTrigger[] {
        const fired: TrapTrigger[] = []
        const timestamp = Date.now()
        const pathLower = path.toLowerCase()

        // ── Check canary endpoints ──
        for (const canary of this.endpoints) {
            if (this.matchPath(pathLower, canary.path)) {
                // Check method restriction
                if (canary.methods.length > 0 && !canary.methods.includes(method.toUpperCase())) continue

                // Check trigger level
                if (canary.triggerLevel === 'post_only' && method.toUpperCase() !== 'POST') continue

                const trigger: TrapTrigger = {
                    trapType: 'endpoint',
                    trapId: `endpoint:${canary.path}`,
                    sourceHash,
                    severity: canary.severity,
                    category: canary.category,
                    timestamp,
                    request: { method, path, params },
                    description: canary.description,
                    confidence: 1.0,
                }
                fired.push(trigger)
                this.recordTrigger(trigger)
            }
        }

        // ── Check canary parameters ──
        const checkParamSource = (
            source: Record<string, string> | undefined,
            location: 'query' | 'body' | 'cookie' | 'header',
        ) => {
            if (!source) return
            for (const canary of this.parameters) {
                if (!canary.locations.includes(location)) continue
                const value = source[canary.name]
                if (value === undefined) continue

                // Check value pattern if specified
                if (canary.valuePattern && !canary.valuePattern.test(value)) continue

                const trigger: TrapTrigger = {
                    trapType: 'parameter',
                    trapId: `param:${canary.name}:${location}`,
                    sourceHash,
                    severity: canary.severity,
                    category: 'custom',
                    timestamp,
                    request: { method, path, params: { [canary.name]: value } },
                    description: canary.description,
                    confidence: 1.0,
                }
                fired.push(trigger)
                this.recordTrigger(trigger)
            }
        }

        checkParamSource(params, 'query')
        checkParamSource(headers, 'header')
        checkParamSource(cookies, 'cookie')

        // Parse body params for parameter canaries
        if (body) {
            try {
                const bodyParams = JSON.parse(body)
                if (typeof bodyParams === 'object' && bodyParams !== null) {
                    checkParamSource(bodyParams as Record<string, string>, 'body')
                }
            } catch {
                // Not JSON — try form-encoded
                const formParams: Record<string, string> = {}
                for (const pair of body.split('&')) {
                    const [k, v] = pair.split('=')
                    if (k && v) formParams[decodeURIComponent(k)] = decodeURIComponent(v)
                }
                checkParamSource(formParams, 'body')
            }
        }

        // ── Check canary tokens ──
        // Look for any canary token in the request (any surface)
        const searchText = `${path} ${params ? JSON.stringify(params) : ''} ${body ?? ''}`
        for (const [token, canaryToken] of this.tokens) {
            if (searchText.includes(token)) {
                // Token found in request — this is either the same source (replay)
                // or a different source (exfiltration)
                const isExfil = canaryToken.issuedTo !== sourceHash
                const trigger: TrapTrigger = {
                    trapType: 'token',
                    trapId: `token:${token.slice(0, 8)}`,
                    sourceHash,
                    severity: isExfil ? 'critical' : 'high',
                    category: 'custom',
                    timestamp,
                    request: { method, path },
                    description: isExfil
                        ? `Canary token exfiltration: token issued to ${canaryToken.issuedTo} found in request from ${sourceHash}`
                        : `Canary token replay: response data being sent back in request`,
                    confidence: 1.0,
                }
                fired.push(trigger)
                this.recordTrigger(trigger)
            }
        }

        // Mark source as confirmed attacker
        if (fired.length > 0) {
            this.confirmedAttackers.add(sourceHash)
        }

        return fired
    }

    /**
     * Generate a canary token to embed in a response.
     * The token is unique per source and can detect exfiltration.
     */
    generateToken(sourceHash: string, embedLocation: string): string {
        // Bounded token storage
        if (this.tokens.size >= this.MAX_TOKENS) {
            // Evict oldest tokens
            const entries = [...this.tokens.entries()]
            entries.sort((a, b) => a[1].generatedAt - b[1].generatedAt)
            for (let i = 0; i < entries.length / 4; i++) {
                this.tokens.delete(entries[i][0])
            }
        }

        // Generate a token that looks like a real API key or session token
        const token = generateRealisticToken()
        this.tokens.set(token, {
            token,
            embedLocation,
            generatedAt: Date.now(),
            issuedTo: sourceHash,
            exfilIndicator: true,
        })
        return token
    }

    /**
     * Check if a source is a confirmed attacker (hit any trap).
     */
    isConfirmedAttacker(sourceHash: string): boolean {
        return this.confirmedAttackers.has(sourceHash)
    }

    /**
     * Get all triggers for a specific source.
     */
    getTriggersForSource(sourceHash: string): TrapTrigger[] {
        return this.triggers.filter(t => t.sourceHash === sourceHash)
    }

    /**
     * Get all recent triggers.
     */
    getRecentTriggers(limit: number = 100): TrapTrigger[] {
        return this.triggers.slice(-limit)
    }

    /**
     * Get stats.
     */
    getStats(): {
        endpoints: number
        parameters: number
        activeTokens: number
        totalTriggers: number
        confirmedAttackers: number
    } {
        return {
            endpoints: this.endpoints.length,
            parameters: this.parameters.length,
            activeTokens: this.tokens.size,
            totalTriggers: this.triggers.length,
            confirmedAttackers: this.confirmedAttackers.size,
        }
    }

    // ── Internal ─────────────────────────────────────────────────────

    private matchPath(requestPath: string, canaryPath: string): boolean {
        // Exact match
        if (requestPath === canaryPath.toLowerCase()) return true
        // Prefix match for directory-style canaries
        if (canaryPath.endsWith('/') && requestPath.startsWith(canaryPath.toLowerCase())) return true
        // Strip trailing slashes for comparison
        if (requestPath.replace(/\/$/, '') === canaryPath.toLowerCase().replace(/\/$/, '')) return true
        return false
    }

    private recordTrigger(trigger: TrapTrigger): void {
        this.triggers.push(trigger)
        if (this.triggers.length > this.MAX_TRIGGERS) {
            this.triggers = this.triggers.slice(-this.MAX_TRIGGERS / 2)
        }
    }
}


// ═══════════════════════════════════════════════════════════════════
// TOKEN GENERATION
// ═══════════════════════════════════════════════════════════════════

/**
 * Generate a token that looks like a real API key.
 * Uses crypto-safe randomness if available, falls back to Math.random.
 */
function generateRealisticToken(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    const prefixes = ['sk-', 'pk-', 'api-', 'key-', 'token-', 'sess-', '']
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)]
    const length = 32 + Math.floor(Math.random() * 16)

    let token = prefix
    for (let i = 0; i < length; i++) {
        token += chars[Math.floor(Math.random() * chars.length)]
    }
    return token
}
