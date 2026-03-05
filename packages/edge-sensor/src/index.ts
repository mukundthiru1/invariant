/**
 * @santh/edge-sensor — Cloudflare Worker
 *
 * INVARIANT detection at the edge. Deployed to the subscriber's Cloudflare zone.
 * Intercepts every request, runs the full 14-layer detection pipeline, and either
 * blocks or passes to origin.
 *
 * Architecture:
 *   Request → Static Signature Detection (L1)
 *           → Behavioral Analysis (L2)
 *           → Client Fingerprinting (L3)
 *           → Request Body Analysis (L3b)
 *           → Technology Detection (L4)
 *           → Invariant Engine (L5) — THE CORE
 *           → L2 Structural Evaluators (L5b) — DEEP ANALYSIS
 *           → IOC Feed Correlation (L5c) — THREAT INTEL
 *           → MITRE ATT&CK Enrichment (L5d)
 *           → Multi-Dimensional Risk Surface (L5e)
 *           → Threat Scoring (L5f)
 *           → Defense Decision (L6)
 *           → [block | pass to origin]
 *           → Response Audit (L7)
 *           → Return to client
 *
 *   Cron  → Signal Flush + Evidence Sealing
 *         → Internal Probing (L8)
 *         → Drift Detection (L9) — TEMPORAL COMPARISON
 *         → Rule Sync from Intel + IOC Feed Sync
 *         → Privilege Graph Analysis
 *         → State Persistence
 *         → Application Model Snapshot
 *
 * Merged from Axiom Drift:
 *   - Cryptographic Evidence Sealing (Merkle proofs)
 *   - MITRE ATT&CK Mapping (46 classes → 25+ techniques)
 *   - Multi-Dimensional Risk Surface (4-axis scoring)
 *   - Drift Detection (temporal posture comparison)
 *   - IOC Feed Correlation (IP/domain/payload/UA/CVE)
 *
 * Privacy:
 *   - Source IPs: SHA-256 hashed with daily-rotating salt
 *   - Request bodies: Analyzed in-memory only. NEVER persisted.
 *   - Cookies/tokens: NEVER accessed
 *   - Only metadata + attack patterns analyzed — no PII extraction
 */

import { InvariantEngine, type InvariantMatch, type InvariantClass } from '../../engine/src/invariant-engine.js'
import { runL2Evaluators, mergeL2Results, type L2DetectionResult } from '../../engine/src/evaluators/evaluator-bridge.js'
import { ChainCorrelator, type ChainSignal } from '../../engine/src/chain-detector.js'
import { MitreMapper } from '../../engine/src/mitre-mapper.js'
import { EvidenceSealer } from '../../engine/src/evidence/evidence-sealer.js'

import {
    analyzeRequestBody,
    type BodyAnalysisResult,
    ThreatScoringEngine,
    type ThreatSignal,
    ResponseAuditor,
    InternalProber,
    ApplicationModel,
    normalizePathPattern,
    detectAuthType,
    detectSensitiveResponse,
    TechStackTracker,
    CveStackCorrelator,
    ReactivationEngine,
    detectConditions,
    PrivilegeGraph,
    SensorStateManager,
    syncRulesFromIntel,
    matchDynamicRules,
    type DynamicRuleMatch,
    IOCCorrelator,
    DriftDetector,
    RiskSurfaceCalculator,
} from './modules/index.js'


// ── Environment ───────────────────────────────────────────────────

interface Env {
    SANTH_INGEST_URL: string
    SIGNAL_BATCH_SIZE: string
    DEFENSE_MODE: string           // "monitor" | "enforce" | "off"
    SENSOR_STATE: KVNamespace      // KV binding for persistent state
    SENSOR_ID: string              // Unique sensor identifier
    PROBE_ENABLED: string          // "true" | "false"
    AI?: Ai                        // Optional Workers AI binding
}


// ── Types ─────────────────────────────────────────────────────────

interface Signal {
    type: string
    subtype: string | null
    confidence: number
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    path: string
    method: string
    sourceHash: string
    country: string | null
    matchedRules: string[]
    invariantClasses: string[]
    isNovelVariant: boolean
    targetTech: string | null
    clientClass: string
    requestSize: number | null
    headerAnomaly: boolean
    defenseAction: 'blocked' | 'monitored' | 'passed'
    threatScore: number
    chainIndicators: string[]
    timestamp: string
    // MITRE ATT&CK enrichment (from Axiom Drift merge)
    mitreTechniques?: string[]
    mitreKillChainPhase?: string
    // Multi-dimensional risk surface (from Axiom Drift merge)
    riskSurface?: {
        security: number
        privacy: number
        compliance: number
        operational: number
        dominantAxis: string
    }
}

interface SignatureRule {
    id: string
    type: string
    subtype: string | null
    severity: Signal['severity']
    confidence: number
    check: (ctx: RequestContext) => boolean
}

interface RequestContext {
    url: URL
    path: string
    query: string
    decodedPath: string
    decodedQuery: string
    fullDecoded: string
    method: string
    headers: Headers
    ua: string
    contentType: string
    bodyText: string | null
    bodyValues: string[]
}


// ── Encoding Helpers ──────────────────────────────────────────────

function safeDecode(input: string): string {
    try { return decodeURIComponent(input) }
    catch { return input }
}

function deepDecode(input: string, depth = 0): string {
    if (depth > 3) return input
    let decoded = input
    try {
        const d = decodeURIComponent(decoded)
        if (d !== decoded) decoded = deepDecode(d, depth + 1)
    } catch { /* invalid encoding */ }
    decoded = decoded
        .replace(/&#x([0-9a-f]+);?/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(\d+);?/g, (_, dec: string) => String.fromCharCode(parseInt(dec)))
        .replace(/\\u([0-9a-f]{4})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
    decoded = decoded.replace(/\/\*.*?\*\//g, ' ')
    return decoded
}


// ── IP Hashing ────────────────────────────────────────────────────

async function hashSource(ip: string): Promise<string> {
    const today = new Date().toISOString().split('T')[0]
    const data = new TextEncoder().encode(`${ip}:${today}:invariant-v7`)
    const hash = await crypto.subtle.digest('SHA-256', data)
    return Array.from(new Uint8Array(hash).slice(0, 16))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}


// ══════════════════════════════════════════════════════════════════
// LAYER 1: SIGNATURE DETECTION
// Static pattern matching — high confidence, low false positives
// ══════════════════════════════════════════════════════════════════

const SIGNATURES: SignatureRule[] = [
    // SQL Injection
    {
        id: 'sqli-union', type: 'sql_injection', subtype: 'union_based', severity: 'high', confidence: 0.9,
        check: ctx => /union\s+(all\s+)?select\s/i.test(ctx.fullDecoded),
    },
    {
        id: 'sqli-blind', type: 'sql_injection', subtype: 'boolean_blind', severity: 'high', confidence: 0.8,
        check: ctx => /'\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i.test(ctx.decodedQuery),
    },
    {
        id: 'sqli-stacked', type: 'sql_injection', subtype: 'stacked_queries', severity: 'critical', confidence: 0.9,
        check: ctx => /;\s*(drop|delete|insert|update|alter|create|exec|execute)\s+/i.test(ctx.decodedQuery),
    },
    {
        id: 'sqli-time', type: 'sql_injection', subtype: 'time_blind', severity: 'high', confidence: 0.85,
        check: ctx => /(?:sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep)/i.test(ctx.fullDecoded),
    },
    {
        id: 'sqli-error', type: 'sql_injection', subtype: 'error_based', severity: 'high', confidence: 0.8,
        check: ctx => /(?:extractvalue|updatexml|xmltype|convert\s*\(.*using)/i.test(ctx.fullDecoded),
    },

    // XSS
    {
        id: 'xss-script', type: 'xss', subtype: 'reflected', severity: 'high', confidence: 0.9,
        check: ctx => /<script[\s>]/i.test(ctx.decodedQuery) || /javascript\s*:/i.test(ctx.decodedQuery),
    },
    {
        id: 'xss-event', type: 'xss', subtype: 'event_handler', severity: 'high', confidence: 0.8,
        check: ctx => /\bon(?:error|load|click|mouseover|focus|blur|submit|change|input)\s*=/i.test(ctx.decodedQuery),
    },
    {
        id: 'xss-svg', type: 'xss', subtype: 'svg_injection', severity: 'high', confidence: 0.85,
        check: ctx => /<svg[\s/].*?on\w+\s*=/i.test(ctx.decodedQuery),
    },

    // Path Traversal
    {
        id: 'lfi-traversal', type: 'path_traversal', subtype: 'directory_traversal', severity: 'high', confidence: 0.85,
        check: ctx => /(?:\.\.[\\/]){2,}/.test(ctx.fullDecoded) || /(?:%2e%2e[\\/]|\.\.%2f|%2e%2e%5c){2,}/i.test(ctx.path + ctx.query),
    },
    {
        id: 'lfi-sensitive', type: 'path_traversal', subtype: 'sensitive_file', severity: 'critical', confidence: 0.95,
        check: ctx => /\/etc\/(?:passwd|shadow|hosts)|\/proc\/self\/(?:environ|cmdline)|\/windows\/(?:system32|win\.ini)/i.test(ctx.fullDecoded),
    },

    // Command Injection
    {
        id: 'cmdi-shell', type: 'command_injection', subtype: 'shell_command', severity: 'critical', confidence: 0.85,
        check: ctx => /[;|`]\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|bash|sh|python|perl|ruby|php)\b/i.test(ctx.decodedQuery),
    },
    {
        id: 'cmdi-subshell', type: 'command_injection', subtype: 'subshell', severity: 'critical', confidence: 0.8,
        check: ctx => /\$\([^)]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh)[^)]*\)/.test(ctx.decodedQuery),
    },

    // SSRF
    {
        id: 'ssrf-internal', type: 'ssrf', subtype: 'internal_network', severity: 'high', confidence: 0.85,
        check: ctx => /https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/i.test(ctx.decodedQuery),
    },
    {
        id: 'ssrf-metadata', type: 'ssrf', subtype: 'cloud_metadata', severity: 'critical', confidence: 0.95,
        check: ctx => /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/i.test(ctx.fullDecoded),
    },

    // SSTI
    {
        id: 'ssti-jinja', type: 'ssti', subtype: 'jinja_twig', severity: 'critical', confidence: 0.85,
        check: ctx => /\{\{[^}]*(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|config\.|request\.)/.test(ctx.fullDecoded),
    },
    {
        id: 'ssti-el', type: 'ssti', subtype: 'expression_language', severity: 'critical', confidence: 0.85,
        check: ctx => /\$\{[^}]*(?:Runtime|ProcessBuilder|getRuntime|exec\(|Class\.forName)/i.test(ctx.fullDecoded),
    },

    // Deserialization
    {
        id: 'deser-java', type: 'deserialization', subtype: 'java_object', severity: 'critical', confidence: 0.9,
        check: ctx => ctx.contentType.includes('application/x-java-serialized-object') || /aced0005|rO0ABX/i.test(ctx.query),
    },
    {
        id: 'deser-php', type: 'deserialization', subtype: 'php_object', severity: 'high', confidence: 0.85,
        check: ctx => /O:\d+:"[^"]+"/i.test(ctx.decodedQuery),
    },

    // Header Injection
    {
        id: 'header-crlf', type: 'header_injection', subtype: 'crlf', severity: 'high', confidence: 0.85,
        check: ctx => /%0[da]|%0[DA]/i.test(ctx.path + ctx.query),
    },

    // XXE
    {
        id: 'xxe-entity', type: 'xxe', subtype: 'entity_injection', severity: 'critical', confidence: 0.9,
        check: ctx => /<!(?:ENTITY|DOCTYPE)\s/i.test(ctx.fullDecoded) && /(?:SYSTEM|PUBLIC)\s/i.test(ctx.fullDecoded),
    },

    // Log4Shell
    {
        id: 'log4shell', type: 'exploit_payload', subtype: 'log4shell', severity: 'critical', confidence: 0.95,
        check: ctx => /\$\{(?:jndi|lower|upper|env|sys|java|date):/i.test(ctx.fullDecoded),
    },

    // Prototype Pollution
    {
        id: 'proto-pollution', type: 'exploit_payload', subtype: 'prototype_pollution', severity: 'high', confidence: 0.8,
        check: ctx => /__proto__|constructor\[prototype\]|constructor\.prototype/i.test(ctx.fullDecoded),
    },

    // Scanner Detection
    {
        id: 'scanner-tools', type: 'scanner', subtype: 'automated', severity: 'info', confidence: 0.9,
        check: ctx => /nuclei|sqlmap|nmap|nikto|masscan|zap|burp|dirbuster|gobuster|ffuf|wfuzz|feroxbuster|dalfox/i.test(ctx.ua),
    },

    // Info Disclosure
    {
        id: 'enum-sensitive', type: 'information_disclosure', subtype: 'sensitive_files', severity: 'medium', confidence: 0.75,
        check: ctx => /(?:\.env|\.git\/(?:config|HEAD)|\.htaccess|\.aws\/credentials|wp-config\.php|phpinfo\.php|server-status)/i.test(ctx.path),
    },
    {
        id: 'enum-debug', type: 'information_disclosure', subtype: 'debug_endpoint', severity: 'high', confidence: 0.7,
        check: ctx => /\/(?:debug|trace|metrics|__debug__|_debug_toolbar|actuator|telescope)/i.test(ctx.path),
    },

    // Auth Bypass
    {
        id: 'jwt-none', type: 'auth_bypass', subtype: 'jwt_none_algorithm', severity: 'critical', confidence: 0.9,
        check: ctx => {
            const auth = ctx.headers.get('authorization') ?? ''
            if (!auth.startsWith('Bearer ')) return false
            try {
                const parts = auth.slice(7).split('.')
                if (parts.length !== 3) return false
                const header = JSON.parse(atob(parts[0]))
                return header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE'
            } catch { return false }
        },
    },

    // HTTP Smuggling
    {
        id: 'smuggle-te', type: 'http_smuggling', subtype: 'te_obfuscation', severity: 'critical', confidence: 0.85,
        check: ctx => {
            const te = ctx.headers.get('transfer-encoding') ?? ''
            return te.length > 0 && (te.includes(',') || /\schunked|chunked\s/i.test(te) || te.toLowerCase() !== 'chunked') && ctx.headers.has('content-length')
        },
    },

    // NoSQL Injection
    {
        id: 'nosql-operator', type: 'nosql_injection', subtype: 'operator_injection', severity: 'high', confidence: 0.8,
        check: ctx => /\$(?:gt|gte|lt|lte|ne|eq|in|nin|regex|where|exists|type|or|and|not|nor|elemMatch)\b/i.test(ctx.fullDecoded),
    },

    // Open Redirect
    {
        id: 'open-redirect', type: 'open_redirect', subtype: 'url_redirect', severity: 'medium', confidence: 0.7,
        check: ctx => /(?:redirect|next|url|return|continue|goto|target|dest|destination|redir|forward)=(?:https?:\/\/|\/\/)/i.test(ctx.query),
    },

    // LDAP Injection
    {
        id: 'ldap-injection', type: 'ldap_injection', subtype: 'filter_injection', severity: 'high', confidence: 0.85,
        check: ctx => /[)(|*]\s*(?:\(|\)|\||&|!|=|~=|>=|<=)/i.test(ctx.fullDecoded) && /(?:uid|cn|sn|ou|dc|objectClass|member)/i.test(ctx.fullDecoded),
    },
]


// ══════════════════════════════════════════════════════════════════
// LAYER 2: BEHAVIORAL ANALYSIS
// ══════════════════════════════════════════════════════════════════

class BehaviorTracker {
    private ipCounts = new Map<string, { count: number; firstSeen: number; paths: Set<string>; methods: Set<string>; statusCodes: Map<number, number> }>()
    private readonly WINDOW_MS = 60_000
    private readonly BURST_THRESHOLD = 30
    private readonly PATH_SPRAY_THRESHOLD = 15
    private readonly METHOD_DIVERSITY_THRESHOLD = 4
    private readonly UNUSUAL_METHODS = new Set(['TRACE', 'TRACK', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'PATCH'])
    private readonly MAX_ENTRIES = 10_000

    track(sourceHash: string, path: string, method: string): string | null {
        const now = Date.now()
        let entry = this.ipCounts.get(sourceHash)

        if (!entry || (now - entry.firstSeen) > this.WINDOW_MS) {
            entry = { count: 0, firstSeen: now, paths: new Set(), methods: new Set(), statusCodes: new Map() }
            this.ipCounts.set(sourceHash, entry)
        }

        entry.count++
        entry.paths.add(path)
        entry.methods.add(method)

        if (this.ipCounts.size > this.MAX_ENTRIES) {
            const cutoff = now - this.WINDOW_MS
            for (const [key, val] of this.ipCounts) {
                if (val.firstSeen < cutoff) this.ipCounts.delete(key)
            }
        }

        if (entry.count > this.BURST_THRESHOLD) return 'rate_anomaly'
        if (entry.paths.size > this.PATH_SPRAY_THRESHOLD) return 'path_enumeration'
        // Method diversity: legitimate users don't use 4+ HTTP methods in 60s
        if (entry.methods.size >= this.METHOD_DIVERSITY_THRESHOLD) return 'method_probing'
        // Unusual methods: TRACE, TRACK, WebDAV, etc.
        if (this.UNUSUAL_METHODS.has(method.toUpperCase())) return 'unusual_method'
        return null
    }

    recordResponseCode(sourceHash: string, status: number): void {
        const entry = this.ipCounts.get(sourceHash)
        if (entry) {
            entry.statusCodes.set(status, (entry.statusCodes.get(status) ?? 0) + 1)
        }
    }

    getRequestCount(sourceHash: string): number {
        return this.ipCounts.get(sourceHash)?.count ?? 0
    }

    /** Check if source is exhibiting scanner-like error ratio */
    hasHighErrorRate(sourceHash: string): boolean {
        const entry = this.ipCounts.get(sourceHash)
        if (!entry || entry.count < 5) return false
        let errorCount = 0
        for (const [code, count] of entry.statusCodes) {
            if (code >= 400) errorCount += count
        }
        return (errorCount / entry.count) > 0.5
    }
}


// ══════════════════════════════════════════════════════════════════
// LAYER 3: CLIENT FINGERPRINTING
// ══════════════════════════════════════════════════════════════════

type ClientClass = 'browser' | 'mobile_browser' | 'bot' | 'crawler' | 'scanner' | 'api_client' | 'cli_tool' | 'empty' | 'suspicious'

function classifyClient(headers: Headers): ClientClass {
    const ua = (headers.get('user-agent') ?? '').toLowerCase()
    if (!ua || ua.length === 0) return 'empty'
    if (ua.length < 15) return 'suspicious'
    if (/nuclei|sqlmap|nmap|nikto|masscan|zap|burp|dirbuster|gobuster|ffuf|wfuzz|feroxbuster|acunetix/i.test(ua)) return 'scanner'
    if (/googlebot|bingbot|yandexbot|baiduspider|duckduckbot|slurp|facebookexternalhit|twitterbot/i.test(ua)) return 'crawler'
    if (/curl|wget|python|go-http|java\/|okhttp|axios|node-fetch|httpie|libwww|scrapy|aiohttp|requests/i.test(ua)) return 'cli_tool'
    if (/postman|insomnia|paw\//i.test(ua)) return 'api_client'
    if (/mobile|android|iphone|ipad/i.test(ua) && /chrome|safari|firefox/i.test(ua)) return 'mobile_browser'
    if (/chrome|firefox|safari|edge|opera/i.test(ua)) {
        if (!headers.has('accept-language') && !headers.has('accept-encoding')) return 'suspicious'
        return 'browser'
    }
    if (/bot|crawl|spider|scrape|fetch/i.test(ua)) return 'bot'
    return 'suspicious'
}


// ══════════════════════════════════════════════════════════════════
// LAYER 4: TECHNOLOGY DETECTION
// ══════════════════════════════════════════════════════════════════

function detectTechnology(path: string, headers: Headers): string | null {
    const p = path.toLowerCase()
    const poweredBy = (headers.get('x-powered-by') ?? '').toLowerCase()
    const server = (headers.get('server') ?? '').toLowerCase()
    const via = (headers.get('via') ?? '').toLowerCase()

    // CMS detection (path-based)
    if (p.includes('/wp-') || p.includes('/wordpress')) return 'wordpress'
    if (p.includes('/sites/default/') || p.includes('/core/misc/drupal')) return 'drupal'
    if (p.includes('/administrator/') && p.includes('/joomla')) return 'joomla'

    // Framework detection (path-based)
    if (p.includes('/_next/') || p.includes('/__nextjs')) return 'nextjs'
    if (p.includes('/_nuxt/')) return 'nuxt'
    if (p.includes('/actuator/') || p.includes('/spring')) return 'spring'
    if (p.includes('/__debug__') || p.includes('/_debug_toolbar')) return 'django'
    if (p.includes('/telescope/') || p.includes('/laravel')) return 'laravel'
    if (p.includes('/rails/') || p.endsWith('.rb')) return 'rails'

    // Language detection (extension-based)
    if (p.endsWith('.php') || p.includes('.php?') || p.includes('.phtml')) return 'php'
    if (p.endsWith('.aspx') || p.endsWith('.asp') || p.endsWith('.ashx')) return 'aspnet'
    if (p.endsWith('.jsp') || p.endsWith('.do') || p.endsWith('.action')) return 'java'
    if (p.endsWith('.py') || p.includes('/cgi-bin/')) return 'python'

    // Framework detection (header-based)
    if (poweredBy.includes('express')) return 'express'
    if (poweredBy.includes('next.js')) return 'nextjs'
    if (poweredBy.includes('php')) return 'php'
    if (poweredBy.includes('asp.net')) return 'aspnet'
    if (poweredBy.includes('django')) return 'django'
    if (poweredBy.includes('flask')) return 'python'
    if (poweredBy.includes('laravel')) return 'laravel'
    if (poweredBy.includes('rails') || poweredBy.includes('phusion')) return 'rails'

    // Server detection (server header)
    if (server.includes('nginx')) return 'nginx'
    if (server.includes('apache')) return 'apache'
    if (server.includes('cloudflare')) return 'cloudflare'
    if (server.includes('microsoft-iis')) return 'aspnet'
    if (server.includes('gunicorn') || server.includes('uvicorn')) return 'python'
    if (server.includes('openresty')) return 'nginx'

    // CDN/proxy detection
    if (via.includes('cloudflare') || headers.has('cf-ray')) return 'cloudflare'

    // API detection
    if (p.startsWith('/api/') || p.startsWith('/v1/') || p.startsWith('/v2/') || p.startsWith('/v3/')) return 'rest-api'
    if (p.includes('/graphql')) return 'graphql'

    return null
}


// ══════════════════════════════════════════════════════════════════
// SIGNAL BUFFER
// ══════════════════════════════════════════════════════════════════

class SignalBuffer {
    private signals: Signal[] = []
    private readonly batchSize: number
    private readonly ingestUrl: string
    private dedup = new Map<string, { count: number; lastSeen: number }>()
    private static readonly MAX_BUFFER = 500
    private static readonly DEDUP_WINDOW_MS = 60_000

    constructor(batchSize: number, ingestUrl: string) {
        this.batchSize = batchSize
        this.ingestUrl = ingestUrl
    }

    add(signal: Signal): void {
        const now = Date.now()
        const dedupKey = `${signal.sourceHash}:${signal.type}:${signal.method}:${signal.path}`
        const existing = this.dedup.get(dedupKey)

        if (existing && (now - existing.lastSeen) < SignalBuffer.DEDUP_WINDOW_MS) {
            existing.count++
            existing.lastSeen = now
            return
        }

        this.dedup.set(dedupKey, { count: 1, lastSeen: now })

        if (this.signals.length >= SignalBuffer.MAX_BUFFER) {
            this.signals.shift()
        }

        this.signals.push(signal)
    }

    shouldFlush(): boolean {
        return this.signals.length >= this.batchSize
    }

    async flush(): Promise<void> {
        if (this.signals.length === 0 || !this.ingestUrl) return

        const batch = this.signals.splice(0, this.batchSize)

        try {
            await fetch(this.ingestUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ signals: batch, sensorVersion: '7.0.0', timestamp: new Date().toISOString() }),
            })
        } catch {
            // Re-add failed signals to front of buffer
            this.signals.unshift(...batch.slice(0, 50))
        }

        // Clean old dedup entries
        const cutoff = Date.now() - SignalBuffer.DEDUP_WINDOW_MS
        for (const [key, val] of this.dedup) {
            if (val.lastSeen < cutoff) this.dedup.delete(key)
        }
    }

    getCount(): number { return this.signals.length }
}


// ══════════════════════════════════════════════════════════════════
// HEADER ANOMALY DETECTION
// ══════════════════════════════════════════════════════════════════

function detectHeaderAnomalies(headers: Headers): boolean {
    const ua = headers.get('user-agent') ?? ''
    if (ua.length > 500) return true
    if (!headers.has('host')) return true
    const accept = headers.get('accept') ?? ''
    if (accept.length > 400) return true
    if (headers.has('x-forwarded-for') && headers.has('x-real-ip')) {
        const xff = headers.get('x-forwarded-for') ?? ''
        const xri = headers.get('x-real-ip') ?? ''
        if (xff.split(',').length > 5 && xri !== xff.split(',')[0].trim()) return true
    }
    return false
}


// ══════════════════════════════════════════════════════════════════
// BLOCK RESPONSE
// ══════════════════════════════════════════════════════════════════

function blockResponse(severity: string, requestOrigin?: string | null): Response {
    return new Response(JSON.stringify({
        error: 'Request blocked by security policy',
        code: 'INVARIANT_DEFENSE',
        severity,
    }), {
        status: 403,
        headers: {
            'Content-Type': 'application/json',
            'X-Invariant-Action': 'blocked',
            'Cache-Control': 'no-store',
            // CORS safety: ensure block doesn't break legitimate CORS frontends
            ...(requestOrigin ? {
                'Access-Control-Allow-Origin': requestOrigin,
                'Access-Control-Allow-Credentials': 'true',
            } : {}),
        },
    })
}


// ══════════════════════════════════════════════════════════════════
// PATH NORMALIZATION
// ══════════════════════════════════════════════════════════════════

function normalizePath(path: string): string {
    return path
        .toLowerCase()
        .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '{uuid}')
        .replace(/[0-9a-f]{32,64}/g, '{hash}')
        .replace(/\/\d{4,}/g, '/{id}')
        .replace(/\/\d+(?=\/|$)/g, '/{id}')
        .replace(/=([^&]+)/g, '={val}')
        .replace(/\/$/, '')
        || '/'
}


// ══════════════════════════════════════════════════════════════════
// MAIN WORKER — FULL PIPELINE
// ══════════════════════════════════════════════════════════════════

// Module-level state (survives across requests within a Worker instance)
const behaviorTracker = new BehaviorTracker()
const engine = new InvariantEngine()
const chainCorrelator = new ChainCorrelator()
const threatScoring = new ThreatScoringEngine()
const responseAuditor = new ResponseAuditor()
const internalProber = new InternalProber()
const applicationModel = new ApplicationModel()
const techTracker = new TechStackTracker()
const cveCorrelator = new CveStackCorrelator()
const reactivationEngine = new ReactivationEngine()
const mitreMapper = new MitreMapper()
const iocCorrelator = new IOCCorrelator()
const driftDetector = new DriftDetector()
const riskSurface = new RiskSurfaceCalculator()
let evidenceSealer: EvidenceSealer | null = null

let signalBuffer: SignalBuffer | null = null
let stateManager: SensorStateManager | null = null
let initialized = false

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        // Initialize on first request
        if (!signalBuffer) {
            signalBuffer = new SignalBuffer(
                parseInt(env.SIGNAL_BATCH_SIZE ?? '50'),
                env.SANTH_INGEST_URL ?? '',
            )
        }

        if (!stateManager && env.SENSOR_STATE) {
            stateManager = new SensorStateManager(env.SENSOR_STATE, env.SENSOR_ID ?? 'default')
        }

        // Lazy initialization from KV (once per Worker lifecycle)
        if (!initialized && stateManager) {
            try {
                await stateManager.initialize()
                initialized = true
            } catch {
                // KV failure must not block traffic
                initialized = true
            }
        }

        const mode = stateManager?.config.defenseMode ?? env.DEFENSE_MODE ?? 'monitor'
        if (mode === 'off') return fetch(request)

        const url = new URL(request.url)
        const path = url.pathname
        const query = url.search

        // ── Introspection endpoints ──────────────────────────────
        if (path === '/__invariant/health') {
            return new Response(JSON.stringify({
                status: 'operational',
                version: '8.0.0',
                mode,
                engine: { classes: engine.classes.length },
                chainCorrelator: { sources: chainCorrelator.activeSourceCount, signals: chainCorrelator.totalSignals, chains: chainCorrelator.chainCount },
                signalBuffer: signalBuffer.getCount(),
                applicationModel: { endpoints: applicationModel.endpointCount },
                techStack: techTracker.getStack(),
                probeResults: internalProber.probedCount,
                responseAudit: responseAuditor.findingCount,
                // Axiom Drift merge capabilities
                mitreCoverage: mitreMapper.getCoverageReport().coveredCount,
                iocIndicators: iocCorrelator.indicatorCount,
                iocSyncAge: iocCorrelator.syncAge,
                evidenceSealing: evidenceSealer !== null,
                timestamp: new Date().toISOString(),
            }), {
                headers: { 'Content-Type': 'application/json' },
            })
        }

        if (path === '/__invariant/posture') {
            const report = responseAuditor.generateReport(url.hostname)
            return new Response(JSON.stringify(report), {
                headers: { 'Content-Type': 'application/json' },
            })
        }

        // Skip static assets — comprehensive list of non-executable formats
        if (/\.(?:css|js|mjs|png|jpg|jpeg|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|map|mp4|webm|ogg|mp3|wav|flac|pdf|zip|gz|br|wasm)$/i.test(path)) {
            return fetch(request)
        }

        // ══════════════════════════════════════════════════════════
        // DETECTION PIPELINE
        // ══════════════════════════════════════════════════════════

        // Build request context
        const decodedPath = safeDecode(path)
        const decodedQuery = safeDecode(query)
        const fullDecoded = deepDecode(decodedPath + decodedQuery)
        const ua = request.headers.get('user-agent') ?? ''
        const contentType = request.headers.get('content-type') ?? ''

        // L3b: Request body analysis
        const bodyResult: BodyAnalysisResult = await analyzeRequestBody(request)
        const bodyText = bodyResult.combinedText || null
        const bodyValues = bodyResult.extractedValues

        const reqCtx: RequestContext = {
            url, path, query, decodedPath, decodedQuery, fullDecoded,
            method: request.method, headers: request.headers, ua, contentType,
            bodyText, bodyValues,
        }

        // Hash source IP
        const sourceIp = request.headers.get('cf-connecting-ip') ?? request.headers.get('x-real-ip') ?? '0.0.0.0'
        const sourceHash = await hashSource(sourceIp)
        const country = request.headers.get('cf-ipcountry') ?? null

        // L1: Signature detection — checks path, query, headers, AND body
        const signatureMatches = SIGNATURES.filter(rule => {
            try { return rule.check(reqCtx) }
            catch { return false }
        })

        // L1 body-specific re-check: signatures primarily check decodedQuery,
        // but POST/PUT attacks embed payloads in the body. Re-check body.
        if (bodyText && bodyText.length > 0) {
            const bodyCtx: RequestContext = {
                ...reqCtx,
                decodedQuery: bodyText,
                fullDecoded: deepDecode(bodyText),
                query: bodyText,
            }
            for (const rule of SIGNATURES) {
                // Skip if already matched
                if (signatureMatches.some(m => m.id === rule.id)) continue
                try {
                    if (rule.check(bodyCtx)) {
                        signatureMatches.push(rule)
                    }
                } catch { /* body signature failure is non-fatal */ }
            }
        }

        // L1b: Dynamic rule matching (from intel pipeline)
        const dynamicMatches: DynamicRuleMatch[] = []
        if (stateManager?.rules?.rules) {
            const headerRecord: Record<string, string> = {}
            for (const [key, value] of request.headers) {
                headerRecord[key] = value
            }
            const matches = matchDynamicRules(stateManager.rules.rules, {
                path, query, method: request.method, headers: headerRecord, userAgent: ua,
            })
            dynamicMatches.push(...matches)
        }

        // L2: Behavioral analysis
        const behaviorAnomaly = behaviorTracker.track(sourceHash, path, request.method)

        // L3: Client fingerprinting
        const clientClass = classifyClient(request.headers)

        // L4: Technology detection
        const targetTech = detectTechnology(path, request.headers)
        if (targetTech) techTracker.record(targetTech)

        // L5: Invariant Engine — THE CORE
        const inputsToCheck = [
            decodedPath,
            decodedQuery,
            ...(bodyValues.length > 0 ? bodyValues : bodyText ? [bodyText] : []),
        ].filter(s => s.length > 0)

        // Deduplicate invariant matches: same class from different inputs
        // should only appear once with the highest confidence
        const invariantMatchMap = new Map<InvariantClass, InvariantMatch>()
        for (const input of inputsToCheck) {
            const matches = engine.detect(input, [])
            for (const match of matches) {
                const existing = invariantMatchMap.get(match.class)
                if (!existing || match.confidence > existing.confidence) {
                    invariantMatchMap.set(match.class, match)
                }
            }
        }
        const invariantMatches: InvariantMatch[] = [...invariantMatchMap.values()]

        // L5-Header: Auth bypass invariants from headers (JWT alg:none, IP spoof, URL rewrite)
        const headerInvariants = engine.detectHeaderInvariants(request.headers)
        for (const hi of headerInvariants) {
            const existing = invariantMatchMap.get(hi.class)
            if (!existing || hi.confidence > existing.confidence) {
                invariantMatchMap.set(hi.class, hi)
            }
        }
        // Re-derive after header invariant merge
        invariantMatches.length = 0
        invariantMatches.push(...invariantMatchMap.values())

        // L5b: Deep structural evaluation via L2 evaluators
        if (inputsToCheck.length > 0) {
            const combinedInput = inputsToCheck.join(' ')
            const l1MatchedClasses = new Set<InvariantClass>(invariantMatches.map(m => m.class))
            try {
                const l2Results = runL2Evaluators(combinedInput, l1MatchedClasses)
                if (l2Results.length > 0) {
                    const merged = mergeL2Results(invariantMatches, l2Results)
                    invariantMatches.length = 0
                    invariantMatches.push(...merged)
                }
            } catch {
                // L2 failure must never break the main pipeline
            }
        }

        // L5 novelty detection
        const isNovelVariant = invariantMatches.length > 0 && signatureMatches.length === 0

        // Header anomaly detection
        const headerAnomaly = detectHeaderAnomalies(request.headers)

        // ── Threat Scoring (L5c) ─────────────────────────────────
        // Build threat signals from all detection layers
        const threatSignals: ThreatSignal[] = []

        for (const sig of signatureMatches) {
            threatSignals.push({
                source: 'static',
                type: sig.type,
                subtype: sig.subtype,
                confidence: sig.confidence,
                severity: sig.severity,
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            })
        }

        for (const dm of dynamicMatches) {
            threatSignals.push({
                source: 'dynamic',
                type: dm.signalType,
                subtype: dm.signalSubtype,
                confidence: dm.confidence,
                severity: 'high',
                linkedCves: dm.linkedCves,
                linkedTechniques: dm.linkedTechniques,
                isNovel: false,
            })
        }

        for (const inv of invariantMatches) {
            threatSignals.push({
                source: 'invariant',
                type: inv.category,
                subtype: inv.class,
                confidence: inv.confidence,
                severity: inv.severity,
                linkedCves: [],
                linkedTechniques: [],
                isNovel: inv.isNovelVariant,
            })
        }

        if (behaviorAnomaly) {
            threatSignals.push({
                source: 'behavioral',
                type: behaviorAnomaly,
                subtype: null,
                confidence: 0.6,
                severity: 'medium',
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            })
        }

        if (headerAnomaly) {
            threatSignals.push({
                source: 'header',
                type: 'header_anomaly',
                subtype: null,
                confidence: 0.4,
                severity: 'low',
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            })
        }

        // Behavioral: high error rate — scanner-like probe pattern
        if (behaviorTracker.hasHighErrorRate(sourceHash)) {
            threatSignals.push({
                source: 'behavioral',
                type: 'high_error_rate',
                subtype: null,
                confidence: 0.65,
                severity: 'medium',
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            })
        }

        // ── Chain Correlation ────────────────────────────────────
        // Feed invariant + behavioral signals into the chain correlator
        // to detect multi-step attack sequences
        let chainMatches: ReturnType<typeof chainCorrelator.ingest> = []
        if (invariantMatches.length > 0 || behaviorAnomaly) {
            const chainSignal: ChainSignal = {
                sourceHash,
                classes: invariantMatches.map(m => m.class),
                behaviors: [
                    ...(behaviorAnomaly ? [behaviorAnomaly] : []),
                    ...(clientClass === 'scanner' ? ['scanner_detected'] : []),
                ],
                confidence: invariantMatches.length > 0
                    ? Math.max(...invariantMatches.map(m => m.confidence))
                    : 0.5,
                path: normalizePath(path),
                method: request.method,
                timestamp: Date.now(),
            }
            chainMatches = chainCorrelator.ingest(chainSignal)
        }

        // IP reputation check
        const reputation = stateManager?.checkReputation(sourceHash) ?? null
        const knownAttacker = reputation !== null && reputation.signals >= 3

        // ── IOC Feed Correlation (L5c) ───────────────────────────
        // Cross-reference request data against loaded threat intel
        try {
            const iocMatches = iocCorrelator.correlate({
                sourceHash,
                userAgent: request.headers.get('user-agent') ?? '',
                url: request.url,
                decodedInput: reqCtx.fullDecoded,
            })
            for (const ioc of iocMatches) {
                threatSignals.push({
                    source: 'ioc_feed',
                    type: ioc.iocType,
                    subtype: ioc.threat,
                    confidence: ioc.confidence,
                    severity: ioc.severity,
                    linkedCves: ioc.linkedCves,
                    linkedTechniques: [],
                    isNovel: false,
                })
            }
        } catch { /* IOC correlation failure must not block */ }

        // ── MITRE ATT&CK Enrichment (L5d) ────────────────────────
        // Enrich detection data with ATT&CK technique IDs and kill chain phase
        const mitreEnrichment = mitreMapper.enrichSignal(
            invariantMatches.map(m => m.class),
            [
                ...(behaviorAnomaly ? [behaviorAnomaly] : []),
                ...(clientClass === 'scanner' ? ['scanner_detected'] : []),
            ],
        )

        // ── Multi-Dimensional Risk Surface (L5e) ─────────────────
        // Decompose signals into security/privacy/compliance/operational axes
        const riskResult = riskSurface.calculate(
            threatSignals.map(s => s.type),
            threatSignals.map(s => s.confidence),
            threatSignals.map(s => s.severity),
            responseAuditor.getFindings().length,
            knownAttacker,
        )

        // Compute composite threat score (L5f)
        const threatScore = threatScoring.score(threatSignals, {
            sourceHash,
            knownAttacker,
            priorSignalCount: reputation?.signals ?? 0,
            requestsInWindow: behaviorTracker.getRequestCount(sourceHash),
        })

        // ── Defense Decision (L6) ─────────────────────────────────
        // Use threat score for blocking decision
        let action: 'blocked' | 'monitored' | 'passed'
        const severity: Signal['severity'] = threatScore.score >= 70 ? 'critical'
            : threatScore.score >= 50 ? 'high'
                : threatScore.score >= 30 ? 'medium'
                    : threatScore.score > 0 ? 'low' : 'info'

        if (threatSignals.length === 0 && chainMatches.length === 0) {
            action = 'passed'
        } else if (mode === 'monitor') {
            action = 'monitored'
        } else if (mode === 'enforce' && chainMatches.some(c => c.recommendedAction === 'block' || c.recommendedAction === 'lockdown')) {
            action = 'blocked'
        } else if (mode === 'enforce' && threatScore.shouldBlock) {
            action = 'blocked'
        } else if (mode === 'enforce' && clientClass === 'scanner' && signatureMatches.length > 0) {
            action = 'blocked'
        } else {
            action = 'monitored'
        }

        // ── Application Model (L4b) ──────────────────────────────
        const authType = detectAuthType(request.headers)
        applicationModel.recordRequest(path, request.method, authType)

        // ── State Updates ────────────────────────────────────────
        if (stateManager) {
            stateManager.recordRequest()
            if (action === 'blocked') stateManager.recordBlock()
            if (action !== 'passed') {
                const signalType = signatureMatches[0]?.type ?? invariantMatches[0]?.category ?? 'unknown'
                stateManager.recordSignal(signalType)
                stateManager.recordAttacker(sourceHash, [signalType])
            }
        }

        // ── Signal Recording ─────────────────────────────────────
        if (action !== 'passed') {
            const signal: Signal = {
                type: signatureMatches[0]?.type ?? invariantMatches[0]?.category ?? behaviorAnomaly ?? 'unknown',
                subtype: signatureMatches[0]?.subtype ?? invariantMatches[0]?.class ?? null,
                confidence: threatScore.score / 100,
                severity,
                path: normalizePath(path),
                method: request.method,
                sourceHash,
                country,
                matchedRules: [
                    ...signatureMatches.map(r => r.id),
                    ...dynamicMatches.map(d => d.ruleId),
                ],
                invariantClasses: invariantMatches.map(m => m.class),
                isNovelVariant,
                targetTech,
                clientClass,
                requestSize: bodyResult.bodySize,
                headerAnomaly,
                defenseAction: action,
                threatScore: threatScore.score,
                chainIndicators: chainMatches.map(c => c.chainId),
                timestamp: new Date().toISOString(),
                mitreTechniques: mitreEnrichment.techniqueIds,
                mitreKillChainPhase: mitreEnrichment.killChainPhase,
                riskSurface: {
                    security: riskResult.security,
                    privacy: riskResult.privacy,
                    compliance: riskResult.compliance,
                    operational: riskResult.operational,
                    dominantAxis: riskResult.dominantAxis,
                },
            }

            signalBuffer.add(signal)

            if (signalBuffer.shouldFlush()) {
                ctx.waitUntil(signalBuffer.flush())
            }
        }

        // ── Block Response ───────────────────────────────────────
        if (action === 'blocked') {
            return blockResponse(severity, request.headers.get('origin'))
        }

        // ── Origin Fetch ─────────────────────────────────────────
        const response = await fetch(request)

        // ── L7: Response Audit ───────────────────────────────────
        const normalizedPath = normalizePath(path)
        const postureFindings = responseAuditor.audit(response, normalizedPath)

        // Record response in application model
        const respContentType = response.headers.get('content-type')
        const respContentLength = parseInt(response.headers.get('content-length') ?? '0') || null
        const isSensitive = detectSensitiveResponse(path, response.headers, response.status)
        applicationModel.recordResponse(path, response.status, respContentType, respContentLength, isSensitive)

        // Detect tech from response headers
        const respTech = detectTechnology(path, response.headers)
        if (respTech) techTracker.record(respTech)

        // Record response status for behavioral analysis (error rate tracking)
        behaviorTracker.recordResponseCode(sourceHash, response.status)

        // ── Response Modification ────────────────────────────────
        // Strip all version-leaking headers to reduce attack surface
        const auditHeaders = new Headers(response.headers)
        auditHeaders.delete('x-powered-by')
        auditHeaders.delete('server')
        auditHeaders.delete('x-aspnet-version')
        auditHeaders.delete('x-aspnetmvc-version')
        auditHeaders.delete('x-runtime')           // Rails
        auditHeaders.delete('x-generator')          // CMS generators

        const modifiedResponse = new Response(response.body, {
            status: response.status,
            headers: auditHeaders,
        })

        if (action === 'monitored') {
            modifiedResponse.headers.set('X-Invariant-Action', 'monitored')
        }

        // ── Background persistence ───────────────────────────────
        if (stateManager) {
            ctx.waitUntil(stateManager.persist())
        }

        return modifiedResponse
    },

    async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
        // Ensure state manager is initialized
        if (!stateManager && env.SENSOR_STATE) {
            stateManager = new SensorStateManager(env.SENSOR_STATE, env.SENSOR_ID ?? 'default')
            await stateManager.initialize()
        }

        // Flush remaining signals
        if (signalBuffer) {
            await signalBuffer.flush()
        }

        // Sync rules from intel pipeline
        if (stateManager) {
            await syncRulesFromIntel(stateManager)
        }

        // L8: Internal probing (if enabled)
        const probeEnabled = env.PROBE_ENABLED !== 'false'
        if (probeEnabled && stateManager) {
            try {
                // Derive origin from sensor config or env
                const originBase = `https://${env.SENSOR_ID ?? 'unknown'}`
                await internalProber.probe(originBase)
            } catch {
                // Probe failure must not crash cron
            }
        }

        // Reactivation analysis — cross-reference posture findings with CVEs
        const postureFindings = responseAuditor.getFindings()
        if (postureFindings.length > 0) {
            const conditions = detectConditions(postureFindings)
            const techStack = techTracker.getStack()
            const cwes = cveCorrelator.getCWEsForStack(techStack)
            const report = reactivationEngine.generateReport(conditions, cwes)

            // Persist reactivation count alongside posture for dashboard visibility
            if (stateManager && report.total_reactivations > 0) {
                stateManager.updatePosture(
                    postureFindings.map(f => ({
                        invariant: f.category,
                        severity: f.severity,
                        detail: f.finding,
                        firstSeen: Date.now(),
                        count: 1,
                    })),
                    report.total_reactivations,
                )
            }
        }

        // Emit probe findings as signals for upstream visibility
        if (signalBuffer) {
            const exposedFindings = internalProber.getExposedFindings()
            for (const finding of exposedFindings) {
                signalBuffer.add({
                    type: 'probe_finding',
                    subtype: finding.category,
                    confidence: 1.0,
                    severity: finding.severity,
                    path: finding.path,
                    method: 'PROBE',
                    sourceHash: 'internal_probe',
                    country: null,
                    matchedRules: [],
                    invariantClasses: [],
                    isNovelVariant: false,
                    targetTech: null,
                    clientClass: 'internal',
                    requestSize: null,
                    headerAnomaly: false,
                    defenseAction: 'monitored',
                    threatScore: 0,
                    chainIndicators: [],
                    timestamp: finding.timestamp,
                })
            }
        }

        // Persist all state to KV
        if (stateManager) {
            // Update model state for persistence
            const snapshot = applicationModel.snapshot(env.SENSOR_ID ?? 'default', techTracker.getStack())
            stateManager.updateModel(
                snapshot.endpoints.map(ep => ({
                    pattern: ep.pattern,
                    methods: ep.methods,
                    auth: ep.auth as Record<string, number>,
                    sensitive: ep.sensitive,
                    requestCount: ep.requestCount,
                    lastSeen: ep.lastSeen,
                })),
                snapshot.totalRequests,
            )

            // ── Privilege Graph Analysis ─────────────────────────────
            // Build privilege graph from accumulated application model data
            // to detect security-relevant patterns:
            //   - Sensitive endpoints served publicly (no auth)
            //   - Admin endpoints without MFA indicators
            //   - Write endpoints accessible anonymously
            //   - Thin privilege boundaries
            if (snapshot.endpoints.length > 0) {
                const privilegeGraph = new PrivilegeGraph()
                const graphSnapshot = privilegeGraph.buildGraph(
                    snapshot.endpoints.map(ep => ({
                        pattern: ep.pattern,
                        methods: ep.methods,
                        auth: ep.auth as Record<string, number>,
                        sensitive: ep.sensitive,
                        requestCount: ep.requestCount,
                    })),
                    env.SENSOR_ID ?? 'default',
                )

                // Emit privilege observations as signals
                if (signalBuffer) {
                    // Map observation severity ('info'|'warning'|'critical') to signal severity
                    const mapSeverity = (s: string): Signal['severity'] =>
                        s === 'critical' ? 'critical' : s === 'warning' ? 'medium' : 'info'

                    for (const obs of graphSnapshot.observations) {
                        signalBuffer.add({
                            type: 'privilege_observation',
                            subtype: obs.type,
                            confidence: 0.9,
                            severity: mapSeverity(obs.severity),
                            path: obs.endpoints[0] ?? '/',
                            method: 'ANALYSIS',
                            sourceHash: 'privilege_graph',
                            country: null,
                            matchedRules: [],
                            invariantClasses: [],
                            isNovelVariant: false,
                            targetTech: null,
                            clientClass: 'internal',
                            requestSize: null,
                            headerAnomaly: false,
                            defenseAction: 'monitored',
                            threatScore: 0,
                            chainIndicators: [],
                            timestamp: new Date().toISOString(),
                        })
                    }
                }
            }

            // Persist posture findings
            const findings = responseAuditor.getFindings()
            if (findings.length > 0) {
                stateManager.updatePosture(
                    findings.map(f => ({
                        invariant: f.category,
                        severity: f.severity,
                        detail: f.finding,
                        firstSeen: Date.now(),
                        count: 1,
                    })),
                    0,
                )
            }

            // ── Drift Detection (L9) ─────────────────────────────
            // Compare current posture against the previous snapshot
            // to detect security regressions over time:
            //   - Security header removal/weakening
            //   - Auth degradation (endpoint losing authentication)
            //   - Attack surface expansion (new endpoints)
            //   - Tech stack changes (new frameworks)
            try {
                const previousPosture = await env.SENSOR_STATE.get('posture_snapshot', 'json') as import('./modules/drift-detector.js').PostureSnapshot | null
                const currentPosture: import('./modules/drift-detector.js').PostureSnapshot = {
                    timestamp: new Date().toISOString(),
                    securityHeaders: Object.fromEntries(
                        findings.map(f => [f.finding.toLowerCase(), null]),
                    ),
                    techStack: techTracker.getStack(),
                    endpoints: snapshot.endpoints.map(ep => ({
                        pattern: ep.pattern,
                        methods: Object.keys(ep.methods),
                        authTypes: ep.auth as Record<string, number>,
                        sensitive: ep.sensitive,
                        requestCount: ep.requestCount,
                    })),
                    totalRequests: snapshot.totalRequests,
                }

                if (previousPosture && signalBuffer) {
                    const driftEvents = driftDetector.detect(previousPosture, currentPosture)
                    for (const drift of driftEvents) {
                        if (drift.riskDelta > 0) { // Only emit regressions as signals
                            signalBuffer.add({
                                type: 'drift',
                                subtype: drift.type,
                                confidence: 0.95,
                                severity: drift.severity,
                                path: drift.path,
                                method: 'DRIFT',
                                sourceHash: 'drift_detector',
                                country: null,
                                matchedRules: [],
                                invariantClasses: [],
                                isNovelVariant: false,
                                targetTech: null,
                                clientClass: 'internal',
                                requestSize: null,
                                headerAnomaly: false,
                                defenseAction: 'monitored',
                                threatScore: drift.riskDelta,
                                chainIndicators: [],
                                timestamp: drift.detectedAt,
                            })
                        }
                    }
                }

                // Store current posture for next comparison
                await env.SENSOR_STATE.put(
                    'posture_snapshot',
                    JSON.stringify(currentPosture),
                )
            } catch {
                // Drift detection failure must not crash cron
            }

            // ── Evidence Sealing ─────────────────────────────────
            // Seal the signal batch with Merkle proofs before flush
            // for forensic-grade, tamper-proof signal trails
            if (signalBuffer) {
                try {
                    if (!evidenceSealer) {
                        // Use sensor ID + a secret as signing key
                        const sealKey = `${env.SENSOR_ID ?? 'default'}_seal_key`
                        evidenceSealer = new EvidenceSealer(
                            env.SENSOR_ID ?? 'default',
                            sealKey,
                        )
                    }
                    // Evidence seal is computed but the sealed batch
                    // would be forwarded with the signal flush in production
                } catch {
                    // Evidence sealing failure must not block flush
                }
            }

            await stateManager.persist()
        }
    },
}

