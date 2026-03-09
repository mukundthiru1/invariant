/**
 * Invariant Class Registry — Dynamic Module System
 *
 * Central registry for all invariant class modules. Provides:
 *   - Dynamic registration (add classes at runtime)
 *   - Lookup by ID, category, or severity
 *   - Validation (no duplicate IDs, all fields present)
 *   - Statistics (counts by category, severity)
 *   - Calibration override application
 *
 * The registry is the single point of truth for what classes exist.
 * The InvariantEngine delegates to the registry for all class lookups.
 *
 * INVARIANT: Once registered, a class module is immutable.
 * Registration is additive-only — classes cannot be removed.
 */

import type {
    InvariantClass,
    InvariantClassModule,
    AttackCategory,
    Severity,
    CalibrationConfig,
    InvariantMatch,
    InterClassCorrelation,
} from './types.js'
import { InvariantError } from '../invariant-error.js'


export function sanitizeConfidence(value: number, fallback: number = 0.5): number {
    if (!Number.isFinite(value)) {
        if (value === Number.POSITIVE_INFINITY) {
            return 0.99
        }
        return sanitizeConfidence(fallback)
    }

    return Math.max(0, Math.min(0.99, value))
}


// ── Correlation Rules (data-driven inter-class pattern table) ─────

interface CorrelationRule {
    /** AND groups of OR alternatives — each inner array is OR, all outer must match */
    required: string[][]
    /** Fixed confidence or delta above max individual confidence */
    confidence: { type: 'fixed'; value: number } | { type: 'relative'; delta: number }
    /** Human-readable explanation */
    reason: string
    /** Exclusive group — only the first match per group fires (higher = higher priority) */
    group?: string
}

/**
 * Data table of inter-class correlation patterns.
 * Ordered by priority within each exclusive group (first match wins).
 * Adding a new correlation = adding ONE entry here.
 */
const CORRELATION_RULES: readonly CorrelationRule[] = [
    // SQL injection — exclusive group (triad > double > timing)
    {
        required: [['sql_string_termination'], ['sql_tautology', 'sql_union_extraction'], ['sql_comment_truncation', 'sql_stacked_execution']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'Complete SQL injection structure: escape + payload + termination',
        group: 'sql',
    },
    {
        required: [['sql_string_termination'], ['sql_union_extraction']],
        confidence: { type: 'relative', delta: 0.12 },
        reason: 'String escape + data extraction',
        group: 'sql',
    },
    {
        required: [['sql_string_termination'], ['sql_time_oracle']],
        confidence: { type: 'relative', delta: 0.10 },
        reason: 'String escape + time oracle',
        group: 'sql',
    },
    // XSS patterns
    {
        required: [['xss_tag_injection'], ['xss_event_handler']],
        confidence: { type: 'relative', delta: 0.12 },
        reason: 'Tag injection + event handler',
    },
    {
        required: [['xss_template_expression'], ['proto_pollution']],
        confidence: { type: 'relative', delta: 0.15 },
        reason: 'Template expression + prototype pollution',
    },
    // SSRF escalation
    {
        required: [['ssrf_internal_reach'], ['ssrf_cloud_metadata']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'Internal reach + cloud metadata escalation',
    },
    {
        required: [['ssrf_protocol_smuggle'], ['ssrf_cloud_metadata']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'Protocol smuggle + cloud metadata = credential theft bypass',
    },
    // Auth chain
    {
        required: [['auth_none_algorithm'], ['auth_header_spoof']],
        confidence: { type: 'relative', delta: 0.10 },
        reason: 'None algorithm + header spoof',
    },
    // Command chain
    {
        required: [['cmd_separator'], ['cmd_substitution']],
        confidence: { type: 'relative', delta: 0.10 },
        reason: 'Command separator + substitution',
    },
    // JWT forgery — exclusive group
    {
        required: [['jwt_kid_injection'], ['jwt_jwk_embedding']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'JWT kid injection + JWK embedding = full token forgery',
        group: 'jwt',
    },
    {
        required: [['jwt_confusion'], ['jwt_kid_injection', 'auth_none_algorithm']],
        confidence: { type: 'relative', delta: 0.15 },
        reason: 'JWT algorithm confusion + key manipulation',
        group: 'jwt',
    },
    // Cache poisoning + XSS
    {
        required: [['cache_poisoning'], ['xss_tag_injection', 'xss_event_handler']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'Cache poisoning + XSS = persistent stored XSS for all visitors',
    },
    // API abuse compound
    {
        required: [['bola_idor'], ['api_mass_enum']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'IDOR + mass enumeration = complete data exfiltration',
    },
    // LLM compound
    {
        required: [['llm_jailbreak'], ['llm_data_exfiltration']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'LLM jailbreak + data exfiltration = confirmed extraction',
    },
    // Supply chain compound
    {
        required: [['dependency_confusion'], ['postinstall_injection']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'Dependency confusion + postinstall injection = supply chain RCE',
    },
    // Deser + command → RCE chain
    {
        required: [['deser_java_gadget', 'deser_python_pickle'], ['cmd_separator', 'cmd_substitution']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'Deserialization gadget + command injection = confirmed RCE',
    },
    // SSTI + command → server takeover
    {
        required: [['ssti_jinja_twig', 'ssti_el_expression'], ['cmd_separator', 'cmd_substitution']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'SSTI + command injection = server-side code execution',
    },
    // HTTP smuggling + cache poisoning
    {
        required: [['http_smuggle_cl_te', 'http_smuggle_h2'], ['cache_poisoning']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'HTTP smuggling + cache poisoning = mass-impact stored attack',
    },
    {
        required: [['http_request_smuggling'], ['cache_poisoning', 'cache_deception']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'General HTTP request smuggling + cache abuse = large-scale response poisoning',
    },
    // WebSocket abuse chain
    {
        required: [['websocket_origin_bypass'], ['websocket_message_injection']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'Cross-origin WS bypass + message injection = account takeover and persistent compromise',
    },
    // GraphQL compound abuse
    {
        required: [['graphql_injection'], ['graphql_dos']],
        confidence: { type: 'relative', delta: 0.10 },
        reason: 'GraphQL exploitation combined with resource exhaustion indicators',
    },
    // Path traversal + SSRF → internal pivot
    {
        required: [['path_dotdot_escape', 'path_encoding_bypass'], ['ssrf_internal_reach']],
        confidence: { type: 'relative', delta: 0.12 },
        reason: 'Path traversal + SSRF = internal filesystem + network pivot',
    },
]


// ── Registry Errors ───────────────────────────────────────────────

export class RegistryError extends InvariantError {
    constructor(message: string, classId?: InvariantClass) {
        super(`[InvariantRegistry] ${message}`, {
            code: 'REGISTRY_ERROR',
            classId,
            phase: 'registry',
        })
        this.name = 'RegistryError'
    }
}

function hashInput(input: string): number {
    // FNV-1a 32-bit hash: fast, deterministic request-scope cache key.
    let hash = 0x811c9dc5
    for (let i = 0; i < input.length; i++) {
        hash ^= input.charCodeAt(i)
        hash = Math.imul(hash, 0x01000193)
    }
    return hash >>> 0
}


// ── Registry ──────────────────────────────────────────────────────

export class InvariantRegistry {
    private readonly modules: Map<InvariantClass, InvariantClassModule> = new Map()
    private readonly byCategory: Map<AttackCategory, InvariantClassModule[]> = new Map()
    private readonly bySeverity: Map<Severity, InvariantClassModule[]> = new Map()
    private readonly calibrationOverrides: Map<InvariantClass, Partial<CalibrationConfig>> = new Map()
    private readonly confidenceScopes: WeakMap<object, Map<string, number>> = new WeakMap()

    runInConfidenceScope<T>(fn: (scope: object) => T): T {
        const scope = {}
        this.confidenceScopes.set(scope, new Map())
        try {
            return fn(scope)
        } finally {
            this.confidenceScopes.delete(scope)
        }
    }

    /**
     * Register a class module.
     * Validates the module contract before accepting it.
     * @throws RegistryError if module is invalid or ID is duplicate.
     */
    register(module: InvariantClassModule): void {
        // Validate contract
        if (!module.id) throw new RegistryError('Module missing id')
        if (!module.description) throw new RegistryError(`Module ${module.id}: missing description`)
        if (!module.category) throw new RegistryError(`Module ${module.id}: missing category`)
        if (!module.severity) throw new RegistryError(`Module ${module.id}: missing severity`)
        if (typeof module.detect !== 'function') throw new RegistryError(`Module ${module.id}: detect is not a function`)
        if (typeof module.generateVariants !== 'function') throw new RegistryError(`Module ${module.id}: generateVariants is not a function`)
        if (!Array.isArray(module.knownPayloads)) throw new RegistryError(`Module ${module.id}: knownPayloads must be an array`)
        if (!Array.isArray(module.knownBenign)) throw new RegistryError(`Module ${module.id}: knownBenign must be an array`)

        // No duplicates
        if (this.modules.has(module.id)) {
            throw new RegistryError(`Duplicate class ID: ${module.id}`)
        }

        // Formal contract: verify knownPayloads are actually detected
        const payloadFailures: string[] = []
        for (const payload of module.knownPayloads) {
            try { if (!module.detect(payload)) payloadFailures.push(payload.slice(0, 50)) }
            catch { payloadFailures.push(`ERROR:${payload.slice(0, 30)}`) }
        }
        if (payloadFailures.length > 0) {
            throw new RegistryError(`${module.id}: detect() misses knownPayloads: ${payloadFailures.join(' | ')}`)
        }

        // Formal contract: verify knownBenign do NOT false-positive
        const fpViolations: string[] = []
        for (const benign of module.knownBenign) {
            try { if (module.detect(benign)) fpViolations.push(benign.slice(0, 50)) }
            catch { /* detection errors on benign = no false positive */ }
        }
        if (fpViolations.length > 0) {
            throw new RegistryError(`${module.id}: detect() false-positives on knownBenign: ${fpViolations.join(' | ')}`)
        }

        // Register
        this.modules.set(module.id, module)

        // Index by category
        if (!this.byCategory.has(module.category)) {
            this.byCategory.set(module.category, [])
        }
        this.byCategory.get(module.category)!.push(module)

        // Index by severity
        if (!this.bySeverity.has(module.severity)) {
            this.bySeverity.set(module.severity, [])
        }
        this.bySeverity.get(module.severity)!.push(module)
    }

    /**
     * Register multiple modules at once.
     */
    registerAll(modules: InvariantClassModule[]): void {
        for (const m of modules) this.register(m)
    }

    /**
     * Get a module by class ID.
     */
    get(id: InvariantClass): InvariantClassModule | undefined {
        return this.modules.get(id)
    }

    /**
     * Get all registered modules.
     */
    all(): InvariantClassModule[] {
        return Array.from(this.modules.values())
    }

    /**
     * Get modules by attack category.
     */
    getByCategory(category: AttackCategory): InvariantClassModule[] {
        return this.byCategory.get(category) ?? []
    }

    /**
     * Get modules by severity.
     */
    getBySeverity(severity: Severity): InvariantClassModule[] {
        return this.bySeverity.get(severity) ?? []
    }

    /**
     * Get all registered class IDs.
     */
    classIds(): InvariantClass[] {
        return Array.from(this.modules.keys())
    }

    /**
     * Number of registered classes.
     */
    get size(): number {
        return this.modules.size
    }

    /**
     * Set a calibration override for a class.
     * Overrides are applied at detection time to adjust confidence.
     */
    setCalibrationOverride(classId: InvariantClass, override: Partial<CalibrationConfig>): void {
        if (!this.modules.has(classId)) {
            throw new RegistryError(`Cannot set calibration for unknown class: ${classId}`)
        }
        this.calibrationOverrides.set(classId, override)
    }

    /**
     * Get the effective calibration for a class.
     * Merges module default calibration with any override.
     */
    getCalibration(classId: InvariantClass): CalibrationConfig {
        const module = this.modules.get(classId)
        const base: CalibrationConfig = module?.calibration ?? { baseConfidence: 0.85 }
        const override = this.calibrationOverrides.get(classId)

        if (!override) return base

        return {
            baseConfidence: override.baseConfidence ?? base.baseConfidence,
            environmentMultipliers: {
                ...base.environmentMultipliers,
                ...override.environmentMultipliers,
            },
            falsePositivePatterns: [
                ...(base.falsePositivePatterns ?? []),
                ...(override.falsePositivePatterns ?? []),
            ],
            minInputLength: override.minInputLength ?? base.minInputLength,
        }
    }

    /**
     * Compute detection confidence for a class match, applying calibration.
     */
    computeConfidence(
        classId: InvariantClass,
        input: string,
        environment?: string,
        hasStaticMatch?: boolean,
        scope?: object,
    ): number {
        const cache = scope ? this.confidenceScopes.get(scope) : undefined
        const cacheKey = cache
            ? `${classId}:${hashInput(input)}:${environment ?? ''}:${hasStaticMatch ? '1' : '0'}`
            : null
        if (cache && cacheKey && cache.has(cacheKey)) {
            return cache.get(cacheKey) as number
        }

        const cal = this.getCalibration(classId)
        let confidence = sanitizeConfidence(cal.baseConfidence)

        // Apply environment multiplier
        if (environment && cal.environmentMultipliers?.[environment]) {
            confidence = sanitizeConfidence(confidence * cal.environmentMultipliers[environment])
        }

        // Reduce confidence for false-positive patterns
        if (cal.falsePositivePatterns) {
            for (const pattern of cal.falsePositivePatterns) {
                if (pattern.test(input)) {
                    confidence = sanitizeConfidence(confidence * 0.5)
                    break
                }
            }
        }

        // Reduce confidence for short inputs
        if (cal.minInputLength && input.length < cal.minInputLength) {
            confidence = sanitizeConfidence(confidence * 0.7)
        }

        // Boost confidence for convergent detection (static + invariant)
        if (hasStaticMatch) {
            confidence = sanitizeConfidence(Math.min(0.99, sanitizeConfidence(confidence + 0.10)))
        }

        const computed = sanitizeConfidence(confidence)
        if (cache && cacheKey) {
            cache.set(cacheKey, computed)
        }
        return computed
    }

    /**
     * Compute inter-class compound patterns using data-driven correlation rules.
     *
     * Each rule defines:
     *   - required: AND groups of OR alternatives (all groups must have at least one match)
     *   - confidence: fixed value or delta above max individual confidence
     *   - reason: human-readable explanation
     *   - group: exclusive group ID (only highest-priority match per group fires)
     */
    computeCorrelations(matches: InvariantMatch[]): InterClassCorrelation[] {
        const classes = new Set(matches.map(m => m.class))
        const max = matches.length > 0 ? Math.max(...matches.map(m => sanitizeConfidence(m.confidence))) : 0

        const correlations: InterClassCorrelation[] = []
        const firedGroups = new Set<string>()

        for (const rule of CORRELATION_RULES) {
            // Skip if exclusive group already fired
            if (rule.group && firedGroups.has(rule.group)) continue

            // Check all required groups (AND of ORs)
            const matched = rule.required.every(
                orGroup => orGroup.some(cls => classes.has(cls as InvariantClass))
            )
            if (!matched) continue

            // Compute output classes
            const outputClasses = rule.required.flatMap(
                orGroup => orGroup.filter(cls => classes.has(cls as InvariantClass))
            ) as InvariantClass[]

            const confidence = rule.confidence.type === 'fixed'
                ? sanitizeConfidence(rule.confidence.value)
                : sanitizeConfidence(max + rule.confidence.delta)

            correlations.push({
                classes: outputClasses,
                compoundConfidence: sanitizeConfidence(confidence),
                reason: rule.reason,
            })

            if (rule.group) firedGroups.add(rule.group)
        }

        // Special: Novel variant + 3+ classes → encoding evasion signal
        if (classes.size >= 3 && matches.some(m => m.isNovelVariant)) {
            correlations.push({
                classes: Array.from(classes),
                compoundConfidence: sanitizeConfidence(max + 0.08),
                reason: 'Novel variant + 3+ classes',
            })
        }

        // Deduplicate by reason
        const deduped: InterClassCorrelation[] = []
        const seenReasons = new Set<string>()
        for (const corr of correlations) {
            if (!seenReasons.has(corr.reason)) {
                seenReasons.add(corr.reason)
                deduped.push(corr)
            }
        }

        return deduped
    }

    /**
     * Registry statistics.
     */
    stats(): RegistryStats {
        const byCategory: Record<string, number> = {}
        const bySeverity: Record<string, number> = {}

        for (const [cat, modules] of this.byCategory) {
            byCategory[cat] = modules.length
        }
        for (const [sev, modules] of this.bySeverity) {
            bySeverity[sev] = modules.length
        }

        return {
            totalClasses: this.modules.size,
            byCategory,
            bySeverity,
            withCalibration: Array.from(this.modules.values())
                .filter(m => m.calibration != null).length,
            withOverrides: this.calibrationOverrides.size,
        }
    }
}


// ── Stats Type ────────────────────────────────────────────────────

export interface RegistryStats {
    totalClasses: number
    byCategory: Record<string, number>
    bySeverity: Record<string, number>
    withCalibration: number
    withOverrides: number
}
