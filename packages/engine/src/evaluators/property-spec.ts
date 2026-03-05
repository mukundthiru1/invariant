/**
 * Invariant Property Specification — Formal ISL Implementation
 *
 * Each invariant is now defined as a FORMAL PROPERTY with:
 *   - Domain (what contexts it applies to)
 *   - Property (the mathematical condition that constitutes an attack)
 *   - Multi-level detection (fast regex → deep evaluator → AI fallback)
 *   - Composability declarations
 *   - Auto-generated test vectors
 *
 * This replaces the ad-hoc InvariantDefinition with a structured
 * specification that enables:
 *   - Formal verification
 *   - Cross-platform transpilation
 *   - Automated completeness auditing
 *   - Compositional attack chain modeling
 */


// ── Property Domain ──────────────────────────────────────────────

export type PropertyDomain =
    | 'sql_injection'
    | 'xss'
    | 'path_traversal'
    | 'command_injection'
    | 'ssrf'
    | 'deserialization'
    | 'authentication'
    | 'template_injection'
    | 'xxe'
    | 'ldap_injection'
    | 'crlf_injection'
    | 'open_redirect'
    | 'prototype_pollution'
    | 'nosql_injection'
    | 'http_smuggling'
    | 'graphql_abuse'
    | 'xml_injection'
    | 'regex_dos'
    | 'mass_assignment'

export type InjectionContext =
    | 'WHERE'
    | 'HAVING'
    | 'ORDER_BY'
    | 'INSERT_VALUES'
    | 'UPDATE_SET'
    | 'HTML_BODY'
    | 'HTML_ATTR'
    | 'JS_STRING'
    | 'JSON_VALUE'
    | 'SHELL_ARG'
    | 'SHELL_PIPE'
    | 'URL_PARAM'
    | 'HEADER_VALUE'
    | 'FILE_PATH'
    | 'TEMPLATE_EXPR'
    | 'XML_CONTENT'
    | 'LDAP_FILTER'
    | 'GRAPHQL_QUERY'
    | 'UNKNOWN'


// ── Detection Levels ─────────────────────────────────────────────

/**
 * Detection results at different analysis depths.
 *
 * Level 1 (Regex):  Fast path. Known patterns. High confidence, low coverage.
 * Level 2 (Eval):   Deep path. Property evaluation. Catches novel variants.
 * Level 3 (AI):     Fallback. Semantic understanding. Handles ambiguity.
 */
export interface DetectionResult {
    /** Whether this level detected a violation */
    detected: boolean
    /** Confidence in the detection (0-1) */
    confidence: number
    /** Human-readable explanation */
    explanation: string
    /** The specific evidence (matched pattern, eval result, etc.) */
    evidence?: string
}

export interface MultiLevelDetection {
    level1: DetectionResult  // Regex fast-path
    level2: DetectionResult  // Expression evaluator
    /** Combined confidence (uses highest detection) */
    combined: DetectionResult
}


// ── Invariant Property Specification ─────────────────────────────

export interface InvariantProperty {
    /** Unique identifier for this invariant (kebab-case) */
    readonly id: string

    /** Human-readable name */
    readonly name: string

    /** The property domain (what category of attack) */
    readonly domain: PropertyDomain

    /** What injection contexts this property applies to */
    readonly contexts: InjectionContext[]

    /** Severity rating */
    readonly severity: 'critical' | 'high' | 'medium' | 'low'

    /**
     * Formal property statement.
     * This is the mathematical invariant — readable by humans,
     * verifiable by the test suite.
     *
     * Example: "∃ subexpr ∈ parse(input, SQL_GRAMMAR) :
     *           eval(subexpr, BOOLEAN_CONTEXT) ∈ {TRUE, TAUTOLOGY}"
     */
    readonly formalProperty: string

    /**
     * Why this property matters — the security impact.
     */
    readonly rationale: string

    /**
     * Level 1: Regex-based fast-path detection.
     * Quick check — may miss novel variants but is extremely fast.
     * Returns null if this property has no Level 1 implementation.
     */
    readonly detectL1: ((input: string) => DetectionResult) | null

    /**
     * Level 2: Deep expression evaluation.
     * Slower but catches novel variants by evaluating the PROPERTY,
     * not matching specific character sequences.
     * Returns null if this property has no Level 2 implementation.
     */
    readonly detectL2: ((input: string) => DetectionResult) | null

    /**
     * IDs of properties this one composes with to form attack chains.
     */
    readonly composableWith: string[]

    /**
     * How this property can be discovered in the wild.
     */
    readonly discoveryChannels: ('runtime_sensor' | 'code_analysis' | 'incident_analysis' | 'crowdsource')[]

    /**
     * Auto-generated test vectors.
     * Each generates inputs that MUST trigger this property (true positives)
     * and inputs that MUST NOT trigger it (true negatives).
     */
    readonly generatePositives: (count: number) => string[]
    readonly generateNegatives: (count: number) => string[]
}


// ── Property Registry ────────────────────────────────────────────

/**
 * The universal property registry.
 * All invariant properties are registered here and can be:
 *   - Queried by domain, context, or severity
 *   - Composed into attack chains
 *   - Audited for completeness against CWEs
 */
export class PropertyRegistry {
    private readonly properties = new Map<string, InvariantProperty>()
    private readonly byDomain = new Map<PropertyDomain, InvariantProperty[]>()

    register(property: InvariantProperty): void {
        if (this.properties.has(property.id)) {
            throw new Error(`Invariant property '${property.id}' is already registered`)
        }
        this.properties.set(property.id, property)

        const domainList = this.byDomain.get(property.domain) ?? []
        domainList.push(property)
        this.byDomain.set(property.domain, domainList)
    }

    get(id: string): InvariantProperty | undefined {
        return this.properties.get(id)
    }

    getByDomain(domain: PropertyDomain): InvariantProperty[] {
        return this.byDomain.get(domain) ?? []
    }

    get all(): InvariantProperty[] {
        return Array.from(this.properties.values())
    }

    get count(): number {
        return this.properties.size
    }

    /**
     * Detect against all registered properties.
     * Returns only properties that detected a violation.
     */
    detect(input: string): PropertyDetection[] {
        const detections: PropertyDetection[] = []

        for (const property of this.properties.values()) {
            const result = detectProperty(property, input)
            if (result.combined.detected) {
                detections.push({
                    property,
                    result,
                })
            }
        }

        return detections
    }

    /**
     * Detect with context awareness — only evaluate properties
     * relevant to the inferred injection context.
     */
    detectWithContext(input: string, contexts: InjectionContext[]): PropertyDetection[] {
        const detections: PropertyDetection[] = []

        for (const property of this.properties.values()) {
            // Skip if no context overlap
            if (contexts.length > 0 && !property.contexts.some(c => contexts.includes(c))) {
                continue
            }

            const result = detectProperty(property, input)
            if (result.combined.detected) {
                detections.push({
                    property,
                    result,
                })
            }
        }

        return detections
    }

    /**
     * Get composition partners for a detected property.
     * Returns properties that form attack chains with the given one.
     */
    getCompositions(propertyId: string): InvariantProperty[] {
        const property = this.properties.get(propertyId)
        if (!property) return []

        return property.composableWith
            .map(id => this.properties.get(id))
            .filter((p): p is InvariantProperty => p !== undefined)
    }

    /**
     * Run self-test: verify all properties detect their own
     * positive test vectors and don't detect their negatives.
     */
    selfTest(): PropertySelfTestResult {
        const results: PropertySelfTestResult = {
            total: this.properties.size,
            passed: 0,
            failed: 0,
            failures: [],
        }

        for (const property of this.properties.values()) {
            try {
                // Test positives
                const positives = property.generatePositives(5)
                for (const input of positives) {
                    const detection = detectProperty(property, input)
                    if (!detection.combined.detected) {
                        results.failures.push({
                            propertyId: property.id,
                            type: 'missed_positive',
                            input,
                        })
                    }
                }

                // Test negatives
                const negatives = property.generateNegatives(5)
                for (const input of negatives) {
                    const detection = detectProperty(property, input)
                    if (detection.combined.detected) {
                        results.failures.push({
                            propertyId: property.id,
                            type: 'false_positive',
                            input,
                        })
                    }
                }

                if (results.failures.filter(f => f.propertyId === property.id).length === 0) {
                    results.passed++
                } else {
                    results.failed++
                }
            } catch (err) {
                results.failed++
                results.failures.push({
                    propertyId: property.id,
                    type: 'error',
                    input: err instanceof Error ? err.message : 'unknown error',
                })
            }
        }

        return results
    }
}


// ── Detection Helpers ────────────────────────────────────────────

export interface PropertyDetection {
    property: InvariantProperty
    result: MultiLevelDetection
}

export interface PropertySelfTestResult {
    total: number
    passed: number
    failed: number
    failures: {
        propertyId: string
        type: 'missed_positive' | 'false_positive' | 'error'
        input: string
    }[]
}

/**
 * Run multi-level detection for a single property.
 */
function detectProperty(property: InvariantProperty, input: string): MultiLevelDetection {
    const noDetection: DetectionResult = { detected: false, confidence: 0, explanation: '' }

    // Level 1: Regex fast-path
    let l1 = noDetection
    if (property.detectL1) {
        try {
            l1 = property.detectL1(input)
        } catch {
            l1 = noDetection
        }
    }

    // Level 2: Deep evaluation
    let l2 = noDetection
    if (property.detectL2) {
        try {
            l2 = property.detectL2(input)
        } catch {
            l2 = noDetection
        }
    }

    // Combined: take the highest confidence detection
    let combined = noDetection
    if (l1.detected || l2.detected) {
        if (l1.confidence >= l2.confidence) {
            combined = {
                detected: true,
                confidence: l1.confidence,
                explanation: l1.explanation,
                evidence: l1.evidence,
            }
        } else {
            combined = {
                detected: true,
                confidence: l2.confidence,
                explanation: l2.explanation,
                evidence: l2.evidence,
            }
        }

        // If both detected, boost confidence (convergent evidence)
        if (l1.detected && l2.detected) {
            combined.confidence = Math.min(0.99, combined.confidence + 0.05)
            combined.explanation = `Convergent detection: ${l1.explanation} + ${l2.explanation}`
        }
    }

    return { level1: l1, level2: l2, combined }
}


// ── Singleton Registry ───────────────────────────────────────────

export const PROPERTY_REGISTRY = new PropertyRegistry()
