/**
 * XXE Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for XXE is:
 *   ∃ declaration ∈ parse(input, XML_PROLOG_GRAMMAR) :
 *     declaration.type = ENTITY_DECL
 *     ∧ declaration.source ∈ {SYSTEM, PUBLIC}
 *     → attacker declares external entity for file read / SSRF / DoS
 *
 *   ∨ ∃ entity_ref ∈ input :
 *     entity_ref = &name;
 *     ∧ name ∈ declared_entities
 *     → entity will be expanded by XML parser
 *
 * This module parses XML DTD declarations structurally,
 * not via regex. It identifies:
 *   - SYSTEM entity declarations (external file/URL)
 *   - PUBLIC entity declarations (external catalog)
 *   - Parameter entity declarations (% entities in DTD)
 *   - Nested entity expansion (Billion Laughs)
 *   - Entity references that would trigger expansion
 *
 * Covers:
 *   - xxe_entity_expansion: external entity declaration + reference
 */


// ── Result Type ──────────────────────────────────────────────────

export interface XXEDetection {
    type: 'external_entity' | 'parameter_entity' | 'entity_expansion' | 'billion_laughs'
    detail: string
    entityName: string
    confidence: number
}


// ── DTD Declaration Parser ───────────────────────────────────────
//
// Parse DTD declarations from XML input. We handle:
//   <!ENTITY name SYSTEM "url">
//   <!ENTITY name PUBLIC "pubid" "url">
//   <!ENTITY % name SYSTEM "url">        (parameter entity)
//   <!ENTITY name "value">               (internal entity)
//   <!DOCTYPE root [...]>                 (inline DTD)

interface EntityDeclaration {
    name: string
    isParameter: boolean  // % entity
    isExternal: boolean   // SYSTEM or PUBLIC
    source: string        // URL or value
    position: number
}

function parseEntityDeclarations(input: string): EntityDeclaration[] {
    const declarations: EntityDeclaration[] = []

    // Normalize case for matching but preserve original for entity names
    const lower = input.toLowerCase()

    // Find all <!ENTITY declarations
    const entityPattern = /<!entity\s+(%\s+)?(\w+)\s+(system|public)\s+["']([^"']*?)["']/gi
    let match: RegExpExecArray | null
    while ((match = entityPattern.exec(lower)) !== null) {
        declarations.push({
            name: match[2],
            isParameter: match[1] !== undefined,
            isExternal: true,
            source: match[4],
            position: match.index,
        })
    }

    // Find internal entity declarations (for billion laughs detection)
    const internalPattern = /<!entity\s+(%\s+)?(\w+)\s+["']([^"']*?)["']\s*>/gi
    while ((match = internalPattern.exec(lower)) !== null) {
        // Skip if already caught as external
        if (!declarations.some(d => d.position === match!.index)) {
            declarations.push({
                name: match[2],
                isParameter: match[1] !== undefined,
                isExternal: false,
                source: match[3],
                position: match.index,
            })
        }
    }

    return declarations
}


// ── Entity Reference Finder ──────────────────────────────────────

function findEntityReferences(input: string): string[] {
    const refs: string[] = []
    const pattern = /&(\w+);/g
    let match: RegExpExecArray | null
    while ((match = pattern.exec(input)) !== null) {
        // Exclude standard XML entities
        const name = match[1]
        if (!['lt', 'gt', 'amp', 'quot', 'apos', 'nbsp'].includes(name)) {
            refs.push(name)
        }
    }
    return refs
}


// ── Dangerous Source Patterns ────────────────────────────────────

const DANGEROUS_SOURCES = [
    /^file:\/\//i,                     // File system read
    /^https?:\/\//i,                   // SSRF
    /^expect:\/\//i,                   // PHP expect:// RCE
    /^php:\/\//i,                      // PHP filter chains
    /^gopher:\/\//i,                   // Protocol smuggling
    /^data:/i,                         // Data URI
    /^jar:/i,                          // Java archive
    /etc\/passwd/i,                    // Sensitive file path
    /etc\/shadow/i,
    /\.ssh/i,
    /windows\/system\.ini/i,
]


// ── Detection Functions ──────────────────────────────────────────

function detectExternalEntity(declarations: EntityDeclaration[], refs: string[]): XXEDetection[] {
    const detections: XXEDetection[] = []

    for (const decl of declarations) {
        if (!decl.isExternal) continue

        const isDangerous = DANGEROUS_SOURCES.some(p => p.test(decl.source))
        const isReferenced = refs.includes(decl.name)

        detections.push({
            type: 'external_entity',
            detail: `External entity "${decl.name}" → ${decl.source}${isDangerous ? ' (DANGEROUS SOURCE)' : ''}${isReferenced ? ' (REFERENCED)' : ''}`,
            entityName: decl.name,
            confidence: isDangerous && isReferenced ? 0.96 :
                isDangerous ? 0.92 :
                    isReferenced ? 0.88 : 0.80,
        })
    }

    return detections
}

function detectParameterEntity(declarations: EntityDeclaration[]): XXEDetection[] {
    const detections: XXEDetection[] = []

    for (const decl of declarations) {
        if (!decl.isParameter) continue

        detections.push({
            type: 'parameter_entity',
            detail: `Parameter entity "%${decl.name}" — can inject into DTD structure`,
            entityName: decl.name,
            confidence: decl.isExternal ? 0.92 : 0.78,
        })
    }

    return detections
}

function detectBillionLaughs(declarations: EntityDeclaration[]): XXEDetection[] {
    const detections: XXEDetection[] = []
    const internalEntities = declarations.filter(d => !d.isExternal)

    // Billion laughs: internal entities that reference other entities.
    // The invariant: an entity value should not contain entity references,
    // because this creates recursive/exponential expansion.
    //
    // Even ONE entity referencing another is suspicious — that's the
    // fundamental amplification pattern. Multiple cross-refs or
    // repeated refs within a single value are high-confidence bombs.
    let totalCrossRefs = 0
    let entitiesWithRefs = 0
    let maxRefsInSingleEntity = 0

    for (const entity of internalEntities) {
        const refsInValue = findEntityReferences(entity.source)
        if (refsInValue.length > 0) {
            entitiesWithRefs++
            totalCrossRefs += refsInValue.length
            maxRefsInSingleEntity = Math.max(maxRefsInSingleEntity, refsInValue.length)
        }
    }

    if (entitiesWithRefs >= 1) {
        // Confidence scales with amplification factor
        const confidence = maxRefsInSingleEntity >= 3 ? 0.94  // repeated refs = bomb
            : entitiesWithRefs >= 2 ? 0.92        // chain of entities
            : 0.85                                  // single entity with ref

        detections.push({
            type: 'billion_laughs',
            detail: `${entitiesWithRefs} entity/entities with ${totalCrossRefs} cross-references — expansion amplification (Billion Laughs)`,
            entityName: 'chain',
            confidence,
        })
    }

    return detections
}

function detectEntityExpansionFromRaw(input: string): XXEDetection[] {
    const detections: XXEDetection[] = []

    // Even without full parsing, detect DTD declaration + entity reference pattern
    const lower = input.toLowerCase()
    const hasDTD = lower.includes('<!doctype') || lower.includes('<!entity')
    const hasSystemOrPublic = lower.includes('system') || lower.includes('public')
    const hasEntityRef = /&\w+;/.test(input)

    if (hasDTD && hasSystemOrPublic && hasEntityRef) {
        detections.push({
            type: 'entity_expansion',
            detail: 'DTD with SYSTEM/PUBLIC declaration and entity reference — XXE pattern',
            entityName: 'unknown',
            confidence: 0.85,
        })
    }

    return detections
}

export function detectXxeParameterEntity(input: string): XXEDetection | null {
    const lower = input.toLowerCase()
    const hasDoctype = lower.includes('<!doctype')
    const hasParameterEntityDecl = /<!entity\s+%\s+\w+\s+(system|public)\s+["'][^"']+["']/i.test(input)
    const hasParameterEntityRef = /%\w+;/.test(input)

    if (hasDoctype && hasParameterEntityDecl && hasParameterEntityRef) {
        return {
            type: 'parameter_entity',
            detail: 'XXE parameter entity injection in DOCTYPE with external SYSTEM/PUBLIC source and %name; reference',
            entityName: 'parameter',
            confidence: 0.94,
        }
    }

    return null
}

export function detectXxeSchemaBasedInjection(input: string): XXEDetection | null {
    const hasXsiNamespace = /xmlns:xsi\s*=\s*["']http:\/\/www\.w3\.org\/2001\/xmlschema-instance["']/i.test(input)
    const hasExternalSchemaLocation = /\bxsi:schemaLocation\s*=\s*["'][^"']*https?:\/\/[^"']+["']/i.test(input)
    const hasExternalImportOrInclude = /<xs:(import|include)\b[^>]*\b(schemaLocation|namespace)\s*=\s*["']https?:\/\/[^"']+["']/i.test(input)

    if ((hasXsiNamespace && hasExternalSchemaLocation) || hasExternalImportOrInclude) {
        return {
            type: 'external_entity',
            detail: 'Schema-based XXE via external xsi:schemaLocation or xs:import/xs:include',
            entityName: 'schema',
            confidence: 0.90,
        }
    }

    return null
}

export function detectXxeXinclude(input: string): XXEDetection | null {
    const hasXincludeNamespace = /xmlns:xi\s*=\s*["']http:\/\/www\.w3\.org\/2001\/xinclude["']/i.test(input)
    const hasXiInclude = /<xi:include\b[^>]*\bhref\s*=\s*["'](?:file:\/\/\/|https?:\/\/)[^"']+["'][^>]*\/?>/i.test(input)

    if (hasXincludeNamespace && hasXiInclude) {
        return {
            type: 'external_entity',
            detail: 'XInclude XXE via xi:include href to local file or external URL',
            entityName: 'xinclude',
            confidence: 0.93,
        }
    }

    return null
}


// ── Public API ───────────────────────────────────────────────────

export function detectXXE(input: string): XXEDetection[] {
    const detections: XXEDetection[] = []

    // Quick bail
    if (input.length < 10) return detections
    const lower = input.toLowerCase()
    if (!lower.includes('<!') && !lower.includes('&') && !lower.includes('entity') &&
        !lower.includes('xi:include') && !lower.includes('xsi:schemalocation') &&
        !lower.includes('xs:import') && !lower.includes('xs:include')) {
        return detections
    }

    // Multi-layer decode
    let decoded = input
    try {
        let prev = ''
        for (let i = 0; i < 3 && decoded !== prev; i++) {
            prev = decoded
            try { decoded = decodeURIComponent(decoded) } catch { break }
        }
    } catch { /* use original */ }

    try {
        const declarations = parseEntityDeclarations(decoded)
        const refs = findEntityReferences(decoded)

        detections.push(...detectExternalEntity(declarations, refs))
        detections.push(...detectParameterEntity(declarations))
        detections.push(...detectBillionLaughs(declarations))

        const parameterEntityAdvanced = detectXxeParameterEntity(decoded)
        if (parameterEntityAdvanced) detections.push(parameterEntityAdvanced)

        const schemaBased = detectXxeSchemaBasedInjection(decoded)
        if (schemaBased) detections.push(schemaBased)

        const xinclude = detectXxeXinclude(decoded)
        if (xinclude) detections.push(xinclude)

        // Fallback: raw pattern detection if parsing found nothing
        if (detections.length === 0) {
            detections.push(...detectEntityExpansionFromRaw(decoded))
        }
    } catch { /* never crash */ }

    return detections
}

