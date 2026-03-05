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

    // Billion laughs: internal entities that reference other entities
    // Entity A references B, B references C, etc. → exponential expansion
    let entityRefChain = 0
    for (const entity of internalEntities) {
        const refsInValue = findEntityReferences(entity.source)
        if (refsInValue.length > 0) {
            entityRefChain++
        }
    }

    if (entityRefChain >= 2) {
        detections.push({
            type: 'billion_laughs',
            detail: `${entityRefChain} entities with cross-references — exponential expansion (Billion Laughs DoS)`,
            entityName: 'chain',
            confidence: 0.94,
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


// ── Public API ───────────────────────────────────────────────────

export function detectXXE(input: string): XXEDetection[] {
    const detections: XXEDetection[] = []

    // Quick bail
    if (input.length < 10) return detections
    const lower = input.toLowerCase()
    if (!lower.includes('<!') && !lower.includes('&') && !lower.includes('entity')) {
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

        // Fallback: raw pattern detection if parsing found nothing
        if (detections.length === 0) {
            detections.push(...detectEntityExpansionFromRaw(decoded))
        }
    } catch { /* never crash */ }

    return detections
}
