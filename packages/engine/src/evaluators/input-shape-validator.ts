/**
 * Input Shape Validator — Negative-Space Detection
 *
 * Traditional detection: "Does this look like an attack?"
 * Shape validation: "Does this look like what it SHOULD be?"
 *
 * This inverts the detection problem. Instead of trying to enumerate
 * every possible attack, we define what LEGITIMATE input looks like
 * for common field types. Any deviation from the expected shape is
 * suspicious — even if we can't name the specific attack class.
 *
 * This catches zero-day attacks: the input violates the SHAPE
 * of legitimate data, even if we've never seen this exploit before.
 *
 * Field types and their shapes:
 *   username:    alphanumeric + _.- , length 1-128
 *   email:       RFC 5321 basic shape
 *   url:         scheme + authority + path
 *   integer:     digits only (optional sign)
 *   uuid:        8-4-4-4-12 hex format
 *   phone:       digits + optional +()-. spacing
 *   date:        ISO 8601 or common date formats
 *   search:      natural language (alpha-heavy, low metachar)
 *   filename:    alphanumeric + ._- (no path separators)
 *   json_value:  valid JSON primitive (string, number, bool, null)
 *   freetext:    minimal constraints (but still flags extremes)
 *
 * The validator returns:
 *   - Whether the input matches the expected shape
 *   - A deviation score (0 = perfect match, 1 = completely wrong)
 *   - Specific violations (which constraints were broken)
 *   - Suggested confidence boost for any detection that co-occurs
 *
 * This is NOT a detection mechanism — it's a CONTEXTUAL SIGNAL
 * that amplifies or attenuates detection confidence.
 */


// ── Field Shape Definitions ──────────────────────────────────────

export type FieldType =
    | 'username'
    | 'email'
    | 'url'
    | 'integer'
    | 'float'
    | 'uuid'
    | 'phone'
    | 'date'
    | 'search'
    | 'filename'
    | 'json_value'
    | 'freetext'
    | 'slug'
    | 'hex'
    | 'base64'
    | 'ipv4'

export interface ShapeViolation {
    /** Which constraint was violated */
    constraint: string
    /** What was expected */
    expected: string
    /** What was found */
    found: string
    /** How severe is this violation (0-1) */
    severity: number
}

export interface ShapeValidation {
    /** Does the input match the expected shape? */
    matches: boolean
    /** Overall deviation score (0 = perfect, 1 = completely wrong) */
    deviation: number
    /** Specific violations found */
    violations: ShapeViolation[]
    /** Confidence boost to apply to co-occurring detections */
    confidenceBoost: number
    /** Human-readable summary */
    detail: string
}


// ── Shape Validators ─────────────────────────────────────────────

const SHAPE_VALIDATORS: Record<FieldType, (input: string) => ShapeViolation[]> = {
    username: (input) => {
        const violations: ShapeViolation[] = []
        if (input.length > 128) {
            violations.push({ constraint: 'length', expected: '≤128', found: `${input.length}`, severity: 0.3 })
        }
        if (input.length < 1) {
            violations.push({ constraint: 'length', expected: '≥1', found: '0', severity: 0.2 })
        }
        const illegal = input.replace(/[a-zA-Z0-9_.@-]/g, '')
        if (illegal.length > 0) {
            const ratio = illegal.length / input.length
            violations.push({
                constraint: 'charset',
                expected: 'alphanumeric + _.@-',
                found: `illegal chars: ${JSON.stringify(illegal.slice(0, 20))}`,
                severity: Math.min(1, ratio * 2),
            })
        }
        if (/\s/.test(input)) {
            violations.push({ constraint: 'whitespace', expected: 'none', found: 'contains whitespace', severity: 0.5 })
        }
        return violations
    },

    email: (input) => {
        const violations: ShapeViolation[] = []
        // Basic RFC 5321 shape: local@domain
        if (!input.includes('@')) {
            violations.push({ constraint: 'format', expected: 'local@domain', found: 'no @ sign', severity: 0.8 })
            return violations
        }
        const atIdx = input.lastIndexOf('@')
        const local = input.slice(0, atIdx)
        const domain = input.slice(atIdx + 1)
        if (!local || local.length > 64) {
            violations.push({ constraint: 'local_part', expected: '1-64 chars', found: `${local?.length ?? 0}`, severity: 0.4 })
        }
        if (!domain || !domain.includes('.') || domain.length < 4) {
            violations.push({ constraint: 'domain', expected: 'valid domain', found: domain ?? '', severity: 0.5 })
        }
        const illegalLocal = local?.replace(/[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]/g, '') ?? ''
        if (illegalLocal.length > 0) {
            violations.push({
                constraint: 'local_charset',
                expected: 'RFC 5321 chars',
                found: `illegal: ${JSON.stringify(illegalLocal.slice(0, 10))}`,
                severity: 0.6,
            })
        }
        // Domain must be alphanumeric + hyphens + dots only
        const illegalDomain = domain?.replace(/[a-zA-Z0-9.-]/g, '') ?? ''
        if (illegalDomain.length > 0) {
            violations.push({
                constraint: 'domain_charset',
                expected: 'alphanumeric + .- only',
                found: `illegal: ${JSON.stringify(illegalDomain.slice(0, 10))}`,
                severity: 0.7,
            })
        }
        return violations
    },

    url: (input) => {
        const violations: ShapeViolation[] = []
        if (!/^https?:\/\//i.test(input) && !/^\//.test(input)) {
            violations.push({ constraint: 'scheme', expected: 'http(s):// or /', found: input.slice(0, 20), severity: 0.3 })
        }
        // Check for control characters
        if (/[\x00-\x1f\x7f]/.test(input)) {
            violations.push({ constraint: 'control_chars', expected: 'none', found: 'contains control chars', severity: 0.8 })
        }
        // Check for shell/SQL metacharacters that don't belong in URLs
        const suspicious = input.replace(/[a-zA-Z0-9/:._~?&=#%+@!$'()*,;-]/g, '')
        if (suspicious.length > 0) {
            violations.push({
                constraint: 'url_charset',
                expected: 'URL-safe characters',
                found: `suspicious: ${JSON.stringify(suspicious.slice(0, 20))}`,
                severity: Math.min(1, (suspicious.length / input.length) * 3),
            })
        }
        return violations
    },

    integer: (input) => {
        const violations: ShapeViolation[] = []
        if (!/^-?\d+$/.test(input.trim())) {
            violations.push({ constraint: 'format', expected: 'integer', found: input.slice(0, 20), severity: 0.9 })
        }
        return violations
    },

    float: (input) => {
        const violations: ShapeViolation[] = []
        if (!/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(input.trim())) {
            violations.push({ constraint: 'format', expected: 'float', found: input.slice(0, 20), severity: 0.9 })
        }
        return violations
    },

    uuid: (input) => {
        const violations: ShapeViolation[] = []
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input.trim())) {
            violations.push({ constraint: 'format', expected: 'UUID v4', found: input.slice(0, 40), severity: 0.9 })
        }
        return violations
    },

    phone: (input) => {
        const violations: ShapeViolation[] = []
        const digits = input.replace(/[^0-9]/g, '')
        if (digits.length < 7 || digits.length > 15) {
            violations.push({ constraint: 'digit_count', expected: '7-15 digits', found: `${digits.length}`, severity: 0.5 })
        }
        const illegal = input.replace(/[0-9+() .-]/g, '')
        if (illegal.length > 0) {
            violations.push({
                constraint: 'charset',
                expected: 'digits + +()-. space',
                found: `illegal: ${JSON.stringify(illegal.slice(0, 10))}`,
                severity: 0.7,
            })
        }
        return violations
    },

    date: (input) => {
        const violations: ShapeViolation[] = []
        // Accept ISO 8601, common formats
        const datePatterns = [
            /^\d{4}-\d{2}-\d{2}$/,                    // 2024-01-15
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/,         // ISO 8601 datetime
            /^\d{2}\/\d{2}\/\d{4}$/,                   // MM/DD/YYYY
            /^\d{2}-\d{2}-\d{4}$/,                     // DD-MM-YYYY
            /^\w{3}\s+\d{1,2},?\s+\d{4}$/,             // Jan 15, 2024
        ]
        if (!datePatterns.some(p => p.test(input.trim()))) {
            violations.push({ constraint: 'format', expected: 'date format', found: input.slice(0, 30), severity: 0.8 })
        }
        return violations
    },

    search: (input) => {
        const violations: ShapeViolation[] = []
        // Search queries should be primarily alphabetic/numeric
        const alpha = (input.match(/[a-zA-Z]/g) || []).length
        const ratio = input.length > 0 ? alpha / input.length : 0
        if (ratio < 0.4 && input.length > 5) {
            violations.push({
                constraint: 'alpha_ratio',
                expected: '≥40% alphabetic',
                found: `${(ratio * 100).toFixed(0)}%`,
                severity: Math.min(1, (0.4 - ratio) * 3),
            })
        }
        // Extremely long search queries are suspicious
        if (input.length > 500) {
            violations.push({ constraint: 'length', expected: '≤500', found: `${input.length}`, severity: 0.4 })
        }
        // High metacharacter ratio in search is suspicious
        const meta = (input.match(/[<>'"`;|&${}()[\]\\]/g) || []).length
        const metaRatio = input.length > 0 ? meta / input.length : 0
        if (metaRatio > 0.10 && input.length > 5) {
            violations.push({
                constraint: 'metachar_ratio',
                expected: '≤10% metacharacters',
                found: `${(metaRatio * 100).toFixed(0)}%`,
                severity: Math.min(1, metaRatio * 5),
            })
        }
        return violations
    },

    filename: (input) => {
        const violations: ShapeViolation[] = []
        // Filenames should not contain path separators
        if (input.includes('/') || input.includes('\\')) {
            violations.push({ constraint: 'path_separator', expected: 'none', found: 'contains / or \\', severity: 0.9 })
        }
        if (input.includes('\0')) {
            violations.push({ constraint: 'null_byte', expected: 'none', found: 'contains null byte', severity: 1.0 })
        }
        if (input.includes('..')) {
            violations.push({ constraint: 'dotdot', expected: 'no ..', found: 'contains ..', severity: 0.9 })
        }
        if (input.length > 255) {
            violations.push({ constraint: 'length', expected: '≤255', found: `${input.length}`, severity: 0.3 })
        }
        return violations
    },

    json_value: (input) => {
        const violations: ShapeViolation[] = []
        try {
            JSON.parse(input)
        } catch {
            violations.push({ constraint: 'valid_json', expected: 'parseable JSON', found: 'invalid', severity: 0.7 })
        }
        return violations
    },

    freetext: (input) => {
        const violations: ShapeViolation[] = []
        // Even freetext has limits
        if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(input)) {
            violations.push({ constraint: 'control_chars', expected: 'no control chars', found: 'contains control chars', severity: 0.6 })
        }
        // Extremely high metacharacter density is suspicious even in freetext
        const meta = (input.match(/[<>'"`;|&${}()[\]\\]/g) || []).length
        const metaRatio = input.length > 0 ? meta / input.length : 0
        if (metaRatio > 0.25 && input.length > 10) {
            violations.push({
                constraint: 'metachar_density',
                expected: '≤25% metacharacters',
                found: `${(metaRatio * 100).toFixed(0)}%`,
                severity: Math.min(1, (metaRatio - 0.25) * 4),
            })
        }
        return violations
    },

    slug: (input) => {
        const violations: ShapeViolation[] = []
        if (!/^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*$/.test(input)) {
            violations.push({ constraint: 'format', expected: 'url-slug', found: input.slice(0, 30), severity: 0.7 })
        }
        if (input.length > 200) {
            violations.push({ constraint: 'length', expected: '≤200', found: `${input.length}`, severity: 0.3 })
        }
        return violations
    },

    hex: (input) => {
        const violations: ShapeViolation[] = []
        if (!/^(?:0x)?[0-9a-fA-F]+$/.test(input.trim())) {
            violations.push({ constraint: 'format', expected: 'hex string', found: input.slice(0, 20), severity: 0.8 })
        }
        return violations
    },

    base64: (input) => {
        const violations: ShapeViolation[] = []
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input.trim())) {
            violations.push({ constraint: 'format', expected: 'base64', found: input.slice(0, 20), severity: 0.8 })
        }
        return violations
    },

    ipv4: (input) => {
        const violations: ShapeViolation[] = []
        const parts = input.trim().split('.')
        if (parts.length !== 4 || !parts.every(p => /^\d{1,3}$/.test(p) && +p >= 0 && +p <= 255)) {
            violations.push({ constraint: 'format', expected: 'IPv4 address', found: input.slice(0, 20), severity: 0.9 })
        }
        return violations
    },
}


// ── Public API ───────────────────────────────────────────────────

/**
 * Validate input against an expected field shape.
 *
 * @param input The raw input to validate
 * @param expectedType What type of data this field should contain
 * @returns Shape validation with deviation score and violations
 */
export function validateShape(input: string, expectedType: FieldType): ShapeValidation {
    const validator = SHAPE_VALIDATORS[expectedType]
    if (!validator) {
        return {
            matches: true,
            deviation: 0,
            violations: [],
            confidenceBoost: 0,
            detail: `Unknown field type: ${expectedType}`,
        }
    }

    const violations = validator(input)

    if (violations.length === 0) {
        return {
            matches: true,
            deviation: 0,
            violations: [],
            confidenceBoost: 0,
            detail: `Input matches expected ${expectedType} shape`,
        }
    }

    // Deviation = weighted average of violation severities
    const totalSeverity = violations.reduce((sum, v) => sum + v.severity, 0)
    const deviation = Math.min(1, totalSeverity / violations.length)

    // Confidence boost scales with deviation
    // High deviation + detection = very likely an attack
    const confidenceBoost = deviation >= 0.7
        ? 0.10
        : deviation >= 0.4
            ? 0.05
            : 0.02

    const violationSummary = violations
        .map(v => `${v.constraint}: expected ${v.expected}, got ${v.found}`)
        .join('; ')

    return {
        matches: false,
        deviation,
        violations,
        confidenceBoost,
        detail: `Input violates ${expectedType} shape: ${violationSummary}`,
    }
}

/**
 * Auto-detect the most likely field type from a parameter name.
 * Returns null if the name doesn't clearly indicate a type.
 */
export function inferFieldType(paramName: string): FieldType | null {
    const lower = paramName.toLowerCase()

    if (/(?:^id$|_id$|Id$)/.test(paramName)) {
        // Could be UUID or integer
        return 'uuid'  // conservative — stricter shape
    }
    if (/(?:email|mail)/.test(lower)) return 'email'
    if (/(?:username|user_name|login|handle|screen_name)/.test(lower)) return 'username'
    if (/(?:phone|tel|mobile|fax)/.test(lower)) return 'phone'
    if (/(?:^url$|website|homepage|link|redirect|callback|return_url|next|goto)/.test(lower)) return 'url'
    if (/(?:^q$|query|search|keyword|term)/.test(lower)) return 'search'
    if (/(?:date|time|created|updated|expires|birthday|dob)/.test(lower)) return 'date'
    if (/(?:file|filename|attachment|upload)/.test(lower)) return 'filename'
    if (/(?:^page$|^limit$|^offset$|^count$|^size$|^port$|^age$|^amount$|^quantity$|^num)/.test(lower)) return 'integer'
    if (/(?:^price$|^rate$|^score$|^weight$|^lat$|^lng$|^longitude$|^latitude$)/.test(lower)) return 'float'
    if (/(?:slug|permalink)/.test(lower)) return 'slug'
    if (/(?:^ip$|ip_address|remote_addr)/.test(lower)) return 'ipv4'

    return null
}

/**
 * Validate input against its auto-inferred shape, if determinable.
 * Returns null if the parameter name doesn't indicate a clear field type.
 */
export function autoValidateShape(input: string, paramName: string): ShapeValidation | null {
    const fieldType = inferFieldType(paramName)
    if (!fieldType) return null
    return validateShape(input, fieldType)
}
