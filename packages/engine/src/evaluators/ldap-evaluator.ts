/**
 * LDAP Injection Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for LDAP injection is:
 *   ∃ filter ∈ parse(input, LDAP_FILTER_GRAMMAR) :
 *     filter.operator ∈ {|, &, !}
 *     ∧ filter.attribute ∈ {uid, cn, objectClass, userPassword, ...}
 *     ∧ filter BREAKS intended filter structure
 *     → attacker modifies LDAP query to bypass auth or enumerate
 *
 * Unlike regex matching )(, this evaluator:
 *   1. Parses LDAP filter syntax (RFC 4515)
 *   2. Identifies filter injection points
 *   3. Detects wildcard abuse for enumeration
 *   4. Recognizes authentication bypass patterns
 *
 * Covers:
 *   - ldap_filter_injection: LDAP filter structure modification
 */


// ── Result Type ──────────────────────────────────────────────────

export interface LDAPDetection {
    type: 'filter_break' | 'wildcard_enum' | 'auth_bypass' | 'operator_injection'
    detail: string
    attribute: string | null
    confidence: number
}


// ── LDAP Filter Token Types ──────────────────────────────────────

type LDAPTokenType = 'LPAREN' | 'RPAREN' | 'OPERATOR' | 'ATTRIBUTE' | 'VALUE' | 'WILDCARD'

interface LDAPToken {
    type: LDAPTokenType
    value: string
    position: number
}


// ── LDAP Security Attributes ─────────────────────────────────────

const SECURITY_ATTRIBUTES = new Set([
    'uid', 'cn', 'sn', 'dn', 'mail', 'givenname',
    'objectclass', 'userpassword', 'unicodepwd',
    'samaccountname', 'memberof', 'admincount',
    'serviceprincipalname', 'userprincipalname',
    'distinguishedname', 'description', 'department',
    'manager', 'directreports', 'lastlogon',
])


// ── LDAP Tokenizer ───────────────────────────────────────────────

function tokenizeLDAP(input: string): LDAPToken[] {
    const tokens: LDAPToken[] = []
    let i = 0

    while (i < input.length) {
        if (input[i] === '(') {
            tokens.push({ type: 'LPAREN', value: '(', position: i })
            i++
        } else if (input[i] === ')') {
            tokens.push({ type: 'RPAREN', value: ')', position: i })
            i++
        } else if (input[i] === '|' || input[i] === '&' || input[i] === '!') {
            tokens.push({ type: 'OPERATOR', value: input[i], position: i })
            i++
        } else if (input[i] === '*') {
            tokens.push({ type: 'WILDCARD', value: '*', position: i })
            i++
        } else if (/[a-zA-Z_]/.test(input[i])) {
            // Attribute name
            let name = ''
            const start = i
            while (i < input.length && /[a-zA-Z0-9_-]/.test(input[i])) {
                name += input[i]
                i++
            }
            // Check if followed by = (it's an attribute=value)
            if (i < input.length && input[i] === '=') {
                tokens.push({ type: 'ATTRIBUTE', value: name, position: start })
                i++ // skip =
                // Read value
                let val = ''
                const valStart = i
                while (i < input.length && input[i] !== ')' && input[i] !== '(') {
                    val += input[i]
                    i++
                }
                if (val === '*') {
                    tokens.push({ type: 'WILDCARD', value: '*', position: valStart })
                } else {
                    tokens.push({ type: 'VALUE', value: val, position: valStart })
                }
            } else {
                tokens.push({ type: 'VALUE', value: name, position: start })
            }
        } else if (input[i] === '=') {
            i++ // skip standalone =
        } else {
            i++ // skip whitespace and other chars
        }
    }

    return tokens
}


// ── Detection Functions ──────────────────────────────────────────

function detectFilterBreak(tokens: LDAPToken[]): LDAPDetection[] {
    const detections: LDAPDetection[] = []

    // Filter injection: )( pattern — closes existing filter and opens new one
    for (let i = 0; i < tokens.length - 1; i++) {
        if (tokens[i].type === 'RPAREN' && tokens[i + 1].type === 'LPAREN') {
            // Check what attribute follows
            let attr: string | null = null
            for (let j = i + 2; j < tokens.length; j++) {
                if (tokens[j].type === 'ATTRIBUTE') {
                    attr = tokens[j].value
                    break
                }
                if (tokens[j].type !== 'OPERATOR') break
            }

            const isSecurity = attr ? SECURITY_ATTRIBUTES.has(attr.toLowerCase()) : false
            detections.push({
                type: 'filter_break',
                detail: `Filter injection via )( — modifies query structure${attr ? ` targeting "${attr}"` : ''}`,
                attribute: attr,
                confidence: isSecurity ? 0.94 : 0.88,
            })
        }
    }

    return detections
}

function detectWildcardEnum(tokens: LDAPToken[]): LDAPDetection[] {
    const detections: LDAPDetection[] = []

    // Wildcard enumeration: attribute=*
    for (let i = 0; i < tokens.length; i++) {
        if (tokens[i].type === 'ATTRIBUTE' &&
            i + 1 < tokens.length &&
            tokens[i + 1].type === 'WILDCARD') {

            const attr = tokens[i].value
            const isSecurity = SECURITY_ATTRIBUTES.has(attr.toLowerCase())

            if (isSecurity) {
                detections.push({
                    type: 'wildcard_enum',
                    detail: `Wildcard enumeration on security attribute: ${attr}=*`,
                    attribute: attr,
                    confidence: 0.88,
                })
            }
        }
    }

    return detections
}

function detectAuthBypass(tokens: LDAPToken[]): LDAPDetection[] {
    const detections: LDAPDetection[] = []

    // Auth bypass: )(uid=*) or similar — always-true condition after filter break
    const hasFilterBreak = tokens.some((t, i) =>
        t.type === 'RPAREN' && i + 1 < tokens.length && tokens[i + 1].type === 'LPAREN'
    )

    if (hasFilterBreak) {
        // Check for always-true conditions
        for (let i = 0; i < tokens.length; i++) {
            if (tokens[i].type === 'ATTRIBUTE' &&
                i + 1 < tokens.length &&
                tokens[i + 1].type === 'WILDCARD') {

                const attr = tokens[i].value.toLowerCase()
                if (attr === 'uid' || attr === 'cn' || attr === 'objectclass') {
                    detections.push({
                        type: 'auth_bypass',
                        detail: `LDAP auth bypass: filter break + always-true ${tokens[i].value}=*`,
                        attribute: tokens[i].value,
                        confidence: 0.94,
                    })
                }
            }
        }
    }

    return detections
}

function detectOperatorInjection(tokens: LDAPToken[]): LDAPDetection[] {
    const detections: LDAPDetection[] = []

    // Operator injection: injecting | or & to modify logic
    const operators = tokens.filter(t => t.type === 'OPERATOR')
    const parens = tokens.filter(t => t.type === 'LPAREN' || t.type === 'RPAREN')

    // Multiple operators + filter break structure = injection
    if (operators.length > 0 && parens.length >= 3) {
        for (const op of operators) {
            detections.push({
                type: 'operator_injection',
                detail: `LDAP operator injection: ${op.value === '|' ? 'OR' : op.value === '&' ? 'AND' : 'NOT'} operator in filter`,
                attribute: null,
                confidence: 0.85,
            })
        }
    }

    return detections
}

export function detectLdapBlindInjection(input: string): LDAPDetection | null {
    const lower = input.toLowerCase()
    const attrProbePattern = /\(([a-zA-Z][a-zA-Z0-9_-]{0,31})=([a-z0-9])\*\)/gi
    const repeatedWildcardPattern = /\([a-zA-Z][a-zA-Z0-9_-]{0,31}=[^)]*\*[^)]*\*\)/i
    const attrToChars = new Map<string, string[]>()
    let match: RegExpExecArray | null

    while ((match = attrProbePattern.exec(lower)) !== null) {
        const attr = match[1]
        const probeChar = match[2]
        const chars = attrToChars.get(attr) || []
        chars.push(probeChar)
        attrToChars.set(attr, chars)
    }

    let hasSequentialProbes = false
    for (const chars of attrToChars.values()) {
        if (chars.length < 2) continue
        for (let i = 0; i < chars.length - 1; i++) {
            const current = chars[i].charCodeAt(0)
            const next = chars[i + 1].charCodeAt(0)
            if (next === current + 1) {
                hasSequentialProbes = true
                break
            }
        }
        if (hasSequentialProbes) break
    }

    const hasRepeatedWildcard = repeatedWildcardPattern.test(lower)
    const hasPasswordProbe = /\((userpassword|unicodepwd)=\*\)/i.test(lower)

    if ((hasSequentialProbes && hasPasswordProbe) || hasRepeatedWildcard) {
        return {
            type: 'wildcard_enum',
            detail: 'Blind LDAP injection via attribute enumeration probes and wildcard abuse',
            attribute: null,
            confidence: 0.91,
        }
    }

    return null
}

export function detectLdapSpecialCharBypass(input: string): LDAPDetection | null {
    const hasEncodedSpecialChar = /\\(?:00|28|29|2a|5c|u[0-9a-f]{4})/i.test(input)
    const hasFilterContext = input.includes('(') || input.includes(')') || input.includes('=')

    if (hasEncodedSpecialChar && hasFilterContext) {
        return {
            type: 'operator_injection',
            detail: 'LDAP special-character bypass using encoded metacharacters (null/paren/unicode escapes)',
            attribute: null,
            confidence: 0.90,
        }
    }

    return null
}

export function detectLdapDnInjection(input: string): LDAPDetection | null {
    const dnInjectionPattern = /=[^,\\)]*,\s*(cn|dc|ou)\s*=/i
    const hasDnChain = /(cn|dc|ou)\s*=[^,)]/i.test(input)

    if (dnInjectionPattern.test(input) && hasDnChain) {
        return {
            type: 'filter_break',
            detail: 'LDAP DN injection with unescaped comma before DN component (cn/dc/ou)',
            attribute: 'dn',
            confidence: 0.89,
        }
    }

    return null
}


// ── Public API ───────────────────────────────────────────────────

export function detectLDAPInjection(input: string): LDAPDetection[] {
    const detections: LDAPDetection[] = []

    if (input.length < 3) return detections

    // Quick bail: must contain LDAP-like characters
    if (!input.includes('(') && !input.includes(')') && !input.includes('=')) {
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
        const tokens = tokenizeLDAP(decoded)
        if (tokens.length < 2) return detections

        detections.push(...detectFilterBreak(tokens))
        detections.push(...detectWildcardEnum(tokens))
        detections.push(...detectAuthBypass(tokens))
        detections.push(...detectOperatorInjection(tokens))

        const blind = detectLdapBlindInjection(decoded)
        if (blind) detections.push(blind)

        const specialCharBypass = detectLdapSpecialCharBypass(decoded)
        if (specialCharBypass) detections.push(specialCharBypass)

        const dnInjection = detectLdapDnInjection(decoded)
        if (dnInjection) detections.push(dnInjection)
    } catch { /* never crash */ }

    // Dedup by type
    const seen = new Set<string>()
    return detections.filter(d => {
        const key = `${d.type}:${d.attribute || ''}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
    })
}

