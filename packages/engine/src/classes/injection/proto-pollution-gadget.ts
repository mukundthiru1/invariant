/**
 * proto_pollution_gadget — Prototype pollution with gadget chain awareness
 *
 * Research: July 2024 arxiv paper (12 exploitable RCE cases, 5 unique gadgets),
 * Next.js CVE-2025-55182, mongodb 6.6.2 gadget, Node.js stdlib gadgets.
 *
 * INVARIANT PROPERTY:
 *   ∃ key_path ∈ parse(input, PROPERTY_ACCESS_GRAMMAR) :
 *     key_path REACHES Object.prototype
 *     ∧ target_property(key_path) ∈ KNOWN_GADGET_PROPERTIES
 *     → gadget_chain REACHABLE(target_property)
 *     → severity(gadget_class(target_property))
 *
 * Why gadget awareness matters:
 *   Basic proto pollution detection catches `__proto__[x]=y`.
 *   But the SEVERITY depends entirely on WHAT x IS:
 *     - __proto__[execArgv]=... → RCE via child_process.fork()
 *     - __proto__[shell]=...   → RCE via child_process.exec()
 *     - __proto__[isAdmin]=... → AuthZ bypass
 *     - __proto__[status]=...  → DoS/info leak
 *     - __proto__[random]=...  → Unknown, medium risk
 *
 * This class detects the COMBINATION of prototype access + known gadget,
 * not just the prototype access alone (which is proto_pollution's job).
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'


// ── Gadget Database ──────────────────────────────────────────────
//
// Organized by severity class. Each gadget maps a polluted property
// to its exploitation consequence.
//
// Sources:
//   - arxiv July 2024: 5 unique gadgets across 4 popular applications
//   - CVE-2025-55182: Next.js React Server Actions PP → RCE
//   - mongodb NPM 6.6.2: Query handling PP → RCE
//   - Node.js stdlib: dns.lookup(), http.request() options pollution

interface GadgetEntry {
    readonly property: string
    readonly severity: 'critical' | 'high' | 'medium'
    readonly consequence: string
    readonly source: string
    readonly cve?: string
}

/**
 * Known gadget properties organized by impact class.
 *
 * Critical: Remote Code Execution
 * High: AuthZ bypass, data exfiltration
 * Medium: DoS, information disclosure
 */
const GADGET_DATABASE: readonly GadgetEntry[] = [
    // ── Critical: RCE Gadgets ──
    { property: 'execArgv', severity: 'critical', consequence: 'RCE via child_process.fork() --eval injection', source: 'Node.js stdlib' },
    { property: 'shell', severity: 'critical', consequence: 'RCE via child_process.exec() shell override', source: 'Node.js stdlib' },
    { property: 'env', severity: 'critical', consequence: 'RCE via environment variable injection (NODE_OPTIONS, LD_PRELOAD)', source: 'Node.js stdlib' },
    { property: 'NODE_OPTIONS', severity: 'critical', consequence: 'RCE via Node.js --require injection', source: 'Node.js stdlib' },
    { property: 'argv0', severity: 'critical', consequence: 'RCE via process spawn argv[0] override', source: 'Node.js stdlib' },
    { property: 'mainModule', severity: 'critical', consequence: 'RCE via module loading redirection', source: 'Node.js stdlib' },
    { property: 'exports', severity: 'critical', consequence: 'RCE via module export poisoning', source: 'Node.js module system' },
    { property: 'require', severity: 'critical', consequence: 'RCE via require() function override', source: 'Node.js module system' },
    { property: 'file', severity: 'critical', consequence: 'RCE via child_process spawn file override', source: 'Node.js stdlib' },
    { property: 'args', severity: 'critical', consequence: 'RCE via child_process spawn args injection', source: 'Node.js stdlib' },
    { property: 'input', severity: 'critical', consequence: 'RCE via child_process execSync stdin injection', source: 'Node.js stdlib' },
    { property: 'stdio', severity: 'critical', consequence: 'RCE/info leak via process I/O redirection', source: 'Node.js stdlib' },

    // ── Critical: Framework-Specific RCE ──
    { property: 'outputFunctionName', severity: 'critical', consequence: 'RCE via EJS template engine function name injection', source: 'EJS', cve: 'CVE-2022-29078' },
    { property: 'client', severity: 'critical', consequence: 'RCE via EJS template compilation', source: 'EJS' },
    { property: 'escapeFunction', severity: 'critical', consequence: 'RCE via Pug template engine escape override', source: 'Pug' },
    { property: 'compileDebug', severity: 'critical', consequence: 'Information disclosure + code injection via Pug debug mode', source: 'Pug' },
    { property: 'allowedProtoMethods', severity: 'critical', consequence: 'RCE via Handlebars prototype method access', source: 'Handlebars', cve: 'CVE-2019-20920' },

    // ── Critical: CVE-Linked ──
    { property: 'serverActions', severity: 'critical', consequence: 'RCE via Next.js React Server Actions prototype pollution', source: 'Next.js', cve: 'CVE-2025-55182' },
    { property: '__NEXT_INIT_QUERY', severity: 'critical', consequence: 'RCE via Next.js initialization query override', source: 'Next.js' },

    // ── High: AuthZ Bypass ──
    { property: 'isAdmin', severity: 'high', consequence: 'Authorization bypass — admin role injection', source: 'Generic' },
    { property: 'admin', severity: 'high', consequence: 'Authorization bypass — admin flag injection', source: 'Generic' },
    { property: 'role', severity: 'high', consequence: 'Authorization bypass — role escalation', source: 'Generic' },
    { property: 'isAuthenticated', severity: 'high', consequence: 'Authentication bypass — auth state override', source: 'Generic' },
    { property: 'verified', severity: 'high', consequence: 'Verification bypass — account verification override', source: 'Generic' },
    { property: 'permissions', severity: 'high', consequence: 'Authorization bypass — permission set override', source: 'Generic' },
    { property: 'scope', severity: 'high', consequence: 'Authorization bypass — OAuth scope escalation', source: 'OAuth' },
    { property: 'allowAll', severity: 'high', consequence: 'Authorization bypass — wildcard access', source: 'Generic' },

    // ── High: Data Exfiltration ──
    { property: 'hostname', severity: 'high', consequence: 'SSRF via DNS resolution override in http.request()', source: 'Node.js stdlib' },
    { property: 'host', severity: 'high', consequence: 'SSRF via host override in http.request()', source: 'Node.js stdlib' },
    { property: 'port', severity: 'high', consequence: 'Port scanning via port override in http.request()', source: 'Node.js stdlib' },
    { property: 'path', severity: 'high', consequence: 'Path traversal via path override in http.request()', source: 'Node.js stdlib' },
    { property: 'href', severity: 'high', consequence: 'Open redirect via URL override', source: 'Node.js URL' },
    { property: 'protocol', severity: 'high', consequence: 'Protocol downgrade via protocol override', source: 'Node.js URL' },

    // ── Medium: DoS / Info Leak ──
    { property: 'status', severity: 'medium', consequence: 'Response manipulation — status code override', source: 'Express' },
    { property: 'statusCode', severity: 'medium', consequence: 'Response manipulation — status code override', source: 'Node.js HTTP' },
    { property: 'headers', severity: 'medium', consequence: 'Header injection via response headers override', source: 'Node.js HTTP' },
    { property: 'charset', severity: 'medium', consequence: 'Encoding confusion via charset override', source: 'Generic' },
    { property: 'type', severity: 'medium', consequence: 'Content-type confusion via type override', source: 'Generic' },
    { property: 'length', severity: 'medium', consequence: 'DoS via array/string length override', source: 'JavaScript' },
    { property: 'toString', severity: 'medium', consequence: 'DoS/info leak via toString override (type coercion)', source: 'JavaScript' },
    { property: 'valueOf', severity: 'medium', consequence: 'DoS/info leak via valueOf override (type coercion)', source: 'JavaScript' },
    { property: 'constructor', severity: 'medium', consequence: 'Prototype chain manipulation', source: 'JavaScript' },
    { property: 'hasOwnProperty', severity: 'medium', consequence: 'Property check bypass', source: 'JavaScript' },
]

// Build lookup maps for O(1) access
const GADGET_BY_PROPERTY = new Map<string, GadgetEntry>(
    GADGET_DATABASE.map(g => [g.property.toLowerCase(), g]),
)

const CRITICAL_GADGETS = new Set(
    GADGET_DATABASE.filter(g => g.severity === 'critical').map(g => g.property.toLowerCase()),
)

const HIGH_GADGETS = new Set(
    GADGET_DATABASE.filter(g => g.severity === 'high').map(g => g.property.toLowerCase()),
)


// ── Property Extraction ──────────────────────────────────────────

/**
 * Extract the target property being set through prototype pollution.
 * Handles multiple access patterns:
 *   - __proto__[property]=value
 *   - __proto__.property=value
 *   - constructor[prototype][property]=value
 *   - constructor.prototype.property=value
 *   - {"__proto__":{"property":value}}
 */
function extractTargetProperties(input: string): string[] {
    const properties: string[] = []

    // URL-encoded bracket notation: __proto__[prop]=val
    const bracketPattern = /__proto__\[['"]?([a-zA-Z_$][a-zA-Z0-9_$]*)['"]?\]/gi
    let match
    while ((match = bracketPattern.exec(input)) !== null) {
        properties.push(match[1])
    }

    // Dot notation: __proto__.prop=val
    const dotPattern = /__proto__\.([a-zA-Z_$][a-zA-Z0-9_$]*)/gi
    while ((match = dotPattern.exec(input)) !== null) {
        properties.push(match[1])
    }

    // constructor.prototype.prop or constructor[prototype][prop]
    const ctorDotPattern = /constructor\.prototype\.([a-zA-Z_$][a-zA-Z0-9_$]*)/gi
    while ((match = ctorDotPattern.exec(input)) !== null) {
        properties.push(match[1])
    }

    const ctorBracketPattern = /constructor\s*\[\s*['"]?prototype['"]?\s*\]\s*\[\s*['"]?([a-zA-Z_$][a-zA-Z0-9_$]*)['"]?\s*\]/gi
    while ((match = ctorBracketPattern.exec(input)) !== null) {
        properties.push(match[1])
    }

    // JSON body: {"__proto__":{"prop":value}}
    const jsonPattern = /"__proto__"\s*:\s*\{([^}]+)\}/gi
    while ((match = jsonPattern.exec(input)) !== null) {
        const innerContent = match[1]
        const keyPattern = /"([a-zA-Z_$][a-zA-Z0-9_$]*)"\s*:/g
        let keyMatch
        while ((keyMatch = keyPattern.exec(innerContent)) !== null) {
            properties.push(keyMatch[1])
        }
    }

    return [...new Set(properties)]
}


// ── Module Export ─────────────────────────────────────────────────

export const protoPollutionGadget: InvariantClassModule = {
    id: 'proto_pollution_gadget',
    description: 'Prototype pollution targeting known RCE/authz-bypass gadget properties — severity based on exploitability of the target property',
    category: 'injection',
    severity: 'critical',
    calibration: {
        baseConfidence: 0.90,
        environmentMultipliers: {
            'nodejs': 1.3,
            'express': 1.2,
            'nextjs': 1.3,
            'ejs': 1.3,
            'pug': 1.2,
        },
        minInputLength: 10,
    },

    formalProperty: `∃ key_path ∈ parse(input, PROPERTY_ACCESS_GRAMMAR) :
        key_path REACHES Object.prototype
        ∧ target(key_path) ∈ GADGET_DATABASE
        → consequence(GADGET_DATABASE[target(key_path)])`,

    composableWith: ['proto_pollution', 'cmd_separator', 'cmd_substitution', 'ssrf_internal_reach'],

    mitre: ['T1059.007', 'T1190'],
    cwe: 'CWE-1321',

    knownPayloads: [
        '__proto__[execArgv][]=--eval=process.exit()',
        '__proto__[shell]=/bin/bash',
        '__proto__[env][NODE_OPTIONS]=--require=/tmp/evil.js',
        '{"__proto__":{"execArgv":["--eval","require(\'child_process\').execSync(\'id\')"]}}',
        '__proto__[isAdmin]=true',
        '__proto__[role]=admin',
        'constructor[prototype][outputFunctionName]=x;process.mainModule.require("child_process").execSync("id");x',
        '__proto__[hostname]=attacker.com',
        '__proto__[serverActions]=true',
    ],

    knownBenign: [
        '__proto__[random]=value',
        'constructor function discussion',
        'prototype design pattern article',
        'property access for form field',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // Must first pass proto pollution detection
        if (!/__proto__|constructor\s*\[\s*['"]?prototype['"]?\s*\]|constructor\.prototype/i.test(d)) return false

        // Extract target properties and check against gadget database
        const targets = extractTargetProperties(d)
        return targets.some(t => GADGET_BY_PROPERTY.has(t.toLowerCase()))
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        if (!/__proto__|constructor\s*\[\s*['"]?prototype['"]?\s*\]|constructor\.prototype/i.test(d)) return null

        const targets = extractTargetProperties(d)
        if (targets.length === 0) return null

        const matchedGadgets = targets
            .map(t => GADGET_BY_PROPERTY.get(t.toLowerCase()))
            .filter((g): g is GadgetEntry => g !== undefined)

        if (matchedGadgets.length === 0) return null

        // Find the most severe gadget
        const bySeverity = matchedGadgets.sort((a, b) => {
            const order = { critical: 0, high: 1, medium: 2 }
            return order[a.severity] - order[b.severity]
        })

        const worst = bySeverity[0]
        const confidence = worst.severity === 'critical' ? 0.96
            : worst.severity === 'high' ? 0.90
                : 0.80

        return {
            detected: true,
            confidence,
            explanation: `Prototype pollution targeting ${worst.property} — ${worst.consequence}` +
                (worst.cve ? ` (${worst.cve})` : '') +
                ` [source: ${worst.source}]`,
            evidence: matchedGadgets.map(g =>
                `${g.property}:${g.severity}:${g.consequence}`,
            ).join(' | '),
        }
    },

    generateVariants: (count: number): string[] => {
        const criticalProps = GADGET_DATABASE.filter(g => g.severity === 'critical')
        const highProps = GADGET_DATABASE.filter(g => g.severity === 'high')
        const allProps = [...criticalProps, ...highProps]

        const accessPatterns: Array<(prop: string) => string> = [
            p => `__proto__[${p}]=malicious`,
            p => `__proto__.${p}=malicious`,
            p => `constructor[prototype][${p}]=malicious`,
            p => `constructor.prototype.${p}=malicious`,
            p => `{"__proto__":{"${p}":"malicious"}}`,
        ]

        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const prop = allProps[i % allProps.length]
            const pattern = accessPatterns[Math.floor(i / allProps.length) % accessPatterns.length]
            variants.push(pattern(prop.property))
        }
        return variants
    },
}
