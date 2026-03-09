/**
 * Supply Chain Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for supply chain attacks:
 *   ∃ pattern ∈ input :
 *     pattern MATCHES supply_chain_attack_structure
 *     ∧ structural_analysis(pattern) CONFIRMS malicious_intent
 *     → attacker compromises software supply chain
 *
 * This module performs structural analysis beyond regex:
 *   - dependency_confusion: validates scoped package + public override structure
 *   - postinstall_injection: parses script bodies for multi-stage shell attacks
 *   - env_exfiltration: tracks data flow from env access to network sink
 */


// ── Result Type ──────────────────────────────────────────────────

export interface SupplyChainDetection {
    type: 'dependency_confusion' | 'postinstall_injection' | 'env_exfiltration' | 'npm_dependency_confusion' | 'typosquat_package'
    detail: string
    confidence: number
    indicators: string[]
}


// ── Dependency Confusion Structural Analysis ─────────────────────
//
// Beyond regex: parse the JSON structure to find scoped packages
// pointing at public registries. Validate that:
//   1. The scope exists (@org/pkg)
//   2. The version resolver points to npmjs.org (public override)
//   3. The package name is plausibly private (not @types/ etc.)

const PUBLIC_REGISTRY_PATTERNS = [
    /registry\.npmjs\.org/i,
    /registry\.yarnpkg\.com/i,
    /npm\.pkg\.github\.com/i,
]

const SAFE_SCOPES = new Set([
    '@types', '@babel', '@rollup', '@esbuild', '@swc',
    '@vitejs', '@vue', '@angular', '@nestjs', '@prisma',
    '@vercel', '@cloudflare', '@aws-sdk', '@azure',
    '@google-cloud', '@grpc', '@hapi', '@fastify',
])

function analyzeDepConfusion(input: string): SupplyChainDetection[] {
    const detections: SupplyChainDetection[] = []
    const indicators: string[] = []

    // Try to parse as JSON to validate structure
    let parsed: Record<string, unknown> | null = null
    try {
        parsed = JSON.parse(input)
    } catch { /* not valid JSON — fall through to heuristic */ }

    if (parsed) {
        const depKeys = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'overrides']
        for (const key of depKeys) {
            const deps = parsed[key]
            if (!deps || typeof deps !== 'object') continue

            for (const [pkgName, pkgValue] of Object.entries(deps as Record<string, unknown>)) {
                if (typeof pkgValue !== 'string') continue
                if (!pkgName.startsWith('@') || !pkgName.includes('/')) continue

                const scope = pkgName.split('/')[0]
                if (SAFE_SCOPES.has(scope)) continue

                const pointsToPublic = PUBLIC_REGISTRY_PATTERNS.some(rx => rx.test(pkgValue))
                if (pointsToPublic) {
                    indicators.push(`${pkgName} → public registry override`)
                }

                // Check for git+https that could be a fork attack
                if (/^git\+https?:\/\/github\.com\//i.test(pkgValue) && !/^git\+https?:\/\/github\.com\/(?:facebook|google|microsoft|vercel|aws)\//i.test(pkgValue)) {
                    indicators.push(`${pkgName} → git override: ${pkgValue.slice(0, 80)}`)
                }
            }
        }
    }

    // Typosquatting: edit-distance analysis on popular packages
    const POPULAR_PACKAGES = ['lodash', 'express', 'react', 'axios', 'moment', 'underscore', 'request', 'chalk', 'debug', 'commander']
    const importPattern = /(?:from\s+['"]|require\(\s*['"])([a-z][a-z0-9._-]*)['"]/gi
    let match: RegExpExecArray | null
    while ((match = importPattern.exec(input)) !== null) {
        const pkg = match[1]
        for (const popular of POPULAR_PACKAGES) {
            if (pkg === popular) continue
            if (pkg.length < 3) continue
            const dist = levenshtein(pkg, popular)
            if (dist === 1) {
                indicators.push(`typosquat: "${pkg}" is 1 edit from "${popular}"`)
            }
        }
    }

    // Package-level dependency confusion: scoped name + publishConfig to public registry
    // The invariant: a package with a private-looking scope (@internal/, @company/)
    // should NOT have publishConfig pointing to the public npm registry.
    if (parsed) {
        const name = parsed['name']
        const publishConfig = parsed['publishConfig']
        if (typeof name === 'string' && name.startsWith('@') && name.includes('/')) {
            const scope = name.split('/')[0]
            if (!SAFE_SCOPES.has(scope)) {
                if (publishConfig && typeof publishConfig === 'object') {
                    const registry = (publishConfig as Record<string, unknown>)['registry']
                    if (typeof registry === 'string' && PUBLIC_REGISTRY_PATTERNS.some(rx => rx.test(registry))) {
                        indicators.push(`scoped package "${name}" with publishConfig → public registry`)
                    }
                }
                // Also suspicious: very high version of a scoped package (version squatting)
                const version = parsed['version']
                if (typeof version === 'string' && /^[5-9]\d\.\d/.test(version)) {
                    indicators.push(`scoped package "${name}" with suspiciously high version: ${version}`)
                }
            }
        }
    }

    if (indicators.length > 0) {
        detections.push({
            type: 'dependency_confusion',
            detail: `Supply chain: ${indicators.join('; ')}`,
            confidence: indicators.length >= 2 ? 0.94 : 0.87,
            indicators,
        })
    }

    return detections
}

function levenshtein(a: string, b: string): number {
    if (a.length === 0) return b.length
    if (b.length === 0) return a.length
    if (Math.abs(a.length - b.length) > 2) return Math.abs(a.length - b.length)

    const matrix: number[][] = []
    for (let i = 0; i <= a.length; i++) {
        matrix[i] = [i]
        for (let j = 1; j <= b.length; j++) {
            if (i === 0) {
                matrix[i][j] = j
            } else {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1
                matrix[i][j] = Math.min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                )
            }
        }
    }
    return matrix[a.length][b.length]
}


// ── Postinstall Injection Structural Analysis ────────────────────
//
// Beyond regex: parse the script body to identify:
//   1. Multi-stage execution (download → execute)
//   2. Encoded payloads (base64, hex, octal)
//   3. Environment variable smuggling via install scripts

const DOWNLOAD_COMMANDS = /\b(curl|wget|fetch|http\.get|axios\.get)\b/i
const SHELL_EXEC = /\|\s*(sh|bash|zsh|dash|exec|eval|node\s+-e)\b/i
const ENCODING_INDICATORS = /\b(base64|btoa|atob|Buffer\.from|\\x[0-9a-f]{2}|\\[0-7]{3})\b/i
const KNOWN_SAFE_SCRIPTS = /\b(husky|lint-staged|patch-package|node-gyp|prebuild|cmake-js|node-pre-gyp|electron-builder)\b/i

function analyzePostinstallInjection(input: string): SupplyChainDetection[] {
    const detections: SupplyChainDetection[] = []
    const indicators: string[] = []

    // Parse JSON to extract script values
    const scriptPattern = /"(?:preinstall|postinstall|install|prepare|prepublish)"\s*:\s*"((?:[^"\\]|\\.)*)"/gi
    let match: RegExpExecArray | null
    while ((match = scriptPattern.exec(input)) !== null) {
        const body = match[1]

        if (KNOWN_SAFE_SCRIPTS.test(body)) continue

        if (DOWNLOAD_COMMANDS.test(body) && SHELL_EXEC.test(body)) {
            indicators.push('download-to-shell pipeline in lifecycle script')
        }

        if (ENCODING_INDICATORS.test(body)) {
            indicators.push('encoded payload in lifecycle script')
        }

        // Direct code execution in lifecycle scripts
        // The invariant: lifecycle scripts should not invoke child_process, exec,
        // spawn, or eval — these are code execution primitives.
        if (/child_process/i.test(body) || /\bexec\s*\(/i.test(body) ||
            /\bspawn\s*\(/i.test(body) || /\beval\s*\(/i.test(body) ||
            /\bexecSync\b/i.test(body) || /\bspawnSync\b/i.test(body)) {
            indicators.push('direct code execution in lifecycle script')
        }

        // node -e "..." or python -c "..." in lifecycle script
        if (/\bnode\s+-e\b/i.test(body) || /\bpython[23]?\s+-c\b/i.test(body) ||
            /\bperl\s+-e\b/i.test(body) || /\bruby\s+-e\b/i.test(body)) {
            indicators.push('inline code execution via interpreter flag in lifecycle script')
        }

        // Detect environment variable access in install scripts (data staging)
        if (/\bprocess\.env\b/i.test(body) || /\$\{?\w*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)\}?\b/i.test(body)) {
            indicators.push('sensitive env access in lifecycle script')
        }

        // Detect network exfiltration combined with env access
        if (/\bprocess\.env\b/i.test(body) && /\b(curl|wget|fetch|http|request)\b/i.test(body)) {
            indicators.push('env-to-network exfiltration in lifecycle script')
        }
    }

    if (indicators.length > 0) {
        detections.push({
            type: 'postinstall_injection',
            detail: `Lifecycle script: ${indicators.join('; ')}`,
            confidence: indicators.length >= 2 ? 0.95 : 0.90,
            indicators,
        })
    }

    return detections
}


// ── Env Exfiltration Structural Analysis ─────────────────────────
//
// Beyond regex: track data flow from environment access to HTTP sink.
// Validates that:
//   1. env access and HTTP sink are in the same logical statement
//   2. The env data flows INTO the request (not just nearby)
//   3. Sensitive env vars are targeted (not just NODE_ENV)

const SENSITIVE_ENV_PATTERNS = [
    /process\.env\.(?!NODE_ENV|PORT|HOST|HOME|PATH|LANG|TERM|SHELL|USER|LOGNAME)\w{3,}/,
    /process\.env\b(?!\.NODE_ENV|\.PORT|\.HOST|\.HOME)/,
    /os\.environ(?!\s*\.get\(\s*['"](?:HOME|PATH|LANG|TERM|SHELL|USER)['"])/,
    /os\.environ(?:\.\w+|\[['"][^'"]+['"]\])/,
]

const NETWORK_SINKS = [
    /\bfetch\s*\(/,
    /\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(/,
    /\bhttp\.request\s*\(/,
    /\bhttps\.request\s*\(/,
    /\bXMLHttpRequest\b/,
    /\brequests\s*\.\s*(?:get|post|put|patch|delete)\s*\(/,
    /\burllib\s*\.\s*request/,
    /\bcurl\b/,
    /\bwget\b/,
    /\bnew\s+WebSocket\s*\(/,
]

function analyzeEnvExfiltration(input: string): SupplyChainDetection[] {
    const detections: SupplyChainDetection[] = []
    const indicators: string[] = []

    // Split by statements (semicolons, newlines)
    const statements = input.split(/[;\n\r]+/)

    for (const stmt of statements) {
        const hasSensitiveEnv = SENSITIVE_ENV_PATTERNS.some(rx => rx.test(stmt))
        if (!hasSensitiveEnv) continue

        const hasNetworkSink = NETWORK_SINKS.some(rx => rx.test(stmt))
        if (!hasNetworkSink) continue

        // Data flow confirmation: env value appears as argument to the sink
        const envInBody = /body\s*[:=].*process\.env/i.test(stmt) ||
            /data\s*[:=].*(?:process\.env|os\.environ)/i.test(stmt) ||
            /JSON\.stringify\s*\(.*process\.env/i.test(stmt) ||
            /\$\{process\.env\./i.test(stmt)

        if (envInBody) {
            indicators.push('env data flows into HTTP request body')
        } else {
            indicators.push('env access co-located with network sink')
        }
    }

    // Cross-statement analysis: env accessed then sent
    const hasEnvCapture = /(?:const|let|var)\s+\w+\s*=\s*(?:process\.env|os\.environ)/i.test(input)
    const hasSendOfCapture = /\b(?:fetch|axios|request|http)\b.*\b(?:body|data|payload)\b/i.test(input)
    if (hasEnvCapture && hasSendOfCapture) {
        indicators.push('env captured into variable then sent via HTTP')
    }

    if (indicators.length > 0) {
        detections.push({
            type: 'env_exfiltration',
            detail: `Exfiltration: ${indicators.join('; ')}`,
            confidence: indicators.some(i => i.includes('flows into')) ? 0.93 : 0.85,
            indicators,
        })
    }

    return detections
}


// ── NPM Dependency Confusion ─────────────────────────────────────
//
// Private package name published publicly with higher version.
// Pattern: package.json referencing internal names (corp-internal, @company/)
// with suspicious registry override.

const INTERNAL_PACKAGE_PATTERNS = [
    /(?:corp-internal|company-internal|internal-pkg|@company\/|@corp\/|@internal\/)/i,
    /@[a-z0-9-]+\/(?:internal|private|proprietary)-/i,
]

export function detectNpmDependencyConfusion(input: string): SupplyChainDetection | null {
    let parsed: Record<string, unknown> | null = null
    try {
        parsed = JSON.parse(input)
    } catch { /* not JSON */ }

    if (!parsed) {
        const looksLikePackageJson = /"dependencies"\s*:\s*\{/i.test(input) && /"name"\s*:\s*"/i.test(input)
        if (!looksLikePackageJson) return null
        const hasInternalRef = INTERNAL_PACKAGE_PATTERNS.some(rx => rx.test(input))
        const hasRegistryOverride = /(?:registry|npmrc|\.npmrc|registry\.npmjs)/i.test(input)
        if (hasInternalRef && hasRegistryOverride) {
            return {
                type: 'npm_dependency_confusion',
                detail: 'npm dependency confusion: internal package name with registry override in package manifest',
                confidence: 0.90,
                indicators: ['internal package name with registry override'],
            }
        }
        return null
    }

    const indicators: string[] = []
    const depKeys = ['dependencies', 'devDependencies', 'optionalDependencies', 'overrides']
    for (const key of depKeys) {
        const deps = parsed[key]
        if (!deps || typeof deps !== 'object') continue
        for (const name of Object.keys(deps as Record<string, unknown>)) {
            if (INTERNAL_PACKAGE_PATTERNS.some(rx => rx.test(name))) {
                indicators.push(`internal package "${name}" in ${key}`)
            }
        }
    }
    const name = parsed['name']
    if (typeof name === 'string' && INTERNAL_PACKAGE_PATTERNS.some(rx => rx.test(name))) {
        indicators.push(`package name "${name}" looks internal`)
    }
    const hasRegistryInPublishConfig = (() => {
        const pc = parsed['publishConfig']
        if (pc && typeof pc === 'object' && typeof (pc as Record<string, unknown>)['registry'] === 'string') return true
        return false
    })()
    if (hasRegistryInPublishConfig) indicators.push('publishConfig.registry override')
    if (indicators.length === 0) return null
    return {
        type: 'npm_dependency_confusion',
        detail: `npm dependency confusion: ${indicators.join('; ')}`,
        confidence: 0.90,
        indicators,
    }
}

// ── Typosquat Package ───────────────────────────────────────────
//
// Package names 1–2 chars different from popular packages (char swap/repeat/insert).

const TYPOSQUAT_TARGETS = [
    'lodash', 'express', 'react', 'angular', 'vue', 'axios', 'moment', 'request', 'chalk', 'debug',
    'commander', 'vuejs',
]

function typosquatDistance(a: string, b: string): number {
    if (a.length === 0) return b.length
    if (b.length === 0) return a.length
    if (Math.abs(a.length - b.length) > 2) return 3
    const matrix: number[][] = []
    for (let i = 0; i <= a.length; i++) {
        matrix[i] = [i]
        for (let j = 1; j <= b.length; j++) {
            if (i === 0) matrix[i][j] = j
            else {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1
                matrix[i][j] = Math.min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                )
            }
        }
    }
    return matrix[a.length][b.length]
}

export function detectTyposquatPackage(input: string): SupplyChainDetection | null {
    const indicators: string[] = []
    const pkgRefPattern = /(?:from\s+['"]|require\s*\(\s*['"]|["'])([a-z][a-z0-9._-]{2,})["']/gi
    const inPackageJson = /"dependencies"|"devDependencies"/i.test(input)
    let match: RegExpExecArray | null
    const seen = new Set<string>()
    while ((match = pkgRefPattern.exec(input)) !== null) {
        const pkg = match[1]
        if (seen.has(pkg)) continue
        seen.add(pkg)
        for (const target of TYPOSQUAT_TARGETS) {
            if (pkg === target) continue
            if (pkg.length < 3) continue
            const dist = typosquatDistance(pkg, target)
            if (dist >= 1 && dist <= 2) {
                indicators.push(`"${pkg}" is ${dist} edit(s) from "${target}"`)
            }
        }
    }
    if (indicators.length === 0) return null
    return {
        type: 'typosquat_package',
        detail: `Typosquat: ${indicators.join('; ')}`,
        confidence: 0.87,
        indicators,
    }
}

// ── Public API ───────────────────────────────────────────────────

export function detectSupplyChain(input: string): SupplyChainDetection[] {
    const detections: SupplyChainDetection[] = []

    if (input.length < 10) return detections

    try { detections.push(...analyzeDepConfusion(input)) } catch { /* safe */ }
    try { detections.push(...analyzePostinstallInjection(input)) } catch { /* safe */ }
    try { detections.push(...analyzeEnvExfiltration(input)) } catch { /* safe */ }
    try {
        const npmConf = detectNpmDependencyConfusion(input)
        if (npmConf) detections.push(npmConf)
    } catch { /* safe */ }
    try {
        const typosquat = detectTyposquatPackage(input)
        if (typosquat) detections.push(typosquat)
    } catch { /* safe */ }

    return detections
}
