import { readdirSync, readFileSync } from 'node:fs'
import { extname, isAbsolute, join, relative, resolve } from 'node:path'
import { ALL_CLASS_MODULES } from './classes/index.js'
import type { Severity } from './classes/types.js'
import { AstScanner, type AstFinding } from './ast-scanner.js'


const DEFAULT_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.vue', '.svelte']
const DEFAULT_EXCLUDE = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.nuxt']
const USER_INPUT_PATTERN = /\b(?:req\.(?:params|query|body|headers)|request\.(?:params|query|body)|ctx\.request\.(?:query|body)|params\.|query\.|body\.|url\b|userInput\b|input\b)\b/i

type ScannerCategory = 'sqli' | 'xss' | 'command_injection' | 'path_traversal' | 'ssrf' | 'auth'

type SinkPattern = {
    sink: string
    regex: RegExp
    severity: Severity
    suggestion: string
    requiresUserInput?: boolean
    allow?: (match: RegExpExecArray) => boolean
}

export interface ScanFinding {
    file: string
    line: number
    column: number
    category: ScannerCategory
    sink: string
    snippet: string
    severity: Severity
    suggestion: string
    confidence?: number
    source?: string
    taintPath?: string[]
}

export interface ScanResult {
    files: number
    findings: ScanFinding[]
    duration: number
}

const CLASSES_BY_CATEGORY = {
    sqli: ALL_CLASS_MODULES.filter((module) => module.category === 'sqli').map((module) => module.id),
    xss: ALL_CLASS_MODULES.filter((module) => module.category === 'xss').map((module) => module.id),
    command_injection: ALL_CLASS_MODULES.filter((module) => module.category === 'cmdi').map((module) => module.id),
    path_traversal: ALL_CLASS_MODULES.filter((module) => module.category === 'path_traversal').map((module) => module.id),
    ssrf: ALL_CLASS_MODULES.filter((module) => module.category === 'ssrf').map((module) => module.id),
    auth: ALL_CLASS_MODULES.filter((module) => module.category === 'auth').map((module) => module.id),
} satisfies Record<ScannerCategory, string[]>

const CATEGORY_DESCRIPTIONS = {
    sqli: 'Potential SQL injection sink usage detected in code; validate and parameterize user-controlled values.',
    xss: 'Potential cross-site scripting sink usage detected; encode or sanitize user-controlled output.',
    command_injection: 'Potential command execution sink usage detected; avoid dynamic command construction and shell execution.',
    path_traversal: 'Potential path traversal sink usage detected; enforce canonical path validation and allowlisting.',
    ssrf: 'Potential SSRF sink usage detected; restrict outbound destinations to safe allowlists.',
    auth: 'Potential authentication/authorization weakness detected; enforce strict security controls and validation.',
} satisfies Record<ScannerCategory, string>

const SARIF_SCHEMA_URL = 'https://json.schemastore.org/sarif-2.1.0.json'
const SARIF_VERSION = '2.1.0'
const ENGINE_VERSION = '1.0.0'

export const SINK_PATTERNS: Record<ScannerCategory, SinkPattern[]> = {
    sqli: [
        {
            sink: 'db.query(VAR)',
            regex: /\bdb\.query\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Use parameterized queries or prepared statements instead of interpolating user-controlled values.',
        },
        {
            sink: 'db.raw(VAR)',
            regex: /\bdb\.raw\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Avoid raw SQL from dynamic strings. Use bound parameters for all external input.',
        },
        {
            sink: 'knex.raw(VAR)',
            regex: /\bknex\.raw\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Replace `knex.raw` string interpolation with bindings (`?` placeholders + values array).',
        },
        {
            sink: 'prisma.$queryRaw(VAR)',
            regex: /\bprisma\.\$(?:queryRaw|queryRawUnsafe|executeRawUnsafe?)\s*\(([^)]*)\)/g,
            severity: 'critical',
            suggestion: 'Prefer safe Prisma query APIs and parameter binding. Avoid `$queryRawUnsafe` with dynamic input.',
        },
        {
            sink: 'sequelize.query(VAR)',
            regex: /\bsequelize\.query\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Use replacements/bind parameters in Sequelize query APIs.',
        },
        {
            sink: 'pool.query(VAR)',
            regex: /\bpool\.query\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Use placeholders and separate values when calling `pool.query`.',
        },
        {
            sink: 'connection.execute(VAR)',
            regex: /\bconnection\.execute\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Use prepared statements with explicit placeholders for external input.',
        },
        {
            sink: '`SELECT ... ${VAR}`',
            regex: /`[^`]*\bSELECT\b[^`]*\$\{[^}]+\}[^`]*`/gi,
            severity: 'critical',
            suggestion: 'Do not embed variables in SQL template literals. Bind values through your DB driver.',
        },
    ],
    xss: [
        {
            sink: 'res.send(VAR)',
            regex: /\bres\.send\s*\(([^)]*)\)/g,
            severity: 'medium',
            suggestion: 'Encode/escape untrusted data before embedding in HTML responses.',
        },
        {
            sink: 'innerHTML = VAR',
            regex: /\binnerHTML\s*=\s*[^;]+/g,
            severity: 'high',
            suggestion: 'Prefer textContent or sanitize untrusted HTML with a strict allowlist sanitizer.',
        },
        {
            sink: 'document.write(VAR)',
            regex: /\bdocument\.write\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Avoid document.write for dynamic data. Use safe DOM APIs and encoding.',
        },
        {
            sink: 'dangerouslySetInnerHTML',
            regex: /\bdangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*__html\s*:\s*[^}]+\}\s*\}/g,
            severity: 'high',
            suggestion: 'Only pass sanitized content to `dangerouslySetInnerHTML` and prefer component-safe rendering.',
        },
        {
            sink: 'v-html=',
            regex: /\bv-html\s*=\s*["'][^"']+["']/g,
            severity: 'high',
            suggestion: 'Avoid `v-html` with user-controlled content. Prefer escaped interpolation.',
        },
        {
            sink: '${VAR} in HTML template literal response',
            regex: /\b(?:res\.send|res\.end|reply\.send)\s*\(\s*`[^`]*<[a-zA-Z][^`]*\$\{[^}]+\}[^`]*`\s*\)/g,
            severity: 'high',
            suggestion: 'Do not interpolate raw user input into HTML template literals; escape output by context.',
        },
    ],
    command_injection: [
        {
            sink: 'exec(VAR)',
            regex: /\bexec\s*\(([^)]*)\)/g,
            severity: 'critical',
            suggestion: 'Avoid `exec` with dynamic strings. Use `spawn`/`execFile` with fixed command + argument array.',
        },
        {
            sink: 'execSync(VAR)',
            regex: /\bexecSync\s*\(([^)]*)\)/g,
            severity: 'critical',
            suggestion: 'Avoid `execSync` for untrusted input. Use safe argument arrays and strict allowlists.',
        },
        {
            sink: 'spawn(VAR, { shell: true })',
            regex: /\bspawn\s*\([^)]*\{[^}]*\bshell\s*:\s*true\b[^}]*\}[^)]*\)/g,
            severity: 'high',
            suggestion: 'Disable shell execution (`shell: false`) and pass validated arguments as an array.',
        },
        {
            sink: 'child_process with string concatenation',
            regex: /\bchild_process\.(?:exec|execSync|spawn)\s*\([^\n;]*(?:\+|\$\{)/g,
            severity: 'critical',
            suggestion: 'Remove command string concatenation. Build argument arrays and validate input against allowlists.',
        },
    ],
    path_traversal: [
        {
            sink: 'readFile(VAR)',
            regex: /\breadFile\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Validate and normalize paths, and constrain access to a fixed base directory.',
        },
        {
            sink: 'readFileSync(VAR)',
            regex: /\breadFileSync\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Validate and normalize paths, and reject `..`, null bytes, and absolute path escapes.',
        },
        {
            sink: 'fs.access(VAR)',
            regex: /\bfs\.access(?:Sync)?\s*\(([^)]*)\)/g,
            severity: 'medium',
            suggestion: 'Do not trust external path input. Resolve against a safe root and enforce prefix checks.',
        },
        {
            sink: 'path.join(VAR from request)',
            regex: /\bpath\.join\s*\(([^)]*)\)/g,
            severity: 'medium',
            suggestion: 'Avoid joining untrusted path segments directly. Normalize and verify final path stays inside a safe root.',
            requiresUserInput: true,
        },
    ],
    ssrf: [
        {
            sink: 'fetch(VAR from user input)',
            regex: /\bfetch\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Disallow arbitrary URLs. Enforce protocol/domain allowlists and block private/meta-data IP ranges.',
            requiresUserInput: true,
        },
        {
            sink: 'axios.get(VAR from user input)',
            regex: /\baxios\.(?:get|post|request)\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Validate destination URLs against a strict allowlist before making outbound requests.',
            requiresUserInput: true,
        },
        {
            sink: 'http.request(VAR from user input)',
            regex: /\b(?:http|https)\.request\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Do not pass user-controlled hosts/URLs directly into request APIs. Enforce destination controls.',
            requiresUserInput: true,
        },
    ],
    auth: [
        {
            sink: 'jwt.verify without algorithm restriction',
            regex: /\bjwt\.verify\s*\(([^)]*)\)/g,
            severity: 'high',
            suggestion: 'Set explicit allowed algorithms in `jwt.verify` options (e.g. `{ algorithms: ["HS256"] }`).',
            allow: (match: RegExpExecArray): boolean => !/\balgorithms?\s*:/i.test(match[1] ?? ''),
        },
        {
            sink: 'bcrypt.compare timing leak pattern',
            regex: /\bbcrypt\.compare(?:Sync)?\s*\(([^)]*)\)\s*(?:===|==|!==|!=)\s*(?:true|false|1|0)/g,
            severity: 'medium',
            suggestion: 'Avoid branching on compare output patterns that expose timing behavior; use constant-time safe auth flows.',
        },
    ],
}

export class CodebaseScanner {
    private readonly rootDir: string
    private readonly extensions: Set<string>
    private readonly exclude: string[]

    private readonly astScanner: AstScanner

    constructor(options: { rootDir: string, extensions?: string[], exclude?: string[] }) {
        this.rootDir = resolve(options.rootDir)
        this.extensions = new Set((options.extensions ?? DEFAULT_EXTENSIONS).map((extension) => extension.toLowerCase()))
        this.exclude = options.exclude ?? DEFAULT_EXCLUDE
        this.astScanner = new AstScanner()
    }

    scanFile(filePath: string): ScanFinding[] {
        const absoluteFilePath = isAbsolute(filePath) ? filePath : resolve(this.rootDir, filePath)
        let content = ''

        try {
            content = readFileSync(absoluteFilePath, 'utf8')
        } catch {
            return []
        }

        const findings: ScanFinding[] = []
        const lines = content.split(/\r?\n/)
        const reportPath = this.toReportPath(absoluteFilePath)

        const lang = this.astScanner.getLanguageForFile(absoluteFilePath)
        if (lang) {
            const astFindings = this.astScanner.scanFile(absoluteFilePath, content, lang)
            for (const af of astFindings) {
                findings.push({
                    file: reportPath,
                    line: af.line,
                    column: af.column,
                    category: af.ruleId.split('.')[0] as ScannerCategory,
                    sink: af.sink,
                    snippet: lines[af.line - 1]?.trim() ?? '',
                    severity: af.severity,
                    suggestion: `AST Taint path detected from source '${af.source}' to sink '${af.sink}'.`,
                    confidence: af.confidence,
                    source: af.source,
                    taintPath: af.taintPath,
                })
            }
        }

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex]

            for (const [category, patterns] of Object.entries(SINK_PATTERNS) as [ScannerCategory, SinkPattern[]][]) {
                for (const pattern of patterns) {
                    pattern.regex.lastIndex = 0
                    let match: RegExpExecArray | null = pattern.regex.exec(line)

                    while (match) {
                        if (!this.shouldIncludeMatch(pattern, match)) {
                            match = pattern.regex.exec(line)
                            continue
                        }

                        findings.push({
                            file: reportPath,
                            line: lineIndex + 1,
                            column: match.index + 1,
                            category,
                            sink: pattern.sink,
                            snippet: line.trim(),
                            severity: pattern.severity,
                            suggestion: pattern.suggestion,
                        })

                        if (match.index === pattern.regex.lastIndex) {
                            pattern.regex.lastIndex += 1
                        }
                        match = pattern.regex.exec(line)
                    }
                }
            }
        }

        return findings
    }

    scanDirectory(): ScanResult {
        const startedAt = Date.now()
        const filePaths = this.collectFiles(this.rootDir)
        const findings: ScanFinding[] = []

        for (const filePath of filePaths) {
            findings.push(...this.scanFile(filePath))
        }

        return {
            files: filePaths.length,
            findings,
            duration: Date.now() - startedAt,
        }
    }

    private collectFiles(currentDir: string): string[] {
        const entries = readdirSync(currentDir, { withFileTypes: true })
        const files: string[] = []

        for (const entry of entries) {
            const fullPath = join(currentDir, entry.name)
            if (this.isExcluded(fullPath, entry.name)) {
                continue
            }

            if (entry.isDirectory()) {
                files.push(...this.collectFiles(fullPath))
                continue
            }

            const extension = extname(entry.name).toLowerCase()
            if (this.extensions.has(extension)) {
                files.push(fullPath)
            }
        }

        return files
    }

    private isExcluded(fullPath: string, entryName: string): boolean {
        const relPath = relative(this.rootDir, fullPath)
        return this.exclude.some((pattern) => {
            if (!pattern) return false
            return entryName === pattern || relPath.split(/[\\/]/).includes(pattern) || relPath.includes(pattern)
        })
    }

    private shouldIncludeMatch(pattern: SinkPattern, match: RegExpExecArray): boolean {
        const candidate = `${match[0]} ${(match[1] ?? '')}`
        if (pattern.requiresUserInput && !USER_INPUT_PATTERN.test(candidate)) {
            return false
        }

        if (pattern.allow && !pattern.allow(match)) {
            return false
        }

        return true
    }

    private toReportPath(filePath: string): string {
        const relativePath = relative(this.rootDir, filePath)
        return relativePath.startsWith('..') ? filePath : relativePath
    }
}

const ANSI = {
    reset: '\u001b[0m',
    bold: '\u001b[1m',
    red: '\u001b[31m',
    yellow: '\u001b[33m',
    blue: '\u001b[34m',
    green: '\u001b[32m',
    gray: '\u001b[90m',
}

function colorBySeverity(severity: Severity): string {
    if (severity === 'critical') return ANSI.red
    if (severity === 'high') return ANSI.yellow
    if (severity === 'medium') return ANSI.blue
    return ANSI.green
}

function severityToSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
    if (severity === 'critical' || severity === 'high') return 'error'
    if (severity === 'medium') return 'warning'
    return 'note'
}

function normalizeRuleId(value: string): string {
    const normalized = value
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9._-]+/gi, '_')
        .replace(/_+/g, '_')
        .replace(/^_+|_+$/g, '')

    return normalized.length > 0 ? normalized : 'pattern'
}

export function toSarif(result: ScanResult): object {
    const rulesById = new Map<string, { category: ScannerCategory; sink: string; description: string }>()
    const results: object[] = []

    for (const category of Object.keys(CATEGORY_DESCRIPTIONS) as ScannerCategory[]) {
        rulesById.set(`${category}.default`, {
            category,
            sink: 'default',
            description: CATEGORY_DESCRIPTIONS[category],
        })
    }

    for (const finding of result.findings) {
        const ruleId = `${finding.category}.${normalizeRuleId(finding.sink)}`
        rulesById.set(ruleId, {
            category: finding.category,
            sink: finding.sink,
            description: CATEGORY_DESCRIPTIONS[finding.category],
        })

        results.push({
            ruleId,
            level: severityToSarifLevel(finding.severity),
            message: {
                text: `${finding.sink}. ${finding.suggestion}`,
            },
            locations: [{
                physicalLocation: {
                    artifactLocation: {
                        uri: finding.file.replace(/\\/g, '/'),
                    },
                    region: {
                        startLine: finding.line,
                        startColumn: finding.column,
                    },
                },
            }],
        })
    }

    const rules = [...rulesById].map(([id, rule]) => ({
        id,
        name: `${rule.category} ${rule.sink}`,
        shortDescription: {
            text: `${rule.category.toUpperCase()} rule`,
        },
        fullDescription: {
            text: rule.description,
        },
    }))

    return {
        $schema: SARIF_SCHEMA_URL,
        version: SARIF_VERSION,
        runs: [{
            tool: {
                driver: {
                    name: 'invariant',
                    version: ENGINE_VERSION,
                    rules,
                },
            },
            results,
        }],
    }
}

function escapeXml(value: string): string {
    return value
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;')
}

function junitFailureMessage(finding: ScanFinding): string {
    return `${finding.sink} (${finding.severity}) in ${finding.file}:${String(finding.line)}:${String(finding.column)}`
}

export function toJunitXml(result: ScanResult): string {
    const suites = (Object.keys(CATEGORY_DESCRIPTIONS) as ScannerCategory[]).map((category) => {
        const findings = result.findings.filter((finding) => finding.category === category)
        const cases = findings.map((finding) => [
            `    <testcase classname="${escapeXml(`invariant.${category}`)}" name="${escapeXml(finding.sink)}">`,
            `      <failure message="${escapeXml(junitFailureMessage(finding))}" type="${escapeXml(finding.severity)}">`,
            `        ${escapeXml(finding.suggestion)}`,
            '      </failure>',
            '    </testcase>',
        ].join('\n'))

        return [
            `  <testsuite name="${escapeXml(`invariant.${category}`)}" tests="${String(findings.length)}" failures="${String(findings.length)}">`,
            ...cases,
            '  </testsuite>',
        ].join('\n')
    })

    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        `<testsuites tests="${String(result.findings.length)}" failures="${String(result.findings.length)}">`,
        ...suites,
        '</testsuites>',
    ].join('\n')
}

export function formatReport(result: ScanResult): string {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    }

    for (const finding of result.findings) {
        counts[finding.severity] += 1
    }

    const lines: string[] = []
    lines.push(`${ANSI.bold}Invariant Codebase Scanner Report${ANSI.reset}`)
    lines.push(`Files scanned: ${result.files}`)
    lines.push(`Findings: ${result.findings.length}`)
    lines.push(`Duration: ${result.duration}ms`)
    lines.push(
        `Severity: ${ANSI.red}critical ${counts.critical}${ANSI.reset}, ` +
        `${ANSI.yellow}high ${counts.high}${ANSI.reset}, ` +
        `${ANSI.blue}medium ${counts.medium}${ANSI.reset}, ` +
        `${ANSI.green}low ${counts.low}${ANSI.reset}`,
    )
    lines.push(`Classes covered: ${Object.values(CLASSES_BY_CATEGORY).flat().length}`)

    if (result.findings.length === 0) {
        lines.push(`${ANSI.green}No sink-pattern findings detected.${ANSI.reset}`)
        return lines.join('\n')
    }

    const sorted = [...result.findings].sort((left, right) => {
        const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }
        const severityDelta = severityOrder[left.severity] - severityOrder[right.severity]
        if (severityDelta !== 0) return severityDelta
        const fileDelta = left.file.localeCompare(right.file)
        if (fileDelta !== 0) return fileDelta
        return left.line - right.line
    })

    lines.push('')
    for (const finding of sorted) {
        const severityColor = colorBySeverity(finding.severity)
        lines.push(
            `${severityColor}[${finding.severity.toUpperCase()}]${ANSI.reset} ` +
            `${finding.category} ${ANSI.gray}${finding.file}:${finding.line}:${finding.column}${ANSI.reset}`,
        )
        lines.push(`  sink: ${finding.sink}`)
        lines.push(`  code: ${finding.snippet}`)
        lines.push(`  fix : ${finding.suggestion}`)
    }

    return lines.join('\n')
}

export { CLASSES_BY_CATEGORY }
