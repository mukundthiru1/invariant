import * as childProcess from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import type { ScanFinding } from './codebase-scanner.js'

export interface FixResult {
    file: string
    line: number
    category: string
    description: string
    original: string
    fixed: string
    applied: boolean
}

export interface FixReport {
    fixes: FixResult[]
    totalFixed: number
    totalSkipped: number
    commitHash?: string
}

const AUTOFIX_SAFE_PATH_HELPER = `
function assertSafePath(inputPath: string): string {
    const safeRoot = process.cwd()
    const resolved = resolvePath(safeRoot, inputPath)
    if (!resolved.startsWith(safeRoot)) {
        throw new Error('Potential path traversal blocked by invariant auto-fix')
    }
    return resolved
}
`

const AUTOFIX_SAFE_URL_HELPER = `
function assertSafeUrl(rawUrl: string): string {
    const parsed = new URL(rawUrl)
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Blocked non-http(s) URL')
    }
    const host = parsed.hostname.toLowerCase()
    if (host === 'localhost' || host === '127.0.0.1' || host.endsWith('.local')) {
        throw new Error('Blocked localhost/private destination')
    }
    return parsed.toString()
}
`

const AUTOFIX_ESCAPE_HTML_IMPORT = "import escapeHtml from 'escape-html'"
const AUTOFIX_SPAWN_IMPORT = "import { spawn } from 'node:child_process'"
const AUTOFIX_RESOLVE_PATH_IMPORT = "import { resolve as resolvePath } from 'node:path'"

export class AutoFixer {
    constructor(private rootDir: string) {
        this.rootDir = resolve(rootDir)
    }

    generateFixes(findings: ScanFinding[]): FixResult[] {
        const seen = new Set<string>()
        const fileCache = new Map<string, string[]>()
        const fixes: FixResult[] = []

        for (const finding of findings) {
            const key = `${finding.file}:${finding.line}:${finding.category}`
            if (seen.has(key)) continue
            seen.add(key)

            const originalLine = this.getOriginalLine(finding.file, finding.line, fileCache)
            if (!originalLine) {
                fixes.push({
                    file: finding.file,
                    line: finding.line,
                    category: finding.category,
                    description: 'Skipped: unable to locate original source line',
                    original: finding.snippet,
                    fixed: finding.snippet,
                    applied: false,
                })
                continue
            }

            const fixedLine = this.generateLineFix(finding.category, originalLine)
            if (!fixedLine) {
                fixes.push({
                    file: finding.file,
                    line: finding.line,
                    category: finding.category,
                    description: `Skipped: no safe automatic fix for ${finding.category}`,
                    original: originalLine,
                    fixed: originalLine,
                    applied: false,
                })
                continue
            }

            fixes.push({
                file: finding.file,
                line: finding.line,
                category: finding.category,
                description: `Auto-fix generated for ${finding.category}`,
                original: originalLine,
                fixed: fixedLine,
                applied: false,
            })
        }

        return fixes
    }

    applyFixes(fixes: FixResult[]): FixResult[] {
        const grouped = new Map<string, FixResult[]>()
        for (const fix of fixes) {
            if (fix.fixed === fix.original) continue
            const fileFixes = grouped.get(fix.file) ?? []
            fileFixes.push(fix)
            grouped.set(fix.file, fileFixes)
        }

        const appliedResults = fixes.map((fix) => ({ ...fix, applied: false }))
        const resultIndex = new Map<string, number>()
        for (let index = 0; index < appliedResults.length; index++) {
            const fix = appliedResults[index]
            resultIndex.set(`${fix.file}:${fix.line}:${fix.original}:${fix.fixed}`, index)
        }

        for (const [file, fileFixes] of grouped) {
            const absolutePath = this.toAbsolutePath(file)
            if (!existsSync(absolutePath)) continue

            const content = readFileSync(absolutePath, 'utf8')
            const lines = content.split(/\r?\n/)
            const appliedCategories = new Set<string>()

            for (const fix of fileFixes) {
                const zeroBasedLine = Math.max(0, fix.line - 1)
                let applied = false

                if (lines[zeroBasedLine] === fix.original) {
                    lines[zeroBasedLine] = fix.fixed
                    applied = true
                } else {
                    const fallbackIndex = lines.findIndex((line) => line === fix.original)
                    if (fallbackIndex >= 0) {
                        lines[fallbackIndex] = fix.fixed
                        applied = true
                    }
                }

                if (applied) {
                    const key = `${fix.file}:${fix.line}:${fix.original}:${fix.fixed}`
                    const index = resultIndex.get(key)
                    if (index !== undefined) {
                        appliedResults[index].applied = true
                    }
                    appliedCategories.add(fix.category)
                }
            }

            let updatedContent = lines.join('\n')
            const fileHadXssFix = appliedCategories.has('xss')
            const fileHadCommandFix = appliedCategories.has('command_injection')
            const fileHadPathFix = appliedCategories.has('path_traversal')
            const fileHadSsrfFix = appliedCategories.has('ssrf')

            if (fileHadXssFix && !this.hasEscapeHtmlImport(updatedContent)) {
                updatedContent = this.prependImport(updatedContent, AUTOFIX_ESCAPE_HTML_IMPORT)
            }
            if (fileHadCommandFix && !this.hasSpawnImport(updatedContent)) {
                updatedContent = this.prependImport(updatedContent, AUTOFIX_SPAWN_IMPORT)
            }
            if (fileHadPathFix && !this.hasResolvePathImport(updatedContent)) {
                updatedContent = this.prependImport(updatedContent, AUTOFIX_RESOLVE_PATH_IMPORT)
            }
            if (fileHadPathFix && !updatedContent.includes('function assertSafePath(')) {
                updatedContent += `\n${AUTOFIX_SAFE_PATH_HELPER}\n`
            }
            if (fileHadSsrfFix && !updatedContent.includes('function assertSafeUrl(')) {
                updatedContent += `\n${AUTOFIX_SAFE_URL_HELPER}\n`
            }

            writeFileSync(absolutePath, updatedContent, 'utf8')
        }

        return appliedResults
    }

    atomicCommit(fixes: FixResult[]): string | null {
        const files = [...new Set(fixes.filter((fix) => fix.applied).map((fix) => fix.file))]
        if (files.length === 0) return null

        const gitAdd = this.runGit(['add', ...files])
        if (!gitAdd.ok) {
            this.rollbackFiles(files)
            return null
        }

        const categoryCounts = new Map<string, number>()
        for (const fix of fixes.filter((entry) => entry.applied)) {
            categoryCounts.set(fix.category, (categoryCounts.get(fix.category) ?? 0) + 1)
        }

        const categorySummary = [...categoryCounts.entries()]
            .sort((left, right) => left[0].localeCompare(right[0]))
            .map(([category, count]) => `${category}(${count})`)
            .join(', ')

        const total = fixes.filter((fix) => fix.applied).length
        const commitMessage = `fix(invariant): auto-fix ${total} vulnerability sinks\n\nFixed: ${categorySummary}\n\nTo revert: git revert HEAD`

        const gitCommit = this.runGit(['commit', '-m', commitMessage])
        if (!gitCommit.ok) {
            this.rollbackFiles(files)
            return null
        }

        const gitHash = this.runGit(['rev-parse', '--short', 'HEAD'])
        if (!gitHash.ok) {
            return null
        }

        return gitHash.stdout.trim()
    }

    revert(commitHash: string): boolean {
        const result = this.runGit(['revert', '--no-edit', commitHash])
        return result.ok
    }

    private getOriginalLine(file: string, line: number, cache: Map<string, string[]>): string | null {
        const lines = this.getFileLines(file, cache)
        if (!lines) return null
        const zeroBased = line - 1
        if (zeroBased < 0 || zeroBased >= lines.length) return null
        return lines[zeroBased]
    }

    private getFileLines(file: string, cache: Map<string, string[]>): string[] | null {
        if (cache.has(file)) {
            return cache.get(file) ?? null
        }

        const absolute = this.toAbsolutePath(file)
        if (!existsSync(absolute)) {
            cache.set(file, [])
            return null
        }

        const lines = readFileSync(absolute, 'utf8').split(/\r?\n/)
        cache.set(file, lines)
        return lines
    }

    private toAbsolutePath(file: string): string {
        return resolve(this.rootDir, file)
    }

    private generateLineFix(category: string, line: string): string | null {
        if (category === 'sqli') return this.generateSqliFix(line)
        if (category === 'xss') return this.generateXssFix(line)
        if (category === 'command_injection') return this.generateCommandInjectionFix(line)
        if (category === 'path_traversal') return this.generatePathTraversalFix(line)
        if (category === 'ssrf') return this.generateSsrfFix(line)
        if (category === 'auth') return this.generateAuthFix(line)
        return null
    }

    private generateSqliFix(line: string): string | null {
        const concatPattern = /(\b(?:[\w$.]+\.)?(?:query|raw|execute|\$queryRaw|\$queryRawUnsafe|\$executeRaw|\$executeRawUnsafe))\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\+\s*([^)]+?)\s*\)/
        const concatMatch = line.match(concatPattern)
        if (concatMatch) {
            const call = concatMatch[1]
            const literal = concatMatch[2]
            const valueExpr = concatMatch[3].trim()
            const sql = this.unquote(literal)

            if (!this.looksLikeSql(sql) || /[`?]/.test(sql) || !valueExpr) {
                return null
            }

            const fixedSql = `${sql}$1`
            const replacement = `${call}(${JSON.stringify(fixedSql)}, [${valueExpr}])`
            return line.replace(concatMatch[0], replacement)
        }

        const templatePattern = /(\b(?:[\w$.]+\.)?(?:query|raw|execute|\$queryRaw|\$queryRawUnsafe|\$executeRaw|\$executeRawUnsafe))\s*\(\s*`([^`]*)\$\{([^}]+)\}([^`]*)`\s*\)/
        const templateMatch = line.match(templatePattern)
        if (templateMatch) {
            const call = templateMatch[1]
            const before = templateMatch[2]
            const expr = templateMatch[3].trim()
            const after = templateMatch[4]

            if (!this.looksLikeSql(before + after)) return null
            if ((before + after).includes('${') || !expr) return null

            const fixedSql = `${before}$1${after}`
            const replacement = `${call}(${JSON.stringify(fixedSql)}, [${expr}])`
            return line.replace(templateMatch[0], replacement)
        }

        return null
    }

    private generateXssFix(line: string): string | null {
        const sendPattern = /\bres\.send\s*\(([^)]+)\)/
        const match = line.match(sendPattern)
        if (!match) return null

        const expression = match[1].trim()
        if (!expression || expression.startsWith('escapeHtml(')) return null

        return line.replace(sendPattern, `res.send(escapeHtml(${expression}))`)
    }

    private generateCommandInjectionFix(line: string): string | null {
        const concatPattern = /\b(?:exec|execSync)\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\+\s*([^)]+?)\s*\)/
        const concatMatch = line.match(concatPattern)
        if (concatMatch) {
            const commandLiteral = this.unquote(concatMatch[1]).trim()
            const extraArg = concatMatch[2].trim()
            const parsed = this.parseCommand(commandLiteral)
            if (!parsed || !extraArg) return null

            const replacement = `spawn(${JSON.stringify(parsed.command)}, [${[...parsed.args.map((arg) => JSON.stringify(arg)), extraArg].join(', ')}], { shell: false })`
            return line.replace(concatMatch[0], replacement)
        }

        const templatePattern = /\b(?:exec|execSync)\s*\(\s*`([^`]*)\$\{([^}]+)\}([^`]*)`\s*\)/
        const templateMatch = line.match(templatePattern)
        if (templateMatch) {
            const before = templateMatch[1]
            const expr = templateMatch[2].trim()
            const after = templateMatch[3]

            if (!expr || after.trim()) return null
            const parsed = this.parseCommand(before.trim())
            if (!parsed) return null

            const replacement = `spawn(${JSON.stringify(parsed.command)}, [${[...parsed.args.map((arg) => JSON.stringify(arg)), expr].join(', ')}], { shell: false })`
            return line.replace(templateMatch[0], replacement)
        }

        return null
    }

    private generatePathTraversalFix(line: string): string | null {
        const pattern = /\b(readFile|readFileSync|fs\.access|fs\.accessSync)\s*\(\s*([^,\)]+)([\s\S]*)\)/
        const match = line.match(pattern)
        if (!match) return null

        const pathArg = match[2].trim()
        if (!this.isSimpleExpression(pathArg)) return null

        return line.replace(match[0], `${match[1]}(assertSafePath(${pathArg})${match[3]})`)
    }

    private generateSsrfFix(line: string): string | null {
        const pattern = /\b(fetch|axios\.(?:get|post|request)|http\.request|https\.request)\s*\(\s*([^,\)]+)([\s\S]*)\)/
        const match = line.match(pattern)
        if (!match) return null

        const target = match[2].trim()
        if (!this.isSimpleExpression(target)) return null

        return line.replace(match[0], `${match[1]}(assertSafeUrl(${target})${match[3]})`)
    }

    private generateAuthFix(line: string): string | null {
        if (line.includes('invariant-autofix: review auth')) return null
        return `${line} // invariant-autofix: review auth hardening manually`
    }

    private looksLikeSql(text: string): boolean {
        return /\b(select|insert|update|delete|with)\b/i.test(text)
    }

    private unquote(value: string): string {
        if (value.length < 2) return value
        const quote = value[0]
        if ((quote !== '"' && quote !== '\'') || value[value.length - 1] !== quote) return value
        return value.slice(1, -1)
    }

    private parseCommand(raw: string): { command: string, args: string[] } | null {
        const pieces = raw.split(/\s+/).filter(Boolean)
        if (pieces.length === 0) return null
        if (/[*|&;$`<>]/.test(raw)) return null

        return {
            command: pieces[0],
            args: pieces.slice(1),
        }
    }

    private isSimpleExpression(value: string): boolean {
        return /^[\w$.\[\]'"`]+$/.test(value)
    }

    private prependImport(content: string, importLine: string): string {
        if (content.includes(importLine)) return content

        const lines = content.split(/\r?\n/)
        let insertAt = 0
        if (lines[0]?.startsWith('#!')) {
            insertAt = 1
        }

        while (insertAt < lines.length && /^\s*\/\//.test(lines[insertAt])) {
            insertAt += 1
        }
        while (insertAt < lines.length && /^\s*\/\*/.test(lines[insertAt])) {
            insertAt += 1
            while (insertAt < lines.length && !/\*\//.test(lines[insertAt])) {
                insertAt += 1
            }
            if (insertAt < lines.length) insertAt += 1
        }

        lines.splice(insertAt, 0, importLine)
        return lines.join('\n')
    }

    private hasEscapeHtmlImport(content: string): boolean {
        return /import\s+escapeHtml\s+from\s+['"]escape-html['"]/.test(content)
    }

    private hasSpawnImport(content: string): boolean {
        if (/import\s+\{\s*[^}]*\bspawn\b[^}]*\}\s+from\s+['"]node:child_process['"]/.test(content)) {
            return true
        }
        if (/import\s+\*\s+as\s+\w+\s+from\s+['"]node:child_process['"]/.test(content)) {
            return true
        }
        return false
    }

    private hasResolvePathImport(content: string): boolean {
        if (/import\s+\{\s*[^}]*\bresolve\s+as\s+resolvePath\b[^}]*\}\s+from\s+['"]node:path['"]/.test(content)) {
            return true
        }
        if (/import\s+\{\s*[^}]*\bresolvePath\b[^}]*\}\s+from\s+['"]node:path['"]/.test(content)) {
            return true
        }
        return false
    }

    private rollbackFiles(files: string[]): void {
        this.runGit(['reset', 'HEAD', '--', ...files])
        this.runGit(['checkout', '--', ...files])
    }

    protected runGit(args: string[]): { ok: boolean, stdout: string, stderr: string } {
        const result = childProcess.spawnSync('git', args, {
            cwd: this.rootDir,
            shell: false,
            encoding: 'utf8',
        })

        return {
            ok: result.status === 0,
            stdout: result.stdout ?? '',
            stderr: result.stderr ?? '',
        }
    }
}
