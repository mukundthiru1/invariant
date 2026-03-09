import { spawnSync } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

import { InvariantEngine, type InvariantMatch } from '../../../engine/src/invariant-engine.js'
import { ALL_CLASS_MODULES, type InvariantClassModule } from '../../../engine/src/classes/index.js'

type Severity = 'critical' | 'high' | 'medium' | 'low'

const ANSI = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    green: '\x1b[32m',
}

export interface DiffAddedLine {
    readonly file: string
    readonly line: number
    readonly code: string
}

export interface DiffDetection {
    readonly file: string
    readonly line: number
    readonly classId: string
    readonly severity: Severity
    readonly description: string
    readonly snippet: string
}

export interface DiffScanResult {
    readonly exitCode: number
    readonly findings: readonly DiffDetection[]
    readonly counts: Record<Severity, number>
}

export interface DiffOptions {
    projectDir: string
    staged?: boolean
    engine?: InvariantEngine
}

const CLASS_BY_ID = new Map<string, InvariantClassModule>(
    ALL_CLASS_MODULES.map((entry: InvariantClassModule) => [entry.id, entry]),
)

function normalizeFilePath(rawPath: string, rootDir?: string): string {
    const normalized = rawPath.replace(/^b\//, '').replace(/^a\//, '').trim()
    if (rootDir && normalized) {
        return relative(rootDir, resolve(rootDir, normalized))
    }

    return normalized
}

export function parseUnifiedDiffToAddedLines(
    rawDiff: string,
    rootDir?: string,
    fallbackFile?: string,
): DiffAddedLine[] {
    const lines = rawDiff.split(/\r?\n/)
    const added: DiffAddedLine[] = []

    let currentFile = fallbackFile ? normalizeFilePath(fallbackFile, rootDir) : ''
    let currentNewLine = 0

    for (const line of lines) {
        if (line.startsWith('diff --git ')) {
            currentFile = ''
            currentNewLine = 0
            continue
        }

        if (line.startsWith('--- ')) {
            if (!currentFile) {
                continue
            }
            continue
        }

        if (line.startsWith('+++ ')) {
            const target = line.slice(4).trim()
            if (target === '/dev/null' || target === 'b/dev/null' || target === 'a/dev/null') {
                currentFile = ''
                continue
            }

            currentFile = normalizeFilePath(target, rootDir)
            continue
        }

        if (line.startsWith('@@ ')) {
            const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line)
            if (m) {
                currentNewLine = Number.parseInt(m[1], 10)
            }
            continue
        }

        if (!currentFile || currentNewLine <= 0) {
            continue
        }

        if (line === '\\ No newline at end of file') {
            continue
        }

        const marker = line[0]
        if (marker === '+') {
            if (line.startsWith('+++')) {
                continue
            }

            const code = line.slice(1)
            added.push({ file: currentFile, line: currentNewLine, code })
            currentNewLine += 1
            continue
        }

        if (marker === ' ' || marker === '' || marker === undefined) {
            currentNewLine += 1
            continue
        }

        if (marker === '-') {
            continue
        }
    }

    return added
}

export function printDiffFindings(findings: readonly DiffDetection[]): void {
    if (findings.length === 0) {
        console.log('  No critical/high/medium findings in diff.')
        return
    }

    const bySeverity = findings.slice().sort((left, right) => {
        const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }
        const byLevel = order[left.severity] - order[right.severity]
        if (byLevel !== 0) return byLevel
        const byFile = left.file.localeCompare(right.file)
        if (byFile !== 0) return byFile
        return left.line - right.line
    })

    for (const finding of bySeverity) {
        const color = finding.severity === 'critical'
            ? ANSI.red
            : finding.severity === 'high'
                ? ANSI.yellow
                : ANSI.blue
        console.log(
            `${color}[${finding.severity.toUpperCase()}]${ANSI.reset} ${finding.file}:${String(finding.line)} ${finding.classId}`,
        )
        console.log(`      ${finding.description}`)
        console.log(`      code: ${finding.snippet}`)
    }
}

function runDiff(projectDir: string, staged: boolean): string {
    const args = staged
        ? ['-C', projectDir, 'diff', 'HEAD', '--unified=0']
        : ['-C', projectDir, 'diff', '--unified=0']

    const result = spawnSync('git', args, { encoding: 'utf8' })
    if (result.error) {
        throw result.error
    }

    if (result.status && result.status !== 0) {
        const details = (result.stderr ?? '').toString().trim()
        throw new Error(`git diff failed: ${details || String(result.status)}`)
    }

    return result.stdout.toString()
}

function toDetection(match: InvariantMatch, file: string, line: number, code: string): DiffDetection {
    const mod = CLASS_BY_ID.get(match.class)
    const description = mod?.description ?? match.description

    return {
        file,
        line,
        classId: match.class,
        severity: match.severity,
        description,
        snippet: code.trim(),
    }
}

export function runDiffScan(options: DiffOptions): DiffScanResult {
    const { projectDir, staged = false, engine = new InvariantEngine() } = options
    const absoluteRoot = resolve(projectDir)
    const reportDir = join(absoluteRoot, '.invariant')
    mkdirSync(reportDir, { recursive: true })

    const raw = runDiff(absoluteRoot, staged)
    const addedLines = parseUnifiedDiffToAddedLines(raw, absoluteRoot)
    const detections: DiffDetection[] = []

    for (const { file, line, code } of addedLines) {
        const matches = engine.detect(code, [])
        for (const match of matches) {
            detections.push(toDetection(match, file, line, code))
        }
    }

    printDiffFindings(detections)

    const counts: Record<Severity, number> = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    }
    for (const finding of detections) {
        counts[finding.severity] += 1
    }

    const exitCode = counts.critical > 0 || counts.high > 0 ? 1 : 0

    return {
        exitCode,
        findings: detections,
        counts,
    }
}
