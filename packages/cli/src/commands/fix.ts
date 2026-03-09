import { createInterface } from 'node:readline'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

import { CodebaseScanner, type ScanFinding } from '../../../engine/src/codebase-scanner.js'
import { AutoFixer } from '../../../engine/src/auto-fixer.js'
import { InvariantEngine } from '../../../engine/src/invariant-engine.js'

interface ScanCache {
    generatedAt: string
    findings: ScanFinding[]
}

export interface InteractiveFixResult {
    total: number
    fixed: number
    skipped: number
    pending: number
}

export interface InteractiveFixOptions {
    projectDir: string
    detector?: InvariantEngine
    findings?: ScanFinding[]
    prompt?: (question: string) => Promise<string>
}

interface FixProgress {
    index: number
    total: number
}

const cachePath = (projectDir: string): string => resolve(projectDir, '.invariant', 'last-scan.json')

function createPrompt(question: string): Promise<string> {
    const readline = createInterface({ input: process.stdin, output: process.stdout })
    return new Promise((resolve) => {
        readline.question(`  ${question}`, (answer) => {
            readline.close()
            resolve(answer.trim().toLowerCase())
        })
    })
}

function saveCache(projectDir: string, findings: ScanFinding[]): void {
    const path = cachePath(projectDir)
    mkdirSync(dirname(path), { recursive: true })
    const payload: ScanCache = {
        generatedAt: new Date().toISOString(),
        findings,
    }
    writeFileSync(path, JSON.stringify(payload, null, 2), 'utf-8')
}

function loadCache(projectDir: string): ScanFinding[] | null {
    const path = cachePath(projectDir)
    if (!existsSync(path)) {
        return null
    }

    try {
        const parsed = JSON.parse(readFileSync(path, 'utf-8')) as ScanCache
        if (!Array.isArray(parsed.findings)) {
            return null
        }

        return parsed.findings
    } catch {
        return null
    }
}

function isLineStillVulnerable(engine: InvariantEngine, line: string, category: string): boolean {
    return engine.detect(line, []).some((match) => match.category === category)
}

function readContext(filePath: string, targetLine: number): string {
    const lines = readFileSync(filePath, 'utf-8').split(/\r?\n/)
    const from = Math.max(1, targetLine - 2)
    const to = Math.min(lines.length, targetLine + 2)

    const out = []
    for (let i = from; i <= to; i += 1) {
        const line = lines[i - 1] ?? ''
        out.push(`${String(i).padStart(4, ' ')}: ${line}`)
    }

    return out.join('\n')
}

function hasLine(filePath: string, line: number): boolean {
    const content = readFileSync(filePath, 'utf-8')
    const lines = content.split(/\r?\n/)
    return line >= 1 && line <= lines.length
}

export async function runInteractiveFix(options: InteractiveFixOptions): Promise<InteractiveFixResult> {
    const projectDir = resolve(options.projectDir)
    const detector = options.detector ?? new InvariantEngine()
    const prompt = options.prompt ?? createPrompt

    let findings = options.findings ?? loadCache(projectDir)

    if (!findings || findings.length === 0) {
        const scanner = new CodebaseScanner({ rootDir: projectDir })
        const scanResult = scanner.scanDirectory()
        findings = scanResult.findings
        saveCache(projectDir, findings)
    }

    const fixer = new AutoFixer(projectDir)
    const fixes = fixer.generateFixes(findings).filter((fix) => fix.fixed !== fix.original)

    if (fixes.length === 0) {
        console.log('  No auto-fix candidates available.')
        return { total: 0, fixed: 0, skipped: 0, pending: 0 }
    }

    let fixedCount = 0
    let skippedCount = 0

    for (let index = 0; index < fixes.length; index += 1) {
        const fix = fixes[index]
        const file = resolve(projectDir, fix.file)
        const progress: FixProgress = { index: index + 1, total: fixes.length }

        if (!existsSync(file) || !hasLine(file, fix.line)) {
            skippedCount += 1
            continue
        }

        console.log(`\n  [${String(progress.index)}/${String(progress.total)}] ${fix.file}:${fix.line} [${fix.category}]`)
        console.log(`  vulnerable: ${fix.original.trim()}`)
        console.log(`  proposed : ${fix.fixed.trim()}`)

        const answer = (await prompt('[Y]es apply fix / [n]o skip / [v]iew context / [q]uit: ')).toLowerCase()

        if (answer === 'q') {
            break
        }

        if (answer === 'v') {
            console.log(readContext(file, fix.line))
            index -= 1
            continue
        }

        if (answer !== 'y' && answer !== 'yes') {
            skippedCount += 1
            continue
        }

        const results = fixer.applyFixes([fix])
        const applied = results.find((entry) => entry.applied)
        if (!applied) {
            console.log('  Failed to apply fix.')
            skippedCount += 1
            continue
        }

        const fixedLine = readFileSync(file, 'utf-8').split(/\r?\n/)[fix.line - 1] ?? ''
        const stillVulnerable = isLineStillVulnerable(detector, fixedLine, fix.category)
        if (stillVulnerable) {
            console.log(`  Applied but detection still triggers for ${fix.category}. Review manually.`)
            skippedCount += 1
        } else {
            fixedCount += 1
            console.log(`  Fixed ${String(fixedCount)} of ${String(fixes.length)} findings`)
        }
    }

    const totalPending = fixes.length - fixedCount - skippedCount
    console.log(`\n  Fixed ${String(fixedCount)} of ${String(fixes.length)} findings`)

    return {
        total: fixes.length,
        fixed: fixedCount,
        skipped: skippedCount,
        pending: totalPending,
    }
}
