import * as core from '@actions/core'
import * as github from '@actions/github'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { isAbsolute, join, relative, resolve } from 'node:path'

import { CodebaseScanner, toSarif, type ScanFinding, type ScanResult } from '../../engine/src/codebase-scanner.js'

type Severity = 'critical' | 'high' | 'medium' | 'low'
type FailOnMode = 'critical' | 'high' | 'medium' | 'any' | 'none'

type ThresholdOverrides = Record<Severity, number>

interface ActionInputs {
    path: string
    extensions: string[]
    exclude: string[]
    failOn: FailOnMode
}

const DEFAULT_EXTENSIONS = ['.ts', '.js', '.tsx', '.jsx']
const DEFAULT_EXCLUDE = ['node_modules', '.git', 'dist', 'build']

const severityRank: Record<Severity, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
}

function parseList(input: string, fallback: string[]): string[] {
    const entries = input
        .split(',')
        .map(value => value.trim())
        .filter(value => value.length > 0)

    return entries.length > 0 ? entries : fallback
}

function normalizeFailOn(raw: string): FailOnMode {
    const value = raw.trim().toLowerCase()
    if (value === 'critical' || value === 'high' || value === 'medium' || value === 'any' || value === 'none') {
        return value
    }

    return 'high'
}

function makeInputs(): ActionInputs {
    return {
        path: core.getInput('path') || '.',
        extensions: parseList(core.getInput('extensions'), DEFAULT_EXTENSIONS),
        exclude: parseList(core.getInput('exclude'), DEFAULT_EXCLUDE),
        failOn: normalizeFailOn(core.getInput('fail-on') || 'high'),
    }
}

function defaultThresholdOverrides(): ThresholdOverrides {
    return {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    }
}

function readThresholdOverrides(scanRoot: string): ThresholdOverrides {
    const configPath = join(scanRoot, 'invariant.config.json')
    const overrides = defaultThresholdOverrides()

    if (!existsSync(configPath)) {
        return overrides
    }

    try {
        const raw = JSON.parse(readFileSync(configPath, 'utf8')) as {
            thresholds?: Partial<Record<Severity, unknown>>
        }

        const thresholds = raw.thresholds
        if (!thresholds || typeof thresholds !== 'object') {
            return overrides
        }

        for (const severity of Object.keys(overrides) as Severity[]) {
            const value = thresholds[severity]
            if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
                overrides[severity] = Math.floor(value)
            }
        }

        core.info(`Loaded threshold overrides from ${configPath}`)
        return overrides
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        core.warning(`Unable to parse invariant.config.json; using defaults. ${message}`)
        return overrides
    }
}

function scanCodebase(scanRoot: string, extensions: string[], exclude: string[]): ScanResult {
    const scanner = new CodebaseScanner({
        rootDir: scanRoot,
        extensions,
        exclude,
    })

    return scanner.scanDirectory()
}

function toAnnotationFile(scanRoot: string, findingFile: string): string {
    const absolute = isAbsolute(findingFile) ? findingFile : resolve(scanRoot, findingFile)
    return relative(process.cwd(), absolute)
}

function annotateFinding(scanRoot: string, finding: ScanFinding): void {
    const annotation: core.AnnotationProperties = {
        file: toAnnotationFile(scanRoot, finding.file),
        startLine: finding.line,
        endLine: finding.line,
        startColumn: finding.column,
        endColumn: finding.column,
        title: `${finding.severity.toUpperCase()} ${finding.category}`,
    }

    const message = `${finding.sink} - ${finding.suggestion}`

    if (finding.severity === 'critical' || finding.severity === 'high') {
        core.error(message, annotation)
        return
    }

    if (finding.severity === 'medium') {
        core.warning(message, annotation)
        return
    }

    core.notice(message, annotation)
}

function createSeverityCounts(findings: ScanFinding[]): Record<Severity, number> {
    const counts: Record<Severity, number> = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    }

    for (const finding of findings) {
        counts[finding.severity] += 1
    }

    return counts
}

function createCategoryCounts(findings: ScanFinding[]): Record<string, number> {
    const counts: Record<string, number> = {}

    for (const finding of findings) {
        const key = finding.category
        counts[key] = (counts[key] ?? 0) + 1
    }

    return counts
}

function failSeverities(mode: FailOnMode): Severity[] {
    if (mode === 'none') return []
    if (mode === 'critical') return ['critical']
    if (mode === 'high') return ['critical', 'high']
    if (mode === 'medium') return ['critical', 'high', 'medium']
    return ['critical', 'high', 'medium', 'low']
}

function evaluateFailure(
    severityCounts: Record<Severity, number>,
    mode: FailOnMode,
    overrides: ThresholdOverrides,
): { shouldFail: boolean, reasons: string[] } {
    const reasons: string[] = []
    const severities = failSeverities(mode)

    for (const severity of severities) {
        const count = severityCounts[severity]
        const allowed = overrides[severity]
        if (count > allowed) {
            reasons.push(`${severity}: ${String(count)} (allowed ${String(allowed)})`)
        }
    }

    return {
        shouldFail: reasons.length > 0,
        reasons,
    }
}

function formatSummaryComment(
    scanRoot: string,
    failOn: FailOnMode,
    findings: ScanFinding[],
    severityCounts: Record<Severity, number>,
    categoryCounts: Record<string, number>,
): string {
    const categoryLines = Object.entries(categoryCounts)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([category, count]) => `| ${category} | ${String(count)} |`)

    const topFindings = [...findings]
        .sort((left, right) => {
            const severityDelta = severityRank[right.severity] - severityRank[left.severity]
            if (severityDelta !== 0) return severityDelta
            const fileDelta = left.file.localeCompare(right.file)
            if (fileDelta !== 0) return fileDelta
            return left.line - right.line
        })
        .slice(0, 20)

    const lines = [
        '## Invariant Security Scan',
        `- **Path:** ${scanRoot}`,
        `- **Fail on:** ${failOn}`,
        `- **Total findings:** ${String(findings.length)}`,
        `- **Critical:** ${String(severityCounts.critical)}`,
        `- **High:** ${String(severityCounts.high)}`,
        `- **Medium:** ${String(severityCounts.medium)}`,
        `- **Low:** ${String(severityCounts.low)}`,
    ]

    if (categoryLines.length > 0) {
        lines.push('', '### Findings by Category', '| Category | Count |', '| --- | ---: |')
        lines.push(...categoryLines)
    }

    if (topFindings.length > 0) {
        lines.push('', '### Top Findings')
        for (const finding of topFindings) {
            lines.push(`- ${finding.file}:${String(finding.line)} [${finding.severity.toUpperCase()}] ${finding.category} - ${finding.sink}`)
        }
    } else {
        lines.push('', 'No findings detected in this scan.')
    }

    return lines.join('\n')
}

function extractPullRequestNumber(payload: Record<string, unknown>): number | null {
    const direct = payload.pull_request
    if (direct && typeof direct === 'object' && 'number' in direct) {
        const numberValue = direct.number
        return typeof numberValue === 'number' ? numberValue : null
    }

    const issue = payload.issue
    if (issue && typeof issue === 'object' && 'number' in issue) {
        const isPullRequestEvent = (issue as { pull_request?: unknown }).pull_request || payload.pull_request
        if (!isPullRequestEvent) {
            return null
        }

        return typeof issue.number === 'number' ? issue.number : null
    }

    return null
}

async function postPullRequestComment(body: string): Promise<void> {
    const payload = github.context.payload as Record<string, unknown>
    const pullRequestNumber = extractPullRequestNumber(payload)

    if (pullRequestNumber === null || Number.isNaN(pullRequestNumber)) {
        core.debug('No pull request context detected; skipping PR comment')
        return
    }

    const token = process.env.GITHUB_TOKEN
    if (!token) {
        core.warning('GITHUB_TOKEN is not available; skipping PR comment')
        return
    }

    try {
        const octokit = github.getOctokit(token)
        await octokit.rest.issues.createComment({
            owner: github.context.repo.owner,
            repo: github.context.repo.repo,
            issue_number: pullRequestNumber,
            body,
        })
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unable to post PR comment'
        core.warning(`Failed to post PR comment: ${message}`)
    }
}

async function uploadSarifIfAvailable(sarifPath: string): Promise<void> {
    const importer = new Function('specifier', 'return import(specifier)')
    try {
        const module = await importer('@actions/upload-sarif')
        const uploadSarif = (module as { uploadSarif?: unknown }).uploadSarif
            || (module as { default?: unknown }).default

        if (typeof uploadSarif !== 'function') {
            core.info('actions/upload-sarif is available but does not expose upload function; skipping.')
            return
        }

        const upload = uploadSarif as (input: Record<string, unknown>) => Promise<void> | void
        const payloads: Array<Record<string, unknown>> = [
            { sarif_file: sarifPath },
            { sarifFile: sarifPath },
            { sarif_file: sarifPath, checkout_path: process.cwd() },
        ]

        for (const payload of payloads) {
            try {
                await upload(payload)
                core.info(`Uploaded SARIF report to GitHub Security: ${sarifPath}`)
                return
            } catch {
                continue
            }
        }

        core.warning('actions/upload-sarif was found but could not be executed. Skipping.')
    } catch {
        core.debug('actions/upload-sarif package not available; SARIF upload skipped.')
    }
}

function writeSarifReport(scanResult: ScanResult, scanRoot: string): string {
    const sarif = toSarif(scanResult)
    const path = join(scanRoot, 'invariant.codescan.sarif')
    writeFileSync(path, JSON.stringify(sarif, null, 2), 'utf-8')
    core.info(`Wrote SARIF report to ${path}`)
    return path
}

async function run(): Promise<void> {
    const inputs = makeInputs()
    const scanRoot = resolve(inputs.path)

    core.info(`Scanning path: ${scanRoot}`)
    core.info(`Extensions: ${inputs.extensions.join(', ')}`)
    core.info(`Exclude: ${inputs.exclude.join(', ')}`)
    core.info(`Fail on: ${inputs.failOn}`)

    let scanResult: ScanResult

    try {
        scanResult = scanCodebase(scanRoot, inputs.extensions, inputs.exclude)
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown scan error'
        core.setOutput('findings-count', '0')
        core.setOutput('critical-count', '0')
        core.setOutput('high-count', '0')
        core.setFailed(`Invariant scanner failed: ${message}`)
        return
    }

    const findings = scanResult.findings
    const severityCounts = createSeverityCounts(findings)
    const categoryCounts = createCategoryCounts(findings)
    const thresholdOverrides = readThresholdOverrides(scanRoot)

    for (const finding of findings) {
        annotateFinding(scanRoot, finding)
    }

    core.setOutput('findings-count', String(findings.length))
    core.setOutput('critical-count', String(severityCounts.critical))
    core.setOutput('high-count', String(severityCounts.high))

    const comment = formatSummaryComment(
        scanRoot,
        inputs.failOn,
        findings,
        severityCounts,
        categoryCounts,
    )

    const sarifPath = writeSarifReport(scanResult, scanRoot)
    await uploadSarifIfAvailable(sarifPath)
    await postPullRequestComment(comment)

    const failure = evaluateFailure(severityCounts, inputs.failOn, thresholdOverrides)

    if (failure.shouldFail) {
        core.setFailed(`Invariant scan failed thresholds (${failure.reasons.join(', ')})`)
    }
}

void run().catch((error) => {
    const message = error instanceof Error ? error.message : 'Unknown action error'
    core.setFailed(`Invariant Security Scan failed: ${message}`)
})
