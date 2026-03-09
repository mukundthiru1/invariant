import { spawnSync } from 'node:child_process'

import { AutoFixer } from '../../../engine/src/auto-fixer.js'
import { InvariantEngine, type InvariantMatch } from '../../../engine/src/invariant-engine.js'
import { ALL_CLASS_MODULES, type InvariantClassModule } from '../../../engine/src/classes/index.js'
import type { AttackCategory } from '../../../engine/src/classes/types.js'

import { parseUnifiedDiffToAddedLines, type DiffAddedLine } from './diff.js'

type Severity = 'critical' | 'high' | 'medium' | 'low'
type FixCategory = 'sqli' | 'xss' | 'command_injection' | 'path_traversal' | 'ssrf' | 'auth'

interface GitHubPRFile {
    filename: string
    patch?: string
}

interface GitHubPRInfo {
    head: {
        sha: string
    }
}

interface PRFinding {
    file: string
    line: number
    classId: string
    severity: Severity
    description: string
    snippet: string
    cwe: string
    cvss: string
    mitre: string
    fixSuggestion: string
}

export interface PrOptions {
    projectDir: string
    pr: number
    token?: string
    owner?: string
    repo?: string
    staged?: boolean
    postComments?: boolean
    engine?: InvariantEngine
}

export interface PrResult {
    exitCode: number
    findings: readonly PRFinding[]
    posted: number
}

const DEFAULT_CVSS: Record<Severity, string> = {
    critical: '9.8',
    high: '8.1',
    medium: '5.9',
    low: '3.3',
}

const CLASS_BY_ID = new Map<string, InvariantClassModule>(
    ALL_CLASS_MODULES.map((entry) => [entry.id, entry]),
)

const FIXER_CATEGORY: Record<AttackCategory | 'unknown', FixCategory | null> = {
    sqli: 'sqli',
    xss: 'xss',
    path_traversal: 'path_traversal',
    cmdi: 'command_injection',
    ssrf: 'ssrf',
    auth: 'auth',
    deser: null,
    injection: null,
    smuggling: null,
    unknown: null,
}

function githubApiGet<T>(token: string, url: string): Promise<T> {
    return fetch(url, {
        headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${token}`,
            'X-GitHub-Api-Version': '2022-11-28',
        },
    }).then(async (response) => {
        if (!response.ok) {
            const message = await response.text().catch(() => 'GitHub API request failed')
            throw new Error(`${String(response.status)} ${response.statusText}: ${message}`)
        }

        return response.json() as Promise<T>
    })
}

function githubApiPost<TInput, TOutput>(token: string, url: string, body: TInput): Promise<TOutput> {
    return fetch(url, {
        method: 'POST',
        headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${token}`,
            'X-GitHub-Api-Version': '2022-11-28',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
    }).then(async (response) => {
        if (!response.ok) {
            const message = await response.text().catch(() => 'GitHub API request failed')
            throw new Error(`${String(response.status)} ${response.statusText}: ${message}`)
        }

        return response.json() as Promise<TOutput>
    })
}

function resolveOwnerRepoFromGit(projectDir: string): { owner: string; repo: string } {
    const result = spawnSync('git', ['-C', projectDir, 'remote', 'get-url', 'origin'], { encoding: 'utf8' })
    if (result.error) {
        throw result.error
    }

    if (result.status !== 0) {
        const detail = (result.stderr ?? '').toString().trim()
        throw new Error(`Failed to read git remote: ${detail || 'no origin remote'}`)
    }

    const remote = (result.stdout ?? '').toString().trim()
    const sshMatch = /^git@github\.com:([^/]+)\/([^/.]+)(?:\.git)?$/.exec(remote)
    const httpsMatch = /^https:\/\/github\.com\/([^/]+)\/([^/.]+)(?:\.git)?$/.exec(remote)
    const match = sshMatch ?? httpsMatch

    if (!match) {
        throw new Error(`Unable to parse GitHub remote URL: ${remote}`)
    }

    return { owner: match[1], repo: match[2] }
}

function parseOwnerRepoFromEnv(): { owner: string; repo: string } {
    const raw = process.env.GITHUB_REPOSITORY
    if (!raw) {
        throw new Error('GITHUB_REPOSITORY is not available')
    }

    const [owner, repo] = raw.split('/')
    if (!owner || !repo) {
        throw new Error(`Invalid GITHUB_REPOSITORY value: ${raw}`)
    }

    return { owner, repo }
}

function resolveOwnerRepo(projectDir: string, owner?: string, repo?: string): { owner: string; repo: string } {
    if (owner && repo) {
        return { owner, repo }
    }

    if (owner || repo) {
        throw new Error('owner and repo must be provided together')
    }

    try {
        return resolveOwnerRepoFromGit(projectDir)
    } catch {
        return parseOwnerRepoFromEnv()
    }
}

function detectFromLine(engine: InvariantEngine, addedLine: DiffAddedLine): InvariantMatch[] {
    return engine.detect(addedLine.code, [])
}

function classifyFixCategory(attackCategory: InvariantMatch['category']): FixCategory | null {
    return FIXER_CATEGORY[attackCategory as AttackCategory | 'unknown'] ?? null
}

function chooseFixSuggestion(projectDir: string, file: string, line: number, snippet: string, match: InvariantMatch): string {
    const attackCategory = CLASS_BY_ID.get(match.class)?.category ?? 'unknown'
    const fixCategory = classifyFixCategory(attackCategory)
    if (!fixCategory) {
        return `No safe automatic fix suggestion for ${match.class}.`
    }

    const fixer = new AutoFixer(projectDir)
    const candidates = fixer.generateFixes([{
        file,
        line,
        category: fixCategory,
        sink: match.class,
        snippet,
        severity: match.severity,
        suggestion: '',
        column: 1,
    }])
    const firstFix = candidates.find((item) => item.fixed !== item.original)
    if (!firstFix) {
        return `No safe automatic fix suggestion for ${match.class}.`
    }

    return `Proposed fix: ${firstFix.fixed}`
}

function createComment(finding: PRFinding): string {
    return `⚠ **${finding.classId}** — ${finding.description}\n\nCWE-${finding.cwe} | CVSS ${finding.cvss} | MITRE ${finding.mitre}\n\n${finding.fixSuggestion}`
}

export async function runPrScan(options: PrOptions): Promise<PrResult> {
    const {
        projectDir,
        pr,
        engine = new InvariantEngine(),
        token: tokenInput,
        owner: ownerInput,
        repo: repoInput,
        postComments = true,
    } = options

    const token = tokenInput ?? process.env.GITHUB_TOKEN
    if (!token) {
        throw new Error('Missing GITHUB_TOKEN. Set env var GITHUB_TOKEN before running this command.')
    }

    const { owner, repo } = resolveOwnerRepo(projectDir, ownerInput, repoInput)
    const apiBase = `https://api.github.com/repos/${owner}/${repo}`
    const prInfo = await githubApiGet<GitHubPRInfo>(token, `${apiBase}/pulls/${String(pr)}`)
    const files = await githubApiGet<GitHubPRFile[]>(token, `${apiBase}/pulls/${String(pr)}/files?per_page=100`)

    const findings: PRFinding[] = []

    for (const file of files) {
        if (!file.patch) {
            continue
        }

        const added = parseUnifiedDiffToAddedLines(file.patch, undefined, file.filename)
        for (const addedLine of added) {
            const matches = detectFromLine(engine, { ...addedLine, file: file.filename })
            for (const match of matches) {
                const moduleMeta = CLASS_BY_ID.get(match.class)
                const cwe = moduleMeta?.cwe ?? 'N/A'
                const mitre = moduleMeta?.mitre?.[0] ?? 'N/A'
                findings.push({
                    file: file.filename,
                    line: addedLine.line,
                    classId: match.class,
                    severity: match.severity,
                    description: moduleMeta?.description ?? match.description,
                    snippet: addedLine.code,
                    cwe,
                    cvss: DEFAULT_CVSS[match.severity as Severity],
                    mitre,
                    fixSuggestion: chooseFixSuggestion(projectDir, file.filename, addedLine.line, addedLine.code, match),
                })
            }
        }
    }

    const summary = `⚠ Invariant PR scan found ${String(findings.length)} issues. ` +
        `Critical: ${findings.filter((finding) => finding.severity === 'critical').length}, ` +
        `High: ${findings.filter((finding) => finding.severity === 'high').length}, ` +
        `Medium: ${findings.filter((finding) => finding.severity === 'medium').length}, ` +
        `Low: ${findings.filter((finding) => finding.severity === 'low').length}`

    console.log(summary)

    if (!postComments || findings.length === 0) {
        return {
            exitCode: findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high') ? 1 : 0,
            findings,
            posted: 0,
        }
    }

    const comments = findings.map((finding) => ({
        path: finding.file,
        line: finding.line,
        body: createComment(finding),
        side: 'RIGHT' as const,
    }))

    await githubApiPost<unknown, unknown>(
        token,
        `${apiBase}/pulls/${String(pr)}/reviews`,
        {
            commit_id: prInfo.head.sha,
            event: 'COMMENT',
            body: summary,
            comments,
        },
    )

    return {
        exitCode: findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high') ? 1 : 0,
        findings,
        posted: comments.length,
    }
}
