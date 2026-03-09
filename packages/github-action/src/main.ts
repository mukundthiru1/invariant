import * as core from '@actions/core'
import { execSync } from 'node:child_process'

import { runActionPrScan, readPullRequestNumberFromEvent } from './pr.js'

type FailOnMode = 'critical' | 'high' | 'medium' | 'any' | 'none'

interface SeverityCounts {
    critical: number
    high: number
    medium: number
    low: number
}

function parseFailOn(raw: string): FailOnMode {
    const value = (raw || 'critical').trim().toLowerCase()
    if (value === 'high' || value === 'medium' || value === 'any' || value === 'none') {
        return value
    }

    return 'critical'
}

function parseRepository(envValue?: string): { owner: string; repo: string } | null {
    if (!envValue) {
        return null
    }

    const [owner, repo] = envValue.split('/')
    if (!owner || !repo) {
        return null
    }

    return { owner, repo }
}

function parseBoolean(raw: string, fallback: boolean): boolean {
    if (!raw) {
        return fallback
    }

    const normalized = raw.trim().toLowerCase()
    if (normalized === 'false' || normalized === '0' || normalized === 'no') {
        return false
    }

    if (normalized === 'true' || normalized === '1' || normalized === 'yes') {
        return true
    }

    return fallback
}

function shouldFail(counts: SeverityCounts, mode: FailOnMode): boolean {
    if (mode === 'none') {
        return false
    }
    if (mode === 'critical') {
        return counts.critical > 0
    }
    if (mode === 'high') {
        return counts.critical > 0 || counts.high > 0
    }
    if (mode === 'medium') {
        return counts.critical > 0 || counts.high > 0 || counts.medium > 0
    }

    return counts.critical > 0 || counts.high > 0 || counts.medium > 0 || counts.low > 0
}

export function generateCOWNERSEntry(): string {
    return `
# Santh Security Controls
.github/workflows/*santh* @santh-security
santh.config.* @santh-security
`.trim()
}

export async function checkSlsaAttestation(artifactPath: string): Promise<boolean> {
    try {
        execSync(`cosign verify-attestation ${artifactPath}`, { stdio: 'ignore' })
        return true
    } catch (err) {
        console.warn('Cosign not found or verification failed for SLSA attestation.')
        return false
    }
}

async function fetchPrDiff(owner: string, repo: string, pr: number, token: string): Promise<string> {
    try {
        const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${pr}`, {
            headers: {
                Accept: 'application/vnd.github.v3.diff',
                Authorization: `Bearer ${token}`,
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'Santh-GitHub-Action'
            }
        })
        if (!response.ok) {
            return ''
        }
        return await response.text()
    } catch (error) {
        console.warn('Failed to fetch PR diff', error)
        return ''
    }
}

async function run(): Promise<void> {
    const token = core.getInput('token') || process.env.GITHUB_TOKEN
    if (!token) {
        core.setFailed('Missing token. Set GITHUB_TOKEN or provide token input.')
        return
    }

    const repository = parseRepository(process.env.GITHUB_REPOSITORY)
    if (!repository) {
        core.setFailed('Missing GITHUB_REPOSITORY env var. Expected owner/repo context.')
        return
    }

    const eventPath = process.env.GITHUB_EVENT_PATH
    if (!eventPath) {
        core.setFailed('Missing GITHUB_EVENT_PATH env var.')
        return
    }

    const pullRequestNumber = readPullRequestNumberFromEvent(eventPath)
    if (!pullRequestNumber) {
        core.setFailed('Unable to determine pull request number from GitHub event payload.')
        return
    }

    const failOn = parseFailOn(core.getInput('fail-on'))
    const postComments = parseBoolean(core.getInput('post-comments'), true)

    const result = await runActionPrScan({
        projectDir: process.cwd(),
        token,
        owner: repository.owner,
        repo: repository.repo,
        pr: pullRequestNumber,
        postComments,
    })

    const prDiff = await fetchPrDiff(repository.owner, repository.repo, pullRequestNumber, token)
    let modifiesSelf = false

    if (prDiff) {
        const files = prDiff.split('diff --git ')
        for (const fileDiff of files) {
            if (!fileDiff.trim()) continue
            
            const lower = fileDiff.toLowerCase()
            
            if (lower.includes('.github/workflows/') && lower.includes('santh')) {
                modifiesSelf = true
            }
            if (lower.includes('santh.config')) {
                modifiesSelf = true
            }
            
            if (lower.includes('package.json')) {
                const lines = fileDiff.split('\n')
                const removesAgent = lines.some(line => line.startsWith('-') && line.includes('@santh/agent'))
                if (removesAgent) {
                    modifiesSelf = true
                }
            }
        }
    }

    const allFindings = [...result.findings] as {
        severity: keyof SeverityCounts
        file: string
        line: number
        classId: string
        description: string
    }[]

    if (modifiesSelf) {
        allFindings.push({
            file: 'santh.config/workflow/package.json',
            line: 1,
            severity: 'critical',
            classId: 'SANTH_SELF_MODIFICATION',
            description: 'This PR modifies or removes Santh security controls — requires explicit security team approval'
        })
    }

    core.setOutput('findings-count', String(allFindings.length))
    core.setOutput('critical-count', String(allFindings.filter((item) => item.severity === 'critical').length))

    const counts: SeverityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    }
    for (const finding of allFindings) {
        counts[finding.severity] += 1
        console.log(`::error file=${finding.file},line=${finding.line}::[${finding.severity}] ${finding.classId} ${finding.description}`)
    }

    if (counts.critical > 0) {
        core.setFailed(`Critical findings detected: ${counts.critical}`)
    }

    if (shouldFail(counts, failOn)) {
        core.setFailed(`Invariant PR scan failed under policy: fail-on=${failOn}`)
    }
}

if (process.env['VITEST'] !== 'true') {
    void run().catch((error) => {
        const message = error instanceof Error ? error.message : 'GitHub Action failed.'
        core.setFailed(message)
    })
}
