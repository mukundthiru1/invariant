import { readFileSync } from 'node:fs'

import type { PrResult } from '../../cli/src/commands/pr.js'
import { runPrScan } from '../../cli/src/commands/pr.js'

interface GHActionMetadata {
    number?: unknown
    pull_request?: unknown
}

interface GHIssuePayload {
    number?: unknown
    pull_request?: unknown
}

interface GitHubEvent {
    pull_request?: GHActionMetadata
    issue?: GHIssuePayload
}

export interface ActionPrScanOptions {
    projectDir: string
    token: string
    owner?: string
    repo?: string
    pr?: number
    postComments: boolean
}

function asFinitePositiveNumber(value: unknown): number | null {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
        return null
    }

    return Number.isInteger(value) ? value : null
}

export function readPullRequestNumberFromEvent(eventPath: string): number | null {
    let payload: GitHubEvent
    try {
        payload = JSON.parse(readFileSync(eventPath, 'utf8')) as GitHubEvent
    } catch {
        return null
    }

    const direct = asFinitePositiveNumber(payload.pull_request?.number)
    if (direct) {
        return direct
    }

    const issueNumber = asFinitePositiveNumber((payload.issue as GHIssuePayload | undefined)?.number)
    if (issueNumber) {
        const issueIsPullRequest = Boolean(payload.issue?.pull_request)
        return issueIsPullRequest ? issueNumber : null
    }

    return null
}

export async function runActionPrScan(options: ActionPrScanOptions): Promise<PrResult> {
    if (!options.pr || options.pr <= 0) {
        throw new Error('Invalid pull request number')
    }

    return runPrScan({
        projectDir: options.projectDir,
        pr: options.pr ?? 0,
        token: options.token,
        owner: options.owner,
        repo: options.repo,
        postComments: options.postComments,
    })
}
