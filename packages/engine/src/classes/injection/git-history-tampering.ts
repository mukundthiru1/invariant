import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

// Git push force patterns (--force or -f)
const GIT_PUSH_FORCE_RE = /\bgit\s+push\s+--force\b/i
const GIT_PUSH_FORCE_SHORT_RE = /\bgit\s+push\s+-f(?:\s|$)/i

// Git rebase interactive
const GIT_REBASE_INTERACTIVE_RE = /\bgit\s+rebase\s+-i\b/i

// Git commit amend
const GIT_COMMIT_AMEND_RE = /\bgit\s+commit\s+--amend\b/i

// Git filter-branch (deprecated history rewriter)
const GIT_FILTER_BRANCH_RE = /\bgit\s+filter-branch\b/i

// Git filter-repo (modern history rewriter)
const GIT_FILTER_REPO_RE = /\bgit\s+filter-repo\b/i

// BFG Repo-Cleaner
const BFG_JAR_RE = /\bjava\s+-jar\s+\S*bfg\.jar\b/i
const BFG_CMD_RE = /\bbfg\s+--/i

function isGitHistoryTampering(input: string): boolean {
    return GIT_PUSH_FORCE_RE.test(input) ||
        GIT_PUSH_FORCE_SHORT_RE.test(input) ||
        GIT_REBASE_INTERACTIVE_RE.test(input) ||
        GIT_COMMIT_AMEND_RE.test(input) ||
        GIT_FILTER_BRANCH_RE.test(input) ||
        GIT_FILTER_REPO_RE.test(input) ||
        BFG_JAR_RE.test(input) ||
        BFG_CMD_RE.test(input)
}

export const gitHistoryTampering: InvariantClassModule = {
    id: 'git_history_tampering',
    description: 'Git history rewrite/tampering via force-push, rebase, amend, filter tools, and BFG repo-cleaner',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.91, minInputLength: 10 },
    mitre: ['T1070.004'],
    cwe: 'CWE-693',
    knownPayloads: [
        'git push --force origin main',
        'git push -f',
        'git rebase -i HEAD~3',
        'git commit --amend --no-edit',
        'git filter-branch --tree-filter',
        'java -jar bfg.jar --strip-blobs-bigger-than 10M',
    ],
    knownBenign: [
        'git push origin main',
        'git commit -m "fix: update config"',
        'git rebase feature/branch onto main',
        'git log --oneline',
    ],
    detect: (input: string): boolean => {
        if (input.length < 10) return false
        const decoded = deepDecode(input)
        return isGitHistoryTampering(decoded)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'git push --force origin main',
            'git push -f',
            'git rebase -i HEAD~3',
            'git commit --amend --no-edit',
            'git filter-branch --tree-filter',
            'java -jar bfg.jar --strip-blobs-bigger-than 10M',
        ]
        return variants.slice(0, count)
    },
}
