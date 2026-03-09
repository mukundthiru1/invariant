import type { DetectionLevelResult, InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const FORCE_PUSH_RE = /\bgit\s+push\b(?:(?!\n).)*\s--force(?!-with-lease)(?:\s|$)/i
const FORCE_PUSH_SHORT_RE = /\bgit\s+push\b(?:(?!\n).)*\s-f(?:\s|$)/i
const FORCE_REFSPEC_RE = /\bgit\s+push\b(?:(?!\n).)*\s\+refs(?:\/|:)/i
const REBASE_INTERACTIVE_RE = /\bgit\s+rebase\s+-i(?:\s|$)/i
const COMMIT_AMEND_RE = /\bgit\s+commit\b(?:(?!\n).)*\s--amend(?:\s|$)/i
const FILTER_BRANCH_RE = /\bgit\s+filter-branch(?:\s|$)/i
const FILTER_REPO_RE = /\bgit\s+filter-repo(?:\s|$)/i
const BFG_RE = /\b(?:bfg\.jar|bfg\s+--strip(?:-blobs-bigger-than|-biggest-blobs|-blobs-with-ids)?)(?:\s|$)/i
const RESET_HARD_RE = /\bgit\s+reset\s+--hard(?:\s|$)/i

function isGitHistoryTampering(input: string): boolean {
    return FORCE_PUSH_RE.test(input) ||
        FORCE_PUSH_SHORT_RE.test(input) ||
        FORCE_REFSPEC_RE.test(input) ||
        REBASE_INTERACTIVE_RE.test(input) ||
        COMMIT_AMEND_RE.test(input) ||
        FILTER_BRANCH_RE.test(input) ||
        FILTER_REPO_RE.test(input) ||
        BFG_RE.test(input) ||
        RESET_HARD_RE.test(input)
}

export const gitHistoryTampering: InvariantClassModule = {
    id: 'git_history_tampering',
    description: 'Git history rewrite/tampering via force-push, rebase, amend, filter tools, and hard reset',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.89, minInputLength: 10 },
    mitre: ['T1070.004'],
    cwe: 'CWE-693',
    knownPayloads: [
        'git push --force origin main',
        'git push -f origin develop',
        'git push origin +refs/heads/main:refs/heads/main',
        'git rebase -i HEAD~5',
        'git commit --amend -m "rewrite commit"',
        'git filter-repo --path secrets.txt --invert-paths',
    ],
    knownBenign: [
        'git push origin main',
        'git commit -m "feat: add endpoint"',
        'rebase: fix merge',
        'git push --force-with-lease origin main',
    ],
    detect: (input: string): boolean => {
        if (input.length < 10) return false
        const decoded = deepDecode(input)
        return isGitHistoryTampering(decoded)
    },
    detectL2: (_input: string): DetectionLevelResult | null => null,
    generateVariants: (count: number): string[] => {
        const variants = [
            'git push --force origin release',
            'git push origin +refs/heads/feature:refs/heads/feature',
            'java -jar bfg.jar --strip-blobs-bigger-than 10M repo.git',
            'git reset --hard HEAD~3',
            'git filter-branch --tree-filter "rm -f .env" -- --all',
        ]
        return variants.slice(0, count)
    },
}
