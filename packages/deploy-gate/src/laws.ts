import type { ScanResult } from './scanner.js'

export interface DeployLawResult {
  law: 1 | 2 | 3 | 4 | 5 | 6
  name: string
  passed: boolean
  detail: string
}

export interface DeployLawInput {
  repo: string
  gitRef: string
  diffLines: string[]
  scanResults: ScanResult[]
  trivyPassed: boolean
  hasBehaviorModel: boolean
  gitIntegrityPassed?: boolean
}

export function evaluateDeployLaws(input: DeployLawInput): DeployLawResult[] {
  const hasRepoRef = input.repo.trim().length > 0 && input.gitRef.trim().length > 0
  const hasDiff = input.diffLines.length > 0
  const hasInvariantScanCoverage = input.scanResults.length === input.diffLines.length
  const hasBehaviorModel = input.hasBehaviorModel
  const failSafe = input.trivyPassed && hasInvariantScanCoverage && hasDiff

  const laws: DeployLawResult[] = [
    {
      law: 1,
      name: 'No Stubs',
      passed: hasDiff && hasInvariantScanCoverage,
      detail: hasDiff
        ? 'Every diff line was scanned by the invariant engine.'
        : 'No diff provided; deployment cannot be treated as clean.',
    },
    {
      law: 2,
      name: 'Backwards Compatibility',
      passed: hasRepoRef,
      detail: hasRepoRef
        ? 'Required repository and git reference metadata present.'
        : 'Missing repo/gitRef contract fields.',
    },
    {
      law: 3,
      name: 'Architecture Fit',
      passed: hasBehaviorModel,
      detail: hasBehaviorModel
        ? 'Behavioral baseline model is active for this deploy.'
        : 'Behavioral model unavailable; cannot evaluate delta.',
    },
    {
      law: 4,
      name: 'Elegance',
      passed: hasInvariantScanCoverage,
      detail: hasInvariantScanCoverage
        ? 'Single-pass scan coverage matches diff input cardinality.'
        : 'Scan coverage mismatch between diff lines and results.',
    },
    {
      law: 5,
      name: 'Fail Safe',
      passed: failSafe,
      detail: failSafe
        ? 'All safety gates passed; deploy may be auto-approved when clean.'
        : 'Safety gates incomplete; deploy requires explicit human approval.',
    },
  ]

  if (typeof input.gitIntegrityPassed === 'boolean') {
    laws.push({
      law: 6,
      name: 'Git Integrity',
      passed: input.gitIntegrityPassed,
      detail: input.gitIntegrityPassed
        ? 'No force-push or suspected rebase detected in deploy git context.'
        : 'Force-push or suspected rebase detected in deploy git context.',
    })
  }

  return laws
}
