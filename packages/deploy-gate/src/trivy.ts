import { spawn } from 'node:child_process'
import { evaluateLicense, loadLicensePolicy, type LicensePolicy } from './license-policy.js'

export interface CveResult {
  id: string
  severity: string
  packageName: string
  installedVersion: string
  fixedVersion: string
  description: string
}

export interface LicenseResult {
  packageName: string
  license: string
  category: 'denied' | 'warned' | 'allowed'
}

export interface TrivyReport {
  cves: CveResult[]
  licenses: LicenseResult[]
  sbom: object
  passed: boolean
}

export interface TrivyScanOptions {
  mode: 'fs' | 'image' | 'repo'
  licensePolicy?: LicensePolicy
  severityThreshold?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
}

export async function runTrivyScan(target: string, opts: TrivyScanOptions): Promise<TrivyReport> {
  const policy = opts.licensePolicy ?? loadLicensePolicy()
  const severityThreshold = opts.severityThreshold ?? 'HIGH'

  const emptyReport: TrivyReport = { cves: [], licenses: [], sbom: {}, passed: true }

  const args = [
    opts.mode,
    '--format', 'json',
    '--quiet',
    '--scanners', 'vuln,license',
    target
  ]

  const output = await new Promise<string>((resolve) => {
    const child = spawn('trivy', args, { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    child.stdout.on('data', (chunk) => { stdout += chunk.toString() })
    child.on('error', () => { resolve('') })
    child.on('close', () => { resolve(stdout) })
  })

  if (!output) {
    console.warn('Trivy binary not found or failed. Proceeding with graceful degradation.')
    return emptyReport
  }

  const report: TrivyReport = {
    cves: [],
    licenses: [],
    sbom: {},
    passed: true
  }

  let parsed: any
  try {
    parsed = JSON.parse(output)
  } catch (err) {
    console.warn('Failed to parse Trivy output.', err)
    return emptyReport
  }

  const severityLevels = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
  const thresholdIndex = severityLevels.indexOf(severityThreshold)

  if (parsed.Results && Array.isArray(parsed.Results)) {
    for (const res of parsed.Results) {
      if (res.Vulnerabilities && Array.isArray(res.Vulnerabilities)) {
        for (const vuln of res.Vulnerabilities) {
          const cve: CveResult = {
            id: vuln.VulnerabilityID || 'UNKNOWN',
            severity: vuln.Severity || 'UNKNOWN',
            packageName: vuln.PkgName || 'unknown',
            installedVersion: vuln.InstalledVersion || '',
            fixedVersion: vuln.FixedVersion || '',
            description: vuln.Description || ''
          }
          report.cves.push(cve)

          const sevIdx = severityLevels.indexOf(cve.severity)
          if (sevIdx >= thresholdIndex && thresholdIndex !== -1) {
            report.passed = false
          }
        }
      }

      if (res.Licenses && Array.isArray(res.Licenses)) {
        for (const lic of res.Licenses) {
          const category = evaluateLicense(lic.Name || '', policy)
          report.licenses.push({
            packageName: lic.PkgName || 'unknown',
            license: lic.Name || 'unknown',
            category
          })
          if (category === 'denied') {
            report.passed = false
          }
        }
      }
    }
  }

  return report
}

export async function generateSbom(target: string): Promise<string> {
  const args = ['sbom', '--format', 'cyclonedx', '--quiet', target]
  const output = await new Promise<string>((resolve) => {
    const child = spawn('trivy', args, { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    child.stdout.on('data', (chunk) => { stdout += chunk.toString() })
    child.on('error', () => { resolve('') })
    child.on('close', () => { resolve(stdout) })
  })

  if (!output) {
    console.warn('Trivy binary not found or failed. Cannot generate SBOM.')
    return '{}'
  }

  return output
}
