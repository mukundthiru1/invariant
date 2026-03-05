/**
 * @santh/agent — Dependency Scanner
 *
 * Reads package-lock.json / yarn.lock / pnpm-lock.yaml.
 * Cross-references every dependency against OSV (Open Source Vulnerabilities) API.
 * OSV is Google's free, comprehensive vulnerability database.
 * Zero API keys required.
 *
 * This runs at startup and daily via interval.
 */

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { InvariantDB, Severity } from '../db.js'

// ── Types ────────────────────────────────────────────────────────

interface PackageLock {
    packages?: Record<string, { version?: string; resolved?: string; name?: string }>
    dependencies?: Record<string, { version: string }>
}

interface OsvVulnerability {
    id: string
    summary?: string
    details?: string
    severity?: Array<{ type: string; score: string }>
    affected?: Array<{
        package?: { ecosystem: string; name: string }
        ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>
    }>
    references?: Array<{ type: string; url: string }>
    database_specific?: { severity?: string }
}

interface OsvBatchResponse {
    results: Array<{ vulns?: OsvVulnerability[] }>
}

interface DependencyEntry {
    name: string
    version: string
}

export interface ScanResult {
    totalDeps: number
    vulnerabilities: VulnResult[]
    scanDuration: number
}

export interface VulnResult {
    package: string
    version: string
    vulnId: string
    summary: string
    severity: Severity
    fixedIn: string | null
}

// ── Lock File Parsers ────────────────────────────────────────────

function parseNpmLock(projectDir: string): DependencyEntry[] {
    const lockPath = join(projectDir, 'package-lock.json')
    if (!existsSync(lockPath)) return []

    const lock: PackageLock = JSON.parse(readFileSync(lockPath, 'utf-8'))
    const deps: DependencyEntry[] = []

    // npm v3+ format (packages key)
    if (lock.packages) {
        for (const [path, info] of Object.entries(lock.packages)) {
            if (path === '') continue // root package
            const name = info.name ?? path.replace(/^node_modules\//, '').replace(/^.*node_modules\//, '')
            if (info.version && name) {
                deps.push({ name, version: info.version })
            }
        }
    }
    // npm v1-v2 format (dependencies key)
    else if (lock.dependencies) {
        for (const [name, info] of Object.entries(lock.dependencies)) {
            deps.push({ name, version: info.version })
        }
    }

    return deps
}

function parseYarnLock(projectDir: string): DependencyEntry[] {
    const lockPath = join(projectDir, 'yarn.lock')
    if (!existsSync(lockPath)) return []

    const content = readFileSync(lockPath, 'utf-8')
    const deps: DependencyEntry[] = []
    const lines = content.split('\n')

    let currentName = ''
    for (const line of lines) {
        // Match package names like "express@^4.18.0":
        const nameMatch = line.match(/^"?(@?[^@\s"]+)@/)
        if (nameMatch) {
            currentName = nameMatch[1]
        }
        // Match version lines like "  version "4.18.2""
        const versionMatch = line.match(/^\s+version\s+"([^"]+)"/)
        if (versionMatch && currentName) {
            deps.push({ name: currentName, version: versionMatch[1] })
            currentName = ''
        }
    }

    return deps
}

function parsePnpmLock(projectDir: string): DependencyEntry[] {
    const lockPath = join(projectDir, 'pnpm-lock.yaml')
    if (!existsSync(lockPath)) return []

    const content = readFileSync(lockPath, 'utf-8')
    const deps: DependencyEntry[] = []

    // Simple extraction — pnpm lock has lines like: /package-name@version:
    const packageRegex = /^\s+\/?(@?[^@\s:]+)@(\d+\.\d+[^:]*?):/gm
    let match: RegExpExecArray | null
    while ((match = packageRegex.exec(content)) !== null) {
        deps.push({ name: match[1], version: match[2] })
    }

    return deps
}

// ── OSV API ──────────────────────────────────────────────────────

function osvSeverity(vuln: OsvVulnerability): Severity {
    // Check database_specific severity first
    const dbSev = vuln.database_specific?.severity?.toLowerCase()
    if (dbSev === 'critical') return 'critical'
    if (dbSev === 'high') return 'high'
    if (dbSev === 'moderate' || dbSev === 'medium') return 'medium'
    if (dbSev === 'low') return 'low'

    // Check CVSS score
    for (const sev of vuln.severity ?? []) {
        const score = parseFloat(sev.score)
        if (!isNaN(score)) {
            if (score >= 9.0) return 'critical'
            if (score >= 7.0) return 'high'
            if (score >= 4.0) return 'medium'
            return 'low'
        }
    }

    return 'medium'
}

function extractFixedVersion(vuln: OsvVulnerability): string | null {
    for (const affected of vuln.affected ?? []) {
        for (const range of affected.ranges ?? []) {
            for (const event of range.events) {
                if (event.fixed) return event.fixed
            }
        }
    }
    return null
}

async function queryOsv(deps: DependencyEntry[]): Promise<VulnResult[]> {
    const results: VulnResult[] = []

    // OSV batch API — query up to 1000 packages at once
    const BATCH_SIZE = 1000
    for (let i = 0; i < deps.length; i += BATCH_SIZE) {
        const batch = deps.slice(i, i + BATCH_SIZE)
        const queries = batch.map(dep => ({
            package: { ecosystem: 'npm', name: dep.name },
            version: dep.version,
        }))

        try {
            const response = await fetch('https://api.osv.dev/v1/querybatch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ queries }),
            })

            if (!response.ok) {
                console.error(`[invariant] OSV API error: ${response.status}`)
                continue
            }

            const data = await response.json() as OsvBatchResponse

            for (let j = 0; j < data.results.length; j++) {
                const vulns = data.results[j]?.vulns ?? []
                const dep = batch[j]

                for (const vuln of vulns) {
                    results.push({
                        package: dep.name,
                        version: dep.version,
                        vulnId: vuln.id,
                        summary: vuln.summary ?? vuln.details?.slice(0, 200) ?? 'No description available',
                        severity: osvSeverity(vuln),
                        fixedIn: extractFixedVersion(vuln),
                    })
                }
            }
        } catch (err) {
            console.error(`[invariant] OSV batch query failed:`, err)
        }
    }

    return results
}

// ── Scanner ──────────────────────────────────────────────────────

export async function scanDependencies(projectDir: string, db: InvariantDB): Promise<ScanResult> {
    const start = Date.now()

    // Parse lock files — try all formats
    let deps: DependencyEntry[] = []
    deps = parseNpmLock(projectDir)
    if (deps.length === 0) deps = parseYarnLock(projectDir)
    if (deps.length === 0) deps = parsePnpmLock(projectDir)

    if (deps.length === 0) {
        return { totalDeps: 0, vulnerabilities: [], scanDuration: Date.now() - start }
    }

    // Deduplicate
    const seen = new Set<string>()
    deps = deps.filter(d => {
        const key = `${d.name}@${d.version}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
    })

    // Store dependency count as asset
    db.setAsset('deps.count', String(deps.length))
    db.setAsset('deps.last_scan', new Date().toISOString())

    // Query OSV for vulnerabilities
    const vulns = await queryOsv(deps)

    // Store findings in database
    const now = new Date().toISOString()
    for (const vuln of vulns) {
        const fixText = vuln.fixedIn ? `Update ${vuln.package} to ${vuln.fixedIn}: npm update ${vuln.package}` : `No fix available yet. Monitor ${vuln.vulnId} for updates.`
        db.insertFinding({
            type: 'dependency_vulnerability',
            category: 'supply_chain',
            severity: vuln.severity,
            status: 'open',
            title: `${vuln.package}@${vuln.version} — ${vuln.vulnId}`,
            description: vuln.summary,
            location: `package-lock.json: ${vuln.package}@${vuln.version}`,
            evidence: JSON.stringify({
                package: vuln.package,
                version: vuln.version,
                vulnId: vuln.vulnId,
                fixedIn: vuln.fixedIn,
            }),
            remediation: fixText,
            cve_id: vuln.vulnId,
            confidence: 0.95,
            first_seen: now,
            last_seen: now,
            rasp_active: false,
        })
    }

    return {
        totalDeps: deps.length,
        vulnerabilities: vulns,
        scanDuration: Date.now() - start,
    }
}
