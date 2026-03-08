import { describe, it, expect } from 'vitest'
import { CodebaseScanner, formatReport, toJunitXml, toSarif } from './codebase-scanner.js'
import { join } from 'node:path'
import type { ScanResult } from './codebase-scanner.js'

describe('CodebaseScanner', () => {
    it('scans the engine source without crashing', () => {
        const scanner = new CodebaseScanner({ rootDir: join(__dirname, '.') })
        const result = scanner.scanDirectory()
        expect(result.files).toBeGreaterThan(0)
        expect(result.duration).toBeGreaterThanOrEqual(0)
        expect(Array.isArray(result.findings)).toBe(true)
    })

    it('formatReport produces non-empty output', () => {
        const scanner = new CodebaseScanner({ rootDir: join(__dirname, '.') })
        const result = scanner.scanDirectory()
        const report = formatReport(result)
        expect(report.length).toBeGreaterThan(0)
        expect(report).toContain('Files scanned')
    })

    it('respects extension filter', () => {
        const scanner = new CodebaseScanner({
            rootDir: join(__dirname, '.'),
            extensions: ['.nonexistent'],
        })
        const result = scanner.scanDirectory()
        expect(result.files).toBe(0)
        expect(result.findings).toHaveLength(0)
    })

    it('findings have required fields', () => {
        const scanner = new CodebaseScanner({ rootDir: join(__dirname, '.') })
        const result = scanner.scanDirectory()
        for (const f of result.findings) {
            expect(f.file).toBeTruthy()
            expect(f.line).toBeGreaterThan(0)
            expect(f.category).toBeTruthy()
            expect(f.sink).toBeTruthy()
            expect(f.snippet).toBeTruthy()
            expect(f.severity).toBeTruthy()
            expect(f.suggestion).toBeTruthy()
        }
    })

    it('toSarif returns valid SARIF structure', () => {
        const result: ScanResult = {
            files: 3,
            duration: 4,
            findings: [
                {
                    file: 'src/index.ts',
                    line: 10,
                    column: 5,
                    category: 'sqli',
                    sink: 'db.query(VAR)',
                    snippet: 'db.query(req.body)',
                    severity: 'critical',
                    suggestion: 'Use parameterized query with bound values.',
                },
                {
                    file: 'src/app.tsx',
                    line: 22,
                    column: 12,
                    category: 'xss',
                    sink: 'res.send(VAR)',
                    snippet: 'res.send(userInput)',
                    severity: 'medium',
                    suggestion: 'Encode output before rendering.',
                },
            ],
        }

        const sarif = toSarif(result) as Record<string, unknown>
        expect(sarif).toMatchObject({
            $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
            version: '2.1.0',
        })

        const runs = sarif.runs as Array<Record<string, unknown>>
        expect(runs.length).toBe(1)
        const run = runs[0]
        const driver = (run.tool as Record<string, unknown>).driver as Record<string, unknown>

        expect(driver).toMatchObject({
            name: 'invariant',
            version: '1.0.0',
        })

        const rules = driver.rules as Array<Record<string, unknown>>
        expect(Array.isArray(rules)).toBe(true)

        const sarifFindings = (run.results as Array<Record<string, unknown>>)
        expect(sarifFindings.length).toBe(2)
        for (const finding of sarifFindings) {
            expect(finding.ruleId).toBeTruthy()
            expect(finding.message).toMatchObject({ text: expect.any(String) })
            const location = (finding.locations as Array<Record<string, unknown>>)?.[0] as Record<string, unknown> | undefined
            expect(location).toBeTruthy()
            expect(location?.physicalLocation).toBeTruthy()
        }
    })

    it('toSarif maps severity to SARIF levels correctly', () => {
        const result: ScanResult = {
            files: 1,
            duration: 1,
            findings: [
                {
                    file: 'src/index.ts',
                    line: 1,
                    column: 1,
                    category: 'sqli',
                    sink: 'db.query(VAR)',
                    snippet: 'db.query(req.body)',
                    severity: 'critical',
                    suggestion: 'Use parameterized query with bound values.',
                },
                {
                    file: 'src/index.ts',
                    line: 2,
                    column: 1,
                    category: 'xss',
                    sink: 'res.send(VAR)',
                    snippet: 'res.send(req.body)',
                    severity: 'medium',
                    suggestion: 'Encode output before rendering.',
                },
                {
                    file: 'src/index.ts',
                    line: 3,
                    column: 1,
                    category: 'path_traversal',
                    sink: 'readFile(VAR)',
                    snippet: 'readFile(req.body)',
                    severity: 'low',
                    suggestion: 'Validate and normalize paths.',
                },
            ],
        }

        const sarif = toSarif(result) as Record<string, unknown>
        const findings = (sarif.runs as Array<Record<string, unknown>>)[0].results as Array<Record<string, unknown>>
        const byFile = new Map<string, string>()

        for (const rawFinding of result.findings) {
            const ruleId = `${rawFinding.category}.${rawFinding.sink.toLowerCase().trim().replace(/[^a-z0-9._-]+/gi, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '')}`
            const mapped = findings.find((candidate) => candidate.ruleId === ruleId)?.level as string | undefined
            expect(mapped).toBe(rawFinding.severity === 'medium' ? 'warning' : rawFinding.severity === 'low' ? 'note' : 'error')
            byFile.set(ruleId, mapped ?? 'missing')
        }

        expect(byFile.size).toBe(3)
    })

    it('toJunitXml produces valid XML and captures findings', () => {
        const result: ScanResult = {
            files: 1,
            duration: 3,
            findings: [
                {
                    file: 'src/index.ts',
                    line: 5,
                    column: 7,
                    category: 'sqli',
                    sink: 'db.query(VAR)',
                    snippet: 'db.query(req.body)',
                    severity: 'high',
                    suggestion: 'Use parameterized query with bound values.',
                },
                {
                    file: 'src/index.ts',
                    line: 12,
                    column: 3,
                    category: 'xss',
                    sink: 'res.send(VAR)',
                    snippet: 'res.send(req.body)',
                    severity: 'low',
                    suggestion: 'Encode output before rendering.',
                },
            ],
        }

        const xml = toJunitXml(result)
        expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>')
        expect(xml).toContain('<testsuites tests="2" failures="2"')
        expect(xml).toContain('<testsuite name="invariant.sqli" tests="1" failures="1">')
        expect(xml).toContain('<testsuite name="invariant.xss" tests="1" failures="1">')
        expect(xml).toContain('<failure')
    })

    it('toSarif and toJunitXml handle empty results', () => {
        const result: ScanResult = {
            files: 0,
            duration: 0,
            findings: [],
        }

        const sarif = toSarif(result) as Record<string, unknown>
        const runs = sarif.runs as Array<Record<string, unknown>>
        expect((runs[0].results as Array<unknown>).length).toBe(0)

        const xml = toJunitXml(result)
        expect(xml).toContain('<testsuite name="invariant.sqli" tests="0" failures="0">')
        expect(xml).toContain('<testsuite name="invariant.auth" tests="0" failures="0">')
        expect(xml).toContain('<testsuites tests="0" failures="0">')
    })
})
