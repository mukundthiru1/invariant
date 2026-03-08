import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { AutoFixer, type FixResult } from './auto-fixer.js'
import type { ScanFinding } from './codebase-scanner.js'

function makeFinding(file: string, line: number, category: ScanFinding['category'], snippet: string): ScanFinding {
    return {
        file,
        line,
        column: 1,
        category,
        sink: 'test.sink',
        snippet,
        severity: 'high',
        suggestion: 'test suggestion',
    }
}

describe('AutoFixer', () => {
    afterEach(() => {
        vi.restoreAllMocks()
    })

    it('generates SQL fix for string concatenation', () => {
        const dir = mkdtempSync(join(tmpdir(), 'autofix-sql-concat-'))
        const file = 'sample.ts'
        writeFileSync(join(dir, file), 'const result = query("SELECT * FROM users WHERE id = " + id)\n', 'utf8')

        const fixer = new AutoFixer(dir)
        const fixes = fixer.generateFixes([
            makeFinding(file, 1, 'sqli', 'const result = query("SELECT * FROM users WHERE id = " + id)'),
        ])

        expect(fixes).toHaveLength(1)
        expect(fixes[0].fixed).toContain('query("SELECT * FROM users WHERE id = $1", [id])')
    })

    it('generates SQL fix for template literal interpolation', () => {
        const dir = mkdtempSync(join(tmpdir(), 'autofix-sql-template-'))
        const file = 'sample.ts'
        writeFileSync(join(dir, file), 'const result = query(`SELECT * FROM users WHERE id = ${id}`)\n', 'utf8')

        const fixer = new AutoFixer(dir)
        const fixes = fixer.generateFixes([
            makeFinding(file, 1, 'sqli', 'const result = query(`SELECT * FROM users WHERE id = ${id}`)'),
        ])

        expect(fixes).toHaveLength(1)
        expect(fixes[0].fixed).toContain('query("SELECT * FROM users WHERE id = $1", [id])')
    })

    it('generates XSS fix', () => {
        const dir = mkdtempSync(join(tmpdir(), 'autofix-xss-'))
        const file = 'sample.ts'
        writeFileSync(join(dir, file), 'app.get("/", (req, res) => res.send(userInput))\n', 'utf8')

        const fixer = new AutoFixer(dir)
        const fixes = fixer.generateFixes([
            makeFinding(file, 1, 'xss', 'app.get("/", (req, res) => res.send(userInput))'),
        ])

        expect(fixes).toHaveLength(1)
        expect(fixes[0].fixed).toContain('res.send(escapeHtml(userInput))')
    })

    it('generates command injection fix', () => {
        const dir = mkdtempSync(join(tmpdir(), 'autofix-cmdi-'))
        const file = 'sample.ts'
        writeFileSync(join(dir, file), 'exec("ls " + dir)\n', 'utf8')

        const fixer = new AutoFixer(dir)
        const fixes = fixer.generateFixes([
            makeFinding(file, 1, 'command_injection', 'exec("ls " + dir)'),
        ])

        expect(fixes).toHaveLength(1)
        expect(fixes[0].fixed).toContain('spawn("ls", [dir], { shell: false })')
    })

    it('fixes are reversible by restoring original line', () => {
        const dir = mkdtempSync(join(tmpdir(), 'autofix-reverse-'))
        const file = 'sample.ts'
        const original = 'const result = query("SELECT * FROM users WHERE id = " + id)'
        writeFileSync(join(dir, file), `${original}\n`, 'utf8')

        const fixer = new AutoFixer(dir)
        const generated = fixer.generateFixes([
            makeFinding(file, 1, 'sqli', original),
        ])
        const applied = fixer.applyFixes(generated)

        expect(applied[0].applied).toBe(true)
        const changed = readFileSync(join(dir, file), 'utf8')
        expect(changed).toContain('query("SELECT * FROM users WHERE id = $1", [id])')

        const reverseFix: FixResult = {
            file,
            line: 1,
            category: 'sqli',
            description: 'reverse test',
            original: generated[0].fixed,
            fixed: generated[0].original,
            applied: false,
        }

        const reversed = fixer.applyFixes([reverseFix])
        expect(reversed[0].applied).toBe(true)

        const restored = readFileSync(join(dir, file), 'utf8')
        expect(restored).toContain(original)
    })

    it('handles atomic commit failure by attempting checkout rollback', () => {
        const dir = mkdtempSync(join(tmpdir(), 'autofix-atomic-fail-'))
        writeFileSync(join(dir, 'sample.ts'), 'const x = 1\n', 'utf8')

        class MockGitAutoFixer extends AutoFixer {
            calls: string[][] = []

            protected override runGit(args: string[]): { ok: boolean, stdout: string, stderr: string } {
                this.calls.push(args)
                if (args[0] === 'add') return { ok: true, stdout: '', stderr: '' }
                if (args[0] === 'commit') return { ok: false, stdout: '', stderr: 'commit failed' }
                if (args[0] === 'reset' || args[0] === 'checkout') return { ok: true, stdout: '', stderr: '' }
                return { ok: true, stdout: '', stderr: '' }
            }
        }

        const fixer = new MockGitAutoFixer(dir)
        const hash = fixer.atomicCommit([
            {
                file: 'sample.ts',
                line: 1,
                category: 'sqli',
                description: 'test',
                original: 'const x = 1',
                fixed: 'const x = 2',
                applied: true,
            },
        ])

        expect(hash).toBeNull()
        expect(fixer.calls).toContainEqual(['checkout', '--', 'sample.ts'])
    })
})
