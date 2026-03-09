import { EventEmitter } from 'node:events'
import { afterEach, describe, expect, it, vi } from 'vitest'

afterEach(() => {
  vi.restoreAllMocks()
  vi.resetModules()
})

function mockSpawnWithOutput(output: string, emitError = false): void {
  vi.doMock('node:child_process', () => ({
    spawn: () => {
      const stdout = new EventEmitter()
      const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter }
      child.stdout = stdout

      queueMicrotask(() => {
        if (emitError) {
          child.emit('error', new Error('spawn failed'))
        } else {
          if (output.length > 0) {
            stdout.emit('data', Buffer.from(output, 'utf8'))
          }
          child.emit('close', 0)
        }
      })

      return child
    },
  }))
}

describe('trivy', () => {
  it('runTrivyScan gracefully degrades when trivy is unavailable', async () => {
    mockSpawnWithOutput('', true)
    const { runTrivyScan } = await import('./trivy.js')

    const report = await runTrivyScan('.', { mode: 'fs' })
    expect(report.passed).toBe(true)
    expect(report.cves).toEqual([])
  })

  it('runTrivyScan parses vulnerabilities and denied licenses', async () => {
    const trivyJson = JSON.stringify({
      Results: [
        {
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2026-0001',
              Severity: 'CRITICAL',
              PkgName: 'openssl',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Description: 'bad',
            },
          ],
          Licenses: [{ PkgName: 'foo', Name: 'GPL-3.0-only' }],
        },
      ],
    })

    mockSpawnWithOutput(trivyJson)
    const { runTrivyScan } = await import('./trivy.js')

    const report = await runTrivyScan('.', { mode: 'fs', severityThreshold: 'HIGH' })
    expect(report.cves).toHaveLength(1)
    expect(report.licenses[0]?.category).toBe('denied')
    expect(report.passed).toBe(false)
  })

  it('generateSbom returns raw sbom output', async () => {
    mockSpawnWithOutput('{"bomFormat":"CycloneDX"}')
    const { generateSbom } = await import('./trivy.js')

    await expect(generateSbom('.')).resolves.toContain('CycloneDX')
  })
})
