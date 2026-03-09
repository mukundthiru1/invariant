import { afterEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { InvariantAgent } from './index.js'

describe('agent law enforcement', () => {
    const dirs: string[] = []

    afterEach(() => {
        while (dirs.length > 0) {
            const dir = dirs.pop()
            if (!dir) continue
            rmSync(dir, { recursive: true, force: true })
        }
    })

    it('records law violations when fail-open capture is disabled', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'agent-laws-'))
        dirs.push(dir)

        const agent = new InvariantAgent({
            projectDir: dir,
            scanOnStart: false,
            auditOnStart: false,
            autoConfigure: false,
            captureRuntimeExceptions: false,
            rescanInterval: 1,
        })

        await agent.start()
        const report = agent.getLawReport()

        expect(report.stage).toBe('start')
        expect(report.violations.some((law) => law.law === 5)).toBe(true)
        agent.stop()
    })

    it('records law 2 violation for negative rescan interval', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'agent-laws-'))
        dirs.push(dir)

        const agent = new InvariantAgent({
            projectDir: dir,
            scanOnStart: false,
            auditOnStart: false,
            autoConfigure: false,
            rescanInterval: -1,
        })

        await agent.start()
        const report = agent.getLawReport()

        expect(report.violations.some((law) => law.law === 2)).toBe(true)
        agent.stop()
    })
})

