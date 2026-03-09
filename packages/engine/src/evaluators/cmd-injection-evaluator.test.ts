import { describe, expect, it } from 'vitest'
import { detectCmdInjection } from './cmd-injection-evaluator.js'

describe('cmd-injection-evaluator', () => {
    it('detects command separator injection', () => {
        const detections = detectCmdInjection('username=alice;whoami')
        expect(detections.some((d) => d.type === 'separator')).toBe(true)
    })

    it('detects null-byte bypass in shell context', () => {
        const detections = detectCmdInjection('cat /etc/passwd%00;id')
        expect(detections.some((d) => d.separator === 'null-byte')).toBe(true)
    })

    it('does not flag benign text input', () => {
        const detections = detectCmdInjection('report_2026_q1_final.txt')
        expect(detections).toHaveLength(0)
    })
})
