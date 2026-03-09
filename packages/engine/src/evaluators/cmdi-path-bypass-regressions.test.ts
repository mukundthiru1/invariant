import { describe, expect, it } from 'vitest'
import { detectCmdInjection } from './cmd-injection-evaluator.js'
import { detectPathTraversal } from './path-traversal-evaluator.js'

describe('cmd/path evaluator bypass regressions', () => {
    it('detects quote fragmentation when null byte is embedded', () => {
        const detections = detectCmdInjection("w\x00'o'r'k")
        expect(detections.some(d => d.type === 'quote_fragmentation')).toBe(true)
    })

    it('detects quote fragmentation when CRLF is used to split fragments', () => {
        const detections = detectCmdInjection("w\r\n'o'r'k")
        expect(detections.some(d => d.type === 'quote_fragmentation')).toBe(true)
    })

    it('detects file:// traversal URL payloads', () => {
        const detections = detectPathTraversal('file:///../../../etc/passwd')
        expect(detections.some(d => d.type === 'dotdot_escape')).toBe(true)
    })

    it('detects file:// URLs containing /../ segments', () => {
        const detections = detectPathTraversal('file://localhost/tmp/../etc/passwd')
        expect(detections.some(d => d.type === 'dotdot_escape' && d.confidence >= 0.95)).toBe(true)
    })
})
