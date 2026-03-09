import { describe, expect, it } from 'vitest'
import { detectPathTraversal } from './path-traversal-evaluator.js'

describe('path-traversal-evaluator', () => {
    it('detects root escape via dot-dot traversal', () => {
        const detections = detectPathTraversal('../../../../etc/passwd')
        expect(detections.some((d) => d.type === 'dotdot_escape')).toBe(true)
    })

    it('detects multi-layer encoding bypass', () => {
        const detections = detectPathTraversal('%252e%252e%252fetc%252fpasswd')
        expect(detections.some((d) => d.type === 'encoding_bypass')).toBe(true)
    })

    it('detects traversal in file URLs', () => {
        const detections = detectPathTraversal('file:///../../etc/passwd')
        expect(detections.some((d) => d.type === 'dotdot_escape')).toBe(true)
    })

    it('does not misclassify network URLs as path traversal', () => {
        const detections = detectPathTraversal('https://example.com/../../etc/passwd')
        expect(detections).toHaveLength(0)
    })
})
