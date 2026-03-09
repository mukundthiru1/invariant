import { describe, expect, it } from 'vitest'
import { detectOpenRedirect } from './open-redirect-evaluator.js'

describe('open redirect evaluator regressions', () => {
    it('detects external redirect via redirect parameter', () => {
        const detections = detectOpenRedirect('?redirect=https://evil.com')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects protocol-relative redirect target', () => {
        const detections = detectOpenRedirect('?next=//evil.com')
        expect(detections.some(d => d.type === 'protocol_relative')).toBe(true)
    })

    it('detects javascript URI redirect payload', () => {
        const detections = detectOpenRedirect('?url=javascript:alert(1)')
        expect(detections.some(d => d.type === 'javascript_uri')).toBe(true)
    })

    it('detects backslash redirect bypass', () => {
        const detections = detectOpenRedirect('?goto=\\\\evil.com')
        expect(detections.some(d => d.type === 'backslash')).toBe(true)
    })

    it('detects url-encoded scheme payload', () => {
        const detections = detectOpenRedirect('?return=%68%74%74%70%3a%2f%2fevil.com')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('does not detect local redirect target', () => {
        const detections = detectOpenRedirect('?redirect=https://localhost/callback')
        expect(detections).toEqual([])
    })

    it('does not detect non-url value', () => {
        const detections = detectOpenRedirect('?page=home')
        expect(detections).toEqual([])
    })
})
