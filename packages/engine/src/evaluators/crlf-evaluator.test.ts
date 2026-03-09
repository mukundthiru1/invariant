import { describe, expect, it } from 'vitest'
import { detectCRLF } from './crlf-evaluator.js'

describe('CRLF evaluator regressions', () => {
    it('detects encoded CRLF with Set-Cookie injection', () => {
        const detections = detectCRLF('name=%0d%0aSet-Cookie: session=evil')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects encoded LF header injection', () => {
        const detections = detectCRLF('ua=%0aX-Injected-Header: malicious')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects unicode CRLF obfuscation payload', () => {
        const detections = detectCRLF('url=%E5%98%8A%E5%98%8DSet-Cookie: admin=1')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects LF-driven log/header injection payload', () => {
        const detections = detectCRLF('msg=hello%0aconsole: injected')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('does not detect benign percent encoding', () => {
        expect(detectCRLF('name=John%20Doe')).toEqual([])
    })

    it('does not detect benign plus-encoded spaces', () => {
        expect(detectCRLF('greeting=Hello+World')).toEqual([])
    })
})
