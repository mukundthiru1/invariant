import { describe, expect, it } from 'vitest'
import { httpSmuggling, xxeInjection } from './misc.js'

describe('legacy misc L2 evaluators', () => {
    it('xxe_injection detectL2 catches external entity payloads', () => {
        const result = xxeInjection.detectL2?.('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>')
        expect(result).not.toBeNull()
        expect(result?.detected).toBe(true)
        expect(result?.confidence).toBeGreaterThan(0.8)
    })

    it('xxe_injection detectL2 does not flag benign xml snippets', () => {
        const result = xxeInjection.detectL2?.('<?xml version="1.0"?><root><name>alice</name></root>')
        expect(result).toBeNull()
    })

    it('http_smuggling detectL2 catches CL/TE ambiguity with escaped CRLF', () => {
        const payload = 'POST / HTTP/1.1\\r\\nHost: target\\r\\nTransfer-Encoding: chunked\\r\\nContent-Length: 0\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1'
        const result = httpSmuggling.detectL2?.(payload)
        expect(result).not.toBeNull()
        expect(result?.detected).toBe(true)
        expect(result?.confidence).toBeGreaterThan(0.85)
    })

    it('http_smuggling detectL2 does not flag normal headers', () => {
        const result = httpSmuggling.detectL2?.('GET / HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Length: 42')
        expect(result).toBeNull()
    })
})
