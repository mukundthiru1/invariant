import { describe, it, expect } from 'vitest'
import { deepDecode } from './encoding.js'

describe('Encoding normalizer new fixes', () => {
    it('Fix 1: decodes URL-safe base64 data URIs and standalone', () => {
        // URL-safe standalone and data URI payloads that use '-' for padding/URL-safe alphabet.
        const urlSafeB64 = 'PHNjcmlwdD5hbGVydCgxKTs8L3NjcmlwdD4-'
        const dataUri = `data:text/html;base64,${urlSafeB64}`
        expect(deepDecode(dataUri)).toContain('<script>alert(1);</script>')
        expect(deepDecode(urlSafeB64)).toBe('<script>alert(1);</script>')

        // URL-safe data URI should also decode after '_' conversion.
        const underscorePayload = 'Or0a_KDEM_R0'
        const expectedUnderscore = atob(underscorePayload.replace(/-/g, '+').replace(/_/g, '/'))
        expect(deepDecode(`data:text/html;base64,${underscorePayload}`)).toContain(expectedUnderscore)
    })

    it('Fix 2: normalizes fullwidth characters', () => {
        const fullwidth = '\uFF53\uFF45\uFF4C\uFF45\uFF43\uFF54' // select
        expect(deepDecode(fullwidth)).toBe('select')
    })

    it('Fix 3: decodes %5Cu unicode escapes', () => {
        const payload = '%5Cu003Cscript%5Cu003E'
        expect(deepDecode(payload)).toBe('<script>')
    })

    it('Fix 4: decodes IIS %uXXXX escapes', () => {
        const payload = '%u003Cscript%u003E'
        expect(deepDecode(payload)).toBe('<script>')
    })
})
