import { describe, it, expect, vi } from 'vitest'

vi.mock('../../evaluators/l2-adapters.js', () => ({
    l2SsrfInternal: (() => []) as unknown,
    l2SsrfCloudMetadata: (() => []) as unknown,
    l2SsrfProtocolSmuggle: (() => []) as unknown,
}))

import { ssrfInternalReach, ssrfCloudMetadata, ssrfProtocolSmuggle } from './index.js'

describe('SSRF classes regressions', () => {
    it('detects internal reach bypass payloads', () => {
        const payloads = [
            'http://localtest.me',
            'http://lvh.me',
            'http://yurets.dev',
            'http://1u.ms',
            'http://127-0-0-1.nip.io',
            'http://127.1',
            'http://10.1',
            'http://[0000:0000:0000:0000:0000:0000:0000:0001]',
            'http://[::ffff:0:0]',
            'http://[::1]/',
            'http://[::ffff:127.0.0.1]/',
            'http://[0:0:0:0:0:ffff:7f00:1]/',
            'http://2130706433/',
            'http://0x7f000001/',
            'http://bit.ly/',
            'http://tinyurl.com/',
            'http://t.co/',
            'http://kubernetes.default.svc/',
            'https://10.0.0.1:6443/api/',
        ]

        for (const payload of payloads) {
            expect(ssrfInternalReach.detect(payload), payload).toBe(true)
        }
    })

    it('detects cloud metadata endpoint variants', () => {
        const payloads = [
            'http://169.254.169.254/latest/api/token',
            'http://metadata.google.internal/',
            'http://169.254.169.254/computeMetadata/v1/',
            'http://169.254.169.254/metadata/identity/',
            'http://metadata.digitalocean.com/metadata/v1/',
            'http://169.254.169.254/opc/v2/instance/',
        ]

        for (const payload of payloads) {
            expect(ssrfCloudMetadata.detect(payload), payload).toBe(true)
        }
    })

    it('detects protocol smuggle wrappers', () => {
        const payloads = [
            'php://filter/read=convert.base64-encode/resource=/etc/passwd',
            'expect://ls',
            'data://text/plain;base64,SGVsbG8=',
            'zip://archive.zip#payload.php',
            'gopher://127.0.0.1:6379/_FLUSHALL',
            'dict://127.0.0.1:11211/stat',
        ]

        for (const payload of payloads) {
            expect(ssrfProtocolSmuggle.detect(payload), payload).toBe(true)
        }
    })

    it('preserves known benign behavior', () => {
        const benign = [
            'http://example.com',
            'https://google.com',
            'http://api.github.com',
            'https://example.com',
            'http://api.service.com',
            'ftp.example.com',
            'file attached',
        ]

        for (const payload of benign) {
            expect(ssrfInternalReach.detect(payload)).toBe(false)
            expect(ssrfProtocolSmuggle.detect(payload)).toBe(false)
        }

        const cloudBenign = [
            'http://example.com/metadata',
            '169.254.0.1',
            'google internal docs',
        ]

        for (const payload of cloudBenign) {
            expect(ssrfCloudMetadata.detect(payload)).toBe(false)
        }
    })
})
