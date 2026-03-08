/**
 * SSRF Invariant Classes — All 3
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2SsrfInternal, l2SsrfCloudMetadata, l2SsrfProtocolSmuggle } from '../../evaluators/l2-adapters.js'

export const ssrfInternalReach: InvariantClassModule = {
    id: 'ssrf_internal_reach',
    description: 'Reach internal network addresses through server-side request',
    category: 'ssrf',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },

    mitre: ['T1090', 'T1018'],
    cwe: 'CWE-918',

    knownPayloads: [
        'http://127.0.0.1',
        'http://localhost',
        'http://10.0.0.1',
        'http://192.168.1.1',
        'http://[::1]',
        'http://0x7f000001',
    ],

    knownBenign: [
        'http://example.com',
        'https://google.com',
        'http://api.github.com',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:https?:\/\/)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0x7f|2130706433|017700000001|\[::1?\]|0177\.0\.0\.01)/i.test(d)
    },
    detectL2: l2SsrfInternal,
    generateVariants: (count: number): string[] => {
        const v = [
            'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
            'http://10.0.0.1', 'http://192.168.1.1', 'http://172.16.0.1',
            'http://[::1]', 'http://0x7f000001', 'http://2130706433',
            'http://0177.0.0.01', 'http://127.1', 'http://127.0.0.1:8080/admin',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const ssrfCloudMetadata: InvariantClassModule = {
    id: 'ssrf_cloud_metadata',
    description: 'Access cloud provider metadata endpoints to steal credentials/tokens',
    category: 'ssrf',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },

    mitre: ['T1552.005'],
    cwe: 'CWE-918',

    knownPayloads: [
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://100.100.100.200/latest/meta-data/',
    ],

    knownBenign: [
        'http://example.com/metadata',
        '169.254.0.1',
        'google internal docs',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|metadata\.azure\.com/i.test(d)
    },
    detectL2: l2SsrfCloudMetadata,
    generateVariants: (count: number): string[] => {
        const v = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://100.100.100.200/latest/meta-data/',
            'http://169.254.169.254/metadata/v1/',
            'http://[fd00:ec2::254]/latest/meta-data/',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const ssrfProtocolSmuggle: InvariantClassModule = {
    id: 'ssrf_protocol_smuggle',
    description: 'Use non-HTTP protocol handlers (file://, gopher://) to access internal resources',
    category: 'ssrf',
    severity: 'critical',
    calibration: { baseConfidence: 0.92 },

    mitre: ['T1090'],
    cwe: 'CWE-918',

    knownPayloads: [
        'file:///etc/passwd',
        'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall',
        'dict://127.0.0.1:6379/INFO',
        'phar:///tmp/evil.phar',
    ],

    knownBenign: [
        'https://example.com',
        'http://api.service.com',
        'ftp.example.com',
        'file attached',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:file|gopher|dict|ldap|tftp|ftp|jar|netdoc|phar):\/\//i.test(d)
    },
    detectL2: l2SsrfProtocolSmuggle,
    generateVariants: (count: number): string[] => {
        const v = [
            'file:///etc/passwd', 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall',
            'dict://127.0.0.1:6379/INFO', 'ldap://evil.com/x',
            'file:///c:/windows/win.ini', 'phar:///tmp/evil.phar',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const SSRF_CLASSES: InvariantClassModule[] = [ssrfInternalReach, ssrfCloudMetadata, ssrfProtocolSmuggle]