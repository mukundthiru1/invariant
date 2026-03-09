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
        'http://2130706433',
        'http://0177.0.0.1',
        'http://[::ffff:127.0.0.1]',
        'http://[::ffff:7f00:1]',
        'http://[0:0:0:0:0:0:0:1]',
        'http://[::ffff:7f00:0001]',
        'http://[fe80::1%25lo]',
    ],

    knownBenign: [
        'http://example.com',
        'https://google.com',
        'http://api.github.com',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:https?:\/\/)?(?:127\.\d+(?:\.\d+)*|localhost|0\.0\.0\.0|10\.\d+(?:\.\d+)*|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0x7f|2130706433|017700000001|\[::1?\]|\[0:0:0:0:0:0:0:1\]|\[(?:0000:){7}0001\]|\[::ffff:127\.0\.0\.1\]|\[::ffff:7f00:1\]|\[::ffff:7f00:0001\]|\[::ffff:0:0\]|\[fe80::1(?:%25|%|).*\]|0177\.0\.0\.01|0177\.0\.0\.1|localtest\.me|lvh\.me|yurets\.dev|1u\.ms|\.nip\.io|\.xip\.io|\.sslip\.io)/i.test(d)
    },
    detectL2: l2SsrfInternal,
    generateVariants: (count: number): string[] => {
        const seeds = [
            'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
            'http://10.0.0.1', 'http://192.168.1.1', 'http://172.16.0.1',
            'http://[::1]', 'http://0x7f000001', 'http://2130706433',
            'http://0177.0.0.01', 'http://127.1', 'http://127.0.0.1:8080/admin',
        ]
        const mutated = [
            'HTTP://127.0.0.1',
            'http://0177.0.0.1',
            'http://017700000001',
            '%68%74%74%70://127.0.0.1',
            '%2568%2574%2574%2570%253A%252F%252F127.0.0.1',
            '%48%54%54%50://localhost',
            'http://[::ffff:127.0.0.1]',
            'http://[::ffff:7f00:1]',
            'http://0x7f000001:80',
            'http://2130706433/admin',
        ]
        const v = [...seeds, ...mutated].filter(candidate => ssrfInternalReach.detect(candidate))
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
        'http://168.63.129.16/metadata',
    ],

    knownBenign: [
        'http://example.com/metadata',
        '169.254.0.1',
        'google internal docs',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|metadata\.azure\.com|168\.63\.129\.16/i.test(d)
    },
    detectL2: l2SsrfCloudMetadata,
    generateVariants: (count: number): string[] => {
        const seeds = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://100.100.100.200/latest/meta-data/',
            'http://169.254.169.254/metadata/v1/',
            'http://[fd00:ec2::254]/latest/meta-data/',
        ]
        const mutated = [
            'HTTP://169.254.169.254/latest/meta-data/',
            '%68%74%74%70://169.254.169.254/latest/meta-data/',
            '%2568%2574%2574%2570%253A%252F%252F169.254.169.254%252Flatest%252Fmeta-data%252F',
            'http://metadata.google.internal/computeMetadata/v1/?recursive=true',
            '%68%74%74%70://metadata.google.internal/computeMetadata/v1/',
            'http://168.63.129.16/metadata/instance',
            '%68%74%74%70://100.100.100.200/latest/meta-data/',
            'http://[fd00:ec2::254]:80/latest/meta-data/',
        ]
        const v = [...seeds, ...mutated].filter(candidate => ssrfCloudMetadata.detect(candidate))
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
        const PROTOCOL_RE = /(?:file|gopher|dict|ldap|tftp|ftp|jar|netdoc|phar|expect|data|php|zip):\/\//i
        // Check both decoded (catches encoded bypasses) and raw (catches data:// URIs that
        // deepDecode transforms into data:text/html,... stripping the ://)
        return PROTOCOL_RE.test(d) || PROTOCOL_RE.test(input)
    },
    detectL2: l2SsrfProtocolSmuggle,
    generateVariants: (count: number): string[] => {
        const seeds = [
            'file:///etc/passwd', 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall',
            'dict://127.0.0.1:6379/INFO', 'ldap://evil.com/x',
            'file:///c:/windows/win.ini', 'phar:///tmp/evil.phar',
        ]
        const mutated = [
            'FILE:///etc/passwd',
            '%66%69%6c%65:///%65%74%63/%70%61%73%73%77%64',
            '%2566%2569%256c%2565%253A%252F%252F%252Fetc%252Fpasswd',
            'GOPHER://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO',
            '%67%6f%70%68%65%72://127.0.0.1:6379/_%2a1%0d%0a',
            'dict://127.0.0.1:6379/%49%4e%46%4f',
            'phar:///%74%6d%70/%65%76%69%6c.phar',
        ]
        const v = [...seeds, ...mutated].filter(candidate => ssrfProtocolSmuggle.detect(candidate))
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const SSRF_CLASSES: InvariantClassModule[] = [ssrfInternalReach, ssrfCloudMetadata, ssrfProtocolSmuggle]
