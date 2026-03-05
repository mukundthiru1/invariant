/**
 * Path Traversal Invariant Classes — All 4
 * (Added path_normalization_bypass)
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const pathDotdotEscape: InvariantClassModule = {
    id: 'path_dotdot_escape',
    description: 'Use ../ sequences to escape the webroot and access arbitrary files',
    category: 'path_traversal',
    severity: 'high',
    calibration: { baseConfidence: 0.88, minInputLength: 6 },

    mitre: ['T1083'],
    cwe: 'CWE-22',

    knownPayloads: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
    ],

    knownBenign: [
        '/home/user/documents',
        'file.txt',
        './local-file.js',
        '../sibling-dir',
        'https://example.com/path',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:\.{2,}[\/\\]+){2,}/i.test(d) ||
            /(?:\.\.%2[fF]|%2[eE]%2[eE]%2[fF]|\.\.%5[cC]){2,}/.test(input)
    },
    generateVariants: (count: number): string[] => {
        const targets = ['/etc/passwd', '/etc/shadow', '/proc/self/environ', '/windows/win.ini']
        const prefixes = [
            '../../../', '..\\..\\..\\', '....//....//....//..../',
            '..%2F..%2F..%2F', '..%252F..%252F..%252F',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f', '..%c0%af..%c0%af..%c0%af', '..%5c..%5c..%5c',
        ]
        const v: string[] = []
        for (let i = 0; i < count; i++) v.push(prefixes[i % prefixes.length] + targets[i % targets.length])
        return v
    },
}

export const pathNullTerminate: InvariantClassModule = {
    id: 'path_null_terminate',
    description: 'Null byte injection to truncate file extension checks',
    category: 'path_traversal',
    severity: 'high',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1083'],
    cwe: 'CWE-158',

    knownPayloads: [
        '../../../etc/passwd%00.jpg',
        'shell.php%00.gif',
        '/etc/passwd\\x00.html',
    ],

    knownBenign: [
        'image.jpg',
        'document.pdf',
        'style.css',
        '100% complete',
    ],

    detect: (input: string): boolean => /%00|\\x00|\\0|\0/.test(input),
    generateVariants: (count: number): string[] => {
        const v = [
            '../../../etc/passwd%00.jpg', '..\\..\\..\\etc\\passwd%00.png',
            'shell.php%00.gif', '/etc/passwd\\x00.html',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const pathEncodingBypass: InvariantClassModule = {
    id: 'path_encoding_bypass',
    description: 'Multi-layer encoding to bypass path traversal filters',
    category: 'path_traversal',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },

    mitre: ['T1083'],
    cwe: 'CWE-22',

    knownPayloads: [
        '%252e%252e%252fetc%252fpasswd',
        '..%c0%af..%c0%afetc/passwd',
        '..%e0%80%ae/etc/passwd',
    ],

    knownBenign: [
        'hello%20world',
        '/api/users',
        'filename.txt',
        '%E2%9C%93 check mark',
    ],

    detect: (input: string): boolean => {
        return /%252[eE]%252[eE]|%25252|%c0%ae|%c0%af|%e0%80%ae|\.%00\./.test(input) ||
            /\/etc\/(?:passwd|shadow|hosts)|\/proc\/self\/(?:environ|cmdline|maps)|\/windows\/(?:system32|win\.ini)/i.test(deepDecode(input))
    },
    generateVariants: (count: number): string[] => {
        const v = [
            '%252e%252e%252fetc%252fpasswd', '..%c0%af..%c0%afetc/passwd',
            '..%e0%80%ae/etc/passwd', '%25252e%25252e%25252f',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const pathNormalizationBypass: InvariantClassModule = {
    id: 'path_normalization_bypass',
    description: 'Path normalization tricks (trailing dots, reserved names, backslash→slash) to bypass access controls',
    category: 'path_traversal',
    severity: 'high',
    calibration: { baseConfidence: 0.80 },

    mitre: ['T1083'],
    cwe: 'CWE-22',

    knownPayloads: [
        '/admin../',
        '/Admin%20/',
        '/admin;/secret',
        '/admin;jsessionid=x/secret',
        '/api/v1/admin\\secret',
    ],

    knownBenign: [
        '/api/users',
        '/home/page',
        '/about',
        '/contact-us',
        '/images/logo.png',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // Trailing dots in path segments (IIS/Windows normalization)
        if (/\/[^\/]+\.{2,}\//.test(d)) return true
        // Trailing spaces in path segments
        if (/\/[^\/]+\s+\//.test(d)) return true
        // Semicolon path parameter injection (Tomcat, Spring)
        if (/\/[^\/]+;[^\/]*\//.test(d)) return true
        // Backslash as path separator targeting sensitive paths (IIS/Windows normalization on Unix)
        if (/^\/.*\\.*\w/.test(d) && /\/(?:admin|config|internal|secret|private|\.env|\.git)[\\/]/i.test(d)) return true
        return false
    },
    generateVariants: (count: number): string[] => {
        const v = [
            '/admin/.', '/admin../', '/admin%20/',
            '/admin;jsessionid=x/secret', '/admin\\secret',
            '/ADMIN/./secret', '/api/v1/admin%09/secret',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const PATH_CLASSES: InvariantClassModule[] = [pathDotdotEscape, pathNullTerminate, pathEncodingBypass, pathNormalizationBypass]
