/**
 * Path Traversal Invariant Classes — All 5
 * (Added path_normalization_bypass + path_windows_traversal)
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2PathDotdot, l2PathNull, l2PathEncoding, l2PathNormalization, l2WindowsPathTraversal } from '../../evaluators/l2-adapters.js'

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
        'file:///../../../etc/passwd',
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
    detectL2: l2PathDotdot,
    generateVariants: (count: number): string[] => {
        const targets = ['/etc/passwd', '/etc/shadow', '/proc/self/environ', '/windows/win.ini']
        const seedPrefixes = [
            '../../../', '..\\..\\..\\', '....//....//....//..../',
            '..%2F..%2F..%2F', '..%252F..%252F..%252F',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f', '..%c0%af..%c0%af..%c0%af', '..%5c..%5c..%5c',
        ]
        const mutationPrefixes = [
            '%252e%252e%252f%252e%252e%252f%252e%252e%252f',
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f',
            '..\\..\\..\\',
            '..%2f..%2f..%2f',
            '..%252f..%252f..%252f',
        ]
        const prefixes = [...seedPrefixes, ...mutationPrefixes]
        const v: string[] = []
        for (let i = 0; i < count; i++) v.push(prefixes[i % prefixes.length] + targets[i % targets.length])
        return v.filter(candidate => pathDotdotEscape.detect(candidate))
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
    detectL2: l2PathNull,
    generateVariants: (count: number): string[] => {
        const seeds = [
            '../../../etc/passwd%00.jpg', '..\\..\\..\\etc\\passwd%00.png',
            'shell.php%00.gif', '/etc/passwd\\x00.html',
        ]
        const mutated = [
            '../etc/passwd%00.jpg',
            '..%2f..%2f..%2fetc%2fpasswd%00.png',
            '..%252f..%252fetc%252fpasswd%2500.jpg',
            '..%c0%af..%c0%afetc/passwd%00.gif',
            '..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd%00.jpg',
        ]
        const v = [...seeds, ...mutated].filter(candidate => pathNullTerminate.detect(candidate))
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
        // Multi-layer encoding patterns are always suspicious
        if (/%252[eE]%252[eE]|%25252|%c0%ae|%c0%af|%e0%80%ae|\.%00\./.test(input)) return true
        // Sensitive system paths require traversal context (../ prefix, encoded dots,
        // or the path being the dominant content — not just mentioned in English prose)
        const d = deepDecode(input)
        const sensitivePathRe = /\/etc\/(?:passwd|shadow|hosts)|\/proc\/self\/(?:environ|cmdline|maps)|\/windows\/(?:system32|win\.ini)/i
        if (sensitivePathRe.test(d)) {
            // Require traversal prefix OR the sensitive path is near-total input content
            const hasTraversal = /(?:\.\.[\\/]|%2e|%252e)/i.test(input)
            const pathMatch = sensitivePathRe.exec(d)
            const isPathDominant = pathMatch && d.trim().length < pathMatch[0].length * 3
            return hasTraversal || !!isPathDominant
        }
        return false
    },
    detectL2: l2PathEncoding,
    generateVariants: (count: number): string[] => {
        const seeds = [
            '%252e%252e%252fetc%252fpasswd', '..%c0%af..%c0%afetc/passwd',
            '..%e0%80%ae/etc/passwd', '%25252e%25252e%25252f',
        ]
        const mutated = [
            '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%afetc%2fpasswd',
            '..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
            '%252e%252e%252fetc%252fpasswd%2500.jpg',
            '..%5c..%5c..%5cwindows%5cwin.ini',
        ]
        const v = [...seeds, ...mutated].filter(candidate => pathEncodingBypass.detect(candidate))
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
        '/admin/./',
        '/admin../',
        '/Admin%20/',
        '/admin;/secret',
        '/admin;jsessionid=x/secret',
        '/api/v1/admin\\secret',
        '..\\..\\windows\\win.ini:streamname',
        '..\\..\\..\\secret.txt::$DATA',
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
        if (/\/[^\/]+\.{1,}\//.test(d)) return true
        // Single-dot segment after a sensitive path segment (/admin/. , /admin/./)
        if (/\/(?:admin|config|internal|secret|private|\.env|\.git)\/\.(?:\/|$)/i.test(d)) return true
        // Trailing spaces in path segments
        if (/\/[^\/]+\s+\//.test(d)) return true
        // Semicolon path parameter injection (Tomcat, Spring)
        if (/\/[^\/]+;[^\/]*\//.test(d)) return true
        // Backslash as path separator targeting sensitive paths (IIS/Windows normalization on Unix)
        if (/^\/.*\\.*\w/.test(d) && /\/(?:admin|config|internal|secret|private|\.env|\.git)[\\/]/i.test(d)) return true
        // NTFS alternate data streams (ADS), often used to bypass extension/path controls on Windows.
        if (/(?:^|[\\/])\.\.[\\/][^:\r\n]*:[a-z0-9_$.-]+/i.test(d)) return true
        if (/::\$(?:DATA|INDEX_ALLOCATION|BITMAP)\b/i.test(d)) return true
        // Double-slash normalization bypass (e.g. //etc//passwd)
        if (/^\/\/|(?<!:)\/\/{1,}(?:[a-z])/i.test(d)) return true
        return false
    },
    detectL2: l2PathNormalization,
    generateVariants: (count: number): string[] => {
        const seeds = [
            '/admin/.', '/admin../', '/admin%20/',
            '/admin;jsessionid=x/secret', '/admin\\secret',
            '/ADMIN/./secret', '/api/v1/admin%09/secret',
        ]
        const mutated = [
            '/admin/.%2f',
            '/admin\\..\\secret',
            '/admin;%6a%73%65%73%73%69%6f%6e%69%64=x/secret',
            '/api/v1/admin%09/secret%00.jpg',
            '/admin//secret',
        ]
        const v = [...seeds, ...mutated].filter(candidate => pathNormalizationBypass.detect(candidate))
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const pathWindowsTraversal: InvariantClassModule = {
    id: 'path_windows_traversal',
    description: 'Windows-specific traversal and path injection primitives (UNC, drive-letter, ADS, zip slip, null-byte bypass)',
    category: 'path_traversal',
    severity: 'high',
    calibration: { baseConfidence: 0.90, minInputLength: 6 },

    mitre: ['T1083', 'T1005'],
    cwe: 'CWE-22',

    knownPayloads: [
        '..\\..\\Windows\\System32',
        '..\\..\\..\\..\\',
        '\\\\evil.com\\share',
        'C:\\Windows\\System32\\cmd.exe',
        'D:\\secrets',
        'archive.zip/../../../etc/passwd',
        'file.txt::DATA',
        'file.php::',
        'file.txt%00.php',
    ],

    knownBenign: [
        'C:\\Users\\file.txt',
        'D:\\Projects\\notes.md',
        'relative\\folder\\file.txt',
        'https://example.com/downloads/archive.zip',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (/(?:^|[\s"'`=:(])\\\\[a-z0-9.-]{1,253}\\[^\s\\/:*?"<>|]+/i.test(d)) return true
        if (/(?:^|[\s"'`=:(])(?:[a-z]:\\)(?:windows\\system32(?:\\|$)|windows\\win\.ini(?:$|\\)|secrets?(?:\\|$)|secret(?:\\|$)|sam(?:\\|$)|config(?:\\|$)|shadow(?:\\|$)|passwd(?:\\|$)|.*\\cmd\.exe\b)/i.test(d)) return true
        if (/(?:^|[\\/])(?:\.\.\\){2,}(?:windows\\system32|windows\\win\.ini|[^\\\r\n]{0,120})/i.test(d)) return true
        if (/(?:^|[\\/])(?:[^\\/\r\n]+\.(?:zip|jar|war|apk|tar|tgz|7z|rar))[\\/](?:\.\.[\\/]){2,}[^\r\n]{0,120}/i.test(d)) return true
        if (/(?:^|[\s"'`=:(])(?:\.\.[\\/]){3,}(?:etc[\\/]passwd|windows[\\/]system32|[^\\/\r\n]{1,120})/i.test(d)) return true
        if (/\.[a-z0-9]{1,8}(?:%00|\\x00|\0)\.[a-z0-9]{1,8}\b/i.test(d) || /\.[a-z0-9]{1,8}%00\.[a-z0-9]{1,8}\b/i.test(input)) return true
        if (/(?:^|[\\/])[^\\/\r\n]+::(?:\$?[a-z_]+)?(?:\b|$)/i.test(d)) return true
        return false
    },
    detectL2: (input: string): DetectionLevelResult | null => l2WindowsPathTraversal(input, input),
    generateVariants: (count: number): string[] => {
        const seeds = [
            '..\\..\\Windows\\System32\\drivers\\etc\\hosts',
            '..\\..\\..\\..\\Windows\\System32\\cmd.exe',
            '\\\\evil.com\\share\\payload.exe',
            'C:\\Windows\\System32\\cmd.exe',
            'D:\\secrets\\backup.txt',
            'archive.zip/../../../etc/passwd',
            'package.jar\\..\\..\\..\\windows\\system32\\config\\sam',
            'file.txt::DATA',
            'file.php::',
            'file.txt%00.php',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(seeds[i % seeds.length])
        return r.filter(candidate => pathWindowsTraversal.detect(candidate))
    },
}

export const PATH_CLASSES: InvariantClassModule[] = [pathDotdotEscape, pathNullTerminate, pathEncodingBypass, pathNormalizationBypass, pathWindowsTraversal]
