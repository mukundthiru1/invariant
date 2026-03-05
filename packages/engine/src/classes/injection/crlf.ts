/**
 * CRLF injection classes — header injection + log injection
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const crlfHeaderInjection: InvariantClassModule = {
    id: 'crlf_header_injection',
    description: 'CRLF injection — \\r\\n sequences that inject HTTP headers or split responses',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },

    mitre: ['T1190'],
    cwe: 'CWE-113',

    knownPayloads: [
        '%0d%0aSet-Cookie: admin=true',
        '%0d%0aLocation: http://evil.com',
        'value%0d%0a%0d%0a<script>alert(1)</script>',
    ],

    knownBenign: [
        'normal text',
        'hello world',
        'Set-Cookie header',
        'Location: https://example.com',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /%0[dD]%0[aA]/i.test(input) || (/\r\n/.test(d) && /(?:Set-Cookie|Location|Content-Type|HTTP\/)/i.test(d))
    },
    generateVariants: (count: number): string[] => {
        const v = ['%0d%0aSet-Cookie: admin=true', '%0d%0aLocation: http://evil.com',
            'value%0d%0a%0d%0a<script>alert(1)</script>', '\\\\r\\\\nHTTP/1.1 200 OK\\\\r\\\\nContent-Type: text/html']
        return v.slice(0, count)
    },
}

export const crlfLogInjection: InvariantClassModule = {
    id: 'crlf_log_injection',
    description: 'Log injection via CRLF — forge log entries or inject control sequences via \\r\\n in logged fields',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.75 },

    mitre: ['T1070.001'],
    cwe: 'CWE-117',

    knownPayloads: [
        'user%0d%0a[INFO] Login successful for admin',
        'input%0a[ALERT] ADMIN_ACCESS_GRANTED',
        'test\r\n[ALERT] Security bypass detected',
    ],

    knownBenign: [
        'normal log entry',
        'user logged in',
        '[INFO] system started',
        'debug message',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // Check for newline characters (from URL encoding or literal) followed by log-like patterns
        const hasNewline = /%0[aAdD]/i.test(input) || /[\r\n]/.test(d)
        if (!hasNewline) return false
        // Log-like prefix patterns in the decoded content
        return /\[(?:INFO|WARN|ERROR|DEBUG|ALERT|CRITICAL|NOTICE)\]/i.test(d) ||
            /\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'user%0d%0a[INFO] Login successful for admin',
            'input%0a[2024-01-01] ADMIN_ACCESS_GRANTED',
            'test%0d%0a[ALERT] Security bypass',
            'data%0a2024-01-01T12:00:00 ADMIN login',
        ]
        return v.slice(0, count)
    },
}
