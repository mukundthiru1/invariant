/**
 * XSS — Protocol Handler (javascript:, vbscript:, data:)
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const xssProtocolHandler: InvariantClassModule = {
    id: 'xss_protocol_handler',
    description: 'javascript:, vbscript:, or data: URI protocol handlers to execute script',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1059.007'],
    cwe: 'CWE-79',

    knownPayloads: [
        'javascript:alert(1)',
        'vbscript:MsgBox("XSS")',
        'data:text/html,<script>alert(1)</script>',
        'javascript:void(0)',
        'JaVaScRiPt:alert(1)',
    ],

    knownBenign: [
        'https://javascript.com',
        'the javascript language',
        'learning javascript basics',
        'data science course',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:javascript|vbscript|livescript)\s*:/i.test(d) ||
            /data\s*:\s*(?:text\/html|application\/xhtml)/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'javascript:alert(1)', 'javascript:alert(document.cookie)',
            'vbscript:MsgBox("XSS")', 'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'JaVaScRiPt:alert(1)', 'java\tscript:alert(1)',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
