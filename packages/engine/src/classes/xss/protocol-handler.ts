/**
 * XSS — Protocol Handler (javascript:, vbscript:, data:)
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectXssVectors } from '../../evaluators/xss-context-evaluator.js'

const PROTOCOL_HANDLER_PATTERN = /(?:javascript|vbscript|livescript)\s*:/i
const DATA_JAVASCRIPT_PATTERN = /data\s*:\s*text\/javascript/i
const DATA_HTML_OR_XHTML_PATTERN = /data\s*:\s*(?:text\/html|application\/xhtml)/i
const OBFUSCATED_JAVASCRIPT_PROTOCOL_PATTERN = /j(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*a(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*v(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*a(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*s(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*c(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*r(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*i(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*p(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:9|0a|0d);)*t\s*:/i

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
        'data:text/javascript,alert(1)',
        'vbscript:MsgBox("XSS")',
        'data:text/html,<script>alert(1)</script>',
        'javascript:void(0)',
        'JaVaScRiPt:alert(1)',
        'java\nscript:alert(1)',
        'java script:alert(1)',
        'j&Tab;avascript:alert(1)',
        'java&#9;script:alert(1)',
    ],

    knownBenign: [
        'https://javascript.com',
        'the javascript language',
        'learning javascript basics',
        'data science course',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return PROTOCOL_HANDLER_PATTERN.test(d) ||
            DATA_JAVASCRIPT_PATTERN.test(d) ||
            DATA_HTML_OR_XHTML_PATTERN.test(d) ||
            OBFUSCATED_JAVASCRIPT_PROTOCOL_PATTERN.test(input)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const vectors = detectXssVectors(d)
        const match = vectors.find(v => v.type === 'protocol_handler')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `HTML analysis: ${match.detail}`,
                evidence: match.element,
            }
        }

        const scriptScheme = d.match(/(?:^|[=\s"'(])(?:javascript|vbscript|livescript)\s*:/i)
        if (scriptScheme?.[0]) {
            return {
                detected: true,
                confidence: 0.91,
                explanation: 'HTML analysis: URI scheme resolves to script-capable protocol',
                evidence: scriptScheme[0],
            }
        }

        const dataExecutable = d.match(/data\s*:\s*(?:text\/javascript|text\/html|application\/xhtml\+xml)[^,\s]*,/i)
        if (dataExecutable?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'HTML analysis: data URI embeds executable document/script content',
                evidence: dataExecutable[0],
            }
        }

        const obfuscatedJavascript = d.match(/j(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*a(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*v(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*a(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*s(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*c(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*r(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*i(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:09|0a|0d);)*p(?:\s|&(?:tab|newline);|&#(?:9|10|13);|&#x(?:9|0a|0d);)*t\s*:/i)
        if (obfuscatedJavascript?.[0]) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'HTML analysis: obfuscated javascript: protocol bypass detected',
                evidence: obfuscatedJavascript[0],
            }
        }
        return null
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
