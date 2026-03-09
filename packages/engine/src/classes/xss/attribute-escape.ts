/**
 * XSS — Attribute Escape
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectXssVectors } from '../../evaluators/xss-context-evaluator.js'

const ATTRIBUTE_BREAK_OR_EVENT_PATTERN = /['"][\s/]*(?:>|on\w+\s*=|style\s*=|xmlns\s*=|src\s*=|href\s*=|action\s*=|formaction\s*=)/i
const STYLE_EXPRESSION_PATTERN = /\bstyle\s*=\s*['"]?[^'">]*\bexpression\s*\(/i
const STYLE_BEHAVIOR_PATTERN = /\bstyle\s*=\s*['"]?[^'">]*\bbehavior\s*:\s*url\(/i
const STYLE_MOZ_BINDING_PATTERN = /\bstyle\s*=\s*['"]?[^'">]*-moz-binding\s*:\s*url\(/i

export const xssAttributeEscape: InvariantClassModule = {
    id: 'xss_attribute_escape',
    description: 'Break out of HTML attribute context to inject new attributes or elements',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.82 },

    mitre: ['T1059.007'],
    cwe: 'CWE-79',

    knownPayloads: [
        '" onmouseover="alert(1)" x="',
        "' onfocus='alert(1)' autofocus='",
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '" style=behavior:url(http://evil.com/xss.htc) x="',
        '" style=expression(alert(1)) x="',
        '" style=-moz-binding:url(http://evil.com/xss.xml#a) x="',
    ],

    knownBenign: [
        'class="active"',
        'data-value="123"',
        "it's a 'quoted' string",
        'she said "hello"',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return ATTRIBUTE_BREAK_OR_EVENT_PATTERN.test(d) ||
            STYLE_EXPRESSION_PATTERN.test(d) ||
            STYLE_BEHAVIOR_PATTERN.test(d) ||
            STYLE_MOZ_BINDING_PATTERN.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const vectors = detectXssVectors(d)
        const match = vectors.find(v => v.type === 'attribute_escape')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `HTML analysis: ${match.detail}`,
                evidence: match.element,
            }
        }

        const quoteBreak = d.match(/['"][\s/]*(?:>|on\w+\s*=|style\s*=|xmlns\s*=|src\s*=|href\s*=|action\s*=|formaction\s*=)/i)
        if (quoteBreak?.[0]) {
            return {
                detected: true,
                confidence: 0.86,
                explanation: 'HTML analysis: input breaks out of quoted attribute into executable context',
                evidence: quoteBreak[0],
            }
        }

        const injectedTag = d.match(/['"]\s*>\s*<(?:script|img|svg|iframe|math)\b[\s\S]{0,180}/i)
        if (injectedTag?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'HTML analysis: attribute escape closes element and injects executable tag',
                evidence: injectedTag[0].slice(0, 220),
            }
        }

        const styleExec = d.match(/\bstyle\s*=\s*['"]?[^'">]{0,220}(?:expression\s*\(|behavior\s*:\s*url\(|-moz-binding\s*:\s*url\()/i)
        if (styleExec?.[0]) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'HTML analysis: escaped attribute introduces style-based script execution primitive',
                evidence: styleExec[0],
            }
        }
        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            '" onmouseover="alert(1)" x="', "' onfocus='alert(1)' autofocus='",
            '"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>",
            '" style="background:url(javascript:alert(1))" x="',
            '"><svg/onload=alert(1)>',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
