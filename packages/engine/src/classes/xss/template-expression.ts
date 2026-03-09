/**
 * XSS — Template Expression ({{...}}, ${...})
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectXssVectors } from '../../evaluators/xss-context-evaluator.js'

const TEMPLATE_MUSTACHE_PATTERN = /\{\{.*(?:constructor|__proto__|prototype|\$on|\$emit|\$eval|alert|prompt|confirm|document|window|globalThis|Function).*\}\}/i
const TEMPLATE_EXPRESSION_PATTERN = /\$\{.*(?:alert|document|window|constructor|eval|Function)\s*\(.*\}\s*/i
const TEMPLATE_EVENT_HANDLER_PATTERN = /(?:window\.)?addEventListener\s*\(\s*['"]message['"][\s\S]*?\beval\s*\(/i
const DOCUMENT_DOMAIN_PATTERN = /\bdocument\.domain\s*=\s*['"][^'"]*['"]/i
const TEMPLATE_TAG_PATTERN = /<(?:img|form)\b[^>]+\b(?:id\s*=\s*['"]?(?:__proto__|prototype|constructor)|name\s*=\s*['"]?(?:domain|polluted|__proto__|prototype|constructor))\b[^>]*>/i

export const xssTemplateExpression: InvariantClassModule = {
    id: 'xss_template_expression',
    description: 'Client-side template expression injection (Angular, Vue, etc.) or DOM-based template literals',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.80 },

    mitre: ['T1059.007'],
    cwe: 'CWE-79',

    knownPayloads: [
        '{{constructor.constructor("alert(1)")()}}',
        "{{constructor.constructor('alert(1)')()}}",
        '${alert(1)}',
        '{{$on.constructor("alert(1)")()}}',
        '<img id=x name=domain src=//evil.com>',
        '<form id=__proto__><input name=polluted value=1>',
        "window.addEventListener('message', function(e) { eval(e.data) })",
        'document.domain = \"\"',
    ],

    knownBenign: [
        'price is {{product.price}}',
        'hello {{user.name}}',
        'the result is ${result}',
        'template {{variable}}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return (
            TEMPLATE_MUSTACHE_PATTERN.test(d)
            || TEMPLATE_EXPRESSION_PATTERN.test(d)
            || TEMPLATE_EVENT_HANDLER_PATTERN.test(d)
            || DOCUMENT_DOMAIN_PATTERN.test(d)
            || TEMPLATE_TAG_PATTERN.test(d)
        )
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const vectors = detectXssVectors(d)
        const match = vectors.find(v => v.type === 'template_expression')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `HTML analysis: ${match.detail}`,
                evidence: match.element,
            }
        }
        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            '{{constructor.constructor("alert(1)")()}}',
            '{{$on.constructor("alert(1)")()}}',
            '${alert(document.cookie)}',
            '{{toString.constructor("alert(1)")()}}',
            '{{7*7}}{{constructor.constructor("return this")().alert(1)}}',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
