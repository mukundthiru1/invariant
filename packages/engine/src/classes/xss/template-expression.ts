/**
 * XSS — Template Expression ({{...}}, ${...})
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

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
        '${alert(1)}',
        '{{$on.constructor("alert(1)")()}}',
    ],

    knownBenign: [
        'price is {{product.price}}',
        'hello {{user.name}}',
        'the result is ${result}',
        'template {{variable}}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\{\{.*(?:constructor|__proto__|prototype|\$on|\$emit|\$eval|alert|prompt|confirm|document|window|globalThis|Function).*\}\}/i.test(d) ||
            /\$\{.*(?:alert|document|window|constructor|eval|Function)\s*\(.*\}\s*/i.test(d)
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
