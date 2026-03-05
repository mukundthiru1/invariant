/**
 * XSS — Tag Injection
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const xssTagInjection: InvariantClassModule = {
    id: 'xss_tag_injection',
    description: 'Inject new HTML elements to execute arbitrary JavaScript',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.88, minInputLength: 5 },

    mitre: ['T1059.007'],
    cwe: 'CWE-79',

    knownPayloads: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
    ],

    knownBenign: [
        '<div>hello world</div>',
        '<p>paragraph text</p>',
        '<br/>',
        'use <code> for code blocks',
        '3 < 5 and 5 > 3',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /<\s*(?:script|iframe|object|embed|applet|form|meta|link|style|base|svg|math|video|audio|source|details|marquee|isindex|frameset|frame|body|img|input|button|textarea|select|keygen)\b[^>]*>/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = [
            '<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>', '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">', '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">', '<details open ontoggle=alert(1)>',
            '<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">',
            '<marquee onstart=alert(1)>',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
