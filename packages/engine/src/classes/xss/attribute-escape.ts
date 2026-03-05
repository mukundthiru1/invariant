/**
 * XSS — Attribute Escape
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

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
    ],

    knownBenign: [
        'class="active"',
        'data-value="123"',
        "it's a 'quoted' string",
        'she said "hello"',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /['"][\s/]*(?:>|on\w+\s*=|style\s*=|xmlns\s*=|src\s*=|href\s*=|action\s*=|formaction\s*=)/i.test(d)
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
