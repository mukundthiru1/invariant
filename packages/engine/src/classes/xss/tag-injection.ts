/**
 * XSS — Tag Injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectXssVectors } from '../../evaluators/xss-context-evaluator.js'

const TAG_INJECTION_HTML_TAG_PATTERN = /<\s*(?:script|iframe|object|embed|applet|form|meta|link|style|base|svg|math|video|audio|source|details|marquee|isindex|frameset|frame|body|img|input|button|textarea|select|keygen|a)\b[^>]*>/i
const TAG_INJECTION_OBFUSCATED_SCRIPT_PATTERN = /<\s*(?:[a-z][\w-]*:)?s[\s/]*c[\s/]*r[\s/]*i[\s/]*p[\s/]*t(?:\b|[\s/>])/i
const TAG_INJECTION_NOSCRIPT_HANDLER_PATTERN = /<\s*noscript\b[^>]*>[^<]*['"][^'"]*<\/noscript>\s*<\s*(?:img|svg|a|iframe|object|embed|body|form|input|marquee|details|video|audio|source)\b/i
const TAG_INJECTION_TABLE_JAVASCRIPT_PATTERN = /<\s*table\b[\s\S]*?<\s*a\b[^>]+\bhref\s*=\s*['"]?\s*javascript:/i
const TAG_INJECTION_TEMPLATE_PATTERN = /<\s*template\b[\s\S]*?<\s*(?:img|svg|iframe|a|body|form|input)\b[\s\S]*?>[\s\S]*?<\/template>/i
const TAG_INJECTION_LINK_JS_PATTERN = /<\s*(?:a|iframe|script)\b[^>]+\b(?:href|src)\s*=\s*['"]?\s*(?:javascript|data:text\/(?:html|javascript))/i
const TAG_INJECTION_DOM_CLOBBER_LINK_PATTERN = /<\s*img\b[^>]*\bid\s*=\s*(['"]?)([a-z][\w:-]*)\1[^>]*>\s*<\s*a\b[^>]*\bid\s*=\s*(['"]?)\2\3[^>]*\bname\s*=\s*(['"]?)\2\4[^>]*\bhref\s*=\s*['"]?\s*javascript:/i
const TAG_INJECTION_DOM_CLOBBER_FORM_ACTION_PATTERN = /<\s*form\b[^>]*\bid\s*=\s*(['"]?)([a-z][\w:-]*)\1[^>]*>[\s\S]*?<\s*input\b[^>]*\bname\s*=\s*(['"]?)action\3[^>]*\bvalue\s*=\s*['"]?\s*javascript:/i

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
        '<scr\tipt>alert(1)</scr\tipt>',
        '<scr/**/ipt>alert(1)</scr/**/ipt>',
        '<svg:script>alert(1)</svg:script>',
        '<html:script>alert(1)</html:script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<table><td><a href="javascript:alert(1)">x</td></table>',
        "<noscript><p title='</noscript><img src=x onerror=alert(1)>'>",
        '<template><img src=x onerror=alert(1)></template>',
        '<script src="data:text/javascript,alert(1)">',
        '<iframe src="data:text/html,<script>alert(1)</script>">',
        '<img id=x><a id=x name=x href=javascript:alert(1)>',
        '<form id=x><input name=action value=javascript:alert(1)>',
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
        const basicMatch =
            TAG_INJECTION_HTML_TAG_PATTERN.test(d) ||
            TAG_INJECTION_OBFUSCATED_SCRIPT_PATTERN.test(d) ||
            TAG_INJECTION_NOSCRIPT_HANDLER_PATTERN.test(d) ||
            TAG_INJECTION_TABLE_JAVASCRIPT_PATTERN.test(d) ||
            TAG_INJECTION_TEMPLATE_PATTERN.test(d) ||
            TAG_INJECTION_LINK_JS_PATTERN.test(d) ||
            TAG_INJECTION_DOM_CLOBBER_LINK_PATTERN.test(d) ||
            TAG_INJECTION_DOM_CLOBBER_FORM_ACTION_PATTERN.test(d)

        if (basicMatch) {
            return true
        }

        const vectors = detectXssVectors(d)
        return vectors.some(v =>
            v.type === 'tag_injection' || v.type === 'protocol_handler' ||
            v.type === 'event_handler' || v.type === 'template_expression',
        )
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const vectors = detectXssVectors(d)
        const match = vectors.find(v => v.type === 'tag_injection')
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
