/**
 * XSS — DOM-Based XSS
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2DomXss } from '../../evaluators/l2-adapters.js'

const DOM_DIRECT_SINK_RE = /(?:\bdocument\.(?:write|writeln)\s*\([^)]*\)|\.\s*(?:innerHTML|outerHTML)\s*=\s*[^;]*(?:location\.(?:hash|search)|new\s+URLSearchParams\s*\(\s*location\.search\s*\)\s*\.get)|\b(?:eval|Function)\s*\(\s*[^)]*(?:location\.(?:hash|search)|new\s+URLSearchParams\s*\(\s*location\.search\s*\)\s*\.get)|javascript\s*:\s*document\.(?:write|writeln)\s*\()/i
const DOM_INDIRECT_SINK_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:location\.(?:hash|search)|new\s+URLSearchParams\s*\(\s*location\.search\s*\)\s*\.get\([^)]*\))[\s\S]{0,180}?(?:document\.(?:write|writeln)\s*\(\s*\1\b|\.\s*(?:innerHTML|outerHTML)\s*=\s*\1\b|\b(?:eval|Function)\s*\(\s*\1\b)/i

export const xssDomXss: InvariantClassModule = {
    id: 'dom_xss',
    description: 'DOM-based XSS via dangerous sinks fed from URL/location-controlled sources',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.86 },

    mitre: ['T1059.007'],
    cwe: 'CWE-79',

    knownPayloads: [
        'document.write(location.hash)',
        '<img onerror=document.write(1)>',
        'javascript:document.write(x)',
    ],

    knownBenign: [
        '<div id="content">Welcome</div>',
        '<p>document.write is disabled in this policy text</p>',
        'window.location.hash is a browser property',
        '<span>Safe static HTML</span>',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return DOM_DIRECT_SINK_RE.test(d) || DOM_INDIRECT_SINK_RE.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        return l2DomXss(d, d)
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'document.write(location.hash)',
            'el.innerHTML = location.search',
            'const p = new URLSearchParams(location.search).get("q"); eval(p)',
            'const h = location.hash; document.writeln(h)',
            'const q = location.search; target.outerHTML = q',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}
