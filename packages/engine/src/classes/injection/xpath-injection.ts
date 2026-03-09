/**
 * xpath_injection — XPath predicate and axis manipulation
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const XPATH_BOOLEAN_BYPASS_RE = /(?:'|")\s*or\s*(?:'?\d+'?|"?\d+"?)\s*=\s*(?:'?\d+'?|"?\d+"?)/i
const XPATH_UNION_RE = /union\s*\(\s*\/\/[\w*\[\]\/@'\"=\s:-]+\)|\/\/\*\[\s*name\s*\(\s*\)\s*=\s*['\"][^'\"]+['\"]\s*\]/i
const XPATH_STAR_RE = /\/\/\*\s*(?:$|\[)/i
const XPATH_FUNCTION_ABUSE_RE = /(?:contains|substring|string-length)\s*\(/i
const XPATH_PREDICATE_ESCAPE_RE = /\[\s*@\w+\s*=\s*['\"][^'\"]*['\"]\s+or\s+['\"]1['\"]\s*=\s*['\"]1['\"]\s*\]/i
const XPATH_AXIS_INJECTION_RE = /\/\/(?:ancestor|parent)::\*|descendant-or-self::/i
const SQL_CONTEXT_RE = /--|\/\*|\b(?:select|insert|update|delete|drop)\b/i

export const xpathInjection: InvariantClassModule = {
    id: 'xpath_injection',
    description: 'Detects XPath injection through predicate bypass, wildcard traversal, and axis/function abuse',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1190'],
    cwe: 'CWE-643',
    knownPayloads: [
        "' or '1'='1",
        "' or 1=1 or '1'='1",
        '//*',
        'union(//users/password)',
        "contains(password,'a')",
        "' or string-length(//user[1]/name)>0 or '",
    ],
    knownBenign: [
        "//div[@class='main']",
        "/root/element[@id='1']",
        'count(//items)',
        "//users[@active='true']",
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const booleanBypass = XPATH_BOOLEAN_BYPASS_RE.test(d)
        if (booleanBypass && !SQL_CONTEXT_RE.test(d)) return true

        return XPATH_UNION_RE.test(d)
            || XPATH_STAR_RE.test(d)
            || XPATH_FUNCTION_ABUSE_RE.test(d)
            || XPATH_PREDICATE_ESCAPE_RE.test(d)
            || XPATH_AXIS_INJECTION_RE.test(d)
    },
    detectL2: (_input: string): DetectionLevelResult | null => null,
    generateVariants: (count: number): string[] => {
        const variants = [
            "' or '1'='1",
            '//*',
            "union(//users/password)",
            "' or string-length(//user[1]/name)>0 or '",
        ]
        return variants.slice(0, count)
    },
}
