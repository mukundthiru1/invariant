/**
 * ognl_injection — OGNL expression injection (Struts/WebWork)
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const OGNL_MARKER_RE = /(?:%|\$)\{[^}]{1,600}\}/
const OGNL_CLASS_ACCESS_RE = /class\.forName|Runtime\.getRuntime|@java\.lang\.Runtime@getRuntime\s*\(/i
const OGNL_COMMAND_RE = /(?:getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bexec\s*\(|ProcessBuilder)/i
const OGNL_PROPERTY_NAV_RE = /\b[a-zA-Z_]\w*\.[a-zA-Z_]\w*\[\d+\]\.[a-zA-Z_]\w*\b/
const OGNL_REDIRECT_ACTION_RE = /(?:method:redirect:|redirect-action:|action:)\s*(?:%\{|\$\{)/i
const OGNL_META_ESCAPE_RE = /#_memberAccess|#context|#root|#attr/i

export const ognlInjection: InvariantClassModule = {
    id: 'ognl_injection',
    description: 'Detects OGNL expression injection patterns used by Apache Struts/WebWork attacks',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.92 },
    mitre: ['T1190'],
    cwe: 'CWE-917',
    knownPayloads: [
        "%{@java.lang.Runtime@getRuntime().exec('id')}",
        '%{#_memberAccess.allowPrivateAccess=true}',
        "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']}",
        'action:%{123+456}',
        "%{'test'.class.forName('java.lang.Runtime')}",
        '%{#root}',
    ],
    knownBenign: [
        '',
        '%{label}',
        'Hello %user%, welcome',
        '{key: value}',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)

        if (OGNL_REDIRECT_ACTION_RE.test(d)) return true

        const marker = d.match(OGNL_MARKER_RE)
        if (!marker) return false

        const expr = marker[0]
        return OGNL_CLASS_ACCESS_RE.test(expr)
            || OGNL_COMMAND_RE.test(expr)
            || OGNL_PROPERTY_NAV_RE.test(expr)
            || OGNL_META_ESCAPE_RE.test(expr)
    },
    detectL2: (_input: string): DetectionLevelResult | null => null,
    generateVariants: (count: number): string[] => {
        const variants = [
            "%{@java.lang.Runtime@getRuntime().exec('id')}",
            '%{#_memberAccess.allowPrivateAccess=true}',
            'action:%{123+456}',
            "%{'test'.class.forName('java.lang.Runtime')}",
        ]
        return variants.slice(0, count)
    },
}
