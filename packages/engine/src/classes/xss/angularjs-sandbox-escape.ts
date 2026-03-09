/**
 * XSS — AngularJS 1.x Sandbox Escape
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2AngularSandboxEscape } from '../../evaluators/l2-adapters.js'

const ANGULAR_SANDBOX_ESCAPE_RE = /(?:\{\{[\s\S]{0,220}\bconstructor\s*\.\s*constructor[\s\S]{0,220}\}\}|\{\{[\s\S]{0,220}\.\s*constructor\s*\([\s\S]{0,220}\}\}|\{\{[\s\S]{0,220}\.constructor\.prototype\.charAt\s*=\s*\[\]\.join[\s\S]{0,220}\}\}|\btoString\s*\.\s*(?:call|bind)\s*\(|\bthis\s*(?:\.\s*window|\[\s*['"]window['"]\s*\])|\bcharAt\s*\(\s*0\s*\)\s*\.\s*constructor\b)/i

export const xssAngularjsSandboxEscape: InvariantClassModule = {
    id: 'angularjs_sandbox_escape',
    description: 'AngularJS 1.x expression sandbox escape via constructor and prototype primitives',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },

    mitre: ['T1059.007'],
    cwe: 'CWE-94',

    knownPayloads: [
        '{{constructor.constructor("alert(1)")()}}',
        "{{'a'.constructor.prototype.charAt=[].join}}",
        "{{.constructor('alert(1)')()}}",
    ],

    knownBenign: [
        '{{ user.name }}',
        '{{ price | currency }}',
        '<div ng-bind="profile.title"></div>',
        'ng-repeat="item in items"',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return ANGULAR_SANDBOX_ESCAPE_RE.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        return l2AngularSandboxEscape(d, d)
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            '{{constructor.constructor("alert(1)")()}}',
            "{{'a'.constructor.prototype.charAt=[].join}}",
            "{{toString.constructor('alert(1)')()}}",
            "{{this.window.alert(1)}}",
            "{{'x'.charAt(0).constructor.constructor('alert(1)')()}}",
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}
