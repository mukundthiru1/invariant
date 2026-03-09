/**
 * XSS — Event Handler Injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectXssVectors } from '../../evaluators/xss-context-evaluator.js'

const EVENT_HANDLER_PATTERN = /\bon(?:error|load|click|mouseover|mouseout|mousedown|mouseup|focus|blur|change|submit|reset|select|abort|unload|resize|scroll|keydown|keypress|keyup|dblclick|drag|drop|input|invalid|toggle|animationend|transitionend|begin|end|copy|cut|paste|search|wheel|contextmenu|auxclick|pointerdown|pointerup|beforeinput|beforeunload|pageshow|pagehide|hashchange|storage|offline|online)\s*=\s*[^\s>]/i

export const xssEventHandler: InvariantClassModule = {
    id: 'xss_event_handler',
    description: 'Inject event handler attributes (onerror, onload, etc.) to execute JavaScript',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1059.007'],
    cwe: 'CWE-79',

    knownPayloads: [
        '" onerror="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',
        '" onload="alert(1)',
        '" onpointerdown="alert(1)',
        '" onpointerup="alert(1)',
        '" onbegin="alert(1)',
        '" ontransitionend="alert(1)',
        '" onend="alert(1)',
        '" onbeforeinput="alert(1)',
        '" onbeforeunload="alert(1)',
        '" onpageshow="alert(1)',
        '" onpagehide="alert(1)',
        '" onhashchange="alert(1)',
        '" onstorage="alert(1)',
        '" onoffline="alert(1)',
        '" ononline="alert(1)',
    ],

    knownBenign: [
        'onerror callback function',
        'handle the onload event',
        'set onfocus to true',
        'when onmouseover fires',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return EVENT_HANDLER_PATTERN.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const vectors = detectXssVectors(d)
        const match = vectors.find(v => v.type === 'event_handler')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `HTML analysis: ${match.detail}`,
                evidence: match.element,
            }
        }

        const attrBreakPattern = d.match(/(?:^|["'\s>\/])on(?:error|load|click|mouseover|mouseout|mousedown|mouseup|focus|blur|change|submit|reset|select|abort|unload|resize|scroll|keydown|keypress|keyup|dblclick|drag|drop|input|invalid|toggle|animationend|transitionend|begin|end|copy|cut|paste|search|wheel|contextmenu|auxclick|pointerdown|pointerup|beforeinput|beforeunload|pageshow|pagehide|hashchange|storage|offline|online)\s*=/i)
        if (attrBreakPattern?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'HTML analysis: attribute-boundary escape injects executable event handler',
                evidence: attrBreakPattern[0],
            }
        }

        const tagEventPattern = d.match(/<\s*(?:img|svg|body|video|audio|iframe|input|button|textarea|select|details|marquee)\b[^>]{0,240}\bon[a-z]+\s*=/i)
        if (tagEventPattern?.[0]) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'HTML analysis: active tag carries inline event handler sink',
                evidence: tagEventPattern[0].slice(0, 220),
            }
        }

        const encodedEventPattern = d.match(/on[a-z]+\s*=\s*(?:alert|prompt|confirm|eval|settimeout|setinterval|fetch)\s*\(/i)
        if (encodedEventPattern?.[0]) {
            return {
                detected: true,
                confidence: 0.85,
                explanation: 'HTML analysis: event handler payload invokes executable JavaScript primitive',
                evidence: encodedEventPattern[0],
            }
        }
        return null
    },

    generateVariants: (count: number): string[] => {
        const events = ['onerror', 'onload', 'onmouseover', 'onfocus', 'onclick', 'onchange', 'onblur']
        const payloads = ['alert(1)', 'alert(document.cookie)', 'eval(atob("YWxlcnQoMSk="))']
        const v: string[] = []
        for (let i = 0; i < count; i++) v.push(`" ${events[i % events.length]}="${payloads[i % payloads.length]}"`)
        return v
    },
}
