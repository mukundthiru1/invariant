/**
 * XSS — Event Handler Injection
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

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
    ],

    knownBenign: [
        'onerror callback function',
        'handle the onload event',
        'set onfocus to true',
        'when onmouseover fires',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\bon(?:error|load|click|mouseover|mouseout|mousedown|mouseup|focus|blur|change|submit|reset|select|abort|unload|resize|scroll|keydown|keypress|keyup|dblclick|drag|drop|input|invalid|toggle|animationend|copy|cut|paste|search|wheel|contextmenu|auxclick)\s*=\s*[^\s>]/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const events = ['onerror', 'onload', 'onmouseover', 'onfocus', 'onclick', 'onchange', 'onblur']
        const payloads = ['alert(1)', 'alert(document.cookie)', 'eval(atob("YWxlcnQoMSk="))']
        const v: string[] = []
        for (let i = 0; i < count; i++) v.push(`" ${events[i % events.length]}="${payloads[i % payloads.length]}"`)
        return v
    },
}
