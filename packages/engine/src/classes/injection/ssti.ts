/**
 * SSTI — Jinja/Twig + Expression Language
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2SSTIJinja, l2SSTIEL } from '../../evaluators/l2-adapters.js'

export const sstiJinjaTwig: InvariantClassModule = {
    id: 'ssti_jinja_twig',
    description: 'Server-side template injection via Jinja2/Twig syntax — {{}} or {%%} expressions',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.88 },

    mitre: ['T1190', 'T1059'],
    cwe: 'CWE-1336',

    knownPayloads: [
        '{{config.__class__.__init__.__globals__}}',
        '{{lipsum.__globals__.os.popen("id").read()}}',
        '{%import os%}{{os.popen("id").read()}}',
        '{{self.__class__.__mro__[2].__subclasses__()}}',
    ],

    knownBenign: [
        '{{user.name}}',
        '{{product.price}}',
        '{%for item in list%}',
        'hello {{world}}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\{\{.*(?:__class__|__mro__|__subclasses__|__builtins__|__globals__|config|lipsum|cycler|joiner|namespace|request\.|self\.).*\}\}/i.test(d)
            || /\{%.*(?:import|include|extends|block|macro|call).*%\}/i.test(d)
            || (/\{\{.*(?:\d+\s*[+\-*/]\s*\d+).*\}\}/.test(d) && /\{\{.*\|.*\}\}/.test(d))
    },
    detectL2: l2SSTIJinja,
    generateVariants: (count: number): string[] => {
        const v = [
            '{{config.__class__.__init__.__globals__}}',
            '{{lipsum.__globals__.os.popen("id").read()}}',
            '{%import os%}{{os.popen("id").read()}}',
            '{{self.__class__.__mro__[2].__subclasses__()}}',
            '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
        ]
        return v.slice(0, count)
    },
}

export const sstiElExpression: InvariantClassModule = {
    id: 'ssti_el_expression',
    description: 'Expression Language injection — ${...} or #{...} in Java EL, Spring SpEL, or OGNL',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.88 },

    mitre: ['T1190', 'T1059'],
    cwe: 'CWE-917',

    knownPayloads: [
        '${T(java.lang.Runtime).getRuntime().exec("id")}',
        '#{T(java.lang.Runtime).getRuntime().exec("id")}',
        '${#rt=@java.lang.Runtime@getRuntime(),#rt.exec("id")}',
    ],

    knownBenign: [
        '${HOME}',
        '#{color}',
        'price is ${amount}',
        'the value of ${x}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\$\{.*(?:Runtime|ProcessBuilder|exec|getClass|forName|getMethod|invoke).*\}/i.test(d)
            || /#\{.*(?:T\(|new |java\.).*\}/i.test(d)
            || /%\{.*(?:#cmd|#context|#attr|@java).*\}/i.test(d)
    },
    detectL2: l2SSTIEL,
    generateVariants: (count: number): string[] => {
        const v = [
            '${T(java.lang.Runtime).getRuntime().exec("id")}',
            '#{T(java.lang.Runtime).getRuntime().exec("id")}',
            '${#rt=@java.lang.Runtime@getRuntime(),#rt.exec("id")}',
            '${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}',
        ]
        return v.slice(0, count)
    },
}
