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
        const seeds = [
            '{{config.__class__.__init__.__globals__}}',
            '{{lipsum.__globals__.os.popen("id").read()}}',
            '{%import os%}{{os.popen("id").read()}}',
            '{{self.__class__.__mro__[2].__subclasses__()}}',
            '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
        ]
        const mutated = seeds.flatMap(payload => [
            encodeURIComponent(payload),
            encodeURIComponent(encodeURIComponent(payload)),
            payload.replace(/\{/g, '\\x7b').replace(/\}/g, '\\x7d'),
            payload.replace(/\{/g, '%7b').replace(/\}/g, '%7d'),
            payload.replace(/import/g, 'IMPORT'),
            payload.replace(/config/g, 'CONFIG'),
            payload.replace(/request/g, 'ReQueSt'),
            payload.replace(/\s+/g, '\t'),
            payload.replace(/\s+/g, '/**/'),
        ])
        const v = [...seeds, ...mutated].filter(candidate => sstiJinjaTwig.detect(candidate))
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
        const seeds = [
            '${T(java.lang.Runtime).getRuntime().exec("id")}',
            '#{T(java.lang.Runtime).getRuntime().exec("id")}',
            '${#rt=@java.lang.Runtime@getRuntime(),#rt.exec("id")}',
            '${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}',
        ]
        const mutated = seeds.flatMap(payload => [
            encodeURIComponent(payload),
            encodeURIComponent(encodeURIComponent(payload)),
            payload.replace(/\s+/g, '\t'),
            payload.replace(/Runtime/g, 'RUNTIME'),
            payload.replace(/java/g, 'JAVA'),
            payload.replace(/\{/g, '\\x7b').replace(/\}/g, '\\x7d'),
            payload.replace(/\{/g, '%7b').replace(/\}/g, '%7d'),
        ])
        const v = [...seeds, ...mutated].filter(candidate => sstiElExpression.detect(candidate))
        return v.slice(0, count)
    },
}

export const templateInjectionGeneric: InvariantClassModule = {
    id: 'template_injection_generic',
    description: 'Generic server-side template injection patterns across ERB, Mako, Handlebars/Mustache, Velocity, FreeMarker, Smarty, Pebble, Go, and Thymeleaf',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.84 },

    mitre: ['T1190'],
    cwe: 'CWE-1336',

    knownPayloads: [
        '${7*7}',
        '{{7*7}}',
        '#{7*7}',
        '*{7*7}',
        '<%= 7*7 %>',
        '<%=7*7%>',
        '#set($x=7*7)$x',
        '{{"".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}}',
        '#set($e="e")$e.class.forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        "${__import__('os').system('id')}",
        '{php}echo `id`;{/php}',
        "{system('id')}",
        '<%= `id` %>',
        "<%= system('id') %>",
        '{{_self.env.registerUndefinedFilterCallback("system")}}',
        '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
        '{{#with (constructor.constructor \'alert(1)\')()}}',
        '{{#with (constructor.constructor "alert(1)")()}}',
        '{{lookup . \'constructor\'}}',
        '{{{raw_html}}}',
        '{{> partial}}',
        '{{.Env}}',
        '{{call .FieldName}}',
        '{{call .OS.Stdout.Write .Request.URL.RawPath}}',
    ],

    knownBenign: [
        'render user profile template',
        'Handlebars template for email rendering',
        'The value is {x}',
        '{{greeting}}',
        '{{name}}',
        'Hello {{world}}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return (
            // Mako / FreeMarker arithmetic or dangerous expression interpolation
            /\$\{\s*(?:\d+\s*[*+\-/]\s*\d+|[^}]{0,120}(?:exec|runtime|processbuilder|system|__|class|env\.)[^}]*)\}/i.test(d)
            // Spring / EL / Thymeleaf style arithmetic probes
            || /[#*]\{\s*\d+\s*[*+\-/]\s*\d+\s*\}/.test(d)
            // Ruby ERB execution tags
            || /<%=\s*[^%]{1,200}\s*%>/.test(d)
            // FreeMarker Execute utility
            || /<\#assign\s+[A-Za-z_]\w*\s*=\s*["'][^"']+["']\?new\(\)\s*>\s*\$\{\s*[A-Za-z_]\w*\s*\(\s*["'][^"']+["']\s*\)\s*\}/i.test(d)
            // Handlebars / Mustache / Pebble expression or dangerous callbacks
            || /\{\{\s*(?:\d+\s*[*+\-/]\s*\d+|[^}]{0,120}(?:exec|runtime|processbuilder|system|__|class|env\.)[^}]*)\}\}/i.test(d)
            || /\{\{\s*_self\.env\.registerUndefinedFilterCallback\(/i.test(d)
            // Smarty dangerous tags
            || /\{php\}[\s\S]{0,200}\{\/php\}/i.test(d)
            || /\{\s*system\s*\(\s*['"`][^'"`]{1,80}['"`]\s*\)\s*\}/i.test(d)
            // Handlebars specific exploit patterns
            || /\{\{#?with\s+.*constructor|lookup\s+\.\s+'constructor'|\{\{[^}]*constructor\.constructor/i.test(d)
            // Mustache unescaped or partials
            || /\{\{\{.*\}\}\}/.test(d)
            || /\{\{>\s*.*\}\}/.test(d)
            // Go template injection patterns
            || /\{\{[^}]*(?:\.Env|call\s|printf\s|println\s|\.OS|exec\.Command)/i.test(d)
            // Smarty variable interpolation (require '$' to avoid plain "{x}" text)
            || /\{\s*\$[A-Za-z_][\w.]*\s*\}/.test(d)
            // Velocity directives
            || /#set\s*\(\s*\$[A-Za-z_]\w*\s*=.+\)/i.test(d)
            // Thymeleaf template directives
            || /\bth:text\s*=/.test(d)
        )
    },
    generateVariants: (count: number): string[] => {
        const seeds = [
            '${7*7}',
            '{{7*7}}',
            '#{7*7}',
            '*{7*7}',
            '<%= 7*7 %>',
            '<%=7*7%>',
            '#set($x=7*7)$x',
            '{{"".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}}',
            '#set($e="e")$e.class.forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")',
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            "${__import__('os').system('id')}",
            '{php}echo `id`;{/php}',
            "{system('id')}",
            '<%= `id` %>',
            "<%= system('id') %>",
            '{{_self.env.registerUndefinedFilterCallback("system")}}',
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            'th:text="${7*7}"',
            '{{#with (constructor.constructor \'alert(1)\')()}}',
            '{{lookup . \'constructor\'}}',
            '{{{raw_html}}}',
            '{{> partial}}',
            '{{.Env}}',
            '{{call .FieldName}}',
        ]
        const mutated = seeds.flatMap(payload => [
            encodeURIComponent(payload),
            encodeURIComponent(encodeURIComponent(payload)),
            payload.replace(/\s+/g, '\t'),
            payload.replace(/\s+/g, '/**/'),
            payload.replace(/\{/g, '%7b').replace(/\}/g, '%7d'),
            payload.replace(/\{/g, '\\x7b').replace(/\}/g, '\\x7d'),
            payload.replace(/system/g, 'SYSTEM'),
            payload.replace(/th:text/g, 'TH:TEXT'),
        ])
        const v = [...seeds, ...mutated].filter(candidate => templateInjectionGeneric.detect(candidate))
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
