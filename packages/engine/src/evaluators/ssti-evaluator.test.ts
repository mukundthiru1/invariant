import { describe, expect, it } from 'vitest'

import { detectSSTI } from './ssti-evaluator'

describe('ssti-evaluator advanced detections', () => {
    it('detects polyglot math probes in Jinja-like braces', () => {
        const detections = detectSSTI('{{7*\'7\'}}')
        expect(detections.some((d) => d.confidence === 0.92)).toBe(true)
    })

    it('detects polyglot config object access', () => {
        const detections = detectSSTI('{{config}}')
        expect(detections.some((d) => d.detail.includes('Polyglot SSTI'))).toBe(true)
    })

    it('detects polyglot Slim/Jinja marker with request env', () => {
        const detections = detectSSTI('{{request.environ}}')
        expect(detections.some((d) => d.confidence === 0.92)).toBe(true)
    })

    it('detects context escape delimiter breakouts', () => {
        const detections = detectSSTI('hello}} {{7*7}}')
        expect(detections.some((d) => d.confidence === 0.91)).toBe(true)
    })

    it('detects context escape via attr(__class__)', () => {
        const detections = detectSSTI('{{foo|attr(\'__class__\')}}')
        expect(detections.some((d) => d.detail.includes('context-escape'))).toBe(true)
    })

    it('detects context escape via class/mro chain', () => {
        const detections = detectSSTI('{{[].__class__.__mro__}}')
        expect(detections.some((d) => d.confidence === 0.91)).toBe(true)
    })

    it('detects blind SSTI file read probes', () => {
        const detections = detectSSTI("''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()")
        expect(detections.some((d) => d.confidence === 0.90)).toBe(true)
    })

    it('detects Freemarker Execute blind probes', () => {
        const detections = detectSSTI('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("/etc/passwd")}')
        expect(detections.some((d) => d.confidence === 0.90)).toBe(true)
    })

    it('detects Jinja2-specific config.items payloads', () => {
        const detections = detectSSTI('{{config.items()}}')
        expect(detections.some((d) => d.confidence === 0.93)).toBe(true)
    })

    it('detects Jinja2-specific builtins import chain', () => {
        const detections = detectSSTI('{{lipsum.__globals__.__builtins__.__import__(\'os\')}}')
        expect(detections.some((d) => d.engine === 'Jinja2' && d.confidence === 0.93)).toBe(true)
    })
})
