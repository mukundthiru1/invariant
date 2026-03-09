import { describe, it, expect } from 'vitest'
import {
    detectPrototypePollution,
    detectPrototypePollutionViaConstructor,
    detectPrototypePollutionViaClone,
    detectPrototypePollutionInUrl,
} from './proto-pollution-evaluator.js'

describe('proto-pollution-evaluator', () => {
    it('ViaConstructor: detects .constructor.prototype.prop pattern', () => {
        const input = 'obj.constructor.prototype.isAdmin = true'
        const r = detectPrototypePollutionViaConstructor(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('constructor_chain')
        expect(r!.path).toContain('constructor')
        expect(r!.path).toContain('prototype')
        expect(r!.pollutedProperty).toBe('isadmin')
        expect(r!.confidence).toBe(0.94)
    })

    it('ViaConstructor: detects bracket ["constructor"]["prototype"] pattern', () => {
        const input = "x['constructor']['prototype']['polluted'] = 1"
        const r = detectPrototypePollutionViaConstructor(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('constructor_chain')
        expect(r!.confidence).toBe(0.94)
    })

    it('ViaClone: detects JSON with __proto__ key', () => {
        const input = '_.merge({}, JSON.parse(req.body)); req.body = {"__proto__":{"isAdmin":true}}'
        const r = detectPrototypePollutionViaClone(input)
        expect(r).not.toBeNull()
        expect(r!.confidence).toBe(0.93)
        expect(r!.detail).toMatch(/clone|merge|__proto__/i)
    })

    it('ViaClone: detects merge/assign with untrusted and __proto__ in input', () => {
        const input = 'Object.assign({}, JSON.parse(userInput)); __proto__'
        const r = detectPrototypePollutionViaClone(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('json_proto_path')
        expect(r!.confidence).toBe(0.93)
    })

    it('InUrl: detects __proto__ and constructor[prototype] in query string', () => {
        const url = 'https://example.com/api?__proto__[isAdmin]=true'
        const r = detectPrototypePollutionInUrl(url)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('bracket_proto_path')
        expect(r!.path).toContain('__proto__')
        expect(r!.confidence).toBe(0.91)
    })

    it('InUrl: detects nested param a[b][__proto__][polluted]=1', () => {
        const url = 'https://site.com/?a[b][__proto__][polluted]=1'
        const r = detectPrototypePollutionInUrl(url)
        expect(r).not.toBeNull()
        expect(r!.evidence).toContain('__proto__')
        expect(r!.confidence).toBe(0.91)
    })
})

describe('detectPrototypePollution integration', () => {
    it('aggregates ViaConstructor, ViaClone, and InUrl in full detection', () => {
        const payload = 'https://evil.com?constructor[prototype][x]=1'
        const detections = detectPrototypePollution(payload)
        expect(detections.some(d => d.type === 'constructor_chain' || d.type === 'bracket_proto_path')).toBe(true)
        expect(detections.every(d => d.l2)).toBe(true)
    })
})
