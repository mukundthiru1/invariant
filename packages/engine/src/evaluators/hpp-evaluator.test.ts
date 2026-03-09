import { describe, it, expect } from 'vitest'
import { detectHttpParameterPollution } from './hpp-evaluator.js'

describe('HPP evaluator', () => {
    it('detects duplicate query param with different values', () => {
        const r = detectHttpParameterPollution('?role=user&role=admin')
        expect(r).not.toBeNull()
        expect(r!.type).toBe('duplicate_query_param')
        expect(r!.paramName).toBe('role')
        expect(r!.values).toEqual(['user', 'admin'])
        expect(r!.confidence).toBe(0.89)
    })

    it('detects duplicate query param in URL', () => {
        const r = detectHttpParameterPollution('https://api.example.com?role=user&role=admin')
        expect(r).not.toBeNull()
        expect(r!.type).toBe('duplicate_query_param')
        expect(r!.paramName).toBe('role')
        expect(r!.confidence).toBe(0.89)
    })

    it('detects duplicate param when query string has no leading ?', () => {
        const r = detectHttpParameterPollution('role=user&role=admin')
        expect(r).not.toBeNull()
        expect(r!.type).toBe('duplicate_query_param')
        expect(r!.confidence).toBe(0.89)
    })

    it('detects duplicate JSON key in body', () => {
        const r = detectHttpParameterPollution('{"role":"user","role":"admin"}')
        expect(r).not.toBeNull()
        expect(r!.type).toBe('duplicate_json_key')
        expect(r!.paramName).toBe('role')
        expect(r!.detail).toContain('duplicate JSON key')
        expect(r!.confidence).toBe(0.89)
    })

    it('detects duplicate param with same value repeated (still HPP)', () => {
        const r = detectHttpParameterPollution('?id=1&id=1&id=1')
        expect(r).not.toBeNull()
        expect(r!.type).toBe('duplicate_query_param')
        expect(r!.values!.length).toBe(3)
        expect(r!.confidence).toBe(0.89)
    })

    it('returns null for single param', () => {
        expect(detectHttpParameterPollution('?role=admin')).toBeNull()
        expect(detectHttpParameterPollution('role=admin')).toBeNull()
    })

    it('returns null for valid JSON without duplicate keys', () => {
        expect(detectHttpParameterPollution('{"role":"admin","name":"bob"}')).toBeNull()
    })

    it('returns null for empty or too short input', () => {
        expect(detectHttpParameterPollution('')).toBeNull()
        expect(detectHttpParameterPollution('ab')).toBeNull()
    })
})
