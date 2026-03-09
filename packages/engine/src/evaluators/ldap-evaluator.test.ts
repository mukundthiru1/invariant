import { describe, it, expect } from 'vitest'
import { detectLDAPInjection } from './ldap-evaluator.js'

describe('ldap-evaluator advanced bypass detection', () => {
    it('detects sequential single-char probes with password wildcard probe', () => {
        const detections = detectLDAPInjection('(&(cn=a*)(cn=b*)(userPassword=*))')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects repeated wildcard abuse in attribute filters', () => {
        const detections = detectLDAPInjection('(&(cn=a**)(uid=test))')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects LDAP special character hex escapes', () => {
        const detections = detectLDAPInjection('(cn=admin\\28\\29\\00)')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects unicode escape bypasses', () => {
        const detections = detectLDAPInjection('(uid=joe\\u0028\\u0029)')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects unescaped comma before DN component (DN injection)', () => {
        const detections = detectLDAPInjection('(uid=admin,cn=users,dc=corp)')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('does not flag simple safe LDAP filter', () => {
        const detections = detectLDAPInjection('(uid=johndoe)')
        expect(detections.filter(d => d.confidence > 0.85).length).toBe(0)
    })
})
