import { describe, expect, it } from 'vitest'
import { detectDeserialization } from './deser-evaluator.js'

describe('deser-evaluator', () => {
    const cases: Array<{ label: string, payload: string, type: 'java_gadget' | 'php_object' | 'python_pickle' }> = [
        {
            label: 'java serialized base64 magic',
            payload: 'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==',
            type: 'java_gadget',
        },
        {
            label: 'python pickle opcode chain',
            payload: "cos\nsystem\n(S'id'\ntR.",
            type: 'python_pickle',
        },
        {
            label: 'php serialized object',
            payload: 'O:7:"Example":1:{s:3:"foo";s:3:"bar";}',
            type: 'php_object',
        },
        {
            label: 'dotnet binaryformatter base64 prefix',
            payload: 'AAEAAAD/////AQAAAAAAAAAMAgAAAFN5c3RlbS5TdHJpbmc=',
            type: 'java_gadget',
        },
        {
            label: 'ruby marshal magic',
            payload: '\\x04\\x08o:\\x08Gem::SpecFetcher',
            type: 'java_gadget',
        },
        {
            label: 'yaml python apply',
            payload: '!!python/object/apply:os.system ["id"]',
            type: 'python_pickle',
        },
        {
            label: 'yaml java processbuilder',
            payload: '!!java.lang.ProcessBuilder ["/bin/sh","-c","id"]',
            type: 'java_gadget',
        },
        {
            label: 'json type gadget key',
            payload: '{"@class":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","cmd":"id"}',
            type: 'java_gadget',
        },
        {
            label: 'xml decoder gadget',
            payload: '<java.beans.XMLDecoder><object class="java.lang.ProcessBuilder"><void method="start"/></object></java.beans.XMLDecoder>',
            type: 'java_gadget',
        },
        {
            label: 'node json prototype mutation',
            payload: '{"constructor":{"prototype":{"polluted":true}}}',
            type: 'php_object',
        },
        {
            label: 'messagepack typed ext chain',
            payload: 'application/x-msgpack {"type":"ExtType","className":"java.lang.Runtime"}',
            type: 'java_gadget',
        },
    ]

    it.each(cases)('detects $label', ({ payload, type }) => {
        const detections = detectDeserialization(payload)
        expect(detections.some(d => d.type === type)).toBe(true)
        const match = detections.find(d => d.type === type)
        expect(match?.proofEvidence?.length).toBeGreaterThan(0)
    })

    it('decodes base64 payloads before magic-byte checks', () => {
        const b64 = Buffer.from('\xAC\xED\x00\x05java.lang.Runtime.getRuntime().exec', 'latin1').toString('base64')
        const detections = detectDeserialization(b64)
        const match = detections.find(d => d.type === 'java_gadget')
        expect(match).toBeDefined()
        expect(match?.gadgetChain).toBeTruthy()
    })

    it('avoids flagging short benign text', () => {
        expect(detectDeserialization('hello world')).toHaveLength(0)
    })
})
