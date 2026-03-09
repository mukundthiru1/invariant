import { describe, expect, it } from 'vitest'
import {
    detectDeserialization,
    detectDeserDotNetFormatter,
    detectDeserJavaGadgetChain,
    detectDeserYamlConstructor,
} from './deser-evaluator.js'

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

    it('detects Java gadget chains in Commons Collections serialization payloads', () => {
        const payload = 'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQABChAIdGVzdA==org.apache.commons.collections.functors.ChainedTransformer'
        const detection = detectDeserJavaGadgetChain(payload)
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('java_gadget')
        expect(detection?.confidence).toBe(0.95)
    })

    it('detects Java serialization payloads with aced0005 and Spring class markers', () => {
        const payload = 'aced0005org.springframework.context.support.ClassPathXmlApplicationContext'
        const detection = detectDeserJavaGadgetChain(payload)
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('java_gadget')
        expect(detection?.detail).toContain('Spring')
    })

    it('detects unsafe YAML python object constructors', () => {
        const payload = '!!python/object/apply:os.system ["id"]'
        const detection = detectDeserYamlConstructor(payload)
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('python_pickle')
        expect(detection?.detail).toContain('YAML unsafe constructor')
    })

    it('detects unsafe YAML java runtime constructors', () => {
        const payload = 'payload: !!java.lang.Runtime ["/bin/sh","-c","id"]'
        const detection = detectDeserYamlConstructor(payload)
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('java_gadget')
        expect(detection?.detail).toContain('!!java.lang.Runtime')
    })

    it('detects .NET BinaryFormatter TypeConfuseDelegate patterns', () => {
        const payload = 'AAEAAAD/////BinaryFormatter.TypeConfuseDelegate.SerializedData'
        const detection = detectDeserDotNetFormatter(payload)
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('java_gadget')
        expect(detection?.confidence).toBe(0.92)
    })

    it('detects .NET ObjectDataProvider gadget chains', () => {
        const payload = 'AAEAAAD/wEAAAAAAAAA:System.Windows.Data.ObjectDataProvider'
        const detection = detectDeserDotNetFormatter(payload)
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('java_gadget')
        expect(detection?.gadgetChain).toContain('ObjectDataProvider')
    })
})
