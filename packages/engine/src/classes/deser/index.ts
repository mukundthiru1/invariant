/**
 * Deserialization Invariant Classes — All 3
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const deserJavaGadget: InvariantClassModule = {
    id: 'deser_java_gadget',
    description: 'Java deserialization gadget chain to achieve remote code execution',
    category: 'deser',
    severity: 'critical',
    calibration: { baseConfidence: 0.92 },

    mitre: ['T1203'],
    cwe: 'CWE-502',

    knownPayloads: [
        'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==',
        'aced00057372',
        'java.lang.Runtime.getRuntime().exec("id")',
    ],

    knownBenign: [
        'java programming language',
        'runtime error occurred',
        'application serialized data',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /aced0005|rO0ABX/i.test(d) ||
            /(?:java\.lang\.Runtime|ProcessBuilder|ChainedTransformer|InvokerTransformer|ConstantTransformer|commons-collections|ysoserial)/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = ['rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==', 'aced00057372']
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const deserPhpObject: InvariantClassModule = {
    id: 'deser_php_object',
    description: 'PHP object injection via unserialize() to trigger magic methods',
    category: 'deser',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },

    mitre: ['T1203'],
    cwe: 'CWE-502',

    knownPayloads: [
        'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}',
        'O:11:"Application":1:{s:3:"cmd";s:2:"id";}',
    ],

    knownBenign: [
        'Order #12345',
        'O: oxygen',
        'a: apple',
        'the format is O:N:',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /O:\d+:"[^"]+"/.test(d) || /a:\d+:\{/.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}',
            'O:11:"Application":1:{s:3:"cmd";s:2:"id";}',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const deserPythonPickle: InvariantClassModule = {
    id: 'deser_python_pickle',
    description: 'Python pickle deserialization to execute arbitrary code via __reduce__',
    category: 'deser',
    severity: 'critical',
    calibration: { baseConfidence: 0.92 },

    mitre: ['T1203'],
    cwe: 'CWE-502',

    knownPayloads: [
        "cos\nsystem\n(S'id'\ntR.",
        "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR.",
    ],

    knownBenign: [
        'pickle jar',
        'python programming',
        'import os',
        'reduce function',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\x80\x04\x95|cos\nsystem|cbuiltins\n|c__builtin__|cposix\nsystem/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = ["cos\nsystem\n(S'id'\ntR.", "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR."]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const DESER_CLASSES: InvariantClassModule[] = [deserJavaGadget, deserPhpObject, deserPythonPickle]
