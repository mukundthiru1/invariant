/**
 * Deserialization Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for deserialization attacks is:
 *   ∃ signature ∈ input :
 *     signature MATCHES serialization_format_magic_bytes
 *     ∧ ∃ gadget ∈ parse(input, FORMAT_GRAMMAR) :
 *       gadget.class ∈ KNOWN_GADGET_CHAINS
 *     → attacker exploits unsafe deserialization for RCE
 *
 * This module analyzes serialized data formats structurally:
 *   - Java: magic bytes (aced0005 / rO0ABX), class name extraction
 *   - PHP: serialize() format parsing, magic method chain analysis
 *   - Python: pickle opcode analysis, __reduce__ detection
 *
 * Covers:
 *   - deser_java_gadget:   Java serialized object with gadget chain
 *   - deser_php_object:    PHP serialized object with magic methods
 *   - deser_python_pickle: Python pickle with code execution
 */


// ── Result Type ──────────────────────────────────────────────────

export interface DeserDetection {
    type: 'java_gadget' | 'php_object' | 'python_pickle'
    detail: string
    format: string
    gadgetChain: string | null
    confidence: number
}


// ── Java Deserialization ─────────────────────────────────────────
//
// Java serialized objects start with:
//   - Hex: aced 0005 (magic + version)
//   - Base64: rO0ABX (first 4 bytes base64 encoded)
//
// Known gadget chains (ysoserial):
//   - CommonsCollections 1-7
//   - CommonsBeanutils
//   - Spring1, Spring2
//   - Hibernate1
//   - JRMPClient/JRMPListener
//   - Wicket1
//   - FileUpload1
//   - C3P0
//   - JBossInterceptors

const JAVA_GADGET_CLASSES = new Set([
    'org.apache.commons.collections.Transformer',
    'org.apache.commons.collections.functors.ChainedTransformer',
    'org.apache.commons.collections.functors.ConstantTransformer',
    'org.apache.commons.collections.functors.InvokerTransformer',
    'org.apache.commons.collections4.functors.InvokerTransformer',
    'org.apache.commons.beanutils.BeanComparator',
    'org.springframework.beans.factory.ObjectFactory',
    'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
    'java.lang.Runtime',
    'java.lang.ProcessBuilder',
    'javax.management.BadAttributeValueExpException',
    'java.util.PriorityQueue',
    'sun.reflect.annotation.AnnotationInvocationHandler',
    'org.hibernate.property.BasicPropertyAccessor',
    'com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase',
    'org.jboss.interceptor.reader.SimpleInterceptorMetadata',
])

const JAVA_GADGET_KEYWORDS = [
    'ChainedTransformer', 'InvokerTransformer', 'ConstantTransformer',
    'ProcessBuilder', 'Runtime.getRuntime', 'exec(',
    'TemplatesImpl', 'BeanComparator', 'JRMPClient',
    'PriorityQueue', 'AnnotationInvocationHandler',
    'BadAttributeValueExpException', 'ObjectFactory',
]

function detectJavaGadget(input: string): DeserDetection[] {
    const detections: DeserDetection[] = []

    // Check for Java serialization magic bytes
    const hasHexMagic = /aced\s*0005/i.test(input)
    const hasBase64Magic = input.includes('rO0ABX')

    if (!hasHexMagic && !hasBase64Magic) return detections

    // Try to decode Base64 and extract class names
    let decoded = input
    if (hasBase64Magic) {
        try {
            decoded = atob(input.replace(/\s/g, ''))
        } catch { /* use original */ }
    }

    // Look for known gadget class names
    let foundGadget: string | null = null
    for (const kw of JAVA_GADGET_KEYWORDS) {
        if (decoded.includes(kw) || input.includes(kw)) {
            foundGadget = kw
            break
        }
    }

    detections.push({
        type: 'java_gadget',
        detail: `Java serialized object${foundGadget ? ` with gadget: ${foundGadget}` : ' (magic bytes detected)'}`,
        format: hasBase64Magic ? 'Base64' : 'Hex',
        gadgetChain: foundGadget,
        confidence: foundGadget ? 0.96 : 0.82,
    })

    return detections
}


// ── PHP Deserialization ──────────────────────────────────────────
//
// PHP serialize format:
//   O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
//   a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}
//
// Structure: type:length:"value"
//   O = object, s = string, a = array, i = integer, b = boolean
//   N = null, d = double, r = reference, R = pointer reference

interface PHPSerializedValue {
    type: string           // O, s, a, i, b, N, d
    className: string | null
    properties: string[]
    raw: string
}

function parsePHPSerialized(input: string): PHPSerializedValue | null {
    // Match PHP object serialization pattern
    const objMatch = input.match(/^O:(\d+):"([^"]+)":(\d+):\{(.+)\}\s*$/)
    if (objMatch) {
        const className = objMatch[2]
        // Extract property names from the serialized string
        const properties: string[] = []
        const propPattern = /s:\d+:"([^"]+)"/g
        let match: RegExpExecArray | null
        while ((match = propPattern.exec(objMatch[4])) !== null) {
            properties.push(match[1])
        }
        return { type: 'O', className, properties, raw: input }
    }

    // Match PHP array serialization
    const arrMatch = input.match(/^a:(\d+):\{(.+)\}\s*$/)
    if (arrMatch) {
        return { type: 'a', className: null, properties: [], raw: input }
    }

    return null
}

const PHP_DANGEROUS_CLASSES = new Set([
    '__destruct', '__wakeup', '__toString', '__call', '__callStatic',
    '__get', '__set', '__isset', '__unset', '__invoke',
])

const PHP_GADGET_CLASSES = new Set([
    'Monolog\\Handler\\SyslogUdpHandler',
    'Guzzle\\Common\\Event\\EventSubscriberInterface',
    'Symfony\\Component\\Process\\Process',
    'Swift_Transport_EsmtpTransport',
    'Doctrine\\Common\\Cache\\FilesystemCache',
])

function detectPHPObject(input: string): DeserDetection[] {
    const detections: DeserDetection[] = []

    // Check for PHP serialized object pattern
    const hasObjectSig = /O:\d+:"[^"]+":\d+:\{/.test(input)
    const hasArraySig = /a:\d+:\{/.test(input)

    if (!hasObjectSig && !hasArraySig) return detections

    const parsed = parsePHPSerialized(input)

    if (parsed && parsed.type === 'O' && parsed.className) {
        // Check for known dangerous properties (magic method indicators)
        const hasDangerousProp = parsed.properties.some(p =>
            p === 'cmd' || p === 'command' || p === 'exec' ||
            p === 'callback' || p === 'function' || p === 'handler'
        )

        detections.push({
            type: 'php_object',
            detail: `PHP serialized object: ${parsed.className}${hasDangerousProp ? ' with dangerous properties' : ''}`,
            format: 'PHP serialize',
            gadgetChain: parsed.className,
            confidence: hasDangerousProp ? 0.94 : 0.82,
        })
    } else if (hasObjectSig) {
        // Partial match — couldn't fully parse but signature is there
        detections.push({
            type: 'php_object',
            detail: 'PHP serialized object signature detected',
            format: 'PHP serialize',
            gadgetChain: null,
            confidence: 0.78,
        })
    }

    return detections
}


// ── Python Pickle ────────────────────────────────────────────────
//
// Pickle format uses opcodes. Dangerous ones:
//   c = GLOBAL (imports module.function)
//   R = REDUCE (calls function with args)
//   i = INST (creates instance)
//   o = OBJ (builds object)
//
// Common malicious patterns:
//   cos\nsystem\n(S'id'\ntR.    → os.system("id")
//   cbuiltins\neval\n           → builtins.eval(...)
//   cposix\nsystem\n            → posix.system(...)

const PICKLE_DANGEROUS_IMPORTS = [
    /c(os|posix)\n(system|popen|exec[lv]?[pe]?)\n/,      // os.system
    /c(builtins|__builtin__)\n(eval|exec|compile)\n/,     // builtins.eval
    /csubprocess\n(call|Popen|check_output)\n/,            // subprocess.call
    /cshutil\n(rmtree|move|copy)\n/,                       // shutil operations
    /cpickle\nloads\n/,                                     // recursive pickle
    /cio\nBytesIO\n/,                                       // IO manipulation
]

const PICKLE_MAGIC_BYTES = [
    /\x80[\x02-\x05]\x95/,     // Protocol 2-5 frame header
    /\x80\x04\x95/,             // Protocol 4 (most common)
    /cos\n/,                     // Protocol 0 GLOBAL opcode
    /cbuiltins\n/,               // Protocol 0 builtins import
    /c__builtin__\n/,            // Protocol 0 legacy import
    /cposix\n/,                  // Protocol 0 posix import
]

function detectPythonPickle(input: string): DeserDetection[] {
    const detections: DeserDetection[] = []

    // Check for pickle signatures
    const hasPickle = PICKLE_MAGIC_BYTES.some(p => p.test(input))
    if (!hasPickle) return detections

    // Check for dangerous imports
    let dangerousImport: string | null = null
    for (const pattern of PICKLE_DANGEROUS_IMPORTS) {
        const match = input.match(pattern)
        if (match) {
            dangerousImport = match[0].replace(/\n/g, '.').replace(/^c/, '').replace(/\.$/, '')
            break
        }
    }

    detections.push({
        type: 'python_pickle',
        detail: `Python pickle${dangerousImport ? ` with dangerous import: ${dangerousImport}` : ' (serialization signature detected)'}`,
        format: 'Python pickle',
        gadgetChain: dangerousImport,
        confidence: dangerousImport ? 0.96 : 0.80,
    })

    return detections
}


// ── Public API ───────────────────────────────────────────────────

export function detectDeserialization(input: string): DeserDetection[] {
    const detections: DeserDetection[] = []

    if (input.length < 5) return detections

    try { detections.push(...detectJavaGadget(input)) } catch { /* safe */ }
    try { detections.push(...detectPHPObject(input)) } catch { /* safe */ }
    try { detections.push(...detectPythonPickle(input)) } catch { /* safe */ }

    return detections
}
