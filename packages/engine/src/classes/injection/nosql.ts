/**
 * NoSQL injection classes — Operator injection + JS injection
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const nosqlOperatorInjection: InvariantClassModule = {
    id: 'nosql_operator_injection',
    description: 'NoSQL query operator injection — MongoDB $gt, $ne, $regex operators in user input',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.82 },

    mitre: ['T1190'],
    cwe: 'CWE-943',

    knownPayloads: [
        '{"$gt":""}',
        '{"$ne":null}',
        '{"$regex":".*"}',
        '{"$where":"this.password.length>0"}',
        '{"username":{"$ne":""},"password":{"$ne":""}}',
    ],

    knownBenign: [
        '{"name":"test"}',
        '{"price":10}',
        'dollar sign $5',
        '$HOME environment variable',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\$(?:gt|gte|lt|lte|ne|eq|in|nin|regex|exists|type|where|or|and|not|nor|elemMatch)\b/i.test(d)
            || /\{"?\$(?:gt|ne|regex|where)"?\s*:/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = ['{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}', '{"$where":"this.password.length>0"}',
            '{"username":{"$ne":""},"password":{"$ne":""}}']
        return v.slice(0, count)
    },
}

export const nosqlJsInjection: InvariantClassModule = {
    id: 'nosql_js_injection',
    description: 'NoSQL JavaScript injection — server-side JS execution via MongoDB $where or mapReduce',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1190', 'T1059.007'],
    cwe: 'CWE-943',

    knownPayloads: [
        '{"$where":"sleep(5000)"}',
        '{"$where":"this.password.match(/^a/)"}',
        '{"$where":"function(){return this.admin==true;}"}',
    ],

    knownBenign: [
        '{"status":"active"}',
        'where clause in SQL',
        'sleep for 5 seconds',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /["']?\$where["']?\s*:\s*["']?(?:function|this\.|sleep|db\.|emit|tojson)/i.test(d)
            || (/mapReduce.*function/i.test(d) && /emit\(/i.test(d))
    },
    generateVariants: (count: number): string[] => {
        const v = ['{"$where":"sleep(5000)"}', '{"$where":"this.password.match(/^a/)"}',
            '{"$where":"function(){return this.admin==true;}"}']
        return v.slice(0, count)
    },
}
