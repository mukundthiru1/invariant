/**
 * NoSQL injection classes — Operator injection + JS injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2NoSQLOperator, l2NoSQLJS } from '../../evaluators/l2-adapters.js'

export const nosqlOperatorInjection: InvariantClassModule = {
    id: 'nosql_operator_injection',
    description: 'NoSQL operator injection — MongoDB/CouchDB query operators, Elasticsearch query-script abuse, and Redis SSRF command vectors',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.82 },

    mitre: ['T1190'],
    cwe: 'CWE-943',

    knownPayloads: [
        '{"$where":"this.password == \\"x\\""}',
        '{"$gt":""}',
        '{"username":{"$ne":null}}',
        '{"email":{"$regex":"^admin","$options":"i"}}',
        '{"$in":["admin","user"]}',
        '{"$nin":[""]}',
        '{"selector":{"$or":[{"type":"admin"}]}}',
        '{"query":{"match_all":{}}}',
        '{"query":{"script":{"script":{"source":"ctx._source.isAdmin=true","lang":"painless"}}}}',
        'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a',
    ],

    knownBenign: [
        '{"name":"test"}',
        '{"price":10}',
        '{"query":{"term":{"status":"active"}}}',
        'redis cache warmup command list',
        'dollar sign $5',
        '$HOME environment variable',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasMongoOrCouchOperator = /\$(?:gt|gte|lt|lte|ne|eq|in|nin|regex|exists|type|where|or|and|not|nor|elemMatch|options)\b/i.test(d)
            || /\{"?\$(?:gt|ne|regex|where)"?\s*:/i.test(d)
            || /"selector"\s*:\s*\{[^}]{0,300}"\$(?:or|and|nor|not)"/i.test(d)

        const hasElasticPattern = /"query"\s*:\s*\{\s*"match_all"\s*:\s*\{\s*\}\s*\}/i.test(d)
            || /"script"\s*:\s*\{[^}]{0,600}"source"\s*:/i.test(d)

        const hasRedisSsrfTransport = /(?:gopher|redis|dict):\/\/|(?:127\.0\.0\.1|localhost|::1)(?::6379)?|%0d%0a/i.test(d)
        let hasRedisSsrfCommand = false
        if (hasRedisSsrfTransport) {
            hasRedisSsrfCommand = /(?:flushall|slaveof|replicaof)\b/i.test(d)
                || /config(?:\s+|%20|%0d%0a|%0a|%0d|\+)+set/i.test(d)
                || /debug(?:\s+|%20|%0d%0a|%0a|%0d|\+)+object/i.test(d)
        }

        return hasMongoOrCouchOperator || hasElasticPattern || hasRedisSsrfCommand
    },
    detectL2: l2NoSQLOperator,
    generateVariants: (count: number): string[] => {
        const v = [
            '{"$where":"this.password == \\"x\\""}',
            '{"$gt":""}',
            '{"username":{"$ne":null}}',
            '{"email":{"$regex":"^admin","$options":"i"}}',
            '{"$in":["admin","user"]}',
            '{"selector":{"$or":[{"type":"admin"}]}}',
            '{"query":{"match_all":{}}}',
        ]
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
    detectL2: l2NoSQLJS,
    generateVariants: (count: number): string[] => {
        const v = ['{"$where":"sleep(5000)"}', '{"$where":"this.password.match(/^a/)"}',
            '{"$where":"function(){return this.admin==true;}"}']
        return v.slice(0, count)
    },
}
