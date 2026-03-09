/**
 * GraphQL and API Abuse Detection Gap Analysis
 * Tests various attack vectors against current detection capabilities
 */

import { describe, it, expect } from 'vitest'
import { graphqlIntrospection, graphqlBatchAbuse } from './graphql.js'
import { bolaIdor, apiMassEnum } from './api-abuse.js'
import { detectGraphQLAbuse } from '../../evaluators/graphql-evaluator.js'
import { detectAPIAbuse } from '../../evaluators/api-abuse-evaluator.js'

describe('GraphQL Gap Analysis', () => {
    
    // ==== 1. GraphQL Introspection ====
    describe('1. Introspection Detection', () => {
        const tests = [
            { name: 'Basic __schema query', payload: '{__schema{queryType{name}}}', l1: true, l2: true },
            { name: 'Full introspection query', payload: '{__schema{types{name fields{name}}}}', l1: true, l2: true },
            { name: '__type query', payload: 'query{__type(name:"User"){fields{name type{name}}}}', l1: true, l2: true },
            { name: 'Case insensitive __SCHEMA', payload: '{__SCHEMA{queryType{name}}}', l1: true, l2: true },
            { name: '__InputValue introspection', payload: '{__type{name inputFields{name type{name}}}}', l1: true, l2: true },
            { name: 'Benign query', payload: '{ user { name } }', l1: false, l2: false },
            { name: 'Mutation', payload: 'mutation { addUser }', l1: false, l2: false },
        ]

        tests.forEach(({ name, payload, l1, l2 }) => {
            it(`L1: ${name}`, () => {
                expect(graphqlIntrospection.detect!(payload)).toBe(l1)
            })
            it(`L2: ${name}`, () => {
                const result = graphqlIntrospection.detectL2!(payload)
                expect(!!result?.detected).toBe(l2)
            })
        })
    })

    // ==== 2. Deeply Nested Queries (10+ levels) ====
    describe('2. Deeply Nested Query Detection', () => {
        const depth5 = '{ user { friends { name } } }'
        const depth10 = '{ a { b { c { d { e { f { g { h { i { j } } } } } } } } } }'
        const depth15 = '{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o } } } } } } } } } } } } } } }'
        const depth20 = '{ ' + 'a{'.repeat(20) + 'x' + '}'.repeat(20) + ' }'

        const tests = [
            { name: 'Depth 5 (benign)', query: depth5, threshold: 10, expectL2: false },
            { name: 'Depth 10 (at threshold)', query: depth10, threshold: 10, expectL2: false },
            { name: 'Depth 15 (abuse)', query: depth15, threshold: 10, expectL2: true },
            { name: 'Depth 20 (severe abuse)', query: depth20, threshold: 10, expectL2: true },
        ]

        tests.forEach(({ name, query, expectL2 }) => {
            it(`L2: ${name}`, () => {
                const detections = detectGraphQLAbuse(query)
                const depthDetection = detections.find(d => d.type === 'depth_abuse')
                expect(!!depthDetection).toBe(expectL2)
            })
        })
    })

    // ==== 3. Alias Bombing (Same field 100x) ====
    describe('3. Alias Bombing Detection', () => {
        const alias5 = '{ ' + Array.from({length: 5}, (_, i) => `a${i}: user(id:${i}){name}`).join(' ') + ' }'
        const alias10 = '{ ' + Array.from({length: 10}, (_, i) => `a${i}: user(id:${i}){name}`).join(' ') + ' }'
        const alias11 = '{ ' + Array.from({length: 11}, (_, i) => `a${i}: user(id:${i}){name}`).join(' ') + ' }'
        const alias50 = '{ ' + Array.from({length: 50}, (_, i) => `a${i}: user(id:${i}){name}`).join(' ') + ' }'
        const alias100 = '{ ' + Array.from({length: 100}, (_, i) => `a${i}: user(id:${i}){name}`).join(' ') + ' }'

        const tests = [
            { name: '5 aliases', query: alias5, expectL2: false },
            { name: '10 aliases (at threshold)', query: alias10, expectL2: false },
            { name: '11 aliases (just above threshold)', query: alias11, expectL2: true },
            { name: '50 aliases', query: alias50, expectL2: true },
            { name: '100 aliases (bombing)', query: alias100, expectL2: true },
        ]

        tests.forEach(({ name, query, expectL2 }) => {
            it(`L2: ${name}`, () => {
                const detections = detectGraphQLAbuse(query)
                const aliasDetection = detections.find(d => d.type === 'alias_abuse')
                expect(!!aliasDetection).toBe(expectL2)
                if (aliasDetection) {
                    console.log(`  Confidence: ${aliasDetection.confidence}, Evidence: ${aliasDetection.evidence}`)
                }
            })
        })
    })

    // ==== 4. Fragment Bombing ====
    describe('4. Fragment Bombing Detection', () => {
        const fragmentNormal = `
            fragment UserFields on User { name email }
            query { user { ...UserFields } }
        `

        const fragmentCircular = `
            fragment F1 on T { a { ...F2 } }
            fragment F2 on T { b { ...F3 } }
            fragment F3 on T { c { ...F4 } }
            fragment F4 on T { d { ...F1 } }
            query { field { ...F1 } }
        `

        const fragmentSpreadBomb = `
            fragment F1 on T { a }
            fragment F2 on T { b }
            fragment F3 on T { c }
            fragment F4 on T { d }
            query { 
                f1 { ...F1 ...F2 ...F3 ...F4 }
                f2 { ...F1 ...F2 ...F3 ...F4 }
                f3 { ...F1 ...F2 ...F3 ...F4 }
                f4 { ...F1 ...F2 ...F3 ...F4 }
            }
        `

        const tests = [
            { name: 'Normal fragment usage', query: fragmentNormal, expectL2: false },
            { name: 'Circular fragment (DOS)', query: fragmentCircular, expectL2: true },
            { name: 'Fragment spread amplification', query: fragmentSpreadBomb, expectL2: true },
        ]

        tests.forEach(({ name, query, expectL2 }) => {
            it(`L2: ${name}`, () => {
                const detections = detectGraphQLAbuse(query)
                const fragmentDetection = detections.find(d => d.type === 'fragment_abuse')
                expect(!!fragmentDetection).toBe(expectL2)
            })
        })
    })

    // ==== 5. Batching Attacks ====
    describe('5. Batching Attack Detection', () => {
        const batch3 = JSON.stringify([
            {query: '{ user(id:1) { name } }'},
            {query: '{ user(id:2) { name } }'},
            {query: '{ user(id:3) { name } }'}
        ])

        const batch5 = JSON.stringify([
            {query: '{ user(id:1) { name } }'},
            {query: '{ user(id:2) { name } }'},
            {query: '{ user(id:3) { name } }'},
            {query: '{ user(id:4) { name } }'},
            {query: '{ user(id:5) { name } }'}
        ])

        const batch6 = JSON.stringify([
            {query: '{ user(id:1) { name } }'},
            {query: '{ user(id:2) { name } }'},
            {query: '{ user(id:3) { name } }'},
            {query: '{ user(id:4) { name } }'},
            {query: '{ user(id:5) { name } }'},
            {query: '{ user(id:6) { name } }'}
        ])

        const batch50 = JSON.stringify(Array.from({length: 50}, (_, i) => ({query: `{ user(id:${i}) { name } }`})))

        const tests = [
            { name: 'Batch 3 queries', query: batch3, expectL2: false },
            { name: 'Batch 5 queries (at threshold)', query: batch5, expectL2: false },
            { name: 'Batch 6 queries (just above threshold)', query: batch6, expectL2: true },
            { name: 'Batch 50 queries', query: batch50, expectL2: true },
        ]

        tests.forEach(({ name, query, expectL2 }) => {
            it(`L2: ${name}`, () => {
                const detections = detectGraphQLAbuse(query)
                const batchDetection = detections.find(d => d.type === 'batch_abuse')
                expect(!!batchDetection).toBe(expectL2)
            })
        })
    })

    // ==== 6. Field Suggestion Enumeration ====
    describe('6. Field Suggestion Enumeration (GAP IDENTIFIED)', () => {
        it('should detect typo-based field suggestion attacks', () => {
            const fieldSuggest1 = '{ usr { idd emal namee } }'  // typos of user, id, email, name
            const fieldSuggest2 = '{ userr { iddd } }'  // multiple typos
            const fieldSuggest3 = '{ productt { pricee } }'

            // Current detection capability
            const detections1 = detectGraphQLAbuse(fieldSuggest1)
            const detections2 = detectGraphQLAbuse(fieldSuggest2)
            const detections3 = detectGraphQLAbuse(fieldSuggest3)

            // These SHOULD be detected but are NOT currently implemented
            const l1Result1 = graphqlBatchAbuse.detect!(fieldSuggest1)
            const l1Result2 = graphqlBatchAbuse.detect!(fieldSuggest2)
            
            console.log('Field suggestion detection status: NOT IMPLEMENTED')
            console.log(`  L1 detection for typo queries: ${l1Result1}, ${l1Result2}`)
            console.log(`  L2 detections: ${detections1.length}, ${detections2.length}, ${detections3.length}`)
            
            // Document the gap
            expect(true).toBe(true) // This test documents the gap
        })
    })

    // ==== 7. Subscription Abuse ====
    describe('7. Subscription Abuse for Data Exfiltration (GAP IDENTIFIED)', () => {
        it('should detect sensitive field subscriptions', () => {
            const subAbuse = `
                subscription {
                    userActivity {
                        user {
                            password
                            ssn
                            creditCard
                            internalNotes
                        }
                    }
                }
            `
            const normalSub = `
                subscription {
                    newPosts {
                        title
                        content
                    }
                }
            `

            const detectionsAbuse = detectGraphQLAbuse(subAbuse)
            const detectionsNormal = detectGraphQLAbuse(normalSub)

            // No current detection for subscription abuse
            console.log('Subscription abuse detection status: NOT IMPLEMENTED')
            console.log(`  Abusive subscription detections: ${detectionsAbuse.length}`)
            console.log(`  Normal subscription detections: ${detectionsNormal.length}`)
            
            // Document the gap
            expect(true).toBe(true)
        })
    })

    // ==== 8. Directive Abuse ====
    describe('8. Directive Abuse (GAP IDENTIFIED)', () => {
        it('should detect directive-based attacks', () => {
            const directiveAbuse = `
                query {
                    user {
                        name @skip(if: false)
                        password @include(if: true)
                        ssn @deprecated @skip(if: false)
                    }
                }
            `

            const detections = detectGraphQLAbuse(directiveAbuse)
            
            console.log('Directive abuse detection status: NOT IMPLEMENTED')
            console.log(`  Directive abuse detections: ${detections.length}`)
            
            expect(true).toBe(true)
        })
    })
})

describe('API Abuse Gap Analysis', () => {
    
    // ==== 8. REST API Verb Tampering ====
    describe('8. REST API Verb Tampering (GAP IDENTIFIED)', () => {
        const verbTests = [
            { method: 'GET', path: '/api/users/1', benign: true },
            { method: 'POST', path: '/api/users/1', benign: true },
            { method: 'HEAD', path: '/api/admin/config', benign: false, desc: 'HEAD bypass' },
            { method: 'OPTIONS', path: '/api/users/1', benign: false, desc: 'OPTIONS probe' },
            { method: 'TRACE', path: '/api/users/1', benign: false, desc: 'TRACE/XST' },
            { method: 'TRACK', path: '/api/users/1', benign: false, desc: 'TRACK (legacy IIS)' },
            { method: 'DEBUG', path: '/api/users/1', benign: false, desc: 'DEBUG method' },
            { method: 'PUT', path: '/api/users/1', headers: 'X-HTTP-Method-Override: DELETE', benign: false, desc: 'Method override' },
            { method: 'POST', path: '/api/users/1?_method=DELETE', benign: false, desc: 'Query param override' },
        ]

        verbTests.forEach(({ method, path, benign, desc, headers }) => {
            const payload = `${method} ${path}${headers ? ` with ${headers}` : ''}`
            it(`detects ${desc || method} - ${payload}`, () => {
                const l1Result = bolaIdor.detect!(payload)
                const l2Result = bolaIdor.detectL2!(payload)
                
                // Document that verb tampering is not currently detected
                if (!benign) {
                    console.log(`  GAP: ${payload} - Not detected (L1: ${l1Result}, L2: ${!!l2Result})`)
                }
                expect(true).toBe(true)
            })
        })
    })

    // ==== BOLA/IDOR Tests ====
    describe('BOLA/IDOR Detection', () => {
        const tests = [
            { name: 'Simple ID access', payload: '/api/users/123', expectL1: false },
            { name: 'ID with auth context mismatch', payload: '/api/users/123 with Authorization: Bearer token_for_user_456', expectL1: true },
            { name: 'Sequential ID probe context', payload: '/api/orders/99999?userId=1 (sequential ID probe)', expectL1: true },
            { name: 'Path traversal to admin', payload: '/api/v1/documents/../../admin/config', expectL1: true },
            { name: 'Self reference', payload: '/api/users/me/profile', expectL1: false },
            { name: 'Pagination', payload: '/api/users?page=2&limit=10', expectL1: false },
        ]

        tests.forEach(({ name, payload, expectL1 }) => {
            it(`L1: ${name}`, () => {
                expect(bolaIdor.detect!(payload)).toBe(expectL1)
            })
        })
    })

    // ==== Mass Enumeration Tests ====
    describe('Mass Enumeration Detection', () => {
        const tests = [
            { name: '3 sequential IDs', payload: 'GET /api/users/1 GET /api/users/2 GET /api/users/3', expectL1: false },
            { name: '4 sequential IDs (at threshold)', payload: 'GET /api/users/1 GET /api/users/2 GET /api/users/3 GET /api/users/4', expectL1: false },
            { name: '5 sequential IDs', payload: 'GET /api/users/1 GET /api/users/2 GET /api/users/3 GET /api/users/4 GET /api/users/5', expectL1: true },
            { name: 'Wide range query', payload: '/api/invoices?id[gte]=1&id[lte]=99999', expectL1: true },
            { name: 'Unbound filter', payload: '/api/v1/records?filter=id>0&limit=999999', expectL1: true },
            { name: 'Normal pagination', payload: '/api/users?page=1&limit=20', expectL1: false },
        ]

        tests.forEach(({ name, payload, expectL1 }) => {
            it(`L1: ${name}`, () => {
                expect(apiMassEnum.detect!(payload)).toBe(expectL1)
            })
        })
    })

    // ==== API Rate Limiting Bypass ====
    describe('9. Rate Limiting Bypass Techniques (GAP IDENTIFIED)', () => {
        it('documents rate limiting bypass methods not detected', () => {
            const bypassTechniques = [
                'X-Forwarded-For: 1.1.1.1', // IP spoofing
                'X-Real-IP: 2.2.2.2',
                'CF-Connecting-IP: 3.3.3.3',
                'X-Originating-IP: 4.4.4.4',
                'X-Forwarded-Host: attacker.com',
                'X-Client-IP: 5.5.5.5',
                'Client-IP: 6.6.6.6',
                'True-Client-IP: 7.7.7.7',
            ]

            bypassTechniques.forEach(technique => {
                const l1Result = bolaIdor.detect!(technique)
                const l2Result = bolaIdor.detectL2!(technique)
                console.log(`  GAP: ${technique} - L1: ${l1Result}, L2: ${!!l2Result}`)
            })

            expect(true).toBe(true)
        })
    })

    // ==== API Version Abuse ====
    describe('10. API Version Abuse (GAP IDENTIFIED)', () => {
        it('documents API version manipulation not detected', () => {
            const versionAttacks = [
                '/api/v1/users/1', // normal
                '/api/v2/users/1', // version enumeration
                '/api/internal/users/1', // internal endpoint
                '/api/beta/users/1', // beta endpoint
                '/api/latest/admin/config', // latest bypass
                '/api/dev/users/1', // dev endpoint
            ]

            versionAttacks.forEach(path => {
                const l1Result = bolaIdor.detect!(path)
                console.log(`  ${path} - L1: ${l1Result}`)
            })

            expect(true).toBe(true)
        })
    })

    // ==== Content-Type Tampering ====
    describe('11. Content-Type Tampering (GAP IDENTIFIED)', () => {
        it('documents content-type manipulation for bypass', () => {
            const tamperingAttempts = [
                { ct: 'application/json', benign: true },
                { ct: 'application/x-www-form-urlencoded', benign: true },
                { ct: 'text/plain', benign: false, desc: 'Unexpected content type' },
                { ct: 'application/xml', benign: false, desc: 'XML instead of JSON' },
                { ct: 'application/x-ndjson', benign: false, desc: 'NDJSON injection' },
            ]

            console.log('Content-Type tampering detection: NOT IMPLEMENTED')
            tamperingAttempts.forEach(({ ct, benign, desc }) => {
                console.log(`  ${ct}${desc ? ` (${desc})` : ''} - No detection`)
            })

            expect(true).toBe(true)
        })
    })
})

describe('Summary of Gaps', () => {
    it('outputs gap analysis summary', () => {
        const gaps = [
            '1. Field Suggestion Enumeration: No detection for typo-based schema probing',
            '2. Subscription Abuse: No detection for sensitive field subscriptions',
            '3. Directive Abuse: No detection for @skip/@include/@deprecated manipulation',
            '4. REST Verb Tampering: No detection for HEAD/OPTIONS/TRACE/X-HTTP-Method-Override',
            '5. Rate Limiting Bypass: No detection for X-Forwarded-For and similar headers',
            '6. API Version Abuse: No detection for internal/beta/dev endpoint access',
            '7. Content-Type Tampering: No detection for unexpected content types',
            '8. GraphQL Variable Injection: Not specifically detected',
            '9. Persisted Query Abuse: No detection for malicious persisted queries',
            '10. Query Cost Analysis: No cost-based depth/alias validation',
        ]

        console.log('\n' + '='.repeat(80))
        console.log('IDENTIFIED GAPS IN GRAPHQL/API ABUSE DETECTION')
        console.log('='.repeat(80))
        gaps.forEach(gap => console.log(gap))
        console.log('='.repeat(80))

        expect(true).toBe(true)
    })
})
