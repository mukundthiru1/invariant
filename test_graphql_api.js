/**
 * GraphQL and API Abuse Detection Gap Analysis Test Suite
 */

const { graphqlIntrospection, graphqlBatchAbuse } = require('./packages/engine/src/classes/injection/graphql.ts');
const { bolaIdor, apiMassEnum } = require('./packages/engine/src/classes/injection/api-abuse.ts');

// Test helper
function testDetection(name, detector, payload, expected) {
    let result;
    try {
        if (typeof detector.detect === 'function') {
            result = detector.detect(payload);
        } else {
            result = false;
        }
    } catch (e) {
        result = `ERROR: ${e.message}`;
    }
    const status = result === expected ? '✓' : '✗';
    return `${status} ${name}: ${result === expected ? 'PASS' : `FAIL (got: ${result}, expected: ${expected})`}`;
}

function testL2(name, detector, payload) {
    let result;
    try {
        if (typeof detector.detectL2 === 'function') {
            result = detector.detectL2(payload);
            result = result ? `DETECTED(${result.confidence})` : 'NOT DETECTED';
        } else {
            result = 'NO L2 DETECTOR';
        }
    } catch (e) {
        result = `ERROR: ${e.message}`;
    }
    return `  L2 ${name}: ${result}`;
}

console.log('='.repeat(80));
console.log('GraphQL and API Abuse Detection Gap Analysis');
console.log('='.repeat(80));

// ==== 1. GraphQL Introspection Tests ====
console.log('\n[1] GraphQL Introspection Detection');
console.log('-'.repeat(40));

const introspectionTests = [
    ['Basic __schema query', '{__schema{queryType{name}}}', true],
    ['Full introspection query', '{__schema{types{name fields{name}}}}', true],
    ['__type query', 'query{__type(name:"User"){fields{name type{name}}}}', true],
    ['Case insensitive __SCHEMA', '{__SCHEMA{queryType{name}}}', true],
    ['Benign query', '{ user { name } }', false],
    ['Mutation', 'mutation { addUser }', false],
    ['Introspection via encoding', '{__sch' + 'ema{queryType{name}}}', true], // basic split
];

introspectionTests.forEach(([name, payload, expected]) => {
    console.log(testDetection(name, graphqlIntrospection, payload, expected));
    console.log(testL2(name, graphqlIntrospection, payload));
});

// ==== 2. Deeply Nested Queries (10+ levels) ====
console.log('\n[2] Deeply Nested Query Detection');
console.log('-'.repeat(40));

const depth5 = '{ user { friends { name } } }';
const depth10 = '{ a { b { c { d { e { f { g { h { i { j } } } } } } } } } }';
const depth15 = '{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o } } } } } } } } } } } } } } }';
const depth20 = '{ ' + 'a{'.repeat(20) + 'x' + '}'.repeat(20) + ' }';

console.log(`Depth 5 (benign): ${graphqlBatchAbuse.detect ? graphqlBatchAbuse.detect(depth5) : 'N/A'}`);
console.log(`Depth 10 (boundary): ${graphqlBatchAbuse.detect ? graphqlBatchAbuse.detect(depth10) : 'N/A'}`);
console.log(`Depth 15: ${graphqlBatchAbuse.detect ? graphqlBatchAbuse.detect(depth15) : 'N/A'}`);
console.log(`Depth 20: ${graphqlBatchAbuse.detect ? graphqlBatchAbuse.detect(depth20) : 'N/A'}`);

// Test L2 depth detection
console.log('\n  L2 Depth Analysis:');
[depth5, depth10, depth15, depth20].forEach((q, i) => {
    const depths = [5, 10, 15, 20];
    console.log(`  Depth ${depths[i]}: ${testL2(`depth-${depths[i]}`, graphqlBatchAbuse, q)}`);
});

// ==== 3. Alias Bombing (Same field 100x) ====
console.log('\n[3] Alias Bombing Detection');
console.log('-'.repeat(40));

const alias5 = '{ a1: login(u:"a",p:"1") a2: login(u:"b",p:"2") a3: login(u:"c",p:"3") a4: login(u:"d",p:"4") a5: login(u:"e",p:"5") }';
const alias10 = Array.from({length: 10}, (_, i) => `a${i}: user(id:${i}){name}`).join(' ');
const alias50 = Array.from({length: 50}, (_, i) => `a${i}: user(id:${i}){name}`).join(' ');
const alias100 = Array.from({length: 100}, (_, i) => `a${i}: user(id:${i}){name}`).join(' ');

console.log(`Alias count 5: ${graphqlBatchAbuse.detect(alias5) ? 'DETECTED' : 'NOT DETECTED'}`);
console.log(`Alias count 10: ${graphqlBatchAbuse.detect(alias10) ? 'DETECTED' : 'NOT DETECTED'}`);
console.log(`Alias count 50: ${graphqlBatchAbuse.detect(alias50) ? 'DETECTED' : 'NOT DETECTED'}`);
console.log(`Alias count 100: ${graphqlBatchAbuse.detect(alias100) ? 'DETECTED' : 'NOT DETECTED'}`);

// ==== 4. Fragment Bombing ====
console.log('\n[4] Fragment Bombing Detection');
console.log('-'.repeat(40));

const fragmentNormal = `
  fragment UserFields on User { name email }
  query { user { ...UserFields } }
`;

const fragmentBomb = `
  fragment F1 on T { a { ...F2 } }
  fragment F2 on T { b { ...F3 } }
  fragment F3 on T { c { ...F4 } }
  fragment F4 on T { d { ...F1 } }
  query { field { ...F1 } }
`;

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
`;

console.log(`Normal fragment: ${graphqlBatchAbuse.detect(fragmentNormal) ? 'DETECTED' : 'NOT DETECTED'}`);
console.log(`Circular fragment: ${graphqlBatchAbuse.detect(fragmentBomb) ? 'DETECTED' : 'NOT DETECTED'}`);
console.log(`Fragment spread bomb: ${graphqlBatchAbuse.detect(fragmentSpreadBomb) ? 'DETECTED' : 'NOT DETECTED'}`);

// ==== 5. Batching Attacks ====
console.log('\n[5] Batching Attack Detection');
console.log('-'.repeat(40));

const batch3 = JSON.stringify([
    {query: '{ user(id:1) { name } }'},
    {query: '{ user(id:2) { name } }'},
    {query: '{ user(id:3) { name } }'}
]);

const batch6 = JSON.stringify([
    {query: '{ user(id:1) { name } }'},
    {query: '{ user(id:2) { name } }'},
    {query: '{ user(id:3) { name } }'},
    {query: '{ user(id:4) { name } }'},
    {query: '{ user(id:5) { name } }'},
    {query: '{ user(id:6) { name } }'}
]);

const batch50 = JSON.stringify(Array.from({length: 50}, (_, i) => ({query: `{ user(id:${i}) { name } }`})));

console.log(`Batch 3 queries: ${graphqlBatchAbuse.detect(batch3) ? 'DETECTED' : 'NOT DETECTED'}`);
console.log(`Batch 6 queries: ${graphqlBatchAbuse.detect(batch6) ? 'DETECTED' : 'NOT DETECTED'}`);
console.log(`Batch 50 queries: ${graphqlBatchAbuse.detect(batch50) ? 'DETECTED' : 'NOT DETECTED'}`);

// ==== 6. Field Suggestion Enumeration ====
console.log('\n[6] Field Suggestion Enumeration');
console.log('-'.repeat(40));
console.log('Field suggestion enumeration detection: NOT IMPLEMENTED in current module');
const fieldSuggest = `
  {
    "query": "{ usr { idd emal namee } }",
    "errors": true
  }
`;
console.log(`Typo-based suggestion attack: ${graphqlBatchAbuse.detect(fieldSuggest) ? 'DETECTED' : 'NOT DETECTED'}`);

// ==== 7. Subscription Abuse ====
console.log('\n[7] Subscription Abuse for Data Exfiltration');
console.log('-'.repeat(40));
console.log('Subscription abuse detection: NOT IMPLEMENTED in current module');
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
`;
console.log(`Sensitive field subscription: ${graphqlBatchAbuse.detect(subAbuse) ? 'DETECTED' : 'NOT DETECTED'}`);

// ==== 8. REST API Verb Tampering ====
console.log('\n[8] REST API Verb Tampering');
console.log('-'.repeat(40));
console.log('Verb tampering detection: NOT IMPLEMENTED in current module');

const verbTests = [
    ['GET /api/users/1', false],
    ['POST /api/users/1/delete', false], // Method override
    ['HEAD /api/admin/config', false],   // HEAD bypass
    ['OPTIONS /api/users/1', false],     // OPTIONS probe
    ['TRACE /api/users/1', false],       // TRACE/XST
    ['PUT /api/users/1 with X-HTTP-Method-Override: DELETE', false],
    ['PATCH /api/admin/settings', false],
];

verbTests.forEach(([payload, expected]) => {
    console.log(`  ${payload}: ${bolaIdor.detect(payload) ? 'DETECTED' : 'NOT DETECTED'}`);
});

// ==== Additional BOLA/IDOR Tests ====
console.log('\n[9] Additional BOLA/IDOR Tests');
console.log('-'.repeat(40));

const bolaTests = [
    ['/api/users/123', false], // Just ID access, no context
    ['/api/users/123 with Authorization: Bearer token_for_user_456', true],
    ['/api/orders/99999?userId=1 (sequential ID probe)', true],
    ['/api/v1/documents/../../admin/config', true],
    ['/api/users/me/profile', false],
    ['/api/users?page=2&limit=10', false],
];

bolaTests.forEach(([payload, expected]) => {
    console.log(testDetection(payload, bolaIdor, payload, expected));
});

// ==== Mass Enumeration Tests ====
console.log('\n[10] Mass Enumeration Tests');
console.log('-'.repeat(40));

const enumTests = [
    ['/api/users/1 /api/users/2 /api/users/3 /api/users/4', false], // Need 4+ sequential
    ['/api/users/1 /api/users/2 /api/users/3 /api/users/4 /api/users/5', true],
    ['/api/invoices?id[gte]=1&id[lte]=99999', true],
    ['/api/v1/records?filter=id>0&limit=999999', true],
    ['/api/users?page=1&limit=20', false],
];

enumTests.forEach(([payload, expected]) => {
    console.log(testDetection(payload, apiMassEnum, payload, expected));
});

console.log('\n' + '='.repeat(80));
console.log('Test Complete');
console.log('='.repeat(80));
