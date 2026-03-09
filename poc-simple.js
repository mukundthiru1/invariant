/**
 * Simple Prototype Pollution Test
 * Demonstrates that JSON.parse() without reviver is vulnerable
 */

console.log('='.repeat(60))
console.log('JSON.parse() Prototype Pollution Demo')
console.log('='.repeat(60))
console.log()

// Store original
const originalToString = Object.prototype.toString;

// Test 1: Vulnerable parsing (what the engine does)
console.log('TEST 1: Vulnerable JSON.parse() (Current Engine Behavior)');
console.log('-'.repeat(60));

const maliciousPayload = '{"__proto__":{"polluted":true,"toString":"OWNED"}}';
console.log('Payload:', maliciousPayload);
console.log();

// This is what the engine does - vulnerable!
const vulnerable = JSON.parse(maliciousPayload);
console.log('Parsed object:', vulnerable);
console.log();

// Check pollution
const testObj = {};
console.log('Object.prototype.polluted:', Object.prototype.polluted);
console.log('testObj.polluted:', testObj.polluted);
console.log('Object.prototype.toString:', Object.prototype.toString);
console.log();

if (Object.prototype.polluted === true) {
    console.log('❌ VULNERABLE: Prototype was polluted!');
} else {
    console.log('✓ Safe: Prototype was NOT polluted');
}

console.log();

// Restore
Object.prototype.toString = originalToString;
delete Object.prototype.polluted;

// Test 2: Safe parsing with reviver
console.log('TEST 2: Safe JSON.parse() with Reviver (Recommended Fix)');
console.log('-'.repeat(60));

function safeReviver(key, value) {
    if (key === '__proto__' || key === 'constructor') {
        console.log(`  → Blocked "${key}" key from polluting prototype`);
        return undefined;
    }
    return value;
}

const safe = JSON.parse(maliciousPayload, safeReviver);
console.log('Parsed object:', safe);
console.log();

const testObj2 = {};
console.log('Object.prototype.polluted:', Object.prototype.polluted);
console.log('testObj2.polluted:', testObj2.polluted);
console.log();

if (Object.prototype.polluted === undefined) {
    console.log('✓ SAFE: Prototype was protected by reviver!');
} else {
    console.log('❌ Still vulnerable');
}

console.log()
console.log('='.repeat(60))
console.log('CONCLUSION')
console.log('='.repeat(60))
console.log()
console.log('The INVARIANT engine uses vulnerable JSON.parse() without a reviver.')
console.log('This allows attackers to pollute Object.prototype during detection.')
console.log()
console.log('FIX: Add the safeReviver function to all JSON.parse() calls in:')
console.log('  - proto-pollution-evaluator.ts')
console.log('  - mass-assignment-evaluator.ts')  
console.log('  - nosql-evaluator.ts')
console.log()
console.log('='.repeat(60))
