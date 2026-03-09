/**
 * Proof of Concept: Prototype Pollution Defense Gap in INVARIANT Engine
 * 
 * This PoC demonstrates that while modern Node.js protects against the most
 * common prototype pollution vectors, the INVARIANT engine lacks defense-in-depth
 * measures that exist elsewhere in the codebase.
 * 
 * The issue: The engine parses untrusted JSON without a reviver function to
 * strip __proto__ and constructor keys, unlike the dashboard and agent RASP.
 * 
 * Run with: npx tsx poc-engine-prototype-pollution.ts
 */

console.log('='.repeat(70))
console.log('INVARIANT Detection Engine - Prototype Pollution Gap Analysis')
console.log('='.repeat(70))
console.log()

// Store original values to restore after test
const originalToString = Object.prototype.toString
const originalValueOf = Object.prototype.valueOf
let gapFound = false

function cleanupPrototype(): void {
    delete (Object.prototype as any).polluted
    delete (Object.prototype as any).isAdmin
    delete (Object.prototype as any).bypass
    Object.prototype.toString = originalToString
    Object.prototype.valueOf = originalValueOf
}

function checkPollution(): boolean {
    const testObj: any = {}
    return testObj.polluted !== undefined || 
           testObj.isAdmin !== undefined ||
           testObj.bypass !== undefined ||
           Object.prototype.toString !== originalToString ||
           Object.prototype.valueOf !== originalValueOf
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 1: Current Engine Behavior (Unsafe)
// ═══════════════════════════════════════════════════════════════════════

console.log('SECTION 1: Current Engine Behavior (No Reviver)')
console.log('-'.repeat(70))

// This is what the engine currently does - parse without protection
function engineJsonParseUnsafe(text: string): any {
    return JSON.parse(text)  // No reviver - vulnerable pattern
}

const maliciousPayload = JSON.stringify({
    "__proto__": {
        "polluted": true,
        "isAdmin": true
    },
    "legitimate": "data"
})

console.log('Input payload:', maliciousPayload.substring(0, 100) + '...')
console.log()

const parsedUnsafe = engineJsonParseUnsafe(maliciousPayload)
console.log('Parsed result keys:', Object.keys(parsedUnsafe))
console.log('Has "__proto__" key:', '__proto__' in parsedUnsafe)
console.log('Has "legitimate" key:', 'legitimate' in parsedUnsafe)
console.log()

const pollutionDetected = checkPollution()
console.log('Direct prototype pollution occurred:', pollutionDetected)

if (pollutionDetected) {
    console.log('⚠️  VULNERABLE: Prototype was polluted!')
    gapFound = true
} else {
    console.log('✓ Protected by Node.js built-in defenses (Node v20+)')
}

cleanupPrototype()
console.log()

// ═══════════════════════════════════════════════════════════════════════
// SECTION 2: Recommended Secure Behavior
// ═══════════════════════════════════════════════════════════════════════

console.log('SECTION 2: Recommended Secure Behavior (With Reviver)')
console.log('-'.repeat(70))

// This is what the engine SHOULD do - parse with protection
function stripPrototypePollution(key: string, value: unknown): unknown {
    if (key === '__proto__' || key === 'constructor') {
        console.log(`  [reviver] Stripped "${key}" key`)
        return undefined
    }
    return value
}

function engineJsonParseSafe(text: string): any {
    return JSON.parse(text, stripPrototypePollution)
}

console.log('Input payload:', maliciousPayload.substring(0, 100) + '...')
console.log()

const parsedSafe = engineJsonParseSafe(maliciousPayload)
console.log('Parsed result keys:', Object.keys(parsedSafe))
console.log('Has "__proto__" key:', '__proto__' in parsedSafe)
console.log('Has "legitimate" key:', 'legitimate' in parsedSafe)
console.log()

const pollutionAfterSafe = checkPollution()
console.log('Direct prototype pollution occurred:', pollutionAfterSafe)

if (pollutionAfterSafe) {
    console.log('⚠️  Still vulnerable')
} else {
    console.log('✓ Protected by reviver function')
}

cleanupPrototype()
console.log()

// ═══════════════════════════════════════════════════════════════════════
// SECTION 3: Flattening Behavior Comparison
// ═══════════════════════════════════════════════════════════════════════

console.log('SECTION 3: Object Flattening Behavior')
console.log('-'.repeat(70))

function flattenObject(obj: any, prefix = ''): Array<{ key: string; value: unknown }> {
    const result: Array<{ key: string; value: unknown }> = []
    
    if (typeof obj !== 'object' || obj === null) {
        return result
    }
    
    for (const [k, v] of Object.entries(obj)) {
        const key = prefix ? `${prefix}.${k}` : k
        result.push({ key, value: v })
        if (typeof v === 'object' && v !== null) {
            result.push(...flattenObject(v, key))
        }
    }
    
    return result
}

console.log('Unsafe parse → flatten:')
const flatUnsafe = flattenObject(engineJsonParseUnsafe(maliciousPayload))
console.log('  Entries:', flatUnsafe.map(e => e.key))

console.log()
console.log('Safe parse → flatten:')
const flatSafe = flattenObject(engineJsonParseSafe(maliciousPayload))
console.log('  Entries:', flatSafe.map(e => e.key))

cleanupPrototype()
console.log()

// ═══════════════════════════════════════════════════════════════════════
// SECTION 4: Detection Logic Impact
// ═══════════════════════════════════════════════════════════════════════

console.log('SECTION 4: Potential Detection Logic Impact')
console.log('-'.repeat(70))

// Simulate what the proto-pollution evaluator might see
function simulateDetection(unsafeParsed: any, safeParsed: any): void {
    console.log('Unsafe parsing detection:')
    console.log('  Object has __proto__ property:', '__proto__' in unsafeParsed)
    console.log('  __proto__ value:', JSON.stringify(unsafeParsed.__proto__))
    
    console.log()
    console.log('Safe parsing detection:')
    console.log('  Object has __proto__ property:', '__proto__' in safeParsed)
    console.log('  __proto__ value:', safeParsed.__proto__)
    
    console.log()
    console.log('Key difference:')
    console.log('  Unsafe: Engine processes __proto__ as a regular property')
    console.log('  Safe: __proto__ is stripped before processing')
}

simulateDetection(
    engineJsonParseUnsafe(maliciousPayload),
    engineJsonParseSafe(maliciousPayload)
)

cleanupPrototype()
console.log()

// ═══════════════════════════════════════════════════════════════════════
// SECTION 5: Codebase Inconsistency
// ═══════════════════════════════════════════════════════════════════════

console.log('SECTION 5: Codebase Inconsistency')
console.log('-'.repeat(70))

console.log('Package: @santh/dashboard (server.ts:496)')
console.log('  Status: ✅ PROTECTED - Uses stripPrototypePollution reviver')
console.log()

console.log('Package: @santh/agent (rasp/deser.ts:174-183)')
console.log('  Status: ✅ PROTECTED - Uses stripProtoKeys function')
console.log()

console.log('Package: @santh/engine (evaluators/*.ts)')
console.log('  Status: ❌ UNPROTECTED - No reviver on JSON.parse()')
console.log('  Files:')
console.log('    - proto-pollution-evaluator.ts:308')
console.log('    - mass-assignment-evaluator.ts:171')
console.log('    - nosql-evaluator.ts:150,159')
console.log('    - jwt-evaluator.ts:50,73')
console.log()

// ═══════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════

console.log('='.repeat(70))
console.log('SUMMARY')
console.log('='.repeat(70))
console.log()

if (checkPollution()) {
    console.log('⚠️  VULNERABILITY CONFIRMED: Prototype pollution is possible!')
    console.log()
    console.log('Your Node.js version may be vulnerable to prototype pollution.')
    console.log('The engine should add reviver protection immediately.')
} else {
    console.log('✓ PROTECTED BY RUNTIME: Node.js v20+ prevents direct prototype pollution')
    console.log()
    console.log('However, this is a DEFENSE-IN-DEPTH GAP:')
    console.log('  1. The engine relies on Node.js for protection instead of explicit measures')
    console.log('  2. Other parts of the codebase (dashboard, agent) have explicit protection')
    console.log('  3. Future Node.js changes could reintroduce vulnerability')
    console.log('  4. Code quality issue: "Practice what you preach"')
}

console.log()
console.log('RECOMMENDATION:')
console.log('  Add the stripPrototypePollution reviver to all JSON.parse() calls')
console.log('  in the engine evaluators for consistency and defense in depth.')
console.log()
console.log('EXAMPLE FIX:')
console.log('  // Before (current):')
console.log('  const obj = JSON.parse(text)')
console.log()
console.log('  // After (recommended):')
console.log('  const obj = JSON.parse(text, (key, value) => {')
console.log('    if (key === "__proto__" || key === "constructor") return undefined')
console.log('    return value')
console.log('  })')
console.log()
console.log('='.repeat(70))

// Final cleanup
cleanupPrototype()
