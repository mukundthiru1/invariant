/**
 * Advanced Prototype Pollution Test
 * Tests edge cases and complex scenarios
 */

console.log('='.repeat(70))
console.log('Advanced Prototype Pollution Tests')
console.log('='.repeat(70))
console.log()

function test(name, fn) {
    // Clean prototype before each test
    delete Object.prototype.polluted;
    delete Object.prototype.isAdmin;
    
    console.log(`Test: ${name}`);
    try {
        const result = fn();
        const testObj = {};
        if (testObj.polluted !== undefined || testObj.isAdmin !== undefined) {
            console.log('  ❌ VULNERABLE: Prototype was polluted!');
            console.log('     polluted:', testObj.polluted);
            console.log('     isAdmin:', testObj.isAdmin);
        } else {
            console.log('  ✓ Safe: No prototype pollution detected');
        }
    } catch (e) {
        console.log('  ⚠ Error:', e.message);
    }
    console.log();
}

// Test 1: JSON.parse with __proto__
test('JSON.parse with __proto__ key', () => {
    const obj = JSON.parse('{"__proto__":{"polluted":true}}');
    return obj;
});

// Test 2: JSON.parse with constructor.prototype
test('JSON.parse with constructor.prototype', () => {
    const obj = JSON.parse('{"constructor":{"prototype":{"polluted":true}}}');
    return obj;
});

// Test 3: Object.assign with parsed object
test('Object.assign from parsed JSON', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    const target = {};
    Object.assign(target, parsed);
    return target;
});

// Test 4: Spread operator
test('Spread operator with parsed JSON', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    const merged = { ...parsed };
    return merged;
});

// Test 5: Object.entries iteration
test('Object.entries iteration', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":true},"a":1}');
    const target = {};
    Object.entries(parsed).forEach(([k, v]) => {
        target[k] = v;
    });
    return target;
});

// Test 6: Object.keys with forEach
test('Object.keys with forEach', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    const target = {};
    Object.keys(parsed).forEach(key => {
        target[key] = parsed[key];
    });
    return target;
});

// Test 7: for...in loop
test('for...in loop', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    const target = {};
    for (const key in parsed) {
        target[key] = parsed[key];
    }
    return target;
});

// Test 8: Deep merge simulation (like lodash merge)
test('Deep merge simulation', () => {
    function deepMerge(target, source) {
        for (const key in source) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) target[key] = {};
                deepMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
        return target;
    }
    
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    const target = {};
    deepMerge(target, parsed);
    return target;
});

// Test 9: Bracket notation assignment
test('Bracket notation assignment', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    const target = {};
    for (const key in parsed) {
        target[key] = parsed[key];
    }
    return target;
});

// Test 10: Complex nested structure
test('Complex nested with multiple __proto__', () => {
    const parsed = JSON.parse(`{
        "user": {
            "__proto__": {"isAdmin": true},
            "name": "attacker"
        },
        "data": {
            "__proto__": {"polluted": true},
            "value": 123
        }
    }`);
    
    // Simulate flattening like mass-assignment-evaluator does
    function flatten(obj, prefix = '', result = {}) {
        for (const key in obj) {
            const newKey = prefix ? `${prefix}.${key}` : key;
            if (typeof obj[key] === 'object' && obj[key] !== null) {
                flatten(obj[key], newKey, result);
            } else {
                result[newKey] = obj[key];
            }
        }
        return result;
    }
    
    return flatten(parsed);
});

// Test 11: Object.defineProperty
test('Object.defineProperty from parsed', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    const target = {};
    Object.keys(parsed).forEach(key => {
        Object.defineProperty(target, key, {
            value: parsed[key],
            writable: true,
            enumerable: true,
            configurable: true
        });
    });
    return target;
});

// Test 12: Structured clone (if available)
test('StructuredClone', () => {
    try {
        const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
        const cloned = structuredClone(parsed);
        return cloned;
    } catch (e) {
        console.log('     (structuredClone not available)');
        return {};
    }
});

// Test 13: Direct property assignment with __proto__
test('Direct __proto__ assignment', () => {
    const obj = {};
    obj['__proto__'] = { polluted: true };
    return obj;
});

// Test 14: Object.setPrototypeOf simulation
test('Object.setPrototypeOf scenario', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
    if (parsed.__proto__) {
        // This would be vulnerable if setPrototypeOf was called
        // Object.setPrototypeOf(someObj, parsed.__proto__);
    }
    return parsed;
});

console.log('='.repeat(70))
console.log('Summary')
console.log('='.repeat(70))
console.log()
console.log('Modern Node.js (v20+) has built-in protections against the most')
console.log('common prototype pollution vectors in JSON.parse().')
console.log()
console.log('However, the engine should still use defensive programming:')
console.log('1. Use reviver functions for defense in depth')
console.log('2. Validate all object keys before assignment')
console.log('3. Use Object.create(null) for maps/dictionaries')
console.log('4. Freeze critical prototypes in production')
console.log()
console.log('The lack of reviver functions is a code quality and defense-in-depth')
console.log('issue that should be fixed to prevent future vulnerabilities.')
console.log()
