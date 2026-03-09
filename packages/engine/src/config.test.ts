import { describe, it, expect } from 'vitest'
import { validateConfig, isValidCategory, ConfigError, DEFAULT_CONFIG } from './config.js'

describe('config.ts', () => {
    it('returns defaults for empty object', () => {
        const config = validateConfig({})
        expect(config.category).toBe('saas')
        expect(config.mode).toBe('monitor')
        expect(config.framework).toBe('unknown')
        expect(config.v).toBe(1)
    })

    it('validates all product categories', () => {
        const categories = [
            'saas', 'api', 'ecommerce', 'fintech', 'healthcare',
            'content', 'devtools', 'gaming', 'education', 'government', 'other',
        ]
        for (const cat of categories) {
            expect(isValidCategory(cat)).toBe(true)
            const config = validateConfig({ category: cat })
            expect(config.category).toBe(cat)
        }
    })

    it('rejects invalid category', () => {
        expect(() => validateConfig({ category: 'invalid' })).toThrow(ConfigError)
    })

    it('rejects invalid mode', () => {
        expect(() => validateConfig({ mode: 'turbo' })).toThrow(ConfigError)
    })

    it('parses full config correctly', () => {
        const config = validateConfig({
            v: 1,
            category: 'fintech',
            framework: 'Express',
            mode: 'enforce',
            appType: 'api',
            dataClassification: 'payment',
            compliance: ['pci', 'soc2'],
            database: 'PostgreSQL',
            plugins: ['./my-plugin.js'],
            signals: { ingestUrl: 'https://ingest.santh.io/v2', batchSize: 100 },
            thresholds: { critical: 0.40, high: 0.60 },
        })

        expect(config.category).toBe('fintech')
        expect(config.framework).toBe('Express')
        expect(config.mode).toBe('enforce')
        expect(config.appType).toBe('api')
        expect(config.dataClassification).toBe('payment')
        expect(config.compliance).toEqual(['pci', 'soc2'])
        expect(config.database).toBe('PostgreSQL')
        expect(config.plugins).toEqual(['./my-plugin.js'])
        expect(config.signals?.ingestUrl).toBe('https://ingest.santh.io/v2')
        expect(config.signals?.batchSize).toBe(100)
        expect(config.thresholds?.critical).toBe(0.40)
        expect(config.thresholds?.high).toBe(0.60)
    })

    it('throws on non-object input', () => {
        expect(() => validateConfig(null)).toThrow(ConfigError)
        expect(() => validateConfig('string')).toThrow(ConfigError)
    })

    it('throws on unsupported version', () => {
        expect(() => validateConfig({ v: 99 })).toThrow(ConfigError)
    })

    it('ignores unknown fields (forwards compat)', () => {
        const config = validateConfig({ futureField: true, category: 'api' })
        expect(config.category).toBe('api')
        expect((config as unknown as Record<string, unknown>).futureField).toBeUndefined()
    })

    it('DEFAULT_CONFIG is valid', () => {
        const config = validateConfig(DEFAULT_CONFIG)
        expect(config).toEqual(DEFAULT_CONFIG)
    })
})
