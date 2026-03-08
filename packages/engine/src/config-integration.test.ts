import { describe, expect, it } from 'vitest'
import { ConfigError, DEFAULT_CONFIG, InvariantConfig, validateConfig } from './config.js'

describe('Invariant config integration', () => {
    it('round-trips full config JSON through validation with all fields', () => {
        const sourceConfig: InvariantConfig = {
            v: 1,
            category: 'fintech',
            framework: 'Express',
            mode: 'enforce',
            appType: 'api',
            dataClassification: 'pii',
            compliance: ['pci', 'gdpr'],
            database: 'PostgreSQL (pg)',
            plugins: ['@santh/plugin-allowlist', './plugins/custom.mjs'],
            signals: {
                ingestUrl: 'https://signals.example.test/ingest',
                batchSize: 42,
            },
            thresholds: {
                critical: 0.1,
                high: 1,
                medium: 5,
                low: 10,
            },
        }

        const raw = JSON.stringify(sourceConfig)
        const parsed = JSON.parse(raw)
        const validated = validateConfig(parsed)

        expect(validated).toEqual(sourceConfig)
        expect(JSON.parse(JSON.stringify(validated))).toEqual(sourceConfig)
    })

    it('matches commandInit JSON file format and parse/validate path', () => {
        const commandInitConfigJson = `{
  "v": 1,
  "category": "saas",
  "framework": "Next.js",
  "mode": "monitor",
  "appType": "web",
  "dataClassification": "none",
  "compliance": [
    "soc2"
  ],
  "database": "Prisma"
}
`

        const parsed = JSON.parse(commandInitConfigJson)
        const validated = validateConfig(parsed)

        expect(commandInitConfigJson).toBe(JSON.stringify(parsed, null, 2) + '\n')
        expect(validated).toEqual({
            ...DEFAULT_CONFIG,
            v: 1,
            category: 'saas',
            framework: 'Next.js',
            mode: 'monitor',
            appType: 'web',
            dataClassification: 'none',
            compliance: ['soc2'],
            database: 'Prisma',
        })
    })

    it('supports plugins array values', () => {
        const raw = JSON.stringify({
            v: 1,
            category: 'api',
            framework: 'Node.js',
            mode: 'monitor',
            appType: 'api',
            dataClassification: 'none',
            compliance: [],
            plugins: ['plugin-a', 'plugin-b'],
        })

        const validated = validateConfig(JSON.parse(raw))
        expect(validated.plugins).toEqual(['plugin-a', 'plugin-b'])
    })

    it('supports thresholds', () => {
        const raw = JSON.stringify({
            v: 1,
            category: 'gaming',
            framework: 'Node.js',
            mode: 'off',
            appType: 'api',
            dataClassification: 'none',
            compliance: [],
            thresholds: {
                critical: 3,
                high: 6,
                medium: 9,
                low: 15,
            },
        })

        const validated = validateConfig(JSON.parse(raw))
        expect(validated.thresholds).toEqual({
            critical: 3,
            high: 6,
            medium: 9,
            low: 15,
        })
    })

    it('supports signals settings', () => {
        const raw = JSON.stringify({
            v: 1,
            category: 'gaming',
            framework: 'Node.js',
            mode: 'monitor',
            appType: 'web',
            dataClassification: 'payment',
            compliance: [],
            signals: {
                ingestUrl: 'https://signals.example.test/ingest',
                batchSize: 256,
            },
        })

        const validated = validateConfig(JSON.parse(raw))
        expect(validated.signals).toEqual({
            ingestUrl: 'https://signals.example.test/ingest',
            batchSize: 256,
        })
    })

    it('ignores unknown fields for forwards compatibility', () => {
        const raw = JSON.stringify({
            v: 1,
            category: 'api',
            framework: 'Node.js',
            mode: 'monitor',
            appType: 'api',
            dataClassification: 'none',
            compliance: [],
            legacyMode: 'observed',
            flags: { darkLaunch: true },
            unknownField: 'ignore-me',
        })

        const validated = validateConfig(JSON.parse(raw))

        expect(validated).toMatchObject({
            v: 1,
            category: 'api',
            framework: 'Node.js',
            mode: 'monitor',
            appType: 'api',
            dataClassification: 'none',
            compliance: [],
        })
        expect((validated as { legacyMode?: string }).legacyMode).toBeUndefined()
        expect((validated as { flags?: { darkLaunch: boolean } }).flags).toBeUndefined()
        expect((validated as { unknownField?: string }).unknownField).toBeUndefined()
    })

    it('backs in defaults for missing optional fields', () => {
        const raw = JSON.stringify({
            category: 'healthcare',
            mode: 'off',
            appType: 'internal',
        })

        const validated = validateConfig(JSON.parse(raw))
        expect(validated).toMatchObject({
            ...DEFAULT_CONFIG,
            category: 'healthcare',
            mode: 'off',
            appType: 'internal',
        })
    })

    it('rejects real-world typos in monitor/appType values', () => {
        const monitoredConfig = JSON.stringify({ appType: 'web', mode: 'monitored' })
        const saasCaseConfig = JSON.stringify({ appType: 'SaaS' as const, mode: 'monitor' })

        expect(() => validateConfig(JSON.parse(monitoredConfig))).toThrow(ConfigError)
        expect(() => validateConfig(JSON.parse(saasCaseConfig))).toThrow(ConfigError)
    })
})
