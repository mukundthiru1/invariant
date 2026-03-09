import { describe, expect, it } from 'vitest'

import { CAPABILITY_INDEX, getCapabilityMarkdown } from './capability-index.js'

describe('capability index', () => {
    it('totalClasses is greater than 60', () => {
        expect(CAPABILITY_INDEX.totalClasses).toBeGreaterThan(60)
    })

    it('every class has mitre coverage', () => {
        const classes = Object.values(CAPABILITY_INDEX.byCategory).flat()
        expect(classes.every(cls => cls.mitre.length > 0)).toBe(true)
    })

    it('every class has cwe mapping', () => {
        const classes = Object.values(CAPABILITY_INDEX.byCategory).flat()
        expect(classes.every(cls => cls.cwe.trim().length > 0)).toBe(true)
    })

    it('markdown output is non-empty', () => {
        const markdown = getCapabilityMarkdown()
        expect(markdown.trim().length).toBeGreaterThan(0)
    })

    it('byCategory includes sqli, xss, and injection', () => {
        expect(CAPABILITY_INDEX.byCategory.sqli).toBeDefined()
        expect(CAPABILITY_INDEX.byCategory.xss).toBeDefined()
        expect(CAPABILITY_INDEX.byCategory.injection).toBeDefined()
    })
})
