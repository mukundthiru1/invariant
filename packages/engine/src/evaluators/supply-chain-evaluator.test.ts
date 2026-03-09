import { describe, expect, it } from 'vitest'
import {
    detectSupplyChain,
    detectNpmDependencyConfusion,
    detectTyposquatPackage,
} from './supply-chain-evaluator.js'

describe('supply-chain-evaluator npm dependency confusion and typosquat', () => {
    it('detects npm dependency confusion for corp-internal package with registry override', () => {
        const input = JSON.stringify({
            name: 'my-app',
            dependencies: {
                'corp-internal-utils': '^1.0.0',
            },
            publishConfig: { registry: 'https://registry.npmjs.org/' },
        })
        const result = detectNpmDependencyConfusion(input)
        expect(result).not.toBeNull()
        expect(result!.type).toBe('npm_dependency_confusion')
        expect(result!.confidence).toBe(0.90)
        expect(result!.indicators.length).toBeGreaterThan(0)
    })

    it('detects npm dependency confusion for @company/ scoped package in dependencies', () => {
        const input = JSON.stringify({
            name: 'app',
            dependencies: {
                '@company/internal-lib': '1.0.0',
            },
        })
        const result = detectNpmDependencyConfusion(input)
        expect(result).not.toBeNull()
        expect(result!.type).toBe('npm_dependency_confusion')
    })

    it('detects typosquat when package name is 1 edit from lodash', () => {
        const input = 'require("lodahs")'
        const result = detectTyposquatPackage(input)
        expect(result).not.toBeNull()
        expect(result!.type).toBe('typosquat_package')
        expect(result!.confidence).toBe(0.87)
        expect(result!.indicators.some(i => i.includes('lodash'))).toBe(true)
    })

    it('detects typosquat when package name is 1 edit from express', () => {
        const input = 'import x from "expres"'
        const result = detectTyposquatPackage(input)
        expect(result).not.toBeNull()
        expect(result!.type).toBe('typosquat_package')
        expect(result!.indicators.some(i => i.includes('express'))).toBe(true)
    })

    it('detects typosquat for react-like name in package.json-like content', () => {
        const input = '"dependencies": { "recat": "^18.0.0" }'
        const result = detectTyposquatPackage(input)
        expect(result).not.toBeNull()
        expect(result!.type).toBe('typosquat_package')
    })

    it('detectSupplyChain includes npm_dependency_confusion and typosquat_package when present', () => {
        const input = JSON.stringify({
            name: 'app',
            dependencies: {
                'corp-internal-x': '1.0.0',
            },
        })
        const all = detectSupplyChain(input)
        const npmConf = all.find(d => d.type === 'npm_dependency_confusion')
        expect(npmConf).toBeDefined()

        const withTypo = input + '\nrequire("lodahs")'
        const all2 = detectSupplyChain(withTypo)
        const typosquat = all2.find(d => d.type === 'typosquat_package')
        expect(typosquat).toBeDefined()
    })
})
