import { describe, it, expect } from 'vitest'

import { InvariantRegistry } from './classes/registry.js'
import type { InvariantClass, InvariantClassModule } from './classes/types.js'
import { defineClass, PluginError, PluginRegistry } from './plugin.js'
import type { InvariantPlugin } from './plugin.js'

function makeClass(id: InvariantClass, marker = 'attack'): InvariantClassModule {
    return {
        id,
        description: `${id} detector`,
        category: 'sqli',
        severity: 'high',
        detect: (input: string) => input.includes(marker),
        generateVariants: (count: number) => Array.from({ length: count }, () => marker),
        knownPayloads: [marker],
        knownBenign: ['safe-input'],
    }
}

function makePlugin(name: string, version: string, classes: InvariantClassModule[]): InvariantPlugin {
    return { name, version, classes }
}

describe('defineClass', () => {
    it('returns a frozen class module when valid', () => {
        const klass = defineClass(makeClass('sql_tautology'))

        expect(klass.id).toBe('sql_tautology')
        expect(Object.isFrozen(klass)).toBe(true)
    })

    it('throws PluginError for invalid class module contract', () => {
        const invalid = {
            ...makeClass('sql_tautology'),
            knownPayloads: 'not-array',
        } as unknown as InvariantClassModule

        expect(() => defineClass(invalid)).toThrow(PluginError)
        expect(() => defineClass(invalid)).toThrow(/knownPayloads must be an array/)
    })
})

describe('PluginRegistry', () => {
    it('registers plugin classes into the provided InvariantRegistry', () => {
        const registry = new InvariantRegistry()
        const plugins = new PluginRegistry(registry)
        const plugin = makePlugin('sql-pack', '1.0.0', [
            makeClass('sql_tautology'),
            makeClass('sql_union_extraction', 'union-attack'),
        ])

        plugins.register(plugin)

        expect(registry.get('sql_tautology')).toBeDefined()
        expect(registry.get('sql_union_extraction')).toBeDefined()
        expect(plugins.getPlugin('sql-pack')?.version).toBe('1.0.0')
    })

    it('listPlugins returns all registered plugins', () => {
        const plugins = new PluginRegistry(new InvariantRegistry())
        plugins.register(makePlugin('p1', '1.0.0', [makeClass('sql_tautology')]))
        plugins.register(makePlugin('p2', '1.1.0', [makeClass('sql_union_extraction')]))

        const names = plugins.listPlugins().map((p) => p.name).sort()
        expect(names).toEqual(['p1', 'p2'])
    })

    it('rejects duplicate plugin names', () => {
        const plugins = new PluginRegistry(new InvariantRegistry())
        const plugin = makePlugin('dup', '1.0.0', [makeClass('sql_tautology')])

        plugins.register(plugin)

        expect(() => plugins.register(plugin)).toThrow(PluginError)
        expect(() => plugins.register(plugin)).toThrow(/Plugin already registered: dup/)
    })

    it('rejects duplicate class IDs inside a single plugin', () => {
        const plugins = new PluginRegistry(new InvariantRegistry())
        const plugin = makePlugin('bad-ids', '1.0.0', [
            makeClass('sql_tautology'),
            makeClass('sql_tautology', 'other-attack'),
        ])

        expect(() => plugins.register(plugin)).toThrow(PluginError)
        expect(() => plugins.register(plugin)).toThrow(/contains duplicate class ID: sql_tautology/)
    })

    it('rolls back already-registered classes when plugin registration fails mid-way', () => {
        const registry = new InvariantRegistry()
        const plugins = new PluginRegistry(registry)

        registry.register(makeClass('sql_tautology', 'existing-attack'))

        const plugin = makePlugin('partial', '1.0.0', [
            makeClass('sql_union_extraction'),
            makeClass('sql_tautology', 'duplicate'),
        ])

        expect(() => plugins.register(plugin)).toThrow(PluginError)
        expect(registry.get('sql_union_extraction')).toBeUndefined()
        expect(plugins.getPlugin('partial')).toBeUndefined()
    })

    it('unregister removes plugin classes from main registry and plugin index', () => {
        const registry = new InvariantRegistry()
        const plugins = new PluginRegistry(registry)

        plugins.register(makePlugin('cleanup', '2.0.0', [
            makeClass('sql_tautology'),
            makeClass('sql_union_extraction'),
        ]))

        expect(plugins.unregister('cleanup')).toBe(true)
        expect(registry.get('sql_tautology')).toBeUndefined()
        expect(registry.get('sql_union_extraction')).toBeUndefined()
        expect(plugins.getPlugin('cleanup')).toBeUndefined()
    })

    it('unregister returns false for unknown plugin name', () => {
        const plugins = new PluginRegistry(new InvariantRegistry())
        expect(plugins.unregister('missing')).toBe(false)
    })

    it('rejects plugin objects with invalid metadata', () => {
        const plugins = new PluginRegistry(new InvariantRegistry())
        const invalid = { name: '', version: '1.0.0', classes: [] } as unknown as InvariantPlugin

        expect(() => plugins.register(invalid)).toThrow(PluginError)
        expect(() => plugins.register(invalid)).toThrow(/non-empty name/)
    })

    it('exposes the underlying registry instance', () => {
        const registry = new InvariantRegistry()
        const plugins = new PluginRegistry(registry)

        expect(plugins.getRegistry()).toBe(registry)
    })
})
