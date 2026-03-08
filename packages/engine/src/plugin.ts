import { InvariantRegistry, RegistryError } from './classes/registry.js'
import type { InvariantClass, InvariantClassModule } from './classes/types.js'

export interface InvariantPlugin {
    readonly name: string
    readonly version: string
    readonly classes: InvariantClassModule[]
}

export class PluginError extends Error {
    constructor(message: string) {
        super(`[PluginRegistry] ${message}`)
        this.name = 'PluginError'
    }
}

interface RegisteredPlugin extends InvariantPlugin {
    readonly classIds: InvariantClass[]
}

interface RegistryInternals {
    modules: Map<InvariantClass, InvariantClassModule>
    byCategory: Map<string, InvariantClassModule[]>
    bySeverity: Map<string, InvariantClassModule[]>
    calibrationOverrides: Map<InvariantClass, unknown>
}

function validateClassContract(module: InvariantClassModule): void {
    if (!module.id) throw new PluginError('Class missing id')
    if (!module.description) throw new PluginError(`Class ${module.id}: missing description`)
    if (!module.category) throw new PluginError(`Class ${module.id}: missing category`)
    if (!module.severity) throw new PluginError(`Class ${module.id}: missing severity`)
    if (typeof module.detect !== 'function') throw new PluginError(`Class ${module.id}: detect is not a function`)
    if (typeof module.generateVariants !== 'function') throw new PluginError(`Class ${module.id}: generateVariants is not a function`)
    if (!Array.isArray(module.knownPayloads)) throw new PluginError(`Class ${module.id}: knownPayloads must be an array`)
    if (!Array.isArray(module.knownBenign)) throw new PluginError(`Class ${module.id}: knownBenign must be an array`)
}

export function defineClass(module: InvariantClassModule): InvariantClassModule {
    validateClassContract(module)
    return Object.freeze(module)
}

export class PluginRegistry {
    private readonly plugins = new Map<string, RegisteredPlugin>()
    private readonly registry: InvariantRegistry

    constructor(registry?: InvariantRegistry) {
        this.registry = registry ?? new InvariantRegistry()
    }

    register(plugin: InvariantPlugin): void {
        this.validatePlugin(plugin)

        if (this.plugins.has(plugin.name)) {
            throw new PluginError(`Plugin already registered: ${plugin.name}`)
        }

        const classIds = new Set<InvariantClass>()
        for (const module of plugin.classes) {
            validateClassContract(module)
            if (classIds.has(module.id)) {
                throw new PluginError(`Plugin ${plugin.name} contains duplicate class ID: ${module.id}`)
            }
            classIds.add(module.id)
        }

        const registered: InvariantClass[] = []
        try {
            for (const module of plugin.classes) {
                this.registry.register(module)
                registered.push(module.id)
            }
        } catch (error) {
            for (const classId of registered) {
                this.removeClassFromRegistry(classId)
            }
            if (error instanceof RegistryError) {
                throw new PluginError(error.message)
            }
            throw error
        }

        this.plugins.set(plugin.name, {
            ...plugin,
            classIds: Array.from(classIds),
        })
    }

    unregister(pluginName: string): boolean {
        const plugin = this.plugins.get(pluginName)
        if (!plugin) return false

        for (const classId of plugin.classIds) {
            this.removeClassFromRegistry(classId)
        }

        this.plugins.delete(pluginName)
        return true
    }

    getPlugin(name: string): InvariantPlugin | undefined {
        const plugin = this.plugins.get(name)
        if (!plugin) return undefined
        return {
            name: plugin.name,
            version: plugin.version,
            classes: [...plugin.classes],
        }
    }

    listPlugins(): InvariantPlugin[] {
        return Array.from(this.plugins.values()).map((plugin) => ({
            name: plugin.name,
            version: plugin.version,
            classes: [...plugin.classes],
        }))
    }

    getRegistry(): InvariantRegistry {
        return this.registry
    }

    private validatePlugin(plugin: InvariantPlugin): void {
        if (!plugin || typeof plugin !== 'object') {
            throw new PluginError('Plugin must be an object')
        }
        if (!plugin.name || typeof plugin.name !== 'string') {
            throw new PluginError('Plugin must include a non-empty name')
        }
        if (!plugin.version || typeof plugin.version !== 'string') {
            throw new PluginError(`Plugin ${plugin.name}: must include a non-empty version`)
        }
        if (!Array.isArray(plugin.classes)) {
            throw new PluginError(`Plugin ${plugin.name}: classes must be an array`)
        }
    }

    private removeClassFromRegistry(classId: InvariantClass): void {
        const internals = this.registry as unknown as RegistryInternals
        const module = internals.modules.get(classId)
        if (!module) return

        internals.modules.delete(classId)
        internals.calibrationOverrides.delete(classId)

        const categoryModules = internals.byCategory.get(module.category)
        if (categoryModules) {
            const next = categoryModules.filter((m) => m.id !== classId)
            if (next.length === 0) internals.byCategory.delete(module.category)
            else internals.byCategory.set(module.category, next)
        }

        const severityModules = internals.bySeverity.get(module.severity)
        if (severityModules) {
            const next = severityModules.filter((m) => m.id !== classId)
            if (next.length === 0) internals.bySeverity.delete(module.severity)
            else internals.bySeverity.set(module.severity, next)
        }
    }
}
