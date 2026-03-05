/**
 * Invariant Class Registry — Dynamic Module System
 *
 * Central registry for all invariant class modules. Provides:
 *   - Dynamic registration (add classes at runtime)
 *   - Lookup by ID, category, or severity
 *   - Validation (no duplicate IDs, all fields present)
 *   - Statistics (counts by category, severity)
 *   - Calibration override application
 *
 * The registry is the single point of truth for what classes exist.
 * The InvariantEngine delegates to the registry for all class lookups.
 *
 * INVARIANT: Once registered, a class module is immutable.
 * Registration is additive-only — classes cannot be removed.
 */

import type {
    InvariantClass,
    InvariantClassModule,
    AttackCategory,
    Severity,
    CalibrationConfig,
} from './types.js'


// ── Registry Errors ───────────────────────────────────────────────

export class RegistryError extends Error {
    constructor(message: string) {
        super(`[InvariantRegistry] ${message}`)
        this.name = 'RegistryError'
    }
}


// ── Registry ──────────────────────────────────────────────────────

export class InvariantRegistry {
    private readonly modules: Map<InvariantClass, InvariantClassModule> = new Map()
    private readonly byCategory: Map<AttackCategory, InvariantClassModule[]> = new Map()
    private readonly bySeverity: Map<Severity, InvariantClassModule[]> = new Map()
    private readonly calibrationOverrides: Map<InvariantClass, Partial<CalibrationConfig>> = new Map()

    /**
     * Register a class module.
     * Validates the module contract before accepting it.
     * @throws RegistryError if module is invalid or ID is duplicate.
     */
    register(module: InvariantClassModule): void {
        // Validate contract
        if (!module.id) throw new RegistryError('Module missing id')
        if (!module.description) throw new RegistryError(`Module ${module.id}: missing description`)
        if (!module.category) throw new RegistryError(`Module ${module.id}: missing category`)
        if (!module.severity) throw new RegistryError(`Module ${module.id}: missing severity`)
        if (typeof module.detect !== 'function') throw new RegistryError(`Module ${module.id}: detect is not a function`)
        if (typeof module.generateVariants !== 'function') throw new RegistryError(`Module ${module.id}: generateVariants is not a function`)
        if (!Array.isArray(module.knownPayloads)) throw new RegistryError(`Module ${module.id}: knownPayloads must be an array`)
        if (!Array.isArray(module.knownBenign)) throw new RegistryError(`Module ${module.id}: knownBenign must be an array`)

        // No duplicates
        if (this.modules.has(module.id)) {
            throw new RegistryError(`Duplicate class ID: ${module.id}`)
        }

        // Register
        this.modules.set(module.id, module)

        // Index by category
        if (!this.byCategory.has(module.category)) {
            this.byCategory.set(module.category, [])
        }
        this.byCategory.get(module.category)!.push(module)

        // Index by severity
        if (!this.bySeverity.has(module.severity)) {
            this.bySeverity.set(module.severity, [])
        }
        this.bySeverity.get(module.severity)!.push(module)
    }

    /**
     * Register multiple modules at once.
     */
    registerAll(modules: InvariantClassModule[]): void {
        for (const m of modules) this.register(m)
    }

    /**
     * Get a module by class ID.
     */
    get(id: InvariantClass): InvariantClassModule | undefined {
        return this.modules.get(id)
    }

    /**
     * Get all registered modules.
     */
    all(): InvariantClassModule[] {
        return Array.from(this.modules.values())
    }

    /**
     * Get modules by attack category.
     */
    getByCategory(category: AttackCategory): InvariantClassModule[] {
        return this.byCategory.get(category) ?? []
    }

    /**
     * Get modules by severity.
     */
    getBySeverity(severity: Severity): InvariantClassModule[] {
        return this.bySeverity.get(severity) ?? []
    }

    /**
     * Get all registered class IDs.
     */
    classIds(): InvariantClass[] {
        return Array.from(this.modules.keys())
    }

    /**
     * Number of registered classes.
     */
    get size(): number {
        return this.modules.size
    }

    /**
     * Set a calibration override for a class.
     * Overrides are applied at detection time to adjust confidence.
     */
    setCalibrationOverride(classId: InvariantClass, override: Partial<CalibrationConfig>): void {
        if (!this.modules.has(classId)) {
            throw new RegistryError(`Cannot set calibration for unknown class: ${classId}`)
        }
        this.calibrationOverrides.set(classId, override)
    }

    /**
     * Get the effective calibration for a class.
     * Merges module default calibration with any override.
     */
    getCalibration(classId: InvariantClass): CalibrationConfig {
        const module = this.modules.get(classId)
        const base: CalibrationConfig = module?.calibration ?? { baseConfidence: 0.85 }
        const override = this.calibrationOverrides.get(classId)

        if (!override) return base

        return {
            baseConfidence: override.baseConfidence ?? base.baseConfidence,
            environmentMultipliers: {
                ...base.environmentMultipliers,
                ...override.environmentMultipliers,
            },
            falsePositivePatterns: [
                ...(base.falsePositivePatterns ?? []),
                ...(override.falsePositivePatterns ?? []),
            ],
            minInputLength: override.minInputLength ?? base.minInputLength,
        }
    }

    /**
     * Compute detection confidence for a class match, applying calibration.
     */
    computeConfidence(
        classId: InvariantClass,
        input: string,
        environment?: string,
        hasStaticMatch?: boolean,
    ): number {
        const cal = this.getCalibration(classId)
        let confidence = cal.baseConfidence

        // Apply environment multiplier
        if (environment && cal.environmentMultipliers?.[environment]) {
            confidence *= cal.environmentMultipliers[environment]
        }

        // Reduce confidence for false-positive patterns
        if (cal.falsePositivePatterns) {
            for (const pattern of cal.falsePositivePatterns) {
                if (pattern.test(input)) {
                    confidence *= 0.5
                    break
                }
            }
        }

        // Reduce confidence for short inputs
        if (cal.minInputLength && input.length < cal.minInputLength) {
            confidence *= 0.7
        }

        // Boost confidence for convergent detection (static + invariant)
        if (hasStaticMatch) {
            confidence = Math.min(0.99, confidence + 0.10)
        }

        // Clamp to [0, 1]
        return Math.max(0, Math.min(1, confidence))
    }

    /**
     * Registry statistics.
     */
    stats(): RegistryStats {
        const byCategory: Record<string, number> = {}
        const bySeverity: Record<string, number> = {}

        for (const [cat, modules] of this.byCategory) {
            byCategory[cat] = modules.length
        }
        for (const [sev, modules] of this.bySeverity) {
            bySeverity[sev] = modules.length
        }

        return {
            totalClasses: this.modules.size,
            byCategory,
            bySeverity,
            withCalibration: Array.from(this.modules.values())
                .filter(m => m.calibration != null).length,
            withOverrides: this.calibrationOverrides.size,
        }
    }
}


// ── Stats Type ────────────────────────────────────────────────────

export interface RegistryStats {
    totalClasses: number
    byCategory: Record<string, number>
    bySeverity: Record<string, number>
    withCalibration: number
    withOverrides: number
}
