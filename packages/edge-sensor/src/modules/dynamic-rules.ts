import type { PatternRule, RuleBundle } from '../../../engine/src/crypto/types.js'

export class DynamicRuleStore {
    private rules: Map<string, PatternRule> = new Map()
    private thresholds: Map<string, number> = new Map()
    private priorities: Map<string, number> = new Map()
    private blocklist: Set<string> = new Set()
    private currentVersion = 0
    private expiresAt = 0

    applyBundle(bundle: RuleBundle): boolean {
        if (bundle.v !== 1) return false
        if (bundle.version <= this.currentVersion) return false

        const now = Date.now()

        for (const ruleId of bundle.l1Removals) {
            this.rules.delete(ruleId)
        }

        for (const rule of bundle.l1Additions) {
            if (rule.expiresAt !== undefined && rule.expiresAt <= now) continue
            this.rules.set(rule.id, rule)
        }

        for (const threshold of bundle.thresholdOverrides) {
            if (threshold.validUntil <= now) {
                this.thresholds.delete(threshold.invariantClass)
                continue
            }

            this.thresholds.set(threshold.invariantClass, threshold.adjustedThreshold)
        }

        for (const priority of bundle.classPriorities) {
            this.priorities.set(priority.invariantClass, priority.priorityMultiplier)
        }

        for (const hashedIp of bundle.blocklistAdditions) {
            this.blocklist.add(hashedIp)
        }

        for (const hashedIp of bundle.blocklistRemovals) {
            this.blocklist.delete(hashedIp)
        }

        this.currentVersion = bundle.version
        this.expiresAt = bundle.expiresAt

        return true
    }

    getActiveRules(): PatternRule[] {
        const now = Date.now()
        return Array.from(this.rules.values()).filter((rule) => {
            if (rule.expiresAt !== undefined && rule.expiresAt <= now) return false
            return true
        })
    }

    getThreshold(invariantClass: string): number | undefined {
        return this.thresholds.get(invariantClass)
    }

    getPriority(invariantClass: string): number {
        return this.priorities.get(invariantClass) ?? 1.0
    }

    isBlocked(hashedIp: string): boolean {
        return this.blocklist.has(hashedIp)
    }

    isExpired(): boolean {
        return this.expiresAt > 0 && Date.now() > this.expiresAt
    }

    get version(): number {
        return this.currentVersion
    }
}

export default DynamicRuleStore
