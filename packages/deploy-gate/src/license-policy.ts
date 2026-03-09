import { existsSync, readFileSync } from 'node:fs'

export interface LicensePolicy {
  deny: string[]
  warn: string[]
  allow?: string[]
}

export const DEFAULT_LICENSE_POLICY: LicensePolicy = {
  deny: ['GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only', 'AGPL-3.0-or-later'],
  warn: ['LGPL-2.1', 'LGPL-3.0', 'CC-BY-SA-4.0']
}

export function evaluateLicense(spdxId: string, policy: LicensePolicy): 'denied' | 'warned' | 'allowed' {
  if (policy.deny.includes(spdxId)) {
    return 'denied'
  }
  if (policy.warn.includes(spdxId)) {
    return 'warned'
  }
  return 'allowed'
}

export function loadLicensePolicy(configPath?: string): LicensePolicy {
  if (!configPath || !existsSync(configPath)) {
    return DEFAULT_LICENSE_POLICY
  }

  try {
    const parsed = JSON.parse(readFileSync(configPath, 'utf8')) as Partial<LicensePolicy>
    const deny = Array.isArray(parsed.deny) ? parsed.deny.filter((item): item is string => typeof item === 'string') : DEFAULT_LICENSE_POLICY.deny
    const warn = Array.isArray(parsed.warn) ? parsed.warn.filter((item): item is string => typeof item === 'string') : DEFAULT_LICENSE_POLICY.warn
    const allow = Array.isArray(parsed.allow) ? parsed.allow.filter((item): item is string => typeof item === 'string') : DEFAULT_LICENSE_POLICY.allow

    return {
      deny,
      warn,
      allow,
    }
  } catch {
    return DEFAULT_LICENSE_POLICY
  }
}
