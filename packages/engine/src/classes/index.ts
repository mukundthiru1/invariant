/**
 * Invariant Class System — Main Barrel Export
 *
 * Re-exports all class modules, the registry, shared types,
 * and the encoding normalizer.
 *
 * Usage:
 *   import { ALL_CLASS_MODULES, InvariantRegistry } from './classes/index.js'
 *   const registry = new InvariantRegistry()
 *   registry.registerAll(ALL_CLASS_MODULES)
 */

// Types
export type {
    InvariantClass,
    InvariantClassModule,
    InvariantMatch,
    AttackCategory,
    Severity,
    CalibrationConfig,
} from './types.js'

// Registry
export { InvariantRegistry, RegistryError, type RegistryStats } from './registry.js'

// Encoding
export { deepDecode } from './encoding.js'

// Category barrel exports
import { SQL_CLASSES } from './sqli/index.js'
import { XSS_CLASSES } from './xss/index.js'
import { PATH_CLASSES } from './path/index.js'
import { CMD_CLASSES } from './cmdi/index.js'
import { SSRF_CLASSES } from './ssrf/index.js'
import { DESER_CLASSES } from './deser/index.js'
import { AUTH_CLASSES } from './auth/index.js'
import { INJECTION_CLASSES } from './injection/index.js'

import type { InvariantClassModule } from './types.js'

/**
 * All registered invariant class modules.
 *
 * v2 upgrade: 46 classes total (was 41)
 *   - Added: path_normalization_bypass, crlf_log_injection,
 *            http_smuggle_cl_te, http_smuggle_h2, cors_origin_abuse
 */
export const ALL_CLASS_MODULES: InvariantClassModule[] = [
    ...SQL_CLASSES,        // 7
    ...XSS_CLASSES,        // 5
    ...PATH_CLASSES,       // 4 (was 3, +normalization_bypass)
    ...CMD_CLASSES,        // 3
    ...SSRF_CLASSES,       // 3
    ...DESER_CLASSES,      // 3
    ...AUTH_CLASSES,        // 2
    ...INJECTION_CLASSES,  // 19 (was 15, +crlf_log, +http_smuggle_cl_te, +http_smuggle_h2, +cors_origin_abuse)
]                          // Total: 46

// Re-export category barrels for selective imports
export { SQL_CLASSES } from './sqli/index.js'
export { XSS_CLASSES } from './xss/index.js'
export { PATH_CLASSES } from './path/index.js'
export { CMD_CLASSES } from './cmdi/index.js'
export { SSRF_CLASSES } from './ssrf/index.js'
export { DESER_CLASSES } from './deser/index.js'
export { AUTH_CLASSES } from './auth/index.js'
export { INJECTION_CLASSES } from './injection/index.js'
