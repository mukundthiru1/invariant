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
    AnalysisRequest,
    AnalysisResult,
    EscapeOperation,
    PayloadOperation,
    RepairOperation,
    AlgebraicComposition,
    InterClassCorrelation,
    BlockRecommendation,
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
import { HYGIENE_CLASSES } from './hygiene/index.js'

import type { InvariantClassModule } from './types.js'

/**
 * All registered invariant class modules.
 *
 * v5 research integration + auth hardening coverage.
 *   +json_sql_bypass           (Claroty Team82 JSON-SQL WAF bypass)
 *   +http_smuggle_chunk_ext    (Kettle 2025 — chunk extension exploits)
 *   +http_smuggle_zero_cl      (Kettle 2025 — 0.CL desync)
 *   +http_smuggle_expect       (Kettle 2025 — Expect-based desync)
 *   +proto_pollution_gadget    (July 2024 arxiv — gadget chain awareness)
 *   +ws_injection              (WebSocket frame payload injection)
 *   +ws_hijack                 (WebSocket upgrade hijacking / CSWSH)
 */
export const ALL_CLASS_MODULES: InvariantClassModule[] = [
    ...SQL_CLASSES,
    ...XSS_CLASSES,
    ...PATH_CLASSES,
    ...CMD_CLASSES,
    ...SSRF_CLASSES,
    ...DESER_CLASSES,
    ...AUTH_CLASSES,
    ...INJECTION_CLASSES,
    ...HYGIENE_CLASSES,
]

// Re-export category barrels for selective imports
export { SQL_CLASSES } from './sqli/index.js'
export { XSS_CLASSES } from './xss/index.js'
export { PATH_CLASSES } from './path/index.js'
export { CMD_CLASSES } from './cmdi/index.js'
export { SSRF_CLASSES } from './ssrf/index.js'
export { DESER_CLASSES } from './deser/index.js'
export { AUTH_CLASSES } from './auth/index.js'
export { INJECTION_CLASSES } from './injection/index.js'
export { HYGIENE_CLASSES } from './hygiene/index.js'
