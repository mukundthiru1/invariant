/**
 * Injection Invariant Classes — Barrel Export
 *
 * 31 injection-category classes covering:
 *   - Proto pollution (basic + gadget-chain-aware)
 *   - Log4Shell / JNDI
 *   - SSTI (Jinja/Twig + EL Expression)
 *   - NoSQL (operator + JS injection)
 *   - XXE / XML
 *   - CRLF (header + log)
 *   - GraphQL (introspection + batch)
 *   - Open redirect
 *   - Mass assignment
 *   - LDAP
 *   - ReDoS
 *   - HTTP Smuggling (CL.TE, H2, chunk extension, 0.CL, Expect-based)
 *   - CORS
 *
 * Each module is self-contained with detect(), generateVariants(),
 * knownPayloads, and knownBenign test vectors.
 */
import type { InvariantClassModule } from '../types.js'

// Individual class imports
import { protoPollution, massAssignment, graphqlIntrospection } from './prototype-pollution.js'
import { protoPollutionGadget } from './proto-pollution-gadget.js'
import { logJndiLookup } from './log-jndi-lookup.js'
import { sstiJinjaTwig, sstiElExpression } from './ssti.js'
import { nosqlOperatorInjection, nosqlJsInjection } from './nosql.js'
import { xxeEntityExpansion, xmlInjection } from './xxe.js'
import { crlfHeaderInjection, crlfLogInjection } from './crlf.js'
import { graphqlBatchAbuse } from './graphql.js'
import { openRedirectBypass, ldapFilterInjection, regexDos } from './misc.js'
import { llmPromptInjection, llmDataExfiltration, llmJailbreak } from './llm-injection.js'
import {
    httpSmuggleClTe,
    httpSmuggleH2,
    httpSmuggleChunkExt,
    httpSmuggleZeroCl,
    httpSmuggleExpect,
} from './http-smuggling.js'
import { corsOriginAbuse } from './cors.js'
import { dependencyConfusion, postinstallInjection, envExfiltration } from './supply-chain.js'
import { ws_injection, ws_hijack } from './websocket.js'
import { cachePoisoning, cacheDeception } from './cache-poisoning.js'
import { bolaIdor, apiMassEnum } from './api-abuse.js'

// Re-export individual classes for selective imports
export { protoPollution, massAssignment, graphqlIntrospection, graphqlInjection } from './prototype-pollution.js'
export { protoPollutionGadget } from './proto-pollution-gadget.js'
export { logJndiLookup } from './log-jndi-lookup.js'
export { sstiJinjaTwig, sstiElExpression } from './ssti.js'
export { nosqlOperatorInjection, nosqlJsInjection } from './nosql.js'
export { xxeEntityExpansion, xmlInjection } from './xxe.js'
export { crlfHeaderInjection, crlfLogInjection } from './crlf.js'
export { graphqlBatchAbuse } from './graphql.js'
export { openRedirectBypass, ldapFilterInjection, regexDos } from './misc.js'
export { llmPromptInjection, llmDataExfiltration, llmJailbreak } from './llm-injection.js'
export {
    httpSmuggleClTe,
    httpSmuggleH2,
    httpSmuggleChunkExt,
    httpSmuggleZeroCl,
    httpSmuggleExpect,
} from './http-smuggling.js'
export { corsOriginAbuse } from './cors.js'
export { dependencyConfusion, postinstallInjection, envExfiltration } from './supply-chain.js'
export { ws_injection, ws_hijack } from './websocket.js'
export { cachePoisoning, cacheDeception } from './cache-poisoning.js'
export { bolaIdor, apiMassEnum } from './api-abuse.js'


// ── Barrel Export ────────────────────────────────────────────────

export const INJECTION_CLASSES: InvariantClassModule[] = [
    // Proto pollution (basic detection + gadget-chain-aware)
    protoPollution,
    protoPollutionGadget,
    // Log4Shell / JNDI
    logJndiLookup,
    // SSTI
    sstiJinjaTwig,
    sstiElExpression,
    // NoSQL
    nosqlOperatorInjection,
    nosqlJsInjection,
    // XXE / XML
    xxeEntityExpansion,
    xmlInjection,
    // CRLF
    crlfHeaderInjection,
    crlfLogInjection,
    // GraphQL
    graphqlIntrospection,
    graphqlBatchAbuse,
    // Open redirect
    openRedirectBypass,
    // Mass assignment
    massAssignment,
    // LDAP
    ldapFilterInjection,
    // ReDoS
    regexDos,
    // HTTP Smuggling — Kettle 2022-2025 complete coverage
    httpSmuggleClTe,        // CL.TE / TE.TE desync
    httpSmuggleH2,          // H2 downgrade smuggling
    httpSmuggleChunkExt,    // Chunk extension exploit (2025)
    httpSmuggleZeroCl,      // 0.CL desync (2025)
    httpSmuggleExpect,      // Expect-based desync (2025)
    // CORS
    corsOriginAbuse,
    // Supply-chain and dependency threats
    dependencyConfusion,
    postinstallInjection,
    envExfiltration,
    // WebSocket-specific threats
    ws_injection,
    ws_hijack,
    // LLM prompt security classes
    llmPromptInjection,
    llmDataExfiltration,
    llmJailbreak,
    // Cache poisoning / deception
    cachePoisoning,
    cacheDeception,
    // API logic abuse
    bolaIdor,
    apiMassEnum,
]
