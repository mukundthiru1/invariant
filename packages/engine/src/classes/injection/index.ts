/**
 * Injection Invariant Classes — Barrel Export
 *
 * All 20 injection-category classes, imported from individual modules.
 * Each module is self-contained with its own detect(), generateVariants(),
 * knownPayloads, and knownBenign test vectors.
 */
import type { InvariantClassModule } from '../types.js'

// Individual class imports
import { protoPollution } from './proto-pollution.js'
import { logJndiLookup } from './log-jndi-lookup.js'
import { sstiJinjaTwig, sstiElExpression } from './ssti.js'
import { nosqlOperatorInjection, nosqlJsInjection } from './nosql.js'
import { xxeEntityExpansion, xmlInjection } from './xxe.js'
import { crlfHeaderInjection, crlfLogInjection } from './crlf.js'
import { graphqlIntrospection, graphqlBatchAbuse } from './graphql.js'
import { openRedirectBypass, massAssignment, ldapFilterInjection, regexDos } from './misc.js'
import { httpSmuggleClTe, httpSmuggleH2 } from './http-smuggling.js'
import { corsOriginAbuse } from './cors.js'

// Re-export individual classes for selective imports
export { protoPollution } from './proto-pollution.js'
export { logJndiLookup } from './log-jndi-lookup.js'
export { sstiJinjaTwig, sstiElExpression } from './ssti.js'
export { nosqlOperatorInjection, nosqlJsInjection } from './nosql.js'
export { xxeEntityExpansion, xmlInjection } from './xxe.js'
export { crlfHeaderInjection, crlfLogInjection } from './crlf.js'
export { graphqlIntrospection, graphqlBatchAbuse } from './graphql.js'
export { openRedirectBypass, massAssignment, ldapFilterInjection, regexDos } from './misc.js'
export { httpSmuggleClTe, httpSmuggleH2 } from './http-smuggling.js'
export { corsOriginAbuse } from './cors.js'


// ── Barrel Export ────────────────────────────────────────────────

export const INJECTION_CLASSES: InvariantClassModule[] = [
    // Proto pollution
    protoPollution,
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
    // HTTP smuggling
    httpSmuggleClTe,
    httpSmuggleH2,
    // CORS
    corsOriginAbuse,
]
