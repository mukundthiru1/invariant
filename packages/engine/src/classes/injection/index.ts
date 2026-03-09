/**
 * Injection Invariant Classes — Barrel Export
 *
 * 61 injection-category classes covering:
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
 *   - Nation-state / advanced threats (XML bomb, method tampering, WebDAV abuse, TRACE/XST,
 *     DNS tunneling, C2 beaconing, container escape indicators)
 *
 * Each module is self-contained with detect(), generateVariants(),
 * knownPayloads, and knownBenign test vectors.
 */
import type { InvariantClassModule } from '../types.js'

// Individual class imports
import { protoPollution, prototypePollutionViaQuery, graphqlIntrospection } from './prototype-pollution.js'
import { protoPollutionGadget } from './proto-pollution-gadget.js'
import { logJndiLookup } from './log-jndi-lookup.js'
import { sstiJinjaTwig, sstiElExpression, templateInjectionGeneric } from './ssti.js'
import { nosqlOperatorInjection, nosqlJsInjection } from './nosql.js'
import { xxeEntityExpansion, xmlInjection } from './xxe.js'
import { crlfHeaderInjection, crlfLogInjection } from './crlf.js'
import { graphqlBatchAbuse, graphql_injection, graphql_dos } from './graphql.js'
import { openRedirectBypass, ldapFilterInjection, regexDos, xxeInjection, httpSmuggling } from './misc.js'
import { llmPromptInjection, llmDataExfiltration, llmJailbreak, llmIndirectInjection, llm_token_smuggling } from './llm-injection.js'
import {
    httpSmuggleClTe,
    httpSmuggleH2,
    httpSmuggleChunkExt,
    httpSmuggleZeroCl,
    httpSmuggleExpect,
    http_request_smuggling,
} from './http-smuggling.js'
import { requestSmuggling } from './request-smuggling.js'
import { corsOriginAbuse } from './cors.js'
import { dependencyConfusion, postinstallInjection, envExfiltration } from './supply-chain.js'
import { ws_injection, ws_hijack } from './websocket.js'
import { websocket_origin_bypass, websocket_message_injection, websocket_dos } from './websocket-attacks.js'
import { cachePoisoning, cacheDeception } from './cache-poisoning.js'
import { bolaIdor, apiMassEnum } from './api-abuse.js'
import { csvInjection } from './csv-injection.js'
import { gitHistoryTampering } from './git-history-tampering.js'
import { credentialStuffing } from '../auth/index.js'
import { webCacheDeception } from './web-cache-deception.js'
import { dnsRebinding } from './dns-rebinding.js'
import { dependencyHijacking } from './dependency-hijacking.js'
import {
    xmlBombDos,
    webdavMethodAbuse,
    traceXstAttack,
    dnsTunnelingIndicator,
    c2BeaconIndicator,
    containerEscapeIndicator,
} from './advanced-threats.js'
import {
    githubActionsInjection,
    kubernetesRbacAbuse,
    terraformInjection,
    dockerEscapeIndicator,
    cloudMetadataAdvanced,
    compressionBomb,
    http2PseudoHeaderInjection,
    graphqlDepthAttack,
} from './infra-attacks.js'
import {
    raceConditionProbe,
    redosPayload,
    httpDesyncAttack,
    cacheDeceptionAttack,
    parameterPollutionAdvanced,
} from './timing-attacks.js'
import {
    log4shellVariant,
    spring4shell,
    springExpressionInjection,
    velocityInjection,
    freemarkerInjection,
    expressionLanguageGeneric,
    groovySandboxEscape,
    serverSideJsInjection,
    memoryDisclosureEndpoint,
    kubernetesSecretExposure,
    awsMetadataSsrfAdvanced,
    fileInclusionRfi,
} from './exploit-signatures.js'
import { xpathInjection } from './xpath-injection.js'
import { ognlInjection } from './ognl-injection.js'
import { apiMassAssignment, apiBfla, apiVersionDowngrade } from './api-logic-abuse.js'
import {
    massAssignment,
    priceManipulation,
    idorParameterProbe,
    http2HeaderInjection,
    websocketProtocolConfusion,
} from './business-logic.js'

import { WEB_ATTACKS_CLASSES } from './web-attacks.js'

// Re-export individual classes for selective imports
export { protoPollution, prototypePollutionViaQuery, graphqlIntrospection, graphqlInjection } from './prototype-pollution.js'
export { protoPollutionGadget } from './proto-pollution-gadget.js'
export { logJndiLookup } from './log-jndi-lookup.js'
export { sstiJinjaTwig, sstiElExpression, templateInjectionGeneric } from './ssti.js'
export { nosqlOperatorInjection, nosqlJsInjection } from './nosql.js'
export { xxeEntityExpansion, xmlInjection } from './xxe.js'
export { crlfHeaderInjection, crlfLogInjection } from './crlf.js'
export { graphqlBatchAbuse } from './graphql.js'
export { graphql_injection, graphql_dos } from './graphql.js'
export { openRedirectBypass, ldapFilterInjection, regexDos, xxeInjection, httpSmuggling } from './misc.js'
export { llmPromptInjection, llmDataExfiltration, llmJailbreak, llmIndirectInjection, llm_token_smuggling } from './llm-injection.js'
export {
    httpSmuggleClTe,
    httpSmuggleH2,
    httpSmuggleChunkExt,
    httpSmuggleZeroCl,
    httpSmuggleExpect,
    http_request_smuggling,
} from './http-smuggling.js'
export { corsOriginAbuse } from './cors.js'
export { dependencyConfusion, postinstallInjection, envExfiltration } from './supply-chain.js'
export { ws_injection, ws_hijack } from './websocket.js'
export { webCacheDeception } from './web-cache-deception.js'
export { websocket_origin_bypass, websocket_message_injection, websocket_dos } from './websocket-attacks.js'
export { cachePoisoning, cacheDeception } from './cache-poisoning.js'
export { dnsRebinding } from './dns-rebinding.js'
export { dependencyHijacking } from './dependency-hijacking.js'
export { bolaIdor, apiMassEnum } from './api-abuse.js'
export { csvInjection } from './csv-injection.js'
export { gitHistoryTampering } from './git-history-tampering.js'
export {
    xmlBombDos,
    webdavMethodAbuse,
    traceXstAttack,
    dnsTunnelingIndicator,
    c2BeaconIndicator,
    containerEscapeIndicator,
} from './advanced-threats.js'
export {
    githubActionsInjection,
    kubernetesRbacAbuse,
    terraformInjection,
    dockerEscapeIndicator,
    cloudMetadataAdvanced,
    compressionBomb,
    http2PseudoHeaderInjection,
    graphqlDepthAttack,
} from './infra-attacks.js'
export {
    raceConditionProbe,
    redosPayload,
    httpDesyncAttack,
    cacheDeceptionAttack,
    parameterPollutionAdvanced,
} from './timing-attacks.js'
export {
    log4shellVariant,
    spring4shell,
    springExpressionInjection,
    velocityInjection,
    freemarkerInjection,
    expressionLanguageGeneric,
    groovySandboxEscape,
    serverSideJsInjection,
    memoryDisclosureEndpoint,
    kubernetesSecretExposure,
    awsMetadataSsrfAdvanced,
    fileInclusionRfi,
} from './exploit-signatures.js'
export { xpathInjection } from './xpath-injection.js'
export { ognlInjection } from './ognl-injection.js'
export { apiMassAssignment, apiBfla, apiVersionDowngrade } from './api-logic-abuse.js'
export {
    massAssignment,
    priceManipulation,
    idorParameterProbe,
    http2HeaderInjection,
    websocketProtocolConfusion,
} from './business-logic.js'


// ── Barrel Export ────────────────────────────────────────────────

export const INJECTION_CLASSES: InvariantClassModule[] = [
    // Proto pollution (basic detection + gadget-chain-aware)
    protoPollution,
    prototypePollutionViaQuery,
    protoPollutionGadget,
    // Log4Shell / JNDI
    logJndiLookup,
    // SSTI
    sstiJinjaTwig,
    sstiElExpression,
    templateInjectionGeneric,
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
    graphql_injection,
    graphql_dos,
    // Open redirect
    openRedirectBypass,
    // Mass assignment
    massAssignment,
    priceManipulation,
    idorParameterProbe,
    http2HeaderInjection,
    websocketProtocolConfusion,
    // LDAP
    ldapFilterInjection,
    // ReDoS
    regexDos,
    xxeInjection,
    httpSmuggling,
    // HTTP Smuggling — Kettle 2022-2025 complete coverage
    httpSmuggleClTe,        // CL.TE / TE.TE desync
    httpSmuggleH2,          // H2 downgrade smuggling
    httpSmuggleChunkExt,    // Chunk extension exploit (2025)
    httpSmuggleZeroCl,      // 0.CL desync (2025)
    httpSmuggleExpect,      // Expect-based desync (2025)
    http_request_smuggling, // CL.TE/TE.CL/general request smuggling detection
    requestSmuggling,
    // CORS
    corsOriginAbuse,
    // Supply-chain and dependency threats
    dependencyConfusion,
    postinstallInjection,
    envExfiltration,
    // WebSocket-specific threats
    ws_injection,
    ws_hijack,
    websocket_origin_bypass,
    websocket_message_injection,
    websocket_dos,
    // LLM prompt security classes
    llmPromptInjection,
    llmDataExfiltration,
    llmJailbreak,
    llmIndirectInjection,
    llm_token_smuggling,
    // Cache poisoning / deception
    cachePoisoning,
    cacheDeception,
    webCacheDeception,
    dnsRebinding,
    dependencyHijacking,
    // API logic abuse
    bolaIdor,
    apiMassEnum,
    // CSV formula / DDE injection
    csvInjection,
    gitHistoryTampering,
    // Rate-based auth abuse
    credentialStuffing,
    // Nation-state / Advanced Threats
    xmlBombDos,
    webdavMethodAbuse,
    traceXstAttack,
    dnsTunnelingIndicator,
    c2BeaconIndicator,
    containerEscapeIndicator,
    // Infrastructure and CI/CD attack classes
    githubActionsInjection,
    kubernetesRbacAbuse,
    terraformInjection,
    dockerEscapeIndicator,
    cloudMetadataAdvanced,
    compressionBomb,
    http2PseudoHeaderInjection,
    graphqlDepthAttack,
    // Timing/desync/cache/HPP advanced classes
    raceConditionProbe,
    redosPayload,
    httpDesyncAttack,
    cacheDeceptionAttack,
    parameterPollutionAdvanced,
    // Nation-state / exploit-signature threats
    log4shellVariant,
    spring4shell,
    springExpressionInjection,
    xpathInjection,
    ognlInjection,
    velocityInjection,
    freemarkerInjection,
    expressionLanguageGeneric,
    groovySandboxEscape,
    serverSideJsInjection,
    memoryDisclosureEndpoint,
    kubernetesSecretExposure,
    awsMetadataSsrfAdvanced,
    fileInclusionRfi,
    apiMassAssignment,
    apiBfla,
    apiVersionDowngrade,
    ...WEB_ATTACKS_CLASSES,
]
