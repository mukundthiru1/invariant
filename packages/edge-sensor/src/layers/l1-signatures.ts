/**
 * Edge Sensor — Layer 1: Static Signature Detection
 *
 * High confidence, low false positive pattern matching.
 * 30+ signatures across SQLi, XSS, path traversal, SSRF,
 * command injection, SSTI, deserialization, and more.
 */

import type { SignatureRule } from './types.js'

export const SIGNATURES: SignatureRule[] = [
    // SQL Injection
    {
        id: 'sqli-union', type: 'sql_injection', subtype: 'union_based', severity: 'high', confidence: 0.9,
        check: ctx => /union\s+(all\s+)?select\s/i.test(ctx.fullDecoded),
    },
    {
        id: 'sqli-blind', type: 'sql_injection', subtype: 'boolean_blind', severity: 'high', confidence: 0.8,
        check: ctx => /'\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i.test(ctx.decodedQuery),
    },
    {
        id: 'sqli-stacked', type: 'sql_injection', subtype: 'stacked_queries', severity: 'critical', confidence: 0.9,
        check: ctx => /;\s*(drop|delete|insert|update|alter|create|exec|execute)\s+/i.test(ctx.decodedQuery),
    },
    {
        id: 'sqli-time', type: 'sql_injection', subtype: 'time_blind', severity: 'high', confidence: 0.85,
        check: ctx => /(?:sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep)/i.test(ctx.fullDecoded),
    },
    {
        id: 'sqli-error', type: 'sql_injection', subtype: 'error_based', severity: 'high', confidence: 0.8,
        check: ctx => /(?:extractvalue|updatexml|xmltype|convert\s*\(.*using)/i.test(ctx.fullDecoded),
    },

    // XSS
    {
        id: 'xss-script', type: 'xss', subtype: 'reflected', severity: 'high', confidence: 0.9,
        check: ctx => /<script[\s>]/i.test(ctx.decodedQuery) || /javascript\s*:/i.test(ctx.decodedQuery),
    },
    {
        id: 'xss-event', type: 'xss', subtype: 'event_handler', severity: 'high', confidence: 0.8,
        check: ctx => /\bon(?:error|load|click|mouseover|focus|blur|submit|change|input)\s*=/i.test(ctx.decodedQuery),
    },
    {
        id: 'xss-svg', type: 'xss', subtype: 'svg_injection', severity: 'high', confidence: 0.85,
        check: ctx => /<svg[\s/].*?on\w+\s*=/i.test(ctx.decodedQuery),
    },

    // Path Traversal
    {
        id: 'lfi-traversal', type: 'path_traversal', subtype: 'directory_traversal', severity: 'high', confidence: 0.85,
        check: ctx => /(?:\.\.[\\/]){2,}/.test(ctx.fullDecoded) || /(?:%2e%2e[\\/]|\.\.%2f|%2e%2e%5c){2,}/i.test(ctx.path + ctx.query),
    },
    {
        id: 'lfi-sensitive', type: 'path_traversal', subtype: 'sensitive_file', severity: 'critical', confidence: 0.95,
        check: ctx => /\/etc\/(?:passwd|shadow|hosts)|\/proc\/self\/(?:environ|cmdline)|\/windows\/(?:system32|win\.ini)/i.test(ctx.fullDecoded),
    },

    // Command Injection
    {
        id: 'cmdi-shell', type: 'command_injection', subtype: 'shell_command', severity: 'critical', confidence: 0.85,
        check: ctx => /[;|`]\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|bash|sh|python|perl|ruby|php)\b/i.test(ctx.decodedQuery),
    },
    {
        id: 'cmdi-subshell', type: 'command_injection', subtype: 'subshell', severity: 'critical', confidence: 0.8,
        check: ctx => /\$\([^)]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh)[^)]*\)/.test(ctx.decodedQuery),
    },

    // SSRF
    {
        id: 'ssrf-internal', type: 'ssrf', subtype: 'internal_network', severity: 'high', confidence: 0.85,
        check: ctx => /https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/i.test(ctx.decodedQuery),
    },
    {
        id: 'ssrf-metadata', type: 'ssrf', subtype: 'cloud_metadata', severity: 'critical', confidence: 0.95,
        check: ctx => /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/i.test(ctx.fullDecoded),
    },

    // SSTI
    {
        id: 'ssti-jinja', type: 'ssti', subtype: 'jinja_twig', severity: 'critical', confidence: 0.85,
        check: ctx => /\{\{[^}]*(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|config\.|request\.)/.test(ctx.fullDecoded),
    },
    {
        id: 'ssti-el', type: 'ssti', subtype: 'expression_language', severity: 'critical', confidence: 0.85,
        check: ctx => /\$\{[^}]*(?:Runtime|ProcessBuilder|getRuntime|exec\(|Class\.forName)/i.test(ctx.fullDecoded),
    },

    // Deserialization
    {
        id: 'deser-java', type: 'deserialization', subtype: 'java_object', severity: 'critical', confidence: 0.9,
        check: ctx => ctx.contentType.includes('application/x-java-serialized-object') || /aced0005|rO0ABX/i.test(ctx.query),
    },
    {
        id: 'deser-php', type: 'deserialization', subtype: 'php_object', severity: 'high', confidence: 0.85,
        check: ctx => /O:\d+:"[^"]+"/i.test(ctx.decodedQuery),
    },

    // Header Injection
    {
        id: 'header-crlf', type: 'header_injection', subtype: 'crlf', severity: 'high', confidence: 0.85,
        check: ctx => /%0[da]|%0[DA]/i.test(ctx.path + ctx.query),
    },

    // XXE
    {
        id: 'xxe-entity', type: 'xxe', subtype: 'entity_injection', severity: 'critical', confidence: 0.9,
        check: ctx => /<!(?:ENTITY|DOCTYPE)\s/i.test(ctx.fullDecoded) && /(?:SYSTEM|PUBLIC)\s/i.test(ctx.fullDecoded),
    },

    // Log4Shell
    {
        id: 'log4shell', type: 'exploit_payload', subtype: 'log4shell', severity: 'critical', confidence: 0.95,
        check: ctx => /\$\{(?:jndi|lower|upper|env|sys|java|date):/i.test(ctx.fullDecoded),
    },

    // Prototype Pollution
    {
        id: 'proto-pollution', type: 'exploit_payload', subtype: 'prototype_pollution', severity: 'high', confidence: 0.8,
        check: ctx => /__proto__|constructor\[prototype\]|constructor\.prototype/i.test(ctx.fullDecoded),
    },

    // Scanner Detection
    {
        id: 'scanner-tools', type: 'scanner', subtype: 'automated', severity: 'info', confidence: 0.9,
        check: ctx => /nuclei|sqlmap|nmap|nikto|masscan|zap|burp|dirbuster|gobuster|ffuf|wfuzz|feroxbuster|dalfox/i.test(ctx.ua),
    },

    // Info Disclosure
    {
        id: 'enum-sensitive', type: 'information_disclosure', subtype: 'sensitive_files', severity: 'medium', confidence: 0.75,
        check: ctx => /(?:\.env|\.git\/(?:config|HEAD)|\.htaccess|\.aws\/credentials|wp-config\.php|phpinfo\.php|server-status)/i.test(ctx.path),
    },
    {
        id: 'enum-debug', type: 'information_disclosure', subtype: 'debug_endpoint', severity: 'high', confidence: 0.7,
        check: ctx => /\/(?:debug|trace|metrics|__debug__|_debug_toolbar|actuator|telescope)/i.test(ctx.path),
    },

    // Auth Bypass
    {
        id: 'jwt-none', type: 'auth_bypass', subtype: 'jwt_none_algorithm', severity: 'critical', confidence: 0.9,
        check: ctx => {
            const auth = ctx.headers.get('authorization') ?? ''
            if (!auth.startsWith('Bearer ')) return false
            try {
                const parts = auth.slice(7).split('.')
                if (parts.length !== 3) return false
                // SECURITY (SAA-043): Use reviver to reject __proto__/constructor injection
                const header = JSON.parse(atob(parts[0]), (key, value) => {
                    if (key === '__proto__' || key === 'constructor') return undefined
                    return value
                })
                return header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE'
            } catch { return false }
        },
    },

    // HTTP Smuggling
    {
        id: 'smuggle-te', type: 'http_smuggling', subtype: 'te_obfuscation', severity: 'critical', confidence: 0.85,
        check: ctx => {
            const te = ctx.headers.get('transfer-encoding') ?? ''
            return te.length > 0 && (te.includes(',') || /\schunked|chunked\s/i.test(te) || te.toLowerCase() !== 'chunked') && ctx.headers.has('content-length')
        },
    },

    // NoSQL Injection
    {
        id: 'nosql-operator', type: 'nosql_injection', subtype: 'operator_injection', severity: 'high', confidence: 0.8,
        check: ctx => /\$(?:gt|gte|lt|lte|ne|eq|in|nin|regex|where|exists|type|or|and|not|nor|elemMatch)\b/i.test(ctx.fullDecoded),
    },

    // Open Redirect
    {
        id: 'open-redirect', type: 'open_redirect', subtype: 'url_redirect', severity: 'medium', confidence: 0.7,
        check: ctx => /(?:redirect|next|url|return|continue|goto|target|dest|destination|redir|forward)=(?:https?:\/\/|\/\/)/i.test(ctx.query),
    },

    // LDAP Injection
    {
        id: 'ldap-injection', type: 'ldap_injection', subtype: 'filter_injection', severity: 'high', confidence: 0.85,
        check: ctx => /[)(|*]\s*(?:\(|\)|\||&|!|=|~=|>=|<=)/i.test(ctx.fullDecoded) && /(?:uid|cn|sn|ou|dc|objectClass|member)/i.test(ctx.fullDecoded),
    },
]
