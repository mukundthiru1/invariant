/**
 * @santh/agent — Filesystem RASP Wrapper
 *
 * Wraps fs operations to detect path traversal violations.
 *
 * The math:
 *   Given path P and base directory B:
 *   resolve(P) must be a child of B.
 *   If resolve(P) escapes B, P is a traversal.
 */

import { resolve, relative } from 'node:path'
import type { InvariantDB, DefenseAction, Severity } from '../db.js'

export interface FsRaspConfig {
    mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    db: InvariantDB
    allowedRoots: string[]
    onViolation?: (violation: FsViolation) => void
}

export interface FsViolation {
    path: string
    resolvedPath: string
    invariantClass: string
    action: DefenseAction
    timestamp: string
}

const PATH_INVARIANTS = [
    {
        id: 'path_traversal',
        test: (inputPath: string) => /(?:\.\.[/\\]){2,}/.test(inputPath),
        severity: 'high' as Severity,
    },
    {
        id: 'path_null_byte',
        test: (inputPath: string) => /\x00|%00/.test(inputPath),
        severity: 'critical' as Severity,
    },
    {
        id: 'path_sensitive_file',
        test: (inputPath: string) => {
            const resolved = inputPath.toLowerCase()
            return /(?:\/etc\/(?:passwd|shadow|hosts)|\/proc\/self\/|\.env|\.git\/|\.ssh\/|id_rsa|\.htpasswd|web\.config)/.test(resolved)
        },
        severity: 'critical' as Severity,
    },
]

function checkEscapesRoot(filePath: string, allowedRoots: string[]): boolean {
    if (allowedRoots.length === 0) return false
    const resolved = resolve(filePath)
    return !allowedRoots.some(root => {
        const rel = relative(root, resolved)
        return !rel.startsWith('..') && !resolve(rel).startsWith('..')
    })
}

export function wrapFsOperation<T extends (...args: unknown[]) => unknown>(
    originalFn: T,
    config: FsRaspConfig,
    opName: string,
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const filePath = typeof args[0] === 'string' ? args[0] : ''
        if (!filePath) return originalFn.apply(this, args)

        // Check invariant violations
        const violations: Array<{ id: string; severity: Severity }> = []

        for (const inv of PATH_INVARIANTS) {
            if (inv.test(filePath)) {
                violations.push({ id: inv.id, severity: inv.severity })
            }
        }

        // Check directory escape
        if (checkEscapesRoot(filePath, config.allowedRoots)) {
            violations.push({ id: 'path_directory_escape', severity: 'high' })
        }

        if (violations.length === 0) return originalFn.apply(this, args)

        const hasCritical = violations.some(v => v.severity === 'critical')
        const action: DefenseAction =
            config.mode === 'observe' ? 'monitored' :
                config.mode === 'sanitize' ? 'normalized' :
                    (hasCritical || config.mode === 'lockdown') ? 'blocked' : 'monitored'

        const now = new Date().toISOString()
        const resolvedPath = resolve(filePath)

        // Record
        try {
            config.db.insertSignal({
                type: 'fs_invariant_violation',
                subtype: violations[0].id,
                severity: violations[0].severity,
                action,
                path: `fs.${opName}()`,
                method: 'FS',
                source_hash: null,
                invariant_classes: JSON.stringify(violations.map(v => v.id)),
                is_novel: false,
                timestamp: now,
            })
            config.db.insertFinding({
                type: 'runtime_invariant_violation',
                category: 'path_traversal',
                severity: violations[0].severity,
                status: 'open',
                title: `Path traversal: ${violations[0].id}`,
                description: `Detected ${violations[0].id} in fs.${opName}(). Path: ${filePath.slice(0, 200)}`,
                location: `fs.${opName}()`,
                evidence: JSON.stringify({ path: filePath.slice(0, 200), resolved: resolvedPath.slice(0, 200), violations: violations.map(v => v.id) }),
                remediation: 'Validate and normalize user-supplied paths before passing to filesystem operations. Use path.resolve() + path.relative() to ensure the resolved path stays within the allowed directory.',
                cve_id: null,
                confidence: 0.9,
                first_seen: now,
                last_seen: now,
                rasp_active: action === 'blocked',
            })
        } catch { /* Never break the app */ }

        if (config.onViolation) {
            try {
                config.onViolation({ path: filePath, resolvedPath, invariantClass: violations[0].id, action, timestamp: now })
            } catch { /* Never break the app */ }
        }

        if (action === 'blocked') {
            throw new Error(`[INVARIANT] File operation blocked — ${violations.map(v => v.id).join(', ')} detected.`)
        }

        // Normalize mode: resolve the path to prevent traversal
        if (action === 'normalized' && config.allowedRoots.length > 0) {
            const safePath = resolve(config.allowedRoots[0], resolve('/', filePath).slice(1))
            args[0] = safePath
        }

        return originalFn.apply(this, args)
    }

    return wrapped as unknown as T
}
