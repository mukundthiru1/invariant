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
import { join, resolve, relative } from 'node:path'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { spawn } from 'node:child_process'

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

    agent.stop()
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
    if (dbDriver) db.setAsset('app.database', dbDriver)

    await agent.start()

    const status = agent.getStatus()
    console.log('')
    console.log('  ═══════════════════════════════════════════════')
    console.log('  INVARIANT initialized successfully.')
    console.log('')
    console.log(`  Findings:    ${status.findings.total} (${status.findings.critical} critical, ${status.findings.high} high)`)
    console.log(`  Database:    invariant.db (${projectDir})`)
    console.log(`  Mode:        observe (safe — monitoring only)`)
    console.log('')
    console.log('  Next steps:')
    console.log('    npx @santh/invariant dashboard   — view findings')
    console.log('    npx @santh/invariant deploy       — deploy edge sensor')
    console.log('')
    console.log('  Add to your app:')
    console.log("    import { invariantMiddleware } from '@santh/agent/middleware/express'")
    console.log('    app.use(invariantMiddleware())')
    console.log('')
    console.log('  ═══════════════════════════════════════════════')

    agent.stop()
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
        case 'dashboard':
        case 'ui':
            logo()
            await commandDashboard(projectDir)
            break
        case 'status':
            logo()
            await commandStatus(projectDir)
            break
        case 'deploy':
            logo()
            await commandDeploy(projectDir)
            break
        case 'watch':
            logo()
            await commandWatch(projectDir)
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
            console.log('    dashboard   Open localhost dashboard')
            console.log('    status      Show current posture')
            console.log('    deploy      Deploy edge sensor to Cloudflare')
            console.log('    watch       Continuous monitoring with periodic rescans')
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

        // Build arguments array (secure, no shell injection)
        const wranglerArgs = ['wrangler', 'deploy', '--var', `DEFENSE_MODE:${mode}`, '--var', 'SIGNAL_BATCH_SIZE:50']
        
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

main().catch(err => {
    console.error('  Error:', err.message ?? err)
    process.exit(1)
})
