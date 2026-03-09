#!/usr/bin/env node
import { resolve4, resolve6, resolveCname, resolveMx, resolveNs } from 'node:dns/promises'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { extname, isAbsolute, join, relative, resolve } from 'node:path'
import tls from 'node:tls'

import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  ALL_CLASS_MODULES,
  AutoFixer,
  CodebaseScanner,
  InvariantEngine,
  type InvariantClass,
  type InvariantClassModule,
  type InvariantMatch,
  type ScanFinding as CodebaseFinding,
  type Severity,
} from '@santh/invariant-engine'
import { DEFAULT_LICENSE_POLICY, evaluateLicense, type LicensePolicy } from '../../deploy-gate/src/license-policy.js'
import { z } from 'zod'

type ToolExtra = {
  _meta?: {
    progressToken?: string | number
  }
  sendNotification: (notification: any) => Promise<void>
}

type ScanFinding = {
  class: string
  category: string
  severity: Severity
  confidence: number
  mitre: string[]
  cwe: string
  description: string
  evidence: string
  remediation: string
  novel: boolean
}

type ExplainResult = {
  explanation: string
  invariant: string
  whyDangerous: string
  examples: string[]
  remediation: string
}

type FixResult = {
  fixedCode: string
  explanation: string
  diff: string
}

type HygieneIssue = {
  id: string
  severity: Severity
  title: string
  details: string
  recommendation: string
  evidence?: string
}

type LicenseViolation = {
  license: string
  reason: string
  policyMatch: string
}

type LicenseWarning = {
  license: string
  reason: string
  policyMatch: string
}

const DEFAULT_SCANNER_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.vue', '.svelte']
const DEFAULT_SCANNER_EXCLUDES = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.nuxt']
const LICENSE_OPERATORS = new Set(['AND', 'OR', 'WITH'])

const engine = new InvariantEngine()
const classById = new Map<string, InvariantClassModule>(ALL_CLASS_MODULES.map((module) => [module.id, module]))

const server = new McpServer({
  name: '@santh/mcp-server',
  version: '1.1.0',
})

const findingSchema = z.object({
  class: z.string().describe('Invariant class id that matched'),
  category: z.string().describe('Attack category for matched class'),
  severity: z.enum(['critical', 'high', 'medium', 'low']).describe('Severity of this finding'),
  confidence: z.number().min(0).max(1).describe('Confidence score (0-1)'),
  mitre: z.array(z.string()).describe('Mapped MITRE ATT&CK technique ids'),
  cwe: z.string().describe('Mapped CWE identifier'),
  description: z.string().describe('Class-level risk description'),
  evidence: z.string().describe('Evidence extracted from L2 or proof context'),
  remediation: z.string().describe('Practical remediation guidance'),
  novel: z.boolean().describe('True when this is novel by L2/L3'),
})

const hygieneIssueSchema = z.object({
  id: z.string().describe('Stable issue identifier'),
  severity: z.enum(['critical', 'high', 'medium', 'low']).describe('Issue severity'),
  title: z.string().describe('Human-readable issue title'),
  details: z.string().describe('Issue details'),
  recommendation: z.string().describe('Remediation recommendation'),
  evidence: z.string().optional().describe('Supporting evidence snippet'),
})

const codebaseFindingSchema = z.object({
  file: z.string().describe('Relative file path'),
  line: z.number().int().min(1).describe('1-based line number'),
  column: z.number().int().min(1).describe('1-based column number'),
  category: z.string().describe('Scanner category'),
  sink: z.string().describe('Sink signature'),
  snippet: z.string().describe('Code snippet'),
  severity: z.enum(['critical', 'high', 'medium', 'low']).describe('Severity'),
  suggestion: z.string().describe('Remediation suggestion'),
  confidence: z.number().optional().describe('Optional confidence score'),
  source: z.string().optional().describe('Detected source symbol for taint path'),
  taintPath: z.array(z.string()).optional().describe('AST taint path if available'),
})

server.registerTool(
  'santh_scan',
  {
    description: 'Scan text or file content with INVARIANT deep detection.',
    inputSchema: {
      input: z.string().describe('Raw text/code to scan'),
      context: z.string().optional().describe('Known interpreter context, e.g. sql/html/shell/url'),
    },
    outputSchema: {
      detected: z.boolean(),
      findings: z.array(findingSchema),
      confidence: z.number().min(0).max(1),
      explanation: z.string(),
    },
  },
  async ({ input, context }) => {
    try {
      const sourceInput = resolveInput(input)
      const deep = engine.detectDeep(sourceInput, [], context)
      const findings = deep.matches.map((match) => toScanFinding(match))
      findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.confidence - a.confidence)
      const detected = findings.length > 0
      const confidence = detected ? Math.max(...findings.map((entry) => entry.confidence)) : 0
      const explanation = detected
        ? `Detected ${findings.length} finding(s): convergent=${deep.convergent}, novelL2=${deep.novelByL2}, novelL3=${deep.novelByL3}.`
        : 'No invariant class violations detected.'
      const structuredContent = { detected, findings, confidence, explanation }
      return {
        content: [{ type: 'text', text: JSON.stringify(structuredContent, null, 2) }],
        structuredContent,
      }
    } catch (error) {
      throw asMcpError(error, 'santh_scan failed')
    }
  },
)

server.registerTool(
  'santh_explain',
  {
    description: 'Explain why an invariant class is dangerous for a given input.',
    inputSchema: {
      input: z.string().describe('Raw input to evaluate against class'),
      classId: z.string().describe('Invariant class id (e.g. sql_tautology)'),
    },
    outputSchema: {
      explanation: z.string(),
      invariant: z.string(),
      whyDangerous: z.string(),
      examples: z.array(z.string()),
      remediation: z.string(),
    },
  },
  async ({ input, classId }) => {
    try {
      const module = classById.get(classId)
      if (!module) {
        throw new McpError(ErrorCode.InvalidParams, `Unknown classId: ${classId}`)
      }

      const deep = engine.detectDeep(input, [], undefined)
      const match = deep.matches.find((entry) => entry.class === module.id)
      const l1Detected = safeDetectL1(module, input)
      const l2Detected = safeDetectL2(module, input)

      const explanation = [
        `Class ${module.id} (${module.category})`,
        `L1=${String(l1Detected)} L2=${String(Boolean(l2Detected?.detected))}`,
        match ? `confidence=${match.confidence.toFixed(2)}` : 'confidence=0.00',
        l2Detected?.explanation ? `detail=${l2Detected.explanation}` : 'detail=No L2 evidence available for this input',
      ].join(' | ')

      const response: ExplainResult = {
        explanation,
        invariant: module.formalProperty ?? `Invariant: input violates ${module.id} class property.`,
        whyDangerous: module.description,
        examples: module.knownPayloads.slice(0, 5),
        remediation: remediationForClass(module.id),
      }
      return {
        content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        structuredContent: response,
      }
    } catch (error) {
      throw asMcpError(error, 'santh_explain failed')
    }
  },
)

server.registerTool(
  'santh_fix',
  {
    description: 'Generate a safer code variant for a specific invariant finding.',
    inputSchema: {
      code: z.string().describe('Source code'),
      language: z.enum(['js', 'ts', 'python', 'go']).describe('Source language'),
      findingId: z.string().describe('Invariant class id to fix'),
    },
    outputSchema: {
      fixedCode: z.string(),
      explanation: z.string(),
      diff: z.string(),
    },
  },
  async ({ code, language, findingId }) => {
    try {
      const autoFix = runAutoFixerPipeline(code, language, findingId)
      if (autoFix) {
        return {
          content: [{ type: 'text', text: JSON.stringify(autoFix, null, 2) }],
          structuredContent: autoFix,
        }
      }

      const fallback = applyPatternFix(code, findingId)
      return {
        content: [{ type: 'text', text: JSON.stringify(fallback, null, 2) }],
        structuredContent: fallback,
      }
    } catch (error) {
      throw asMcpError(error, 'santh_fix failed')
    }
  },
)

server.registerTool(
  'santh_hygiene',
  {
    description: 'Run DNS/TLS/header hygiene checks for a URL or domain.',
    inputSchema: {
      target: z.string().describe('URL or domain to evaluate'),
    },
    outputSchema: {
      issues: z.array(hygieneIssueSchema),
      score: z.number().min(0).max(100),
      summary: z.string(),
    },
  },
  async ({ target }) => {
    try {
      const report = await runHygiene(target)
      return {
        content: [{ type: 'text', text: JSON.stringify(report, null, 2) }],
        structuredContent: report,
      }
    } catch (error) {
      throw asMcpError(error, 'santh_hygiene failed')
    }
  },
)

server.registerTool(
  'santh_license_check',
  {
    description: 'Evaluate SPDX license compatibility against deny/warn policy.',
    inputSchema: {
      licenses: z.array(z.string()).min(1).max(500).describe('SPDX identifiers or expressions'),
      policy: z.object({
        deny: z.array(z.string()).default(DEFAULT_LICENSE_POLICY.deny),
        warn: z.array(z.string()).default(DEFAULT_LICENSE_POLICY.warn),
      }).optional().describe('Optional policy override'),
    },
    outputSchema: {
      violations: z.array(z.object({
        license: z.string(),
        reason: z.string(),
        policyMatch: z.string(),
      })),
      warnings: z.array(z.object({
        license: z.string(),
        reason: z.string(),
        policyMatch: z.string(),
      })),
      passed: z.boolean(),
    },
  },
  async ({ licenses, policy }) => {
    try {
      const effectivePolicy: LicensePolicy = {
        deny: policy?.deny ?? DEFAULT_LICENSE_POLICY.deny,
        warn: policy?.warn ?? DEFAULT_LICENSE_POLICY.warn,
      }

      const violations: LicenseViolation[] = []
      const warnings: LicenseWarning[] = []

      for (const expression of licenses) {
        const tokens = parseSpdxExpression(expression)
        if (tokens.length === 0) {
          warnings.push({
            license: expression,
            reason: 'Unable to parse SPDX expression.',
            policyMatch: 'unparsed',
          })
          continue
        }

        for (const token of tokens) {
          const verdict = evaluateLicense(token, effectivePolicy)
          if (verdict === 'denied') {
            violations.push({
              license: expression,
              reason: `Denied license component found: ${token}`,
              policyMatch: token,
            })
          } else if (verdict === 'warned') {
            warnings.push({
              license: expression,
              reason: `Warning license component found: ${token}`,
              policyMatch: token,
            })
          }
        }
      }

      const passed = violations.length === 0
      const structuredContent = { violations, warnings, passed }
      return {
        content: [{ type: 'text', text: JSON.stringify(structuredContent, null, 2) }],
        structuredContent,
      }
    } catch (error) {
      throw asMcpError(error, 'santh_license_check failed')
    }
  },
)

server.registerTool(
  'santh_codebase_scan',
  {
    description: 'Scan a codebase directory with CodebaseScanner and stream progress updates.',
    inputSchema: {
      directory: z.string().describe('Directory path to scan'),
      excludePatterns: z.array(z.string()).optional().describe('Additional exclude path patterns'),
    },
    outputSchema: {
      findings: z.array(codebaseFindingSchema),
      summary: z.string(),
      criticalCount: z.number().int().min(0),
      highCount: z.number().int().min(0),
    },
  },
  async ({ directory, excludePatterns }, extra) => {
    try {
      const root = resolve(directory)
      if (!existsSync(root) || !statSync(root).isDirectory()) {
        throw new McpError(ErrorCode.InvalidParams, `Directory does not exist: ${directory}`)
      }

      const excludes = [...DEFAULT_SCANNER_EXCLUDES, ...(excludePatterns ?? [])]
      const scanner = new CodebaseScanner({ rootDir: root, exclude: excludes })
      const files = collectScannableFiles(root, excludes)
      const findings: CodebaseFinding[] = []

      const total = files.length
      if (total === 0) {
        const empty = {
          findings,
          summary: `No scannable files found in ${root}.`,
          criticalCount: 0,
          highCount: 0,
        }
        return {
          content: [{ type: 'text', text: JSON.stringify(empty, null, 2) }],
          structuredContent: empty,
        }
      }

      for (let index = 0; index < files.length; index++) {
        const filePath = files[index]
        findings.push(...scanner.scanFile(filePath))

        if ((index + 1) % 20 === 0 || index + 1 === total) {
          await emitProgress(extra, index + 1, total, `Scanned ${index + 1}/${total} files`)
        }
      }

      const criticalCount = findings.filter((finding) => finding.severity === 'critical').length
      const highCount = findings.filter((finding) => finding.severity === 'high').length
      const summary = `Scanned ${total} files in ${root}; findings=${findings.length}, critical=${criticalCount}, high=${highCount}.`
      const structuredContent = { findings, summary, criticalCount, highCount }
      return {
        content: [{ type: 'text', text: JSON.stringify(structuredContent, null, 2) }],
        structuredContent,
      }
    } catch (error) {
      throw asMcpError(error, 'santh_codebase_scan failed')
    }
  },
)

async function main(): Promise<void> {
  const transport = new StdioServerTransport()
  await server.connect(transport)
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error)
  process.stderr.write(`${message}\n`)
  process.exit(1)
})

function toScanFinding(match: InvariantMatch): ScanFinding {
  const module = classById.get(match.class)
  return {
    class: match.class,
    category: match.category,
    severity: match.severity,
    confidence: clampConfidence(match.confidence),
    mitre: module?.mitre ?? [],
    cwe: module?.cwe ?? 'Unknown',
    description: module?.description ?? match.description,
    evidence: match.l2Evidence ?? match.proof?.witness ?? match.description,
    remediation: remediationForClass(match.class),
    novel: match.isNovelVariant,
  }
}

function resolveInput(input: string): string {
  const trimmed = input.trim()
  if (!trimmed) return input

  const absolute = isAbsolute(trimmed) ? trimmed : resolve(process.cwd(), trimmed)
  if (!existsSync(absolute)) return input

  try {
    if (statSync(absolute).isFile()) {
      return readFileSync(absolute, 'utf8')
    }
  } catch {
    return input
  }
  return input
}

function asMcpError(error: unknown, prefix: string): McpError {
  if (error instanceof McpError) {
    return error
  }
  const detail = error instanceof Error ? error.message : String(error)
  return new McpError(ErrorCode.InternalError, `${prefix}: ${detail}`)
}

function safeDetectL1(module: InvariantClassModule, input: string): boolean {
  try {
    return module.detect(input)
  } catch {
    return false
  }
}

function safeDetectL2(module: InvariantClassModule, input: string): { detected: boolean; explanation: string } | null {
  if (!module.detectL2) return null
  try {
    const result = module.detectL2(input)
    if (!result) return null
    return {
      detected: result.detected,
      explanation: result.explanation,
    }
  } catch {
    return null
  }
}

function remediationForClass(classId: InvariantClass): string {
  if (classId.startsWith('sql_') || classId === 'json_sql_bypass') {
    return 'Use parameterized queries and avoid dynamic SQL string construction.'
  }
  if (classId.includes('xss') || classId === 'dom_xss') {
    return 'Encode output by context and avoid unsafe DOM sinks such as innerHTML/eval.'
  }
  if (classId.startsWith('cmd_') || classId === 'server_side_js_injection') {
    return 'Avoid shell execution with dynamic strings; use argument arrays and strict allowlists.'
  }
  if (classId.startsWith('path_')) {
    return 'Resolve paths against a fixed base directory and reject traversal or absolute escapes.'
  }
  if (classId.startsWith('ssrf_') || classId === 'cloud_metadata_advanced' || classId === 'aws_metadata_ssrf_advanced') {
    return 'Restrict outbound requests to explicit allowlists and block private or metadata destinations.'
  }
  if (classId === 'proto_pollution' || classId === 'proto_pollution_gadget') {
    return 'Block __proto__/prototype/constructor keys and use safe merge routines.'
  }
  if (classId.startsWith('secret_')) {
    return 'Move secrets to a managed secret store and rotate leaked credentials.'
  }
  return 'Apply strict input validation, contextual output encoding, and least-privilege controls for this class.'
}

function runAutoFixerPipeline(code: string, language: 'js' | 'ts' | 'python' | 'go', findingId: string): FixResult | null {
  const extension = languageToExtension(language)
  const tempRoot = mkdtempSync(join(tmpdir(), 'santh-fix-'))
  const tempFile = join(tempRoot, `snippet${extension}`)

  try {
    writeFileSync(tempFile, code, 'utf8')

    const scanner = new CodebaseScanner({ rootDir: tempRoot })
    const rawFindings = scanner.scanFile(tempFile)
    const targetCategory = invariantClassToScannerCategory(findingId)
    const targetFindings = targetCategory
      ? rawFindings.filter((finding) => finding.category === targetCategory)
      : rawFindings

    if (targetFindings.length === 0) return null

    const fixer = new AutoFixer(tempRoot)
    const generatedFixes = fixer.generateFixes(targetFindings)
    const selectedFix = generatedFixes.find((fix) => fix.fixed !== fix.original)
    if (!selectedFix) return null

    const applied = fixer.applyFixes([selectedFix])
    const appliedFix = applied.find((fix) => fix.file === selectedFix.file && fix.line === selectedFix.line && fix.applied)
    if (!appliedFix) return null

    const fixedCode = readFileSync(tempFile, 'utf8')
    return {
      fixedCode,
      explanation: `AutoFixer applied ${selectedFix.category} mitigation at line ${selectedFix.line}.`,
      diff: createUnifiedDiff(code, fixedCode),
    }
  } finally {
    rmSync(tempRoot, { recursive: true, force: true })
  }
}

function applyPatternFix(code: string, findingId: string): FixResult {
  let fixedCode = code
  const normalized = findingId.toLowerCase()

  if (normalized.startsWith('sql_') || normalized === 'json_sql_bypass') {
    fixedCode = fixedCode
      .replace(/`([^`]*\bSELECT\b[^`]*)\$\{[^}]+\}([^`]*)`/gi, '"$1?$2"')
      .replace(/\.query\s*\(\s*([^,\n]+\+[^\n]+)\)/g, '.query(/* parameterized */ sql, params)')
  } else if (normalized.includes('xss') || normalized === 'dom_xss') {
    fixedCode = fixedCode
      .replace(/\.innerHTML\s*=\s*/g, '.textContent = ')
      .replace(/\bdangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/g, 'children={$1}')
      .replace(/\bdocument\.write\s*\(/g, '/* blocked */ document.body.append(')
  } else if (normalized.startsWith('cmd_') || normalized === 'server_side_js_injection') {
    fixedCode = fixedCode
      .replace(/\bexecSync\s*\(/g, 'execFileSync(')
      .replace(/\bexec\s*\(/g, 'execFile(')
      .replace(/\bshell\s*:\s*true/g, 'shell: false')
  } else if (normalized.startsWith('path_')) {
    fixedCode = fixedCode
      .replace(/\bpath\.join\s*\(/g, 'safeJoin(')
      .replace(/\breadFileSync\s*\(/g, 'readFileSync(assertSafePath(')
  } else if (normalized.startsWith('ssrf_')) {
    fixedCode = fixedCode
      .replace(/\bfetch\s*\(/g, 'fetch(assertSafeUrl(')
      .replace(/\baxios\.(get|post|request)\s*\(/g, 'axios.$1(assertSafeUrl(')
  } else if (normalized === 'proto_pollution' || normalized === 'proto_pollution_gadget') {
    fixedCode = fixedCode
      .replace(/__proto__/g, '__blocked_proto__')
      .replace(/constructor\.prototype/g, 'safePrototypeAccess')
  }

  return {
    fixedCode,
    explanation: `Applied pattern-based fallback remediation for ${findingId}.`,
    diff: createUnifiedDiff(code, fixedCode),
  }
}

async function runHygiene(target: string): Promise<{ issues: HygieneIssue[]; score: number; summary: string }> {
  const normalized = normalizeTarget(target)
  const issues: HygieneIssue[] = []

  const [a, aaaa, mx, ns, cname] = await Promise.all([
    safeDns(() => resolve4(normalized.host)),
    safeDns(() => resolve6(normalized.host)),
    safeDns(async () => (await resolveMx(normalized.host)).map((entry) => entry.exchange)),
    safeDns(() => resolveNs(normalized.host)),
    safeDns(() => resolveCname(normalized.host)),
  ])

  if (a.length === 0 && aaaa.length === 0) {
    issues.push({
      id: 'dns-no-address-records',
      severity: 'high',
      title: 'No A/AAAA records resolved',
      details: `Unable to resolve ${normalized.host} to a routable address.`,
      recommendation: 'Check DNS zone configuration and authoritative nameserver health.',
    })
  }

  if (mx.length === 0) {
    issues.push({
      id: 'dns-no-mx',
      severity: 'low',
      title: 'No MX records found',
      details: 'No MX records were returned.',
      recommendation: 'If this domain receives email, configure MX records explicitly.',
    })
  }

  const tlsCheck = await checkTlsCertificate(normalized.host)
  if (!tlsCheck.valid) {
    issues.push({
      id: 'tls-handshake-failed',
      severity: 'high',
      title: 'TLS handshake failed',
      details: tlsCheck.details,
      recommendation: 'Ensure a valid certificate chain is deployed on port 443.',
    })
  } else if (typeof tlsCheck.daysRemaining === 'number' && tlsCheck.daysRemaining < 14) {
    issues.push({
      id: 'tls-expiring-soon',
      severity: 'medium',
      title: 'TLS certificate expiring soon',
      details: `Certificate expires in ${tlsCheck.daysRemaining} day(s).`,
      recommendation: 'Rotate the certificate before expiry.',
      evidence: tlsCheck.validTo,
    })
  }

  const headersResult = await fetchHeaders(normalized.url)
  if (!headersResult) {
    issues.push({
      id: 'http-unreachable',
      severity: 'high',
      title: 'Unable to fetch HTTP headers',
      details: `Failed to fetch ${normalized.url.toString()} over HTTP(S).`,
      recommendation: 'Validate network path, DNS records, and service availability.',
    })
  } else {
    const headers = headersResult.headers
    if (!headers['strict-transport-security']) {
      issues.push({
        id: 'missing-hsts',
        severity: 'medium',
        title: 'Missing Strict-Transport-Security header',
        details: 'HSTS header was not observed.',
        recommendation: 'Add Strict-Transport-Security with a long max-age and includeSubDomains.',
      })
    }
    if (!headers['content-security-policy']) {
      issues.push({
        id: 'missing-csp',
        severity: 'medium',
        title: 'Missing Content-Security-Policy header',
        details: 'CSP header was not observed.',
        recommendation: 'Define a restrictive Content-Security-Policy to reduce XSS impact.',
      })
    }
    if (headers['access-control-allow-origin'] === '*') {
      issues.push({
        id: 'cors-wildcard',
        severity: 'medium',
        title: 'Wildcard CORS origin',
        details: 'Access-Control-Allow-Origin is set to *.',
        recommendation: 'Restrict CORS origins to trusted domains.',
      })
    }
    if (headers.server && /\d/.test(headers.server)) {
      issues.push({
        id: 'server-version-exposed',
        severity: 'low',
        title: 'Server version disclosure',
        details: `Server header leaks version: ${headers.server}`,
        recommendation: 'Remove or normalize server/version disclosure headers.',
      })
    }
  }

  const rawMaterial = [
    `target=${normalized.url.toString()}`,
    `a=${a.join(',')}`,
    `aaaa=${aaaa.join(',')}`,
    `mx=${mx.join(',')}`,
    `ns=${ns.join(',')}`,
    `cname=${cname.join(',')}`,
    headersResult ? JSON.stringify(headersResult.headers) : 'headers=unavailable',
  ].join('\n')

  const deepMatches = engine.detectDeep(rawMaterial, [], 'url').matches
  for (const match of deepMatches) {
    const module = classById.get(match.class)
    if (!module) continue
    issues.push({
      id: `invariant-${module.id}`,
      severity: match.severity,
      title: module.id,
      details: module.description,
      recommendation: remediationForClass(module.id),
      evidence: match.l2Evidence ?? match.proof?.witness,
    })
  }

  const dedupedIssues = dedupeIssues(issues)
  const score = hygieneScore(dedupedIssues)
  const summary = `Hygiene scan for ${normalized.host}: ${dedupedIssues.length} issue(s), score=${score}/100.`
  return { issues: dedupedIssues, score, summary }
}

function dedupeIssues(issues: HygieneIssue[]): HygieneIssue[] {
  const seen = new Set<string>()
  const deduped: HygieneIssue[] = []
  for (const issue of issues) {
    if (seen.has(issue.id)) continue
    seen.add(issue.id)
    deduped.push(issue)
  }
  return deduped
}

function hygieneScore(issues: HygieneIssue[]): number {
  let score = 100
  for (const issue of issues) {
    if (issue.severity === 'critical') score -= 30
    else if (issue.severity === 'high') score -= 20
    else if (issue.severity === 'medium') score -= 10
    else score -= 5
  }
  return Math.max(0, score)
}

async function safeDns<T>(resolver: () => Promise<T>): Promise<T extends string[] ? T : string[]> {
  try {
    return await resolver() as T extends string[] ? T : string[]
  } catch {
    return [] as T extends string[] ? T : string[]
  }
}

async function fetchHeaders(url: URL): Promise<{ status: number; headers: Record<string, string> } | null> {
  const candidates = [url.toString()]
  if (url.protocol === 'https:') {
    const fallback = new URL(url.toString())
    fallback.protocol = 'http:'
    candidates.push(fallback.toString())
  }

  for (const candidate of candidates) {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 6000)
    try {
      const response = await fetch(candidate, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
      })
      clearTimeout(timeout)
      const headers: Record<string, string> = {}
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value
      })
      return { status: response.status, headers }
    } catch {
      clearTimeout(timeout)
    }
  }
  return null
}

function normalizeTarget(target: string): { host: string; url: URL } {
  const trimmed = target.trim()
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  const url = new URL(withProtocol)
  const host = url.hostname.toLowerCase()
  if (!host) {
    throw new McpError(ErrorCode.InvalidParams, 'Invalid target: host is empty')
  }
  return { host, url }
}

function checkTlsCertificate(host: string): Promise<{ valid: boolean; details: string; daysRemaining?: number; validTo?: string }> {
  return new Promise((resolvePromise) => {
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: 6000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate()
          const validTo = typeof cert.valid_to === 'string' ? cert.valid_to : undefined
          const expiry = validTo ? new Date(validTo) : null
          const msRemaining = expiry ? expiry.getTime() - Date.now() : NaN
          const daysRemaining = Number.isFinite(msRemaining) ? Math.floor(msRemaining / (1000 * 60 * 60 * 24)) : undefined
          resolvePromise({
            valid: true,
            details: 'TLS certificate retrieved',
            daysRemaining,
            validTo,
          })
        } catch (error) {
          resolvePromise({
            valid: false,
            details: `TLS certificate parse failed: ${String(error)}`,
          })
        } finally {
          socket.end()
        }
      },
    )

    socket.on('error', (error) => {
      resolvePromise({ valid: false, details: `TLS error: ${error.message}` })
    })
    socket.on('timeout', () => {
      socket.destroy()
      resolvePromise({ valid: false, details: 'TLS timeout' })
    })
  })
}

function parseSpdxExpression(expression: string): string[] {
  return expression
    .replace(/[()]/g, ' ')
    .split(/\s+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0 && !LICENSE_OPERATORS.has(token.toUpperCase()))
}

function invariantClassToScannerCategory(classId: string): CodebaseFinding['category'] | null {
  const module = classById.get(classId)
  if (!module) return null
  if (module.category === 'sqli') return 'sqli'
  if (module.category === 'xss') return 'xss'
  if (module.category === 'cmdi') return 'command_injection'
  if (module.category === 'path_traversal') return 'path_traversal'
  if (module.category === 'ssrf') return 'ssrf'
  if (module.category === 'auth') return 'auth'
  return null
}

function languageToExtension(language: 'js' | 'ts' | 'python' | 'go'): string {
  if (language === 'ts') return '.ts'
  if (language === 'python') return '.py'
  if (language === 'go') return '.go'
  return '.js'
}

function createUnifiedDiff(original: string, fixed: string): string {
  if (original === fixed) return 'No changes generated.'
  const before = original.split(/\r?\n/)
  const after = fixed.split(/\r?\n/)
  const lines: string[] = ['--- original', '+++ fixed']
  lines.push(`@@ -1,${before.length} +1,${after.length} @@`)

  const maxLength = Math.max(before.length, after.length)
  for (let index = 0; index < maxLength; index++) {
    const left = before[index]
    const right = after[index]
    if (left === right) continue
    if (left !== undefined) lines.push(`-${left}`)
    if (right !== undefined) lines.push(`+${right}`)
  }
  return lines.join('\n')
}

function collectScannableFiles(root: string, excludes: string[]): string[] {
  const output: string[] = []
  walkDirectory(root, root, excludes, output)
  return output
}

function walkDirectory(root: string, currentDir: string, excludes: string[], output: string[]): void {
  const entries = readdirSync(currentDir, { withFileTypes: true })
  for (const entry of entries) {
    const fullPath = join(currentDir, entry.name)
    const relPath = relative(root, fullPath)
    if (isExcludedPath(entry.name, relPath, excludes)) {
      continue
    }
    if (entry.isDirectory()) {
      walkDirectory(root, fullPath, excludes, output)
      continue
    }
    const extension = extname(entry.name).toLowerCase()
    if (DEFAULT_SCANNER_EXTENSIONS.includes(extension)) {
      output.push(fullPath)
    }
  }
}

function isExcludedPath(entryName: string, relPath: string, excludes: string[]): boolean {
  return excludes.some((pattern) => {
    const trimmed = pattern.trim()
    if (trimmed.length === 0) return false
    return entryName === trimmed || relPath.includes(trimmed) || relPath.split(/[\\/]/).includes(trimmed)
  })
}

async function emitProgress(extra: ToolExtra, progress: number, total: number, message: string): Promise<void> {
  if (extra._meta?.progressToken === undefined) return
  await extra.sendNotification({
    method: 'notifications/progress',
    params: {
      progressToken: extra._meta.progressToken,
      progress,
      total,
      message,
    },
  })
}

function severityRank(severity: Severity): number {
  if (severity === 'critical') return 4
  if (severity === 'high') return 3
  if (severity === 'medium') return 2
  return 1
}

function clampConfidence(value: number): number {
  if (!Number.isFinite(value)) return 0
  if (value < 0) return 0
  if (value > 1) return 1
  return value
}
