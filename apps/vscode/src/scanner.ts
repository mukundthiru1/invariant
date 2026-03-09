import * as vscode from 'vscode'
import type { InvariantMatch, Severity } from '@santh/invariant-engine'

export type SeverityThreshold = 'low' | 'medium' | 'high' | 'critical'

interface InvariantEngineLike {
  detectDeep(input: string, staticRuleIds: string[], environment?: string): {
    matches: InvariantMatch[]
  }
}

interface MitreMapperLike {
  getTechniques(cls: string): Array<{ id: string }>
}

interface AutoFixerLike {
  generateFixes(findings: AutoFixScanFinding[]): Array<{
    file: string
    line: number
    category: string
    description: string
    original: string
    fixed: string
    applied: boolean
  }>
  applyFixes(fixes: Array<{
    file: string
    line: number
    category: string
    description: string
    original: string
    fixed: string
    applied: boolean
  }>): Array<{ applied: boolean }>
}

interface EngineBindings {
  InvariantEngine: new () => InvariantEngineLike
  MitreMapper: new () => MitreMapperLike
  AutoFixer?: new (rootDir: string) => AutoFixerLike
}

const severityOrder: Record<SeverityThreshold | 'info', number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const rangeHints: Array<{ prefix: string; pattern: RegExp }> = [
  { prefix: 'sql_', pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE|UNION|WHERE|FROM|DROP|ALTER|db\.query|pool\.query|sequelize\.query)\b/i },
  { prefix: 'xss_', pattern: /\b(?:innerHTML|outerHTML|document\.write|eval|Function|onerror|onload|<script)\b/i },
  { prefix: 'cmd_', pattern: /\b(?:exec|spawn|child_process|system\(|\/bin\/sh|`.+`)\b/i },
  { prefix: 'path_', pattern: /\b(?:path\.join|path\.resolve|\.\.\/|%2e%2e%2f)\b/i },
  { prefix: 'ssrf_', pattern: /\b(?:fetch\(|axios\.|request\(|http:\/\/|https:\/\/|localhost|169\.254\.169\.254)\b/i },
  { prefix: 'proto_', pattern: /\b(?:__proto__|prototype|constructor\.)\b/i },
  { prefix: 'auth_', pattern: /\b(?:jwt|token|authorization|bearer|session|oauth)\b/i },
]

export interface ScanFinding {
  id: string
  classId: string
  severity: Severity | 'info'
  confidence: number
  message: string
  danger: string
  remediation: string
  mitreTechniques: string[]
  line: number
  startColumn: number
  endColumn: number
}

let bindingsPromise: Promise<EngineBindings> | undefined

async function loadEngineBindings(): Promise<EngineBindings> {
  if (!bindingsPromise) {
    bindingsPromise = (0, eval)(`import('@santh/invariant-engine')`).then((module: unknown) => module as EngineBindings)
  }
  const bindings = await bindingsPromise
  if (!bindings) {
    throw new Error('Failed to load @santh/invariant-engine bindings.')
  }
  return bindings
}

function normalizeSeverity(severity: Severity): Severity | 'info' {
  if (severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low') {
    return severity
  }
  return 'info'
}

function passesThreshold(severity: Severity | 'info', threshold: SeverityThreshold): boolean {
  return severityOrder[severity] >= severityOrder[threshold]
}

function classToCategory(classId: string): AutoFixScanFinding['category'] {
  if (classId.startsWith('sql_')) {
    return 'sqli'
  }
  if (classId.startsWith('xss_')) {
    return 'xss'
  }
  if (classId.startsWith('cmd_')) {
    return 'command_injection'
  }
  if (classId.startsWith('path_')) {
    return 'path_traversal'
  }
  if (classId.startsWith('ssrf_')) {
    return 'ssrf'
  }
  return 'auth'
}

interface AutoFixScanFinding {
  file: string
  line: number
  column: number
  category: 'sqli' | 'xss' | 'command_injection' | 'path_traversal' | 'ssrf' | 'auth'
  sink: string
  snippet: string
  severity: Severity
  suggestion: string
}

function remediationForClass(classId: string): string {
  if (classId.startsWith('sql_')) {
    return 'Use parameterized queries and avoid SQL string interpolation.'
  }
  if (classId.startsWith('xss_')) {
    return 'Encode or sanitize untrusted output before rendering in HTML contexts.'
  }
  if (classId.startsWith('cmd_')) {
    return 'Avoid shell execution with untrusted input; use safe process APIs with explicit args.'
  }
  if (classId.startsWith('path_')) {
    return 'Canonicalize and validate user-provided paths against an allowlisted base directory.'
  }
  if (classId.startsWith('ssrf_')) {
    return 'Restrict outbound requests to allowlisted hosts/protocols and block internal metadata ranges.'
  }
  if (classId.startsWith('proto_')) {
    return 'Block dangerous keys like __proto__, prototype, and constructor when merging objects.'
  }
  return 'Harden auth/session handling with strict token validation and secure defaults.'
}

function ghostTextForClass(classId: string): string {
  void classId
  return '⚠ SQL injection — use parameterized queries'
}

function inferColumns(lineText: string, classId: string): { start: number; end: number } {
  for (const hint of rangeHints) {
    if (!classId.startsWith(hint.prefix)) {
      continue
    }
    const hit = hint.pattern.exec(lineText)
    if (hit && typeof hit.index === 'number') {
      return {
        start: hit.index,
        end: Math.max(hit.index + hit[0].length, hit.index + 1),
      }
    }
  }

  const firstNonWhitespace = lineText.search(/\S/)
  const start = firstNonWhitespace >= 0 ? firstNonWhitespace : 0
  const end = Math.max(lineText.length, start + 1)
  return { start, end }
}

function uniqueSortedRanges(changes: readonly vscode.TextDocumentContentChangeEvent[]): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = []
  for (const change of changes) {
    const start = Math.max(0, change.range.start.line)
    const end = Math.max(start, change.range.end.line + change.text.split(/\r?\n/).length - 1)
    ranges.push({ start, end })
  }

  ranges.sort((left, right) => left.start - right.start)
  const merged: Array<{ start: number; end: number }> = []
  for (const candidate of ranges) {
    const last = merged[merged.length - 1]
    if (!last || candidate.start > last.end + 1) {
      merged.push({ ...candidate })
      continue
    }
    last.end = Math.max(last.end, candidate.end)
  }
  return merged
}

function overlaps(line: number, ranges: readonly { start: number; end: number }[]): boolean {
  return ranges.some((range) => line >= range.start && line <= range.end)
}

export class SanthScanner {
  private readonly findingsByUri = new Map<string, ScanFinding[]>()
  private engine: InvariantEngineLike | undefined
  private mitreMapper: MitreMapperLike | undefined

  async fullScan(document: vscode.TextDocument, threshold: SeverityThreshold): Promise<ScanFinding[]> {
    const engine = await this.getEngine()
    const deep = engine.detectDeep(document.getText(), [])
    const classes = new Set(
      deep.matches
        .filter((match) => passesThreshold(normalizeSeverity(match.severity), threshold))
        .map((match) => match.class),
    )

    const findings =
      classes.size === 0
        ? []
        : await this.scanLineRanges(document, [{ start: 0, end: Math.max(0, document.lineCount - 1) }], threshold, classes)

    this.setFindings(document.uri, findings)
    return findings
  }

  async scanChangedRanges(
    document: vscode.TextDocument,
    changes: readonly vscode.TextDocumentContentChangeEvent[],
    threshold: SeverityThreshold,
  ): Promise<ScanFinding[]> {
    const ranges = uniqueSortedRanges(changes)
    if (ranges.length === 0) {
      return this.getFindings(document.uri)
    }

    const existing = this.getFindings(document.uri)
    const retained = existing.filter((finding) => !overlaps(finding.line, ranges))
    const rescanned = await this.scanLineRanges(document, ranges, threshold)
    const merged = [...retained, ...rescanned]
    this.setFindings(document.uri, merged)
    return merged
  }

  getFindings(uri: vscode.Uri): ScanFinding[] {
    return this.findingsByUri.get(uri.toString()) ?? []
  }

  clear(uri: vscode.Uri): void {
    this.findingsByUri.delete(uri.toString())
  }

  ghostTextForFinding(finding: ScanFinding): string {
    return ghostTextForClass(finding.classId)
  }

  async applyAutoFix(document: vscode.TextDocument, finding: ScanFinding): Promise<{ applied: boolean; message: string }> {
    if (vscode.env.uiKind === vscode.UIKind.Web) {
      return { applied: false, message: 'Santh auto-fix is not available in web extension host.' }
    }

    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri)
    if (!workspaceFolder) {
      return { applied: false, message: 'Open a workspace folder to run Santh auto-fix.' }
    }

    const bindings = await loadEngineBindings()
    if (!bindings.AutoFixer) {
      return { applied: false, message: 'Auto-fixer is not available from the engine module.' }
    }

    const fixer = new bindings.AutoFixer(workspaceFolder.uri.fsPath)
    const lineText = document.lineAt(finding.line).text

    const engineFinding: AutoFixScanFinding = {
      file: document.uri.fsPath,
      line: finding.line + 1,
      column: finding.startColumn + 1,
      category: classToCategory(finding.classId),
      sink: finding.classId,
      snippet: lineText,
      severity: finding.severity === 'info' ? 'low' : finding.severity,
      suggestion: finding.remediation,
    }

    const fixes = fixer.generateFixes([engineFinding])
    if (fixes.length === 0) {
      return { applied: false, message: 'No auto-fix could be generated for this finding.' }
    }

    const applied = fixer.applyFixes(fixes)
    if (!applied.some((entry) => entry.applied)) {
      return { applied: false, message: 'Santh could not apply an auto-fix for this finding.' }
    }

    return { applied: true, message: `Santh auto-fix applied for ${finding.classId}.` }
  }

  private setFindings(uri: vscode.Uri, findings: ScanFinding[]): void {
    const deduped = new Map<string, ScanFinding>()
    for (const finding of findings) {
      deduped.set(finding.id, finding)
    }
    this.findingsByUri.set(uri.toString(), [...deduped.values()].sort((left, right) => left.line - right.line || left.startColumn - right.startColumn))
  }

  private async scanLineRanges(
    document: vscode.TextDocument,
    ranges: readonly { start: number; end: number }[],
    threshold: SeverityThreshold,
    classAllowList?: ReadonlySet<string>,
  ): Promise<ScanFinding[]> {
    const engine = await this.getEngine()
    const mapper = await this.getMitreMapper()
    const findings: ScanFinding[] = []

    for (const range of ranges) {
      for (let lineNumber = range.start; lineNumber <= range.end && lineNumber < document.lineCount; lineNumber++) {
        const textLine = document.lineAt(lineNumber)
        if (!textLine.text.trim()) {
          continue
        }

        const deep = engine.detectDeep(textLine.text, [])
        for (const match of deep.matches) {
          const severity = normalizeSeverity(match.severity)
          if (!passesThreshold(severity, threshold)) {
            continue
          }
          if (classAllowList && !classAllowList.has(match.class)) {
            continue
          }

          const columns = inferColumns(textLine.text, match.class)
          const mitreTechniques = mapper.getTechniques(match.class).map((technique) => technique.id)
          const remediation = remediationForClass(match.class)

          findings.push({
            id: `${document.uri.toString()}:${lineNumber}:${columns.start}:${match.class}`,
            classId: match.class,
            severity,
            confidence: match.confidence,
            message: match.description,
            danger: match.description,
            remediation,
            mitreTechniques,
            line: lineNumber,
            startColumn: columns.start,
            endColumn: columns.end,
          })
        }
      }
    }

    return findings
  }

  private async getEngine(): Promise<InvariantEngineLike> {
    if (!this.engine) {
      const bindings = await loadEngineBindings()
      this.engine = new bindings.InvariantEngine()
    }
    return this.engine
  }

  private async getMitreMapper(): Promise<MitreMapperLike> {
    if (!this.mitreMapper) {
      const bindings = await loadEngineBindings()
      this.mitreMapper = new bindings.MitreMapper()
    }
    return this.mitreMapper
  }
}
