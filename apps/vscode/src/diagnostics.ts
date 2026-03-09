import * as vscode from 'vscode'
import { SanthScanner, type ScanFinding, type SeverityThreshold } from './scanner'
import { updateStatusBar } from './statusbar'

const SCAN_DEBOUNCE_MS = 500

const severityToDiagnostic: Record<ScanFinding['severity'], vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Warning,
  medium: vscode.DiagnosticSeverity.Information,
  low: vscode.DiagnosticSeverity.Hint,
  info: vscode.DiagnosticSeverity.Hint,
}

export interface SanthSettings {
  enable: boolean
  threshold: SeverityThreshold
  onType: boolean
  autoFix: boolean
}

export function getSettings(): SanthSettings {
  const config = vscode.workspace.getConfiguration('santh')
  return {
    enable: config.get<boolean>('enable', true),
    threshold: config.get<SeverityThreshold>('severity.threshold', 'medium'),
    onType: config.get<boolean>('scan.onType', false),
    autoFix: config.get<boolean>('autoFix', true),
  }
}

export class SanthDiagnosticsController implements vscode.Disposable {
  private readonly scanner = new SanthScanner()
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>()
  private readonly codeLensEmitter = new vscode.EventEmitter<void>()
  private readonly findingsEmitter = new vscode.EventEmitter<vscode.Uri>()
  private readonly ghostTextDecoration = vscode.window.createTextEditorDecorationType({
    after: {
      contentText: '',
      color: '#D93025',
      margin: '0 0 0 1rem',
    },
  })
  private readonly disposables: vscode.Disposable[] = []

  constructor(
    private readonly collection: vscode.DiagnosticCollection,
    private readonly statusBarItem: vscode.StatusBarItem,
  ) {}

  get onDidChangeCodeLenses(): vscode.Event<void> {
    return this.codeLensEmitter.event
  }

  get onDidChangeFindings(): vscode.Event<vscode.Uri> {
    return this.findingsEmitter.event
  }

  getFindings(uri: vscode.Uri): ScanFinding[] {
    return this.scanner.getFindings(uri)
  }

  async applyAutoFix(document: vscode.TextDocument, finding: ScanFinding): Promise<{ applied: boolean; message: string }> {
    return this.scanner.applyAutoFix(document, finding)
  }

  register(context: vscode.ExtensionContext): void {
    this.disposables.push(
      this.ghostTextDecoration,
      this.codeLensEmitter,
      this.findingsEmitter,
      vscode.workspace.onDidOpenTextDocument((document) => this.scheduleFullScan(document)),
      vscode.workspace.onDidSaveTextDocument((document) => this.scheduleFullScan(document)),
      vscode.workspace.onDidCloseTextDocument((document) => {
        this.clearTimer(document.uri)
        this.collection.delete(document.uri)
        this.scanner.clear(document.uri)
        this.refreshStatusBar()
        this.applyGhostTextToVisibleEditors()
      }),
      vscode.workspace.onDidChangeTextDocument((event) => {
        const settings = getSettings()
        if (!settings.enable || !settings.onType || !shouldScan(event.document)) {
          return
        }
        this.schedulePartialScan(event.document, event.contentChanges)
      }),
      vscode.window.onDidChangeActiveTextEditor(() => {
        this.refreshStatusBar()
        this.applyGhostTextToVisibleEditors()
      }),
      vscode.window.onDidChangeVisibleTextEditors(() => this.applyGhostTextToVisibleEditors()),
      vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration('santh')) {
          void this.rescanOpenDocuments()
        }
      }),
    )

    context.subscriptions.push(this, ...this.disposables)
    void this.rescanOpenDocuments()
  }

  async rescanOpenDocuments(): Promise<void> {
    const settings = getSettings()
    if (!settings.enable) {
      this.collection.clear()
      for (const document of vscode.workspace.textDocuments) {
        this.scanner.clear(document.uri)
      }
      this.refreshStatusBar()
      this.applyGhostTextToVisibleEditors()
      this.codeLensEmitter.fire()
      return
    }

    const targets = vscode.workspace.textDocuments.filter((document) => shouldScan(document))
    await Promise.all(targets.map((document) => this.runFullScan(document)))
    this.refreshStatusBar()
    this.applyGhostTextToVisibleEditors()
    this.codeLensEmitter.fire()
  }

  private scheduleFullScan(document: vscode.TextDocument): void {
    if (!shouldScan(document)) {
      return
    }
    this.schedule(document, () => this.runFullScan(document))
  }

  private schedulePartialScan(
    document: vscode.TextDocument,
    changes: readonly vscode.TextDocumentContentChangeEvent[],
  ): void {
    if (!shouldScan(document)) {
      return
    }
    this.schedule(document, () => this.runPartialScan(document, changes))
  }

  private schedule(document: vscode.TextDocument, task: () => Promise<void>): void {
    const key = document.uri.toString()
    this.clearTimer(document.uri)
    const timer = setTimeout(() => {
      this.timers.delete(key)
      void task()
    }, SCAN_DEBOUNCE_MS)
    this.timers.set(key, timer)
  }

  private clearTimer(uri: vscode.Uri): void {
    const key = uri.toString()
    const timer = this.timers.get(key)
    if (timer) {
      clearTimeout(timer)
      this.timers.delete(key)
    }
  }

  private async runFullScan(document: vscode.TextDocument): Promise<void> {
    const settings = getSettings()
    if (!settings.enable) {
      this.collection.delete(document.uri)
      this.scanner.clear(document.uri)
      this.afterScan(document.uri)
      return
    }

    const findings = await this.scanner.fullScan(document, settings.threshold)
    this.collection.set(document.uri, findingsToDiagnostics(findings))
    this.afterScan(document.uri)
  }

  private async runPartialScan(
    document: vscode.TextDocument,
    changes: readonly vscode.TextDocumentContentChangeEvent[],
  ): Promise<void> {
    const settings = getSettings()
    if (!settings.enable) {
      this.collection.delete(document.uri)
      this.scanner.clear(document.uri)
      this.afterScan(document.uri)
      return
    }

    const findings = await this.scanner.scanChangedRanges(document, changes, settings.threshold)
    this.collection.set(document.uri, findingsToDiagnostics(findings))
    this.afterScan(document.uri)
  }

  private afterScan(uri: vscode.Uri): void {
    this.refreshStatusBar()
    this.applyGhostTextToVisibleEditors()
    this.codeLensEmitter.fire()
    this.findingsEmitter.fire(uri)
  }

  private refreshStatusBar(): void {
    const editor = vscode.window.activeTextEditor
    if (!editor) {
      updateStatusBar(this.statusBarItem, 0)
      return
    }
    updateStatusBar(this.statusBarItem, this.scanner.getFindings(editor.document.uri).length)
  }

  private applyGhostTextToVisibleEditors(): void {
    for (const editor of vscode.window.visibleTextEditors) {
      const findings = this.scanner.getFindings(editor.document.uri)
      const highConfidence = findings.filter((finding) => finding.confidence > 0.9)
      const decorations = highConfidence.map<vscode.DecorationOptions>((finding) => {
        const line = editor.document.lineAt(finding.line)
        const anchor = new vscode.Position(finding.line, line.text.length)
        return {
          range: new vscode.Range(anchor, anchor),
          renderOptions: {
            after: {
              contentText: this.scanner.ghostTextForFinding(finding),
              color: '#D93025',
            },
          },
        }
      })
      editor.setDecorations(this.ghostTextDecoration, decorations)
    }
  }

  dispose(): void {
    for (const [_, timer] of this.timers) {
      clearTimeout(timer)
    }
    this.timers.clear()
    this.disposables.forEach((disposable) => disposable.dispose())
  }
}

function findingsToDiagnostics(findings: readonly ScanFinding[]): vscode.Diagnostic[] {
  return findings.map((finding) => {
    const range = new vscode.Range(
      new vscode.Position(finding.line, finding.startColumn),
      new vscode.Position(finding.line, finding.endColumn),
    )

    const diagnostic = new vscode.Diagnostic(
      range,
      `[${finding.classId}] ${finding.message}`,
      severityToDiagnostic[finding.severity],
    )
    diagnostic.source = 'santh'
    diagnostic.code = finding.classId
    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(vscode.Uri.parse('santh://invariant-engine'), new vscode.Range(0, 0, 0, 0)),
        `MITRE: ${finding.mitreTechniques.join(', ') || 'N/A'} | Remediation: ${finding.remediation}`,
      ),
    ]

    return diagnostic
  })
}

function shouldScan(document: vscode.TextDocument): boolean {
  return document.uri.scheme === 'file' || document.uri.scheme === 'untitled'
}
