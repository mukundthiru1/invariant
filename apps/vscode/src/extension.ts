import * as vscode from 'vscode'
import { SanthDiagnosticsController, getSettings } from './diagnostics'
import { SanthHoverProvider } from './hover'
import { createStatusBarItem } from './statusbar'
import type { ScanFinding } from './scanner'

const FIX_COMMAND = 'santh.fixFinding'

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection('santh')
  const statusBarItem = createStatusBarItem()
  const controller = new SanthDiagnosticsController(collection, statusBarItem)

  context.subscriptions.push(collection, statusBarItem, controller)
  controller.register(context)

  const selector: vscode.DocumentSelector = [
    { scheme: 'file' },
    { scheme: 'untitled' },
  ]

  const hoverProvider = new SanthHoverProvider((uri) => controller.getFindings(uri))
  const codeLensProvider: vscode.CodeLensProvider<vscode.CodeLens> = {
    onDidChangeCodeLenses: controller.onDidChangeCodeLenses,
    provideCodeLenses<T extends vscode.CodeLens>(document: vscode.TextDocument): T[] {
      const findings = controller.getFindings(document.uri)
      const lenses = findings.map((finding) => {
        const lineRange = new vscode.Range(
          new vscode.Position(finding.line, 0),
          new vscode.Position(finding.line, 0),
        )
        return new vscode.CodeLens(lineRange, {
          command: FIX_COMMAND,
          title: `Santh: [${finding.classId}] detected — Click to fix`,
          arguments: [document.uri, finding.classId, finding.line],
        })
      })
      return lenses as T[]
    },
  }

  const codeActionProvider: vscode.CodeActionProvider = {
    provideCodeActions<T extends vscode.CodeAction>(
      document: vscode.TextDocument,
      _range: vscode.Range | vscode.Selection,
      contextInfo: vscode.CodeActionContext,
    ): T[] {
      const actions: vscode.CodeAction[] = []
      for (const diagnostic of contextInfo.diagnostics) {
        if (diagnostic.source !== 'santh') {
          continue
        }

        const classId = String(diagnostic.code ?? '')
        const line = diagnostic.range.start.line
        const action = new vscode.CodeAction('Fix with Santh', vscode.CodeActionKind.QuickFix)
        action.diagnostics = [diagnostic]
        action.command = {
          command: FIX_COMMAND,
          title: 'Fix with Santh',
          arguments: [document.uri, classId, line],
        }
        action.isPreferred = true
        actions.push(action)
      }

      return actions as T[]
    },
  }

  context.subscriptions.push(
    vscode.languages.registerHoverProvider(selector, hoverProvider),
    vscode.languages.registerCodeLensProvider(selector, codeLensProvider),
    vscode.languages.registerCodeActionsProvider(selector, codeActionProvider, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
    vscode.commands.registerCommand(FIX_COMMAND, async (uri: vscode.Uri, classId: string, line: number) => {
      const settings = getSettings()
      if (!settings.autoFix) {
        void vscode.window.showWarningMessage('Santh auto-fix is disabled in settings (santh.autoFix).')
        return
      }

      const document = await vscode.workspace.openTextDocument(uri)
      const finding = resolveFinding(controller.getFindings(uri), classId, line)
      if (!finding) {
        void vscode.window.showWarningMessage('Santh finding is stale. Re-scan the document and try again.')
        return
      }

      const result = await controller.applyAutoFix(document, finding)
      if (result.applied) {
        void vscode.window.showInformationMessage(result.message)
        await document.save()
        await controller.rescanOpenDocuments()
      } else {
        void vscode.window.showWarningMessage(result.message)
      }
    }),
  )
}

export function deactivate(): void {
  // VS Code disposes context subscriptions.
}

function resolveFinding(findings: readonly ScanFinding[], classId: string, line: number): ScanFinding | undefined {
  return findings.find((finding) => finding.classId === classId && finding.line === line)
}
