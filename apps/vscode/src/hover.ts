import * as vscode from 'vscode'
import type { ScanFinding } from './scanner'

export class SanthHoverProvider implements vscode.HoverProvider {
  constructor(private readonly getFindings: (uri: vscode.Uri) => readonly ScanFinding[]) {}

  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.ProviderResult<vscode.Hover> {
    const finding = this.getFindings(document.uri).find((candidate) => {
      if (candidate.line !== position.line) {
        return false
      }
      return position.character >= candidate.startColumn && position.character <= candidate.endColumn
    })

    if (!finding) {
      return undefined
    }

    const markdown = new vscode.MarkdownString()
    markdown.isTrusted = false
    markdown.appendMarkdown(`### ${finding.classId}\n`)
    markdown.appendMarkdown(`**Why dangerous:** ${finding.danger}\n\n`)
    markdown.appendMarkdown(`**MITRE technique:** ${finding.mitreTechniques.join(', ') || 'N/A'}\n\n`)
    markdown.appendMarkdown(`**Remediation:** ${finding.remediation}`)

    const range = new vscode.Range(
      new vscode.Position(finding.line, finding.startColumn),
      new vscode.Position(finding.line, finding.endColumn),
    )

    return new vscode.Hover(markdown, range)
  }
}
