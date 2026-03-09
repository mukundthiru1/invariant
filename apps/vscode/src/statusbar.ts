import * as vscode from 'vscode'

export function createStatusBarItem(): vscode.StatusBarItem {
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100)
  item.name = 'Santh Security'
  item.tooltip = 'Santh invariant scanner status'
  item.text = 'Santh: Clean'
  item.show()
  return item
}

export function updateStatusBar(item: vscode.StatusBarItem, issueCount: number): void {
  if (issueCount > 0) {
    item.text = `Santh: ${issueCount} issues`
    item.backgroundColor = undefined
    item.color = new vscode.ThemeColor('statusBarItem.warningForeground')
    return
  }

  item.text = 'Santh: Clean'
  item.backgroundColor = undefined
  item.color = undefined
}
