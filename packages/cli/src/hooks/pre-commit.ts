import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'

export function generatePreCommitHook(): string {
    return `#!/usr/bin/env bash
set -euo pipefail

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
  echo "[invariant] No staged files to scan."
  exit 0
fi

FILTERED_FILES=""
while IFS= read -r FILE; do
  case "$FILE" in
    *.ts|*.tsx|*.js|*.jsx)
      FILTERED_FILES+="$FILE"$'\n'
      ;;
  esac
done <<< "$STAGED_FILES"

if [ -z "$FILTERED_FILES" ]; then
  echo "[invariant] No staged .ts/.tsx/.js/.jsx files to scan."
  exit 0
fi

TMP_DIR=$(mktemp -d)
REPORT_FILE="$TMP_DIR/invariant-codescan-report.txt"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

while IFS= read -r FILE; do
  [ -z "$FILE" ] && continue

  mkdir -p "$TMP_DIR/$(dirname "$FILE")"

  if ! git show ":$FILE" > "$TMP_DIR/$FILE"; then
    echo "[invariant] Failed to read staged file: $FILE"
    exit 1
  fi
done <<< "$FILTERED_FILES"

echo "[invariant] Scanning staged files with Invariant code scanner..."

if ! (cd "$TMP_DIR" && npx @santh/invariant codescan > "$REPORT_FILE" 2>&1); then
  cat "$REPORT_FILE"
  echo "[invariant] Code scanner execution failed."
  exit 1
fi

cat "$REPORT_FILE"

CRITICAL_COUNT=$(grep -Eoc '\\[CRITICAL\\]' "$REPORT_FILE" || true)
HIGH_COUNT=$(grep -Eoc '\\[HIGH\\]' "$REPORT_FILE" || true)
TOTAL_BLOCKING=$((CRITICAL_COUNT + HIGH_COUNT))

echo "[invariant] Summary: critical=$CRITICAL_COUNT high=$HIGH_COUNT blocking=$TOTAL_BLOCKING"

if [ "$TOTAL_BLOCKING" -gt 0 ]; then
  echo "[invariant] Commit blocked due to critical/high findings in staged files."
  exit 1
fi

echo "[invariant] Pre-commit scan passed."
exit 0
`
}

export function installPreCommitHook(projectDir: string): void {
    const dotGitPath = join(projectDir, '.git')
    if (!existsSync(dotGitPath)) {
        throw new Error(`No .git directory found in ${projectDir}`)
    }

    const gitDir = resolveGitDir(projectDir, dotGitPath)
    const hooksDir = join(gitDir, 'hooks')
    mkdirSync(hooksDir, { recursive: true })

    const hookPath = join(hooksDir, 'pre-commit')
    writeFileSync(hookPath, generatePreCommitHook(), 'utf8')
    chmodSync(hookPath, 0o755)
}

function resolveGitDir(projectDir: string, dotGitPath: string): string {
    const stats = statSync(dotGitPath)
    if (stats.isDirectory()) {
        return dotGitPath
    }

    if (!stats.isFile()) {
        throw new Error(`Unsupported .git entry at ${dotGitPath}`)
    }

    const content = readFileSync(dotGitPath, 'utf8')
    const match = content.match(/^gitdir:\s*(.+)\s*$/im)
    if (!match?.[1]) {
        throw new Error(`Unable to resolve git directory from ${dotGitPath}`)
    }

    const configuredPath = match[1].trim()
    return isAbsolute(configuredPath)
        ? configuredPath
        : resolve(projectDir, configuredPath)
}
