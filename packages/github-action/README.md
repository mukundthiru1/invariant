# Invariant Security Scan Action

Use this action to run an Invariant codebase scan and surface findings as GitHub annotations and PR comments.

## Usage

```yaml
- uses: santh-io/invariant-scan@v1
  with:
    path: './src'
    severity-threshold: 'medium'
```

## Inputs

- `path` — Path to scan. Default: `.`
- `severity-threshold` — Minimum severity to fail the action. Default: `high`
- `fail-on-findings` — Fail the job when findings exceed threshold. Default: `true`
- `extensions` — File extensions to include. Default: `.ts,.js,.tsx,.jsx`
- `exclude` — Directories/files to skip. Default: `node_modules,.git,dist,build`

## Outputs

- `findings-count`
- `critical-count`
- `high-count`
