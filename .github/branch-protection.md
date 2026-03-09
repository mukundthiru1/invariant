# Branch Protection for `main`

Configure a branch protection rule for `main` with these settings:

1. Require a pull request before merging.
2. Require approvals (team policy decides the minimum).
3. Require status checks to pass before merging.
4. Require branches to be up to date before merging.
5. Restrict force pushes and deletions.

Required status checks from CI:

- `test (Node 20)`
- `test (Node 22)`
- `security-audit`
- `type-check`
- `bundle-size`
- `codex-review` (required only for pull requests where this job runs)

Notes:

- `security-audit` and `bundle-size` depend on all matrix test jobs passing.
- `codex-review` runs only on `pull_request` events and requires `OPENAI_API_KEY` in repository secrets.
