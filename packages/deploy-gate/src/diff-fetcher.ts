export interface GithubDiffRequest {
  owner: string
  repo: string
  base: string
  head: string
  token?: string
}

export async function fetchGithubDiff(
  owner: string,
  repo: string,
  base: string,
  head: string,
  token?: string,
): Promise<string> {
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3.diff',
    'User-Agent': 'santh-deploy-gate',
  }

  if (token && token.length > 0) {
    headers.Authorization = `Bearer ${token}`
  }

  const response = await fetch(url, { method: 'GET', headers })
  if (!response.ok) {
    throw new Error(`GitHub diff fetch failed (${response.status}): ${await response.text()}`)
  }

  return response.text()
}

export function parseDiff(patch: string): string[] {
  const lines = patch.split(/\r?\n/)
  const added: string[] = []

  for (const line of lines) {
    if (!line.startsWith('+')) continue
    if (line.startsWith('+++ ')) continue
    added.push(line.slice(1))
  }

  return added
}

export async function fetchGithubDiffFromRequest(request: GithubDiffRequest): Promise<string[]> {
  const patch = await fetchGithubDiff(request.owner, request.repo, request.base, request.head, request.token)
  return parseDiff(patch)
}
