export type AuditEventType =
  | 'commit'
  | 'deploy'
  | 'approval'
  | 'block'
  | 'tamper_detected'
  | 'rollback'

export type AuditEvent = {
  id?: number
  event_type: AuditEventType
  commit_hash?: string | null
  tree_hash?: string | null
  author_email?: string | null
  ts?: string
  deploy_id?: string | null
  approved_by?: string | null
  customer_id: string
  platform?: string | null
  findings_json?: string | null
  hmac: string
}

export type EventForSignature = Omit<AuditEvent, 'id' | 'hmac'>

export type TamperReport = {
  reason: 'forced_push' | 'missing_commits' | 'suspected_rebase'
  forced: boolean
  missing_commits: string[]
  before?: string
  after?: string
  repository?: string
  customer_id?: string
}

export type MissingCommits = {
  commit_hash: string
}

export type DbRowResult<T = Record<string, unknown>> = {
  rows: T[]
}

export type DbClient = {
  query<T = Record<string, unknown>>(text: string, params?: unknown[]): Promise<DbRowResult<T>>
}

export type RollbackPlatform = 'vercel' | 'cloudflare_pages'
