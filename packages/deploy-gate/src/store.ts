export type DeployStatus = 'pending' | 'approved' | 'denied'

export interface DeployRecord {
  deployId: string
  status: DeployStatus
  findings: unknown
  platform: string
  callbackUrl: string | null
  approverCredentialId: string | null
  createdAt: string
  updatedAt: string
}

export interface StoreEnv {
  DEPLOY_STATE: KVNamespace
}

export async function createDeployRecord(
  env: StoreEnv,
  deployId: string,
  findings: unknown,
  platform: string,
  callbackUrl?: string | null,
): Promise<DeployRecord> {
  const now = new Date().toISOString()
  const record: DeployRecord = {
    deployId,
    status: 'pending',
    findings,
    platform,
    callbackUrl: callbackUrl ?? null,
    approverCredentialId: null,
    createdAt: now,
    updatedAt: now,
  }

  await env.DEPLOY_STATE.put(`deploy:${deployId}`, JSON.stringify(record))
  return record
}

export async function getDeployRecord(env: StoreEnv, deployId: string): Promise<DeployRecord | null> {
  const raw = await env.DEPLOY_STATE.get(`deploy:${deployId}`)
  if (!raw) return null

  try {
    const parsed = JSON.parse(raw) as DeployRecord
    return parsed
  } catch {
    return null
  }
}

export async function approveDeployRecord(
  env: StoreEnv,
  deployId: string,
  approverCredentialId: string,
): Promise<DeployRecord | null> {
  const record = await getDeployRecord(env, deployId)
  if (!record) return null

  const approved: DeployRecord = {
    ...record,
    status: 'approved',
    approverCredentialId,
    updatedAt: new Date().toISOString(),
  }

  await env.DEPLOY_STATE.put(`deploy:${deployId}`, JSON.stringify(approved))
  return approved
}

export async function denyDeployRecord(env: StoreEnv, deployId: string): Promise<DeployRecord | null> {
  const record = await getDeployRecord(env, deployId)
  if (!record) return null

  const denied: DeployRecord = {
    ...record,
    status: 'denied',
    updatedAt: new Date().toISOString(),
  }

  await env.DEPLOY_STATE.put(`deploy:${deployId}`, JSON.stringify(denied))
  return denied
}
