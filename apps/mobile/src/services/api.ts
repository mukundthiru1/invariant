import { Alert, AlertSeverity, HygieneReport, SensorStats } from '../types';

const TIMEOUT_MS = 10000;

function withTimeout(ms: number): AbortController {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller;
}

function normalizeSeverity(value: unknown): AlertSeverity {
  if (typeof value !== 'string') {
    return 'Medium';
  }

  const normalized = value.toLowerCase();
  if (normalized === 'critical') {
    return 'Critical';
  }
  if (normalized === 'high') {
    return 'High';
  }
  if (normalized === 'medium') {
    return 'Medium';
  }
  return 'Low';
}

async function request<T>(url: string, apiKey: string): Promise<T | null> {
  try {
    const controller = withTimeout(TIMEOUT_MS);
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/json',
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      return null;
    }

    const data: unknown = await response.json();
    return data as T;
  } catch {
    return null;
  }
}

export async function getSensorStats(sensorUrl: string, apiKey: string): Promise<SensorStats | null> {
  const data = await request<Partial<SensorStats>>(`${sensorUrl.replace(/\/$/, '')}/stats`, apiKey);
  if (!data) {
    return null;
  }

  return {
    attacksBlocked: typeof data.attacksBlocked === 'number' ? data.attacksBlocked : 0,
    activeSensors: typeof data.activeSensors === 'number' ? data.activeSensors : 0,
  };
}

export async function getAlerts(sensorUrl: string, apiKey: string, limit: number): Promise<Alert[] | null> {
  const data = await request<unknown>(
    `${sensorUrl.replace(/\/$/, '')}/alerts?limit=${encodeURIComponent(limit.toString())}`,
    apiKey
  );

  if (!data || !Array.isArray(data)) {
    return null;
  }

  return data.map((raw, index) => {
    const item = raw as Record<string, unknown>;
    return {
      id: typeof item.id === 'string' ? item.id : `${index}-${Date.now()}`,
      severity: normalizeSeverity(item.severity),
      attackClass: typeof item.attackClass === 'string' ? item.attackClass : 'Unknown',
      sourceIp: typeof item.sourceIp === 'string' ? item.sourceIp : '0.0.0.0',
      timestamp: typeof item.timestamp === 'string' ? item.timestamp : new Date().toISOString(),
      mitreTechnique: typeof item.mitreTechnique === 'string' ? item.mitreTechnique : 'Unknown',
      recommendedAction:
        typeof item.recommendedAction === 'string' ? item.recommendedAction : 'Investigate this activity.',
      details: typeof item.details === 'object' && item.details !== null ? (item.details as Record<string, unknown>) : {},
    };
  });
}

export async function getHygieneScore(sensorUrl: string, apiKey: string): Promise<HygieneReport | null> {
  const data = await request<Partial<HygieneReport>>(`${sensorUrl.replace(/\/$/, '')}/hygiene`, apiKey);
  if (!data) {
    return null;
  }

  return {
    score: typeof data.score === 'number' ? data.score : 0,
    grade: typeof data.grade === 'string' ? data.grade : 'N/A',
    updatedAt: typeof data.updatedAt === 'string' ? data.updatedAt : new Date().toISOString(),
  };
}
