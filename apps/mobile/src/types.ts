export type AlertSeverity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface StoredCredentials {
  sensorUrl: string;
  sensorId: string;
  apiKey: string;
}

export interface SensorStats {
  attacksBlocked: number;
  activeSensors: number;
}

export interface Alert {
  id: string;
  severity: AlertSeverity;
  attackClass: string;
  sourceIp: string;
  timestamp: string;
  mitreTechnique: string;
  recommendedAction: string;
  details: Record<string, unknown>;
}

export interface HygieneReport {
  score: number;
  grade: string;
  updatedAt: string;
}
