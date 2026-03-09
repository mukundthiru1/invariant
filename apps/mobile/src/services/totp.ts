import * as SecureStore from 'expo-secure-store';
import { authenticator } from 'otplib';

const TOKEN_PERIOD_SECONDS = 30;
const SENSOR_SECRET_KEY_PREFIX = 'santh.totp.secret.';
const SENSOR_LIST_KEY = 'santh.totp.sensors';

export interface PairedTotpSensor {
  sensorId: string;
  sensorName: string;
  issuer: string;
}

authenticator.options = {
  ...authenticator.options,
  digits: 6,
  step: TOKEN_PERIOD_SECONDS,
};

function getSecretKey(sensorId: string): string {
  return `${SENSOR_SECRET_KEY_PREFIX}${sensorId}`;
}

export function generateSecret(): string {
  return authenticator.generateSecret();
}

export function getToken(secret: string): string {
  return authenticator.generate(secret);
}

export function getTimeRemaining(): number {
  const currentEpochSeconds = Math.floor(Date.now() / 1000);
  return (TOKEN_PERIOD_SECONDS - (currentEpochSeconds % TOKEN_PERIOD_SECONDS)) % TOKEN_PERIOD_SECONDS;
}

export function generateQrUri(secret: string, accountName: string, issuer: string): string {
  return authenticator.keyuri(accountName, issuer, secret);
}

export function verifyToken(secret: string, token: string): boolean {
  const previousOptions = authenticator.options;
  authenticator.options = {
    ...previousOptions,
    window: [1, 1],
  };

  const isValid = authenticator.check(token, secret);
  authenticator.options = previousOptions;
  return isValid;
}

export async function storeSensorSecret(sensorId: string, secret: string): Promise<void> {
  await SecureStore.setItemAsync(getSecretKey(sensorId), secret);
}

export async function getSensorSecret(sensorId: string): Promise<string | null> {
  return SecureStore.getItemAsync(getSecretKey(sensorId));
}

export async function getPairedSensors(): Promise<PairedTotpSensor[]> {
  const raw = await SecureStore.getItemAsync(SENSOR_LIST_KEY);
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter((item): item is PairedTotpSensor => {
      const candidate = item as Partial<PairedTotpSensor>;
      return (
        typeof candidate.sensorId === 'string' &&
        typeof candidate.sensorName === 'string' &&
        typeof candidate.issuer === 'string'
      );
    });
  } catch {
    return [];
  }
}

export async function upsertPairedSensor(sensor: PairedTotpSensor): Promise<void> {
  const sensors = await getPairedSensors();
  const next = sensors.filter((entry) => entry.sensorId !== sensor.sensorId);
  next.push(sensor);
  await SecureStore.setItemAsync(SENSOR_LIST_KEY, JSON.stringify(next));
}
