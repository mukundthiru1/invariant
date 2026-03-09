import { NativeStackScreenProps } from '@react-navigation/native-stack';
import { BarcodeScanningResult, CameraView, useCameraPermissions } from 'expo-camera';
import { useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { RootStackParamList } from '../navigation/AppNavigator';
import { storeSensorSecret, upsertPairedSensor } from '../services/totp';

type Props = NativeStackScreenProps<RootStackParamList, 'Pair'>;

interface ParsedTotpPayload {
  sensorId: string;
  sensorName: string;
  issuer: string;
  secret: string;
}

function parseOtpauthUri(value: string): ParsedTotpPayload | null {
  try {
    const uri = new URL(value);
    if (uri.protocol !== 'otpauth:' || uri.hostname.toLowerCase() !== 'totp') {
      return null;
    }

    const rawSecret = uri.searchParams.get('secret');
    if (!rawSecret) {
      return null;
    }

    const label = decodeURIComponent(uri.pathname.replace(/^\//, ''));
    const separatorIndex = label.indexOf(':');
    const labelIssuer = separatorIndex >= 0 ? label.slice(0, separatorIndex).trim() : '';
    const labelAccount = separatorIndex >= 0 ? label.slice(separatorIndex + 1).trim() : label.trim();
    const issuer = (uri.searchParams.get('issuer') ?? labelIssuer ?? '').trim() || 'Santh';
    const sensorName = labelAccount || 'Sensor';
    const sensorId = encodeURIComponent(`${issuer}:${sensorName}`.toLowerCase());

    return {
      sensorId,
      sensorName,
      issuer,
      secret: rawSecret.trim().replace(/\s+/g, ''),
    };
  } catch {
    return null;
  }
}

export function PairScreen({ navigation }: Props) {
  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [pendingPair, setPendingPair] = useState<ParsedTotpPayload | null>(null);
  const [pairing, setPairing] = useState<boolean>(false);

  const onScan = (result: BarcodeScanningResult): void => {
    if (scanned || pendingPair) {
      return;
    }

    const payload = parseOtpauthUri(result.data);
    if (!payload) {
      setError('Unsupported QR format. Scan a valid TOTP setup code.');
      return;
    }

    setError('');
    setScanned(true);
    setPendingPair(payload);
  };

  const confirmPair = async (): Promise<void> => {
    if (!pendingPair || pairing) {
      return;
    }

    setPairing(true);
    await storeSensorSecret(pendingPair.sensorId, pendingPair.secret);
    await upsertPairedSensor({
      sensorId: pendingPair.sensorId,
      sensorName: pendingPair.sensorName,
      issuer: pendingPair.issuer,
    });
    setPairing(false);
    navigation.goBack();
  };

  if (!permission) {
    return (
      <View style={styles.centered}>
        <Text style={styles.text}>Checking camera permission...</Text>
      </View>
    );
  }

  if (!permission.granted) {
    return (
      <View style={styles.centered}>
        <Text style={styles.text}>Camera access is required to pair a sensor authenticator.</Text>
        <Pressable style={styles.button} onPress={() => void requestPermission()}>
          <Text style={styles.buttonText}>Grant Permission</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {!pendingPair ? (
        <>
          <CameraView
            style={styles.camera}
            onBarcodeScanned={onScan}
            barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
          />
          <View style={styles.overlay}>
            <Text style={styles.overlayText}>Scan the TOTP QR code from your Santh sensor onboarding flow.</Text>
            {!!error && <Text style={styles.error}>{error}</Text>}
          </View>
        </>
      ) : (
        <View style={styles.confirmContainer}>
          <Text style={styles.title}>Pair with {pendingPair.sensorName}?</Text>
          <Text style={styles.subtitle}>Issuer: {pendingPair.issuer}</Text>

          <Pressable style={styles.confirmButton} onPress={() => void confirmPair()} disabled={pairing}>
            <Text style={styles.confirmButtonText}>{pairing ? 'Pairing...' : 'Confirm Pairing'}</Text>
          </Pressable>

          <Pressable
            style={styles.secondaryButton}
            onPress={() => {
              setPendingPair(null);
              setScanned(false);
            }}
          >
            <Text style={styles.secondaryButtonText}>Scan Again</Text>
          </Pressable>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#FFFFFF' },
  camera: { flex: 1 },
  overlay: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    paddingHorizontal: 20,
    paddingVertical: 22,
    backgroundColor: 'rgba(255,255,255,0.92)',
    gap: 8,
  },
  overlayText: { color: '#1D1D1F', textAlign: 'center', fontSize: 15, lineHeight: 20 },
  error: { color: '#C1272D', textAlign: 'center', fontSize: 13 },
  confirmContainer: {
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: 24,
    gap: 12,
    backgroundColor: '#FFFFFF',
  },
  title: { color: '#1D1D1F', fontSize: 24, fontWeight: '800', textAlign: 'center' },
  subtitle: { color: '#4E5968', fontSize: 15, textAlign: 'center', marginBottom: 8 },
  centered: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 24,
    backgroundColor: '#FFFFFF',
    gap: 12,
  },
  text: { color: '#1D1D1F', textAlign: 'center' },
  button: {
    borderRadius: 12,
    borderWidth: 1,
    borderColor: '#0B4A8F',
    paddingVertical: 10,
    paddingHorizontal: 16,
  },
  buttonText: { color: '#0B4A8F', fontWeight: '700' },
  confirmButton: {
    borderRadius: 12,
    backgroundColor: '#0B4A8F',
    paddingVertical: 14,
  },
  confirmButtonText: { color: '#FFFFFF', textAlign: 'center', fontWeight: '700', fontSize: 16 },
  secondaryButton: {
    borderRadius: 12,
    borderWidth: 1,
    borderColor: '#0B4A8F',
    paddingVertical: 14,
  },
  secondaryButtonText: { color: '#0B4A8F', textAlign: 'center', fontWeight: '700', fontSize: 16 },
});
