import { NativeStackScreenProps } from '@react-navigation/native-stack';
import { CameraView, BarcodeScanningResult, useCameraPermissions } from 'expo-camera';
import * as SecureStore from 'expo-secure-store';
import { useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { RootStackParamList } from '../navigation/AppNavigator';
import { StoredCredentials } from '../types';

const CREDENTIALS_KEY = 'santh.credentials';

type Props = NativeStackScreenProps<RootStackParamList, 'Scanner'>;

function parseCredentials(payload: string): StoredCredentials | null {
  try {
    const parsed = JSON.parse(payload) as Partial<StoredCredentials>;
    if (
      typeof parsed.sensorUrl !== 'string' ||
      typeof parsed.sensorId !== 'string' ||
      typeof parsed.apiKey !== 'string'
    ) {
      return null;
    }

    const url = new URL(parsed.sensorUrl);
    if (!url.protocol.startsWith('http')) {
      return null;
    }

    return {
      sensorUrl: parsed.sensorUrl,
      sensorId: parsed.sensorId,
      apiKey: parsed.apiKey,
    };
  } catch {
    return null;
  }
}

export function ScannerScreen({ navigation }: Props) {
  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  const onScan = async (result: BarcodeScanningResult): Promise<void> => {
    if (scanned) {
      return;
    }

    setScanned(true);
    const credentials = parseCredentials(result.data);

    if (!credentials) {
      setError('Invalid QR code format.');
      setScanned(false);
      return;
    }

    await SecureStore.setItemAsync(CREDENTIALS_KEY, JSON.stringify(credentials));
    navigation.reset({ index: 0, routes: [{ name: 'MainTabs' }] });
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
        <Text style={styles.text}>Camera permission is required to pair your sensor.</Text>
        <Pressable style={styles.button} onPress={() => void requestPermission()}>
          <Text style={styles.buttonText}>Grant Permission</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <CameraView
        style={styles.camera}
        onBarcodeScanned={onScan}
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
      />
      <View style={styles.overlay}>
        <Text style={styles.instruction}>Point camera at the QR code in your Santh dashboard</Text>
        {!!error && <Text style={styles.error}>{error}</Text>}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#000000' },
  camera: { flex: 1 },
  overlay: {
    position: 'absolute',
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0,0,0,0.7)',
    paddingHorizontal: 16,
    paddingVertical: 24,
    gap: 8,
  },
  instruction: { color: '#FFFFFF', textAlign: 'center', fontSize: 15 },
  error: { color: '#FF453A', textAlign: 'center' },
  centered: { flex: 1, backgroundColor: '#000000', alignItems: 'center', justifyContent: 'center', padding: 20, gap: 12 },
  text: { color: '#FFFFFF', textAlign: 'center' },
  button: { paddingHorizontal: 16, paddingVertical: 10, borderRadius: 10, borderColor: '#FFFFFF', borderWidth: 1 },
  buttonText: { color: '#FFFFFF', fontWeight: '700' },
});
