import { Ionicons } from '@expo/vector-icons';
import { BottomTabScreenProps } from '@react-navigation/bottom-tabs';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { useFocusEffect } from '@react-navigation/native';
import * as Clipboard from 'expo-clipboard';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Animated,
  Easing,
  FlatList,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { RootStackParamList, TabParamList } from '../navigation/AppNavigator';
import {
  getPairedSensors,
  getSensorSecret,
  getTimeRemaining,
  getToken,
  PairedTotpSensor,
} from '../services/totp';

type Props = BottomTabScreenProps<TabParamList, 'Authenticator'>;

interface SensorCodeEntry extends PairedTotpSensor {
  code: string;
}

interface CountdownRingProps {
  progress: Animated.Value;
  remaining: number;
  size?: number;
  strokeWidth?: number;
}

function formatCode(code: string): string {
  if (code.length !== 6) {
    return code;
  }
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

function CountdownRing({ progress, remaining, size = 60, strokeWidth = 5 }: CountdownRingProps) {
  const rightRotation = progress.interpolate({
    inputRange: [0, 0.5, 1],
    outputRange: ['0deg', '180deg', '180deg'],
  });

  const leftRotation = progress.interpolate({
    inputRange: [0, 0.5, 1],
    outputRange: ['0deg', '0deg', '180deg'],
  });

  return (
    <View style={[styles.ringContainer, { width: size, height: size }]}>
      <View
        style={[
          styles.ringTrack,
          {
            width: size,
            height: size,
            borderRadius: size / 2,
            borderWidth: strokeWidth,
          },
        ]}
      />

      <View style={[styles.ringProgressLayer, { width: size, height: size, transform: [{ rotate: '-90deg' }] }]}>
        <View style={[styles.halfMask, styles.leftHalf, { width: size / 2, height: size }]}>
          <Animated.View
            style={[
              styles.progressCircle,
              {
                width: size,
                height: size,
                borderRadius: size / 2,
                borderWidth: strokeWidth,
                transform: [{ rotate: leftRotation }],
              },
            ]}
          />
        </View>

        <View style={[styles.halfMask, styles.rightHalf, { width: size / 2, height: size }]}>
          <Animated.View
            style={[
              styles.progressCircle,
              {
                width: size,
                height: size,
                borderRadius: size / 2,
                borderWidth: strokeWidth,
                transform: [{ rotate: rightRotation }],
              },
            ]}
          />
        </View>
      </View>

      <View style={styles.ringCenter}>
        <Text style={styles.ringText}>{remaining}</Text>
      </View>
    </View>
  );
}

export function AuthenticatorScreen({ navigation }: Props) {
  const [sensors, setSensors] = useState<PairedTotpSensor[]>([]);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [remaining, setRemaining] = useState<number>(getTimeRemaining());
  const [copiedSensorId, setCopiedSensorId] = useState<string | null>(null);
  const progress = useRef<Animated.Value>(
    new Animated.Value((30 - getTimeRemaining()) / 30)
  ).current;
  const rootNavigation = navigation.getParent<NativeStackNavigationProp<RootStackParamList>>();

  const loadSensors = useCallback(async (): Promise<void> => {
    const paired = await getPairedSensors();
    const secretEntries = await Promise.all(
      paired.map(async (item) => ({
        sensorId: item.sensorId,
        secret: await getSensorSecret(item.sensorId),
      }))
    );

    const nextSecrets: Record<string, string> = {};
    secretEntries.forEach((entry) => {
      if (entry.secret) {
        nextSecrets[entry.sensorId] = entry.secret;
      }
    });

    setSensors(paired.filter((item) => Boolean(nextSecrets[item.sensorId])));
    setSecrets(nextSecrets);
  }, []);

  useFocusEffect(
    useCallback(() => {
      void loadSensors();
    }, [loadSensors])
  );

  useEffect(() => {
    const update = (): void => {
      const nextRemaining = getTimeRemaining();
      setRemaining(nextRemaining);

      const nextProgress = (30 - nextRemaining) / 30;
      Animated.timing(progress, {
        toValue: nextProgress,
        duration: 220,
        easing: Easing.linear,
        useNativeDriver: false,
      }).start();
    };

    update();
    const interval = setInterval(update, 250);
    return () => clearInterval(interval);
  }, [progress]);

  useEffect(() => {
    if (!copiedSensorId) {
      return;
    }

    const timeout = setTimeout(() => setCopiedSensorId(null), 1200);
    return () => clearTimeout(timeout);
  }, [copiedSensorId]);

  const entries = useMemo<SensorCodeEntry[]>(
    () =>
      sensors.map((sensor) => ({
        ...sensor,
        code: getToken(secrets[sensor.sensorId]),
      })),
    [remaining, secrets, sensors]
  );

  if (entries.length === 0) {
    return (
      <View style={styles.container}>
        <View style={styles.emptyState}>
          <Text style={styles.title}>Authenticator</Text>
          <Text style={styles.emptyText}>No paired sensors yet.</Text>
          <Text style={styles.emptySubtext}>
            Scan a TOTP setup QR code from a sensor to generate rotating access codes.
          </Text>
          <Pressable style={styles.primaryButton} onPress={() => rootNavigation?.navigate('Pair')}>
            <Text style={styles.primaryButtonText}>Add Sensor</Text>
          </Pressable>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Authenticator</Text>
        <Pressable
          style={styles.addButton}
          onPress={() => rootNavigation?.navigate('Pair')}
        >
          <Ionicons name="add" size={18} color="#FFFFFF" />
          <Text style={styles.addButtonText}>Add Sensor</Text>
        </Pressable>
      </View>

      <FlatList
        data={entries}
        keyExtractor={(item) => item.sensorId}
        contentContainerStyle={styles.listContent}
        renderItem={({ item }) => (
          <Pressable
            style={styles.sensorCard}
            onPress={() => {
              void Clipboard.setStringAsync(item.code);
              setCopiedSensorId(item.sensorId);
            }}
          >
            <View style={styles.sensorTextWrap}>
              <Text style={styles.sensorName}>{item.sensorName}</Text>
              <Text style={styles.sensorIssuer}>{item.issuer}</Text>
              <Text style={styles.sensorCode}>{formatCode(item.code)}</Text>
              <Text style={styles.tapHint}>
                {copiedSensorId === item.sensorId ? 'Copied' : 'Tap to copy code'}
              </Text>
            </View>
            <CountdownRing progress={progress} remaining={remaining} />
          </Pressable>
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#FFFFFF', paddingHorizontal: 16, paddingTop: 18 },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 },
  title: { color: '#1D1D1F', fontSize: 28, fontWeight: '800' },
  addButton: {
    backgroundColor: '#0B4A8F',
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 8,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  addButtonText: { color: '#FFFFFF', fontWeight: '700' },
  listContent: { paddingBottom: 22, gap: 12 },
  sensorCard: {
    backgroundColor: '#F6F9FD',
    borderRadius: 16,
    borderWidth: 1,
    borderColor: '#D8E5F5',
    paddingHorizontal: 14,
    paddingVertical: 16,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  sensorTextWrap: { flex: 1, gap: 2 },
  sensorName: { color: '#1D1D1F', fontSize: 18, fontWeight: '700' },
  sensorIssuer: { color: '#516172', fontSize: 13, marginBottom: 6 },
  sensorCode: { color: '#0B4A8F', fontSize: 38, fontWeight: '800', letterSpacing: 1 },
  tapHint: { color: '#516172', fontSize: 12, marginTop: 2 },
  emptyState: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 10, paddingHorizontal: 18 },
  emptyText: { color: '#1D1D1F', fontSize: 20, fontWeight: '700' },
  emptySubtext: { color: '#516172', textAlign: 'center', lineHeight: 20 },
  primaryButton: {
    backgroundColor: '#0B4A8F',
    paddingHorizontal: 18,
    paddingVertical: 12,
    borderRadius: 12,
    marginTop: 8,
  },
  primaryButtonText: { color: '#FFFFFF', fontWeight: '700' },
  ringContainer: { justifyContent: 'center', alignItems: 'center' },
  ringTrack: { position: 'absolute', borderColor: '#D8E5F5' },
  ringProgressLayer: { position: 'absolute' },
  halfMask: { position: 'absolute', overflow: 'hidden' },
  leftHalf: { left: 0 },
  rightHalf: { right: 0 },
  progressCircle: { position: 'absolute', borderColor: '#0B4A8F' },
  ringCenter: { alignItems: 'center', justifyContent: 'center' },
  ringText: { color: '#0B4A8F', fontWeight: '800', fontSize: 14 },
});
