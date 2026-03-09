import { Ionicons } from '@expo/vector-icons';
import { BottomTabScreenProps } from '@react-navigation/bottom-tabs';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { useFocusEffect } from '@react-navigation/native';
import * as SecureStore from 'expo-secure-store';
import { useCallback, useState } from 'react';
import {
  Pressable,
  RefreshControl,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { RootStackParamList, TabParamList } from '../navigation/AppNavigator';
import { getAlerts, getHygieneScore, getSensorStats } from '../services/api';
import { registerForPushNotifications } from '../services/notifications';
import { Alert, HygieneReport, SensorStats, StoredCredentials } from '../types';

const CREDENTIALS_KEY = 'santh.credentials';

type Props = BottomTabScreenProps<TabParamList, 'Dashboard'>;

function formatTime(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleString();
}

function gradeColor(grade: string): string {
  if (grade.startsWith('A')) {
    return '#32D74B';
  }
  if (grade.startsWith('B')) {
    return '#FFD60A';
  }
  return '#FF453A';
}

function severityColor(severity: string): string {
  if (severity === 'Critical') {
    return '#FF453A';
  }
  if (severity === 'High') {
    return '#FF9F0A';
  }
  if (severity === 'Medium') {
    return '#FFD60A';
  }
  return '#64D2FF';
}

async function loadCredentials(): Promise<StoredCredentials | null> {
  const raw = await SecureStore.getItemAsync(CREDENTIALS_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<StoredCredentials>;
    if (typeof parsed.sensorUrl !== 'string' || typeof parsed.apiKey !== 'string' || typeof parsed.sensorId !== 'string') {
      return null;
    }
    return parsed as StoredCredentials;
  } catch {
    return null;
  }
}

export function DashboardScreen({ navigation }: Props) {
  const [credentials, setCredentials] = useState<StoredCredentials | null>(null);
  const [stats, setStats] = useState<SensorStats | null>(null);
  const [hygiene, setHygiene] = useState<HygieneReport | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    const creds = await loadCredentials();
    setCredentials(creds);

    if (!creds) {
      setStats(null);
      setHygiene(null);
      setAlerts([]);
      setRefreshing(false);
      return;
    }

    const [statsData, hygieneData, alertsData] = await Promise.all([
      getSensorStats(creds.sensorUrl, creds.apiKey),
      getHygieneScore(creds.sensorUrl, creds.apiKey),
      getAlerts(creds.sensorUrl, creds.apiKey, 10),
    ]);

    setStats(statsData);
    setHygiene(hygieneData);
    setAlerts(alertsData ?? []);
    setRefreshing(false);
  }, []);

  useFocusEffect(
    useCallback(() => {
      void refresh();
      void registerForPushNotifications();
    }, [refresh])
  );

  const rootNavigation = navigation.getParent<NativeStackNavigationProp<RootStackParamList>>();

  if (!credentials) {
    return (
      <View style={styles.container}>
        <View style={styles.header}>
          <Text style={styles.wordmark}>SANTH</Text>
          <Pressable onPress={() => navigation.navigate('Settings')}>
            <Ionicons name="settings" size={24} color="#FFFFFF" />
          </Pressable>
        </View>
        <View style={styles.emptyState}>
          <Text style={styles.emptyText}>No sensor connected.</Text>
          <Pressable style={styles.connectButton} onPress={() => rootNavigation?.navigate('Scanner')}>
            <Text style={styles.connectButtonText}>Connect a sensor →</Text>
          </Pressable>
        </View>
      </View>
    );
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void refresh()} tintColor="#FFFFFF" />}
    >
      <View style={styles.header}>
        <Text style={styles.wordmark}>SANTH</Text>
        <Pressable onPress={() => navigation.navigate('Settings')}>
          <Ionicons name="settings" size={24} color="#FFFFFF" />
        </Pressable>
      </View>

      <View style={styles.cardGrid}>
        <View style={styles.card}>
          <Text style={styles.cardLabel}>Attacks Blocked</Text>
          <Text style={styles.cardValue}>{stats?.attacksBlocked ?? 0}</Text>
        </View>
        <View style={styles.card}>
          <Text style={styles.cardLabel}>Hygiene Score</Text>
          <Text style={styles.cardValue}>{hygiene?.score ?? 0}</Text>
          <Text style={[styles.badge, { backgroundColor: gradeColor(hygiene?.grade ?? 'F') }]}>{hygiene?.grade ?? 'N/A'}</Text>
        </View>
        <View style={styles.card}>
          <Text style={styles.cardLabel}>Active Sensors</Text>
          <Text style={styles.cardValue}>{stats?.activeSensors ?? 0}</Text>
        </View>
      </View>

      <Text style={styles.sectionTitle}>Recent Alerts</Text>
      {alerts.map((alert) => (
        <View key={alert.id} style={styles.alertItem}>
          <View style={[styles.severityPill, { backgroundColor: severityColor(alert.severity) }]}>
            <Text style={styles.severityText}>{alert.severity}</Text>
          </View>
          <View style={styles.alertBody}>
            <Text style={styles.alertClass}>{alert.attackClass}</Text>
            <Text style={styles.alertTime}>{formatTime(alert.timestamp)}</Text>
          </View>
        </View>
      ))}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#000000', paddingHorizontal: 16, paddingTop: 18 },
  content: { paddingBottom: 28, gap: 16 },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 },
  wordmark: { color: '#FFFFFF', fontSize: 24, fontWeight: '900', letterSpacing: 4 },
  cardGrid: { gap: 12 },
  card: { backgroundColor: '#1C1C1E', borderRadius: 14, padding: 14 },
  cardLabel: { color: '#8E8E93', fontSize: 12 },
  cardValue: { color: '#FFFFFF', fontSize: 30, fontWeight: '800' },
  badge: { alignSelf: 'flex-start', color: '#000000', fontWeight: '700', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 8 },
  sectionTitle: { color: '#FFFFFF', fontSize: 18, fontWeight: '700' },
  alertItem: { flexDirection: 'row', backgroundColor: '#1C1C1E', borderRadius: 12, padding: 12, gap: 10, alignItems: 'center' },
  severityPill: { borderRadius: 999, paddingHorizontal: 10, paddingVertical: 4 },
  severityText: { color: '#000000', fontWeight: '700', fontSize: 12 },
  alertBody: { gap: 4 },
  alertClass: { color: '#FFFFFF', fontWeight: '700' },
  alertTime: { color: '#AEAEB2', fontSize: 12 },
  emptyState: { flex: 1, justifyContent: 'center', alignItems: 'center', gap: 16 },
  emptyText: { color: '#FFFFFF', fontSize: 16 },
  connectButton: { borderWidth: 1, borderColor: '#FFFFFF', borderRadius: 10, paddingVertical: 12, paddingHorizontal: 16 },
  connectButtonText: { color: '#FFFFFF', fontWeight: '700' },
});
