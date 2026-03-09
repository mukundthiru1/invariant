import { BottomTabScreenProps } from '@react-navigation/bottom-tabs';
import { useFocusEffect } from '@react-navigation/native';
import * as SecureStore from 'expo-secure-store';
import { useCallback, useMemo, useState } from 'react';
import {
  FlatList,
  Modal,
  Pressable,
  RefreshControl,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { TabParamList } from '../navigation/AppNavigator';
import { getAlerts } from '../services/api';
import { Alert, StoredCredentials } from '../types';

const CREDENTIALS_KEY = 'santh.credentials';
const PAGE_SIZE = 20;

type Props = BottomTabScreenProps<TabParamList, 'Alerts'>;
type Filter = 'All' | 'Critical' | 'High' | 'Medium';

async function loadCredentials(): Promise<StoredCredentials | null> {
  const raw = await SecureStore.getItemAsync(CREDENTIALS_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<StoredCredentials>;
    if (
      typeof parsed.sensorUrl === 'string' &&
      typeof parsed.sensorId === 'string' &&
      typeof parsed.apiKey === 'string'
    ) {
      return parsed as StoredCredentials;
    }
    return null;
  } catch {
    return null;
  }
}

function maskIp(ip: string): string {
  const split = ip.split('.');
  if (split.length === 4) {
    return `x.x.${split[2]}.${split[3]}`;
  }
  return ip;
}

function severityColor(severity: string): string {
  if (severity === 'Critical') {
    return '#FF453A';
  }
  if (severity === 'High') {
    return '#FF9F0A';
  }
  return '#FFD60A';
}

export function AlertsScreen(_: Props) {
  const [credentials, setCredentials] = useState<StoredCredentials | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<Filter>('All');
  const [limit, setLimit] = useState<number>(PAGE_SIZE);
  const [hasMore, setHasMore] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [loadingMore, setLoadingMore] = useState<boolean>(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const fetchAlerts = useCallback(async (creds: StoredCredentials, nextLimit: number): Promise<void> => {
    const data = await getAlerts(creds.sensorUrl, creds.apiKey, nextLimit);
    const alertsData = data ?? [];
    setAlerts(alertsData);
    setHasMore(alertsData.length >= nextLimit);
  }, []);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    const creds = await loadCredentials();
    setCredentials(creds);

    if (!creds) {
      setAlerts([]);
      setHasMore(false);
      setLimit(PAGE_SIZE);
      setRefreshing(false);
      return;
    }

    setLimit(PAGE_SIZE);
    await fetchAlerts(creds, PAGE_SIZE);
    setRefreshing(false);
  }, [fetchAlerts]);

  useFocusEffect(
    useCallback(() => {
      void refresh();
    }, [refresh])
  );

  const filtered = useMemo(() => {
    if (filter === 'All') {
      return alerts;
    }
    return alerts.filter((item) => item.severity === filter);
  }, [alerts, filter]);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Security Alerts</Text>

      <View style={styles.filters}>
        {(['All', 'Critical', 'High', 'Medium'] as Filter[]).map((item) => (
          <Pressable
            key={item}
            onPress={() => {
              setFilter(item);
            }}
            style={[styles.filterPill, filter === item && styles.filterPillActive]}
          >
            <Text style={[styles.filterText, filter === item && styles.filterTextActive]}>{item}</Text>
          </Pressable>
        ))}
      </View>

      <FlatList
        data={filtered}
        keyExtractor={(item) => item.id}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void refresh()} tintColor="#FFFFFF" />}
        onEndReached={() => void (async () => {
          if (loadingMore || !hasMore || !credentials) {
            return;
          }

          setLoadingMore(true);
          const nextLimit = limit + PAGE_SIZE;
          setLimit(nextLimit);
          await fetchAlerts(credentials, nextLimit);
          setLoadingMore(false);
        })()}
        onEndReachedThreshold={0.2}
        renderItem={({ item }) => (
          <View style={styles.alertCard}>
            <View style={[styles.badge, { backgroundColor: severityColor(item.severity) }]}>
              <Text style={styles.badgeText}>{item.attackClass}</Text>
            </View>
            <Text style={styles.bodyText}>Source: {maskIp(item.sourceIp)}</Text>
            <Text style={styles.bodyText}>{new Date(item.timestamp).toLocaleString()}</Text>
            <Pressable onPress={() => setSelectedAlert(item)}>
              <Text style={styles.link}>View details →</Text>
            </Pressable>
          </View>
        )}
        ListEmptyComponent={<Text style={styles.empty}>No alerts found.</Text>}
      />

      <Modal visible={selectedAlert !== null} transparent animationType="slide" onRequestClose={() => setSelectedAlert(null)}>
        <View style={styles.modalBackdrop}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>Alert Details</Text>
            {selectedAlert && (
              <>
                <Text style={styles.modalText}>Severity: {selectedAlert.severity}</Text>
                <Text style={styles.modalText}>Attack Class: {selectedAlert.attackClass}</Text>
                <Text style={styles.modalText}>MITRE ATT&CK: {selectedAlert.mitreTechnique}</Text>
                <Text style={styles.modalText}>Recommended Action: {selectedAlert.recommendedAction}</Text>
                <Text style={styles.modalText}>Data: {JSON.stringify(selectedAlert.details)}</Text>
              </>
            )}
            <Pressable style={styles.closeButton} onPress={() => setSelectedAlert(null)}>
              <Text style={styles.closeText}>Close</Text>
            </Pressable>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#000000', padding: 16 },
  title: { color: '#FFFFFF', fontSize: 24, fontWeight: '800', marginBottom: 12 },
  filters: { flexDirection: 'row', gap: 8, marginBottom: 12 },
  filterPill: { borderWidth: 1, borderColor: '#555', borderRadius: 999, paddingHorizontal: 12, paddingVertical: 8 },
  filterPillActive: { backgroundColor: '#FFFFFF', borderColor: '#FFFFFF' },
  filterText: { color: '#FFFFFF', fontWeight: '600' },
  filterTextActive: { color: '#000000' },
  alertCard: { backgroundColor: '#1C1C1E', borderRadius: 12, padding: 12, marginBottom: 10, gap: 6 },
  badge: { alignSelf: 'flex-start', borderRadius: 999, paddingHorizontal: 10, paddingVertical: 4 },
  badgeText: { color: '#000000', fontWeight: '700', fontSize: 12 },
  bodyText: { color: '#D1D1D6' },
  link: { color: '#64D2FF', fontWeight: '700' },
  empty: { color: '#8E8E93', textAlign: 'center', marginTop: 30 },
  modalBackdrop: { flex: 1, backgroundColor: 'rgba(0,0,0,0.7)', justifyContent: 'flex-end' },
  modalCard: { backgroundColor: '#1C1C1E', borderTopLeftRadius: 20, borderTopRightRadius: 20, padding: 16, gap: 8 },
  modalTitle: { color: '#FFFFFF', fontSize: 20, fontWeight: '700' },
  modalText: { color: '#D1D1D6' },
  closeButton: { marginTop: 8, alignSelf: 'flex-start', paddingHorizontal: 14, paddingVertical: 10, borderWidth: 1, borderColor: '#FFFFFF', borderRadius: 10 },
  closeText: { color: '#FFFFFF', fontWeight: '700' },
});
