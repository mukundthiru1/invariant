import { BottomTabScreenProps } from '@react-navigation/bottom-tabs';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { useFocusEffect } from '@react-navigation/native';
import * as SecureStore from 'expo-secure-store';
import { useCallback, useState } from 'react';
import { Pressable, StyleSheet, Switch, Text, View } from 'react-native';

import { RootStackParamList, TabParamList } from '../navigation/AppNavigator';
import { StoredCredentials } from '../types';

const CREDENTIALS_KEY = 'santh.credentials';
const NOTIFICATIONS_KEY = 'santh.notifications.enabled';

type Props = BottomTabScreenProps<TabParamList, 'Settings'>;

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

export function SettingsScreen({ navigation }: Props) {
  const [credentials, setCredentials] = useState<StoredCredentials | null>(null);
  const [notificationsEnabled, setNotificationsEnabled] = useState<boolean>(true);

  useFocusEffect(
    useCallback(() => {
      const run = async (): Promise<void> => {
        const creds = await loadCredentials();
        const pref = await SecureStore.getItemAsync(NOTIFICATIONS_KEY);
        setCredentials(creds);
        setNotificationsEnabled(pref !== 'false');
      };

      void run();
    }, [])
  );

  const rootNavigation = navigation.getParent<NativeStackNavigationProp<RootStackParamList>>();

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Settings</Text>

      <View style={styles.panel}>
        <Text style={styles.label}>Sensor URL</Text>
        <Text style={styles.value}>{credentials?.sensorUrl ?? 'No sensor connected'}</Text>
      </View>

      <View style={[styles.panel, styles.inline]}>
        <Text style={styles.label}>Notification preferences</Text>
        <Switch
          value={notificationsEnabled}
          onValueChange={(value) => {
            setNotificationsEnabled(value);
            void SecureStore.setItemAsync(NOTIFICATIONS_KEY, value ? 'true' : 'false');
          }}
          trackColor={{ false: '#3A3A3C', true: '#30D158' }}
        />
      </View>

      <Pressable style={styles.button} onPress={() => rootNavigation?.navigate('Scanner')}>
        <Text style={styles.buttonText}>Re-pair Sensor</Text>
      </Pressable>

      <Pressable
        style={[styles.button, styles.signOutButton]}
        onPress={async () => {
          await SecureStore.deleteItemAsync(CREDENTIALS_KEY);
          navigation.getParent<NativeStackNavigationProp<RootStackParamList>>()?.reset({
            index: 0,
            routes: [{ name: 'Lock' }],
          });
        }}
      >
        <Text style={styles.buttonText}>Sign Out</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#000000', padding: 16, gap: 12 },
  title: { color: '#FFFFFF', fontSize: 24, fontWeight: '800' },
  panel: { backgroundColor: '#1C1C1E', borderRadius: 12, padding: 12, gap: 8 },
  inline: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  label: { color: '#8E8E93', fontWeight: '600' },
  value: { color: '#FFFFFF' },
  button: { borderWidth: 1, borderColor: '#FFFFFF', borderRadius: 12, padding: 12 },
  signOutButton: { borderColor: '#FF453A' },
  buttonText: { color: '#FFFFFF', textAlign: 'center', fontWeight: '700' },
});
