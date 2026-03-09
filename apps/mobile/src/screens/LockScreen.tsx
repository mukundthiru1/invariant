import * as LocalAuthentication from 'expo-local-authentication';
import { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text, View } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { NativeStackScreenProps } from '@react-navigation/native-stack';

import { RootStackParamList } from '../navigation/AppNavigator';

type Props = NativeStackScreenProps<RootStackParamList, 'Lock'>;

export function LockScreen({ navigation }: Props) {
  const [authenticating, setAuthenticating] = useState<boolean>(true);
  const [error, setError] = useState<string>('');

  const authenticate = useCallback(async () => {
    setAuthenticating(true);
    setError('');

    try {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Verify your identity',
        fallbackLabel: 'Use passcode',
      });

      if (result.success) {
        navigation.replace('MainTabs');
        return;
      }

      setError('Authentication failed. Try again.');
    } catch {
      setError('Biometric authentication is unavailable.');
    } finally {
      setAuthenticating(false);
    }
  }, [navigation]);

  useEffect(() => {
    void authenticate();
  }, [authenticate]);

  return (
    <View style={styles.container}>
      <Text style={styles.wordmark}>SANTH</Text>
      <Ionicons name="finger-print" size={72} color="#FFFFFF" />
      <Text style={styles.status}>{authenticating ? 'Verifying identity...' : error || 'Authenticated'}</Text>
      {authenticating ? (
        <ActivityIndicator color="#FFFFFF" />
      ) : (
        <Pressable onPress={() => void authenticate()} style={styles.retryButton}>
          <Text style={styles.retryText}>Retry</Text>
        </Pressable>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000000',
    justifyContent: 'center',
    alignItems: 'center',
    gap: 16,
  },
  wordmark: {
    color: '#FFFFFF',
    fontSize: 40,
    fontWeight: '800',
    letterSpacing: 6,
  },
  status: {
    color: '#D1D1D6',
    fontSize: 16,
  },
  retryButton: {
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 12,
    borderColor: '#FFFFFF',
    borderWidth: 1,
  },
  retryText: {
    color: '#FFFFFF',
    fontWeight: '700',
  },
});
