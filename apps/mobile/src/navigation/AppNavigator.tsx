import { Ionicons } from '@expo/vector-icons';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createNativeStackNavigator } from '@react-navigation/native-stack';

import { AlertsScreen } from '../screens/AlertsScreen';
import { AuthenticatorScreen } from '../screens/AuthenticatorScreen';
import { DashboardScreen } from '../screens/DashboardScreen';
import { LockScreen } from '../screens/LockScreen';
import { PairScreen } from '../screens/PairScreen';
import { ScannerScreen } from '../screens/ScannerScreen';
import { SettingsScreen } from '../screens/SettingsScreen';

export type RootStackParamList = {
  Lock: undefined;
  MainTabs: undefined;
  Scanner: undefined;
  Pair: undefined;
};

export type TabParamList = {
  Dashboard: undefined;
  Authenticator: undefined;
  Alerts: undefined;
  Settings: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();
const Tab = createBottomTabNavigator<TabParamList>();

function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarActiveTintColor: '#ffffff',
        tabBarInactiveTintColor: '#8E8E93',
        tabBarStyle: { backgroundColor: '#121212', borderTopColor: '#2C2C2E' },
        tabBarIcon: ({ color, size }) => {
          const iconByRoute: Record<keyof TabParamList, keyof typeof Ionicons.glyphMap> = {
            Dashboard: 'shield-checkmark',
            Authenticator: 'key',
            Alerts: 'notifications',
            Settings: 'settings',
          };

          return <Ionicons name={iconByRoute[route.name]} size={size} color={color} />;
        },
      })}
    >
      <Tab.Screen name="Dashboard" component={DashboardScreen} />
      <Tab.Screen name="Authenticator" component={AuthenticatorScreen} />
      <Tab.Screen name="Alerts" component={AlertsScreen} />
      <Tab.Screen name="Settings" component={SettingsScreen} />
    </Tab.Navigator>
  );
}

export function AppNavigator() {
  return (
    <Stack.Navigator screenOptions={{ headerShown: false }}>
      <Stack.Screen name="Lock" component={LockScreen} />
      <Stack.Screen name="MainTabs" component={MainTabs} />
      <Stack.Screen
        name="Scanner"
        component={ScannerScreen}
        options={{
          presentation: 'modal',
          headerShown: true,
          title: 'Pair Sensor',
          headerStyle: { backgroundColor: '#000000' },
          headerTintColor: '#FFFFFF',
        }}
      />
      <Stack.Screen
        name="Pair"
        component={PairScreen}
        options={{
          presentation: 'modal',
          headerShown: true,
          title: 'Add Authenticator Sensor',
          headerStyle: { backgroundColor: '#FFFFFF' },
          headerTintColor: '#1D1D1F',
        }}
      />
    </Stack.Navigator>
  );
}
