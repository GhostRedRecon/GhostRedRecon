import { TAB_KEYS, TABS } from '../config/tabs'

export const runtimeConfig = window.GHOSTRECON_CONFIG || {}

export const API_BASE =
  runtimeConfig.network?.backend?.resolvedUrl ||
  runtimeConfig.network?.backend?.publicUrl ||
  `${window.location.protocol}//${window.location.hostname}:8100`

export const GUI_CONFIG = runtimeConfig.gui || {}
export const SESSION_CONFIG = runtimeConfig.session || {}

const DEFAULT_CATEGORIES = {
  subghz: {
    enabled: true,
    displayName: 'Sub-GHz',
    defaultFrequencyMHz: 433.92,
    channels: [
      { label: '315M', frequencyMHz: 315.0 },
      { label: '433.92M', frequencyMHz: 433.92 },
      { label: '868.1M', frequencyMHz: 868.1 },
      { label: '915M', frequencyMHz: 915.0 },
    ],
  },
  ble: {
    enabled: true,
    displayName: 'Bluetooth / BLE',
    defaultFrequencyMHz: 2402.0,
    channels: [
      { label: 'ADV37', frequencyMHz: 2402.0 },
      { label: 'ADV38', frequencyMHz: 2426.0 },
      { label: 'ADV39', frequencyMHz: 2480.0 },
    ],
  },
  lora: {
    enabled: true,
    displayName: 'LoRa',
    defaultFrequencyMHz: 915.0,
    channels: [
      { label: 'EU868', frequencyMHz: 868.1 },
      { label: 'US915', frequencyMHz: 915.0 },
      { label: 'ISM433', frequencyMHz: 433.92 },
    ],
  },
  zigbee: {
    enabled: true,
    displayName: 'Zigbee',
    defaultFrequencyMHz: 2405.0,
    channels: [
      { label: 'CH11', frequencyMHz: 2405.0 },
      { label: 'CH15', frequencyMHz: 2425.0 },
      { label: 'CH20', frequencyMHz: 2450.0 },
      { label: 'CH24', frequencyMHz: 2470.0 },
      { label: 'CH26', frequencyMHz: 2480.0 },
    ],
  },
  wifi: {
    enabled: true,
    displayName: 'WiFi',
    defaultFrequencyMHz: 2412.0,
    channels: [
      { label: 'CH1', frequencyMHz: 2412.0 },
      { label: 'CH6', frequencyMHz: 2437.0 },
      { label: 'CH11', frequencyMHz: 2462.0 },
    ],
  },
  wifiMk7: {
    enabled: true,
    displayName: 'WiFi MK7',
    defaultFrequencyMHz: 2412.0,
    channels: [
      { label: '2.4 GHz Sweep', frequencyMHz: 2412.0 },
      { label: '5 GHz Sweep', frequencyMHz: 5180.0 },
    ],
  },
  bleNr5: {
    enabled: true,
    displayName: 'BLE NR5',
    defaultFrequencyMHz: 2402.0,
    channels: [
      { label: 'ADV37', frequencyMHz: 2402.0 },
      { label: 'ADV38', frequencyMHz: 2426.0 },
      { label: 'ADV39', frequencyMHz: 2480.0 },
    ],
  },
  iot: {
    enabled: true,
    displayName: 'IoT',
    defaultFrequencyMHz: 2405.0,
    channels: [
      { label: 'BLE37', frequencyMHz: 2402.0 },
      { label: 'ZB11', frequencyMHz: 2405.0 },
      { label: 'WIFI1', frequencyMHz: 2412.0 },
      { label: 'ZB15', frequencyMHz: 2425.0 },
      { label: 'BLE38', frequencyMHz: 2426.0 },
      { label: 'WIFI6', frequencyMHz: 2437.0 },
      { label: 'ZB20', frequencyMHz: 2450.0 },
      { label: 'WIFI11', frequencyMHz: 2462.0 },
      { label: 'ZB24', frequencyMHz: 2470.0 },
      { label: 'BLE39', frequencyMHz: 2480.0 },
      { label: '433.92', frequencyMHz: 433.92 },
      { label: '868.30', frequencyMHz: 868.30 },
      { label: '868.95', frequencyMHz: 868.95 },
      { label: '869.525', frequencyMHz: 869.525 },
      { label: 'LORA915', frequencyMHz: 915.0 },
    ],
  },
  wbHunt: {
    enabled: true,
    displayName: 'WB Hunt',
    defaultFrequencyMHz: 433.92,
    channels: [
      { label: 'EU ISM Sweep', frequencyMHz: 433.92 },
      { label: '2.4 GHz Sweep', frequencyMHz: 2412.0 },
      { label: 'Full RF Sweep', frequencyMHz: 868.30 },
    ],
  },
  ismDecoder: {
    enabled: true,
    displayName: '433 / 868 Decoder',
    defaultFrequencyMHz: 433.92,
    channels: [
      { label: 'ISM433', frequencyMHz: 433.92 },
      { label: 'EU868.30', frequencyMHz: 868.30 },
      { label: 'EU868.95', frequencyMHz: 868.95 },
      { label: 'EU869.525', frequencyMHz: 869.525 },
    ],
  },
  signalLab: {
    enabled: true,
    displayName: 'Signal Lab',
    defaultFrequencyMHz: 433.92,
    channels: [
      { label: 'Replay Lab 433', frequencyMHz: 433.92 },
      { label: 'Replay Lab 868', frequencyMHz: 868.30 },
      { label: 'Replay Lab 2.4', frequencyMHz: 2402.0 },
    ],
  },
  kismetFusion: {
    enabled: true,
    displayName: 'Kismet RF Fusion',
    defaultFrequencyMHz: 2412.0,
    channels: [
      { label: 'WiFi/BLE/Zigbee 2.4', frequencyMHz: 2412.0 },
      { label: 'BLE ADV38', frequencyMHz: 2426.0 },
      { label: 'BLE/Zigbee 2480', frequencyMHz: 2480.0 },
    ],
  },
}

export const CATEGORY_CONFIG = {
  ...DEFAULT_CATEGORIES,
  ...(runtimeConfig.categories || {}),
}

export const DEFAULT_FREQUENCY_MHZ = String(SESSION_CONFIG.defaultFrequencyMHz ?? 433.92)

const TAB_CATEGORY_MAP = {
  'SUB-GHZ': 'subghz',
  BLE: 'ble',
  LORA: 'lora',
  ZIGBEE: 'zigbee',
  IOT: 'iot',
  WIFI: 'wifi',
  'WIFI-MK7': 'wifiMk7',
  'BLE-NR5': 'bleNr5',
  'WB-HUNT': 'wbHunt',
  'ISM-DECODER': 'ismDecoder',
  'SIGNAL-LAB': 'signalLab',
  'KISMET-FUSION': 'kismetFusion',
}

export function fmt(value, fallback = '--') {
  if (value === null || value === undefined || value === '') return fallback
  return value
}

export function freq(value) {
  const num = Number(value)
  return Number.isFinite(num) ? `${num.toFixed(2)} MHz` : '--'
}

export function filterSignalsByTab(tab, signals) {
  const protocolNeedle = tab === 'HOME' ? '' : tab.toLowerCase().replace('-', '')
  if (!protocolNeedle || tab === 'DEVICES' || tab === 'SETTINGS' || tab === 'MANUAL' || tab === 'WB-HUNT' || tab === 'ISM-DECODER' || tab === 'SIGNAL-LAB' || tab === 'KISMET-FUSION' || tab === 'WIFI-MK7' || tab === 'BLE-NR5') return signals

  return signals.filter((sig) => {
    if (protocolNeedle === 'ble') {
      const protocol = String(sig.protocol || '').toUpperCase()
      const rfProtocol = String(sig.rf_protocol || '').toUpperCase()
      const channelFamily = String(sig.channel_family || '').toLowerCase()
      if ([protocol, rfProtocol].some((value) => ['WIFI', 'IEEE_802.11', 'ZIGBEE', 'LORA', 'LORAWAN'].some((needle) => value.includes(needle)))) {
        return false
      }
      return (
        protocol === 'BLE'
        || protocol === 'BLUETOOTH'
        || rfProtocol === 'BLUETOOTH_LE'
        || channelFamily === 'ble'
      )
    }

    const haystack = [
      sig.protocol,
      sig.rf_protocol,
      sig.channel_family,
      sig.device,
      sig.device_class,
      sig.device_type,
      sig.device_category,
      sig.rf_band,
      sig.rf_device_class,
      sig.behavior_profile_hint,
      sig.product_category_hint,
      sig.lora_device_type_hint,
      sig.subghz_profile,
    ].filter(Boolean).join(' ').toLowerCase()
    if (protocolNeedle === 'subghz') {
      return haystack.includes('sub') || Number(sig.freq_mhz) < 1000
    }
    if (protocolNeedle === 'zigbee') {
      return haystack.includes('zigbee')
    }
    if (protocolNeedle === 'iot') {
      const isWifiIot = haystack.includes('wifi') && ['camera', 'plug', 'bulb', 'thermostat', 'vacuum', 'speaker', 'doorbell', 'robot', 'sensor', 'appliance'].some((token) => haystack.includes(token))
      return (
        ['iot', 'zigbee', 'ble', 'bluetooth', 'thread', 'lora', 'meter', 'telemetry', 'tracker', 'gateway', 'hub', 'lock', 'camera', 'plug', 'bulb', 'thermostat', 'sensor', 'utility'].some((token) => haystack.includes(token))
        || isWifiIot
      )
    }
    return haystack.includes(protocolNeedle)
  })
}

export function getDefaultFrequencyForTab(tab) {
  const categoryKey = TAB_CATEGORY_MAP[tab]
  if (!categoryKey) return DEFAULT_FREQUENCY_MHZ
  const category = CATEGORY_CONFIG[categoryKey] || {}
  return String(category.defaultFrequencyMHz ?? DEFAULT_FREQUENCY_MHZ)
}

export function getCategoryConfigForTab(tab) {
  const categoryKey = TAB_CATEGORY_MAP[tab]
  return categoryKey ? (CATEGORY_CONFIG[categoryKey] || {}) : {}
}

export function getChannelProfilesForTab(tab) {
  return getCategoryConfigForTab(tab).channels || []
}

export { TABS, TAB_KEYS }
