const TAB_DEFINITIONS = {
  HOME: { key: 'HOME', label: 'Home' },
  SDR_HKRF: {
    key: 'SDR-HKRF',
    label: 'SDR HKRF',
    hidden: true,
    children: [
      'SUB_GHZ',
      'BLE',
      'LORA',
      'ZIGBEE',
      'IOT',
      'WIFI',
      'WB_HUNT',
      'ISM_DECODER',
      'SIGNAL_LAB',
      'KISMET_FUSION',
      'DEVICES',
    ],
  },
  SUB_GHZ: { key: 'SUB-GHZ', label: 'SUB GHZ', parent: 'SDR_HKRF' },
  BLE: { key: 'BLE', label: 'BLUETOOTH', parent: 'SDR_HKRF' },
  LORA: { key: 'LORA', label: 'LORA', parent: 'SDR_HKRF' },
  ZIGBEE: { key: 'ZIGBEE', label: 'ZIGBEE', parent: 'SDR_HKRF' },
  IOT: { key: 'IOT', label: 'IOT', parent: 'SDR_HKRF' },
  WIFI: { key: 'WIFI', label: 'WIFI', parent: 'SDR_HKRF' },
  WB_HUNT: { key: 'WB-HUNT', label: 'WB HUNT', parent: 'SDR_HKRF' },
  ISM_DECODER: { key: 'ISM-DECODER', label: '433/868 DECODE', parent: 'SDR_HKRF' },
  SIGNAL_LAB: { key: 'SIGNAL-LAB', label: 'SIGNAL LAB', parent: 'SDR_HKRF' },
  KISMET_FUSION: { key: 'KISMET-FUSION', label: 'KISMET', parent: 'SDR_HKRF' },
  DEVICES: { key: 'DEVICES', label: 'DEVICES', parent: 'SDR_HKRF' },
  BLE_NR5: { key: 'BLE-NR5', label: 'BLE NR5' },
  HUNT_DRONES: { key: 'HUNT-DRONES', label: 'Hunt Drones', hidden: true },
  WIFI_MK7: { key: 'WIFI-MK7', label: 'WiFi MK7' },
  CAMERA_HUNT: { key: 'CAMERA-HUNT', label: 'Camera Hunt' },
  SETTINGS: { key: 'SETTINGS', label: 'Settings' },
  MANUAL: { key: 'MANUAL', label: 'Manual' },
}

export const TABS = Object.freeze(TAB_DEFINITIONS)

const PRIMARY_TAB_IDS = [
  'HOME',
  'SDR_HKRF',
  'BLE_NR5',
  'HUNT_DRONES',
  'WIFI_MK7',
  'CAMERA_HUNT',
  'SETTINGS',
  'MANUAL',
]

export const PRIMARY_TABS = PRIMARY_TAB_IDS
  .map((id) => TABS[id])
  .filter((tab) => !tab.hidden)
  .map((tab) => ({ key: tab.key, label: tab.label }))

export const SDR_HKRF_TABS = TABS.SDR_HKRF.hidden
  ? []
  : TABS.SDR_HKRF.children
    .map((id) => TABS[id])
    .filter((tab) => !tab.hidden)
    .map((tab) => ({ key: tab.key, label: tab.label }))

export const SDR_HKRF_TAB_KEYS = new Set(SDR_HKRF_TABS.map((tab) => tab.key))

export const VALID_VIEW_TABS = new Set([
  ...PRIMARY_TABS.filter((tab) => tab.key !== TABS.SDR_HKRF.key).map((tab) => tab.key),
  ...SDR_HKRF_TABS.map((tab) => tab.key),
])

export const TAB_KEYS = Array.from(VALID_VIEW_TABS)

export function getPrimaryTabForView(viewTab) {
  if (SDR_HKRF_TAB_KEYS.has(viewTab)) return TABS.SDR_HKRF.key
  return PRIMARY_TABS.some((tab) => tab.key === viewTab) ? viewTab : TABS.HOME.key
}
