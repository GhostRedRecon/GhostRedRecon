import { useEffect, useState } from 'react'
import { GUI_CONFIG } from './runtime'

const STORAGE_KEY = 'ghostredrecon:view-panels'
const EVENT_NAME = 'ghostredrecon:view-panels:changed'

const CATEGORY_TAB_KEYS = ['SUB-GHZ', 'BLE', 'LORA', 'ZIGBEE', 'IOT', 'WIFI']

const CATEGORY_PANEL_DEFINITIONS = [
  { key: 'opsDeck', label: 'Live Ops Deck', defaultVisible: true },
  { key: 'sweepControls', label: 'Sweep Controls', defaultVisible: true },
  { key: 'channelProfiles', label: 'Channel Profiles', defaultVisible: true },
  { key: 'inventory', label: 'Inventory Table', defaultVisible: true },
  { key: 'primaryIntel', label: 'Primary Intel', defaultVisible: true },
  { key: 'secondaryIntel', label: 'Extended Intel', defaultVisible: false },
  { key: 'inspector', label: 'Inspector', defaultVisible: false },
]

const INTEGRATION_PANEL_DEFINITIONS = [
  { key: 'hostReadiness', label: 'Host Readiness', defaultVisible: true },
  { key: 'targetProfile', label: 'Recommended Frequencies', defaultVisible: false },
  { key: 'workflow', label: 'Workflow Panels', defaultVisible: true },
  { key: 'artifacts', label: 'Artifacts / Files', defaultVisible: false },
  { key: 'processes', label: 'Process Detail', defaultVisible: false },
]

export const TAB_PANEL_DEFINITIONS = {
  HOME: [
    { key: 'runtimeProfile', label: 'SDR Runtime Profile', defaultVisible: true },
    { key: 'statusStrip', label: 'Runtime Status Strip', defaultVisible: true },
    { key: 'dashboard', label: 'Dashboard Panels', defaultVisible: true },
    { key: 'topDetections', label: 'Top Detections', defaultVisible: true },
    { key: 'signalInspector', label: 'Selected Signal', defaultVisible: true },
    { key: 'deviceInventory', label: 'Top Devices', defaultVisible: true },
    { key: 'deviceDetail', label: 'Device Detail', defaultVisible: true },
  ],
  DEVICES: [
    { key: 'inventory', label: 'Device Inventory', defaultVisible: true },
    { key: 'detail', label: 'Device Detail', defaultVisible: true },
  ],
  MANUAL: [
    { key: 'overview', label: 'Overview', defaultVisible: true },
    { key: 'coreGuides', label: 'Core Guides', defaultVisible: true },
    { key: 'reference', label: 'Tab Reference', defaultVisible: true },
    { key: 'support', label: 'Support / Troubleshooting', defaultVisible: true },
  ],
  SETTINGS: [
    { key: 'deployment', label: 'Deployment Settings', defaultVisible: true },
    { key: 'dependencies', label: 'Host Diagnostics', defaultVisible: true },
    { key: 'modules', label: 'Optional Engine Readiness', defaultVisible: true },
    { key: 'integrations', label: 'Tool Readiness', defaultVisible: true },
    { key: 'wifiMk7Red', label: 'WiFi MK7 RED Profile', defaultVisible: true },
    { key: 'layoutControl', label: 'Configurable Tab Windows', defaultVisible: true },
    { key: 'projectConfig', label: 'Loaded Project Config', defaultVisible: true },
    { key: 'identities', label: 'Stored Identity Snapshots', defaultVisible: true },
  ],
  'WB-HUNT': INTEGRATION_PANEL_DEFINITIONS,
  'ISM-DECODER': INTEGRATION_PANEL_DEFINITIONS,
  'SIGNAL-LAB': INTEGRATION_PANEL_DEFINITIONS,
  'KISMET-FUSION': INTEGRATION_PANEL_DEFINITIONS,
  'WIFI-MK7': [
    { key: 'guidance', label: 'Operator Guidance', defaultVisible: true },
    { key: 'controls', label: 'Sensor Control', defaultVisible: true },
    { key: 'ranking', label: 'Mission Ranking', defaultVisible: true },
    { key: 'redIntel', label: 'RED Team Intelligence', defaultVisible: true },
    { key: 'packetTruth', label: 'Packet Truth Table', defaultVisible: true },
    { key: 'selectedNetwork', label: 'Selected SSID Tasks', defaultVisible: true },
    { key: 'clients', label: 'Observed Clients', defaultVisible: true },
    { key: 'channelPlan', label: 'Channel Plan', defaultVisible: true },
    { key: 'evidence', label: 'Evidence', defaultVisible: true },
    { key: 'lastSweep', label: 'Last Sweep', defaultVisible: true },
    { key: 'timeline', label: 'Timeline', defaultVisible: true },
  ],
  'BLE-NR5': [
    { key: 'guidance', label: 'Operator Guidance', defaultVisible: true },
    { key: 'controls', label: 'Sensor Control', defaultVisible: true },
    { key: 'inventory', label: 'Device Census', defaultVisible: true },
    { key: 'queue', label: 'Assessment Queue', defaultVisible: true },
    { key: 'intel', label: 'Knowledge and Risk Intel', defaultVisible: true },
    { key: 'timeline', label: 'Timeline', defaultVisible: true },
  ],
  ...Object.fromEntries(CATEGORY_TAB_KEYS.map((tab) => [tab, CATEGORY_PANEL_DEFINITIONS])),
}

function readStoredPreferences() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : {}
  } catch {
    return {}
  }
}

function writeStoredPreferences(nextValue) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(nextValue))
    window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: nextValue }))
  } catch {
    // ignore storage failures
  }
}

function getConfiguredPanelDefaults() {
  return GUI_CONFIG.panelPreferences || {}
}

export function getPanelDefinitionsForTab(tab) {
  return TAB_PANEL_DEFINITIONS[tab] || []
}

export function getResolvedPanelPreferences(tab) {
  const definitions = getPanelDefinitionsForTab(tab)
  const configuredDefaults = getConfiguredPanelDefaults()?.[tab] || {}
  const stored = readStoredPreferences()?.[tab] || {}
  return definitions.reduce((acc, definition) => {
    const configValue = configuredDefaults?.[definition.key]
    const defaultVisible = typeof configValue === 'boolean' ? configValue : definition.defaultVisible !== false
    acc[definition.key] = typeof stored?.[definition.key] === 'boolean' ? stored[definition.key] : defaultVisible
    return acc
  }, {})
}

export function setPanelPreference(tab, panelKey, visible) {
  const current = readStoredPreferences()
  const next = {
    ...current,
    [tab]: {
      ...(current?.[tab] || {}),
      [panelKey]: !!visible,
    },
  }
  writeStoredPreferences(next)
  return next
}

export function resetPanelPreferences(tab) {
  const current = readStoredPreferences()
  if (tab) {
    const next = { ...current }
    delete next[tab]
    writeStoredPreferences(next)
    return next
  }
  writeStoredPreferences({})
  return {}
}

export function usePanelPreferences(tab) {
  const definitions = getPanelDefinitionsForTab(tab)
  const [visibility, setVisibility] = useState(() => getResolvedPanelPreferences(tab))

  useEffect(() => {
    setVisibility(getResolvedPanelPreferences(tab))

    function handleChange() {
      setVisibility(getResolvedPanelPreferences(tab))
    }

    window.addEventListener(EVENT_NAME, handleChange)
    window.addEventListener('storage', handleChange)
    return () => {
      window.removeEventListener(EVENT_NAME, handleChange)
      window.removeEventListener('storage', handleChange)
    }
  }, [tab])

  function updatePanel(panelKey, visible) {
    setPanelPreference(tab, panelKey, visible)
    setVisibility(getResolvedPanelPreferences(tab))
  }

  return {
    panelDefinitions: definitions,
    panelVisibility: visibility,
    isPanelVisible: (panelKey) => visibility?.[panelKey] !== false,
    setPanelVisible: updatePanel,
    resetPanels: () => {
      resetPanelPreferences(tab)
      setVisibility(getResolvedPanelPreferences(tab))
    },
  }
}
