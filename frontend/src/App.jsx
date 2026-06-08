import { useEffect, useMemo, useRef, useState } from 'react'
import HeroHeader from './components/HeroHeader'
import { BRANDING } from './lib/branding'
import ErrorBoundary from './components/ErrorBoundary'
import {
  API_BASE,
  DEFAULT_FREQUENCY_MHZ,
  GUI_CONFIG,
  SESSION_CONFIG,
  getDefaultFrequencyForTab,
  filterSignalsByTab,
} from './lib/runtime'
import {
  PRIMARY_TABS,
  SDR_HKRF_TABS,
  SDR_HKRF_TAB_KEYS,
  TABS,
  VALID_VIEW_TABS,
  getPrimaryTabForView,
} from './config/tabs'
import {
  clearSdrSweep,
  clearBleNr5Session,
  clearWiFiMk7Session,
  fetchBleDecoderStatus,
  fetchDashboardState,
  fetchIntegrationSummary,
  fetchSdrSweepState,
  restartBackend,
  retuneSession,
  runBleNr5Scan,
  startSdrSweep,
  startBleNr5Session,
  startSession,
  startWiFiMk7Session,
  stopSdrSweep,
  stopBleNr5Session,
  stopSession,
  stopWiFiMk7Session,
} from './lib/api'
import HomeView from './views/HomeView'
import DevicesView from './views/DevicesView'
import ManualView from './views/ManualView'
import SettingsView from './views/SettingsView'
import SubGhzView from './views/SubGhzView'
import BleView from './views/BleView'
import LoraView from './views/LoraView'
import ZigbeeView from './views/ZigbeeView'
import WifiView from './views/WifiView'
import WifiMk7View from './views/WifiMk7View'
import BleNr5View from './views/BleNr5View'
import HuntDronesView from './views/HuntDronesView'
import IotView from './views/IotView'
import WbHuntView from './views/WbHuntView'
import IsmDecoderView from './views/IsmDecoderView'
import SignalLabView from './views/SignalLabView'
import KismetFusionView from './views/KismetFusionView'

function getNavigationType() {
  try {
    return window.performance?.getEntriesByType?.('navigation')?.[0]?.type || ''
  } catch {
    return ''
  }
}

export default function App() {
  const initialReloadNavigation = getNavigationType() === 'reload'
  const mode = 'RED'
  const [activeTab, setActiveTab] = useState(() => {
    try {
      const stored = window.sessionStorage.getItem('ghostredrecon:active-tab')
      return VALID_VIEW_TABS.has(stored) ? stored : 'HOME'
    } catch {
      return 'HOME'
    }
  })
  const layoutMode = 'laptop'
  const [activeSdrTab, setActiveSdrTab] = useState(() => (
    SDR_HKRF_TAB_KEYS.has(activeTab) ? activeTab : 'SUB-GHZ'
  ))
  const [statusLine, setStatusLine] = useState('GhostRedRecon operator console ready.')
  const [system, setSystem] = useState(null)
  const [rfHealth, setRfHealth] = useState(null)
  const [signals, setSignals] = useState([])
  const [devices, setDevices] = useState([])
  const [fft, setFft] = useState([])
  const [fftTimestamp, setFftTimestamp] = useState(null)
  const [diagnostics, setDiagnostics] = useState(null)
  const [identities, setIdentities] = useState([])
  const [integrations, setIntegrations] = useState({})
  const [bleDecoderStatus, setBleDecoderStatus] = useState(null)
  const [selectedSignal, setSelectedSignal] = useState(null)
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [targetFreq, setTargetFreq] = useState(DEFAULT_FREQUENCY_MHZ)
  const [lastStreamUpdate, setLastStreamUpdate] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [viewHeaderContext, setViewHeaderContext] = useState([])
  const [sweepState, setSweepState] = useState(null)
  const [sweepNonceByTab, setSweepNonceByTab] = useState({})
  const [sweepResetNonceByTab, setSweepResetNonceByTab] = useState({})
  const lastAutoTuneRef = useRef('')
  const [reloadSettling, setReloadSettling] = useState(initialReloadNavigation)
  const activePrimaryTab = getPrimaryTabForView(activeTab)
  const sdrFeatureEnabled = !TABS.SDR_HKRF.hidden
  const nativePlatformTabActive = activeTab === 'WIFI-MK7' || activeTab === 'CAMERA-HUNT' || activeTab === 'BLE-NR5' || activeTab === 'HUNT-DRONES'

  useEffect(() => {
    setViewHeaderContext([])
  }, [activeTab])

  const filteredSignals = useMemo(() => filterSignalsByTab(activeTab, signals), [activeTab, signals])
  const degradedModules = useMemo(() => {
    const modules = diagnostics?.optional_modules || {}
    return Object.entries(modules).filter(([, value]) => !value?.available)
  }, [diagnostics])
  const integrationOwnership = useMemo(() => {
    if (!sdrFeatureEnabled) return { owner: '', detail: '' }
    const wbManager = integrations?.wbHunt?.manager || {}
    const rtlManager = integrations?.rtl433?.manager || {}
    if (wbManager.running) {
      return {
        owner: 'wb_hunt',
        detail: wbManager.profile?.label
          ? `WB Hunt is using the HackRF for ${wbManager.profile.label}.`
          : 'WB Hunt is using the HackRF.',
      }
    }
    if (rtlManager.running) {
      return {
        owner: 'rtl433',
        detail: '433/868 Decoder is using the HackRF for live decode.',
      }
    }
    const wbCompletedAt = Number(wbManager.completed_at || 0)
    if (
      wbCompletedAt
      && !system?.session_active
      && (Date.now() / 1000) - wbCompletedAt < 30
    ) {
      return {
        owner: 'wb_hunt_recent',
        detail: 'WB Hunt completed and the SDR session was intentionally released. Start Session again to resume live streaming.',
      }
    }
    return { owner: '', detail: '' }
  }, [integrations, sdrFeatureEnabled, system?.session_active])
  const streamingConfirmed = useMemo(() => !!rfHealth?.sdr_streaming_confirmed, [rfHealth])
  const bleCaptureExpected = useMemo(() => (
    activeTab === 'BLE'
    && !!rfHealth?.hackrf?.available
    && !!system?.session_active
    && !streamingConfirmed
  ), [activeTab, rfHealth?.hackrf?.available, streamingConfirmed, system?.session_active])
  const bleDecoderOwnsHackrf = useMemo(() => (
    bleCaptureExpected && !!bleDecoderStatus?.running
  ), [bleCaptureExpected, bleDecoderStatus?.running])
  const sdrRuntimeWarning = useMemo(() => {
    if (!sdrFeatureEnabled || !rfHealth) return ''
    if (!rfHealth?.hackrf?.available) {
      return 'SDR not connected. Please connect SDR.'
    }
    if (integrationOwnership.owner === 'wb_hunt' || integrationOwnership.owner === 'rtl433') {
      return integrationOwnership.detail
    }
    if (integrationOwnership.owner === 'wb_hunt_recent') {
      return integrationOwnership.detail
    }
    if (system?.session_active && !rfHealth?.sdr_streaming_confirmed && !bleCaptureExpected) {
      return rfHealth?.sdr_fault_reason || 'SDR session is active but streaming is not verified yet.'
    }
    return ''
  }, [bleCaptureExpected, integrationOwnership, rfHealth, sdrFeatureEnabled, system?.session_active])
  const startBlocked = useMemo(() => (sdrFeatureEnabled && rfHealth ? !rfHealth?.preflight?.ready_to_start : false), [rfHealth, sdrFeatureEnabled])
  const sessionStartBlocked = startBlocked || reloadSettling || busy
  const operatorMessage = useMemo(() => {
    if (activeTab === 'WIFI-MK7') {
      return {
        tone: 'ready',
        headline: 'WiFi Hunt packet sensor ready',
        detail: 'This tab is separate from the HackRF path. Use the tab-local Start Session and Run Sweep controls for native 802.11 capture and evidence-backed Wi-Fi hunting.',
        tags: ['Packet truth', 'WiFi Hunt', 'MK7 monitor mode'],
      }
    }
    if (activeTab === 'CAMERA-HUNT') {
      return {
        tone: 'ready',
        headline: 'Camera Hunt packet sensor ready',
        detail: 'This tab is separate from the HackRF path. Use the tab-local Hard Audit and camera-hunt controls for evidence-first video-device validation on MK7AC capture.',
        tags: ['Packet truth', 'Camera Hunt', 'Video evidence'],
      }
    }
    if (activeTab === 'BLE-NR5') {
      return {
        tone: 'ready',
        headline: 'BLE NR5 operator platform ready',
        detail: 'BLE NR5 is a native nRF52840 platform for Bluetooth discovery, lab validation, and knowledge-driven target scoring. Use the tab-local controls below.',
        tags: ['nRF52840 native', 'Lab validation', 'Target scoring'],
      }
    }
    if (activeTab === 'HUNT-DRONES') {
      return {
        tone: 'ready',
        headline: 'Hunt Drones passive audit workspace ready',
        detail: 'Hunt Drones is receive-only and evidence-first. Use the tab-local session controls to verify HackRF and MK7AC, run passive collection, and build topology-backed findings.',
        tags: ['Passive only', 'MK7AC + HackRF', 'Topology + evidence'],
      }
    }
    if (reloadSettling) {
      return {
        tone: 'warn',
        headline: 'Resetting after refresh',
        detail: sdrFeatureEnabled ? 'A hard refresh forces the SDR session back to idle. Wait for the reset to complete before starting a new session.' : 'A hard refresh is settling the local control plane. Wait for the GUI to return to ready.',
        tags: sdrFeatureEnabled ? ['Refresh reset', 'Stopping old session', 'Idle safe'] : ['Refresh reset', 'Control plane', 'Idle safe'],
      }
    }
    if (!sdrFeatureEnabled) {
      return {
        tone: 'ready',
        headline: 'Public v1 operator console ready',
        detail: 'SDR HKRF and Hunt Drones are hidden for v2.0 testing. Use WiFi MK7, Camera Hunt, and BLE NR5 for the public v1 workflow.',
        tags: ['WiFi MK7', 'Camera Hunt', 'BLE NR5'],
      }
    }
    if (!rfHealth?.hackrf?.available) {
      return {
        tone: 'error',
        headline: 'Connect SDR to begin',
        detail: 'HackRF is not visible. Connect the SDR, then click Start Session.',
        tags: ['SDR offline', 'Session locked', 'No sweep'],
      }
    }
    if (bleDecoderOwnsHackrf || bleCaptureExpected) {
      return {
        tone: 'active',
        headline: 'BLE capture is active',
        detail: bleDecoderOwnsHackrf
          ? 'The BLE decoder currently owns the HackRF for packet capture. This is expected on the Bluetooth tab after refresh, and the live stream indicator may stay paused while BLE capture runs.'
          : 'A BLE session is already active. After refresh, the Bluetooth tab may briefly report paused streaming while the decoder reacquires the HackRF. This is expected unless the session is actually stopped.',
        tags: ['BLE decoder active', 'HackRF in use', 'Streaming pause expected'],
      }
    }
    if (integrationOwnership.owner === 'wb_hunt') {
      return {
        tone: 'active',
        headline: 'WB Hunt is running',
        detail: integrationOwnership.detail,
        tags: ['Integration owns SDR', 'Wideband sweep active', 'Wait for results'],
      }
    }
    if (integrationOwnership.owner === 'rtl433') {
      return {
        tone: 'active',
        headline: '433/868 Decoder is running',
        detail: integrationOwnership.detail,
        tags: ['Integration owns SDR', 'Live decode active', 'Do not retune'],
      }
    }
    if (integrationOwnership.owner === 'wb_hunt_recent') {
      return {
        tone: 'success',
        headline: 'WB Hunt completed',
        detail: integrationOwnership.detail,
        tags: ['Results retained', 'Session released', 'Restart live stream if needed'],
      }
    }
    if (sweepState?.running) {
      return {
        tone: 'active',
        headline: `${sweepState.tab} sweep is running`,
        detail: `Hang on while ${sweepState.currentLabel || '--'} at ${sweepState.currentFrequencyMHz || '--'} MHz is being scanned. The table will populate as findings are retained.`,
        tags: [`Step ${sweepState.currentIndex || 0}/${sweepState.total || 0}`, 'Collecting results', 'Do not interrupt'],
      }
    }
    if (sweepState?.completed) {
      return {
        tone: 'success',
        headline: `${sweepState.tab} sweep complete`,
        detail: 'Sweep finished. Review the retained table results or export them for analysis.',
        tags: ['Results retained', 'Export ready', 'Run next sweep'],
      }
    }
    if (!system?.session_active) {
      return {
        tone: 'ready',
        headline: 'SDR connected, session idle',
        detail: 'HackRF is attached. Start Session only begins live streaming. Run Sweep stays locked until a session is active and is the only action that starts a scan.',
        tags: ['Hardware ready', 'Idle safe', 'Operator controlled'],
      }
    }
    if (system?.session_active && streamingConfirmed) {
      return {
        tone: 'ready',
        headline: 'Session is started',
        detail: 'SDR streaming is verified. No scan is running yet. Click Run Sweep in the active tab to scan that protocol range.',
        tags: ['Started and locked', 'Streaming verified', `${activeTab} ready`],
      }
    }
    if (system?.session_active && !streamingConfirmed) {
      return {
        tone: 'warn',
        headline: 'Session started, waiting for verified stream',
        detail: sdrRuntimeWarning || 'The SDR session exists, but streaming is not verified yet.',
        tags: ['Stream not verified', 'Sweep locked', 'Check SDR state'],
      }
    }
    return {
      tone: 'info',
      headline: 'Click Start Session first',
      detail: 'Tabs do not start scanning by themselves. Start the SDR session, wait for stream verification, then open a tab and click Run Sweep.',
      tags: ['Manual workflow', 'No auto-sweep', 'Operator controlled'],
    }
  }, [activeTab, bleCaptureExpected, bleDecoderOwnsHackrf, integrationOwnership, reloadSettling, rfHealth?.hackrf?.available, sdrFeatureEnabled, sdrRuntimeWarning, streamingConfirmed, sweepState, system?.session_active])

  const hardwareStatusItems = useMemo(() => {
    const wifiStatus = integrations?.wifiMk7?.manager
    const bleStatus = integrations?.bleNr5?.manager
    const items = []
    if (sdrFeatureEnabled) {
      items.push({
        label: 'HackRF SDR',
        value: rfHealth?.hackrf?.available ? 'CONNECTED' : 'OFFLINE',
        detail: system?.session_active ? 'session active' : 'idle',
        tone: rfHealth?.hackrf?.available ? 'online' : 'offline',
      })
    }
    items.push(
      {
        label: 'WIFI MK7AC',
        value: wifiStatus?.adapter?.detected ? 'CONNECTED' : 'OFFLINE',
        detail: wifiStatus?.capture_active ? 'capture active' : (wifiStatus?.adapter?.monitor_interface || wifiStatus?.adapter?.base_interface || 'awaiting adapter'),
        tone: wifiStatus?.adapter?.detected ? 'online' : 'offline',
      },
      {
        label: 'Bluetooth NRF',
        value: integrations?.bleNr5?.status?.installed ? 'CONNECTED' : 'OFFLINE',
        detail: bleStatus?.active ? 'nr5 active' : ((bleStatus?.sensors || []).length ? `${bleStatus.sensors.length} sensor` : 'awaiting sensor'),
        tone: integrations?.bleNr5?.status?.installed ? 'online' : 'offline',
      },
    )
    return items
  }, [integrations?.bleNr5?.manager, integrations?.bleNr5?.status?.installed, integrations?.wifiMk7?.manager, rfHealth?.hackrf?.available, sdrFeatureEnabled, system?.session_active])

  async function handleStartBleNr5FromRail() {
    setBusy(true)
    try {
      const needsStart = !integrations?.bleNr5?.manager?.active
      if (needsStart) {
        await startBleNr5Session({
          profile: 'red_team_validation',
          mission: 'gatt_analysis',
          labMode: mode === 'RED',
        })
      }
      await runBleNr5Scan(60)
      await loadAll()
      setStatusLine(needsStart ? 'BLE NR5 session started and scan completed.' : 'BLE NR5 scan completed.')
    } catch (err) {
      setStatusLine(`BLE NR5 start/scan failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStopBleNr5FromRail() {
    setBusy(true)
    try {
      await stopBleNr5Session()
      await loadAll()
      setStatusLine('BLE NR5 session stopped.')
    } catch (err) {
      setStatusLine(`BLE NR5 stop failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleClearBleNr5FromRail() {
    setBusy(true)
    try {
      await clearBleNr5Session()
      await loadAll()
      setStatusLine('BLE NR5 results cleared.')
    } catch (err) {
      setStatusLine(`BLE NR5 clear failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStartWiFiMk7FromRail() {
    setBusy(true)
    try {
      await clearWiFiMk7Session()
      await startWiFiMk7Session({
        bands: ['2.4ghz', '5ghz'],
        durationSeconds: 60,
        scanMode: 'broad',
        scanScenario: 'passive_observation',
      })
      await loadAll()
      setStatusLine('WIFI Hunt session started and sweep initiated.')
    } catch (err) {
      setStatusLine(`WIFI Hunt start failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStartCameraHuntFromRail() {
    setBusy(true)
    try {
      await clearWiFiMk7Session()
      await startWiFiMk7Session({
        bands: ['2.4ghz', '5ghz'],
        durationSeconds: 60,
        scanMode: 'broad',
        scanScenario: 'live_view',
        cameraHunt: true,
      })
      await loadAll()
      setStatusLine('Camera Hunt session started and sweep initiated.')
    } catch (err) {
      setStatusLine(`Camera Hunt start failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStopWiFiMk7FromRail() {
    setBusy(true)
    try {
      await stopWiFiMk7Session()
      await loadAll()
      setStatusLine('WIFI Hunt session stopped.')
    } catch (err) {
      setStatusLine(`WIFI Hunt stop failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleClearWiFiMk7FromRail() {
    setBusy(true)
    try {
      await clearWiFiMk7Session()
      await loadAll()
      setStatusLine('WIFI Hunt retained results cleared.')
    } catch (err) {
      setStatusLine(`WIFI Hunt clear failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  function handlePrimaryTabSelect(tabKey) {
    if (tabKey === TABS.SDR_HKRF.key) {
      setActiveTab(activeSdrTab)
      return
    }
    setActiveTab(tabKey)
  }

  function handleSdrSubTabSelect(tabKey) {
    setActiveSdrTab(tabKey)
    setActiveTab(tabKey)
  }

  const commandRail = useMemo(() => {
    if (activePrimaryTab === 'BLE-NR5') {
      const bleManager = integrations?.bleNr5?.manager || {}
      return {
        kicker: 'Command Rail / NRF52840',
        state: bleManager.active ? 'NRF Active' : 'NRF Idle',
        primaryNote: 'NRF52840 controls are live from the header. Start the sensor, run a scan, then select a device for lab work.',
        notes: [
          bleManager.sensor_ready ? 'nRF sensor detected' : 'nRF sensor offline',
          'RED profile uses lab validation mode',
          'Restart Backend resets the BLE controller state',
        ],
        actions: [
          { label: bleManager.active ? 'Run NRF Scan' : 'Start NRF Scan', onClick: handleStartBleNr5FromRail, disabled: busy, tone: 'primary' },
          { label: 'Stop NRF', onClick: handleStopBleNr5FromRail, disabled: !bleManager.active },
          { label: 'Clear', onClick: handleClearBleNr5FromRail, disabled: busy },
          { label: 'Restart Backend', onClick: handleRestartBackend, disabled: busy },
        ],
      }
    }

    if (activePrimaryTab === 'HUNT-DRONES') {
      return {
        kicker: 'Command Rail / Hunt Drones',
        state: 'Passive Drone Hunt',
        primaryNote: 'Hunt Drones stays receive-only. Use the tab-local controls to create a session, run passive scans, and review topology-backed findings.',
        notes: [
          'No transmit path is exposed in the field build',
          'MK7AC and HackRF evidence are preserved under session folders',
          'Research hooks remain disabled',
        ],
        actions: [
          { label: 'Restart Backend', onClick: handleRestartBackend, disabled: busy, tone: 'primary' },
        ],
      }
    }

    if (activePrimaryTab === 'WIFI-MK7') {
      const wifiManager = integrations?.wifiMk7?.manager || {}
      const captureActive = !!wifiManager.capture_active
      return {
        kicker: 'Command Rail / MK7AC',
        state: captureActive ? 'WiFi Hunt Active' : 'WiFi Hunt Idle',
        primaryNote: 'WiFi Hunt uses the MK7AC packet sensor. Start the session, run a sweep, then pivot to selected targets.',
        notes: [
          wifiManager.adapter?.detected ? 'MK7AC adapter detected' : 'MK7AC adapter offline',
          'RED mode keeps operator-driven recon enabled',
          'Restart Backend resets monitor mode orchestration',
        ],
        actions: [
          { label: 'WIFI Hunt', onClick: handleStartWiFiMk7FromRail, disabled: busy, tone: 'primary' },
          { label: 'Stop Hunt', onClick: handleStopWiFiMk7FromRail, disabled: !captureActive },
          { label: 'Clear', onClick: handleClearWiFiMk7FromRail, disabled: busy },
          { label: 'Restart Backend', onClick: handleRestartBackend, disabled: busy },
        ],
      }
    }

    if (activePrimaryTab === 'CAMERA-HUNT') {
      const wifiManager = integrations?.wifiMk7?.manager || {}
      const captureActive = !!wifiManager.capture_active
      return {
        kicker: 'Command Rail / MK7AC Camera Hunt',
        state: captureActive ? 'Camera Hunt Active' : 'Camera Hunt Idle',
        primaryNote: 'Camera Hunt uses the MK7AC packet sensor for evidence-first video-device detection and audit preparation.',
        notes: [
          wifiManager.adapter?.detected ? 'MK7AC adapter detected' : 'MK7AC adapter offline',
          'Camera Hunt isolates video-device leads from general WiFi hunt results',
          'Restart Backend resets monitor mode orchestration',
        ],
        actions: [
          { label: 'Hunt Camera', onClick: handleStartCameraHuntFromRail, disabled: busy, tone: 'primary' },
          { label: 'Stop Hunt', onClick: handleStopWiFiMk7FromRail, disabled: !captureActive },
          { label: 'Clear', onClick: handleClearWiFiMk7FromRail, disabled: busy },
          { label: 'Restart Backend', onClick: handleRestartBackend, disabled: busy },
        ],
      }
    }

    if (activePrimaryTab === TABS.SDR_HKRF.key) {
      return {
        kicker: 'Command Rail / HackRF SDR',
        state: system?.session_active ? 'HackRF Session Active' : 'HackRF Idle',
        primaryNote: 'HackRF controls drive the SDR session for the selected SDR HKRF sub-tab.',
        notes: [
          'Start Session arms the HackRF stream',
          'Retune follows the active SDR HKRF sub-tab frequency target',
          'Restart Backend resets the SDR controller and session state',
        ],
        actions: [
          { label: system?.session_active ? 'HackRF Ready' : 'Start Session', onClick: () => handleStart(targetFreq), disabled: sessionStartBlocked || !!system?.session_active, tone: 'primary' },
          { label: 'Retune', onClick: () => handleRetune(targetFreq), disabled: sessionStartBlocked || !system?.session_active },
          { label: 'Stop', onClick: handleStop, disabled: !system?.session_active },
          { label: 'Restart Backend', onClick: handleRestartBackend, disabled: busy },
        ],
      }
    }

    return {
      kicker: 'Command Rail / Platform',
      state: 'Platform Idle',
      primaryNote: 'Home, Settings, and Manual stay read-oriented. Use Restart Backend only when the platform needs a control-plane reset.',
      notes: [
        'Hardware controls follow the active SDR HKRF, BLE NR5, or WIFI MK7 tab',
        'WiFi Hunt uses the MK7AC packet-truth workflow',
        'Operator guidance changes with the selected workspace',
      ],
      actions: [
        { label: 'Restart Backend', onClick: handleRestartBackend, disabled: busy, tone: 'primary' },
      ],
    }
  }, [activePrimaryTab, busy, handleRestartBackend, integrations?.bleNr5?.manager, integrations?.wifiMk7?.manager, mode, sessionStartBlocked, system?.session_active, targetFreq])

  async function loadAllUntil(predicate, attempts = 4, delayMs = 700) {
    let lastDashboard = null
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      lastDashboard = await loadAll()
      if (predicate(lastDashboard)) {
        return lastDashboard
      }
      if (attempt < attempts - 1) {
        await new Promise((resolve) => window.setTimeout(resolve, delayMs))
      }
    }
    return lastDashboard
  }

  async function loadAll() {
    try {
      const [dashboard, integrationSummary, decoderStatus] = await Promise.all([
        fetchDashboardState(),
        fetchIntegrationSummary(),
        fetchBleDecoderStatus().catch(() => null),
      ])
      setSystem(dashboard.system)
      setRfHealth(dashboard.rfHealth)
      setSignals(dashboard.signals)
      setDevices(dashboard.devices)
      setFft(dashboard.fft)
      setFftTimestamp(dashboard.fftTimestamp)
      setDiagnostics(dashboard.diagnostics)
      setIdentities(dashboard.identities)
      setIntegrations(integrationSummary)
      setBleDecoderStatus(decoderStatus)
      setLastStreamUpdate(Date.now())
      setError('')
      return dashboard
    } catch (err) {
      setError(String(err.message || err))
      throw err
    }
  }

  useEffect(() => {
    let cancelled = false
    let timer = null

    async function initialize() {
      if (initialReloadNavigation) {
        setStatusLine('Hard refresh detected. Resetting the SDR session to idle...')
        try {
          await stopSession()
        } catch {
          // ignore stop failures during reload recovery
        }
      }

      try {
        await loadAll()
        if (!cancelled && initialReloadNavigation) {
          setStatusLine('Refresh reset complete. SDR is idle until you click Start Session.')
        }
      } catch {
        // loadAll already sets error state
      } finally {
        if (!cancelled) {
          setReloadSettling(false)
          timer = setInterval(() => {
            loadAll().catch(() => null)
          }, SESSION_CONFIG.pollIntervalMs || 3000)
        }
      }
    }

    initialize()

    return () => {
      cancelled = true
      if (timer) clearInterval(timer)
    }
  }, [])

  useEffect(() => {
    const stopLiveSession = () => {
      try {
        const body = new Blob([], { type: 'application/json' })
        if (navigator.sendBeacon) {
          navigator.sendBeacon(`${API_BASE}/api/system/stop`, body)
          return
        }
      } catch {
        // fall through
      }
      try {
        fetch(`${API_BASE}/api/system/stop`, {
          method: 'POST',
          keepalive: true,
          headers: { 'Content-Type': 'application/json' },
        }).catch(() => {})
      } catch {
        // ignore unload stop errors
      }
    }

    const handlePageHide = () => {
      stopLiveSession()
    }

    window.addEventListener('pagehide', handlePageHide)
    return () => {
      window.removeEventListener('pagehide', handlePageHide)
    }
  }, [])

  useEffect(() => {
    setTargetFreq(getDefaultFrequencyForTab(activeTab))
  }, [activeTab])

  useEffect(() => {
    if (SDR_HKRF_TAB_KEYS.has(activeTab)) {
      setActiveSdrTab(activeTab)
    }
  }, [activeTab])

  useEffect(() => {
    try {
      window.sessionStorage.setItem('ghostredrecon:active-tab', activeTab)
    } catch {
      // ignore storage failures
    }
  }, [activeTab])

  useEffect(() => {
    try {
      window.sessionStorage.setItem('ghostredrecon:mode', mode)
    } catch {
      // ignore sessionStorage failures
    }
  }, [mode])


  useEffect(() => {
    const operationalTabs = ['SUB-GHZ', 'BLE', 'LORA', 'ZIGBEE', 'IOT', 'WIFI']
    if (!operationalTabs.includes(activeTab) || reloadSettling) {
      setSweepState((current) => (operationalTabs.includes(current?.tab) ? null : current))
      return
    }
    let cancelled = false
    async function loadSweepState() {
      try {
        const payload = await fetchSdrSweepState(activeTab)
        if (!cancelled) {
          setSweepState(payload?.sweep?.state || null)
        }
      } catch {
        if (!cancelled) {
          setSweepState(null)
        }
      }
    }

    loadSweepState()
    const timer = window.setInterval(loadSweepState, 1500)

    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [activeTab, reloadSettling])

  async function handleStart(freqMHz) {
    if (reloadSettling) {
      setStatusLine('Refresh reset is still in progress. Wait for the SDR to return to idle.')
      setError('Refresh reset is still in progress. Wait for the SDR to return to idle.')
      return
    }
    if (startBlocked) {
      setStatusLine('SDR not connected. Please connect SDR.')
      setError('SDR not connected. Please connect SDR.')
      return
    }
    setBusy(true)
    try {
      await startSession(freqMHz)
      const dashboard = await loadAllUntil((next) => !!next?.rfHealth?.sdr_streaming_confirmed)
      if (!dashboard?.rfHealth?.sdr_streaming_confirmed) {
        setStatusLine(`Session start failed to verify stream at ${freqMHz} MHz`)
        setError(dashboard?.rfHealth?.sdr_fault_reason || 'SDR session did not reach verified streaming state.')
        await stopSession()
        await loadAll()
        return
      }
      setStatusLine(`Session started and verified at ${freqMHz} MHz`)
    } catch (err) {
      setStatusLine(`Start failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleRetune(freqMHz) {
    if (reloadSettling) {
      setStatusLine('Refresh reset is still in progress. Wait for the SDR to return to idle.')
      setError('Refresh reset is still in progress. Wait for the SDR to return to idle.')
      return
    }
    if (startBlocked) {
      setStatusLine('SDR not connected. Please connect SDR.')
      setError('SDR not connected. Please connect SDR.')
      return
    }
    setBusy(true)
    try {
      await retuneSession(freqMHz)
      setStatusLine(`Retuned to ${freqMHz} MHz`)
      await loadAll()
    } catch (err) {
      setStatusLine(`Retune failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleOperationalTune(freqMHz, label) {
    if (reloadSettling) {
      setStatusLine('Refresh reset is still in progress. Wait for the SDR to return to idle.')
      setError('Refresh reset is still in progress. Wait for the SDR to return to idle.')
      return
    }
    if (startBlocked) {
      setStatusLine(sdrRuntimeWarning || 'SDR preflight failed.')
      setError(sdrRuntimeWarning || 'SDR preflight failed.')
      return
    }
    if (!system?.session_active) {
      setStatusLine('Start Session first. Tune controls only retune an active SDR session.')
      setError('Start Session first. Tune controls only retune an active SDR session.')
      return
    }
    setBusy(true)
    try {
      await retuneSession(freqMHz)
      setStatusLine(`${label} active at ${freqMHz} MHz`)
      setTargetFreq(String(freqMHz))
      lastAutoTuneRef.current = `${activeTab}:${freqMHz}`
      await loadAll()
    } catch (err) {
      setStatusLine(`${label} failed: ${err.message}`)
      setError(String(err.message || err))
      lastAutoTuneRef.current = ''
    } finally {
      setBusy(false)
    }
  }

  async function handleStop() {
    setBusy(true)
    try {
      await stopSession()
      lastAutoTuneRef.current = ''
      setStatusLine('Session stopped')
      await loadAll()
    } catch (err) {
      setStatusLine(`Stop failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleRestartBackend() {
    setBusy(true)
    try {
      setStatusLine('Restarting backend and resetting the session to idle...')
      setError('')
      setReloadSettling(true)
      setSweepState(null)
      setSelectedSignal(null)
      setSelectedDevice(null)
      setSweepResetNonceByTab({
        'SUB-GHZ': Date.now(),
        BLE: Date.now(),
        LORA: Date.now(),
        ZIGBEE: Date.now(),
        IOT: Date.now(),
        WIFI: Date.now(),
      })
      await restartBackend().catch(() => null)
      let dashboard = null
      for (let attempt = 0; attempt < 12; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, attempt < 2 ? 1200 : 1000))
        try {
          dashboard = await loadAll()
          if (dashboard?.system && dashboard?.rfHealth) {
            break
          }
        } catch {
          // keep polling until backend returns
        }
      }
      setStatusLine(dashboard?.system?.session_active
        ? 'Backend restarted. Session is still active.'
        : 'Backend restarted. Session reset to idle.')
    } catch (err) {
      setStatusLine(`Backend restart failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setReloadSettling(false)
      setBusy(false)
    }
  }

  async function handleRunSweep(tab, options = {}) {
    if (reloadSettling) {
      setStatusLine('Refresh reset is still in progress. Wait for the SDR to return to idle.')
      setError('Refresh reset is still in progress. Wait for the SDR to return to idle.')
      return
    }
    if (!system?.session_active || !streamingConfirmed) {
      setStatusLine('Start Session first. Sweep controls remain locked until SDR streaming is verified.')
      setError('Start Session first. Sweep controls remain locked until SDR streaming is verified.')
      return
    }
    try {
      setBusy(true)
      const payload = await startSdrSweep(tab, options)
      const nextState = payload?.sweep?.state || null
      setSweepState(nextState)
      setSweepResetNonceByTab((current) => ({ ...current, [tab]: (current[tab] || 0) + 1 }))
      setSweepNonceByTab((current) => ({ ...current, [tab]: (current[tab] || 0) + 1 }))
      if (payload?.status === 'blocked') {
        const message = payload?.capability?.reason || payload?.error || `${tab} sweep is not available on this host.`
        setStatusLine(message)
        setError(message)
        return
      }
      setError('')
      if (tab === 'BLE' && Number(options?.durationMinutes || 0) > 0) {
        setStatusLine(`${tab} backend sweep started for ${options.durationMinutes} minute(s).`)
      } else {
        setStatusLine(`${tab} backend sweep started.`)
      }
    } catch (err) {
      setStatusLine(`${tab} sweep start failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleClearSweepResults(tab) {
    try {
      setBusy(true)
      await clearSdrSweep(tab)
      setSweepState((current) => (current?.tab === tab ? null : current))
      setSweepResetNonceByTab((current) => ({ ...current, [tab]: (current[tab] || 0) + 1 }))
      setStatusLine(`${tab} sweep results cleared.`)
      setError('')
    } catch (err) {
      setStatusLine(`${tab} clear failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStopSweep(tab) {
    try {
      setBusy(true)
      const payload = await stopSdrSweep(tab)
      setSweepState(payload?.sweep?.state || null)
      setStatusLine(`${tab} sweep stopped by operator.`)
      setError('')
    } catch (err) {
      setStatusLine(`${tab} stop failed: ${err.message}`)
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  function handlePivotTab(tabLabel) {
    const normalized = String(tabLabel || '').toUpperCase()
    if (normalized.includes('BLUETOOTH')) {
      setActiveTab('BLE')
      setStatusLine('WB Hunt pivoted to Bluetooth. Review the tab and run a sweep when ready.')
      return
    }
    if (normalized.includes('ZIGBEE')) {
      setActiveTab('ZIGBEE')
      setStatusLine('WB Hunt pivoted to Zigbee. Review the tab and run a sweep when ready.')
      return
    }
    if (normalized.includes('WIFI')) {
      setActiveTab('WIFI')
      setStatusLine('WB Hunt pivoted to WiFi. Review the tab and run a sweep when ready.')
      return
    }
    if (normalized.includes('LORA')) {
      setActiveTab('LORA')
      setStatusLine('WB Hunt pivoted to LoRa. Review the tab and run a sweep when ready.')
      return
    }
    if (normalized.includes('433/868') || normalized.includes('SUB-GHZ')) {
      setActiveTab('ISM-DECODER')
      setStatusLine('WB Hunt pivoted to 433/868 Decoder. Review the decoder tab and start decode when ready.')
      return
    }
    if (normalized.includes('SIGNAL LAB')) {
      setActiveTab('SIGNAL-LAB')
      setStatusLine('WB Hunt pivoted to Signal Lab. Review the tab and inspect captures when ready.')
      return
    }
  }

  function renderActiveView() {
    const liveOperationalSignals = streamingConfirmed ? filteredSignals : []
    const liveOperationalDevices = streamingConfirmed ? devices : []
    const liveOperationalFft = streamingConfirmed ? fft : []
    const liveOperationalFftTimestamp = streamingConfirmed ? fftTimestamp : null

    if (activeTab === 'HOME') {
      return (
        <HomeView
          layoutMode={layoutMode}
          mode={mode}
                    onNavigate={setActiveTab}
          system={system}
          rfHealth={rfHealth}
          signals={signals}
          devices={devices}
          fft={fft}
          fftTimestamp={fftTimestamp}
          diagnostics={diagnostics}
          selectedSignal={selectedSignal}
          selectedDevice={selectedDevice}
          onSelectSignal={setSelectedSignal}
          onSelectDevice={setSelectedDevice}
          lastStreamUpdate={lastStreamUpdate}
          error={error}
          apiBase={API_BASE}
          integrations={integrations}
        />
      )
    }

    if (activeTab === 'DEVICES') {
      return <DevicesView devices={devices} selectedDevice={selectedDevice} onSelectDevice={setSelectedDevice} />
    }


    if (activeTab === 'MANUAL') {
      return <ManualView mode={mode} layoutMode={layoutMode} />
    }

    if (activeTab === 'SETTINGS') {
      return <SettingsView diagnostics={diagnostics} identities={identities} integrations={integrations} layoutMode={layoutMode} />
    }

    if (activeTab === 'SUB-GHZ') {
      return <SubGhzView layoutMode={layoutMode} signals={liveOperationalSignals} devices={liveOperationalDevices} fft={liveOperationalFft} fftTimestamp={liveOperationalFftTimestamp} system={system} rfHealth={rfHealth} busy={busy} onTune={handleOperationalTune} selectedSignal={selectedSignal} selectedDevice={selectedDevice} onSelectSignal={setSelectedSignal} onSelectDevice={setSelectedDevice} lastStreamUpdate={lastStreamUpdate} sweepState={sweepState} sweepResetNonce={sweepResetNonceByTab['SUB-GHZ'] || 0} onRunSweep={() => handleRunSweep('SUB-GHZ')} onStopSweep={() => handleStopSweep('SUB-GHZ')} onClearSweepResults={() => handleClearSweepResults('SUB-GHZ')} />
    }

    if (activeTab === 'BLE') {
      return <BleView layoutMode={layoutMode} mode={mode} signals={liveOperationalSignals} devices={liveOperationalDevices} fft={liveOperationalFft} fftTimestamp={liveOperationalFftTimestamp} system={system} rfHealth={rfHealth} busy={busy} onTune={handleOperationalTune} selectedSignal={selectedSignal} selectedDevice={selectedDevice} onSelectSignal={setSelectedSignal} onSelectDevice={setSelectedDevice} lastStreamUpdate={lastStreamUpdate} sweepState={sweepState} sweepResetNonce={sweepResetNonceByTab['BLE'] || 0} onRunSweep={(options) => handleRunSweep('BLE', options)} onStopSweep={() => handleStopSweep('BLE')} onClearSweepResults={() => handleClearSweepResults('BLE')} />
    }

    if (activeTab === 'LORA') {
      return <LoraView layoutMode={layoutMode} signals={liveOperationalSignals} devices={liveOperationalDevices} fft={liveOperationalFft} fftTimestamp={liveOperationalFftTimestamp} system={system} rfHealth={rfHealth} busy={busy} onTune={handleOperationalTune} selectedSignal={selectedSignal} selectedDevice={selectedDevice} onSelectSignal={setSelectedSignal} onSelectDevice={setSelectedDevice} lastStreamUpdate={lastStreamUpdate} sweepState={sweepState} sweepResetNonce={sweepResetNonceByTab['LORA'] || 0} onRunSweep={() => handleRunSweep('LORA')} onStopSweep={() => handleStopSweep('LORA')} onClearSweepResults={() => handleClearSweepResults('LORA')} />
    }

    if (activeTab === 'ZIGBEE') {
      return <ZigbeeView layoutMode={layoutMode} signals={liveOperationalSignals} devices={liveOperationalDevices} fft={liveOperationalFft} fftTimestamp={liveOperationalFftTimestamp} system={system} rfHealth={rfHealth} busy={busy} onTune={handleOperationalTune} selectedSignal={selectedSignal} selectedDevice={selectedDevice} onSelectSignal={setSelectedSignal} onSelectDevice={setSelectedDevice} lastStreamUpdate={lastStreamUpdate} sweepState={sweepState} sweepResetNonce={sweepResetNonceByTab['ZIGBEE'] || 0} onRunSweep={() => handleRunSweep('ZIGBEE')} onStopSweep={() => handleStopSweep('ZIGBEE')} onClearSweepResults={() => handleClearSweepResults('ZIGBEE')} />
    }

    if (activeTab === 'WIFI') {
      return <WifiView layoutMode={layoutMode} signals={liveOperationalSignals} devices={liveOperationalDevices} fft={liveOperationalFft} fftTimestamp={liveOperationalFftTimestamp} system={system} rfHealth={rfHealth} busy={busy} onTune={handleOperationalTune} selectedSignal={selectedSignal} selectedDevice={selectedDevice} onSelectSignal={setSelectedSignal} onSelectDevice={setSelectedDevice} lastStreamUpdate={lastStreamUpdate} sweepState={sweepState} sweepResetNonce={sweepResetNonceByTab['WIFI'] || 0} onRunSweep={() => handleRunSweep('WIFI')} onStopSweep={() => handleStopSweep('WIFI')} onClearSweepResults={() => handleClearSweepResults('WIFI')} />
    }

    if (activeTab === 'WIFI-MK7') {
      return <WifiMk7View layoutMode={layoutMode} mode={mode} onPivot={handlePivotTab} />
    }

    if (activeTab === 'CAMERA-HUNT') {
      return <WifiMk7View layoutMode={layoutMode} mode={mode} onPivot={handlePivotTab} cameraOnly />
    }

    if (activeTab === 'BLE-NR5') {
      return <BleNr5View layoutMode={layoutMode} mode={mode} />
    }

    if (activeTab === 'HUNT-DRONES') {
      return <HuntDronesView layoutMode={layoutMode} mode={mode} onHeaderContextChange={setViewHeaderContext} />
    }

    if (activeTab === 'WB-HUNT') {
      return <WbHuntView onPivot={handlePivotTab} />
    }

    if (activeTab === 'IOT') {
      return <IotView layoutMode={layoutMode} signals={liveOperationalSignals} devices={liveOperationalDevices} fft={liveOperationalFft} fftTimestamp={liveOperationalFftTimestamp} system={system} rfHealth={rfHealth} busy={busy} onTune={handleOperationalTune} selectedSignal={selectedSignal} selectedDevice={selectedDevice} onSelectSignal={setSelectedSignal} onSelectDevice={setSelectedDevice} lastStreamUpdate={lastStreamUpdate} sweepState={sweepState} sweepResetNonce={sweepResetNonceByTab['IOT'] || 0} onRunSweep={() => handleRunSweep('IOT')} onStopSweep={() => handleStopSweep('IOT')} onClearSweepResults={() => handleClearSweepResults('IOT')} />
    }

    if (activeTab === 'ISM-DECODER') {
      return <IsmDecoderView />
    }

    if (activeTab === 'SIGNAL-LAB') {
      return <SignalLabView />
    }

    if (activeTab === 'KISMET-FUSION') {
      return <KismetFusionView />
    }

    return null
  }

  return (
    <div className="shell" data-mode="RED" data-layout-mode="laptop">
      <HeroHeader
        statusLine={statusLine}
        busy={busy}
        eyebrow="RF RED TEAM OPERATIONS"
        title="Radio Frequency RED TEAM Intelligence Platform"
        blockReason={reloadSettling ? 'Refresh reset in progress. Wait for idle state.' : (activePrimaryTab === TABS.SDR_HKRF.key && startBlocked ? sdrRuntimeWarning : '')}
        operatorMessage={operatorMessage}
        hardwareStatus={hardwareStatusItems}
        commandRail={commandRail}
        workspaceLabel={activePrimaryTab === TABS.SDR_HKRF.key ? `SDR HKRF / ${activeTab}` : activePrimaryTab}
        workspaceDetail="RED operator context"
        backendState={busy ? 'BUSY' : 'READY'}
        apiBase={API_BASE}
        contextSummary={viewHeaderContext}
      />

      <nav className="tabbar primary-tabbar">
        {PRIMARY_TABS.map((tab) => (
          <button
            key={tab.key}
            className={tab.key === activePrimaryTab ? 'tab active' : 'tab'}
            onClick={() => handlePrimaryTabSelect(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {activePrimaryTab === TABS.SDR_HKRF.key ? (
        <nav className="tabbar subtabbar">
          {SDR_HKRF_TABS.map((tab) => (
            <button
              key={tab.key}
              className={tab.key === activeTab ? 'tab active' : 'tab'}
              onClick={() => handleSdrSubTabSelect(tab.key)}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      ) : null}

      {degradedModules.length > 0 && (
        <section className="error-banner soft-warning">
          Optional runtime modules degraded: {degradedModules.map(([name]) => name).join(', ')}. Core API remains online.
        </section>
      )}

      {sdrFeatureEnabled && sdrRuntimeWarning && !nativePlatformTabActive && (
        <section className="error-banner soft-warning">
          {sdrRuntimeWarning}
        </section>
      )}

      <ErrorBoundary resetKey={`${activeTab}:${sweepNonceByTab[activeTab] || 0}:${sweepResetNonceByTab[activeTab] || 0}`}>
        {renderActiveView()}
      </ErrorBoundary>

      <footer className="footer">
        <div>{BRANDING.developed} / Backend {API_BASE}</div>
        <a
          className="footer-link"
          href={BRANDING.supportUrl}
          target="_blank"
          rel="noreferrer"
        >
          {BRANDING.support}
        </a>
      </footer>
    </div>
  )
}
