import { API_BASE } from './runtime'

function markBackendRestartWindow(milliseconds = 16000) {
  try {
    window.__ghostreconBackendRestartUntil = Date.now() + milliseconds
  } catch {
    // ignore
  }
}

function isBackendRestartWindowActive() {
  try {
    return Number(window.__ghostreconBackendRestartUntil || 0) > Date.now()
  } catch {
    return false
  }
}

function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

async function request(path, options = {}) {
  const method = String(options?.method || 'GET').toUpperCase()
  const restartWindow = isBackendRestartWindowActive()
  const retryableRequest = method === 'GET' || path.includes('/restart_backend') || restartWindow
  const maxAttempts = retryableRequest ? (restartWindow ? 18 : 8) : 1
  let lastError = null

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const response = await fetch(`${API_BASE}${path}`, {
        headers: { 'Content-Type': 'application/json' },
        ...options,
      })

      if (!response.ok) {
        const body = await response.text()
        const retryableStatus = retryableRequest && [502, 503, 504].includes(response.status)
        if (retryableStatus && attempt < maxAttempts) {
          await sleep(Math.min(1800, 250 * attempt))
          continue
        }
        throw new Error(body || `${response.status}`)
      }

      return response.json()
    } catch (error) {
      lastError = error
      const isNetworkFailure = error instanceof TypeError || /Failed to fetch|NetworkError|Load failed/i.test(String(error?.message || error))
      if (retryableRequest && isNetworkFailure && attempt < maxAttempts) {
        await sleep(Math.min(1800, 250 * attempt))
        continue
      }
      if (isNetworkFailure) {
        throw new Error('Backend is restarting or temporarily unreachable. Retry in a few seconds.')
      }
      throw error
    }
  }

  throw lastError || new Error('Backend request failed.')
}

export async function fetchDashboardState() {
  const [system, rfHealth, intelTop, devices, liveFft, diagnostics, identities] = await Promise.all([
    request('/api/system/state'),
    request('/api/rf/health'),
    request('/api/intel/top?limit=50'),
    request('/api/devices'),
    request('/api/live/fft'),
    request('/api/system/diagnostics'),
    request('/api/system/identities'),
  ])

  return {
    system,
    rfHealth,
    signals: intelTop.signals || [],
    devices: devices.devices || [],
    fft: liveFft.bins || [],
    fftTimestamp: liveFft.fft_frame_timestamp || null,
    diagnostics,
    identities: identities.identities || [],
  }
}


export function fetchBandIntel(band) {
  return request(`/api/intel/band/${encodeURIComponent(band)}?limit=250`)
}

export function startSdrSweep(band, options = {}) {
  const durationMinutes = Number(options?.durationMinutes || 0)
  return request(
    `/api/intel/sweep/start?band=${encodeURIComponent(band)}&duration_minutes=${encodeURIComponent(durationMinutes)}`,
    { method: 'POST' },
  )
}

export function stopSdrSweep(band) {
  return request(`/api/intel/sweep/stop?band=${encodeURIComponent(band)}`, { method: 'POST' })
}

export function clearSdrSweep(band) {
  return request(`/api/intel/sweep/clear?band=${encodeURIComponent(band)}`, { method: 'POST' })
}

export function fetchSdrSweepState(band) {
  return request(`/api/intel/sweep/state?band=${encodeURIComponent(band)}`)
}

export function fetchBleDecoderStatus() {
  return request('/api/intel/ble/decoder/status')
}

export function startBleDecoder() {
  return request('/api/intel/ble/decoder/start', { method: 'POST' })
}

export function stopBleDecoder() {
  return request('/api/intel/ble/decoder/stop', { method: 'POST' })
}

export function clearBleDecoder() {
  return request('/api/intel/ble/decoder/clear', { method: 'POST' })
}

export function fetchCorrelations() {
  return request('/api/intel/correlations')
}

export function fetchSignalDetail(signalId) {
  return request(`/api/intel/signal/${encodeURIComponent(signalId)}`)
}

export function fetchIntelDeviceDetail(deviceId) {
  return request(`/api/intel/device/${encodeURIComponent(deviceId)}`)
}

export function startSession(freqMHz) {
  return request(`/api/system/start?freq_mhz=${encodeURIComponent(freqMHz)}`, { method: 'POST' })
}

export function retuneSession(freqMHz) {
  return request(`/api/system/retune?freq_mhz=${encodeURIComponent(freqMHz)}`, { method: 'POST' })
}

export function stopSession() {
  return request('/api/system/stop', { method: 'POST' })
}

export function restartBackend() {
  markBackendRestartWindow()
  return request('/api/system/restart_backend', { method: 'POST' })
}

export function fetchIntegrationStatus(kind) {
  return request(`/api/integrations/${encodeURIComponent(kind)}`)
}

export function fetchWiFiMk7Status(prepare = false, light = false) {
  return request(`/api/wifi_mk7/status?prepare=${encodeURIComponent(prepare)}&light=${encodeURIComponent(light)}`)
}

export function fetchWiFiMk7OperatorSnapshot({
  prepare = false,
  light = false,
  includeData = true,
  includeRedTeam = false,
} = {}) {
  return request(
    `/api/wifi_mk7/operator_snapshot?prepare=${encodeURIComponent(prepare)}&light=${encodeURIComponent(light)}&include_data=${encodeURIComponent(includeData)}&include_redteam=${encodeURIComponent(includeRedTeam)}`,
  )
}

export function fetchWiFiMk7RedTeamStatus() {
  return request('/api/wifi_mk7/redteam/status')
}

export function runWiFiMk7RedTeamPreflight({
  targetId = '',
  actionType = 'deauth_evidence_probe',
  confirmAuthorizedLab = false,
  channel = 0,
} = {}) {
  return request(
    `/api/wifi_mk7/redteam/preflight?target_id=${encodeURIComponent(targetId)}&action_type=${encodeURIComponent(actionType)}&confirm_authorized_lab=${encodeURIComponent(confirmAuthorizedLab)}&channel=${encodeURIComponent(channel)}`,
    { method: 'POST' },
  )
}

export function runWiFiMk7RedTeamValidation({
  targetId = '',
  actionType = 'deauth_evidence_probe',
  confirmAuthorizedLab = false,
  channel = 0,
  maxDuration = 30,
  maxFrameCount = 3,
  reasonCode = '7',
  notes = '',
} = {}) {
  return request(
    `/api/wifi_mk7/redteam/run?target_id=${encodeURIComponent(targetId)}&action_type=${encodeURIComponent(actionType)}&confirm_authorized_lab=${encodeURIComponent(confirmAuthorizedLab)}&channel=${encodeURIComponent(channel)}&max_duration=${encodeURIComponent(maxDuration)}&max_frame_count=${encodeURIComponent(maxFrameCount)}&reason_code=${encodeURIComponent(reasonCode)}&notes=${encodeURIComponent(notes)}`,
    { method: 'POST' },
  )
}

export function fetchWiFiMk7AdversaryReplayStatus() {
  return request('/api/wifi_mk7/adversary_replay/status')
}

export function runWiFiMk7AdversaryReplay({
  capturePath = '',
  confirmAuthorizedLab = false,
  replayLabel = '',
  resetBeforeReplay = true,
} = {}) {
  return request(
    `/api/wifi_mk7/adversary_replay/run?capture_path=${encodeURIComponent(capturePath)}&confirm_authorized_lab=${encodeURIComponent(confirmAuthorizedLab)}&replay_label=${encodeURIComponent(replayLabel)}&reset_before_replay=${encodeURIComponent(resetBeforeReplay)}`,
    { method: 'POST' },
  )
}

export function fetchBleNr5Status() {
  return request('/api/ble_nr5/status')
}

export function fetchHuntDronesStatus() {
  return request('/api/hunt_drones/status')
}

export function startHuntDronesSession({
  sessionName = 'Hunt Drones Session',
  operator = '',
  location = '',
  notes = '',
  scanProfile = 'passive_standard',
  evidencePath = '',
} = {}) {
  return request('/api/hunt_drones/start', {
    method: 'POST',
    body: JSON.stringify({
      session_name: sessionName,
      operator,
      location,
      notes,
      scan_profile: scanProfile,
      evidence_path: evidencePath,
    }),
  })
}

export function stopHuntDronesSession() {
  return request('/api/hunt_drones/stop', { method: 'POST' })
}

export function clearHuntDronesSession() {
  return request('/api/hunt_drones/clear', { method: 'POST' })
}

export function deleteHuntDronesData() {
  return request('/api/hunt_drones/delete', { method: 'POST' })
}

export function runHuntDronesScan() {
  return request('/api/hunt_drones/scan', { method: 'POST' })
}

export function fetchHuntDronesLive() {
  return request('/api/hunt_drones/live')
}

export function fetchHuntDronesDetections() {
  return request('/api/hunt_drones/detections')
}

export function fetchHuntDronesTimeline() {
  return request('/api/hunt_drones/timeline')
}

export function fetchHuntDronesOperatorLog() {
  return request('/api/hunt_drones/operator_log')
}

export function fetchHuntDronesTopology() {
  return request('/api/hunt_drones/topology')
}

export function fetchHuntDronesReports() {
  return request('/api/hunt_drones/reports')
}

export function fetchHuntDronesSettings() {
  return request('/api/hunt_drones/settings')
}

export function fetchHuntDronesEvidence() {
  return request('/api/hunt_drones/evidence')
}

export function fetchHuntDronesTargetDetail(targetId) {
  return request(`/api/hunt_drones/targets/${encodeURIComponent(targetId)}`)
}

export function fetchHuntDronesReplaySessions() {
  return request('/api/hunt_drones/replay_sessions')
}

export function loadHuntDronesReplaySession(sessionId) {
  return request('/api/hunt_drones/replay_load', {
    method: 'POST',
    body: JSON.stringify({ session_id: sessionId }),
  })
}

export function requestHuntDronesCapability(capability) {
  return request('/api/hunt_drones/capability', {
    method: 'POST',
    body: JSON.stringify({ capability }),
  })
}

export function startBleNr5Session({
  profile = 'production_monitoring',
  mission = 'asset_discovery',
  labMode = false,
  classicSidecar = false,
  sensorIds = [],
} = {}) {
  return request(
    `/api/ble_nr5/start?profile=${encodeURIComponent(profile)}&mission=${encodeURIComponent(mission)}&lab_mode=${encodeURIComponent(labMode)}&classic_sidecar=${encodeURIComponent(classicSidecar)}&sensor_ids=${encodeURIComponent(sensorIds.join(','))}`,
    { method: 'POST' },
  )
}

export function stopBleNr5Session() {
  return request('/api/ble_nr5/stop', { method: 'POST' })
}

export function clearBleNr5Session() {
  return request('/api/ble_nr5/clear', { method: 'POST' })
}

export function runBleNr5Scan(durationSeconds = 8) {
  return request(`/api/ble_nr5/scan?duration_seconds=${encodeURIComponent(durationSeconds)}`, { method: 'POST' })
}

export function startBleNr5LiveHunt({ scanSeconds = 60 } = {}) {
  return request(`/api/ble_nr5/live_hunt/start?scan_seconds=${encodeURIComponent(scanSeconds)}`, { method: 'POST' })
}

export function stopBleNr5LiveHunt() {
  return request('/api/ble_nr5/live_hunt/stop', { method: 'POST' })
}

export function fetchBleNr5Devices() {
  return request('/api/ble_nr5/devices')
}

export function fetchBleNr5Queue() {
  return request('/api/ble_nr5/queue')
}

export function fetchBleNr5Timeline(limit = 80) {
  return request(`/api/ble_nr5/timeline?limit=${encodeURIComponent(limit)}`)
}

export function fetchBleNr5Knowledge() {
  return request('/api/ble_nr5/knowledge')
}

export function fetchBleNr5ValidationFramework() {
  return request('/api/ble_nr5/validation_framework')
}

export function fetchBleNr5ValidationRuns(deviceKey = '') {
  return request(`/api/ble_nr5/validation_runs?device_key=${encodeURIComponent(deviceKey)}`)
}

export function fetchBleNr5Tasks() {
  return request('/api/ble_nr5/tasks')
}

export function setBleNr5Workflow({ deviceKey = '', workflow = 'monitor', notes = '' } = {}) {
  return request('/api/ble_nr5/workflow', {
    method: 'POST',
    body: JSON.stringify({
      device_key: deviceKey,
      workflow,
      notes,
    }),
  })
}

export function recordBleNr5ValidationResult({
  deviceKey = '',
  pairableVerdict = 'unknown',
  legacyPinRisk = 'unknown',
  manualResult = 'unknown',
  notes = '',
} = {}) {
  return request('/api/ble_nr5/validate_result', {
    method: 'POST',
    body: JSON.stringify({
      device_key: deviceKey,
      pairable_verdict: pairableVerdict,
      legacy_pin_risk: legacyPinRisk,
      manual_result: manualResult,
      notes,
    }),
  })
}

export function runActiveBleNr5Validation({ deviceKey = '' } = {}) {
  return request('/api/ble_nr5/active_validate', {
    method: 'POST',
    body: JSON.stringify({
      device_key: deviceKey,
    }),
  })
}

export function runBleNr5ValidationSuite({
  deviceKey = '',
  scenarioIds = [],
  ownedTarget = false,
  notes = '',
} = {}) {
  return request('/api/ble_nr5/validation_suite', {
    method: 'POST',
    body: JSON.stringify({
      device_key: deviceKey,
      scenario_ids: scenarioIds,
      owned_target: ownedTarget,
      notes,
    }),
  })
}

export function runBleNr5GattTest({
  deviceKey = '',
  notes = '',
  ownedTarget = false,
} = {}) {
  return request('/api/ble_nr5/gatt_test', {
    method: 'POST',
    body: JSON.stringify({
      device_key: deviceKey,
      notes,
      owned_target: ownedTarget,
    }),
  })
}

export function runBleNr5HardTest({
  deviceKey = '',
  notes = '',
  ownedTarget = false,
} = {}) {
  return request('/api/ble_nr5/hard_test', {
    method: 'POST',
    body: JSON.stringify({
      device_key: deviceKey,
      notes,
      owned_target: ownedTarget,
    }),
  })
}

export function startWiFiMk7Session({
  bands = ['2.4ghz', '5ghz'],
  dwellMs = 250,
  durationSeconds = 60,
  scanMode = 'broad',
  scanScenario = 'passive_observation',
  lockedChannels = [],
  interfaces = [],
  cameraHunt = false,
  processingEnabled = true,
} = {}) {
  return request(
    `/api/wifi_mk7/start?bands=${encodeURIComponent(bands.join(','))}&dwell_ms=${encodeURIComponent(dwellMs)}&duration_seconds=${encodeURIComponent(durationSeconds)}&scan_mode=${encodeURIComponent(scanMode)}&scan_scenario=${encodeURIComponent(scanScenario)}&locked_channels=${encodeURIComponent(lockedChannels.join(','))}&interfaces=${encodeURIComponent(interfaces.join(','))}&camera_hunt=${encodeURIComponent(cameraHunt)}&processing_enabled=${encodeURIComponent(processingEnabled)}`,
    { method: 'POST' },
  )
}

export function stopWiFiMk7Session() {
  return request('/api/wifi_mk7/stop', { method: 'POST' })
}

export function clearWiFiMk7Session() {
  return request('/api/wifi_mk7/clear', { method: 'POST' })
}

export function runWiFiMk7Sweep({
  bands = ['2.4ghz', '5ghz'],
  dwellMs = 250,
  scanMode = 'broad',
  scanScenario = 'passive_observation',
  lockedChannels = [],
  interfaces = [],
  cameraHunt = false,
} = {}) {
  return request(
    `/api/wifi_mk7/sweep?bands=${encodeURIComponent(bands.join(','))}&dwell_ms=${encodeURIComponent(dwellMs)}&scan_mode=${encodeURIComponent(scanMode)}&scan_scenario=${encodeURIComponent(scanScenario)}&locked_channels=${encodeURIComponent(lockedChannels.join(','))}&interfaces=${encodeURIComponent(interfaces.join(','))}&camera_hunt=${encodeURIComponent(cameraHunt)}`,
    { method: 'POST' },
  )
}

export function fetchWiFiMk7Networks() {
  return request('/api/wifi_mk7/networks')
}

export function fetchWiFiMk7Clients() {
  return request('/api/wifi_mk7/clients')
}

export function fetchWiFiMk7Targets() {
  return request('/api/wifi_mk7/targets')
}

export function fetchWiFiMk7CameraHuntStatus() {
  return request('/api/wifi_mk7/camera_hunt/status')
}

export function fetchWiFiMk7CameraHuntResults() {
  return request('/api/wifi_mk7/camera_hunt/results')
}

export function fetchWiFiMk7Pcap() {
  return request('/api/wifi_mk7/pcap')
}

export function fetchWiFiMk7Channels() {
  return request('/api/wifi_mk7/channels')
}

export function fetchWiFiMk7ChannelsLight() {
  return request('/api/wifi_mk7/channels?light=true')
}

export function runWiFiMk7ServiceAudit({ targetId = '', allowInfrastructure = false } = {}) {
  return request(
    `/api/wifi_mk7/service_audit?target_id=${encodeURIComponent(targetId)}&allow_infrastructure=${encodeURIComponent(allowInfrastructure)}`,
    { method: 'POST' },
  )
}

export function runWiFiMk7HardAudit({ targetId = '', allowInfrastructure = false } = {}) {
  return request(
    `/api/wifi_mk7/hard_audit?target_id=${encodeURIComponent(targetId)}&allow_infrastructure=${encodeURIComponent(allowInfrastructure)}`,
    { method: 'POST' },
  )
}

export function runWiFiMk7ImportedAnalysis({ capturePath = '', replay = false } = {}) {
  return request(
    `/api/wifi_mk7/imported_analysis?capture_path=${encodeURIComponent(capturePath)}&replay=${encodeURIComponent(replay)}`,
    { method: 'POST' },
  )
}

export function analyzeWiFiMk7CameraLead({ leadId = '', seconds = 30 } = {}) {
  return request(
    `/api/wifi_mk7/camera_hunt/analyze_lead?lead_id=${encodeURIComponent(leadId)}&seconds=${encodeURIComponent(seconds)}`,
    { method: 'POST' },
  )
}

export function probeWiFiMk7CameraLead({ leadId = '' } = {}) {
  return request(
    `/api/wifi_mk7/camera_hunt/probe_lead?lead_id=${encodeURIComponent(leadId)}`,
    { method: 'POST' },
  )
}

export function probeWiFiMk7CameraIp({ ip = '' } = {}) {
  return request(
    `/api/wifi_mk7/camera_hunt/probe_ip?ip=${encodeURIComponent(ip)}`,
    { method: 'POST' },
  )
}

export function hardAuditWiFiMk7CameraLead({ leadId = '', seconds = 30 } = {}) {
  return request(
    `/api/wifi_mk7/camera_hunt/hard_audit?lead_id=${encodeURIComponent(leadId)}&seconds=${encodeURIComponent(seconds)}`,
    { method: 'POST' },
  )
}

export function auditLayersWiFiMk7CameraLead({ leadId = '' } = {}) {
  return request(
    `/api/wifi_mk7/camera_hunt/audit_layers?lead_id=${encodeURIComponent(leadId)}`,
    { method: 'POST' },
  )
}

export function startWiFiMk7VideoTruthTest({ leadId = '', seconds = 40 } = {}) {
  return request(
    `/api/wifi_mk7/camera_hunt/video_truth_test?lead_id=${encodeURIComponent(leadId)}&seconds=${encodeURIComponent(seconds)}`,
    { method: 'POST' },
  )
}

export function startRtl433(freqMHz) {
  return request(`/api/integrations/rtl433/start?freq_mhz=${encodeURIComponent(freqMHz)}`, { method: 'POST' })
}

export function startRtl433Sweep(dwellSeconds = 4) {
  return request(`/api/integrations/rtl433/start_sweep?dwell_seconds=${encodeURIComponent(dwellSeconds)}`, { method: 'POST' })
}

export function stopRtl433() {
  return request('/api/integrations/rtl433/stop', { method: 'POST' })
}

export function startWbHunt(
  profileKey = 'eu_ism',
  { autoDecode = true, autoDecodeMode = 'top5', autoDecodeDwellSeconds = 4, autoDecodeLimit = 5 } = {},
) {
  return request(
    `/api/integrations/wb_hunt/start?profile_key=${encodeURIComponent(profileKey)}&auto_decode=${encodeURIComponent(autoDecode)}&auto_decode_mode=${encodeURIComponent(autoDecodeMode)}&auto_decode_dwell_seconds=${encodeURIComponent(autoDecodeDwellSeconds)}&auto_decode_limit=${encodeURIComponent(autoDecodeLimit)}`,
    { method: 'POST' },
  )
}

export function stopWbHunt() {
  return request('/api/integrations/wb_hunt/stop', { method: 'POST' })
}

export function captureWbHuntPeak(peakMHz, family = '', notes = '') {
  return request(
    `/api/integrations/wb_hunt/capture_peak?peak_mhz=${encodeURIComponent(peakMHz)}&family=${encodeURIComponent(family)}&notes=${encodeURIComponent(notes)}`,
    { method: 'POST' },
  )
}

export function decodeWbHuntSignal(peakMHz, dwellSeconds = 4) {
  return request(
    `/api/integrations/wb_hunt/decode_signal?peak_mhz=${encodeURIComponent(peakMHz)}&dwell_seconds=${encodeURIComponent(dwellSeconds)}`,
    { method: 'POST' },
  )
}

export function updateWbHuntRow(rowId, { retentionState = '', operatorPriority = '', tags = [] } = {}) {
  return request(
    `/api/integrations/wb_hunt/row_update?row_id=${encodeURIComponent(rowId)}&retention_state=${encodeURIComponent(retentionState)}&operator_priority=${encodeURIComponent(operatorPriority)}&tags=${encodeURIComponent(tags.join(','))}`,
    { method: 'POST' },
  )
}

export function startWbHuntAutoDecode(mode = 'top5', dwellSeconds = 4, limit = 5) {
  return request(
    `/api/integrations/wb_hunt/auto_decode/start?mode=${encodeURIComponent(mode)}&dwell_seconds=${encodeURIComponent(dwellSeconds)}&limit=${encodeURIComponent(limit)}`,
    { method: 'POST' },
  )
}

export function stopWbHuntAutoDecode() {
  return request('/api/integrations/wb_hunt/auto_decode/stop', { method: 'POST' })
}

export async function fetchIntegrationSummary() {
  const entries = await Promise.allSettled([
    fetchIntegrationStatus('rtl433'),
    fetchIntegrationStatus('wb_hunt'),
    fetchIntegrationStatus('signal_lab'),
    fetchIntegrationStatus('kismet'),
    fetchWiFiMk7Status(),
    fetchBleNr5Status(),
  ])

  const wifiMk7Status = entries[4].status === 'fulfilled' ? entries[4].value : null
  const bleNr5Status = entries[5].status === 'fulfilled' ? entries[5].value : null
  const wifiMk7 = wifiMk7Status
    ? {
        integration: 'wifi_mk7',
        title: 'WiFi MK7',
        status: {
          installed: !!wifiMk7Status.adapter?.detected,
          path: wifiMk7Status.adapter?.monitor_interface || wifiMk7Status.adapter?.base_interface || '',
          detail: wifiMk7Status.adapter?.detail || '',
        },
        process: {
          running: !!wifiMk7Status.capture_active,
        },
        manager: wifiMk7Status,
      }
    : null

  const bleNr5 = bleNr5Status
    ? {
        integration: 'ble_nr5',
        title: 'BLE NR5',
        status: {
          installed: !!bleNr5Status.sensor_ready,
          path: (bleNr5Status.sensors || []).flatMap((sensor) => sensor.serial_paths || []).join(', '),
          detail: (bleNr5Status.sensors || []).map((sensor) => sensor.usb_descriptor).join(' | ') || '',
        },
        process: {
          running: !!bleNr5Status.active,
        },
        manager: bleNr5Status,
      }
    : null

  return {
    rtl433: entries[0].status === 'fulfilled' ? entries[0].value : null,
    wbHunt: entries[1].status === 'fulfilled' ? entries[1].value : null,
    signalLab: entries[2].status === 'fulfilled' ? entries[2].value : null,
    kismet: entries[3].status === 'fulfilled' ? entries[3].value : null,
    wifiMk7,
    bleNr5,
  }
}
