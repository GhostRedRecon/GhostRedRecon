import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { Metric, Panel, Pill } from '../components/ui'
import {
  clearBleNr5Session,
  fetchBleNr5Devices,
  fetchBleNr5Knowledge,
  fetchBleNr5Queue,
  fetchBleNr5Status,
  fetchBleNr5Tasks,
  fetchBleNr5Timeline,
  fetchBleNr5ValidationFramework,
  fetchBleNr5ValidationRuns,
  runBleNr5HardTest,
  runBleNr5Scan,
  setBleNr5Workflow,
  startBleNr5LiveHunt,
  startBleNr5Session,
  stopBleNr5LiveHunt,
  stopBleNr5Session,
} from '../lib/api'
import { usePanelPreferences } from '../lib/viewPreferences'

function fmtTime(timestamp) {
  if (!timestamp) return '--'
  return new Date(Number(timestamp) * 1000).toLocaleString()
}

function fmtRelative(timestamp) {
  if (!timestamp) return '--'
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - Number(timestamp)))
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`
  return `${Math.round(seconds / 3600)}h ago`
}

function compactAddress(address) {
  if (!address) return '--'
  const parts = String(address).split(':')
  if (parts.length !== 6) return address
  return `${parts.slice(0, 3).join(':')}..${parts.slice(4).join(':')}`
}

function shortText(value, max = 32) {
  const text = String(value || '').trim()
  if (!text) return '--'
  if (text.length <= max) return text
  return `${text.slice(0, max - 1)}…`
}

function compactPairingDetail(device = {}) {
  const auditability = device.auditability || {}
  if (auditability.state && auditability.state !== 'AUDITABLE') {
    return `${auditability.state.toLowerCase()} · ${shortText(auditability.reason || 'audit gate', 28)}`
  }
  if (device.active_validation?.attempted) {
    return `${activeValidationLabel(device.active_validation)} · ${shortText(activeValidationDetail(device.active_validation), 28)}`
  }
  if (device.validation?.manual_result && device.validation.manual_result !== 'unknown') {
    return `${validationLabel(device.validation)} · ${shortText(validationDetail(device.validation), 24)}`
  }
  return `${shortText(device.pairable_reason || 'connectability_unknown', 22)} · ${device.pairable_confidence || 'low'}`
}

function compactIntelDetail(device = {}) {
  const executedTests = Array.isArray(device.active_validation?.harder_test_results) ? device.active_validation.harder_test_results : []
  const executedNotify = executedTests.find((item) => item?.id === 'notify_surface' && item?.executed)
  if (executedNotify) {
    return shortText(`notify audit executed · ${executedNotify.detail || 'subscription evidence retained'}`, 72)
  }
  const redTeamValue = device.validation_run?.red_team_value?.summary || ''
  if (redTeamValue) return shortText(redTeamValue, 72)
  const harderTests = Array.isArray(device.validation_run?.harder_tests) ? device.validation_run.harder_tests : []
  const readyCount = harderTests.filter((item) => item?.readiness === 'ready').length
  if (readyCount > 0) {
    return `${readyCount} harder test path${readyCount > 1 ? 's' : ''} ready · ${shortText(device.failure_reason || 'owned-target validation path available', 38)}`
  }
  const families = (device.exploit_families || []).slice(0, 2).join(', ') || 'fingerprint'
  const uuids = (device.service_uuids || []).slice(0, 2).join(', ') || 'no uuid'
  return `${shortText(families, 24)} · ${shortText(uuids, 16)} · ${shortText(device.failure_reason || `${device.gatt_writable_count || 0} wr`, 24)}`
}

function validationLabel(validation = {}) {
  const manualResult = String(validation?.manual_result || '').trim().toLowerCase()
  if (manualResult === 'paired') return 'paired'
  if (manualResult === 'rejected') return 'rejected'
  const pairableVerdict = String(validation?.pairable_verdict || '').trim().toLowerCase()
  if (pairableVerdict === 'yes') return 'pairable'
  if (pairableVerdict === 'no') return 'not pairable'
  return 'not validated'
}

function validationDetail(validation = {}) {
  const parts = []
  if (validation?.legacy_pin_risk && validation.legacy_pin_risk !== 'unknown') {
    parts.push(`pin ${validation.legacy_pin_risk}`)
  }
  if (validation?.updated_at) {
    parts.push(fmtRelative(validation.updated_at))
  }
  return parts.join(' · ') || 'lab validation pending'
}

function displayLegacyPinRisk(device = {}) {
  const risk = String(device.validation?.legacy_pin_risk || '').trim().toLowerCase()
  if (risk && risk !== 'unknown') return risk.toUpperCase()
  if (device.validation_suite?.scenario_count) return 'NO PIN FLOW'
  return 'UNKNOWN'
}

function displayValidationResult(device = {}) {
  const result = String(device.validation?.manual_result || '').trim().toLowerCase()
  if (result && result !== 'unknown') return result.toUpperCase()
  if (device.validation_suite?.scenario_count) return 'PARTIAL'
  return 'UNKNOWN'
}

function displayPairableValue(device = {}) {
  const verdict = String(device.validation?.pairable_verdict || '').trim().toLowerCase()
  if (verdict === 'yes' || verdict === 'no') return verdict.toUpperCase()
  return String(device.pairable || 'unknown').toUpperCase()
}

function isWeakestAsset(device = {}, devices = []) {
  if (!devices.length) return false
  const topRank = Number(devices[0]?.weakness_rank || 0)
  const currentRank = Number(device?.weakness_rank || 0)
  if (!topRank || currentRank !== topRank) return false
  return currentRank >= 50 || String(device?.risk?.tier || '') === 'critical' || String(device?.risk?.tier || '') === 'high'
}

function activeValidationLabel(active = {}) {
  const result = String(active?.connect_result || '').trim().toLowerCase()
  if (result === 'connected') return 'connected'
  if (result === 'paired') return 'paired'
  if (result === 'failed') return 'connect failed'
  if (result.startsWith('skipped_')) return result.replaceAll('_', ' ')
  return active?.attempted ? 'active tested' : 'not active-tested'
}

function pinAuditSummary(device = {}) {
  const audit = device.validation?.pin_audit || device.validation_run?.pin_audit || {}
  const tested = Array.isArray(audit.tested_pins) ? audit.tested_pins : []
  if (!tested.length) return shortText(audit.summary || 'no PIN audit evidence', 30)
  return tested
    .map((entry) => `${entry.pin}:${String(entry.status || 'unknown').replaceAll('_', '-')}`)
    .join(' · ')
}

function validationStatusLabel(device = {}) {
  const auditability = String(device.auditability?.state || '').trim().toUpperCase()
  if (auditability === 'NOT_AUDITABLE') return 'NOT AUDITABLE'
  if (auditability === 'LIMITED') return 'LIMITED'
  const status = String(device.auto_validation?.status || '').trim().toLowerCase()
  if (status === 'validated') return 'VERIFIED'
  if (status === 'partial') return 'PARTIAL'
  if (status === 'weak') return 'LOW CONF'
  return status ? status.toUpperCase() : 'PARTIAL'
}

function technicalTrustLabel(device = {}) {
  const pairing = String(device.trust_lifecycle_summary?.pairing_method || '').trim()
  if (pairing && pairing !== 'unknown') return pairing
  const reconnect = String(device.trust_lifecycle_summary?.reconnect_result || '').trim()
  if (reconnect) return reconnect.replaceAll('_', ' ')
  return '--'
}

function identityConfidenceLabel(device = {}) {
  return device.identity_confidence_label || device.identity_confidence || device.classification?.level || 'unknown'
}

function blockedSummary(device = {}) {
  const blocked = device.active_validation?.blocked_state || {}
  if (blocked.reason) return `${blocked.stage || 'validation'} · ${blocked.reason}`
  if (device.resolution_failure_reason) return `materialization · ${device.resolution_failure_reason}`
  return device.failure_reason || 'no blocked state retained'
}

function gattDifferentialSummary(gattTest = {}) {
  const differential = gattTest?.gatt_differential || {}
  const summary = String(differential.summary || '').trim()
  if (summary) return summary
  return 'no differential retained'
}

function harderTestEntries(device = {}) {
  const activeResults = Array.isArray(device.active_validation?.harder_test_results) ? device.active_validation.harder_test_results : []
  if (activeResults.length) return activeResults
  const planned = Array.isArray(device.validation_run?.harder_tests) ? device.validation_run.harder_tests : []
  return planned
}

function compactScenarioLabel(label = '') {
  return shortText(label, 12)
}

function activeValidationDetail(active = {}) {
  if (!active?.attempted) return active?.detail || 'active product test pending'
  const parts = []
  parts.push(`${active.service_count || 0} svc`)
  parts.push(`${active.characteristic_count || 0} char`)
  parts.push(`${active.writable_count || 0} writable`)
  if (active?.tested_at) {
    parts.push(fmtRelative(active.tested_at))
  }
  return parts.join(' · ')
}

function validationSuiteLabel(suite = {}) {
  const status = String(suite?.status || '').trim().toLowerCase()
  if (status === 'pass') return 'suite pass'
  if (status === 'fail') return 'suite fail'
  if (status === 'weak') return 'suite weak'
  return 'suite pending'
}

function gattTestLabel(gattTest = {}) {
  const status = String(gattTest?.status || '').trim().toLowerCase()
  if (status === 'high_value') return 'high value'
  if (status === 'mapped') return 'mapped'
  if (status === 'blocked') return 'blocked'
  return 'pending'
}

function gattTestSummary(gattTest = {}) {
  const serviceCount = Number(gattTest?.service_count || 0)
  const characteristicCount = Number(gattTest?.characteristic_count || 0)
  const controlCount = Array.isArray(gattTest?.control_surfaces) ? gattTest.control_surfaces.length : 0
  return `${serviceCount} svc · ${characteristicCount} char · ${controlCount} ctrl`
}

function gattRiskEntries(gattTest = {}) {
  const findings = Array.isArray(gattTest?.risk_findings) ? gattTest.risk_findings : []
  if (findings.length) {
    return findings.slice(0, 4).map((entry) => {
      if (typeof entry === 'string') return shortText(entry.replaceAll('_', ' '), 34)
      if (entry && typeof entry === 'object') {
        return shortText(entry.title || entry.label || entry.finding || entry.summary || entry.uuid || 'risk finding', 34)
      }
      return 'risk finding'
    })
  }
  const unauthReadable = Number(gattTest?.unauth_readable_count || 0)
  const unauthWritable = Number(gattTest?.unauth_writable_count || 0)
  const writable = Number(gattTest?.writable_count || 0)
  const fallback = []
  if (unauthWritable > 0) fallback.push(`${unauthWritable} unauth writable`)
  if (unauthReadable > 0) fallback.push(`${unauthReadable} unauth readable`)
  if (!fallback.length && writable > 0) fallback.push(`${writable} writable paths`)
  return fallback.length ? fallback : ['no high-value finding retained']
}

function gattControlEntries(gattTest = {}) {
  const controls = Array.isArray(gattTest?.control_surfaces) ? gattTest.control_surfaces : []
  if (controls.length) {
    return controls.slice(0, 4).map((entry) => {
      if (typeof entry === 'string') return shortText(entry, 34)
      if (entry && typeof entry === 'object') {
        const uuid = entry.characteristic_uuid || entry.uuid || entry.service_uuid || 'control'
        const flags = Array.isArray(entry.flags) ? entry.flags.slice(0, 2).join('/') : ''
        const auth = entry.unauthenticated_writable ? 'unauth' : (entry.requires_auth ? 'auth' : '')
        return shortText([uuid, flags, auth].filter(Boolean).join(' · '), 34)
      }
      return 'control path'
    })
  }
  const services = Array.isArray(gattTest?.services) ? gattTest.services : []
  const fallback = []
  services.slice(0, 3).forEach((service) => {
    const characteristics = Array.isArray(service?.characteristics) ? service.characteristics : []
    characteristics.forEach((characteristic) => {
      if (fallback.length >= 4) return
      if (characteristic?.writable || characteristic?.notifiable) {
        const flags = Array.isArray(characteristic?.flags) ? characteristic.flags.slice(0, 2).join('/') : ''
        fallback.push(shortText([characteristic?.uuid || 'char', flags].filter(Boolean).join(' · '), 34))
      }
    })
  })
  return fallback.length ? fallback : ['no control surface retained']
}

function gattSurfaceEntries(gattTest = {}) {
  const services = Array.isArray(gattTest?.services) ? gattTest.services : []
  if (services.length) {
    return services.slice(0, 4).map((service) => {
      const characteristics = Array.isArray(service?.characteristics) ? service.characteristics.length : 0
      const primary = service?.primary ? 'primary' : 'secondary'
      return shortText(`${service?.uuid || 'service'} · ${characteristics} char · ${primary}`, 36)
    })
  }
  const lines = Array.isArray(gattTest?.attribute_lines) ? gattTest.attribute_lines : []
  if (lines.length) {
    return lines.slice(0, 4).map((line) => shortText(line, 36))
  }
  return ['no service map retained']
}

function gattAccessSummary(gattTest = {}) {
  const readable = Number(gattTest?.readable_count || 0)
  const writable = Number(gattTest?.writable_count || 0)
  const notify = Number(gattTest?.notify_count || 0)
  const unauthReadable = Number(gattTest?.unauth_readable_count || 0)
  const unauthWritable = Number(gattTest?.unauth_writable_count || 0)
  return [
    `${readable} rd`,
    `${writable} wr`,
    `${notify} ntf`,
    `${unauthReadable} ur`,
    `${unauthWritable} uw`,
  ].join(' · ')
}

function testStateSummary(device = {}) {
  const tested = device.tested_state || {}
  const parts = []
  if (tested.active_tested) parts.push('ACT')
  if (tested.suite_tested) parts.push('SUITE')
  if (tested.gatt_tested) parts.push('GATT')
  return parts.length ? parts.join(' · ') : 'untested'
}

function compactStageState(stage = {}) {
  const state = String(stage?.state || 'idle').toUpperCase()
  const detail = String(stage?.detail || '--')
  return `${state} // ${detail}`
}

function classificationTone(device = {}) {
  return device.classification?.ui_tone || 'neutral'
}

function auditabilityTone(state = '') {
  const normalized = String(state || '').trim().toUpperCase()
  if (normalized === 'AUDITABLE') return 'green'
  if (normalized === 'LIMITED') return 'warning'
  return 'danger'
}

function rfQualityTone(label = '') {
  const normalized = String(label || '').trim().toUpperCase()
  if (normalized === 'STRONG') return 'green'
  if (normalized === 'MEDIUM') return 'warning'
  return 'danger'
}

function materializationTone(status = '') {
  const normalized = String(status || '').trim().toLowerCase()
  if (normalized === 'materialized' || normalized === 'materialized_after_retry') return 'green'
  if (normalized === 'candidate_only') return 'warning'
  return 'danger'
}

function protocolTone(protocol = '') {
  const normalized = String(protocol || '').trim().toLowerCase()
  if (normalized === 'zigbee (inferred)') return 'amber'
  if (normalized === 'ble') return 'cyan'
  if (normalized === 'ble + cloud') return 'green'
  if (normalized === 'broadcast') return 'purple'
  return 'red'
}

function confidenceTone(level = '') {
  const normalized = String(level || '').trim().toUpperCase()
  if (normalized === 'HIGH') return 'green'
  if (normalized === 'MEDIUM') return 'amber'
  return 'red'
}

function formatClassificationSummary(device = {}) {
  const classification = device.classification || {}
  const auditability = device.auditability || {}
  if (classification.matched_device) {
    return `${classification.matched_device} · ${classification.device_type || 'Unknown'} · ${auditability.state || 'UNKNOWN'}`
  }
  const type = classification.device_type || 'Unknown'
  const protocol = classification.protocol || 'Unknown'
  const ecosystem = classification.ecosystem || 'Unknown'
  return `${type} · ${protocol} · ${ecosystem} · ${auditability.state || 'UNKNOWN'}`
}

function groupDevices(devices = [], groupBy = 'ecosystem') {
  const grouped = new Map()
  devices.forEach((device) => {
    const classification = device.classification || {}
    const key = groupBy === 'type'
      ? (classification.device_type || 'Unknown')
      : (classification.ecosystem || 'Unknown')
    const entry = grouped.get(key) || { key, devices: [], observations: 0, score: 0 }
    entry.devices.push(device)
    entry.observations += Number(device.observation_count || 0)
    entry.score = Math.max(entry.score, Number(classification.confidence || 0))
    grouped.set(key, entry)
  })
  return Array.from(grouped.values()).sort((left, right) => {
    if (right.devices.length !== left.devices.length) return right.devices.length - left.devices.length
    if (right.score !== left.score) return right.score - left.score
    return left.key.localeCompare(right.key)
  })
}

function downloadJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function buildBleTopology({ status, summary, devices, queue, scanStages, operationState }) {
  const stageMap = Object.fromEntries((scanStages || []).map((stage) => [stage.id, stage]))
  const scanning = operationState === 'scanning' || operationState === 'starting'
  return [
    {
      id: 'sensor',
      label: 'nRF52 Sensor',
      role: 'sensor',
      state: stageMap.sensor?.state || (status?.sensor_ready ? 'completed' : ((status?.sensor_count || 0) > 0 ? 'active' : 'idle')),
      detail: stageMap.sensor?.detail || (status?.sensor_ready ? `${status?.sensor_count || 0} ready` : (((status?.sensor_count || 0) > 0) ? 'firmware blocked' : 'no hardware')),
      percent: stageMap.sensor?.percent ?? (status?.sensor_ready ? 100 : (((status?.sensor_count || 0) > 0) ? 55 : 10)),
    },
    {
      id: 'census',
      label: 'Asset Census',
      role: 'collector',
      state: stageMap.collect?.state || ((summary?.device_count || 0) > 0 ? 'completed' : (status?.active ? 'active' : 'idle')),
      detail: stageMap.collect?.detail || `${summary?.device_count || 0} devices`,
      percent: stageMap.collect?.percent ?? Math.min(100, Math.max(12, (summary?.device_count || 0) * 12)),
    },
    {
      id: 'trust',
      label: 'Assessment',
      role: 'analyzer',
      state: stageMap.enrich?.state || ((summary?.assigned_targets || 0) > 0 ? 'active' : (scanning ? 'active' : 'idle')),
      detail: stageMap.enrich?.detail || `${summary?.assigned_targets || 0} auto-assigned`,
      percent: stageMap.enrich?.percent ?? Math.min(100, Math.max(8, (summary?.assigned_targets || 0) * 18)),
    },
    {
      id: 'gatt',
      label: 'Validation',
      role: 'analyzer',
      state: stageMap.active?.state || ((summary?.active_tested_devices || 0) > 0 ? 'completed' : (scanning ? 'active' : 'idle')),
      detail: stageMap.active?.detail || `${summary?.active_tested_devices || 0} tested`,
      percent: stageMap.active?.percent ?? Math.min(100, Math.max(8, (summary?.active_tested_devices || 0) * 18)),
    },
    {
      id: 'retain',
      label: 'Retention',
      role: 'evidence',
      state: stageMap.retain?.state || ((devices?.length || 0) > 0 ? 'completed' : (status?.active ? 'active' : 'idle')),
      detail: stageMap.retain?.detail || `${devices?.length || 0} assets`,
      percent: stageMap.retain?.percent ?? (status?.active ? 72 : 10),
    },
  ]
}

function buildVisualQueue(queue) {
  return (queue || []).slice(0, 4)
}

const PROFILE_OPTIONS = [
  { value: 'production_monitoring', label: 'Passive Recon Monitoring' },
  { value: 'red_team_validation', label: 'Red Team Validation' },
  { value: 'intel_baselining', label: 'Red Team Intel Baseline' },
]

const MISSION_OPTIONS = [
  { value: 'asset_discovery', label: 'Asset Discovery' },
  { value: 'pairing_telemetry', label: 'Pairing Telemetry' },
  { value: 'gatt_analysis', label: 'GATT Analysis' },
  { value: 'vulnerability_enrichment', label: 'Vulnerability Enrichment' },
  { value: 'target_prioritization', label: 'Target Prioritization' },
]

const DEVICE_WORKFLOWS = {
  monitor: {
    label: 'Monitor',
    profile: 'production_monitoring',
    mission: 'asset_discovery',
    labMode: false,
    summary: 'Keep this asset in passive census and timeline tracking.',
  },
  assess: {
    label: 'Assess',
    profile: 'intel_baselining',
    mission: 'target_prioritization',
    labMode: false,
    summary: 'Promote this asset into the Bluetooth assessment queue.',
  },
  validate: {
    label: 'Validate',
    profile: 'red_team_validation',
    mission: 'gatt_analysis',
    labMode: true,
    summary: 'Mark this asset for approved lab validation and deeper trust testing.',
  },
}

const SCAN_DURATION_OPTIONS = [
  { value: 60, label: '1 minute' },
  { value: 180, label: '3 minutes' },
  { value: 300, label: '5 minutes' },
]

export default function BleNr5View({ mode, layoutMode = 'laptop' }) {
  const { isPanelVisible } = usePanelPreferences('BLE-NR5')
  const [status, setStatus] = useState(null)
  const [devices, setDevices] = useState([])
  const [queue, setQueue] = useState([])
  const [timeline, setTimeline] = useState([])
  const [knowledge, setKnowledge] = useState({})
  const [validationFramework, setValidationFramework] = useState({})
  const [validationRuns, setValidationRuns] = useState([])
  const [tasks, setTasks] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [scanDuration, setScanDuration] = useState(60)
  const [profile, setProfile] = useState('production_monitoring')
  const [mission, setMission] = useState('asset_discovery')
  const [labMode, setLabMode] = useState(false)
  const [classicSidecar, setClassicSidecar] = useState(false)
  const [selectedDeviceKey, setSelectedDeviceKey] = useState('')
  const [selectedWorkflow, setSelectedWorkflow] = useState('monitor')
  const [groupBy, setGroupBy] = useState('ecosystem')
  const [operationState, setOperationState] = useState('idle')
  const [operationLabel, setOperationLabel] = useState('Session idle')
  const [operationDetail, setOperationDetail] = useState('Start BLE NR5 to begin passive collection.')
  const [operationProgress, setOperationProgress] = useState(0)
  const progressRef = useRef(null)

  function clearProgressTicker() {
    if (progressRef.current) {
      window.clearInterval(progressRef.current)
      progressRef.current = null
    }
  }

  function beginTimedProgress({ state, label, detail, seconds, floor = 8, ceiling = 92 }) {
    clearProgressTicker()
    setOperationState(state)
    setOperationLabel(label)
    setOperationDetail(detail)
    setOperationProgress(floor)
    const started = Date.now()
    const durationMs = Math.max(1200, Number(seconds || 1) * 1000)
    progressRef.current = window.setInterval(() => {
      const elapsed = Date.now() - started
      const ratio = Math.min(1, elapsed / durationMs)
      const next = floor + ((ceiling - floor) * ratio)
      setOperationProgress(Math.round(next))
      if (ratio >= 1) {
        clearProgressTicker()
      }
    }, 250)
  }

  function completeProgress({ state, label, detail }) {
    clearProgressTicker()
    setOperationState(state)
    setOperationLabel(label)
    setOperationDetail(detail)
    setOperationProgress(100)
  }

  async function refresh() {
    try {
      const [statusPayload, devicePayload, queuePayload, timelinePayload, knowledgePayload, taskPayload] = await Promise.all([
        fetchBleNr5Status(),
        fetchBleNr5Devices(),
        fetchBleNr5Queue(),
        fetchBleNr5Timeline(),
        fetchBleNr5Knowledge(),
        fetchBleNr5Tasks(),
      ])
      setStatus(statusPayload)
      setDevices(devicePayload?.devices || [])
      setQueue(queuePayload?.queue || [])
      setTimeline(timelinePayload?.events || [])
      setKnowledge(knowledgePayload?.knowledge_base || {})
      setValidationFramework(statusPayload?.validation_framework || {})
      setTasks(taskPayload?.tasks || [])
      setProfile(statusPayload?.profile || 'production_monitoring')
      setMission(statusPayload?.mission || 'asset_discovery')
      setLabMode(!!statusPayload?.lab_mode)
      setClassicSidecar(false)
      if (statusPayload?.active && operationState === 'idle') {
        setOperationLabel('Session active')
        setOperationDetail('BLE NR5 session is online and ready for scan windows.')
        setOperationProgress(100)
      }
      if (statusPayload?.live_hunt?.active) {
        const cycleCount = statusPayload.live_hunt.cycle_count || 0
        const visibleDevices = statusPayload.live_hunt.last_cycle_device_count || statusPayload?.summary?.device_count || 0
        setOperationState('scanning')
        setOperationLabel('Live Hunt active')
        setOperationDetail(
          statusPayload.live_hunt.detail
            || `Cycle ${cycleCount} is streaming Bluetooth observations into the table. ${visibleDevices} device${visibleDevices === 1 ? '' : 's'} visible for audit.`
        )
        setOperationProgress(72 + ((cycleCount % 3) * 6))
      }
      setError('')
    } catch (err) {
      setError(err.message || 'Unable to refresh BLE NR5 state.')
    }
  }

  useEffect(() => {
    refresh()
    const handle = window.setInterval(refresh, status?.live_hunt?.active ? 1200 : 5000)
    return () => {
      clearProgressTicker()
      window.clearInterval(handle)
    }
  }, [status?.live_hunt?.active])

  async function handleStart() {
    setBusy(true)
    setError('')
    try {
      const needsStart = !status?.active
      if (needsStart) {
        beginTimedProgress({
          state: 'starting',
          label: 'Starting session',
          detail: 'Bringing the nRF52840 collection session online.',
          seconds: 3,
          floor: 12,
          ceiling: 34,
        })
        await startBleNr5Session({ profile, mission, labMode: true, classicSidecar })
        await refresh()
      }
      beginTimedProgress({
        state: 'scanning',
        label: 'Scan running',
        detail: `Collecting with the nRF52840 and running active owned-target validation for ${Math.round(scanDuration / 60)} minute${scanDuration >= 120 ? 's' : ''}.`,
        seconds: scanDuration + 12,
        floor: needsStart ? 34 : 8,
        ceiling: 96,
      })
      const scanPayload = await runBleNr5Scan(scanDuration)
      await refresh()
      const promotedCount = scanPayload?.scan?.promoted_count || 0
      const activeTestedCount = scanPayload?.scan?.active_tested_count || 0
      completeProgress({
        state: 'active',
        label: 'Scan complete',
        detail: `${scanPayload?.scan?.observation_count || 0} observations retained from the last ${scanDurationLabel.toLowerCase()} window. ${promotedCount} assets auto-promoted and ${activeTestedCount} targets active-tested.`,
      })
    } catch (err) {
      completeProgress({
        state: 'error',
        label: 'Start failed',
        detail: err.message || 'Unable to start BLE NR5 scan.',
      })
      setError(err.message || 'Unable to start BLE NR5 scan.')
    } finally {
      setBusy(false)
    }
  }

  async function handleStartLiveHunt() {
    setBusy(true)
    setError('')
    try {
      const needsStart = !status?.active
      if (needsStart) {
        beginTimedProgress({
          state: 'starting',
          label: 'Starting session',
          detail: 'Bringing the nRF52840 collection session online for Live Hunt.',
          seconds: 3,
          floor: 12,
          ceiling: 34,
        })
        await startBleNr5Session({ profile, mission, labMode: true, classicSidecar })
        await refresh()
      }
      await startBleNr5LiveHunt({ scanSeconds: scanDuration })
      await refresh()
      setOperationState('scanning')
      setOperationLabel('Live Hunt active')
      setOperationDetail('Continuous Bluetooth collection is alive. Stop the hunt when you want to freeze the table for operator audits.')
      setOperationProgress(78)
    } catch (err) {
      completeProgress({
        state: 'error',
        label: 'Live Hunt failed',
        detail: err.message || 'Unable to start Live Hunt.',
      })
      setError(err.message || 'Unable to start Live Hunt.')
    } finally {
      setBusy(false)
    }
  }

  async function handleStop() {
    setBusy(true)
    setError('')
    try {
      if (liveHuntActive) {
        await stopBleNr5LiveHunt()
        await refresh()
        completeProgress({
          state: 'active',
          label: 'Live Hunt paused',
          detail: 'Continuous scan stopped. Devices remain in the list so the operator can run audits.',
        })
        return
      }
      await stopBleNr5Session()
      await refresh()
      completeProgress({
        state: 'idle',
        label: 'Session stopped',
        detail: 'BLE NR5 collection is paused. Retained evidence stays available until cleared.',
      })
    } catch (err) {
      setError(err.message || 'Unable to stop BLE NR5 session.')
    } finally {
      setBusy(false)
    }
  }

  async function handleClear() {
    setBusy(true)
    setError('')
    try {
      await clearBleNr5Session()
      await refresh()
      setSelectedDeviceKey('')
      completeProgress({
        state: 'idle',
        label: 'Evidence cleared',
        detail: 'Observed assets, timeline, and scan stages were reset.',
      })
    } catch (err) {
      setError(err.message || 'Unable to clear BLE NR5 evidence.')
    } finally {
      setBusy(false)
    }
  }

  const summary = status?.summary || {}
  const missionModules = knowledge?.mission_modules || status?.mission_modules || []
  const vulnerabilityFamilies = knowledge?.vulnerability_families || []
  const priorityClasses = useMemo(() => Object.entries(summary?.priority_classes || {}), [summary])
  const topology = useMemo(
    () => buildBleTopology({ status, summary, devices, queue, scanStages: status?.scan_stages || [], operationState }),
    [status, summary, devices, queue, operationState],
  )
  const visualQueue = useMemo(() => buildVisualQueue(queue), [queue])
  const scanStages = status?.scan_stages || []
  const toolReadiness = status?.tool_readiness || {}
  const lastScan = status?.last_scan || {}
  const primarySensor = (status?.sensors || [])[0] || null
  const primaryProbe = primarySensor?.transport_probe || {}
  const sensorMode = primarySensor?.firmware_mode || 'unknown'
  const sensorCollectorReady = !!primarySensor?.collector_ready
  const liveHunt = status?.live_hunt || {}
  const liveHuntActive = !!liveHunt?.active
  const gattEngine = status?.gatt_engine_state || {}
  const identityEngine = status?.identity_engine_state || {}
  const hardTestState = status?.hard_test_state || {}
  const selectedDevice = useMemo(
    () => devices.find((device) => device.device_key === selectedDeviceKey) || null,
    [devices, selectedDeviceKey],
  )
  const workflowConfig = DEVICE_WORKFLOWS[selectedWorkflow] || DEVICE_WORKFLOWS.monitor
  const scanDurationLabel = SCAN_DURATION_OPTIONS.find((option) => option.value === scanDuration)?.label || `${scanDuration}s`
  const selectedGatt = selectedDevice?.gatt_test || {}
  const gattTopology = (selectedGatt?.stages?.length ? selectedGatt : gattEngine)?.stages || []
  const selectedHardTest = selectedDevice && hardTestState?.device_key === selectedDevice.device_key ? hardTestState : null
  const groupedDevices = useMemo(() => groupDevices(devices, groupBy), [devices, groupBy])
  const classifiedTypeCounts = summary?.classified_types || {}
  const fingerprintSummary = status?.fingerprint_summary || knowledge?.fingerprint_summary || {}

  useEffect(() => {
    if (!devices.length) {
      setSelectedDeviceKey('')
      return
    }
    if (!selectedDeviceKey || !devices.some((device) => device.device_key === selectedDeviceKey)) {
      setSelectedDeviceKey(devices[0].device_key)
    }
  }, [devices, selectedDeviceKey])

  useEffect(() => {
    let cancelled = false
    async function loadRuns() {
      if (!selectedDeviceKey) {
        setValidationRuns([])
        return
      }
      try {
        const payload = await fetchBleNr5ValidationRuns(selectedDeviceKey)
        if (!cancelled) {
          setValidationRuns(payload?.runs || [])
        }
      } catch {
        if (!cancelled) {
          setValidationRuns([])
        }
      }
    }
    loadRuns()
    return () => {
      cancelled = true
    }
  }, [selectedDeviceKey, status?.started_at, tasks])

  useEffect(() => {
    if (selectedDevice?.workflow && selectedDevice.workflow !== selectedWorkflow) {
      setSelectedWorkflow(selectedDevice.workflow)
    }
  }, [selectedDevice, selectedWorkflow])

  async function applyDeviceWorkflow(device, workflowKey) {
    const nextWorkflow = DEVICE_WORKFLOWS[workflowKey] || DEVICE_WORKFLOWS.monitor
    setBusy(true)
    setError('')
    try {
      await setBleNr5Workflow({ deviceKey: device.device_key, workflow: workflowKey })
      await refresh()
    } catch (err) {
      setError(err.message || 'Unable to assign BLE NR5 workflow.')
    } finally {
      setBusy(false)
    }
    setSelectedDeviceKey(device.device_key)
    setSelectedWorkflow(workflowKey)
    setProfile(nextWorkflow.profile)
    setMission(nextWorkflow.mission)
    setLabMode(nextWorkflow.labMode)
    setClassicSidecar(false)
    setOperationState('targeted')
    setOperationLabel(`${nextWorkflow.label} target selected`)
    setOperationDetail(`${device.name || 'Unknown BLE Device'} is now the active ${nextWorkflow.label.toLowerCase()} target.`)
    setOperationProgress(status?.active ? 100 : 28)
  }

  async function handleRunHardBleTest() {
    if (!selectedDevice) return
    const confirmedOwnedTarget = window.confirm('Run active BLE validation only against a device you own or are explicitly authorized to test. Continue?')
    if (!confirmedOwnedTarget) return
    setBusy(true)
    setError('')
    try {
      if (!status?.active || !labMode) {
        await startBleNr5Session({
          profile: 'red_team_validation',
          mission: 'gatt_analysis',
          labMode: true,
          classicSidecar: false,
        })
        await refresh()
      }
      beginTimedProgress({
        state: 'validating',
        label: 'Hard BLE test running',
        detail: `Running bootstrap, active trust probe, validation suite, and GATT control-surface audit against ${selectedDevice.name || compactAddress(selectedDevice.address)}.`,
        seconds: 34,
        floor: 18,
        ceiling: 94,
      })
      const payload = await runBleNr5HardTest({
        deviceKey: selectedDevice.device_key,
        ownedTarget: true,
      })
      await refresh()
      const gattTest = payload?.gatt_test || {}
      const suite = payload?.validation_suite || {}
      const active = payload?.active_validation || {}
      completeProgress({
        state: 'targeted',
        label: 'Hard BLE test complete',
        detail: `${selectedDevice.name || 'Selected device'} · ${activeValidationLabel(active)} · ${validationSuiteLabel(suite)} · ${gattTestLabel(gattTest)} · ${gattTestSummary(gattTest)}`,
      })
    } catch (err) {
      completeProgress({
        state: 'error',
        label: 'Hard BLE test failed',
        detail: err.message || 'Unable to run the combined BLE hard test.',
      })
      setError(err.message || 'Unable to run the combined BLE hard test.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="workspace category-workspace">
      <div className="main-column">
        <section className="metrics-grid compact-metrics">
          <Metric label="Sensor" value={sensorCollectorReady ? 'READY' : (status?.sensor_count ? 'BLOCKED' : 'MISSING')} detail={`${status?.sensor_count || 0} nRF52840 path(s) detected`} />
          <Metric label="Mission" value={status?.mission || '--'} detail={status?.active ? 'session active' : 'session idle'} />
          <Metric label="Validated" value={summary?.validation_suite_devices ?? '--'} detail={`${summary?.active_tested_devices ?? 0} active-tested`} />
          <Metric label="Device Census" value={summary?.device_count ?? '--'} detail={`${summary?.auditable_devices ?? 0} auditable · ${summary?.recommended_targets ?? 0} recommended`} />
        </section>

        {!!error && <section className="error-banner">{error}</section>}

        {isPanelVisible('controls') ? (
	        <Panel
	          kicker="Sensor Control"
	          title="BLE NR5 Session Workflow"
	          action={(
	            <div className="pill-row ble-nr5-action-row">
	              <label className="ble-nr5-duration-inline">
	                <span className="control-label">Scan</span>
	                <select value={scanDuration} onChange={(event) => setScanDuration(Number(event.target.value))}>
	                  {SCAN_DURATION_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
	                </select>
	              </label>
	              <button className={`mini-action ble-nr5-start-button ${(operationState === 'starting' || operationState === 'scanning') && !liveHuntActive ? 'live' : ''}`} disabled={busy || !status?.sensor_ready || liveHuntActive} onClick={handleStart}>
	                {(operationState === 'starting' || operationState === 'scanning') && !liveHuntActive ? 'Starting' : 'Start'}
	              </button>
	              <button className={`mini-action ble-nr5-live-button ${liveHuntActive ? 'live' : ''}`} disabled={busy || !status?.sensor_ready || liveHuntActive} onClick={handleStartLiveHunt}>
	                {liveHuntActive ? 'Live Hunt Running' : 'Live Hunt'}
	              </button>
	              <button className="mini-action" disabled={busy || (!status?.active && !liveHuntActive)} onClick={handleStop}>{liveHuntActive ? 'Stop Hunt' : 'Stop'}</button>
	              <button className="mini-action" disabled={busy} onClick={handleClear}>Clear</button>
	              <button className="mini-action" disabled={busy} onClick={() => downloadJson('ble_nr5_snapshot.json', { status, devices, queue, timeline, knowledge })}>Export JSON</button>
	            </div>
          )}
        >
          <div className="ble-nr5-compact-head">
	            <div className="pill-row">
	              <Pill text={sensorCollectorReady ? 'sniffer-ready' : (status?.sensor_count ? `firmware:${sensorMode}` : 'sensor-missing')} tone={sensorCollectorReady ? 'green' : 'amber'} />
	              <Pill text={status?.active ? 'session-active' : 'session-idle'} tone={status?.active ? 'cyan' : 'neutral'} />
	              <Pill text={`${selectedWorkflow}`} tone={selectedWorkflow === 'validate' ? 'warning' : (selectedWorkflow === 'assess' ? 'cyan' : 'green')} />
	              <Pill text="nrf-only" tone="neutral" />
	            </div>
              <div className={`ble-nr5-live-indicator ${liveHuntActive ? 'live' : ''}`}>
                <span className="ble-nr5-live-dot" aria-hidden="true" />
                <strong>Live Hunt</strong>
                <small>{liveHuntActive ? `cycle ${liveHunt.cycle_count || 1} · alive` : 'standby'}</small>
              </div>
	          </div>
	          <div className={`ble-nr5-progress-card ${operationState}`}>
	            <div className="ble-nr5-progress-head">
	              <strong>{operationLabel}</strong>
	              <span>{Math.max(0, Math.min(100, operationProgress))}%</span>
	            </div>
	            <div className="ble-nr5-progress-bar">
	              <span style={{ width: `${Math.max(0, Math.min(100, operationProgress))}%` }} />
	            </div>
	            <div className="table-secondary">{operationDetail}</div>
	          </div>
	          <div className="detail-grid">
	            <Metric label="Scan" value={scanDurationLabel} detail={status?.started_at ? fmtTime(status?.started_at) : 'ready'} />
	            <Metric label="Intel" value={status?.knowledge_loaded ? 'LOADED' : 'OFFLINE'} detail={`${fingerprintSummary.device_count || 0} fingerprints · ${vulnerabilityFamilies.length} vuln families`} />
	            <Metric label="Target" value={selectedDevice ? (selectedDevice.name || compactAddress(selectedDevice.address)) : '--'} detail={selectedDevice ? (selectedDevice.vendor || '--') : 'select asset'} />
	          </div>
        </Panel>
        ) : null}

        {isPanelVisible('inventory') ? (
        <Panel
          kicker="Device Census"
          title="Observed Bluetooth Assets"
          action={(
            <div className="pill-row ble-nr5-action-row">
              <label className="ble-nr5-duration-inline">
                <span className="control-label">Group</span>
                <select value={groupBy} onChange={(event) => setGroupBy(event.target.value)}>
                  <option value="ecosystem">Ecosystem</option>
                  <option value="type">Type</option>
                </select>
              </label>
            </div>
          )}
        >
          <div className="ble-nr5-group-strip">
            <Pill text={`auditable ${summary?.auditable_devices || 0}`} tone="green" />
            <Pill text={`limited ${summary?.limited_devices || 0}`} tone="warning" />
            <Pill text={`not-auditable ${summary?.not_auditable_devices || 0}`} tone="danger" />
            <Pill text={`mobile ${classifiedTypeCounts.Mobile || 0}`} tone="cyan" />
            <Pill text={`iot ${classifiedTypeCounts.IoT || 0}`} tone="green" />
            <Pill text={`beacon ${classifiedTypeCounts.Beacon || 0}`} tone="purple" />
            <Pill text={`unknown ${classifiedTypeCounts.Unknown || 0}`} tone="red" />
          </div>
          <div className="table-wrap ble-nr5-table-wrap">
            <table className="matrix-table ble-nr5-asset-table">
	              <thead>
	                <tr>
	                  <th>Device</th>
	                  <th>Classification</th>
	                  <th>Protocol / Behavior</th>
	                  <th>Red-Team Intel</th>
	                  <th>Signal</th>
	                  <th>Status</th>
	                  <th>Workflow</th>
	                </tr>
	              </thead>
	              <tbody>
	                {groupedDevices.flatMap((group) => [
                    (
                      <tr key={`group-${group.key}`} className="ble-nr5-group-row">
                        <td colSpan={7}>
                          <div className="ble-nr5-group-head">
                            <strong>{group.key}</strong>
                            <span>{group.devices.length} devices · {group.observations} observations · top confidence {group.score}%</span>
                          </div>
                        </td>
                      </tr>
                    ),
                    ...group.devices.map((device) => (
                    <Fragment key={device.device_key}>
	                  <tr
                      key={device.device_key}
                      className={[
                        selectedDeviceKey === device.device_key ? 'selected-ssid-row' : '',
                        isWeakestAsset(device, devices) ? 'ble-nr5-weakest-row' : '',
                        `ble-nr5-class-row ble-nr5-class-${String(device.classified_type || 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
                      ].filter(Boolean).join(' ')}
                      onClick={() => setSelectedDeviceKey((current) => current === device.device_key ? '' : device.device_key)}
                    >
	                    <td>
	                      <div className="network-primary-cell ble-nr5-device-cell">
	                        <strong>{`${device.classification?.icon || '❓'} ${device.name || 'Unknown BLE Device'}`}</strong>
	                      <div className="ble-nr5-cell-pills">
	                        <Pill text={shortText(device.device_type || 'bluetooth device', 16)} tone="neutral" />
	                        <Pill text={device.vendor || '--'} tone={classificationTone(device)} />
                          <Pill text={device.auditability?.state || 'UNKNOWN'} tone={auditabilityTone(device.auditability?.state)} />
                          {device.recommended_target ? <Pill text="RECOMMENDED TARGET" tone="green" /> : null}
                          {isWeakestAsset(device, devices) ? <Pill text="weakest" tone="danger" /> : null}
	                        </div>
                      </div>
                      <div className="wb-hunt-cell-detail">
                        {device.connectable ? 'conn' : 'bcast'} · {device.scannable ? 'scan' : 'fixed'} · {device.observation_count || 0} obs · {shortText(device.priority_class || '--', 12)}
                      </div>
                    </td>
                    <td>
                      <div>{formatClassificationSummary(device)}</div>
                      <div className="wb-hunt-cell-detail">
                        {compactAddress(device.address)} · {device.classification?.level || 'LOW'} · {device.classification?.confidence || 0}%
                      </div>
                    </td>
                    <td>
                      <div className="ble-nr5-cell-pills">
                        <Pill text={device.classified_protocol || 'Unknown'} tone={protocolTone(device.classified_protocol)} />
                        <Pill text={device.classification?.movement || 'unknown'} tone="neutral" />
                        <Pill text={device.classification?.advertising_pattern || 'burst'} tone="neutral" />
                      </div>
                      <div className="wb-hunt-cell-detail">
                        {device.classification?.behavior || 'unknown'} · {device.address_type || '--'} · {shortText(device.auditability?.reason || 'no audit guidance', 34)}
                      </div>
                    </td>
                    <td>
                      <div>{shortText(device.likely_family || '--', 22)}</div>
                      <div className="wb-hunt-cell-detail">
                        {compactIntelDetail(device)}
                      </div>
                    </td>
                    <td>
                      <div>{device.avg_rssi != null ? `${device.avg_rssi} dBm` : '--'}</div>
                      <div className="wb-hunt-cell-detail">
                        {device.rf_quality?.label || 'WEAK'} · {Math.round(device.dwell_seconds || 0)}s · {shortText((device.rf_quality?.reasons || []).join(' · ') || 'limited samples', 48)}
                      </div>
                    </td>
                    <td>
                      <div className="ble-nr5-cell-pills">
                        <Pill text={`${device.classified_type || 'Unknown'}`} tone={classificationTone(device)} />
                        <Pill text={device.classification?.level || 'LOW'} tone={confidenceTone(device.classification?.level)} />
                        <Pill text={device.rf_quality?.label || 'WEAK'} tone={rfQualityTone(device.rf_quality?.label)} />
                        <Pill text={String(device.materialization_status || 'failed').replaceAll('_', ' ')} tone={materializationTone(device.materialization_status)} />
                        <Pill text={`${device.risk?.tier || 'baseline'} ${device.risk?.score || 0}`} tone={device.risk?.tier === 'critical' ? 'danger' : (device.risk?.tier === 'high' ? 'warning' : 'cyan')} />
                        <Pill text={device.tracking_risk || 'low'} tone={device.tracking_risk === 'high' ? 'warning' : 'neutral'} />
                        {device.operation_running ? <Pill text={shortText(device.operation_label || 'running', 10)} tone="warning" /> : null}
                      </div>
	                      <div className="wb-hunt-cell-detail">{compactPairingDetail(device)} · {fmtRelative(device.last_seen)}</div>
	                    </td>
	                  <td>
	                      <div className="ble-nr5-row-actions">
	                        <button className={`mini-action ${device.workflow === 'monitor' ? 'active' : ''}`} onClick={(event) => { event.stopPropagation(); applyDeviceWorkflow(device, 'monitor') }}>Monitor</button>
	                      </div>
	                      <div className="wb-hunt-cell-detail">
                        {device.operation_running
                          ? `running · ${shortText(device.operation_label || 'operation', 14)}`
                          : device.workflow === 'monitor'
                          ? `${device.workflow_state || 'monitoring'}`
                          : `${device.workflow_state || 'validation_ready'} · ${shortText(device.failure_action || validationSuiteLabel(device.validation_suite), 42)}`}
                        </div>
	                    </td>
	                  </tr>
                    {selectedDeviceKey === device.device_key ? (
                    <tr className="ble-nr5-validation-row">
                      <td colSpan={7}>
                        <div className="ble-nr5-validation-strip">
                          <div className="ble-nr5-validation-head">
                            <strong>Lab Audit</strong>
                            <span>{validationStatusLabel(device)}</span>
                          </div>
                          <div className="ble-nr5-cell-pills">
                            <Pill text={testStateSummary(device)} tone="cyan" />
                            {device.operation_running ? <Pill text={`running:${shortText(device.operation_label || 'op', 10)}`} tone="warning" /> : null}
                            {device.active_validation?.attempted ? <Pill text={activeValidationLabel(device.active_validation)} tone="green" /> : null}
                            {device.gatt_test?.tested_at ? <Pill text={gattTestLabel(device.gatt_test)} tone="warning" /> : null}
                          </div>
                          <div className="ble-nr5-inline-audit">
                            <div className="ble-nr5-inline-audit-card">
                              <span>Auditability</span>
                              <strong>{device.auditability?.state || 'UNKNOWN'}</strong>
                              <small>{shortText(device.auditability?.reason || 'audit gate pending', 38)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>RF Quality</span>
                              <strong>{device.rf_quality?.label || 'WEAK'}</strong>
                              <small>{shortText((device.rf_quality?.reasons || []).join(' · ') || 'limited signal data', 38)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>Identity</span>
                              <strong>{identityConfidenceLabel(device)}</strong>
                              <small>{shortText(`${device.linked_rf_addresses?.length || device.linked_addresses?.length || 1} addr · ${device.identity_id || device.logical_device_id || 'no cluster id'}`, 34)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>Materialize</span>
                              <strong>{String(device.materialization_status || 'failed').replaceAll('_', ' ')}</strong>
                              <small>{shortText(device.resolution_summary || device.resolution_failure_reason || 'resolution pending', 38)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>Link Path</span>
                              <strong>{displayPairableValue(device)}</strong>
                              <small>{shortText(device.pairable_reason || 'unknown', 26)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>PIN Audit</span>
                              <strong>{displayLegacyPinRisk(device)}</strong>
                              <small>{shortText(pinAuditSummary(device), 30)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>Verdict</span>
                              <strong>{displayValidationResult(device)}</strong>
                              <small>{shortText(device.active_validation?.detail || 'validation pending', 26)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>Scenario Set</span>
                              <strong>{validationSuiteLabel(device.validation_suite)}</strong>
                              <small>{(device.validation_suite?.scenario_count || 0)} scenarios</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>Trust State</span>
                              <strong>{technicalTrustLabel(device)}</strong>
                              <small>{shortText(device.trust_lifecycle_summary?.reconnect_result || 'not tested', 22)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>GATT Engine</span>
                              <strong>{gattTestLabel(device.gatt_test)}</strong>
                              <small>{shortText(device.gatt_test?.summary || gattTestSummary(device.gatt_test), 34)}</small>
                            </div>
                            <div className="ble-nr5-inline-audit-card">
                              <span>Blocked Stage</span>
                              <strong>{shortText((device.active_validation?.blocked_state?.code || device.materialization_status || 'none').replaceAll('_', ' '), 24)}</strong>
                              <small>{shortText(blockedSummary(device), 42)}</small>
                            </div>
                          </div>
                          <div className="ble-nr5-validation-steps">
                            {(device.auto_validation?.steps || []).slice(0, 4).map((step) => (
                              <div key={step.id} className={`ble-nr5-validation-step ${step.status}`}>
                                <span>{step.label}</span>
                                <strong>{shortText(step.detail, 28)}</strong>
                              </div>
                            ))}
                          </div>
                          <div className="ble-nr5-validation-steps suite-grid">
                            {(device.validation_suite?.scenarios || []).slice(0, 3).map((scenario) => (
                              <div key={`${device.device_key}-${scenario.id}`} className={`ble-nr5-validation-step ${scenario.status}`}>
                                <span>{compactScenarioLabel(scenario.label)}</span>
                                <strong>{shortText(scenario.detail, 28)}</strong>
                              </div>
                            ))}
                          </div>
                          {((device.validation_suite?.scenarios || []).length > 0) ? (
                            <div className="ble-nr5-scenario-strip">
                              <div className="ble-nr5-gatt-findings-head">
                                <strong>Scenarios</strong>
                                <span>{(device.validation_suite?.scenarios || []).length} tested</span>
                              </div>
                              <div className="ble-nr5-cell-pills ble-nr5-scenario-pills">
                                {(device.validation_suite?.scenarios || []).map((scenario) => (
                                  <Pill key={`${device.device_key}-scenario-${scenario.id}`} text={`${compactScenarioLabel(scenario.label)}:${String(scenario.status || 'unknown').toUpperCase()}`} tone={scenario.status === 'pass' ? 'green' : (scenario.status === 'fail' ? 'danger' : (scenario.status === 'weak' ? 'warning' : 'neutral'))} />
                                ))}
                              </div>
                            </div>
                          ) : null}
                          {harderTestEntries(device).length ? (
                            <div className="ble-nr5-gatt-findings">
                              <div className="ble-nr5-gatt-findings-head">
                                <strong>Harder Tests</strong>
                                <span>{harderTestEntries(device).length} vectors</span>
                              </div>
                              <div className="ble-nr5-gatt-findings-grid">
                                {harderTestEntries(device).slice(0, 4).map((item) => (
                                  <div key={`${device.device_key}-harder-${item.id || item.label}`} className="ble-nr5-gatt-findings-card">
                                    <span>{shortText(item.label || item.id || 'harder test', 28)}</span>
                                    <strong>{shortText((item.execution_status || item.status || item.readiness || 'unknown').replaceAll('_', ' '), 28)}</strong>
                                    <small>{shortText(item.detail || (Array.isArray(item.findings) ? item.findings.join(' · ') : 'no detail retained'), 96)}</small>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : null}
                          {(selectedHardTest?.stages?.length || device.operation_running) ? (
                            <div className="ble-nr5-hard-stage-strip">
                              <div className="ble-nr5-gatt-findings-head">
                                <strong>Hard Test Stages</strong>
                                <span>{selectedHardTest?.status || (device.operation_running ? 'running' : '--')}</span>
                              </div>
                              <div className="ble-nr5-hard-stage-grid">
                                {(selectedHardTest?.stages?.length ? selectedHardTest.stages : [
                                  { id: 'bootstrap', label: 'Bootstrap', state: device.operation_running ? 'active' : 'idle', detail: device.operation_running ? 'preparing lab workflow' : 'awaiting hard test', percent: device.operation_running ? 18 : 0 },
                                  { id: 'active', label: 'Active', state: 'idle', detail: 'awaiting trust probe', percent: 0 },
                                  { id: 'suite', label: 'Suite', state: 'idle', detail: 'awaiting adversary scenarios', percent: 0 },
                                  { id: 'gatt', label: 'GATT', state: 'idle', detail: 'awaiting control map', percent: 0 },
                                  { id: 'finalize', label: 'Finalize', state: 'idle', detail: 'awaiting evidence merge', percent: 0 },
                                ]).map((stage) => (
                                  <div key={stage.id} className={`ble-nr5-hard-stage-card ${stage.state}`}>
                                    <div className="ble-nr5-hard-stage-head">
                                      <span>{stage.label}</span>
                                      <strong>{String(stage.state || 'idle').toUpperCase()}</strong>
                                    </div>
                                    <div className="backend-stage-progress ble-nr5-hard-stage-progress">
                                      <span style={{ width: `${Math.max(0, Math.min(100, Number(stage.percent || 0)))}%` }} />
                                    </div>
                                    <small>{shortText(stage.detail || '--', 52)}</small>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : null}
                          <div className="ble-nr5-gatt-findings">
                            <div className="ble-nr5-gatt-findings-head">
                              <strong>Failure Reason / Action</strong>
                              <span>{device.recommended_target ? 'recommended target' : 'operator guidance'}</span>
                            </div>
                            <div className="ble-nr5-gatt-findings-grid">
                              <div className="ble-nr5-gatt-findings-card">
                                <span>Reason</span>
                                <strong>{shortText(device.failure_reason || 'no failure retained', 40)}</strong>
                                <small>{shortText(device.auditability?.reason || 'no additional detail', 64)}</small>
                              </div>
                              <div className="ble-nr5-gatt-findings-card">
                                <span>Action</span>
                                <strong>{shortText(device.failure_action || 'continue passive monitoring', 40)}</strong>
                                <small>{shortText(device.recommended_target ? 'This target currently meets the strongest audit conditions.' : 'Follow the action before running deeper tests.', 64)}</small>
                              </div>
                            </div>
                          </div>
                          {(device.session_evidence_timeline || []).length ? (
                            <div className="backend-timeline-card">
                              <div className="ble-nr5-gatt-findings-head">
                                <strong>Session Evidence Timeline</strong>
                                <span>{(device.session_evidence_timeline || []).length} events</span>
                              </div>
                              <div className="timeline-list">
                                {(device.session_evidence_timeline || []).slice().reverse().map((item, index) => (
                                  <div key={`${device.device_key}-timeline-${index}`} className="timeline-item">
                                    <span className="timeline-dot" />
                                    <div>
                                      <strong>{shortText(item.event || 'event', 20)}</strong>
                                      <div className="table-secondary">{shortText(item.detail || '--', 92)}</div>
                                      <div className="wb-hunt-cell-detail">{fmtTime(item.timestamp)}</div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : null}
                          {(device.gatt_test?.tested_at || device.gatt_test?.service_count || device.gatt_test?.characteristic_count || device.gatt_test?.control_surfaces?.length || device.gatt_test?.risk_findings?.length) ? (
                            <div className="ble-nr5-gatt-findings">
                              <div className="ble-nr5-gatt-findings-head">
                                <strong>GATT Findings</strong>
                                <span>{gattTestLabel(device.gatt_test)}</span>
                              </div>
                              <div className="ble-nr5-cell-pills ble-nr5-gatt-pill-row">
                                <Pill text={`${device.gatt_test?.service_count || 0} svc`} tone="cyan" />
                                <Pill text={`${device.gatt_test?.characteristic_count || 0} char`} tone="neutral" />
                                <Pill text={`${device.gatt_test?.writable_count || 0} wr`} tone={Number(device.gatt_test?.writable_count || 0) > 0 ? 'warning' : 'neutral'} />
                                <Pill text={`${device.gatt_test?.unauth_writable_count || 0} unauth-w`} tone={Number(device.gatt_test?.unauth_writable_count || 0) > 0 ? 'danger' : 'neutral'} />
                              </div>
                              <div className="ble-nr5-gatt-findings-grid">
                                <div className="ble-nr5-gatt-findings-card">
                                  <span>Access Posture</span>
                                  <strong>{gattAccessSummary(device.gatt_test)}</strong>
                                  <small>{shortText(device.gatt_test?.summary || gattTestSummary(device.gatt_test), 46)}</small>
                                </div>
                                <div className="ble-nr5-gatt-findings-card">
                                  <span>Differential</span>
                                  <strong>{shortText(gattDifferentialSummary(device.gatt_test), 42)}</strong>
                                  <small>{shortText((device.gatt_test?.gatt_differential?.highlights || []).join(' · ') || 'no differential highlight retained', 72)}</small>
                                </div>
                                <div className="ble-nr5-gatt-findings-card">
                                  <span>Control Paths</span>
                                  <strong>{gattControlEntries(device.gatt_test)[0]}</strong>
                                  <small>{gattControlEntries(device.gatt_test).slice(1).join(' · ') || 'no secondary path retained'}</small>
                                </div>
                                <div className="ble-nr5-gatt-findings-card">
                                  <span>High-Value Findings</span>
                                  <strong>{gattRiskEntries(device.gatt_test)[0]}</strong>
                                  <small>{gattRiskEntries(device.gatt_test).slice(1).join(' · ') || 'no additional finding retained'}</small>
                                </div>
                                <div className="ble-nr5-gatt-findings-card">
                                  <span>Service Hotspots</span>
                                  <strong>{gattSurfaceEntries(device.gatt_test)[0]}</strong>
                                  <small>{gattSurfaceEntries(device.gatt_test).slice(1).join(' · ') || 'no additional hotspot retained'}</small>
                                </div>
                              </div>
                            </div>
                          ) : null}
                          <div className="ble-nr5-row-actions ble-nr5-expanded-actions">
                            <button className="mini-action ble-nr5-hard-test-button" disabled={busy || device.operation_running || device.auditability?.state !== 'AUDITABLE'} onClick={(event) => { event.stopPropagation(); handleRunHardBleTest() }}>{device.operation_running && device.operation_label === 'hard_ble_test' ? 'Hard Test Running' : (device.auditability?.state === 'AUDITABLE' ? 'Hard BLE Test' : (device.auditability?.state === 'LIMITED' ? 'Improve RF First' : 'Not Auditable'))}</button>
                          </div>
                        </div>
                      </td>
                    </tr>
                    ) : null}
                    </Fragment>
	                )),
                  ])}
	              </tbody>
	            </table>
            {!devices.length && <div className="empty-box">No BLE NR5 observations recorded yet. Start the session and attach a collector or import observations.</div>}
          </div>
        </Panel>
        ) : null}

      </div>

      <div className="side-column">
        {isPanelVisible('intel') ? (
        <Panel kicker="Bluetooth Topology" title="BLE NR5 Processing Topology">
          <div className={`backend-stage-hud ble-nr5-topology-board ${(operationState === 'scanning' || operationState === 'starting') ? 'scanning' : ''}`}>
            <div className="ble-nr5-topology-mesh" aria-hidden="true">
              <span className="mesh-line mesh-line-a" />
              <span className="mesh-line mesh-line-b" />
              <span className="mesh-line mesh-line-c" />
              <span className="mesh-pulse mesh-pulse-a" />
              <span className="mesh-pulse mesh-pulse-b" />
              <span className="mesh-pulse mesh-pulse-c" />
            </div>
            <div className="ble-nr5-topology-head">
              <div>
                <span className="backend-stage-kicker">Live mesh</span>
                <strong>nRF signal mesh</strong>
              </div>
              <div className={`backend-stage-status ${status?.active ? 'live' : ''}`}>
                <span className="backend-stage-status-dot" />
                {status?.active ? 'online' : 'idle'}
              </div>
            </div>
            <div className="ble-nr5-topology-grid">
              {topology.map((phase, index) => (
                <div key={phase.id} className={`ble-nr5-topology-node ${phase.state} mesh-slot-${index + 1}`} title={`${phase.label} · ${phase.detail} · ${phase.percent}%`}>
                  <div className="ble-nr5-topology-node-head">
                    <span className="ble-nr5-topology-glyph" />
                    <span className="backend-stage-label">{phase.label}</span>
                  </div>
                  <div className="backend-stage-role">{phase.role}</div>
                  <div className="backend-stage-progress">
                    <span style={{ width: `${phase.percent}%` }} />
                  </div>
                  <div className="backend-stage-caption">{phase.detail}</div>
                </div>
              ))}
            </div>
          </div>
          {(selectedHardTest?.stages?.length || hardTestState?.status === 'running') ? (
            <div className="ble-nr5-hard-rail">
              <div className="ble-nr5-console-head">
                <span>hard.ble.test</span>
                <span>{selectedHardTest?.status || hardTestState?.status || 'idle'}</span>
              </div>
              <div className="ble-nr5-hard-rail-grid">
                {(selectedHardTest?.stages?.length ? selectedHardTest.stages : hardTestState?.stages || []).map((stage) => (
                  <div key={stage.id} className={`ble-nr5-hard-rail-node ${stage.state}`}>
                    <span>{stage.label}</span>
                    <div className="backend-stage-progress ble-nr5-hard-stage-progress">
                      <span style={{ width: `${Math.max(0, Math.min(100, Number(stage.percent || 0)))}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </Panel>
        ) : null}

        {isPanelVisible('intel') ? (
        <Panel kicker="Identity Correlation" title="State-Aware Identity & Session Correlation">
          <div className={`backend-stage-hud ble-nr5-topology-board ble-nr5-identity-board ${(operationState === 'scanning' || operationState === 'validating' || identityEngine?.status === 'running' || hardTestState?.status === 'running') ? 'scanning' : ''}`}>
            <div className="ble-nr5-topology-mesh ble-nr5-identity-mesh" aria-hidden="true">
              <span className="mesh-line mesh-line-a" />
              <span className="mesh-line mesh-line-b" />
              <span className="mesh-line mesh-line-c" />
              <span className="mesh-pulse mesh-pulse-a" />
              <span className="mesh-pulse mesh-pulse-b" />
              <span className="mesh-pulse mesh-pulse-c" />
            </div>
            <div className="ble-nr5-topology-head">
              <div>
                <span className="backend-stage-kicker">State-aware</span>
                <strong>identity.session.graph</strong>
              </div>
              <div className={`backend-stage-status ${(operationState === 'scanning' || operationState === 'validating' || identityEngine?.status === 'running' || hardTestState?.status === 'running') ? 'live' : ''}`}>
                <span className="backend-stage-status-dot" />
                {(operationState === 'scanning' || operationState === 'validating' || identityEngine?.status === 'running' || hardTestState?.status === 'running') ? 'running' : (identityEngine?.status || 'idle')}
              </div>
            </div>
            <div className="ble-nr5-topology-grid">
              {(identityEngine?.stages?.length ? identityEngine.stages : [
                { id: 'features', label: 'Features', state: 'idle', detail: 'awaiting scan observations', percent: 0 },
                { id: 'correlate', label: 'Correlate', state: 'idle', detail: 'awaiting identity graph', percent: 0 },
                { id: 'host', label: 'Host Bind', state: 'idle', detail: 'awaiting BlueZ correlation', percent: 0 },
                { id: 'sessions', label: 'Sessions', state: 'idle', detail: 'awaiting validation binding', percent: 0 },
                { id: 'state', label: 'State', state: 'idle', detail: 'awaiting GATT/trust history', percent: 0 },
              ]).map((phase, index) => (
                <div key={phase.id} className={`ble-nr5-topology-node ${phase.state} mesh-slot-${(index % 5) + 1}`} title={`${phase.label} · ${phase.detail} · ${phase.percent}%`}>
                  <div className="ble-nr5-topology-node-head">
                    <span className="ble-nr5-topology-glyph" />
                    <span className="backend-stage-label">{phase.label}</span>
                  </div>
                  <div className="backend-stage-role">identity</div>
                  <div className="backend-stage-progress">
                    <span style={{ width: `${phase.percent}%` }} />
                  </div>
                  <div className="backend-stage-caption">{phase.detail}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="ble-nr5-console-strip">
            <span>nodes[{identityEngine?.node_count || summary?.identity_nodes || 0}]</span>
            <span>corr[{identityEngine?.correlated_nodes || summary?.identity_correlated_nodes || 0}]</span>
            <span>host[{identityEngine?.resolved_hosts || summary?.identity_resolved_hosts || 0}]</span>
            <span>ids[{devices.filter((device) => device.identity_id).length}]</span>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('intel') ? (
        <Panel kicker="GATT Engine" title="GATT Adversarial Interaction Topology">
          <div className={`backend-stage-hud ble-nr5-topology-board ble-nr5-gatt-board ${(operationState === 'gatt' || operationState === 'validating' || gattEngine?.status === 'running' || hardTestState?.status === 'running') ? 'scanning' : ''}`}>
            <div className="ble-nr5-topology-mesh ble-nr5-gatt-mesh" aria-hidden="true">
              <span className="mesh-line mesh-line-a" />
              <span className="mesh-line mesh-line-b" />
              <span className="mesh-line mesh-line-c" />
              <span className="mesh-pulse mesh-pulse-a" />
              <span className="mesh-pulse mesh-pulse-b" />
              <span className="mesh-pulse mesh-pulse-c" />
            </div>
            <div className="ble-nr5-topology-head">
              <div>
                <span className="backend-stage-kicker">State-aware</span>
                <strong>gatt.control.mesh</strong>
              </div>
              <div className={`backend-stage-status ${(operationState === 'gatt' || operationState === 'validating' || gattEngine?.status === 'running' || hardTestState?.status === 'running') ? 'live' : ''}`}>
                <span className="backend-stage-status-dot" />
                {(operationState === 'gatt' || operationState === 'validating' || gattEngine?.status === 'running' || hardTestState?.status === 'running') ? 'running' : (selectedGatt?.status || gattEngine?.status || 'idle')}
              </div>
            </div>
            <div className="ble-nr5-topology-grid">
              {(gattTopology.length ? gattTopology : [
                { id: 'resolve', label: 'Resolve', state: 'idle', detail: 'awaiting gatt test', percent: 0 },
                { id: 'map', label: 'Map', state: 'idle', detail: 'awaiting service map', percent: 0 },
                { id: 'diff', label: 'Diff', state: 'idle', detail: 'awaiting state comparison', percent: 0 },
                { id: 'control', label: 'Control', state: 'idle', detail: 'awaiting control-surface audit', percent: 0 },
                { id: 'transcript', label: 'Transcript', state: 'idle', detail: 'awaiting att transcript', percent: 0 },
                { id: 'classify', label: 'Classify', state: 'idle', detail: 'awaiting risk mapping', percent: 0 },
              ]).map((phase, index) => (
                <div key={phase.id} className={`ble-nr5-topology-node ${phase.state} mesh-slot-${(index % 5) + 1}`} title={`${phase.label} · ${phase.detail} · ${phase.percent}%`}>
                  <div className="ble-nr5-topology-node-head">
                    <span className="ble-nr5-topology-glyph" />
                    <span className="backend-stage-label">{phase.label}</span>
                  </div>
                  <div className="backend-stage-role">gatt</div>
                  <div className="backend-stage-progress">
                    <span style={{ width: `${phase.percent}%` }} />
                  </div>
                  <div className="backend-stage-caption">{phase.detail}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="ble-nr5-console-strip">
            <span>svc[{selectedGatt?.service_count || 0}]</span>
            <span>char[{selectedGatt?.characteristic_count || 0}]</span>
            <span>ctrl[{Array.isArray(selectedGatt?.control_surfaces) ? selectedGatt.control_surfaces.length : 0}]</span>
            <span>risk[{Array.isArray(selectedGatt?.risk_findings) ? selectedGatt.risk_findings.length : 0}]</span>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('intel') ? (
        <Panel kicker="Visual Snapshot" title="Bluetooth Tactical Picture">
          <div className="ble-nr5-console-board ble-nr5-intel-board" title="BLE NR5 tactical picture">
            <div className="ble-nr5-console-head">
              <span>tactical.view</span>
              <span>{visualQueue.length ? 'HOT' : 'QUIET'}</span>
            </div>
            <div className="ble-nr5-console-grid">
              {visualQueue.length ? visualQueue.map((item) => (
                <div key={item.device_key} className="ble-nr5-console-row active" title={`${item.name} · ${item.priority_class} · ${item.vendor}`}>
                  <span className="ble-nr5-console-tag">{item.priority_class || 'general'}</span>
                  <span className="ble-nr5-console-value">
                    {shortText(item.name || 'Unknown BLE Device', 22)} // {shortText(item.vendor || 'Unknown', 12)} // {shortText((item.pairing_methods || []).join(', ') || 'no trust signal', 18)}
                  </span>
                  <span className="ble-nr5-console-percent">{item.score || 0}</span>
                </div>
              )) : (
                <div className="ble-nr5-console-row idle">
                  <span className="ble-nr5-console-tag">queue</span>
                  <span className="ble-nr5-console-value">no queue items yet</span>
                  <span className="ble-nr5-console-percent">0</span>
                </div>
              )}
            </div>
          </div>
          <div className="ble-nr5-console-strip">
            <span>classes[{priorityClasses.length}]</span>
            <span>families[{summary?.top_vulnerability_families?.length || 0}]</span>
            <span>risk[{summary?.high_risk_devices || 0}]</span>
            <span>gatt[{summary?.gatt_exposure_devices || 0}]</span>
            {(summary?.top_vulnerability_families || []).slice(0, 2).map(([family, count]) => (
              <span key={family}>{shortText(family, 18)}[{count}]</span>
            ))}
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('intel') ? (
        <Panel kicker="Scan Stages" title="Collector and Analysis Stages">
          <div className="ble-nr5-console-board" title="BLE NR5 scan stages and tool telemetry">
            <div className="ble-nr5-console-head">
              <span>pipeline.sys</span>
              <span>{status?.active ? 'LIVE' : 'IDLE'}</span>
            </div>
            <div className="ble-nr5-console-grid">
              {scanStages.map((stage) => (
                <div key={stage.id} className={`ble-nr5-console-row ${stage.state}`} title={`${stage.label} · ${stage.detail} · ${stage.percent}%`}>
                  <span className="ble-nr5-console-tag">{stage.label}</span>
                  <span className="ble-nr5-console-value">{compactStageState(stage)}</span>
                  <span className="ble-nr5-console-percent">{stage.percent || 0}%</span>
                </div>
              ))}
            </div>
          </div>
          <div className="ble-nr5-console-strip">
            <span>tools[{Object.entries(toolReadiness).filter(([, value]) => value?.installed).length}]</span>
            <span>frames[{lastScan?.collector_attempts?.[0]?.raw_frame_count || 0}]</span>
            <span>obs[{lastScan?.observation_count || 0}]</span>
            <span>err[{(lastScan?.errors || []).length}]</span>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('intel') ? (
        <Panel kicker="Knowledge and Risk" title="Bluetooth Intelligence Model">
          <div className="ble-nr5-console-board ble-nr5-intel-board">
            <div className="ble-nr5-console-head">
              <span>intel.map</span>
              <span>{status?.knowledge_loaded ? 'SYNC' : 'OFF'}</span>
            </div>
            <div className="ble-nr5-console-grid">
              <div className="ble-nr5-console-row active">
                <span className="ble-nr5-console-tag">modules</span>
                <span className="ble-nr5-console-value">{(missionModules || []).length} loaded</span>
                <span className="ble-nr5-console-percent">{(missionModules || []).length}</span>
              </div>
              {(summary?.top_vulnerability_families || []).slice(0, 4).map(([family, count]) => (
                <div key={family} className="ble-nr5-console-row weak">
                  <span className="ble-nr5-console-tag">risk</span>
                  <span className="ble-nr5-console-value">{family}</span>
                  <span className="ble-nr5-console-percent">{count}</span>
                </div>
              ))}
              {!summary?.top_vulnerability_families?.length && (
                <div className="ble-nr5-console-row idle">
                  <span className="ble-nr5-console-tag">risk</span>
                  <span className="ble-nr5-console-value">no matched families</span>
                  <span className="ble-nr5-console-percent">0</span>
                </div>
              )}
            </div>
          </div>
          <div className="ble-nr5-console-strip">
            {priorityClasses.slice(0, 4).map(([label, count]) => (
              <span key={label}>{label}[{count}]</span>
            ))}
            {!priorityClasses.length && <span>general[0]</span>}
          </div>
        </Panel>
        ) : null}

      </div>
    </main>
  )
}
