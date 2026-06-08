import { useEffect, useMemo, useRef, useState } from 'react'
import { Panel, Pill } from '../components/ui'
import {
  clearHuntDronesSession,
  clearWiFiMk7Session,
  deleteHuntDronesData,
  fetchHuntDronesDetections,
  fetchHuntDronesEvidence,
  fetchHuntDronesLive,
  fetchHuntDronesReplaySessions,
  fetchHuntDronesReports,
  fetchHuntDronesSettings,
  fetchHuntDronesStatus,
  fetchHuntDronesTopology,
  loadHuntDronesReplaySession,
  requestHuntDronesCapability,
  runHuntDronesScan,
  startHuntDronesSession,
  startWiFiMk7Session,
  stopHuntDronesSession,
  stopWiFiMk7Session,
} from '../lib/api'

function fmtTime(ts) {
  if (!ts) return '--'
  return new Date(Number(ts) * 1000).toLocaleString()
}

function toneForConfidence(value) {
  const score = Number(value || 0)
  if (score >= 85) return 'green'
  if (score >= 65) return 'warning'
  return 'neutral'
}

function toneForClass(value = '') {
  const text = String(value || '').toLowerCase()
  if (text.includes('confirmed')) return 'green'
  if (text.includes('probable')) return 'warning'
  if (text.includes('controller')) return 'cyan'
  if (text.includes('baseline')) return 'neutral'
  return 'danger'
}

function toneForProof(tier) {
  const level = Number(tier || 0)
  if (level >= 4) return 'green'
  if (level >= 2) return 'warning'
  return 'neutral'
}

function getSettledValue(result, fallback) {
  return result?.status === 'fulfilled' ? result.value : fallback
}

function titleCaseFromToken(value) {
  return String(value || 'idle')
    .replaceAll('_', ' ')
    .split(' ')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

function buildDroneVerdict(target) {
  if (!target) {
    return {
      label: 'No target selected',
      tone: 'neutral',
      summary: 'No drone verdict is available until a lead is selected.',
    }
  }
  const proofTier = Number(target?.proof_tier?.tier || 0)
  const confidence = Number(target?.confidence_score?.score ?? target?.confidence ?? 0)
  const sensors = target?.sensor_sources || []
  const family = String(target?.family_label || '').toLowerCase()
  const model = String(target?.model_family || '').toLowerCase()
  const hasRemoteId = model.includes('remote id')
  const hasDjiFamily = family.includes('dji')
  if (hasRemoteId || proofTier >= 3) {
    return {
      label: 'Drone Confirmed',
      tone: 'green',
      summary: 'Multi-sensor or protocol-backed evidence confirms drone-related activity.',
    }
  }
  if ((hasDjiFamily && sensors.includes('sdr')) || proofTier >= 2 || confidence >= 45) {
    return {
      label: 'Probable Drone Detected',
      tone: 'warning',
      summary: 'Passive evidence supports a likely drone presence, but exact model and control path remain unresolved.',
    }
  }
  return {
    label: 'Drone-Related RF Watch',
    tone: 'neutral',
    summary: 'This is a weak drone-related lead and should be treated as watch-state evidence, not confirmation.',
  }
}

function formatSchedulerHints(target) {
  const hints = target?.scheduler_hints || []
  if (!hints.length) return 'No scheduler hints retained for this target.'
  return hints
    .map((item) => titleCaseFromToken(item))
    .join(' · ')
}

function buildOperatorTableTargets(rows) {
  const ranked = (rows || [])
    .filter((item) => {
      const state = String(item?.live_state || '').toLowerCase()
      const label = String(item?.label || '').toLowerCase()
      const targetClass = String(item?.target_class || item?.classification || '').toLowerCase()
      const targetType = String(item?.target_type || '').toLowerCase()
      const family = String(item?.family_label || '').toLowerCase()
      const model = String(item?.model_family || '').toLowerCase()
      const sensors = item?.sensor_sources || []
      const confidence = Number(item?.confidence_score?.score ?? item?.confidence ?? 0)
      const lastSeen = Number(item?.last_seen || item?.first_seen || 0)
      const ageSeconds = lastSeen ? Math.max(0, (Date.now() / 1000) - lastSeen) : 9999
      const sdrOnly = sensors.length === 1 && sensors[0] === 'sdr'
      const correlated = sensors.includes('sdr') || sensors.length >= 2
      const droneFamily = family.includes('dji') || family.includes('remote id')
      const droneModel = model.includes('remote id') || model.includes('drone') || model.includes('correlated drone')
      const genericRfContact = (
        label.includes('rf cluster')
        || label.includes('aerial contact')
        || model.includes('passive rf cluster')
        || model.includes('zigbee')
        || model.includes('802.15.4')
        || targetClass.includes('unknown aerial')
        || targetClass.includes('rf watch')
      )
      if (sdrOnly && ageSeconds > 8) return false
      if (genericRfContact && !droneFamily && !droneModel && !correlated) return false
      if (genericRfContact && !droneFamily && !droneModel && confidence < 70) return false
      if (state === 'confirmed_drone_evidence' && confidence >= 55) return true
      if (state === 'probable_drone' && confidence >= 45 && (!genericRfContact || droneFamily || droneModel || correlated)) return true
      if (state === 'correlated_drone_candidate' && correlated && (!genericRfContact || droneFamily || droneModel)) return true
      if (targetClass.includes('confirmed') && confidence >= 55) return true
      if (targetClass.includes('probable') && confidence >= 45 && (!genericRfContact || droneFamily || droneModel || correlated)) return true
      if (targetType === 'probable_drone' && sdrOnly && confidence >= 45 && (droneFamily || droneModel)) return true
      if (model.includes('remote id') && confidence >= 35) return true
      if (family.includes('dji') && correlated && confidence >= 45) return true
      return false
    })
    .sort((a, b) => Number(b?.confidence_score?.score ?? b?.confidence ?? 0) - Number(a?.confidence_score?.score ?? a?.confidence ?? 0))

  const deduped = []
  const seen = new Set()
  for (const item of ranked) {
    const key = [
      String(item?.manufacturer || ''),
      String(item?.family_label || item?.target_class || item?.classification || ''),
      String(item?.model_family || ''),
    ].join('|').toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    deduped.push(item)
    if (deduped.length >= 6) break
  }
  return deduped
}

function recentPassiveActivity(wifiStatus) {
  const scan = wifiStatus || {}
  return [
    {
      title: 'Capture',
      detail: wifiStatus?.capture_active ? 'Passive Wi-Fi capture active.' : 'Passive Wi-Fi capture idle.',
      meta: `mode ${wifiStatus?.scan_mode || 'idle'} · ${Number(scan?.progress_percent || 0).toFixed(0)}%`,
    },
    {
      title: 'Coverage',
      detail: wifiStatus?.coverage_summary || 'Coverage summary unavailable.',
      meta: `channel ${wifiStatus?.current_channel ?? '--'} · ${wifiStatus?.channels_state || 'unknown'}`,
    },
    {
      title: 'Inventory',
      detail: `${wifiStatus?.network_count ?? 0} passive Wi-Fi observations · ${wifiStatus?.client_count ?? 0} client observations`,
      meta: `${wifiStatus?.pcap_count ?? 0} pcaps retained for drone-only correlation`,
    },
  ]
}

function mergeOperatorTargets(rows) {
  const grouped = new Map()
  for (const item of rows || []) {
    const key = [
      String(item?.manufacturer || ''),
      String(item?.family_label || item?.target_class || item?.classification || ''),
      String(item?.model_family || ''),
    ].join('|').toLowerCase()
    const current = grouped.get(key)
    if (!current) {
      grouped.set(key, {
        ...item,
        sensor_sources: [...(item?.sensor_sources || [])],
        band: item?.band || '--',
      })
      continue
    }
    const currentScore = Number(current?.confidence_score?.score ?? current?.confidence ?? 0)
    const nextScore = Number(item?.confidence_score?.score ?? item?.confidence ?? 0)
    const mergedSensors = Array.from(new Set([...(current?.sensor_sources || []), ...(item?.sensor_sources || [])]))
    const mergedBands = Array.from(new Set([String(current?.band || '').trim(), String(item?.band || '').trim()].filter(Boolean)))
    grouped.set(key, {
      ...(nextScore > currentScore ? item : current),
      sensor_sources: mergedSensors,
      evidence_sensors: mergedSensors,
      band: mergedBands.join(' + ') || '--',
      merged_candidate_count: Number(current?.merged_candidate_count || 1) + 1,
      confidence_score: nextScore > currentScore ? item?.confidence_score : current?.confidence_score,
      confidence: Math.max(currentScore, nextScore),
      last_seen: Math.max(Number(current?.last_seen || 0), Number(item?.last_seen || 0)),
    })
  }
  return Array.from(grouped.values())
    .sort((a, b) => Number(b?.confidence_score?.score ?? b?.confidence ?? 0) - Number(a?.confidence_score?.score ?? a?.confidence ?? 0))
}

function operatorIdentityForTarget(target) {
  const family = String(target?.family_label || '').toLowerCase()
  const targetClass = String(target?.target_class || target?.classification || '').toLowerCase()
  if (family.includes('dji') || targetClass.includes('drone')) {
    return { badge: 'UAV', label: 'Drone Detected' }
  }
  return { badge: 'AIR', label: 'Aerial Contact' }
}

function buildCommandFeed({ schedulerActions, bandAttention, passiveRows, scanPhases, scanningDevices, liveState }) {
  const feed = []
  schedulerActions.slice(0, 6).forEach((item) => {
    feed.push({
      title: titleCaseFromToken(item.action),
      detail: `${item.sensor} · ${item.band}`,
      meta: item.reason,
      tone: 'action',
    })
  })
  bandAttention.slice(0, 3).forEach((item) => {
    feed.push({
      title: `${item.band} Focus`,
      detail: `${item.priority} · ${item.attention_score}`,
      meta: (item.rationale || []).slice(0, 2).join(' · '),
      tone: 'band',
    })
  })
  if (!feed.length) {
    scanPhases.filter((item) => item.status === 'active' || item.status === 'completed').slice(0, 3).forEach((item) => {
      feed.push({
        title: item.label,
        detail: titleCaseFromToken(item.status),
        meta: liveState?.lead_detected ? 'Lead watch active.' : 'Baseline passive watch active.',
        tone: item.status === 'active' ? 'action' : 'quiet',
      })
    })
  }
  if (!feed.length) {
    scanningDevices.slice(0, 2).forEach((item) => {
      feed.push({
        title: item.name,
        detail: item.active ? 'Active' : 'Ready',
        meta: item.role,
        tone: item.active ? 'action' : 'quiet',
      })
    })
  }
  if (!feed.length) {
    passiveRows.slice(0, 3).forEach((item) => {
      feed.push({
        title: item.title,
        detail: item.detail,
        meta: item.meta,
        tone: 'quiet',
      })
    })
  }
  return feed.slice(0, 8)
}

export default function HuntDronesView({ layoutMode = 'laptop', onHeaderContextChange = null }) {
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState(null)
  const [detections, setDetections] = useState([])
  const [topology, setTopology] = useState({ nodes: [], edges: [] })
  const [reports, setReports] = useState([])
  const [settings, setSettings] = useState({})
  const [evidence, setEvidence] = useState({ bundles: [], counts: {} })
  const [replaySessions, setReplaySessions] = useState([])
  const [liveState, setLiveState] = useState({ active: false, phase: 'idle', live_leads: [], live_lead_count: 0, lead_detected: false, audit_started: false })
  const [wifiStatus, setWiFiStatus] = useState({})
  const [workspace, setWorkspace] = useState('live')
  const [selectedTargetId, setSelectedTargetId] = useState('')
  const [policyMessage, setPolicyMessage] = useState('')
  const [actionMessage, setActionMessage] = useState('')
  const [error, setError] = useState('')
  const scanLoopActive = useRef(false)
  const statusLoopActive = useRef(false)
  const operatorStopped = useRef(false)
  const seenLeadIds = useRef(new Set())
  const [newDroneAlert, setNewDroneAlert] = useState(null)

  async function loadAll({ full = false } = {}) {
    const requests = [
      fetchHuntDronesStatus(),
      fetchHuntDronesDetections(),
      fetchHuntDronesTopology(),
    ]
    if (full) {
      requests.push(
        fetchHuntDronesReports(),
        fetchHuntDronesSettings(),
        fetchHuntDronesEvidence(),
        fetchHuntDronesReplaySessions(),
      )
    }
    const settled = await Promise.allSettled(requests)
    const nextStatus = getSettledValue(settled[0], {})
    const nextDetections = getSettledValue(settled[1], { detections: [] })
    const nextTopology = getSettledValue(settled[2], { nodes: [], edges: [] })
    setStatus(nextStatus)
    setDetections(nextDetections.detections || [])
    setTopology(nextTopology || { nodes: [], edges: [] })
    if (full) {
      const nextReports = getSettledValue(settled[3], { reports: [] })
      const nextSettings = getSettledValue(settled[4], { settings: {} })
      const nextEvidence = getSettledValue(settled[5], { bundles: [], counts: {} })
      const nextReplay = getSettledValue(settled[6], { sessions: [] })
      setReports(nextReports.reports || [])
      setSettings(nextSettings.settings || {})
      setEvidence(nextEvidence || { bundles: [], counts: {} })
      setReplaySessions(nextReplay.sessions || [])
    }
    setWiFiStatus(nextStatus?.wifi_runtime || {})
    setSelectedTargetId((current) => {
      if (!current) return ''
      return (nextDetections.detections || []).some((item) => item?.target_id === current) ? current : ''
    })
    setError('')
  }

  useEffect(() => {
    let cancelled = false
    let timer = null
    let initialLoadPending = true

    async function pollStatus({ full = false } = {}) {
      if (statusLoopActive.current) return
      statusLoopActive.current = true
      try {
        await loadAll({ full })
      } catch (err) {
        if (!cancelled) {
          setError(String(err.message || err))
        }
      } finally {
        statusLoopActive.current = false
      }
    }

    async function scheduleStatusPoll() {
      await pollStatus({ full: initialLoadPending })
      initialLoadPending = false
      if (cancelled) return
      const interval = 6000
      timer = window.setTimeout(() => {
        scheduleStatusPoll().catch(() => null)
      }, interval)
    }

    scheduleStatusPoll().catch(() => null)
    return () => {
      cancelled = true
      if (timer) window.clearTimeout(timer)
      statusLoopActive.current = false
    }
  }, [layoutMode])

  useEffect(() => {
    const huntRunning = Boolean(status?.active)
    const passiveCaptureRunning = Boolean(wifiStatus?.capture_active)
    if (!huntRunning && !passiveCaptureRunning) {
      scanLoopActive.current = false
      return undefined
    }
    let cancelled = false
    let timer = null

    async function pollLive() {
      if (scanLoopActive.current) return
      scanLoopActive.current = true
      try {
        const [nextLive, nextDetections] = await Promise.all([
          fetchHuntDronesLive().catch(() => ({ active: false, live_leads: [] })),
          fetchHuntDronesDetections().catch(() => ({ detections: [] })),
        ])
        setLiveState(nextLive || { active: false, live_leads: [] })
        setDetections(nextDetections?.detections || [])
        if (nextLive?.wifi_runtime) {
          setWiFiStatus(nextLive.wifi_runtime)
        }
      } finally {
        scanLoopActive.current = false
      }
    }

    async function scheduleLivePoll() {
      await pollLive()
      if (cancelled) return
      const interval = 700
      timer = window.setTimeout(() => {
        scheduleLivePoll().catch(() => null)
      }, interval)
    }

    scheduleLivePoll().catch(() => null)
    return () => {
      cancelled = true
      if (timer) window.clearTimeout(timer)
      scanLoopActive.current = false
    }
  }, [status?.active, wifiStatus?.capture_active, layoutMode])

  async function handleScan() {
    setBusy(true)
    setActionMessage('Starting passive hunt...')
    try {
      operatorStopped.current = false
      if (!status?.active) {
        await startHuntDronesSession({
          sessionName: 'Proof-Grade Hunt Drones Demo',
          notes: 'Demo passive session with evidence retention, proof tiers, and replay.',
          scanProfile: 'dji_focus',
        })
      }
      await clearWiFiMk7Session().catch(() => null)
      await startWiFiMk7Session({
        bands: ['5ghz'],
        dwellMs: 100,
        durationSeconds: 86400,
        scanMode: 'adaptive',
        scanScenario: 'passive_observation',
        lockedChannels: [149, 153, 157, 161],
        cameraHunt: false,
        processingEnabled: false,
      })
      await runHuntDronesScan()
      await loadAll({ full: true })
      setActionMessage('Hunt Drones fast-acquire is scanning top DJI 5 GHz channels.')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStop() {
    setBusy(true)
    setActionMessage('Stopping hunt...')
    try {
      await stopWiFiMk7Session().catch(() => null)
      await stopHuntDronesSession()
      operatorStopped.current = true
      setNewDroneAlert(null)
      await loadAll({ full: true })
      setActionMessage('Hunt stopped. Retained findings remain available for operator review.')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleReset() {
    setBusy(true)
    setActionMessage('Resetting current hunt state...')
    try {
      await clearWiFiMk7Session().catch(() => null)
      await clearHuntDronesSession()
      operatorStopped.current = true
      await loadAll({ full: true })
      setActionMessage('Hunt state reset.')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleDelete() {
    setBusy(true)
    setActionMessage('Deleting retained Hunt Drones data...')
    try {
      await stopWiFiMk7Session().catch(() => null)
      await deleteHuntDronesData()
      await clearWiFiMk7Session().catch(() => null)
      operatorStopped.current = true
      setSelectedTargetId('')
      setDetections([])
      setLiveState({ active: false, phase: 'idle', live_leads: [], live_lead_count: 0, lead_detected: false, audit_started: false })
      setTopology({ nodes: [], edges: [] })
      setEvidence({ bundles: [], counts: {} })
      setReports([])
      setReplaySessions([])
      setNewDroneAlert(null)
      await loadAll({ full: true })
      setActionMessage('Hunt Drones data deleted.')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleReplayLoad(sessionId) {
    setBusy(true)
    try {
      await loadHuntDronesReplaySession(sessionId)
      await loadAll({ full: true })
      setWorkspace('replay')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleBlockedCapability(capability) {
    try {
      const result = await requestHuntDronesCapability(capability)
      setPolicyMessage(result?.message || 'The feature has been disabled on the backend.')
    } catch (err) {
      setPolicyMessage(String(err.message || err))
    }
  }

  const hardware = status?.hardware || {}
  const scan = status?.scan || {}
  const scanPhases = Array.isArray(scan.phases) ? scan.phases : []
  const graphPoints = Array.isArray(scan.graph_points) ? scan.graph_points : []
  const toolchain = Array.isArray(scan.toolchain) ? scan.toolchain : []
  const topologyNodes = topology?.nodes || []
  const topologyEdges = topology?.edges || []
  const displayDetections = [...(detections || []), ...((liveState?.live_leads || []))]
  const operatorTableTargets = mergeOperatorTargets(buildOperatorTableTargets(displayDetections))
  const assurance = liveState?.assurance || status?.assurance || {}
  const assuranceLeads = Array.isArray(liveState?.live_leads) ? liveState.live_leads : []
  const bandAttention = Array.isArray(assurance?.band_attention) ? assurance.band_attention : []
  const schedulerActions = Array.isArray(assurance?.scheduler_actions) ? assurance.scheduler_actions : []
  const fusionWindows = Array.isArray(assurance?.fusion_windows) ? assurance.fusion_windows : []
  const sensorSync = assurance?.sensor_sync || { status: 'idle' }
  const rawFilteredCounts = assurance?.raw_filtered_counts || {}
  const swarmFamilies = new Set(displayDetections.map((item) => item.swarm_label || item.family_label || item.target_id)).size
  const passiveRows = recentPassiveActivity(wifiStatus)
  const selectedTarget = useMemo(
    () => operatorTableTargets.find((item) => item.target_id === selectedTargetId) || null,
    [operatorTableTargets, selectedTargetId],
  )
  const droneVerdict = buildDroneVerdict(selectedTarget)
  const scanningDevices = Array.isArray(liveState?.scanning_devices) && liveState.scanning_devices.length
    ? liveState.scanning_devices
    : (scan?.scanning_devices || [])
  const huntActive = Boolean(status?.active || wifiStatus?.capture_active || scan?.active || liveState?.active)
  const effectiveToolchain = toolchain.length
    ? toolchain
    : [
        {
          name: 'wifi_mk7',
          role: 'Passive Wi-Fi capture',
          integration_state: wifiStatus?.capture_active ? 'active' : 'idle',
          active: !!wifiStatus?.capture_active,
        },
        {
          name: 'hackrf_sweep',
          role: 'Passive spectrum sweep',
          integration_state: hardware?.hackrf?.connected ? 'ready' : 'offline',
          active: false,
        },
      ]
  const commandFeed = buildCommandFeed({ schedulerActions, bandAttention, passiveRows, scanPhases, scanningDevices, liveState })
  const activeDroneLead = operatorTableTargets.find((item) => String(item?.live_state || '').includes('drone')) || null
  const contactDetected = Boolean(huntActive && (liveState?.lead_detected || activeDroneLead))
  const leadStatusLabel = !huntActive
    ? 'Idle'
    : liveState?.audit_started || scan?.phase === 'audit'
    ? 'Auditing'
    : contactDetected
      ? 'Drone Detected'
      : 'Scanning'
  const leadStatusTone = !huntActive
    ? 'neutral'
    : liveState?.audit_started || scan?.phase === 'audit'
    ? 'warning'
    : contactDetected
      ? 'danger'
      : 'cyan'
  useEffect(() => {
    onHeaderContextChange?.([
      { label: 'Mode', value: leadStatusLabel, detail: huntActive ? 'passive live' : 'standby' },
      { label: 'Leads', value: assuranceLeads.length, detail: `${sensorSync?.correlated_lead_count ?? 0} fused` },
      { label: 'Band', value: bandAttention?.[0]?.band || '--', detail: bandAttention?.[0]?.priority || 'watch' },
      { label: 'Sensors', value: `${sensorSync?.wifi_only_lead_count ?? 0}/${sensorSync?.sdr_only_lead_count ?? 0}`, detail: 'wifi/sdr' },
    ])
    return () => {
      onHeaderContextChange?.([])
    }
  }, [assuranceLeads.length, bandAttention, huntActive, leadStatusLabel, onHeaderContextChange, sensorSync?.correlated_lead_count, sensorSync?.sdr_only_lead_count, sensorSync?.wifi_only_lead_count])

  useEffect(() => {
    if (!huntActive) {
      seenLeadIds.current = new Set()
      setNewDroneAlert(null)
      return
    }
    const nextIds = operatorTableTargets
      .map((item) => String(item?.target_id || '').trim())
      .filter(Boolean)
    const newIds = nextIds.filter((id) => !seenLeadIds.current.has(id))
    nextIds.forEach((id) => seenLeadIds.current.add(id))
    if (!newIds.length) return
    const newest = operatorTableTargets.find((item) => newIds.includes(String(item?.target_id || '')))
    setNewDroneAlert({
      count: newIds.length,
      label: newest?.label || 'New drone activity',
      at: Date.now(),
    })
  }, [operatorTableTargets, huntActive])

  return (
    <>
      {workspace !== 'live' ? (
      <section className="metrics-grid">
        {(
          <>
        <div className="metric">
          <span className="metric-label">Receive Only</span>
          <strong>{status?.passive_only_locked ? 'LOCKED ON' : 'UNKNOWN'}</strong>
          <small>operator transmit paths disabled</small>
        </div>
        <div className="metric">
          <span className="metric-label">Targets</span>
          <strong>{displayDetections.length}</strong>
          <small>retained evidence-backed detections</small>
        </div>
        <div className="metric">
          <span className="metric-label">Live Leads</span>
          <strong>{liveState?.live_lead_count ?? status?.live_lead_count ?? displayDetections.length}</strong>
          <small>drone leads detected before audit</small>
        </div>
        <div className="metric">
          <span className="metric-label">Assurance Leads</span>
          <strong>{assuranceLeads.length}</strong>
          <small>watch states and provisional leads</small>
        </div>
        <div className="metric">
          <span className="metric-label">Proof Tier 3+</span>
          <strong>{detections.filter((item) => Number(item?.proof_tier?.tier || 0) >= 3).length}</strong>
          <small>multi-sensor or audit-grade</small>
        </div>
        <div className="metric">
          <span className="metric-label">Replay Sessions</span>
          <strong>{replaySessions.length}</strong>
          <small>retained forensic bundles</small>
        </div>
        <div className="metric">
          <span className="metric-label">Topology</span>
          <strong>{topologyNodes.length}N / {topologyEdges.length}E</strong>
          <small>session + sensor + target graph</small>
        </div>
        <div className="metric">
          <span className="metric-label">Swarm Groups</span>
          <strong>{swarmFamilies}</strong>
          <small>family clusters in mission window</small>
        </div>
        <div className="metric">
          <span className="metric-label">Live Inventory</span>
          <strong>{wifiStatus?.network_count ?? 0} / {wifiStatus?.client_count ?? 0}</strong>
          <small>observation surface seen by MK7AC</small>
        </div>
        <div className="metric">
          <span className="metric-label">Sensor Sync</span>
          <strong>{String(sensorSync?.status || 'idle').toUpperCase()}</strong>
          <small>{sensorSync?.correlated_lead_count ?? 0} correlated leads</small>
        </div>
          </>
        )}
      </section>
      ) : null}

      {!!error && <section className="error-banner">{error}</section>}
      {!!actionMessage && !error && <section className="error-banner">{actionMessage}</section>}
      {!!policyMessage && <section className="error-banner">{policyMessage}</section>}

      <Panel kicker="Workspace" title="Hunt Drones">
        <div className="pill-row">
          {[
            ['live', 'Live Hunt'],
            ['evidence', 'Evidence'],
            ['target', 'Target Intelligence'],
            ['topology', 'Topology'],
            ['replay', 'Replay / Validation'],
            ['settings', 'Settings / Policy'],
          ].map(([key, label]) => (
            <button key={key} className={`mini-action ${workspace === key ? 'active' : ''}`} onClick={() => setWorkspace(key)}>
              {label}
            </button>
          ))}
        </div>
      </Panel>

      <main className="workspace">
        <div className="main-column">
          {workspace === 'live' ? (
            <Panel kicker="Workspace 1" title="Drone Detection Console">
              <div className="hunt-drones-console-shell">
              <div className="hunt-drones-command-center">
                <div className="hunt-drones-command-left hunt-drones-console-module">
                  <div className={`hunt-drones-status-radar ${huntActive ? 'live' : 'idle'} ${contactDetected ? 'contact' : ''}`}>
                    <div className="hunt-drones-status-radar-grid" aria-hidden="true" />
                    <div className="hunt-drones-status-radar-sweep" aria-hidden="true" />
                    <div className="hunt-drones-status-radar-core" aria-hidden="true">
                      <span />
                      <span />
                      <span />
                    </div>
                    <div className="hunt-drones-status-radar-copy">
                      <small>Scan Status</small>
                      <strong>{leadStatusLabel}</strong>
                      {contactDetected ? <div className="hunt-drones-status-radar-alert"><span className="hunt-drones-status-radar-contact-dot" aria-hidden="true" /> Drone signature retained in live operator table</div> : null}
                      <span>{huntActive ? 'Dual-sensor passive hunt online' : 'Awaiting operator start'}</span>
                    </div>
                  </div>
                  <div className="hunt-drones-command-strip">
                    <div className="hunt-drones-command-chip">
                      <span>Wi-Fi</span>
                      <strong>{wifiStatus?.capture_active ? 'LIVE' : 'READY'}</strong>
                      <small>{hardware?.mk7ac?.interface || 'wlan1mon'}</small>
                    </div>
                    <div className="hunt-drones-command-chip">
                      <span>SDR</span>
                      <strong>{hardware?.hackrf?.connected ? 'READY' : 'OFFLINE'}</strong>
                      <small>HackRF One</small>
                    </div>
                    <div className="hunt-drones-command-chip">
                      <span>Sync</span>
                      <strong>{String(sensorSync?.status || 'idle').toUpperCase()}</strong>
                      <small>{sensorSync?.correlated_lead_count ?? 0} fused leads</small>
                    </div>
                  </div>
                </div>
                <div className="hunt-drones-command-right hunt-drones-console-module">
                  <div className="hunt-drones-command-stack">
                    <strong>Phase Rail</strong>
                    <div className="hunt-drones-phase-row hunt-drones-phase-row--compact">
                      {scanPhases.map((item) => (
                        <div key={item.key} className={`hunt-drones-phase-pill hunt-drones-phase-pill--${item.status}`}>
                          <span>{item.label}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="hunt-drones-command-stack">
                    <strong>Band Focus</strong>
                    <div className="hunt-drones-band-ribbon">
                      {(bandAttention.length ? bandAttention : [{ band: '2.4 GHz', attention_score: 0, priority: 'watch' }, { band: '5.8 GHz', attention_score: 0, priority: 'watch' }]).map((item) => (
                        <div key={item.band} className={`hunt-drones-band-cell priority-${item.priority || 'watch'}`}>
                          <span>{item.band}</span>
                          <strong>{Math.max(8, Math.min(100, Number(item.attention_score || 0)))}%</strong>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              <div className="control-button-row hunt-drones-control-row">
                <button className={`button-primary ${huntActive ? 'button-primary--live' : ''}`} onClick={handleScan} disabled={busy || huntActive}>{busy && !huntActive ? 'Starting...' : 'Start Hunt'}</button>
                <button className="button-secondary" onClick={handleStop} disabled={busy || !huntActive}>{busy && huntActive ? 'Stopping...' : 'Stop Hunt'}</button>
                <button className="button-secondary" onClick={handleDelete} disabled={busy}>{busy ? 'Working...' : 'Delete'}</button>
              </div>
              {newDroneAlert ? (
                <div className="advisory-card hunt-drones-alert-card">
                  <strong>New Drone Activity</strong>
                  <div className="device-meta">
                    {newDroneAlert.count} new drone candidate{newDroneAlert.count > 1 ? 's' : ''} surfaced in the live hunt. Latest: {newDroneAlert.label}.
                  </div>
                </div>
              ) : null}
              <div className="hunt-drones-live-console hunt-drones-console-module">
                <div className="hunt-drones-graph hunt-drones-console-card">
                  <div className="hunt-drones-graph-grid" aria-hidden="true" />
                  {graphPoints.length ? (
                    <div className="hunt-drones-graph-bars" aria-hidden="true">
                      {graphPoints.map((item, index) => (
                        <span
                          key={item.row_id || index}
                          className={`hunt-drones-graph-bar ${String(item.band || '').includes('5.8') ? 'is-58' : 'is-24'}`}
                          style={{ height: `${item.height}px` }}
                        />
                      ))}
                    </div>
                  ) : (
                    <div className="hunt-drones-graph-line" aria-hidden="true"><span /><span /><span /><span /><span /><span /></div>
                  )}
                  <div className="hunt-drones-graph-scanline" aria-hidden="true" />
                </div>
                <div className="hunt-drones-tool-rail hunt-drones-console-card">
                  <strong>Operational</strong>
                  {effectiveToolchain.map((item) => (
                    <div key={item.name} className="hunt-drones-tool-row">
                      <span>{item.name}</span>
                      <small>{item.integration_state}</small>
                      <Pill text={item.active ? 'ACTIVE' : 'READY'} tone={item.active ? 'green' : 'neutral'} />
                    </div>
                  ))}
                </div>
              </div>
              <div className="hunt-drones-sensor-grid hunt-drones-sensor-grid--command">
                <div className="hunt-drones-sensor-card">
                  <strong>Channel</strong>
                  <Pill text={wifiStatus?.current_channel ?? '--'} tone={wifiStatus?.capture_active ? 'green' : 'neutral'} />
                  <small>{wifiStatus?.coverage_level || 'UNKNOWN'}</small>
                </div>
                <div className="hunt-drones-sensor-card">
                  <strong>Inventory</strong>
                  <Pill text={`${wifiStatus?.network_count ?? 0}/${wifiStatus?.client_count ?? 0}`} tone="neutral" />
                  <small>wifi/client</small>
                </div>
                <div className="hunt-drones-sensor-card">
                  <strong>Lead Pressure</strong>
                  <Pill text={`${rawFilteredCounts?.active_leads ?? 0}`} tone={leadStatusTone} />
                  <small>watch objects</small>
                </div>
                <div className="hunt-drones-sensor-card">
                  <strong>Uptime</strong>
                  <Pill text={`${Number(scan.progress_percent || 0).toFixed(0)}%`} tone="cyan" />
                  <small>{Number(scan.elapsed_seconds || 0).toFixed(0)}s</small>
                </div>
              </div>
              <div className="hunt-drones-table hunt-drones-console-module">
                <div className="hunt-drones-table-head hunt-drones-table-head--command">
                  <span>Target</span>
                  <span>Verdict</span>
                  <span>Sensors</span>
                  <span>Confidence</span>
                </div>
                {operatorTableTargets.map((item) => (
                  <button key={item.target_id} className={`hunt-drones-row hunt-drones-row--command ${selectedTargetId === item.target_id ? 'selected' : ''} ${huntActive && String(item?.live_state || '').includes('drone') ? 'live-contact' : ''}`} onClick={() => { setSelectedTargetId(item.target_id); setWorkspace('target') }}>
                    <span><strong><span className="hunt-drones-target-icon" aria-hidden="true">{operatorIdentityForTarget(item).badge}</span>{item.label}</strong><small>{operatorIdentityForTarget(item).label} · {item.family_label || item.identifier}</small></span>
                    <span><Pill text={String(item.live_state || (liveState?.audit_started || scan?.audit_started ? 'auditing' : 'tracked')).replaceAll('_', ' ')} tone={item.live_state === 'confirmed_drone_evidence' ? 'green' : (item.live_state === 'correlated_drone_candidate' ? 'warning' : 'cyan')} /></span>
                    <span>{(item.sensor_sources || []).join(' + ') || '--'}</span>
                    <span><Pill text={`${item?.confidence_score?.score ?? item.confidence ?? 0}`} tone={toneForConfidence(item?.confidence_score?.score ?? item.confidence)} /></span>
                  </button>
                ))}
                {!operatorTableTargets.length ? (
                  <div className="empty-box empty-box--operator">
                    {huntActive
                      ? 'No confident drone target retained yet. The operator table will populate only after the system promotes a drone candidate.'
                      : 'Operator table is empty. Click Start Hunt to begin passive drone detection.'}
                  </div>
                ) : null}
              </div>
              </div>
            </Panel>
          ) : null}

          {workspace === 'evidence' ? (
            <Panel kicker="Workspace 2" title="Evidence">
              <div className="intel-stack">
                <div className="intel-row"><span>Raw Wi-Fi rows</span><strong>{evidence?.counts?.wifi_rows ?? 0}</strong></div>
                <div className="intel-row"><span>Raw SDR rows</span><strong>{evidence?.counts?.sdr_rows ?? 0}</strong></div>
                <div className="intel-row"><span>Evidence bundles</span><strong>{evidence?.counts?.targets ?? 0}</strong></div>
              </div>
              <div className="hunt-drones-log-list">
                {(evidence?.bundles || []).map((bundle) => (
                  <div key={bundle.target_id} className="hunt-drones-log-item">
                    <strong>{bundle.label}</strong>
                    <span>Tier {bundle?.proof_tier?.tier ?? 0} · confidence {bundle.confidence ?? 0}</span>
                    <small>{(bundle?.evidence_bundle?.replay_pointers || []).join(' · ') || 'No replay pointers retained.'}</small>
                  </div>
                ))}
              </div>
            </Panel>
          ) : null}

          {workspace === 'target' ? (
            <Panel kicker="Workspace 3" title={selectedTarget?.label || 'Target Intelligence'}>
              {selectedTarget ? (
                <div className="hunt-drones-detail">
                  <div className="pill-row">
                    <Pill text={droneVerdict.label} tone={droneVerdict.tone} />
                    <Pill text={selectedTarget.target_class || selectedTarget.classification} tone={toneForClass(selectedTarget.target_class || selectedTarget.classification)} />
                    <Pill text={`Tier ${selectedTarget?.proof_tier?.tier ?? 0}`} tone={toneForProof(selectedTarget?.proof_tier?.tier)} />
                    <Pill text={`${selectedTarget?.confidence_score?.score ?? 0} confidence`} tone={toneForConfidence(selectedTarget?.confidence_score?.score)} />
                    <Pill text={`DSS ${selectedTarget?.disruption_susceptibility?.label || 'Unknown'}`} tone="neutral" />
                  </div>
                  <div className="advisory-card">
                    <strong>Operator Verdict</strong>
                    <div className="device-meta">{droneVerdict.summary}</div>
                  </div>
                  <div className="intel-stack">
                    <div className="intel-row"><span>Manufacturer</span><strong>{selectedTarget.manufacturer || '--'}</strong></div>
                    <div className="intel-row"><span>Protocol Class</span><strong>{selectedTarget.model_family || '--'}</strong></div>
                    <div className="intel-row"><span>Family</span><strong>{selectedTarget.family_label || '--'}</strong></div>
                    <div className="intel-row"><span>Sensor Sources</span><strong>{(selectedTarget.sensor_sources || []).join(', ') || '--'}</strong></div>
                    <div className="intel-row"><span>Band / Channel</span><strong>{selectedTarget.band} / {selectedTarget.channel}</strong></div>
                    <div className="intel-row"><span>Group</span><strong>{selectedTarget.swarm_label || 'Single Target'} · {selectedTarget.swarm_count || 1}</strong></div>
                  </div>
                  <div className="advisory-card">
                    <strong>Confidence Rationale</strong>
                    <div className="device-meta">{(selectedTarget?.confidence_score?.rationale || []).join(' · ') || 'No rationale retained.'}</div>
                  </div>
                  <div className="advisory-card">
                    <strong>Scheduler Hints</strong>
                    <div className="device-meta">{formatSchedulerHints(selectedTarget)}</div>
                  </div>
                  <div className="advisory-card">
                    <strong>Resilience Audit</strong>
                    <div className="device-meta">{selectedTarget?.disruption_susceptibility?.label || 'Unknown'} susceptibility · {(selectedTarget?.disruption_susceptibility?.rationale || []).join(' · ')}</div>
                    <div className="device-meta">Audit-safe estimate only. This workspace does not provide jamming, takeover, forced landing, or interference actions.</div>
                  </div>
                  <div className="advisory-card">
                    <strong>Decoder Diagnostics</strong>
                    <div className="device-meta">{(selectedTarget?.decoder_diagnostics?.rationale || []).join(' · ') || 'No decoder diagnostics retained.'}</div>
                  </div>
                </div>
              ) : <div className="empty-box">Select a retained drone row from the operator table to inspect target intelligence.</div>}
            </Panel>
          ) : null}

          {workspace === 'topology' ? (
            <Panel kicker="Workspace 4" title="Topology">
              <div className="hunt-drones-topology hunt-drones-topology--stack">
                <div className="hunt-drones-topology-column">
                  <strong>Nodes</strong>
                  {topologyNodes.map((node) => (
                    <div key={node.id} className="hunt-drones-topology-item">
                      <span>{node.label}</span>
                      <small>{node.type} · {node.confidence ?? '--'}</small>
                    </div>
                  ))}
                </div>
                <div className="hunt-drones-topology-column">
                  <strong>Edges</strong>
                  {topologyEdges.map((edge) => (
                    <div key={edge.id} className="hunt-drones-topology-item">
                      <span>{edge.type}</span>
                      <small>{edge.source} → {edge.target}</small>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          ) : null}

          {workspace === 'replay' ? (
            <Panel kicker="Workspace 5" title="Replay / Validation">
              <div className="hunt-drones-log-list">
                {replaySessions.map((item) => (
                  <div key={item.session_id} className="hunt-drones-log-item">
                    <strong>{item.session_name}</strong>
                    <span>{item.target_count} targets · {item.scan_profile}</span>
                    <small>{fmtTime(item.created_at)}</small>
                    <button className="mini-action" onClick={() => handleReplayLoad(item.session_id)} disabled={busy}>Load Replay</button>
                  </div>
                ))}
              </div>
              <div className="advisory-card">
                <strong>Replay Notes</strong>
                <div className="device-meta">{status?.replay_state === 'loaded' ? 'Replay loaded from retained evidence bundle. Compare score model output against previous report artifacts.' : 'Load a prior session to validate deterministic scoring and report regeneration.'}</div>
              </div>
            </Panel>
          ) : null}

          {workspace === 'settings' ? (
            <Panel kicker="Workspace 6" title="Settings / Policy">
              <div className="hunt-drones-lock">The operator-facing product is receive-only. Offensive and research-sensitive controls are backend-disabled in this build.</div>
              <div className="intel-stack">
                {(settings?.policy?.operator_blocks || []).map((item) => (
                  <div key={item.name} className="intel-row">
                    <span>{item.name}</span>
                    <strong>{item.operator_state}</strong>
                  </div>
                ))}
              </div>
              <div className="pill-row">
                {['jamming', 'injection', 'transmit_sdr', 'deauth', 'spoofing', 'rerouting', 'takeover'].map((item) => (
                  <button key={item} className="mini-action" onClick={() => handleBlockedCapability(item)}>
                    {item}
                  </button>
                ))}
              </div>
              <div className="advisory-card">
                <strong>Research Gates</strong>
                <div className="device-meta">
                  {(settings?.policy?.research_blocks || []).map((item) => `${item.name}: ${item.state}`).join(' · ')}
                </div>
              </div>
            </Panel>
          ) : null}
        </div>

        <div className="side-column">
          {workspace === 'live' ? (
            <>
              <Panel kicker="Command Rail" title="Scan Activity">
                <div className="hunt-drones-ops-console">
                  <div className="hunt-drones-ops-head">
                    <div className={`hunt-drones-ops-led ${huntActive ? 'live' : ''} ${liveState?.lead_detected ? 'contact' : ''}`} />
                    <strong>{leadStatusLabel}</strong>
                    <small>{huntActive ? 'scan operational' : 'waiting for start'}</small>
                  </div>
                  <div className="hunt-drones-ops-feed">
                    {commandFeed.map((item, index) => (
                      <div key={`${item.title}-${index}`} className={`hunt-drones-ops-item tone-${item.tone || 'quiet'}`}>
                        <span>{item.title}</span>
                        <strong>{item.detail}</strong>
                        <small>{item.meta}</small>
                      </div>
                    ))}
                  </div>
                </div>
              </Panel>

              <Panel kicker="Command Rail" title="Signal Matrix">
                <div className="hunt-drones-signal-matrix">
                  {(bandAttention.length ? bandAttention : [{ band: '2.4 GHz', attention_score: 12, priority: 'watch' }, { band: '5.8 GHz', attention_score: 12, priority: 'watch' }]).map((item) => (
                    <div key={item.band} className="hunt-drones-signal-cell">
                      <div className="hunt-drones-signal-meter">
                        <span style={{ height: `${Math.max(10, Math.min(100, Number(item.attention_score || 0)))}%` }} />
                      </div>
                      <strong>{item.band}</strong>
                      <small>{item.priority}</small>
                    </div>
                  ))}
                </div>
                <div className="hunt-drones-ops-mini-grid">
                  {scanningDevices.map((item) => (
                    <div key={`${item.name}-${item.device}`} className={`hunt-drones-ops-mini ${item.active ? 'active' : ''}`}>
                      <span>{item.name}</span>
                      <strong>{item.active ? 'LIVE' : 'READY'}</strong>
                    </div>
                  ))}
                </div>
              </Panel>
            </>
          ) : (
            <>
              <Panel kicker="Live Graph" title="Topology">
                <div className="hunt-drones-log-list">
                  {topologyNodes.map((node) => (
                    <div key={node.id} className="hunt-drones-log-item">
                      <strong>{node.label}</strong>
                      <span>{node.type}</span>
                      <small>{node.confidence ?? '--'} confidence</small>
                    </div>
                  ))}
                  {!topologyNodes.length ? <div className="empty-box">No live topology nodes yet.</div> : null}
                </div>
              </Panel>

              <Panel kicker="Live Links" title="What Is Happening">
                <div className="hunt-drones-log-list">
                  {schedulerActions.length ? schedulerActions.map((item, index) => (
                    <div key={`${item.lead_id}-${item.action}-${index}`} className="hunt-drones-log-item">
                      <strong>{item.action}</strong>
                      <span>{item.sensor} · {item.band}</span>
                      <small>{item.reason}</small>
                    </div>
                  )) : topologyEdges.map((edge) => (
                    <div key={edge.id} className="hunt-drones-log-item">
                      <strong>{edge.type}</strong>
                      <span>{edge.source} → {edge.target}</span>
                      <small>live correlation</small>
                    </div>
                  ))}
                  {!topologyEdges.length ? passiveRows.map((item, index) => (
                    <div key={`${item.title}-${index}`} className="hunt-drones-log-item">
                      <strong>{item.title}</strong>
                      <span>{item.detail}</span>
                      <small>{item.meta}</small>
                    </div>
                  )) : null}
                </div>
              </Panel>

              <Panel kicker="Reports" title="Audit Reports">
                <div className="hunt-drones-log-list">
                  {reports.map((item, index) => (
                    <div key={index} className="hunt-drones-log-item">
                      <strong>{item.session_name || 'Session Summary'}</strong>
                      <span>{item.summary?.detections || 0} detections · {item.summary?.decoder_backed || 0} decoder-backed</span>
                      <small>{fmtTime(item.generated_at)}</small>
                    </div>
                  ))}
                </div>
              </Panel>

              <Panel kicker="Fusion" title="Evidence Strength Timeline">
                <div className="hunt-drones-log-list">
                  {fusionWindows.slice(0, 8).map((item) => (
                    <div key={`${item.lead_id}-${item.last_seen}`} className="hunt-drones-log-item">
                      <strong>{item.band_focus}</strong>
                      <span>{(item.sensor_sources || []).join(' + ') || 'unknown sensors'}</span>
                      <small>recurrence {item.recurrence} · density {Number(item.density || 0).toFixed(2)}</small>
                    </div>
                  ))}
                  {!fusionWindows.length ? <div className="empty-box">No fused evidence windows yet.</div> : null}
                </div>
              </Panel>
            </>
          )}
        </div>
      </main>
    </>
  )
}
