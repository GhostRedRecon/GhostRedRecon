import { useEffect, useMemo, useRef, useState } from 'react'
import { Panel, Pill } from '../components/ui'
import {
  auditLayersWiFiMk7CameraLead,
  analyzeWiFiMk7CameraLead,
  clearWiFiMk7Session,
  fetchWiFiMk7CameraHuntResults,
  fetchWiFiMk7CameraHuntStatus,
  fetchWiFiMk7Channels,
  fetchWiFiMk7ChannelsLight,
  fetchWiFiMk7Clients,
  fetchWiFiMk7Networks,
  fetchWiFiMk7OperatorSnapshot,
  fetchWiFiMk7Pcap,
  fetchWiFiMk7Status,
  probeWiFiMk7CameraIp,
  probeWiFiMk7CameraLead,
  runWiFiMk7AdversaryReplay,
  runWiFiMk7HardAudit,
  runWiFiMk7RedTeamPreflight,
  runWiFiMk7RedTeamValidation,
  runWiFiMk7ImportedAnalysis,
  startWiFiMk7VideoTruthTest,
  startWiFiMk7Session,
  stopWiFiMk7Session,
} from '../lib/api'
import { usePanelPreferences } from '../lib/viewPreferences'
import { useWiFiMk7FeaturePreferences } from '../lib/wifiMk7FeaturePreferences'

function fmtTime(timestamp) {
  if (!timestamp) return '--'
  return new Date(Number(timestamp) * 1000).toLocaleString()
}

const DEFAULT_SCAN_DURATION_SECONDS = 180
const HARD_AUDIT_DURATION_SECONDS = 60
const SCAN_DURATION_OPTIONS = [
  { value: 60, label: '1 Minute' },
  { value: 180, label: '3 Minutes' },
  { value: 300, label: '5 Minutes' },
]

function fmtBandList(items) {
  return (items || []).join(' / ') || '--'
}

function fmtBytes(value) {
  const bytes = Math.max(0, Number(value || 0))
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${Math.round(bytes)} B`
}

function shortText(value, max = 48) {
  const text = String(value || '').trim()
  if (!text) return '--'
  if (text.length <= max) return text
  return `${text.slice(0, Math.max(0, max - 1)).trimEnd()}…`
}

function copyText(value) {
  const text = String(value || '').trim()
  if (!text || !navigator?.clipboard?.writeText) return
  navigator.clipboard.writeText(text).catch(() => {})
}

function clampPercent(value) {
  return Math.max(0, Math.min(100, Math.round(Number(value || 0))))
}

function formatScenarioLabel(value) {
  const raw = String(value || 'passive_observation').trim()
  if (!raw) return 'Passive Observation'
  return raw
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

const DEVICE_GROUP_ORDER = {
  AP: 1,
  CAMERA: 2,
  IOT: 3,
  INFRASTRUCTURE: 4,
  CLIENT: 5,
  UNKNOWN: 6,
}

const DEVICE_GROUP_COLORS = {
  green: '#1fa971',
  purple: '#8c57ff',
  yellow: '#d3a61a',
  red: '#de5148',
  blue: '#2d8cff',
  gray: '#8491a6',
}

const WIFI_INVENTORY_BUCKETS = {
  ROUTER: { order: 1, label: 'Routers', pill: 'Router', tone: 'cyan' },
  IOT: { order: 2, label: 'IoT Devices', pill: 'IoT', tone: 'warning' },
  CAMERA: { order: 3, label: 'WiFi Cameras', pill: 'Camera', tone: 'danger' },
  UNKNOWN: { order: 4, label: 'Unknown Devices', pill: 'Unknown', tone: 'neutral' },
}

const WIFI_HARD_AUDIT_PROGRESS_PLAN = [
  {
    id: 'target_validation',
    label: 'Target Validate',
    activeDetail: 'Resolving MAC, BSSID, and retained DDI evidence into a single target identity.',
    completeDetail: 'Target identity and IP evidence retained.',
    pendingDetail: 'Awaiting target selection.',
  },
  {
    id: 'port_discovery',
    label: 'Port Discovery',
    activeDetail: 'Testing safe local TCP surfaces exposed by the selected WiFi device.',
    completeDetail: 'Safe port discovery complete.',
    pendingDetail: 'Awaiting validated target IP.',
  },
  {
    id: 'service_id',
    label: 'Service ID',
    activeDetail: 'Inspecting open services for HTTP, TLS, RTSP, and banner-level identity proof.',
    completeDetail: 'Service identity evidence retained.',
    pendingDetail: 'Awaiting open port confirmation.',
  },
  {
    id: 'access_posture',
    label: 'Access Posture',
    activeDetail: 'Checking safe auth surfaces and whether services present open or gated access.',
    completeDetail: 'Access posture classified from safe probes.',
    pendingDetail: 'Awaiting service responses.',
  },
  {
    id: 'destination_analysis',
    label: 'External Destinations',
    activeDetail: 'Correlating retained PCAP evidence with DNS, TLS, and external endpoint telemetry.',
    completeDetail: 'External destination evidence retained.',
    pendingDetail: 'Awaiting target capture and audit trace.',
  },
  {
    id: 'trace',
    label: 'Trace',
    activeDetail: 'Finalizing artifacts, verdict, and evidence-backed hard-audit trace.',
    completeDetail: 'Hard-audit trace retained.',
    pendingDetail: 'Awaiting retained audit evidence.',
  },
]

function getDeviceClassification(item) {
  const classification = item?.device_classification || {}
  const group = String(classification?.device_group || item?.device_group || '').trim().toUpperCase() || 'UNKNOWN'
  const color = String(classification?.color || item?.device_group_color || '').trim().toLowerCase() || 'gray'
  const confidence = String(classification?.confidence || item?.device_group_confidence || '').trim().toUpperCase() || 'LOW'
  return {
    ...classification,
    device_group: group,
    color,
    confidence,
    confidence_rank: Number(classification?.confidence_rank || (confidence === 'HIGH' ? 3 : confidence === 'MEDIUM' ? 2 : 1)),
    sort_order: Number(classification?.sort_order || DEVICE_GROUP_ORDER[group] || DEVICE_GROUP_ORDER.UNKNOWN),
    group_label: classification?.group_label || group.replaceAll('_', ' '),
    classification_signals: Array.isArray(classification?.classification_signals) ? classification.classification_signals : (item?.classification_signals || []),
    explanation: String(classification?.explanation || item?.classification_explanation || '').trim() || 'No retained classification explanation.',
  }
}

function getDeviceGroupColor(item) {
  return DEVICE_GROUP_COLORS[getDeviceClassification(item).color] || DEVICE_GROUP_COLORS.gray
}

function getDeviceGroupTone(item) {
  const group = getDeviceClassification(item).device_group
  if (group === 'AP') return 'green'
  if (group === 'CAMERA') return 'danger'
  if (group === 'IOT') return 'warning'
  if (group === 'INFRASTRUCTURE') return 'danger'
  if (group === 'CLIENT') return 'cyan'
  return 'neutral'
}

function getWiFiInventoryBucket(item) {
  const classification = getDeviceClassification(item)
  const combinedText = [
    classification.device_group,
    classification.group_label,
    item?.fingerprint?.role,
    item?.fingerprint?.device_type,
    item?.fingerprint?.product_category,
    item?.fingerprint?.vendor_family,
    item?.vendor,
    item?.service_exposure?.summary,
  ].join(' ').toLowerCase()

  if (classification.device_group === 'CAMERA' || /camera|onvif|rtsp|nvr|dvr/.test(combinedText)) {
    return { key: 'CAMERA', ...WIFI_INVENTORY_BUCKETS.CAMERA }
  }
  if (classification.device_group === 'IOT') {
    return { key: 'IOT', ...WIFI_INVENTORY_BUCKETS.IOT }
  }
  if (classification.device_group === 'INFRASTRUCTURE' || classification.device_group === 'AP' || /router|gateway|mesh|access point|cpe|modem/.test(combinedText)) {
    return { key: 'ROUTER', ...WIFI_INVENTORY_BUCKETS.ROUTER }
  }
  return { key: 'UNKNOWN', ...WIFI_INVENTORY_BUCKETS.UNKNOWN }
}

function getWiFiInventoryTone(item) {
  return getWiFiInventoryBucket(item).tone
}

function getWiFiInventoryLabel(item) {
  if (item?.inventory_kind === 'client') {
    const host = item?.fingerprint?.probable_model || item?.fingerprint?.device_type || item?.device_assessment?.identity?.label
    return host || item?.vendor || item?.mac || 'Observed client'
  }
  return item?.ssid || '<hidden>'
}

function getWiFiInventorySupportingId(item) {
  if (item?.inventory_kind === 'client') {
    return item?.mac || item?.associated_bssid || 'unresolved client'
  }
  return item?.bssid || 'unresolved BSSID'
}

function getWiFiInventoryRfIpSummary(item) {
  const rssi = item?.rssi_dbm ?? '--'
  const ips = getDeviceIpEvidence(item).ips
  const base = [`${rssi} dBm`]
  if (ips.length) base.push(ips.slice(0, 2).join(', '))
  else if (item?.inventory_kind === 'client' && item?.associated_bssid) base.push(`assoc ${item.associated_bssid}`)
  return base.join(' · ')
}

function getWiFiInventoryEvidenceSummary(item) {
  const classification = getDeviceClassification(item)
  const signals = classification.classification_signals || []
  if (!signals.length) return classification.explanation
  return `${classification.explanation} Signals: ${signals.join(', ')}`
}

function getCompactObservedSupportLine(item) {
  const channel = item?.channel || '--'
  const kind = item?.inventory_kind === 'client' ? 'client' : 'ap'
  return shortText(`${getWiFiInventorySupportingId(item)} · ch ${channel} · ${kind}`, 38)
}

function getCompactObservedWhy(item, override) {
  const classification = getDeviceClassification(item)
  const deviceEvidence = getDeviceAuditEvidence(item, override)
  return {
    primary: shortText(classification.explanation, 34),
    secondary: shortText(deviceEvidence.summary, 30),
  }
}

function getCompactObservedRfIp(item) {
  return shortText(getWiFiInventoryRfIpSummary(item), 30)
}

function getCompactObservedVendorCategory(item) {
  return shortText(`${item?.fingerprint?.vendor_family || 'unknown'} · ${item?.fingerprint?.product_category || 'unclassified'}`, 28)
}

function getCompactObservedArtifactSummary(item) {
  const pcap = getPcapSavedStatus(item)
  const ips = getDeviceIpEvidence(item).ips
  return shortText(`${pcap.label} · ${ips.length ? `${ips.length} ip` : 'no ip'}`, 24)
}

function buildWiFiDeviceInventory(networks, clients) {
  const rows = [
    ...(networks || []).map((item) => ({ ...item, inventory_kind: 'network' })),
    ...(clients || []).map((item) => ({ ...item, inventory_kind: 'client' })),
  ]
    .filter((item) => !item?.synthetic_identity)
    .sort((left, right) => {
      const leftBucket = getWiFiInventoryBucket(left)
      const rightBucket = getWiFiInventoryBucket(right)
      const groupDelta = Number(leftBucket.order || 99) - Number(rightBucket.order || 99)
      if (groupDelta) return groupDelta
      const leftClass = getDeviceClassification(left)
      const rightClass = getDeviceClassification(right)
      const confidenceDelta = Number(rightClass.confidence_rank || 0) - Number(leftClass.confidence_rank || 0)
      if (confidenceDelta) return confidenceDelta
      const rightRssi = Number(right?.rssi_dbm ?? -1000)
      const leftRssi = Number(left?.rssi_dbm ?? -1000)
      if (rightRssi !== leftRssi) return rightRssi - leftRssi
      const scoreDelta = Number(right?.target_score?.score || 0) - Number(left?.target_score?.score || 0)
      if (scoreDelta) return scoreDelta
      return getWiFiInventoryLabel(left).localeCompare(getWiFiInventoryLabel(right))
    })
  let lastGroup = ''
  return rows.map((item) => {
    const bucket = getWiFiInventoryBucket(item)
    const withDivider = {
      ...item,
      inventory_group_divider: bucket.key !== lastGroup,
      inventory_group_key: bucket.key,
      inventory_group_label: bucket.label,
      inventory_group_pill: bucket.pill,
    }
    lastGroup = bucket.key
    return withDivider
  })
}

function buildRunningWiFiHardAuditState(targetId, activeStageIndex = 0) {
  const safeIndex = Math.max(0, Math.min(WIFI_HARD_AUDIT_PROGRESS_PLAN.length - 1, Number(activeStageIndex || 0)))
  return {
    status: 'running',
    audit_kind: 'wifi_hard_audit',
    audit_label: 'WiFi Hard Audit',
    target_id: targetId,
    pipeline: {
      status: 'running',
      current_stage: WIFI_HARD_AUDIT_PROGRESS_PLAN[safeIndex]?.id || 'target_validation',
      stages: WIFI_HARD_AUDIT_PROGRESS_PLAN.map((stage, index) => ({
        id: stage.id,
        label: stage.label,
        status: index < safeIndex ? 'completed' : index === safeIndex ? 'active' : 'pending',
        detail: index < safeIndex ? stage.completeDetail : index === safeIndex ? stage.activeDetail : stage.pendingDetail,
      })),
    },
  }
}

function extractDeviceStrings(values) {
  const seen = new Set()
  const rows = []
  for (const value of values || []) {
    const text = String(value || '').trim()
    if (!text || seen.has(text)) continue
    seen.add(text)
    rows.push(text)
  }
  return rows
}

function isHandshakeFocusedScanMode(value) {
  return ['handshake_hunt', 'adaptive_handshake_hunt'].includes(String(value || '').trim())
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

function normalizeSecurityValue(value) {
  return String(value || '').trim().toUpperCase()
}

function getSecurityWeight(network) {
  const security = normalizeSecurityValue(network?.security)
  if (security.includes('OPEN')) return 5
  if (security.includes('PROTECTED')) return 4
  if (security.includes('WPA2')) return 3
  if (security.includes('WPA3')) return 1
  return 2
}

function getPacketTruthScore(network) {
  const packetCount = Number(network?.packet_count || 0)
  const clientCount = Number(network?.client_count || 0)
  const hidden = network?.hidden_ssid ? 2 : 0
  const rssi = Math.max(0, 100 + Number(network?.rssi_dbm || -95))
  return getSecurityWeight(network) * 8 + clientCount * 5 + Math.round(packetCount / 2) + hidden * 3 + Math.round(rssi / 8)
}

function getOperationalTargetScore(item, mode) {
  const target = Number(item?.target_score?.score || 0)
  if (target) return target
  return getPacketTruthScore(item, mode)
}

function getNetworkPosture(network) {
  const security = normalizeSecurityValue(network?.security)
  if (security.includes('OPEN')) return 'Exposed Target'
  return network?.hidden_ssid ? 'Stealth Lead' : 'Profiled'
}

function getExposureSummary(network) {
  const security = normalizeSecurityValue(network?.security)
  const pmfEnabled = String(network?.pmf || '').toLowerCase() === 'true'
  const details = []
  if (security.includes('OPEN')) {
    details.push('Open')
  } else if (security.includes('WPA3')) {
    details.push('WPA3')
  } else if (security.includes('WPA2')) {
    details.push('WPA2')
  } else if (security.includes('PROTECTED')) {
    details.push('Protected')
  } else {
    details.push('Unknown')
  }
  if (!pmfEnabled) details.push('No PMF')
  if (network?.hidden_ssid) details.push('Hidden')
  return details.join(' / ')
}

function getHandshakeStatus(item) {
  const quality = String(item?.authentication_evidence?.quality || item?.authentication_evidence_quality || '').toUpperCase()
  if (quality === 'CONFIRMED') return 'Confirmed'
  if (quality === 'LIKELY') return 'Likely'
  if (quality === 'PARTIAL') return 'Partial'
  const observedFrames = Number(item?.authentication_evidence?.eapol_frame_count ?? item?.authentication_evidence_frame_count ?? item?.handshake_eapol_count ?? item?.eapol_count ?? 0)
  if (observedFrames > 0) return 'Observed'
  return 'Not Observed'
}

function getHandshakeTone(item) {
  const status = getHandshakeStatus(item)
  if (status === 'Confirmed') return 'danger'
  if (status === 'Likely') return 'warning'
  if (status === 'Partial' || status === 'Observed') return 'cyan'
  return 'neutral'
}

function getPasswordRiskTone(risk) {
  if (risk === 'UNASSESSED') return 'neutral'
  if (risk === 'CRITICAL') return 'danger'
  if (risk === 'HIGH') return 'warning'
  if (risk === 'MEDIUM') return 'cyan'
  return 'green'
}

function getPasswordRiskSummary(network) {
  if (network?.password_risk?.summary) return network.password_risk.summary
  if (network?.security_posture?.summary) return network.security_posture.summary
  return 'No passive password-risk assessment retained.'
}

function getPasswordRiskLabel(network) {
  return network?.password_risk?.risk || 'UNASSESSED'
}

function buildPasswordRiskTargets(networks) {
  return (networks || [])
    .filter((network) => !network?.synthetic_identity)
    .sort((left, right) => {
      const riskDelta = Number(right?.password_risk?.score || 0) - Number(left?.password_risk?.score || 0)
      if (riskDelta) return riskDelta
      const handshakeDelta = Number(right?.handshake_eapol_count || right?.eapol_count || 0) - Number(left?.handshake_eapol_count || left?.eapol_count || 0)
      if (handshakeDelta) return handshakeDelta
      return Number(right?.target_score?.score || 0) - Number(left?.target_score?.score || 0)
    })
    .slice(0, 8)
}

function buildHandshakeSummary(authEvidence) {
  const qualityCounts = authEvidence?.quality_counts || {}
  return {
    sessionCount: Number(authEvidence?.session_count || 0),
    networkCount: Number(authEvidence?.network_count || 0),
    clientCount: Number(authEvidence?.client_count || 0),
    evidenceCount: Number(authEvidence?.session_count || 0),
    totalEapolFrames: Number(authEvidence?.total_frame_count || 0),
    qualityCounts: {
      CONFIRMED: Number(qualityCounts.CONFIRMED || 0),
      LIKELY: Number(qualityCounts.LIKELY || 0),
      PARTIAL: Number(qualityCounts.PARTIAL || 0),
    },
  }
}

function getAuthenticationEvidenceTone(quality) {
  if (quality === 'CONFIRMED') return 'danger'
  if (quality === 'LIKELY') return 'warning'
  if (quality === 'PARTIAL') return 'cyan'
  return 'neutral'
}

function buildEvidenceQueue(sessions, networks) {
  const networkByBssid = new Map((networks || []).map((network) => [String(network?.bssid || '').toLowerCase(), network]))
  return (sessions || [])
    .sort((left, right) => {
      const evidenceDelta = Number(right?.frame_count || 0) - Number(left?.frame_count || 0)
      if (evidenceDelta) return evidenceDelta
      const rightNetwork = networkByBssid.get(String(right?.bssid || '').toLowerCase())
      const leftNetwork = networkByBssid.get(String(left?.bssid || '').toLowerCase())
      return Number(rightNetwork?.observation_opportunity?.score || 0) - Number(leftNetwork?.observation_opportunity?.score || 0)
    })
    .slice(0, 8)
    .map((session) => ({
      ...session,
      network: networkByBssid.get(String(session?.bssid || '').toLowerCase()) || null,
    }))
}

function buildCoverageRows(networks, sessions) {
  const sessionCounts = new Map()
  for (const session of sessions || []) {
    const bssid = String(session?.bssid || '').toLowerCase()
    if (!bssid) continue
    sessionCounts.set(bssid, (sessionCounts.get(bssid) || 0) + 1)
  }

  return (networks || [])
    .filter((network) => !network?.synthetic_identity)
    .map((network) => {
      const bssid = String(network?.bssid || '').toLowerCase()
      const evidence = network?.authentication_evidence || {}
      const opportunity = network?.observation_opportunity || {}
      const sessionCount = sessionCounts.get(bssid) || 0
      const retainedFrames = Number(network?.frame_count_total || network?.packet_count || 0)
      const visits = Number(network?.observation_capture_count || 0)
      const evidenceQuality = evidence?.quality || 'NONE'
      const observationLevel = opportunity?.level || 'LOW'
      const observationScore = Number(opportunity?.score || 0)
      const observationSummary = opportunity?.summary || 'limited passive observation cues'
      const redObservation = [
        network?.security || 'Unknown security',
        network?.pmf ? `PMF ${network.pmf}` : 'PMF unknown',
        `${sessionCount} observed EAPOL session${sessionCount === 1 ? '' : 's'}`,
        `${retainedFrames} retained frames`,
        `${visits} capture visit${visits === 1 ? '' : 's'}`,
        `opportunity ${observationLevel} ${observationScore}/100`,
        evidence?.summary || observationSummary,
      ].join(' · ')

      return {
        id: getNetworkId(network),
        network,
        bssid,
        ssid: network?.ssid || '<hidden>',
        channel: network?.channel || '--',
        visits,
        retainedFrames,
        sessionCount,
        observationLevel,
        observationScore,
        observationSummary,
        evidenceQuality,
        redObservation,
      }
    })
    .sort((left, right) => {
      const sessionDelta = right.sessionCount - left.sessionCount
      if (sessionDelta) return sessionDelta
      const qualityRank = { CONFIRMED: 3, LIKELY: 2, PARTIAL: 1, NONE: 0 }
      const qualityDelta = (qualityRank[right.evidenceQuality] || 0) - (qualityRank[left.evidenceQuality] || 0)
      if (qualityDelta) return qualityDelta
      const opportunityDelta = right.observationScore - left.observationScore
      if (opportunityDelta) return opportunityDelta
      return right.retainedFrames - left.retainedFrames
    })
}

function buildCoverageMap(rows) {
  return new Map((rows || []).map((row) => [row.id, row]))
}

function buildOperatorSummary(networks, coverageRows, handshakeSummary) {
  const totalNetworks = Number((networks || []).length || 0)
  const highOpportunity = (coverageRows || []).filter((row) => row.observationScore >= 70).length
  const evidenceBacked = (coverageRows || []).filter((row) => row.sessionCount > 0).length
  const underObserved = (coverageRows || []).filter((row) => row.visits <= 1 && row.observationScore >= 50).length
  return [
    { label: 'Observed', value: totalNetworks, detail: 'confirmed SSIDs' },
    { label: 'Evidence', value: handshakeSummary?.sessionCount ?? 0, detail: 'observed sessions' },
    { label: 'High Opp', value: highOpportunity, detail: 'priority SSIDs' },
    { label: 'Underseen', value: underObserved, detail: 'needs more dwell' },
    { label: 'Backed', value: evidenceBacked, detail: 'SSID with EAPOL' },
  ]
}

function getNetworkObservationTooltip(network, coverageRow) {
  const reasons = getMissionReasons(network, 'RED').slice(0, 3)
  const details = [
    network?.ssid || '<hidden>',
    network?.bssid || 'unresolved',
    network?.security || 'Unknown security',
    `risk ${network?.password_risk?.risk || 'LOW'} ${network?.password_risk?.score ?? 0}/100`,
    `auth ${network?.authentication_evidence?.quality || 'NONE'} ${network?.authentication_evidence?.eapol_frame_count ?? 0} EAPOL`,
    `opp ${coverageRow?.observationLevel || network?.observation_opportunity?.level || 'LOW'} ${coverageRow?.observationScore ?? network?.observation_opportunity?.score ?? 0}/100`,
    `visits ${coverageRow?.visits ?? network?.observation_capture_count ?? 0}`,
    `frames ${coverageRow?.retainedFrames ?? network?.frame_count_total ?? network?.packet_count ?? 0}`,
  ]
  if (reasons.length) {
    details.push(`red read ${reasons.join(' / ')}`)
  }
  return details.join(' · ')
}

function evaluatePskPolicy(candidate, network) {
  const psk = String(candidate || '')
  const security = String(network?.security || '').toUpperCase()
  const result = {
    score: 0,
    verdict: 'Needs review',
    checks: [],
    recommendations: [],
  }

  if (!psk) {
    result.checks.push('No PSK entered')
    result.recommendations.push('Use a long random passphrase of at least 16 characters.')
    result.recommendations.push('Prefer WPA3-SAE where supported and disable WPS.')
    return result
  }

  const longEnough = psk.length >= 16
  const hasUpper = /[A-Z]/.test(psk)
  const hasLower = /[a-z]/.test(psk)
  const hasDigit = /\d/.test(psk)
  const hasSymbol = /[^A-Za-z0-9]/.test(psk)
  const looksSequential = /(0123|1234|2345|3456|4567|5678|6789|7890|qwer|asdf|password|admin|welcome)/i.test(psk)
  const ssid = String(network?.ssid || '').toLowerCase()
  const containsSsid = ssid && psk.toLowerCase().includes(ssid.replace(/[^a-z0-9]/g, ''))

  if (longEnough) result.score += 35
  if (hasUpper) result.score += 15
  if (hasLower) result.score += 15
  if (hasDigit) result.score += 15
  if (hasSymbol) result.score += 20
  if (looksSequential) result.score -= 25
  if (containsSsid) result.score -= 20
  if (security.includes('WPA3')) result.score += 10

  result.checks.push(longEnough ? 'Length >= 16' : 'Length < 16')
  result.checks.push(hasUpper ? 'Uppercase present' : 'No uppercase')
  result.checks.push(hasLower ? 'Lowercase present' : 'No lowercase')
  result.checks.push(hasDigit ? 'Digit present' : 'No digit')
  result.checks.push(hasSymbol ? 'Symbol present' : 'No symbol')
  if (looksSequential) result.checks.push('Common or sequential pattern detected')
  if (containsSsid) result.checks.push('Contains SSID-related text')

  if (result.score >= 80) result.verdict = 'Strong policy alignment'
  else if (result.score >= 60) result.verdict = 'Moderate policy alignment'
  else result.verdict = 'Weak policy alignment'

  if (!longEnough) result.recommendations.push('Increase PSK length to at least 16 characters.')
  if (!(hasUpper && hasLower && hasDigit && hasSymbol)) result.recommendations.push('Use mixed case, digits, and symbols for a less predictable passphrase.')
  if (looksSequential || containsSsid) result.recommendations.push('Avoid common words, vendor names, SSID fragments, or sequential patterns.')
  if (!security.includes('WPA3')) result.recommendations.push('Upgrade the SSID to WPA3-SAE where supported.')
  result.recommendations.push('Disable WPS and isolate high-value devices onto a separate SSID or VLAN.')

  return result
}

function buildHandshakeEvidence(networks, clients) {
  const networkHits = (networks || [])
    .filter((item) => getHandshakeStatus(item) !== 'Not Observed')
    .sort((left, right) => Number(right.handshake_eapol_count || 0) - Number(left.handshake_eapol_count || 0))
    .slice(0, 6)
    .map((item) => ({
      kind: 'network',
      id: item.record_id || item.bssid,
      label: item.ssid || '<hidden>',
      supportingId: item.bssid || '--',
      count: Number(item.handshake_eapol_count || item.eapol_count || 0),
      channel: item.channel || '--',
      rssi: item.rssi_dbm ?? '--',
      firstSeen: item.handshake_first_seen || item.first_seen,
      lastSeen: item.handshake_last_seen || item.last_seen,
      related: item.handshake_related_macs || [],
    }))

  const clientHits = (clients || [])
    .filter((item) => getHandshakeStatus(item) !== 'Not Observed')
    .sort((left, right) => Number(right.eapol_count || 0) - Number(left.eapol_count || 0))
    .slice(0, 6)
    .map((item) => ({
      kind: 'client',
      id: item.mac,
      label: item.mac || '<unknown client>',
      supportingId: item.associated_bssid || '--',
      count: Number(item.eapol_count || 0),
      channel: item.channel || '--',
      rssi: item.rssi_dbm ?? '--',
      firstSeen: item.handshake_first_seen || item.first_seen,
      lastSeen: item.handshake_last_seen || item.last_seen,
      related: item.handshake_related_macs || [],
    }))

  return [...networkHits, ...clientHits]
    .sort((left, right) => right.count - left.count)
    .slice(0, 8)
}

function getPostureDetail(network) {
  const security = normalizeSecurityValue(network?.security)
  if (security.includes('OPEN')) return 'Open network with no link-layer protection.'
  if (network?.hidden_ssid) return 'Hidden SSID worth profiling for quiet infrastructure or staged assets.'
  return 'Profiled target with packet-backed visibility and retained evidence.'
}

function formatVendorCountry(network) {
  const vendor = network?.vendor || '--'
  const country = network?.vendor_country || network?.vendor_country_code || '--'
  return `${vendor} / ${country}`
}

function countryCodeToFlag(value) {
  const code = String(value || '').trim().toUpperCase()
  if (!/^[A-Z]{2}$/.test(code)) return ''
  return String.fromCodePoint(...[...code].map((char) => 127397 + char.charCodeAt(0)))
}

function getDestinationAnalysis(target, override) {
  return override?.destination_analysis || target?.destination_analysis || {}
}

function getExternalDestinationLimitations(target, override) {
  const analysis = getDestinationAnalysis(target, override)
  const limits = analysis?.limitations || []
  return Array.isArray(limits) && limits.length
    ? limits
    : [
        'GeoIP accuracy depends on database freshness.',
        'ASN ownership may change.',
        'CDN infrastructure may mask backend.',
        'Routing does not prove ownership.',
        'Encrypted traffic limits visibility.',
      ]
}

function getEndpointConfidencePercent(endpoint) {
  const numeric = Number(endpoint?.confidence_score ?? 0)
  if (numeric > 0) return clampPercent(numeric)
  const label = String(endpoint?.confidence || '').trim().toUpperCase()
  if (label === 'HIGH') return 85
  if (label === 'MEDIUM') return 55
  if (label === 'LOW') return 20
  return 0
}

function getExternalDestinationSummary(target, override) {
  const analysis = getDestinationAnalysis(target, override)
  const endpoints = analysis?.external_endpoints || []
  if (endpoints.length) {
    const top = endpoints[0]
    const flag = countryCodeToFlag(top?.country)
    const country = top?.country || top?.country_display || 'UNKNOWN'
    return {
      primary: `${flag ? `${flag} ` : ''}${country} · ${top?.ip || '--'}`.trim(),
      secondary: `${top?.org || top?.domain || 'external endpoint'} · ${top?.confidence || 'LOW'}`,
      endpointCount: endpoints.length,
    }
  }
  const state = String(analysis?.analysis_state || '').trim()
  if (state === 'NO_EXTERNAL_ENDPOINTS') {
    return { primary: 'No external endpoints', secondary: analysis?.assessment || 'No public destination was retained.', endpointCount: 0 }
  }
  if (state === 'SKIPPED_NO_VALIDATED_IP') {
    return { primary: 'No validated IP', secondary: analysis?.assessment || 'DDI validation required before EDDA.', endpointCount: 0 }
  }
  if (state === 'UNAVAILABLE') {
    return { primary: 'Analysis unavailable', secondary: analysis?.assessment || 'Target PCAP parsing did not complete.', endpointCount: 0 }
  }
  if (state === 'DISABLED') {
    return { primary: 'EDDA disabled', secondary: analysis?.assessment || 'External destination analysis is disabled.', endpointCount: 0 }
  }
  return { primary: 'Not analyzed', secondary: 'Run Service Audit to retain offline external destination evidence.', endpointCount: 0 }
}

function getNetworkId(network) {
  return network?.record_id || network?.bssid || network?.associated_bssid || network?.mac || network?.client_mac || ''
}

function getCameraLeadId(item) {
  if (!item) return ''
  if (String(item?.leadKind || '').toLowerCase() === 'client' || item?.mac) {
    return `client:${String(item?.mac || item?.record_id || '').toLowerCase()}`
  }
  return `network:${String(item?.bssid || item?.record_id || '').toLowerCase()}`
}

function getEntitySelectionId(item, cameraHuntMode = false) {
  if (!item) return ''
  if (cameraHuntMode) return getCameraLeadId(item) || getNetworkId(item) || String(item?.mac || '')
  return getNetworkId(item)
}

function getRedTeamTargetId(item, cameraHuntMode = false) {
  if (!item) return ''
  if (cameraHuntMode) {
    if (String(item?.leadKind || '').toLowerCase() === 'client' || item?.mac) {
      return String(item?.mac || item?.record_id || '').toLowerCase()
    }
    return String(item?.bssid || item?.record_id || '').toLowerCase()
  }
  return String(item?.bssid || item?.associated_bssid || item?.record_id || item?.mac || item?.client_mac || '').toLowerCase()
}

function formatPercent(value) {
  const numeric = Number(value || 0)
  return `${Math.round(numeric * 100)}%`
}

function formatProbeFamilies(matches) {
  return (matches || [])
    .map((match) => {
      if (!match?.family) return ''
      const tokens = (match.tokens || []).slice(0, 3).join(', ')
      return tokens ? `${match.family} (${tokens})` : String(match.family)
    })
    .filter(Boolean)
    .join(' · ')
}

function getRedTeamBadgeTone(value) {
  const text = String(value || '').toUpperCase()
  if (text.includes('BLOCKED') || text.includes('FAILED')) return 'danger'
  if (text.includes('REAL_FRAMES_OBSERVED') || text.includes('EAPOL_OBSERVED') || text.includes('EFFECT_OBSERVED')) return 'green'
  if (text.includes('PMF_LIKELY_EFFECTIVE') || text.includes('NO_EFFECT_OBSERVED')) return 'warning'
  if (text.includes('READY')) return 'cyan'
  return 'neutral'
}

function getRedTeamActionProfile(actionType) {
  const profiles = {
    deauth_evidence_probe: {
      label: 'Deauth Evidence Probe',
      filter: 'wlan.fc.type_subtype == 0x0c',
      expected: 'Deauthentication management frames affecting the selected AP/client pair.',
      defensive: 'Protected Management Frames / 802.11w may suppress or reduce effect.',
    },
    disassociation_evidence_probe: {
      label: 'Disassociation Evidence Probe',
      filter: 'wlan.fc.type_subtype == 0x0a',
      expected: 'Disassociation management frames affecting the selected AP/client pair.',
      defensive: 'Protected Management Frames / 802.11w may suppress or reduce effect.',
    },
    handshake_visibility_trigger: {
      label: 'Handshake Visibility Trigger',
      filter: 'eapol',
      expected: 'EAPOL sequence associated with reconnect or authentication activity.',
      defensive: 'PMF or absence of reconnect behavior may prevent any observable effect.',
    },
  }
  return profiles[actionType] || profiles.deauth_evidence_probe
}

function buildRedTeamEvidenceIndicator(actionType, lastRun) {
  const run = lastRun || {}
  const badges = new Set(run?.result_badges || [])
  const packetCounters = run?.packet_counters || {}
  const observedEffects = run?.observed_effects || {}
  const matchingPackets = Number(packetCounters?.matching_packets || 0)
  const actionPcap = String(run?.evidence_files?.action_pcap || '').trim()
  const deauthMode = actionType === 'deauth_evidence_probe'
  const disassocMode = actionType === 'disassociation_evidence_probe'
  const handshakeMode = actionType === 'handshake_visibility_trigger'

  if (deauthMode) {
    if (matchingPackets > 0) {
      return {
        tone: 'green',
        status: 'DEAUTH EVIDENCE CONFIRMED',
        summary: `${matchingPackets} real deauthentication frame(s) were retained for the selected target.`,
        detail: actionPcap ? `Evidence file retained: ${actionPcap}` : 'Action PCAP retained in the current WiFi Hunt red-team evidence set.',
      }
    }
    if (badges.has('PMF_LIKELY_EFFECTIVE') || observedEffects?.pmf_likely_effective) {
      return {
        tone: 'warning',
        status: 'PMF LIKELY EFFECTIVE',
        summary: 'No deauthentication effect was observed and Protected Management Frames likely reduced or blocked the behavior.',
        detail: 'This is retained as packet-truth evidence for operator review.',
      }
    }
    if (badges.has('NO_EFFECT_OBSERVED') || run?.state === 'COMPLETED_NO_EFFECT_OBSERVED') {
      return {
        tone: 'warning',
        status: 'NO DEAUTH FRAMES OBSERVED',
        summary: 'The validation completed, but no matching deauthentication evidence was retained for the selected target.',
        detail: 'Review channel lock, target recency, and whether the loaded PCAP actually contains deauth traffic.',
      }
    }
    return {
      tone: 'neutral',
      status: run?.state || 'IDLE',
      summary: 'No deauthentication evidence run has completed yet.',
      detail: 'Run Validation during live capture to produce retained deauth evidence.',
    }
  }

  if (disassocMode) {
    return {
      tone: matchingPackets > 0 ? 'green' : 'neutral',
      status: matchingPackets > 0 ? 'DISASSOC EVIDENCE CONFIRMED' : (run?.state || 'IDLE'),
      summary: matchingPackets > 0
        ? `${matchingPackets} real disassociation frame(s) were retained for the selected target.`
        : 'No completed disassociation evidence run is retained yet.',
      detail: matchingPackets > 0
        ? (actionPcap ? `Evidence file retained: ${actionPcap}` : 'Action PCAP retained in the current WiFi Hunt red-team evidence set.')
        : 'Use this action when you want disassociation-specific packet evidence.',
    }
  }

  if (handshakeMode) {
    const eapolPackets = Number(packetCounters?.eapol_packets || 0)
    return {
      tone: eapolPackets > 0 ? 'green' : 'neutral',
      status: eapolPackets > 0 ? 'EAPOL EVIDENCE CONFIRMED' : (run?.state || 'IDLE'),
      summary: eapolPackets > 0
        ? `${eapolPackets} EAPOL frame(s) were retained for the selected target.`
        : 'No completed handshake visibility run is retained yet.',
      detail: eapolPackets > 0
        ? 'Use the retained EAPOL evidence and mapping for RED validation.'
        : 'Use this action when you want reconnect / authentication visibility evidence.',
    }
  }

  return {
    tone: 'neutral',
    status: run?.state || 'IDLE',
    summary: 'No action-specific evidence indicator is available.',
    detail: 'Select a Red Team action to produce retained evidence.',
  }
}

function summarizeHttpProbe(httpProbe) {
  const findings = httpProbe?.findings || []
  if (!findings.length) return httpProbe?.error || 'No HTTP response'
  const best = findings.find((item) => item?.camera_hint) || findings[0]
  const parts = [
    `${String(best?.scheme || 'http').toUpperCase()} ${best?.port || '--'}${best?.path || '/'}`,
    best?.status ? `${best.status} ${best.reason || ''}`.trim() : '',
    best?.server ? `server ${best.server}` : '',
    best?.www_authenticate ? `auth ${best.www_authenticate}` : '',
    best?.matched_families?.length ? `families ${formatProbeFamilies(best.matched_families)}` : '',
  ]
  return parts.filter(Boolean).join(' · ')
}

function summarizeOnvifProbe(onvifProbe) {
  if (!onvifProbe) return 'No ONVIF result'
  const parts = []
  const wsDiscovery = onvifProbe?.ws_discovery || {}
  const httpService = onvifProbe?.http_service || {}
  if (wsDiscovery?.ok) {
    parts.push(`WS-Discovery ${wsDiscovery.status || 'reply'}${wsDiscovery.matched_tokens?.length ? ` (${wsDiscovery.matched_tokens.join(', ')})` : ''}`)
  }
  if (httpService?.ok) {
    parts.push(`Device Service ${httpService.status || '--'} ${httpService.reason || ''}`.trim())
  }
  if (onvifProbe?.matched_families?.length) {
    parts.push(`families ${formatProbeFamilies(onvifProbe.matched_families)}`)
  }
  return parts.filter(Boolean).join(' · ') || onvifProbe?.error || 'No ONVIF response'
}

function summarizeRtspProbe(rtspProbe) {
  if (!rtspProbe?.ok) return rtspProbe?.error || 'No RTSP response'
  const parts = [
    rtspProbe?.status_line || 'RTSP response',
    rtspProbe?.server ? `server ${rtspProbe.server}` : '',
    rtspProbe?.public ? `public ${rtspProbe.public}` : '',
    rtspProbe?.matched_families?.length ? `families ${formatProbeFamilies(rtspProbe.matched_families)}` : '',
  ]
  return parts.filter(Boolean).join(' · ')
}

function summarizeSnapshotProbe(snapshotProbe) {
  const findings = snapshotProbe?.findings || []
  if (!findings.length) return snapshotProbe?.error || 'No snapshot response'
  const best = findings.find((item) => item?.image_hint) || findings[0]
  const parts = [
    `${String(best?.scheme || 'http').toUpperCase()} ${best?.port || '--'}${best?.path || '/'}`,
    best?.status ? `${best.status} ${best.reason || ''}`.trim() : '',
    best?.content_type ? `type ${best.content_type}` : '',
    best?.content_length ? `${best.content_length} bytes` : '',
    best?.matched_families?.length ? `families ${formatProbeFamilies(best.matched_families)}` : '',
  ]
  return parts.filter(Boolean).join(' · ')
}

function getMissionReasons(network, mode) {
  const reasons = []
  if (mode === 'RED') {
    if (network.camera_detection?.detected) reasons.push('camera coverage lead')
    if (Number(network.client_count || 0) >= 3) reasons.push('multi-client infrastructure')
    if (Number(network.rssi_dbm || -95) >= -60) reasons.push('close proximity')
    if (String(network.security || '').toUpperCase().includes('OPEN')) reasons.push('open exposure')
  } else {
    if (network.camera_detection?.detected) reasons.push('surveillance review')
    if (!String(network.pmf || '').toLowerCase().includes('true')) reasons.push('PMF gap')
    if (Number(network.client_count || 0) >= 3) reasons.push('user-impact concentration')
    if (network.hidden_ssid) reasons.push('hidden asset validation')
  }
  return reasons.slice(0, 3)
}

function buildMissionRankings(networks, mode) {
  return [...networks]
    .sort((left, right) => {
      const clientDelta = Number(right.client_count || 0) - Number(left.client_count || 0)
      if (clientDelta) return clientDelta
      return getOperationalTargetScore(right, mode) - getOperationalTargetScore(left, mode)
    })
    .slice(0, 6)
}

function buildLockChannelOptions(channels) {
  const options = []
  for (const channel of channels?.plan_24 || []) options.push(channel)
  for (const channel of channels?.plan_5 || []) options.push(channel)
  return options
}

function normalizeEssLabel(network) {
  const ssid = String(network?.ssid || '').trim()
  if (!ssid || ssid === '<hidden>') return ''
  return ssid
    .replace(/[_-](plus|5g|2g)$/i, '')
    .replace(/[_-](?:[0-9a-f]{4}|[0-9a-f]{3,6})$/i, '')
    .trim()
    .toUpperCase()
}

function buildFamilySummary(networks) {
  const families = new Map()
  for (const network of networks || []) {
    const key = normalizeEssLabel(network) || String(network?.ssid || '<hidden>').toUpperCase()
    if (!families.has(key)) {
      families.set(key, {
        key,
        label: key,
        networkCount: 0,
        clientCount: 0,
        strongestRssi: null,
        bands: new Set(),
        security: new Set(),
        vendors: new Set(),
      })
    }
    const family = families.get(key)
    family.networkCount += 1
    family.clientCount += Number(network?.client_count || 0)
    family.bands.add(network?.band || '--')
    family.security.add(network?.security || '--')
    if (network?.vendor) family.vendors.add(network.vendor)
    const rssi = Number(network?.rssi_dbm ?? -999)
    if (family.strongestRssi === null || rssi > family.strongestRssi) {
      family.strongestRssi = rssi
    }
  }
  return [...families.values()]
    .map((family) => ({
      ...family,
      bands: [...family.bands],
      security: [...family.security],
      vendors: [...family.vendors],
    }))
    .sort((left, right) => {
      const clientDelta = Number(right.clientCount || 0) - Number(left.clientCount || 0)
      if (clientDelta) return clientDelta
      return Number(right.strongestRssi || -999) - Number(left.strongestRssi || -999)
    })
}

function getDeviceFamilyLabel(network) {
  const family = String(network?.fingerprint?.device_family || '').toLowerCase()
  if (family === 'isp-cpe') return 'ISP Router / CPE'
  if (family === 'extender') return 'Mesh / Extender'
  if (family === 'onboarding') return 'IoT Onboarding'
  if (family === 'vacuum') return 'Robot Vacuum'
  if (family === 'tv-media') return 'TV / Media'
  if (family === 'camera') return 'Camera'
  return network?.fingerprint?.device_type || '--'
}

function getPredictedNetworkLabel(network) {
  const family = String(network?.fingerprint?.device_family || '').toLowerCase()
  const baseType = network?.fingerprint?.device_type || 'WiFi Network'
  const cameraConfidence = Number(network?.camera_detection?.confidence || 0)

  if (cameraConfidence >= 0.7 || family === 'camera') return 'Likely Camera Network'
  if (family === 'isp-cpe') return 'Likely Residential Router / CPE'
  if (family === 'extender') return 'Likely Mesh / Extender Network'
  if (family === 'onboarding') return 'Likely IoT Onboarding Network'
  if (family === 'vacuum') return 'Likely Robot Appliance Network'
  if (family === 'tv-media') return 'Likely Media Device Network'
  return `Likely ${baseType}`
}

function getNetworkConfidenceLabel(network) {
  return network?.fingerprint?.confidence_tier || network?.target_score?.confidence_tier || 'LOW'
}

function getConfidenceTone(value) {
  const label = String(value || '').toUpperCase()
  if (label === 'HIGH') return 'green'
  if (label === 'MED' || label === 'MEDIUM') return 'cyan'
  return 'neutral'
}

function getRoleBadge(label) {
  const value = String(label || '').toLowerCase()
  if (value.includes('camera')) return { text: 'Camera', tone: 'danger' }
  if (value.includes('router') || value.includes('cpe')) return { text: 'Router', tone: 'cyan' }
  if (value.includes('mesh') || value.includes('extender')) return { text: 'Mesh', tone: 'cyan' }
  if (value.includes('media') || value.includes('tv')) return { text: 'Media', tone: 'green' }
  if (value.includes('iot')) return { text: 'IoT', tone: 'warning' }
  if (value.includes('vacuum')) return { text: 'Appliance', tone: 'warning' }
  return { text: 'Device', tone: 'neutral' }
}

function getClientAttribution(client, network) {
  if (!client || !network) return null
  const sameBssid = String(client.associated_bssid || '').toLowerCase() === String(network.bssid || '').toLowerCase()
  const sameChannel = Number(client.channel || 0) > 0 && Number(client.channel) === Number(network.channel || -1)
  const sameBand = client.band && network.band && client.band === network.band
  const associationCount = Number(client.association_count || 0)
  const packetCount = Number(client.packet_count || 0)
  const probeCount = Number(client.probe_request_count || 0)

  if (sameBssid && associationCount > 0) {
    return {
      level: 'Confirmed',
      rank: 3,
      reason: 'association frame seen',
    }
  }

  if (sameBssid && packetCount >= 2) {
    return {
      level: 'Strong',
      rank: 2,
      reason: 'repeated frames to BSSID',
    }
  }

  if ((sameChannel || sameBand) && probeCount > 0) {
    return {
      level: 'Probable',
      rank: 1,
      reason: 'same channel + repeated timing correlation',
    }
  }

  return null
}

function getRelatedClientsForNetwork(network, clients, filter) {
  const acceptedRank = filter === 'confirmed'
    ? 3
    : filter === 'strong'
      ? 2
      : 1

  return (clients || [])
    .map((client) => {
      const attribution = getClientAttribution(client, network)
      if (!attribution) return null
      if (attribution.rank < acceptedRank) return null
      return { ...client, attribution }
    })
    .filter(Boolean)
    .sort((left, right) => {
      const rankDelta = Number(right.attribution?.rank || 0) - Number(left.attribution?.rank || 0)
      if (rankDelta) return rankDelta
      return Number(right.packet_count || 0) - Number(left.packet_count || 0)
    })
}

function sortNetworks(items, mode) {
  return [...items].sort((left, right) => {
    const clientDelta = Number(right?.client_count || 0) - Number(left?.client_count || 0)
    if (clientDelta) return clientDelta
    const delta = getOperationalTargetScore(right, mode) - getOperationalTargetScore(left, mode)
    if (delta) return delta
    const targetDelta = Number(right?.target_score?.confidence || 0) - Number(left?.target_score?.confidence || 0)
    if (targetDelta) return targetDelta
    return Number(right?.packet_count || 0) - Number(left?.packet_count || 0)
  })
}

function buildTaskPresets(network) {
  const ssid = network?.ssid || '<hidden>'
  return [
    { key: 'iot', label: 'Pivot IoT', detail: `Cross-check ${ssid} for cameras, hubs, and embedded WiFi assets.`, targetTab: 'IOT' },
    { key: 'wifi', label: 'Open WiFi SDR', detail: `Move into SDR-backed WiFi workflow while preserving packet truth.`, targetTab: 'WIFI' },
    { key: 'focus', label: 'Focus Clients', detail: `Filter the client table to stations associated with ${ssid}.`, targetTab: '' },
    { key: 'export', label: 'Export Evidence', detail: `Export retained packet-truth details and PCAP references for ${ssid}.`, targetTab: '' },
  ]
}

function getPredictedClientLabel(client) {
  const baseType = client?.fingerprint?.device_type || client?.device_type || 'Unknown Device'
  const family = String(client?.fingerprint?.device_family || '').toLowerCase()
  const cameraConfidence = Number(client?.camera_detection?.confidence || 0)

  if (cameraConfidence >= 0.7 || family === 'camera') return 'Likely WiFi Camera'
  if (family === 'tv-media') return 'Likely Smart TV / Media Device'
  if (family === 'vacuum') return 'Likely Robot Vacuum'
  if (family === 'onboarding') return 'Likely IoT Onboarding Device'
  if (family === 'extender') return 'Likely Extender / Mesh Node'
  if (family === 'isp-cpe') return 'Likely Router / CPE'
  return `Likely ${baseType}`
}

function getClientSummary(client) {
  const predicted = getPredictedClientLabel(client)
  const confidence = client?.fingerprint?.confidence_tier || client?.target_score?.confidence_tier || 'LOW'
  const mobility = client?.mobility_class || 'unknown mobility'
  const associated = client?.associated_bssid ? `linked to ${client.associated_bssid}` : 'not yet linked to a retained AP'
  const exposure = client?.service_exposure?.exposures?.[0] || client?.service_exposure?.summary || ''
  const anomaly = client?.anomaly_profile?.findings?.[0] || ''

  return `${predicted} · ${confidence} confidence · ${associated} · ${mobility}${exposure ? ` · ${exposure}` : ''} · target score ${client?.target_score?.score ?? getPacketTruthScore(client)}`
}

function getRedClientValue(client) {
  const predicted = String(getPredictedClientLabel(client) || '').toLowerCase()
  const mobility = String(client?.mobility_class || '').toLowerCase()
  const exposure = String(client?.service_exposure?.summary || '').toLowerCase()
  const score = Number(client?.target_score?.score || 0)

  if (predicted.includes('camera')) {
    return { label: 'Surveillance', tone: 'danger', reason: 'static camera-like endpoint with elevated recon value' }
  }
  if (predicted.includes('router') || predicted.includes('extender')) {
    return { label: 'Infrastructure', tone: 'cyan', reason: 'infrastructure-adjacent endpoint or mesh-related node' }
  }
  if (predicted.includes('iot') || predicted.includes('vacuum')) {
    return { label: 'Embedded IoT', tone: 'warning', reason: 'embedded or appliance-class device with environmental value' }
  }
  if (predicted.includes('tv') || predicted.includes('media')) {
    return { label: 'Media', tone: 'green', reason: 'static media endpoint useful for household/site profiling' }
  }
  if (mobility.includes('high') || predicted.includes('phone')) {
    return { label: 'Mobile', tone: 'neutral', reason: 'roaming/mobile endpoint with lower persistence value' }
  }
  if (score < 45 && !exposure) {
    return { label: 'Low Value', tone: 'neutral', reason: 'limited passive evidence and low current targeting value' }
  }
  return { label: 'Follow-Up', tone: 'cyan', reason: 'retain for correlation and continued passive observation' }
}

function getRedPriorityReasons(client) {
  const reasons = []
  const predicted = String(getPredictedClientLabel(client) || '').toLowerCase()
  const exposure = String(client?.service_exposure?.summary || '')
  const anomaly = String(client?.anomaly_profile?.summary || '')
  if (predicted.includes('camera')) reasons.push('surveillance candidate')
  if (predicted.includes('iot') || predicted.includes('vacuum')) reasons.push('embedded device')
  if (String(client?.mobility_class || '') === 'static') reasons.push('static presence')
  if (Number(client?.rssi_dbm || -999) >= -60) reasons.push('close proximity')
  if (exposure && exposure !== 'No service exposure observed') reasons.push(exposure)
  if (anomaly && anomaly !== 'No strong anomaly detected') reasons.push(anomaly)
  return reasons.slice(0, 3)
}

function isStrongCameraCandidate(item) {
  const uiLabel = String(item?.camera_detection?.ui_label || '')
  const classification = String(item?.camera_detection?.classification || '').toLowerCase()
  const score = Number(item?.camera_detection?.score || 0)
  const confidence = Number(item?.camera_detection?.confidence || 0)
  const protocols = (item?.service_exposure?.protocols || []).map((value) => String(value).toUpperCase())
  const summary = String(item?.service_exposure?.summary || '').toLowerCase()
  const family = String(item?.fingerprint?.device_family || '').toLowerCase()
  const inferredKind = item?.mac ? 'client' : 'network'
  const kind = String(item?.leadKind || item?.kind || inferredKind).toLowerCase()
  const trafficPattern = String(item?.traffic_pattern || '')
  const associatedBssid = String(item?.associated_bssid || '')
  const uplinkRatio = Number(item?.flow_metrics?.uplink_ratio || 0)
  const packetCount = Number(item?.packet_count || 0)
  const hasRealAssociation = Boolean(associatedBssid && associatedBssid !== 'ff:ff:ff:ff:ff:ff')
  const hasProtocolEvidence = protocols.some((value) => ['RTSP', 'ONVIF', 'MDNS', 'TLS', 'HTTP'].includes(value)) || summary.includes('cloud endpoints identified') || summary.includes('rtsp') || summary.includes('onvif')
  const hasCameraIdentity = family === 'camera' || Boolean(item?.wps_primary_device_camera)
  const isInfrastructure = kind === 'network' && ['isp-cpe', 'router', 'extender'].includes(family)
  const behaviorCameraCandidate = kind === 'client'
    && family === 'camera'
    && trafficPattern === 'steady-stream'
    && hasRealAssociation
    && packetCount >= 10
    && uplinkRatio >= 0.8

  if (uiLabel === 'confirmed_camera_local' || uiLabel === 'likely_camera_cloud') return true
  if (uiLabel === 'camera_capable_network') return !isInfrastructure && (hasProtocolEvidence || hasCameraIdentity)
  if (uiLabel === 'possible_stream_device') {
    if (kind === 'client' && (score >= 45 || confidence >= 0.45 || hasProtocolEvidence || hasCameraIdentity)) return true
    if (kind === 'network' && !isInfrastructure && (hasProtocolEvidence || hasCameraIdentity) && (score >= 45 || confidence >= 0.45)) return true
    return false
  }
  if (behaviorCameraCandidate) return true
  if (classification.includes('confirmed') || classification.includes('likely')) return !isInfrastructure || hasProtocolEvidence || hasCameraIdentity
  if (!isInfrastructure && (score >= 55 || confidence >= 0.55) && (hasProtocolEvidence || hasCameraIdentity)) return true
  if (family === 'camera' && (protocols.includes('RTSP') || summary.includes('onvif') || summary.includes('camera service'))) return true
  return false
}

function getCameraConfidenceBasis(item) {
  if (Array.isArray(item?.pipeline_confidence_basis) && item.pipeline_confidence_basis.length) {
    return item.pipeline_confidence_basis.join(' + ')
  }
  const protocols = (item?.service_exposure?.protocols || []).map((value) => String(value).toUpperCase())
  const indicators = (item?.camera_detection?.indicators || []).map((value) => String(value).toLowerCase())
  const matchedFamilies = item?.camera_detection?.matched_families || []
  if (protocols.includes('RTSP') || protocols.includes('ONVIF')) return 'Protocol'
  if (protocols.includes('TLS') || String(item?.service_exposure?.summary || '').toLowerCase().includes('cloud endpoints')) return 'Cloud TLS'
  if (item?.wps_primary_device_camera || indicators.some((value) => value.includes('wps primary device camera type'))) return 'WPS Identity'
  if (matchedFamilies.length && indicators.some((value) => value.includes('camera naming') || value.includes('camera-oriented identity'))) return 'Vendor+Identity'
  if (matchedFamilies.length && indicators.some((value) => value.includes('known camera vendor'))) return 'Vendor+Behavior'
  if (String(item?.fingerprint?.device_family || '').toLowerCase() === 'camera') return 'Behavior'
  return 'Passive'
}

function buildEnvironmentMap(networks, channels) {
  const total = networks.length || 1
  const open = networks.filter((item) => String(item.security || '').toLowerCase().includes('open')).length
  const hidden = networks.filter((item) => item.hidden_ssid).length
  const wpa3 = networks.filter((item) => String(item.security || '').toLowerCase().includes('wpa3')).length
  const wpa2 = networks.filter((item) => String(item.security || '').toLowerCase().includes('wpa2')).length
  const channelStats = channels?.channel_statistics || {}
  const hotspots = Object.entries(channelStats)
    .map(([channel, stats]) => ({ channel, frames: Number(stats?.frames || 0), visits: Number(stats?.visits || 0) }))
    .filter((item) => item.frames > 0)
    .sort((left, right) => right.frames - left.frames)
    .slice(0, 5)
  return {
    total: networks.length,
    density: networks.length >= 30 ? 'High density' : networks.length >= 12 ? 'Moderate density' : 'Low density',
    openPct: Math.round((open / total) * 100),
    hiddenPct: Math.round((hidden / total) * 100),
    wpa2Pct: Math.round((wpa2 / total) * 100),
    wpa3Pct: Math.round((wpa3 / total) * 100),
    hotspots,
  }
}

function buildVendorRiskSummary(networks, clients) {
  const combined = [...networks, ...clients]
  const buckets = new Map()
  for (const item of combined) {
    const vendor = String(item.vendor || 'Unknown')
    const country = String(item.vendor_country || item.vendor_country_code || '--')
    const key = `${vendor}::${country}`
    const risk = vendor === 'Unknown' || vendor === '--' ? 'Unknown Vendor' : ['china', 'hong kong'].includes(country.toLowerCase()) ? 'Supply-Chain Review' : 'Observed Vendor'
    if (!buckets.has(key)) {
      buckets.set(key, { vendor, country, count: 0, risk, highValue: 0 })
    }
    const bucket = buckets.get(key)
    bucket.count += 1
    if (Number(item?.target_score?.score || 0) >= 70) bucket.highValue += 1
  }
  return [...buckets.values()]
    .sort((left, right) => {
      const riskDelta = right.highValue - left.highValue
      if (riskDelta) return riskDelta
      return right.count - left.count
    })
    .slice(0, 5)
}

function buildAnomalyLeads(networks, clients) {
  return [...networks, ...clients]
    .filter((item) => item?.anomaly_profile?.has_anomaly)
    .sort((left, right) => Number(right?.risk_profile?.risk_score || 0) - Number(left?.risk_profile?.risk_score || 0))
    .slice(0, 5)
    .map((item) => ({
      label: item.ssid || item.mac || item.bssid || '<unknown>',
      summary: item.anomaly_profile?.summary || 'Anomaly detected',
      score: item.risk_profile?.risk_score || item.target_score?.score || 0,
    }))
}

function buildClientClusters(clients) {
  const buckets = new Map()
  for (const client of clients || []) {
    const mac = String(client.mac || '').toLowerCase()
    const vendor = String(client.vendor || 'Unknown')
    const channel = String(client.channel || '--')
    const oui = mac.split(':').slice(0, 3).join(':')
    const key = `${vendor}::${oui}::${channel}`
    if (!buckets.has(key)) {
      buckets.set(key, {
        key,
        vendor,
        oui,
        channel,
        count: 0,
        predicted: getPredictedClientLabel(client),
        strongestRssi: null,
      })
    }
    const bucket = buckets.get(key)
    bucket.count += 1
    const rssi = Number(client.rssi_dbm ?? -999)
    if (bucket.strongestRssi === null || rssi > bucket.strongestRssi) bucket.strongestRssi = rssi
  }
  return [...buckets.values()]
    .filter((item) => item.count >= 2)
    .sort((left, right) => right.count - left.count || Number(right.strongestRssi || -999) - Number(left.strongestRssi || -999))
    .slice(0, 5)
}

function getProximityLabel(value) {
  const rssi = Number(value ?? -999)
  if (rssi >= -55) return 'Close'
  if (rssi >= -70) return 'Medium'
  return 'Weak'
}

function getRedNextAction(network) {
  const exposure = String(network?.service_exposure?.summary || '').toLowerCase()
  const predicted = String(getPredictedNetworkLabel(network) || '').toLowerCase()
  if (predicted.includes('camera')) return 'Deep observe and map surveillance coverage'
  if (String(network?.security || '').toLowerCase().includes('open')) return 'Prioritize exposed infrastructure and watch clients'
  if (exposure.includes('rtsp') || exposure.includes('onvif') || exposure.includes('http')) return 'Pivot to service follow-up and retain evidence'
  if (predicted.includes('onboarding') || predicted.includes('iot')) return 'Pivot to IoT workflow and monitor device churn'
  if (Number(network?.client_count || 0) >= 3) return 'Watch client churn and cluster related endpoints'
  return 'Retain target and continue passive observation'
}

function buildAttackableTargets(networks) {
  return [...networks]
    .sort((left, right) => {
      const scoreDelta = Number(right?.target_score?.score || 0) - Number(left?.target_score?.score || 0)
      if (scoreDelta) return scoreDelta
      return Number(right?.rssi_dbm || -999) - Number(left?.rssi_dbm || -999)
    })
    .slice(0, 5)
    .map((network) => ({
      id: getNetworkId(network),
      network,
      label: network.ssid || '<hidden>',
      score: network?.target_score?.score ?? 0,
      type: getPredictedNetworkLabel(network),
      proximity: getProximityLabel(network?.rssi_dbm),
      nextAction: getRedNextAction(network),
      why: (network?.target_score?.reasons || []).slice(0, 3).join(' · ') || network?.risk_profile?.summary || 'high-value WiFi lead',
    }))
}

function getCameraLeadLabel(item) {
  if (item?.cloud_camera_evidence?.bucket === 'possible_cloud_camera') return 'Possible Cloud Camera'
  const label = String(item?.camera_detection?.ui_label || '')
  const family = String(item?.fingerprint?.device_family || '').toLowerCase()
  const trafficPattern = String(item?.traffic_pattern || '')
  const associatedBssid = String(item?.associated_bssid || '')
  const uplinkRatio = Number(item?.flow_metrics?.uplink_ratio || 0)
  const packetCount = Number(item?.packet_count || 0)
  const behaviorCameraCandidate = item?.leadKind === 'client'
    && family === 'camera'
    && trafficPattern === 'steady-stream'
    && associatedBssid
    && packetCount >= 10
    && uplinkRatio >= 0.8
  if (label === 'confirmed_camera_local') return 'Confirmed Local Camera'
  if (label === 'likely_camera_cloud') return 'Likely Cloud Camera'
  if (label === 'possible_stream_device') return 'Possible Stream Device'
  if (label === 'camera_capable_network') return 'Camera-Capable Network'
  if (behaviorCameraCandidate) return 'Behavior Camera Candidate'
  if (label === 'non_camera_static_device') return 'Non-Camera Static Device'
  if (item?.leadKind === 'client') return getPredictedClientLabel(item)
  return getPredictedNetworkLabel(item)
}

function getCameraLeadIdentity(item) {
  if (item?.leadKind === 'client') return item?.mac || '<unknown client>'
  return item?.ssid || '<hidden>'
}

function getCameraLeadSupportingId(item) {
  if (item?.leadKind === 'client') return item?.associated_bssid || '--'
  return item?.bssid || 'unresolved BSSID'
}

function getCameraLeadAssociatedSsid(item) {
  if (item?.leadKind !== 'client') return item?.ssid || '--'
  return String(item?.associated_ssid || item?.associated_network?.ssid || '').trim() || '--'
}

function getCameraLeadEvidence(item) {
  const confirmation = item?.camera_confirmation || {}
  if (Array.isArray(confirmation?.service_reasons) && confirmation.service_reasons.length) {
    return confirmation.service_reasons.slice(0, 2).join(' · ')
  }
  const camera = item?.camera_detection || {}
  const indicators = Array.isArray(camera?.indicators) ? camera.indicators.slice(0, 3) : []
  if (indicators.length) return indicators.join(' · ')
  return item?.service_exposure?.summary || item?.behavior_analysis?.summary || 'limited passive camera evidence'
}

function shouldDisplayCameraLead(item) {
  if (!item) return false
  const family = String(item?.fingerprint?.device_family || '').toLowerCase()
  const classification = String(item?.camera_detection?.classification || '').toLowerCase()
  const uiLabel = String(item?.camera_detection?.ui_label || '').toLowerCase()
  const vendorState = String(item?.camera_detection?.vendor_role_state || '').toLowerCase()
  const familyMatch = String(item?.camera_detection?.family_match || item?.camera_detection?.vendor_family || '').toLowerCase()
  const confirmationLevel = String(item?.camera_confirmation?.level || 'unconfirmed').toLowerCase()
  const protocols = new Set((item?.service_exposure?.protocols || []).map((value) => String(value || '').toUpperCase()))
  const probeSummary = item?.active_fingerprint?.summary || {}
  const score = Number(item?.camera_detection?.score || item?.target_score?.score || 0)
  const confidence = Number(item?.camera_detection?.confidence || 0)
  const infraFamily = ['isp-cpe', 'router', 'extender'].includes(family)
  const confirmed = ['artifact_confirmed', 'confirmed', 'likely'].includes(confirmationLevel)
  const protocolPositive = protocols.has('RTSP')
    || protocols.has('ONVIF')
    || protocols.has('TLS')
    || protocols.has('HTTP')
    || Number(probeSummary?.rtsp_hits || 0) > 0
    || Number(probeSummary?.onvif_hits || 0) > 0
    || Number(probeSummary?.snapshot_hits || 0) > 0
  const cameraIdentity = family === 'camera'
    || classification.includes('camera')
    || uiLabel.includes('camera')
    || familyMatch.includes('camera')
    || vendorState.includes('cloud_camera')
    || vendorState.includes('historical_camera_identity')
    || Boolean(item?.wps_primary_device_camera)

  if (classification.includes('non_camera')) return false
  if (infraFamily && !confirmed && !protocolPositive) return false
  if (!cameraIdentity && !protocolPositive && score < 55 && confidence < 0.55) return false
  return true
}

function shouldDisplayCameraNearMiss(item) {
  if (!item) return false
  const family = String(item?.fingerprint?.device_family || '').toLowerCase()
  const classification = String(item?.camera_detection?.classification || '').toLowerCase()
  const vendorState = String(item?.camera_detection?.vendor_role_state || '').toLowerCase()
  const familyMatch = String(item?.camera_detection?.family_match || item?.camera_detection?.vendor_family || '').toLowerCase()
  const protocols = new Set((item?.service_exposure?.protocols || []).map((value) => String(value || '').toUpperCase()))
  const score = Number(item?.camera_detection?.score || item?.pipeline_score || item?.target_score?.score || 0)
  const confidence = Number(item?.camera_detection?.confidence || 0)
  const associated = Boolean(item?.associated_bssid)
  const clientLike = String(item?.leadKind || (item?.mac ? 'client' : 'network')).toLowerCase() === 'client'
  const infraFamily = ['isp-cpe', 'router', 'extender'].includes(family)
  const cameraSignals = family === 'camera'
    || classification.includes('camera')
    || familyMatch.includes('camera')
    || vendorState.includes('cloud_camera')
    || vendorState.includes('historical_camera_identity')
    || Boolean(item?.wps_primary_device_camera)
    || protocols.has('RTSP')
    || protocols.has('ONVIF')
    || protocols.has('TLS')
    || protocols.has('HTTP')

  if (classification.includes('non_camera')) return false
  if (infraFamily) return false
  if (cameraSignals && (score >= 35 || confidence >= 0.35)) return true
  if (clientLike && vendorState.includes('cloud_camera') && familyMatch && associated && (score >= 28 || confidence >= 0.25)) return true
  if (clientLike && associated && (score >= 45 || confidence >= 0.4)) return true
  return false
}

function getCompactCameraPathSummary(item) {
  const transport = String(item?.camera_confirmation?.transport_path || item?.stream_state?.transport || 'unknown')
  const protocols = (item?.camera_confirmation?.local_protocols || item?.service_exposure?.protocols || []).slice(0, 2).join(', ')
  const state = formatStreamStateLabel(item?.stream_state?.state || 'unknown')
  return [transport, protocols || 'no local protocol', state].filter(Boolean).join(' · ')
}

function getCompactCameraAuditSummary(item) {
  const probe = getProbeStatus(item)
  const hard = getHardAuditStatus(item)
  return `${probe.label} · ${hard.detail}`
}

function formatCameraConfirmationLevel(value) {
  const raw = String(value || 'unconfirmed')
  if (raw === 'artifact_confirmed') return 'Artifact Confirmed'
  if (raw === 'confirmed') return 'Confirmed'
  if (raw === 'likely') return 'Likely'
  if (raw === 'possible') return 'Possible'
  return 'Unconfirmed'
}

function getCameraLeadSecondarySummary(item) {
  const confidenceBasis = getCameraConfidenceBasis(item)
  const confidence = Number(item?.camera_detection?.confidence || 0)
  const familyMatch = String(item?.camera_detection?.family_match || '')
  const familyConfidence = String(item?.camera_detection?.family_match_confidence || '')
  const protocols = (item?.service_exposure?.protocols || []).slice(0, 2).join(', ')
  const mode = String(item?.camera_detection?.detection_mode || '').replaceAll('_', ' ')
  const confirmation = item?.camera_confirmation || {}
  const parts = [
    `basis ${confidenceBasis}`,
    `${Math.round(confidence * 100)}% camera confidence`,
  ]
  if (familyMatch) parts.push(`family ${familyMatch}${familyConfidence ? ` ${familyConfidence}` : ''}`)
  if (mode) parts.push(mode)
  if (protocols) parts.push(protocols)
  if (confirmation?.level && confirmation.level !== 'unconfirmed') parts.push(formatCameraConfirmationLevel(confirmation.level))
  return parts.join(' · ')
}

function getCameraAuditTooltip(item) {
  const audit = item?.camera_detection?.audit || {}
  const suppression = item?.camera_detection?.suppression_reasons || item?.pipeline_suppression_reasons || []
  const confirmation = item?.camera_confirmation || {}
  const details = [
    `classification ${item?.camera_detection?.classification || 'unknown'}`,
    `score ${item?.camera_detection?.score ?? '--'}`,
    `confidence ${Math.round(Number(item?.camera_detection?.confidence || 0) * 100)}%`,
    `basis ${(item?.pipeline_confidence_basis || []).join(' / ') || 'Passive'}`,
  ]
  if (confirmation?.level) details.push(`confirmation ${formatCameraConfirmationLevel(confirmation.level)}`)
  if (confirmation?.transport_path) details.push(`path ${confirmation.transport_path}`)
  if ((audit.vendor_hits || []).length) details.push(`vendor ${(audit.vendor_hits || []).join(', ')}`)
  if ((audit.identity_hits || []).length) details.push(`identity ${(audit.identity_hits || []).join(', ')}`)
  if ((audit.tls_hits || []).length) details.push(`tls ${(audit.tls_hits || []).join(', ')}`)
  if ((audit.discovery_hits || []).length) details.push(`discovery ${(audit.discovery_hits || []).join(', ')}`)
  if (item?.camera_detection?.vendor_explainer) details.push(item.camera_detection.vendor_explainer)
  if (suppression.length) details.push(`suppression ${suppression.join(' / ')}`)
  return details.join(' · ')
}

function getAssessmentSections(item) {
  const sections = item?.device_assessment?.sections || {}
  return Object.entries(sections)
}

function formatAssessmentValue(answer) {
  const value = String(answer?.value || 'UNKNOWN')
  return value || 'UNKNOWN'
}

function formatStreamStateLabel(value) {
  return String(value || 'unknown').replaceAll('_', ' ')
}

function getProbeStatus(item) {
  const summary = item?.active_fingerprint?.summary || {}
  const candidateIps = item?.active_fingerprint?.candidate_ips || []
  const reason = String(item?.active_fingerprint?.candidate_ip_reason || '').trim()
  const visualProofCount = Number(summary?.visual_artifact_count || 0)
  const totalHits = Number(summary?.http_hits || 0)
    + Number(summary?.onvif_hits || 0)
    + Number(summary?.rtsp_hits || 0)
    + Number(summary?.snapshot_hits || 0)
  if (!item?.active_fingerprint) return { label: 'Not Probed', tone: 'neutral', detail: 'no active fingerprint retained' }
  if (summary?.video_or_image_proof) return { label: 'Visual Proof', tone: 'danger', detail: `${visualProofCount} image/frame artifact${visualProofCount === 1 ? '' : 's'} · ${(candidateIps || []).slice(0, 2).join(', ') || 'candidate IPs retained'}` }
  if (summary?.camera_positive) return { label: 'Service Positive', tone: 'warning', detail: `${totalHits} service checks · no visual artifact` }
  if ((candidateIps || []).length) return { label: 'Probed', tone: 'cyan', detail: `${(candidateIps || []).length} candidate IPs · 0 positives` }
  return { label: 'Probe Failed', tone: 'warning', detail: reason || 'probe returned no candidate path' }
}

function getHardAuditStatus(item) {
  const audit = item?.hard_audit || {}
  if (!audit || !Object.keys(audit).length) return { label: 'Not Audited', tone: 'neutral', detail: 'hard audit not run' }
  const verdict = audit?.validation_report?.verdict || {}
  const classification = String(verdict?.classification || audit?.status || 'partial').replaceAll('_', ' ')
  const evidenceQuality = String(verdict?.evidence_quality || 'partial').replaceAll('_', ' ')
  return {
    label: 'Hard Audited',
    tone: audit?.status === 'completed' ? 'danger' : 'warning',
    detail: `${classification} · ${evidenceQuality}`,
  }
}

function getCameraValidationReport(item) {
  return item?.hard_audit?.validation_report || item?.validation_report || {}
}

function getCameraVideoEvidence(item) {
  return item?.video_evidence || {}
}

function getCameraCloudLeakageAudit(item) {
  const direct = getCameraVideoEvidence(item)?.cloud_leakage_audit || {}
  if (Object.keys(direct || {}).length) return direct
  const behavior = (getCameraValidationReport(item)?.evidence?.behavior || [])
  return behavior.find((entry) => entry?.evidence_type === 'cloud_leakage_audit') || {}
}

function formatCameraCloudLeakage(item) {
  const audit = getCameraCloudLeakageAudit(item)
  if (!Object.keys(audit || {}).length) return 'not assessed'
  const risk = String(audit?.risk_level || 'UNKNOWN').toUpperCase()
  const verdict = String(audit?.leakage_verdict || 'cloud behavior inconclusive').replaceAll('_', ' ')
  const endpoints = (audit?.cloud_endpoints || audit?.new_live_view_endpoints || []).length
  if (String(audit?.status || '').toLowerCase() === 'not_observed' || risk === 'NONE') return 'NONE · no cloud leakage observed'
  return `${risk} · ${verdict} · ${endpoints} endpoint${endpoints === 1 ? '' : 's'}`
}

function formatCloudCameraEvidence(item) {
  const evidence = item?.cloud_camera_evidence || {}
  if (!Object.keys(evidence || {}).length) return 'not assessed'
  const bucket = String(evidence.bucket || 'unknown').replaceAll('_', ' ')
  const proof = String(evidence.proof_status || 'unknown').replaceAll('_', ' ')
  const blockers = (evidence.proof_blockers || []).slice(0, 2).join(' · ')
  return blockers ? `${bucket} · ${proof} · ${blockers}` : `${bucket} · ${proof}`
}

function getCameraVisualAcquisition(item) {
  return item?.hard_audit?.visual_acquisition || {}
}

function getCameraEvidencePolicy(item) {
  return item?.hard_audit?.evidence_policy || getCameraVisualAcquisition(item)?.evidence_policy || {}
}

function formatCameraOutcomeClass(value) {
  return String(value || 'network_proof_only').replaceAll('_', ' ')
}

function getVideoEvidenceLabel(value, fallback = 'unknown') {
  return String(value || fallback).replaceAll('_', ' ')
}

function getVideoEvidenceEndpoints(item, limit = 4) {
  const profile = getCameraVideoEvidence(item).traffic_profile || {}
  return (profile.endpoints || profile.new_endpoints || [])
    .map((value) => String(value || '').trim())
    .filter(Boolean)
    .slice(0, limit)
}

function getVideoEvidenceSummary(item) {
  const videoEvidence = getCameraVideoEvidence(item)
  const traffic = videoEvidence.traffic_profile || {}
  const correlation = videoEvidence.correlation || {}
  return [
    getVideoEvidenceLabel(videoEvidence.video_capable || 'inconclusive'),
    getVideoEvidenceLabel(videoEvidence.evidence_type || 'partial'),
    traffic.bandwidth_classification || 'no bandwidth class',
    correlation.summary || 'no live-view correlation',
  ].join(' · ')
}

function getCameraEvidenceQuality(item) {
  const verdict = getCameraValidationReport(item)?.verdict || {}
  const quality = String(verdict?.evidence_quality || '').trim()
  if (quality) return quality.replaceAll('_', ' ')
  const summary = item?.active_fingerprint?.summary || {}
  if (summary?.camera_positive) return 'direct confirmed'
  if ((item?.active_fingerprint?.candidate_ips || []).length) return 'partial'
  return 'inconclusive'
}

function getCameraVerdictSummary(item) {
  const verdict = getCameraValidationReport(item)?.verdict || {}
  const videoEvidence = getCameraVideoEvidence(item)
  const visualAcquisition = getCameraVisualAcquisition(item)
  if (String(visualAcquisition?.outcome_class || '').trim()) {
    return `${formatCameraOutcomeClass(visualAcquisition.outcome_class)} · ${String(visualAcquisition.summary || '').trim() || 'visual acquisition policy retained'}`
  }
  if (!String(verdict?.classification || '').trim() && String(videoEvidence?.video_capable || '') === 'confirmed') {
    return `${String(videoEvidence.video_device_class || 'video_device').replaceAll('_', ' ')} · ${String(videoEvidence.evidence_type || 'behavioral')}`
  }
  const classification = String(verdict?.classification || '').trim()
  const action = String(verdict?.recommended_action || '').trim()
  if (classification) {
    return `${classification.replaceAll('_', ' ')}${action ? ` · ${action.replaceAll('_', ' ')}` : ''}`
  }
  return 'inconclusive · evidence insufficient'
}

function getCameraVerdictGuidance(item) {
  const verdict = getCameraValidationReport(item)?.verdict || {}
  return String(verdict?.operator_guidance || verdict?.reasoning || '').trim()
}

function getCameraProtocolEvidence(item) {
  const probes = item?.active_fingerprint?.probes || []
  if (!probes.length) return []
  const first = probes[0] || {}
  return [
    { label: 'HTTP', detail: summarizeHttpProbe(first.http) },
    { label: 'ONVIF', detail: summarizeOnvifProbe(first.onvif) },
    { label: 'RTSP', detail: summarizeRtspProbe(first.rtsp) },
    { label: 'Snapshot', detail: summarizeSnapshotProbe(first.snapshot) },
  ]
}

function getCameraVisualArtifacts(item) {
  const artifacts = []
  const seen = new Set()
  const appendArtifact = (entry) => {
    const savedPath = String(entry?.saved_path || entry?.capture_file || '').trim()
    if (!savedPath || seen.has(savedPath)) return
    seen.add(savedPath)
    const suffix = savedPath.toLowerCase()
    const imageLike = ['.jpg', '.jpeg', '.png', '.bmp', '.webp'].some((ext) => suffix.endsWith(ext))
    const videoLike = ['.mp4', '.webm', '.mov', '.m4v'].some((ext) => suffix.endsWith(ext))
    artifacts.push({
      path: savedPath,
      imageLike,
      videoLike,
      previewKind: imageLike ? 'image' : videoLike ? 'video' : 'file',
      hash: String(entry?.payload_sha256 || entry?.summary || '').trim(),
      targetIp: String(entry?.target_ip || '').trim(),
      protocol: String(entry?.protocol || '').trim(),
      pathHint: String(entry?.path || '').trim(),
      savedLabel: imageLike ? 'Saved Snapshot' : videoLike ? 'Saved Clip' : 'Saved Artifact',
      url: `/api/wifi_mk7/camera_hunt/artifact?path=${encodeURIComponent(savedPath)}`,
    })
  }
  for (const probe of item?.active_fingerprint?.probes || []) {
    for (const finding of probe?.snapshot?.findings || []) appendArtifact({ ...finding, target_ip: probe?.ip })
    if (probe?.rtsp?.frame_capture_path) {
      appendArtifact({
        capture_file: probe.rtsp.frame_capture_path,
        protocol: 'rtsp',
        target_ip: probe?.ip,
        path: probe?.rtsp?.frame_capture_url || '',
        summary: probe?.rtsp?.status_line || '',
      })
    }
  }
  const protocolEvidence = getCameraValidationReport(item)?.evidence?.protocol || []
  for (const entry of protocolEvidence) {
    if (['snapshot_artifact', 'rtsp_frame_artifact', 'behavioral_video_proof'].includes(String(entry?.evidence_type || ''))) appendArtifact(entry)
  }
  if (item?.hard_audit?.behavioral_video_proof_artifact) {
    appendArtifact({
      capture_file: item.hard_audit.behavioral_video_proof_artifact,
      protocol: 'behavioral',
      path: 'behavioral_video_proof.json',
      summary: item?.hard_audit?.video_truth?.status_reason || '',
    })
  }
  for (const entry of getCameraEvidencePolicy(item)?.visual_evidence || []) {
    appendArtifact({
      capture_file: entry?.path,
      protocol: entry?.protocol,
      path: entry?.detail,
      summary: entry?.label || '',
    })
  }
  return artifacts
}

function getPrimaryCameraMediaArtifact(item) {
  const artifacts = getCameraVisualArtifacts(item)
  return artifacts.find((artifact) => artifact.imageLike) || artifacts.find((artifact) => artifact.videoLike) || artifacts[0] || null
}

function getCameraMediaEvidenceLevel(item) {
  const artifacts = getCameraVisualArtifacts(item)
  const imageArtifacts = artifacts.filter((artifact) => artifact.imageLike)
  const videoTruth = getCameraVideoTruth(item)
  const visualAcquisition = getCameraVisualAcquisition(item)
  const confirmation = String(item?.camera_confirmation?.level || '').trim().toLowerCase()
  const streamState = String(item?.stream_state?.state || '').trim().toLowerCase()
  const protocols = getCameraProtocolEvidence(item)
  const activeProtocols = protocols.filter((entry) => !String(entry?.detail || '').toLowerCase().startsWith('no '))
  const streamVerified = ['confirmed', 'verified', 'artifact_confirmed'].includes(String(videoTruth?.video_confirmed || '').trim().toLowerCase())
    || Number(videoTruth?.correlation_confidence || 0) >= 0.72
    || ['confirmed', 'verified'].includes(streamState)

  if (streamVerified) {
    return {
      label: 'Live Stream Verified',
      tone: 'danger',
      summary: videoTruth?.status_reason || 'A retained live-view correlation or sustained stream proof is present.',
    }
  }
  if (String(visualAcquisition?.outcome_class || '') === 'stream_path_recovered_but_decode_blocked') {
    return {
      label: 'Decode Blocked',
      tone: 'warning',
      summary: visualAcquisition?.summary || 'A stream path was retained but no image or clip was decoded.',
    }
  }
  if (String(visualAcquisition?.outcome_class || '') === 'encrypted_cloud_relay_only') {
    return {
      label: 'Cloud Relay Only',
      tone: 'cyan',
      summary: visualAcquisition?.summary || 'Encrypted cloud relay behavior was retained without a local visual artifact.',
    }
  }
  if (imageArtifacts.length) {
    return {
      label: 'Snapshot Captured',
      tone: 'danger',
      summary: `${imageArtifacts.length} retained image artifact${imageArtifacts.length === 1 ? '' : 's'} are available for operator review.`,
    }
  }
  if (activeProtocols.length || ['confirmed', 'artifact_confirmed'].includes(confirmation)) {
    return {
      label: 'Protocol Confirmed',
      tone: 'cyan',
      summary: activeProtocols.map((entry) => entry.label).join(', ') || 'Camera-specific local protocol evidence is retained, but no image artifact has been captured yet.',
    }
  }
  return {
    label: 'Identity Only',
    tone: 'neutral',
    summary: visualAcquisition?.summary || 'No retained snapshot or verified live-stream artifact is available yet.',
  }
}

function getCameraNegativeEvidence(item) {
  const negatives = []
  const summary = item?.active_fingerprint?.summary || {}
  if (!(item?.active_fingerprint?.candidate_ips || []).length) {
    negatives.push(getLeadIpReason(item))
  }
  if (Number(summary?.http_hits || 0) <= 0) negatives.push('HTTP produced no camera-confirming response')
  if (Number(summary?.onvif_hits || 0) <= 0) negatives.push('ONVIF service was not confirmed')
  if (Number(summary?.rtsp_hits || 0) <= 0) negatives.push('RTSP control path was not confirmed')
  if (Number(summary?.snapshot_hits || 0) <= 0) negatives.push('Snapshot retrieval did not produce an artifact')
  return negatives.slice(0, 4)
}

function buildCameraAttackAssessment(item, audit, replayState) {
  const replay = replayState?.last_run || {}
  const counters = replay?.counters || {}
  const classification = String(audit?.final_verdict?.classification || '').trim().toLowerCase()
  const protocols = getCameraProtocolEvidence(item)
  const candidateIps = getLeadCandidateIps(item)
  const pmfEnabled = String(item?.pmf || '').toLowerCase() === 'true'
  const openSignals = protocols.filter((entry) => !String(entry?.detail || '').toLowerCase().startsWith('no '))
  const replaySignalCount = Number(counters?.deauthentication || 0)
    + Number(counters?.disassociation || 0)
    + Number(counters?.eapol || 0)
    + Number(counters?.beacon || 0)

  let verdict = 'INCONCLUSIVE'
  let tone = 'warning'
  let summary = 'Camera evidence remains partial. More proof is needed before calling the device safe or exploitable.'

  if (classification.includes('confirmed') || classification.includes('exposed')) {
    verdict = 'EXPOSED SERVICES'
    tone = 'danger'
    summary = 'The camera or its supporting services expose reachable local surfaces that deserve operator action.'
  } else if (openSignals.length >= 2 || (candidateIps.length && !pmfEnabled)) {
    verdict = 'WEAK CAMERA POSTURE'
    tone = 'warning'
    summary = 'The camera shows weak posture indicators such as candidate IP reachability, limited protections, or partial local protocol exposure.'
  } else if (pmfEnabled && !openSignals.length && classification.includes('negative')) {
    verdict = 'SAFE / HARDENED'
    tone = 'cyan'
    summary = 'Observed evidence suggests the camera is hardened against the assessed local paths and did not expose a justified local attack path.'
  }

  const findings = [
    replaySignalCount > 0
      ? `Replay surfaced ${Number(counters?.deauthentication || 0)} deauth, ${Number(counters?.disassociation || 0)} disassoc, ${Number(counters?.eapol || 0)} EAPOL, and ${Number(counters?.beacon || 0)} rogue beacon signals.`
      : 'Replay did not surface adversary-frame indicators in the selected PCAP.',
    candidateIps.length
      ? `Candidate IP evidence retained: ${candidateIps.slice(0, 3).join(', ')}.`
      : 'No validated or candidate IP evidence is retained for this lead.',
    openSignals.length
      ? `Protocol checks produced ${openSignals.length} non-negative responses across HTTP / ONVIF / RTSP / snapshot checks.`
      : 'Protocol checks did not confirm a local HTTP / ONVIF / RTSP / snapshot path.',
    pmfEnabled
      ? 'PMF appears enabled on the retained Wi-Fi evidence.'
      : 'PMF was not seen in the retained Wi-Fi evidence.',
    String(item?.camera_confirmation?.summary || item?.stream_state?.summary || '').trim() || 'No camera confirmation summary retained.',
  ]

  return { verdict, tone, summary, findings }
}

function getServiceAudit(target, override) {
  return override || target?.service_audit || {}
}

function getDdiResolution(target, override) {
  return override?.ddi_resolution || target?.ddi_resolution || {}
}

function getDeviceIpEvidence(target, override) {
  const audit = getServiceAudit(target, override)
  const ddi = getDdiResolution(target, override)
  const ips = extractDeviceStrings([
    ...(audit?.validated_ips || []),
    ...(audit?.candidate_ips || []),
    ...(ddi?.validated_ips || []),
    ...(ddi?.candidate_ips || []),
    ...(target?.candidate_ips || []),
    target?.ip_address,
    target?.local_ip,
  ])
  const reason = String(
    audit?.target_validation?.explanation
    || ddi?.resolution_summary
    || ddi?.reason
    || target?.candidate_ip_reason
    || ''
  ).trim()
  return {
    ips,
    summary: ips.length ? ips.join(', ') : (reason || 'No retained IP evidence.'),
  }
}

function getDeviceCredentialEvidence(target, override) {
  const audit = getServiceAudit(target, override)
  const access = audit?.access_posture || {}
  const serviceId = audit?.service_identification || {}
  const credentialHints = extractDeviceStrings([
    ...(audit?.credential_findings || []),
    ...(access?.credential_findings || []),
    ...(serviceId?.credential_findings || []),
    ...(access?.default_credentials || []),
  ])
  const loginHints = extractDeviceStrings([
    ...(access?.login_paths || []),
    ...(serviceId?.login_paths || []),
    ...(access?.auth_paths || []),
    access?.login_required ? 'login_required' : '',
  ])
  return {
    credentials: credentialHints,
    logins: loginHints,
    summary: credentialHints.length || loginHints.length
      ? [...credentialHints.slice(0, 2), ...loginHints.slice(0, 2)].join(' · ')
      : 'No credential or login evidence retained.',
  }
}

function getDeviceAuditEvidence(target, override) {
  const classification = getDeviceClassification(target)
  const ip = getDeviceIpEvidence(target, override)
  const creds = getDeviceCredentialEvidence(target, override)
  const services = target?.service_exposure || {}
  const serviceInventory = services?.service_inventory || []
  const serviceText = serviceInventory.length
    ? serviceInventory.slice(0, 3).map((entry) => `${entry?.service || '--'}:${entry?.port || '--'}`).join(' · ')
    : ((services?.protocols || []).join(', ') || 'No retained services')
  return {
    classification,
    ip,
    creds,
    serviceText,
    summary: `${classification.group_label} · ${classification.confidence} · ${serviceText}`,
  }
}

function getDdiStateLabel(value) {
  const raw = String(value || 'NO_IP_EVIDENCE').trim()
  if (!raw) return 'No IP Evidence'
  return raw.replaceAll('_', ' ')
}

function getHandshakeEvidenceState(target) {
  const handshake = target?.handshake_evidence || {}
  const raw = String(handshake?.state || '').trim()
  if (raw) return raw.replaceAll('_', ' ')
  return getHandshakeStatus(target)
}

function getEvidenceArtifacts(target, override) {
  const audit = getServiceAudit(target, override)
  const ddi = getDdiResolution(target, override)
  const destination = getDestinationAnalysis(target, override)
  const sessionManifest = target?.evidence_artifacts?.session_manifest || ddi?.evidence_artifacts?.session_manifest || ''
  const rows = []
  for (const entry of [
    { label: 'Target Manifest', path: target?.evidence_artifacts?.target_manifest || ddi?.evidence_artifacts?.target_manifest },
    { label: 'DDI Resolution', path: target?.evidence_artifacts?.ddi_resolution_path || ddi?.evidence_artifacts?.ddi_resolution_path },
    { label: 'Target Filtered PCAP', path: target?.evidence_artifacts?.target_filtered_pcap || ddi?.evidence_artifacts?.target_filtered_pcap },
    { label: 'Handshake Evidence PCAP', path: target?.evidence_artifacts?.handshake_evidence_pcap || ddi?.evidence_artifacts?.handshake_evidence_pcap },
    { label: 'Service Audit Trace', path: audit?.evidence_artifacts?.service_audit_trace || audit?.service_audit_trace_path || '' },
    { label: 'Destination Analysis', path: destination?.evidence_artifacts?.destination_analysis || audit?.evidence_artifacts?.destination_analysis || target?.evidence_artifacts?.destination_analysis || '' },
    { label: 'External IPs', path: destination?.evidence_artifacts?.external_ips || audit?.evidence_artifacts?.external_ips || target?.evidence_artifacts?.external_ips || '' },
    { label: 'DNS Records', path: destination?.evidence_artifacts?.dns_records || audit?.evidence_artifacts?.dns_records || target?.evidence_artifacts?.dns_records || '' },
    { label: 'TLS Metadata', path: destination?.evidence_artifacts?.tls_metadata || audit?.evidence_artifacts?.tls_metadata || target?.evidence_artifacts?.tls_metadata || '' },
    { label: 'Session Manifest', path: sessionManifest },
  ]) {
    const cleaned = String(entry?.path || '').trim()
    if (cleaned) rows.push({ ...entry, path: cleaned, url: `/api/wifi_mk7/artifact?path=${encodeURIComponent(cleaned)}` })
  }
  for (const exportEntry of target?.evidence_artifacts?.audit_exports?.pcapng_exports || ddi?.evidence_artifacts?.audit_exports?.pcapng_exports || []) {
    const cleaned = String(exportEntry?.path || '').trim()
    if (cleaned) rows.push({ label: 'Audit PCAPNG', path: cleaned, url: `/api/wifi_mk7/artifact?path=${encodeURIComponent(cleaned)}` })
  }
  for (const exportEntry of target?.evidence_artifacts?.audit_exports?.pcap_exports || ddi?.evidence_artifacts?.audit_exports?.pcap_exports || []) {
    const cleaned = String(exportEntry?.path || '').trim()
    if (cleaned) rows.push({ label: 'Audit PCAP', path: cleaned, url: `/api/wifi_mk7/artifact?path=${encodeURIComponent(cleaned)}` })
  }
  return rows
}

function getPcapSavedStatus(target) {
  const ddi = getDdiResolution(target)
  const artifacts = target?.evidence_artifacts || ddi?.evidence_artifacts || {}
  const status = artifacts?.artifact_status || {}
  const exports = artifacts?.audit_exports || {}
  const pcapngCount = Number((exports?.pcapng_exports || []).length || 0)
  const pcapCount = Number((exports?.pcap_exports || []).length || 0)
  const targetCaptureSaved = Boolean(status?.target_capture_saved)
  const handshakeSaved = Boolean(status?.handshake_capture_saved)
  const handshakeState = String(status?.handshake_state || target?.handshake_evidence?.state || ddi?.handshake_evidence?.state || 'NO_HANDSHAKE_OBSERVED').trim()
  const saved = targetCaptureSaved
  const detailParts = []
  if (targetCaptureSaved) detailParts.push(`capture ${Number(status?.target_capture_packet_count || 0)} pkts`)
  else detailParts.push('capture missing')
  if (handshakeSaved) detailParts.push(`handshake ${Number(status?.handshake_capture_packet_count || 0)} pkts`)
  else if (handshakeState && handshakeState !== 'NO_HANDSHAKE_OBSERVED') detailParts.push(handshakeState.replaceAll('_', ' ').toLowerCase())
  else detailParts.push('no handshake observed')
  if (pcapngCount > 0 || pcapCount > 0) detailParts.push(`${pcapngCount} pcapng · ${pcapCount} pcap`)
  return {
    saved,
    label: saved ? 'Saved' : 'Not Saved',
    detail: detailParts.join(' · '),
  }
}

function getServiceAuditStages(target, override) {
  return ((getServiceAudit(target, override).pipeline || {}).stages || []).map((stage) => ({
    id: String(stage?.id || ''),
    label: String(stage?.label || stage?.id || 'stage'),
    status: String(stage?.status || 'pending'),
    detail: String(stage?.detail || '').trim(),
  }))
}

function getServiceAuditStatus(target, override) {
  const audit = getServiceAudit(target, override)
  const ddi = getDdiResolution(target, override)
  if (!audit || !Object.keys(audit).length) return { label: 'Not Audited', tone: 'neutral', detail: 'hard audit not run' }
  const verdict = String(audit?.final_verdict?.classification || '').trim()
  if (String(audit?.status || '').toLowerCase() === 'running') return { label: 'Auditing', tone: 'cyan', detail: 'hard audit in progress' }
  if (String(audit?.pipeline?.status || '').toLowerCase() === 'blocked' || !audit?.ok) {
    return {
      label: 'Blocked',
      tone: 'warning',
      detail: ddi?.resolution_state ? getDdiStateLabel(ddi.resolution_state) : (audit?.target_validation?.explanation || 'no validated IP'),
    }
  }
  return {
    label: 'Audited',
    tone: verdict.includes('OPEN_NO_AUTH') ? 'danger' : verdict.includes('AUTH_REQUIRED') ? 'warning' : 'green',
    detail: verdict ? verdict.replaceAll('_', ' ') : 'audit retained',
  }
}

function getServiceAuditProcessingStageId(target, override) {
  const audit = getServiceAudit(target, override)
  const running = String(audit?.status || '').toLowerCase() === 'running' || String(audit?.pipeline?.status || '').toLowerCase() === 'running'
  if (!running) return ''
  return String(audit?.pipeline?.current_stage || '').trim()
}

function buildCameraLeadStageList(item) {
  const analysisOk = Boolean(item?.camera_detection?.detected || item?.camera_detection?.score || item?.behavior_analysis?.summary)
  const candidateIps = item?.active_fingerprint?.candidate_ips || []
  const summary = item?.active_fingerprint?.summary || {}
  const verdict = getCameraValidationReport(item)?.verdict || {}
  const classification = String(verdict?.classification || '').toLowerCase()
  return [
    {
      label: 'Passive',
      state: analysisOk ? 'complete' : 'pending',
      detail: analysisOk ? (item?.camera_detection?.classification || 'camera signals retained') : 'no retained passive signals',
    },
    {
      label: 'IP',
      state: candidateIps.length ? 'complete' : 'blocked',
      detail: candidateIps.length ? candidateIps.slice(0, 2).join(', ') : 'no candidate IP',
    },
    {
      label: 'Probe',
      state: summary?.camera_positive ? 'complete' : (item?.active_fingerprint ? 'partial' : 'pending'),
      detail: summary?.camera_positive ? 'protocol-positive' : getProbeStatus(item).detail,
    },
    {
      label: 'Audit',
      state: classification === 'unsafe' || classification === 'weak_enforcement'
        ? 'complete'
        : classification === 'secure'
          ? 'complete'
          : item?.hard_audit
            ? 'partial'
            : 'pending',
      detail: getCameraVerdictSummary(item),
    },
  ]
}

function getCameraHardAuditPipeline(item) {
  return item?.hard_audit?.pipeline || {}
}

function getCameraLayerAudit(item) {
  return item?.hard_audit?.layer_audit || item?.layer_audit || {}
}

function withCameraHardAudit(item, hardAudit) {
  if (!item || !hardAudit) return item
  return {
    ...item,
    hard_audit: hardAudit,
  }
}

function withCameraLayerAudit(item, layerAudit) {
  if (!item || !layerAudit) return item
  return {
    ...item,
    hard_audit: {
      ...(item?.hard_audit || {}),
      layer_audit: layerAudit,
    },
    layer_audit: layerAudit,
  }
}

function getCameraHardAuditStages(item) {
  const stages = (getCameraHardAuditPipeline(item).stages || []).map((stage) => ({
    id: String(stage?.id || ''),
    label: String(stage?.label || stage?.id || 'stage'),
    status: String(stage?.status || 'pending'),
    detail: String(stage?.detail || '').trim(),
  }))
  const artifacts = getCameraVisualArtifacts(item)
  if (artifacts.length) {
    const primary = artifacts[0] || {}
    stages.push({
      id: 'media_saved',
      label: 'Media Saved',
      status: 'completed',
      detail: `${artifacts.length} artifact${artifacts.length === 1 ? '' : 's'} retained${primary?.savedLabel ? ` · ${primary.savedLabel}` : ''}`,
    })
  } else if (item?.hard_audit?.video_truth_test) {
    const truth = item?.hard_audit?.video_truth_test || {}
    stages.push({
      id: 'media_saved',
      label: 'Media Saved',
      status: String(truth?.status || '').toLowerCase() === 'completed' ? 'partial' : 'pending',
      detail: String(truth?.summary || 'Media capture ran, but no saved artifact was retained yet.').trim(),
    })
  }
  return stages
}

function getCameraHardAuditProgress(item) {
  const stages = getCameraHardAuditStages(item)
  if (!stages.length) return 0
  const completed = stages.filter((stage) => stage.status === 'completed').length
  const active = stages.some((stage) => stage.status === 'active') ? 0.5 : 0
  return Math.round(((completed + active) / stages.length) * 100)
}

function getCameraHardAuditProcessingStageId(item) {
  const stages = getCameraHardAuditStages(item)
  const activeStage = stages.find((stage) => stage.status === 'active')
    || stages.find((stage) => stage.status === 'partial')
    || stages.find((stage) => stage.status === 'pending')
    || null
  return String(activeStage?.id || '')
}

function getCameraHardAuditTraffic(item) {
  return getCameraHardAuditPipeline(item).traffic_intelligence || {}
}

function getCameraLayerAuditRows(item) {
  return (getCameraLayerAudit(item).layers || []).map((layer) => ({
    id: String(layer?.id || ''),
    label: String(layer?.label || layer?.id || 'layer'),
    status: String(layer?.status || 'blocked'),
    detail: String(layer?.detail || '').trim(),
    signals: Array.isArray(layer?.signals) ? layer.signals.filter(Boolean) : [],
  }))
}

function getCameraVideoTruth(item) {
  return item?.hard_audit?.video_truth || {}
}

function getCameraOperatorPrompt(item) {
  return getCameraHardAuditPipeline(item).operator_prompt || {}
}

function getLeadCandidateIps(item, limit = 4) {
  return (item?.active_fingerprint?.candidate_ips || [])
    .map((value) => String(value || '').trim())
    .filter(Boolean)
    .slice(0, limit)
}

function getLeadIpReason(item) {
  return String(item?.active_fingerprint?.candidate_ip_reason || '').trim() || 'No IP could be inferred from the current passive evidence.'
}

function getOperatorLeadSnapshot(item) {
  const stream = item?.stream_state || {}
  const metrics = stream?.metrics || {}
  const protocols = (item?.camera_confirmation?.local_protocols || item?.stream_state?.protocols || []).slice(0, 3).join(', ')
  const candidateIps = getLeadCandidateIps(item, 2).join(', ')
  return [
    formatStreamStateLabel(stream?.state || 'unknown'),
    protocols || 'no local protocol',
    `${metrics?.total_packets ?? item?.packet_count ?? 0} pkts`,
    fmtBytes(metrics?.total_bytes ?? item?.frame_bytes_total ?? 0),
    candidateIps ? `IPs ${candidateIps}` : 'IPs --',
  ].join(' · ')
}

function getLeadMacAddress(item) {
  return String(item?.mac || item?.bssid || item?.associated_bssid || '').trim()
}

function getLeadOui(item) {
  const mac = getLeadMacAddress(item)
  const parts = mac.split(':').filter(Boolean)
  if (parts.length < 3) return '--'
  return parts.slice(0, 3).join(':').toUpperCase()
}

function getCameraLeadKindLabel(item) {
  return item?.leadKind === 'client' ? 'Client Lead' : 'Network Lead'
}

function getCameraProtocolHintSummary(item) {
  const confidence = item?.service_exposure?.protocol_confidence || {}
  return [
    `HTTP ${Math.round(Number(confidence?.HTTP || item?.stream_state?.metrics?.http_confidence || 0))}`,
    `RTSP ${Math.round(Number(confidence?.RTSP || item?.stream_state?.metrics?.rtsp_confidence || 0))}`,
    `TLS ${Math.round(Number(confidence?.TLS || item?.stream_state?.metrics?.tls_confidence || 0))}`,
    `DNS ${Math.round(Number(confidence?.['mDNS/DNS'] || 0))}`,
  ].join(' · ')
}

function getCameraServiceHintSummary(item) {
  const protocols = (item?.service_exposure?.protocols || []).filter(Boolean)
  const summary = String(item?.service_exposure?.summary || '').trim()
  if (protocols.length && summary) return `${protocols.join(', ')} · ${summary}`
  if (protocols.length) return protocols.join(', ')
  return summary || 'No retained service exposure hints.'
}

function getHardAuditTimerSnapshot(startedAtMs, nowMs, active) {
  if (!active || !startedAtMs) {
    return {
      active: false,
      durationSeconds: HARD_AUDIT_DURATION_SECONDS,
      elapsedSeconds: 0,
      remainingSeconds: HARD_AUDIT_DURATION_SECONDS,
      progress: 0,
      label: `0s / ${HARD_AUDIT_DURATION_SECONDS}s`,
      summary: `Hard Audit window fixed at ${HARD_AUDIT_DURATION_SECONDS}s.`,
    }
  }
  const elapsedMs = Math.max(0, Number(nowMs || startedAtMs) - Number(startedAtMs || 0))
  const elapsedSeconds = Math.min(HARD_AUDIT_DURATION_SECONDS, Math.floor(elapsedMs / 1000))
  const remainingSeconds = Math.max(0, HARD_AUDIT_DURATION_SECONDS - elapsedSeconds)
  const progress = Math.max(0, Math.min(100, Math.round((elapsedSeconds / HARD_AUDIT_DURATION_SECONDS) * 100)))
  return {
    active: true,
    durationSeconds: HARD_AUDIT_DURATION_SECONDS,
    elapsedSeconds,
    remainingSeconds,
    progress,
    label: `${elapsedSeconds}s / ${HARD_AUDIT_DURATION_SECONDS}s`,
    summary: remainingSeconds > 0
      ? `${remainingSeconds}s remaining in the fixed Hard Audit capture window.`
      : 'Hard Audit capture window completed. Finalizing retained evidence.',
  }
}

function getCameraCaptureMonitor(item, busy = false, timerSnapshot = null) {
  const pipeline = getCameraHardAuditPipeline(item)
  const stages = getCameraHardAuditStages(item)
  const operatorPrompt = getCameraOperatorPrompt(item)
  const activeStage = stages.find((stage) => stage.status === 'active')
    || stages.find((stage) => stage.status === 'partial')
    || stages.find((stage) => stage.status === 'pending')
    || null
  const completed = stages.filter((stage) => stage.status === 'completed').length
  const stageProgress = stages.length
    ? getCameraHardAuditProgress(item)
    : (busy ? 8 : 0)
  const timerProgress = Number(timerSnapshot?.progress || 0)
  const progress = busy ? Math.max(stageProgress, timerProgress) : stageProgress
  const status = String(pipeline?.status || item?.hard_audit?.status || (busy ? 'running' : 'idle')).toLowerCase()
  const promptMessage = String(operatorPrompt?.message || '').trim()
  const detail = [
    timerSnapshot?.active ? timerSnapshot.label : '',
    `${completed}/${stages.length || 0} stages completed`,
    activeStage?.detail || activeStage?.label || '',
    promptMessage,
  ].filter(Boolean).join(' · ')
  return {
    progress,
    status,
    statusLabel: busy || status === 'running'
      ? (Number(timerSnapshot?.progress || 0) >= 100 ? 'Finalizing Evidence' : 'Hard Audit Active')
      : status === 'completed'
        ? 'Capture Complete'
        : 'Ready',
    stageLabel: activeStage?.label || (busy ? 'Bootstrap' : 'Idle'),
    detail: detail || 'Media evidence capture is idle.',
    promptMessage: promptMessage || 'Awaiting operator-triggered capture.',
    activeStage,
    stages,
    timer: timerSnapshot || getHardAuditTimerSnapshot(0, 0, false),
  }
}

function getCameraTopologyNodes(item) {
  const association = getCameraLeadAssociatedSsid(item)
  const supportingId = getCameraLeadSupportingId(item)
  const candidateIps = getLeadCandidateIps(item, 3)
  const traffic = getCameraHardAuditTraffic(item)
  const endpoints = (traffic.endpoints || []).slice(0, 3)
  const localProtocols = (item?.camera_confirmation?.local_protocols || []).slice(0, 3)
  const cloudProtocols = (item?.camera_confirmation?.cloud_protocols || []).slice(0, 3)
  return [
    {
      id: 'target',
      label: 'Target',
      state: item?.camera_detection?.detected ? 'completed' : 'active',
      detail: `${getCameraLeadKindLabel(item)} · ${getLeadMacAddress(item) || 'unresolved MAC'}`,
    },
    {
      id: 'association',
      label: 'Association',
      state: association && association !== '--' ? 'completed' : 'pending',
      detail: `${association || 'unassociated'} · ${supportingId || '--'}`,
    },
    {
      id: 'ip',
      label: 'IP Layer',
      state: candidateIps.length ? 'completed' : 'pending',
      detail: candidateIps.length ? candidateIps.join(', ') : shortText(getLeadIpReason(item), 52),
    },
    {
      id: 'services',
      label: 'Services',
      state: (localProtocols.length || cloudProtocols.length || (item?.service_exposure?.protocols || []).length) ? 'completed' : 'partial',
      detail: [
        localProtocols.length ? `local ${localProtocols.join('/')}` : '',
        cloudProtocols.length ? `cloud ${cloudProtocols.join('/')}` : '',
        !localProtocols.length && !cloudProtocols.length ? shortText(getCameraServiceHintSummary(item), 52) : '',
      ].filter(Boolean).join(' · '),
    },
    {
      id: 'endpoints',
      label: 'Endpoints',
      state: endpoints.length ? 'completed' : 'partial',
      detail: endpoints.length
        ? endpoints.map((entry) => `${entry.domain || entry.endpoint_ip}:${entry.port}/${entry.protocol}`).join(' · ')
        : shortText(traffic.explanation || 'No endpoint attribution retained yet.', 52),
    },
  ]
}

function buildCameraAuditSeed(summary, operatorMessage) {
  return {
    status: 'running',
    pipeline: {
      status: 'running',
      summary,
      operator_prompt: {
        state: 'baseline',
        message: operatorMessage,
      },
      stages: [
        { id: 'passive_probe', label: 'Passive + Probe', status: 'active', detail: 'Seeding the audit from retained passive evidence.' },
        { id: 'network_reality', label: 'Network Reality', status: 'pending', detail: 'Awaiting validated device/IP mapping.' },
        { id: 'ip_materialization', label: 'IP Materialization', status: 'pending', detail: 'Awaiting candidate IP escalation.' },
        { id: 'baseline', label: 'Baseline', status: 'pending', detail: 'Idle baseline not started yet.' },
        { id: 'trigger', label: 'Trigger', status: 'pending', detail: 'Awaiting operator live-view trigger.' },
        { id: 'post_trigger', label: 'Post Trigger', status: 'pending', detail: 'Post-trigger capture not started yet.' },
        { id: 'traffic_intel', label: 'Traffic Intel', status: 'pending', detail: 'Awaiting MAC-scoped flow extraction.' },
        { id: 'live_view', label: 'Live-View Correlation', status: 'pending', detail: 'Correlation not attempted yet.' },
        { id: 'stream_detection', label: 'Stream Detection', status: 'pending', detail: 'Awaiting stream classification.' },
        { id: 'endpoint_attribution', label: 'Endpoint Attribution', status: 'pending', detail: 'Awaiting endpoint attribution.' },
        { id: 'artifact_decision', label: 'Artifact Decision', status: 'pending', detail: 'Awaiting artifact eligibility decision.' },
        { id: 'negative_proof', label: 'Negative Proof', status: 'pending', detail: 'Awaiting negative evidence review.' },
        { id: 'finalize', label: 'Finalize', status: 'pending', detail: 'Awaiting final classification.' },
      ],
    },
  }
}

function getCameraConfirmationRank(level) {
  const ranks = {
    artifact_confirmed: 5,
    confirmed: 4,
    likely: 3,
    possible: 2,
    unconfirmed: 1,
  }
  return ranks[String(level || 'unconfirmed')] || 0
}

function getCameraActionabilityScore(item, mode) {
  const protocols = new Set((item?.service_exposure?.protocols || []).map((value) => String(value || '').toUpperCase()))
  const confidence = item?.service_exposure?.protocol_confidence || {}
  const httpScore = Number(confidence?.HTTP || 0)
  const rtspScore = Number(confidence?.RTSP || 0)
  const tlsScore = Number(confidence?.TLS || 0)
  const onvifPresent = protocols.has('ONVIF')
  const rtspPresent = protocols.has('RTSP') || rtspScore >= 20
  const httpPresent = protocols.has('HTTP') || httpScore >= 35
  const localMediaPath = rtspPresent || onvifPresent || httpPresent
  const cloudMediaPath = tlsScore >= 20 || protocols.has('TLS') || protocols.has('QUIC')
  const streamState = String(item?.stream_state?.state || 'no_session')
  const transportPath = String(item?.camera_confirmation?.transport_path || item?.stream_state?.transport || 'unknown')
  const confirmationRank = getCameraConfirmationRank(item?.camera_confirmation?.level)
  const scenario = item?.scenario_delta?.comparisons || {}
  const idleVsLive = String(scenario?.idle_vs_live_view?.status || '')
  const motionVsIdle = String(scenario?.motion_vs_idle?.status || '')
  const appOpenDelta = String(scenario?.app_open_delta?.status || '')
  const positiveDeltaCount = [idleVsLive, motionVsIdle, appOpenDelta].filter((value) => value === 'STRONGER_TARGET' || value === 'HIGHER_PAYLOAD').length
  const objectHits = Number(item?.stream_state?.metrics?.object_hits || 0)
  const eapolFrames = Number(item?.stream_state?.metrics?.eapol_frame_count || 0)
  const score = Number(item?.camera_detection?.score || item?.target_score?.score || getOperationalTargetScore(item, mode) || 0)
  const probeSummary = item?.active_fingerprint?.summary || {}
  const probeHits = Number(probeSummary?.http_hits || 0) + Number(probeSummary?.onvif_hits || 0) + Number(probeSummary?.rtsp_hits || 0)
  const associated = Boolean(item?.associated_bssid)

  let actionability = 0
  actionability += confirmationRank * 30
  actionability += Math.min(30, rtspScore)
  actionability += Math.min(20, httpScore / 2)
  actionability += onvifPresent ? 35 : 0
  actionability += rtspPresent ? 45 : 0
  actionability += httpPresent ? 25 : 0
  actionability += localMediaPath ? 35 : 0
  actionability += transportPath === 'local' ? 20 : 0
  actionability += transportPath === 'hybrid' ? 12 : 0
  actionability += streamState === 'artifact_recovered' ? 60 : 0
  actionability += streamState === 'media_path_confirmed' ? 45 : 0
  actionability += streamState === 'possible_encrypted_media' ? 20 : 0
  actionability += positiveDeltaCount * 18
  actionability += Math.min(24, objectHits * 12)
  actionability += Math.min(12, eapolFrames * 2)
  actionability += Math.min(24, probeHits * 8)
  actionability += associated ? 4 : 0
  actionability += cloudMediaPath && !localMediaPath ? 6 : 0
  actionability += Math.min(20, score / 5)
  return actionability
}

function isCameraLeadRedAlert(item) {
  const streamMetrics = item?.stream_state?.metrics || {}
  const http = Number(streamMetrics?.http_confidence || item?.service_exposure?.protocol_confidence?.HTTP || 0)
  const rtsp = Number(streamMetrics?.rtsp_confidence || item?.service_exposure?.protocol_confidence?.RTSP || 0)
  const tls = Number(streamMetrics?.tls_confidence || item?.service_exposure?.protocol_confidence?.TLS || 0)
  const bytes = Number(streamMetrics?.total_bytes || item?.frame_bytes_total || 0)
  const packets = Number(streamMetrics?.total_packets || item?.packet_count || 0)
  const eapol = Number(streamMetrics?.eapol_frame_count || item?.authentication_evidence?.eapol_frame_count || item?.eapol_count || 0)
  const longLived = Boolean(streamMetrics?.long_lived_flow)
  const cameraScore = Number(item?.camera_detection?.score || item?.target_score?.score || 0)
  const confirmationLevel = String(item?.camera_confirmation?.level || 'unconfirmed')
  const probeHits = Number(item?.active_fingerprint?.summary?.http_hits || 0)
    + Number(item?.active_fingerprint?.summary?.onvif_hits || 0)
    + Number(item?.active_fingerprint?.summary?.rtsp_hits || 0)
    + Number(item?.active_fingerprint?.summary?.snapshot_hits || 0)

  const protocolDark = http <= 0 && rtsp <= 0 && tls <= 0
  const tinyPayload = bytes <= 1024 && packets <= 8 && eapol <= 0 && !longLived
  const highScored = cameraScore >= 60
  const notConfirmed = !['confirmed', 'artifact_confirmed'].includes(confirmationLevel)
  const noProbeWin = probeHits <= 0
  return highScored && protocolDark && tinyPayload && notConfirmed && noProbeWin
}

function buildCameraLeads(networks, clients, mode) {
  const networkLeads = (networks || [])
    .map((item) => ({ ...item, leadKind: 'network' }))
    .filter((item) => isStrongCameraCandidate(item))
  const clientLeads = (clients || [])
    .map((item) => ({ ...item, leadKind: 'client' }))
    .filter((item) => isStrongCameraCandidate(item))

  return [...networkLeads, ...clientLeads]
    .sort((left, right) => {
      const actionabilityDelta = getCameraActionabilityScore(right, mode) - getCameraActionabilityScore(left, mode)
      if (actionabilityDelta) return actionabilityDelta
      const detectedDelta = Number(!!right?.camera_detection?.detected) - Number(!!left?.camera_detection?.detected)
      if (detectedDelta) return detectedDelta
      const scoreDelta = getOperationalTargetScore(right, mode) - getOperationalTargetScore(left, mode)
      if (scoreDelta) return scoreDelta
      const confidenceDelta = Number(right?.camera_detection?.confidence || 0) - Number(left?.camera_detection?.confidence || 0)
      if (confidenceDelta) return confidenceDelta
      return Number(right?.rssi_dbm || -999) - Number(left?.rssi_dbm || -999)
    })
}

function buildCameraAttackableTargets(cameraLeads, networks, mode) {
  return (cameraLeads || [])
    .slice(0, 5)
    .map((item, index) => {
      const network = item?.leadKind === 'network'
        ? item
        : (networks || []).find((entry) => String(entry?.bssid || '').toLowerCase() === String(item?.associated_bssid || '').toLowerCase())
      return {
        id: `${item?.leadKind || 'lead'}:${item?.record_id || item?.bssid || item?.mac || index}`,
        item,
        network,
        label: item?.leadKind === 'client' ? (item?.mac || '<unknown client>') : (item?.ssid || '<hidden>'),
        score: item?.camera_detection?.score ?? item?.target_score?.score ?? 0,
        type: getCameraLeadLabel(item),
        proximity: getProximityLabel(item?.rssi_dbm),
        nextAction: item?.leadKind === 'client'
          ? 'Deep observe associated AP and retain surveillance candidate evidence'
          : getRedNextAction(item),
        why: getCameraLeadEvidence(item),
      }
    })
}

function buildBackendActivity(status, cameraHuntMode, handshakeAnalysisEnabled, networks = [], clients = []) {
  const scan = status?.scan || {}
  const channels = status?.channels || {}
  const currentChannel = channels?.current_channel ?? '--'
  const mode = scan?.mode || channels?.mode || 'broad'
  const interfaces = (scan?.interfaces || channels?.selected_interfaces || []).join(', ') || '--'
  const hotChannels = (channels?.hot_channels || []).slice(0, 6).join(', ') || '--'
  const channelStats = channels?.channel_statistics || {}
  const toolchain = status?.toolchain || {}
  const pipeline = status?.camera_hunt_pipeline || {}
  const processing = status?.processing_pipeline || toolchain.processing_pipeline || {}
  const sensorTools = toolchain.sensor_control || []
  const packetTools = toolchain.packet_capture || []
  const externalTools = toolchain.external_tools || []
  const runtimeApps = [...sensorTools, ...packetTools, ...externalTools].map((tool) => {
    const available = Boolean(tool?.available)
    const active = Boolean(tool?.active)
    const state = active ? 'running' : (available ? 'stopped' : 'unavailable')
    const interfaceLabel = tool?.interface || (tool?.interfaces || []).join(', ')
    const detailParts = [
      tool?.role || 'runtime component',
      interfaceLabel ? `iface ${interfaceLabel}` : '',
      tool?.pid ? `pid ${tool.pid}` : '',
      tool?.last_stop_state && !active ? `stop ${tool.last_stop_state}` : '',
    ]
    return {
      ...tool,
      state,
      detail: detailParts.filter(Boolean).join(' · '),
    }
  })
  const activeTools = [...sensorTools, ...packetTools, ...externalTools].filter((tool) => tool?.active).map((tool) => tool.name)
  const availableExternal = externalTools.filter((tool) => tool?.available).map((tool) => `${tool.name}${tool.active ? ' active' : ' standby'}`)
  const runtimeSummary = toolchain?.runtime_summary || {}
  const scanSummary = status?.last_scan_summary || {}
  const coreCaptureInterfaces = scanSummary?.core_capture_interfaces || scan?.interfaces || []
  const pipelineInterfaces = scanSummary?.pipeline_interfaces || []
  const collectorAssignments = (pipeline?.assignments || {})
  const phasePlan = Array.isArray(pipeline?.phase_plan) ? pipeline.phase_plan : []
  const phaseState = pipeline?.phase_state || {}
  const hasPhasedPipeline = phasePlan.length > 0
  const topology = [
    `Core Capture: ${coreCaptureInterfaces.join(', ') || '--'}`,
    `Airodump: ${collectorAssignments['airodump-ng'] || 'disabled: no spare interface'}`,
    `Kismet: ${collectorAssignments.kismet || 'disabled: no spare interface'}`,
    `Bettercap: ${collectorAssignments.bettercap || 'disabled: no spare interface'}`,
    `Pipeline Pool: ${pipelineInterfaces.join(', ') || '--'}`,
  ]
  const phasedTopology = phasePlan.length
    ? phasePlan.map((phase) => `${phase.name} ${phase.seconds}s`).join(' -> ')
    : ''
  const processingTopology = processing?.topology || (cameraHuntMode
    ? 'Capture Thread -> Decode Thread -> Enrichment Thread (tshark/Zeek) -> Flow Engine -> Camera Scoring -> UI'
    : 'Capture Thread -> Decode Thread -> Flow Engine -> Detection Engine -> UI')
  const queueSummary = processing?.queues
    ? `decode ${processing.queues.decode ?? 0} · flow ${processing.queues.flow ?? 0} · detect ${processing.queues.detect ?? 0}`
    : 'decode 0 · flow 0 · detect 0'
  const stageCounts = processing?.counts
    ? `capture ${processing.counts.capture ?? 0} · decode ${processing.counts.decode ?? 0} · flow ${processing.counts.flow ?? 0} · detect ${processing.counts.detect ?? 0}`
    : 'capture 0 · decode 0 · flow 0 · detect 0'
  const detectionSummary = processing?.summary
    ? (
      cameraHuntMode
        ? `camera leads ${processing.summary.camera_candidate_count ?? 0} · networks ${processing.summary.network_count ?? 0} · clients ${processing.summary.client_count ?? 0}${handshakeAnalysisEnabled ? ` · passive handshakes ${processing.summary.handshake_event_count ?? 0}` : ''}`
        : `networks ${processing.summary.network_count ?? 0} · clients ${processing.summary.client_count ?? 0} · camera candidates ${processing.summary.camera_candidate_count ?? 0}${handshakeAnalysisEnabled ? ` · passive handshakes ${processing.summary.handshake_event_count ?? 0}` : ''}`
    )
    : (
      cameraHuntMode
        ? `camera leads 0 · networks 0 · clients 0${handshakeAnalysisEnabled ? ' · passive handshakes 0' : ''}`
        : `networks 0 · clients 0 · camera candidates 0${handshakeAnalysisEnabled ? ' · passive handshakes 0' : ''}`
    )
  const authEvidence = status?.authentication_evidence || {}
  const observationAudit = status?.observation_audit || {}
  const coverageConfidence = observationAudit?.coverage_confidence || channels?.coverage_confidence || {}
  const passiveEventSummary = processing?.summary
    ? `assoc ${processing.summary.association_event_count ?? 0} · reassoc ${processing.summary.reassociation_event_count ?? 0} · auth ${processing.summary.authentication_event_count ?? 0} · probes ${processing.summary.probe_request_count ?? 0}`
    : 'assoc 0 · reassoc 0 · auth 0 · probes 0'
  const rawEvidenceSummary = processing?.summary
    ? `raw ${processing.summary.raw_eapol_frame_count ?? authEvidence?.debug?.raw_eapol_frame_count ?? 0} · dup ${processing.summary.duplicate_eapol_frame_count ?? authEvidence?.debug?.duplicate_eapol_frame_count ?? 0} · unmatched ${processing.summary.unmatched_eapol_frame_count ?? authEvidence?.debug?.unmatched_eapol_frame_count ?? 0}`
    : `raw ${authEvidence?.debug?.raw_eapol_frame_count ?? 0} · dup ${authEvidence?.debug?.duplicate_eapol_frame_count ?? 0} · unmatched ${authEvidence?.debug?.unmatched_eapol_frame_count ?? 0}`
  const toolProgress = phasePlan.map((phase) => {
    const state = phaseState?.[phase.name] || {}
    return `${phase.name}: ${state.percent ?? 0}% ${state.status || 'pending'}`
  })
  const currentPhase = String(pipeline?.current_phase || 'idle')
  const combinedEntities = [...(networks || []), ...(clients || [])]
  const cameraEntities = cameraHuntMode
    ? combinedEntities.filter((item) => (
      isStrongCameraCandidate(item)
      || Number(item?.camera_detection?.camera_confidence_score || item?.camera_detection?.score || 0) >= 15
    ))
    : combinedEntities
  const relevantEntities = cameraEntities.length ? cameraEntities : combinedEntities
  const getEntityBytes = (item) => {
    const explicitBytes = Number(item?.frame_bytes_total || item?.flow_metrics?.total_bytes || 0)
    if (explicitBytes > 0) return explicitBytes
    const frameCount = Number(item?.frame_count_total || item?.packet_count || 0)
    const avgFrameLength = Number(item?.avg_frame_len || 0)
    return frameCount > 0 && avgFrameLength > 0 ? frameCount * avgFrameLength : 0
  }
  const getEntityDataFrames = (item) => {
    const frameTypeCounts = item?.frame_type_counts || {}
    return Number(
      frameTypeCounts?.data
      ?? frameTypeCounts?.Data
      ?? item?.flow_metrics?.total_packets
      ?? item?.packet_count
      ?? 0,
    )
  }
  const getEntityProtocolPotential = (item) => {
    const confidence = item?.service_exposure?.protocol_confidence || {}
    const http = Number(confidence?.HTTP || 0)
    const rtsp = Number(confidence?.RTSP || 0)
    const tls = Number(confidence?.TLS || 0)
    const mdns = Number(confidence?.['mDNS/DNS'] || 0)
    return Math.min(100, http + (rtsp * 1.2) + (tls * 0.45) + (mdns * 0.2))
  }
  const getEntityProtocolSignals = (item) => {
    const confidence = item?.service_exposure?.protocol_confidence || {}
    return {
      http: Number(confidence?.HTTP || 0),
      rtsp: Number(confidence?.RTSP || 0),
      tls: Number(confidence?.TLS || 0),
      mdns: Number(confidence?.['mDNS/DNS'] || 0),
      vendorWps: Number(confidence?.['vendor/WPS'] || 0),
    }
  }
  const scoreImageRecovery = (item) => {
    const bytes = getEntityBytes(item)
    const dataFrames = getEntityDataFrames(item)
    const protocolSignals = getEntityProtocolSignals(item)
    const protocolScore = getEntityProtocolPotential(item)
    const eapolFrames = Number(
      item?.authentication_evidence?.eapol_frame_count
      ?? item?.authentication_evidence_frame_count
      ?? item?.handshake_eapol_count
      ?? item?.eapol_count
      ?? 0,
    )
    const serviceProtocols = (item?.service_exposure?.protocols || []).map((value) => String(value).toUpperCase())
    const httpSignal = protocolSignals.http > 0 || serviceProtocols.includes('HTTP')
    const rtspSignal = protocolSignals.rtsp > 0 || serviceProtocols.includes('RTSP')
    const tlsSignal = protocolSignals.tls > 0 || serviceProtocols.includes('TLS')
    const objectSignals = Number(item?.saved_image_count || 0) + Number(item?.http_object_count || 0)
    const decryptSignal = eapolFrames > 0
    const mediaPathSignal = httpSignal || rtspSignal || tlsSignal
    const artifactSignal = objectSignals > 0
    const realRecoverySignal = mediaPathSignal || decryptSignal || artifactSignal
    let score = 0
    score += Math.min(12, Math.log2(bytes + 1) * 0.9)
    score += Math.min(10, dataFrames * 1.1)
    if (httpSignal) score += 22 + Math.min(12, protocolSignals.http * 0.22)
    if (rtspSignal) score += 28 + Math.min(14, protocolSignals.rtsp * 0.24)
    if (tlsSignal) score += 10 + Math.min(8, protocolSignals.tls * 0.16)
    if (decryptSignal) score += 18
    if (artifactSignal) score += 30 + Math.min(12, objectSignals * 4)
    if (!realRecoverySignal) score = Math.min(score, bytes >= 65536 && dataFrames >= 12 ? 24 : 12)
    if (!httpSignal && !rtspSignal && !artifactSignal) score = Math.min(score, decryptSignal ? 34 : 24)
    if (bytes < 4096 && dataFrames < 6 && protocolScore <= 0) score = Math.min(score, 10)
    if (bytes < 1024 && dataFrames < 2) score = Math.min(score, 4)
    return Math.max(0, Math.min(100, Math.round(score)))
  }
  const buildBlockers = ({ bytes, dataFrames, httpScore, rtspScore, tlsScore, eapolFrames, objectSignals }) => {
    const blockers = []
    if (bytes < 4096 && dataFrames < 8) blockers.push('No object-sized payload retained')
    if (httpScore <= 0 && rtspScore <= 0 && tlsScore <= 0) blockers.push('No media protocol observed')
    if (eapolFrames <= 0) blockers.push('No decryptable session evidence')
    if (objectSignals <= 0) blockers.push('No artifact or object yield')
    return blockers.slice(0, 3)
  }
  const imageSignals = relevantEntities
    .map((item) => {
      const bytes = getEntityBytes(item)
      const dataFrames = getEntityDataFrames(item)
      const protocolScore = getEntityProtocolPotential(item)
      const protocolSignals = getEntityProtocolSignals(item)
      const cameraScore = Number(item?.camera_detection?.camera_confidence_score || item?.camera_detection?.score || 0)
      const serviceProtocols = (item?.service_exposure?.protocols || []).map((value) => String(value).toUpperCase())
      const familySignals = (item?.camera_detection?.matched_families || []).length
      const identityScore = Math.min(100, cameraScore + (protocolSignals.vendorWps * 0.8) + (familySignals ? 12 : 0))
      const continuityScore = Math.min(100, Math.round(Math.min(1, bytes / 32768) * 50 + Math.min(1, dataFrames / 24) * 50))
      const objectSignals = Number(item?.saved_image_count || 0) + Number(item?.http_object_count || 0)
      return {
        item,
        channel: Number(item?.channel || 0),
        bytes,
        dataFrames,
        protocolScore,
        protocolSignals,
        cameraScore,
        identityScore,
        continuityScore,
        objectSignals,
        serviceProtocols,
        score: scoreImageRecovery(item),
      }
    })
    .filter((item) => item.channel > 0)
  const buildEvidenceStage = (label, score, detail) => ({
    label,
    score: clampPercent(score),
    active: clampPercent(score) > 0,
    detail,
  })
  const topRecoverableLeads = imageSignals
    .slice()
    .sort((left, right) => right.score - left.score || right.bytes - left.bytes || right.dataFrames - left.dataFrames)
    .slice(0, 5)
    .map((entry, index) => {
      const item = entry.item
      const timestamps = Array.isArray(item?.packet_timestamps) ? item.packet_timestamps : []
      const samples = timestamps.length >= 2
        ? Array.from({ length: 8 }, (_, bucketIndex) => {
          const first = Number(timestamps[0] || 0)
          const last = Number(timestamps[timestamps.length - 1] || first)
          const span = Math.max(1, last - first)
          const bucketStart = first + (span * bucketIndex / 8)
          const bucketEnd = first + (span * (bucketIndex + 1) / 8)
          const count = timestamps.filter((ts) => Number(ts) >= bucketStart && Number(ts) < bucketEnd).length
          return count
        })
        : [
            Math.max(0, Math.round(entry.dataFrames * 0.1)),
            Math.max(0, Math.round(entry.dataFrames * 0.22)),
            Math.max(0, Math.round(entry.dataFrames * 0.5)),
            Math.max(0, Math.round(entry.dataFrames * 0.36)),
            Math.max(0, Math.round(entry.dataFrames * 0.74)),
            Math.max(0, Math.round(entry.dataFrames * 0.44)),
            Math.max(0, Math.round(entry.dataFrames * 0.28)),
            Math.max(0, Math.round(entry.dataFrames * 0.16)),
          ]
      const maxSample = Math.max(1, ...samples)
      const confidence = Number(item?.camera_detection?.camera_confidence_score || item?.camera_detection?.score || 0)
      const eapolFrames = Number(
        item?.authentication_evidence?.eapol_frame_count
        ?? item?.authentication_evidence_frame_count
        ?? item?.handshake_eapol_count
        ?? item?.eapol_count
        ?? 0,
      )
      const { http: httpScore, rtsp: rtspScore, tls: tlsScore, mdns: mdnsScore, vendorWps } = entry.protocolSignals
      const serviceProtocols = entry.serviceProtocols
      const httpSurface = httpScore > 0 || serviceProtocols.includes('HTTP')
      const rtspSurface = rtspScore > 0 || serviceProtocols.includes('RTSP')
      const decryptPotential = eapolFrames > 0 ? 75 : Math.min(35, tlsScore > 0 ? 18 : 0)
      const blockers = buildBlockers({
        bytes: entry.bytes,
        dataFrames: entry.dataFrames,
        httpScore,
        rtspScore,
        tlsScore,
        eapolFrames,
        objectSignals: entry.objectSignals,
      })
      const ladder = [
        buildEvidenceStage('Identity', entry.identityScore, `${(item?.camera_detection?.matched_families || []).slice(0, 2).join(', ') || 'no family'} · ${Math.round(confidence)} cam`),
        buildEvidenceStage('Session', entry.continuityScore, `${entry.dataFrames} data · continuity ${Math.min(100, Math.round((timestamps.length || entry.dataFrames) / Math.max(1, entry.dataFrames || 1) * 100))}%`),
        buildEvidenceStage('Media Path', Math.max(httpScore, rtspScore, tlsScore, mdnsScore), serviceProtocols.slice(0, 3).join(', ') || 'no visible media path'),
        buildEvidenceStage('Payload', Math.min(100, Math.log2(entry.bytes + 1) * 6 + entry.dataFrames * 2.8), `${fmtBytes(entry.bytes)} retained`),
        buildEvidenceStage('Decrypt', decryptPotential, eapolFrames > 0 ? `${eapolFrames} EAPOL` : 'no handshake'),
        buildEvidenceStage('Artifacts', Math.min(100, entry.objectSignals * 20 + Math.max(httpScore, rtspScore) * 0.25), entry.objectSignals > 0 ? `${entry.objectSignals} object hits` : 'no object yield'),
        buildEvidenceStage('Recoverable', entry.score, blockers.length ? `blocked by ${blockers[0].toLowerCase()}` : `${fmtBytes(entry.bytes)} recoverable estimate`),
      ]
      return {
        id: `${item?.leadKind || item?.device_type || 'lead'}:${item?.bssid || item?.mac || item?.associated_bssid || index}`,
        label: item?.ssid || item?.mac || item?.bssid || item?.associated_bssid || `lead-${index + 1}`,
        kind: item?.leadKind || item?.device_type || 'lead',
        channel: item?.channel || '--',
        score: entry.score,
        bytes: entry.bytes,
        dataFrames: entry.dataFrames,
        confidence,
        httpScore,
        rtspScore,
        tlsScore,
        decryptScore: decryptPotential,
        objectScore: Math.min(100, entry.objectSignals * 20 + Math.max(httpScore, rtspScore) * 0.25),
        continuity: timestamps.length >= 2
          ? Math.min(100, Math.round((timestamps.length / Math.max(2, entry.dataFrames || timestamps.length)) * 100))
          : Math.min(100, Math.round((entry.dataFrames / 12) * 100)),
        spark: samples.map((value) => maxSample > 0 ? Math.max(8, Math.round((value / maxSample) * 100)) : 8),
        ladder,
        blockers,
      }
    })
  const stageRail = phasePlan.map((phase, index) => {
    const state = phaseState?.[phase.name] || {}
    const percent = Number(state?.percent ?? 0)
    const status = String(state?.status || 'pending')
    const phaseName = String(phase?.name || `phase-${index + 1}`)
    const role = String(state?.role || phase?.role || '')
    const isCurrent = currentPhase === phaseName || (currentPhase === 'dumpcap/tshark' && phaseName === 'dumpcap/tshark')
    const visualState = status === 'completed'
      ? 'complete'
      : status === 'active' || isCurrent
        ? 'active'
        : status === 'error'
          ? 'error'
          : 'pending'
    return {
      id: phaseName,
      label: phaseName,
      shortLabel: phaseName.replace('-ng', '').replace('dumpcap/tshark', 'decode'),
      role,
      percent,
      status,
      visualState,
      seconds: Number(phase?.seconds || 0),
    }
  })
  const pulseChannels = Object.entries(channelStats)
    .map(([channel, stats]) => ({
      channel: Number(channel),
      frames: Number(stats?.frames || 0),
      visits: Number(stats?.visits || 0),
      hits: Number(stats?.hits || 0),
      bytes: 0,
      dataFrames: 0,
      imagePotential: 0,
    }))
    .filter((item) => item.frames > 0 || item.visits > 0)
    .sort((left, right) => right.frames - left.frames || right.visits - left.visits)
    .slice(0, 10)
    .map((item) => {
      const channelSignals = imageSignals.filter((entry) => entry.channel === item.channel)
      const bytes = channelSignals.reduce((sum, entry) => sum + entry.bytes, 0)
      const dataFrames = channelSignals.reduce((sum, entry) => sum + entry.dataFrames, 0)
      const imagePotential = channelSignals.length
        ? Math.max(...channelSignals.map((entry) => entry.score))
        : 0
      return {
        ...item,
        bytes,
        dataFrames,
        imagePotential,
      }
    })
  const strongestChannelFrames = Math.max(1, ...pulseChannels.map((item) => item.frames || 0))
  const strongestChannelBytes = Math.max(1, ...pulseChannels.map((item) => item.bytes || 0))
  const plan24 = Array.isArray(channels?.plan_24) ? channels.plan_24 : []
  const plan5 = Array.isArray(channels?.plan_5) ? channels.plan_5 : []
  const planAll = [...plan24, ...plan5]
  const radarBlips = pulseChannels.slice(0, 8).map((item, index) => {
    const planIndex = Math.max(0, planAll.indexOf(item.channel))
    const angle = planAll.length > 1 ? (planIndex / planAll.length) * Math.PI * 2 : (index / Math.max(1, pulseChannels.length)) * Math.PI * 2
    const strength = Math.max(0.24, item.frames / strongestChannelFrames)
    const radius = 18 + (54 * strength)
    return {
      ...item,
      strength,
      x: Math.cos(angle - (Math.PI / 2)) * radius,
      y: Math.sin(angle - (Math.PI / 2)) * radius,
    }
  })
  const livePulseCount = Math.max(
    4,
    Math.min(
      12,
      Math.round(
        (Number(processing?.queues?.decode || 0)
          + Number(processing?.queues?.flow || 0)
          + Number(processing?.queues?.detect || 0)
          + (status?.capture_active ? 2 : 0))
      ),
    ),
  )
  const imagePotentialPeak = Math.max(0, ...imageSignals.map((item) => item.score))
  const totalImageBytes = imageSignals.reduce((sum, item) => sum + item.bytes, 0)
  const totalImageDataFrames = imageSignals.reduce((sum, item) => sum + item.dataFrames, 0)
  const visibleProtocolPaths = imageSignals.filter((item) => item.protocolSignals.http > 0 || item.protocolSignals.rtsp > 0 || item.protocolSignals.tls > 0).length
  const imageRecoveryLevel = imagePotentialPeak >= 65
    ? 'HIGH'
    : imagePotentialPeak >= 38
      ? 'MEDIUM'
      : 'LOW'
  const imageRecoverySummary = imagePotentialPeak >= 65
    ? 'Observed media-path evidence and retained payload support a plausible image-recovery path.'
    : imagePotentialPeak >= 38
      ? 'Some real media-path evidence exists, but recovery still depends on stronger protocol or artifact yield.'
      : 'No real media-path evidence is retained yet; byte volume alone is not being treated as image recoverability.'
  const imageRecoveryReasons = [
    `${fmtBytes(totalImageBytes)} candidate traffic`,
    `${totalImageDataFrames} data frames`,
    `${visibleProtocolPaths} protocol-positive lead${visibleProtocolPaths === 1 ? '' : 's'}`,
    `${processing?.summary?.raw_eapol_frame_count ?? authEvidence?.debug?.raw_eapol_frame_count ?? 0} raw EAPOL`,
  ]
  const aggregateProtocol = {
    http: Math.max(0, ...imageSignals.map((item) => item.protocolSignals.http)),
    rtsp: Math.max(0, ...imageSignals.map((item) => item.protocolSignals.rtsp)),
    tls: Math.max(0, ...imageSignals.map((item) => item.protocolSignals.tls)),
    mdns: Math.max(0, ...imageSignals.map((item) => item.protocolSignals.mdns)),
    vendorWps: Math.max(0, ...imageSignals.map((item) => item.protocolSignals.vendorWps)),
  }
  const evidenceLadder = [
    buildEvidenceStage('Identity', Math.max(0, ...imageSignals.map((item) => item.identityScore)), `${imageSignals.length} scoped leads · WPS ${aggregateProtocol.vendorWps}`),
    buildEvidenceStage('Session Presence', Math.max(0, ...imageSignals.map((item) => item.continuityScore)), `${totalImageDataFrames} data frames across ${imageSignals.filter((item) => item.dataFrames > 0).length} leads`),
    buildEvidenceStage('Media Protocol Path', Math.max(aggregateProtocol.http, aggregateProtocol.rtsp, aggregateProtocol.tls, aggregateProtocol.mdns), `HTTP ${aggregateProtocol.http} · RTSP ${aggregateProtocol.rtsp} · TLS ${aggregateProtocol.tls}`),
    buildEvidenceStage('Payload Volume', Math.min(100, Math.log2(totalImageBytes + 1) * 6 + totalImageDataFrames * 2.2), `${fmtBytes(totalImageBytes)} retained candidate traffic`),
    buildEvidenceStage('Decryption State', Number(processing?.summary?.raw_eapol_frame_count ?? authEvidence?.debug?.raw_eapol_frame_count ?? 0) > 0 ? 72 : 0, `${processing?.summary?.raw_eapol_frame_count ?? authEvidence?.debug?.raw_eapol_frame_count ?? 0} raw EAPOL`),
    buildEvidenceStage('Artifact Yield', Math.min(100, imageSignals.reduce((sum, item) => sum + item.objectSignals, 0) * 18), `${imageSignals.reduce((sum, item) => sum + item.objectSignals, 0)} object/image hits`),
    buildEvidenceStage('Image Recoverability', imagePotentialPeak, imageRecoverySummary),
  ]
  const recoverabilityGauge = {
    label: imagePotentialPeak >= 75
      ? 'Image-Capable'
      : imagePotentialPeak >= 55
        ? 'Protocol Path'
        : imagePotentialPeak >= 35
          ? 'Payload'
          : 'Metadata',
    score: imagePotentialPeak,
  }
  const blockerCounts = new Map()
  for (const lead of topRecoverableLeads) {
    for (const blocker of lead.blockers || []) blockerCounts.set(blocker, (blockerCounts.get(blocker) || 0) + 1)
  }
  const recoveryBlockers = [...blockerCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
    .map(([label, count]) => ({ label, count }))
  const mediaPathMatrix = topRecoverableLeads.map((lead) => ({
    id: lead.id,
    label: lead.label,
    cells: [
      { label: 'Identity', score: lead.ladder[0]?.score ?? 0 },
      { label: 'Continuity', score: lead.continuity ?? 0 },
      { label: 'HTTP', score: clampPercent(lead.httpScore) },
      { label: 'RTSP', score: clampPercent(lead.rtspScore) },
      { label: 'TLS', score: clampPercent(lead.tlsScore) },
      { label: 'Decrypt', score: clampPercent(lead.decryptScore) },
      { label: 'Objects', score: clampPercent(lead.objectScore) },
      { label: 'Image', score: clampPercent(lead.score) },
    ],
  }))

  const steps = cameraHuntMode
    ? [
        `Sensor control: iw retunes the monitor interfaces to channel ${currentChannel}.`,
        'Capture: dumpcap records short per-channel pcapng slices from the monitor interfaces.',
        `Decode: tshark parses 802.11 frames, RSSI, retries,${handshakeAnalysisEnabled ? ' passive EAPOL handshake activity,' : ''} WPS hints, DHCP, DNS, mDNS, HTTP, RTSP, and TLS SNI when visible.`,
        'Enrichment: retained PCAP slices are enriched by tshark identity extraction and Zeek protocol/service analysis when available.',
        'Inventory: the tracker builds per-lead service inventory plus split protocol confidence for mDNS/DNS, HTTP, TLS, RTSP, and vendor/WPS evidence.',
        'Additive collectors: airodump-ng, Kismet, and Bettercap contribute RF discovery, device intelligence, and live recon events when active.',
        'Analysis: Camera Hunt 2.0 fuses behavior, protocol inventory, vendor signatures, external-tool matches, and retained service evidence into scored camera leads.',
      ]
    : [
        `Sensor control: iw retunes the monitor interfaces to channel ${currentChannel}.`,
        'Capture: dumpcap records short per-channel pcapng slices from the monitor interfaces.',
        `Decode: tshark parses 802.11 frame metadata,${handshakeAnalysisEnabled ? ' passive EAPOL handshake activity,' : ''} and visible protocol/service hints.`,
        'Additive collectors: airodump-ng, Kismet, and Bettercap run in phased MK7AC recon mode when Start Session uses the staged pipeline.',
        'Analysis: the WiFi MK7 parser, device tracker, pipeline controller, and intelligence engine classify WiFi networks, clients, and camera candidates.',
      ]

  return {
    workflowLabel: cameraHuntMode ? 'Camera Hunt Backend Activity' : 'WiFi Recon Backend Activity',
    summaryTitle: cameraHuntMode ? 'Camera Hunt Backend Activity Summary' : 'WiFi Recon Backend Activity Summary',
    detectionLabel: cameraHuntMode ? 'Camera Lead Detection' : 'WiFi Device Detection',
    mode,
    currentChannel,
    interfaces,
    hotChannels,
    steps,
    activeTools,
    runtimeApps,
    runtimeSummary: {
      activeCount: Number(runtimeSummary?.active_count || 0),
      allStopped: Boolean(runtimeSummary?.all_stopped),
      cleanupState: runtimeSummary?.cleanup_state || 'idle',
      summary: Boolean(runtimeSummary?.all_stopped)
        ? 'All scan collectors and decode workers are stopped.'
        : (activeTools.length
          ? `Runtime still active: ${activeTools.join(', ')}`
          : 'Backend is draining post-scan work.'),
    },
    availableExternal,
    topology: phasedTopology
      ? [
        `MK7AC ${status?.adapter?.monitor_interface || '--'}`,
        phasedTopology,
        'Core Stages: dumpcap -> tshark parse -> Zeek/tshark enrichment -> tracker inventory -> camera scoring',
        `Current Phase: ${pipeline?.current_phase || 'idle'}`,
      ]
      : topology,
    processingTopology,
    queueSummary,
    stageCounts,
    detectionSummary,
    authEvidenceSummary: `${authEvidence?.quality_counts?.CONFIRMED ?? 0} confirmed · ${authEvidence?.quality_counts?.LIKELY ?? 0} likely · ${authEvidence?.quality_counts?.PARTIAL ?? 0} partial`,
    passiveEventSummary,
    rawEvidenceSummary,
    coverageConfidenceLevel: coverageConfidence?.level || processing?.summary?.coverage_confidence_level || 'WEAK',
    coverageConfidenceSummary: coverageConfidence?.summary || processing?.summary?.coverage_confidence_summary || 'Weak coverage; zero evidence is not conclusive.',
    toolProgress,
    currentPhase,
    stageRail,
    pulseChannels,
    radarBlips,
    livePulseCount,
    strongestChannelBytes,
    evidenceLadder,
    recoverabilityGauge,
    topRecoverableLeads,
    recoveryBlockers,
    mediaPathMatrix,
    imageRecovery: {
      score: imagePotentialPeak,
      level: imageRecoveryLevel,
      summary: imageRecoverySummary,
      reasons: imageRecoveryReasons,
      totalBytes: totalImageBytes,
      totalDataFrames: totalImageDataFrames,
      visibleProtocolPaths,
    },
    hasPhasedPipeline,
    summary: hasPhasedPipeline ? (pipeline.summary || toolchain.summary || '') : (cameraHuntMode ? (pipeline.summary || toolchain.summary || '') : (toolchain.summary || '')),
  }
}

function hasActiveRuntimeTools(status) {
  const toolchain = status?.toolchain || {}
  const sensorTools = toolchain.sensor_control || []
  const packetTools = toolchain.packet_capture || []
  const externalTools = toolchain.external_tools || []
  const processing = toolchain.processing_pipeline || status?.processing_pipeline || {}
  return [...sensorTools, ...packetTools, ...externalTools].some((tool) => Boolean(tool?.active)) || Boolean(processing?.running)
}

export default function WifiMk7View({ onPivot, cameraOnly = false }) {
  const mode = 'RED'
  const workspaceKey = cameraOnly ? 'CAMERA-HUNT' : 'WIFI-MK7'
  const { isPanelVisible } = usePanelPreferences(workspaceKey)
  const { features } = useWiFiMk7FeaturePreferences()
  const [status, setStatus] = useState(null)
  const [networks, setNetworks] = useState([])
  const [clients, setClients] = useState([])
  const [pcaps, setPcaps] = useState([])
  const [channels, setChannels] = useState(null)
  const [busy, setBusy] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const [error, setError] = useState('')
  const [operatorNote, setOperatorNote] = useState('')
  const [dwellMs, setDwellMs] = useState(500)
  const [bandMode, setBandMode] = useState('both')
  const [scanMode, setScanMode] = useState('broad')
  const [scanDurationSeconds, setScanDurationSeconds] = useState(DEFAULT_SCAN_DURATION_SECONDS)
  const [scanScenario, setScanScenario] = useState('passive_observation')
  const [lockedChannel, setLockedChannel] = useState('')
  const [sensorScope, setSensorScope] = useState('all')
  const [selectedNetworkId, setSelectedNetworkId] = useState('')
  const [selectedNetworkSnapshot, setSelectedNetworkSnapshot] = useState(null)
  const [focusedBssid, setFocusedBssid] = useState('')
  const [expandedNetworks, setExpandedNetworks] = useState({})
  const [clientAttributionFilter, setClientAttributionFilter] = useState('strong')
  const [redLeadScope, setRedLeadScope] = useState('all')
  const [cameraHuntMode, setCameraHuntMode] = useState(Boolean(cameraOnly))
  const [selectedDetailTab, setSelectedDetailTab] = useState('core')
  const [cameraHuntResults, setCameraHuntResults] = useState({ leads: [], pipeline: { active_collectors: [], available_collectors: [] } })
  const [importedCapturePath, setImportedCapturePath] = useState('')
  const [importedAnalysis, setImportedAnalysis] = useState(null)
  const [importBusy, setImportBusy] = useState(false)
  const [adversaryReplayState, setAdversaryReplayState] = useState({ state: 'IDLE', last_run: {} })
  const [adversaryReplayBusy, setAdversaryReplayBusy] = useState(false)
  const [adversaryReplayLabel, setAdversaryReplayLabel] = useState('')
  const [adversaryReplayAuthorized, setAdversaryReplayAuthorized] = useState(false)
  const [adversaryReplayReset, setAdversaryReplayReset] = useState(true)
  const [cameraLeadAnalysis, setCameraLeadAnalysis] = useState(null)
  const [cameraLeadAnalysisBusy, setCameraLeadAnalysisBusy] = useState(false)
  const [cameraLeadProbe, setCameraLeadProbe] = useState(null)
  const [cameraLeadProbeBusy, setCameraLeadProbeBusy] = useState(false)
  const [cameraLeadHardAudit, setCameraLeadHardAudit] = useState(null)
  const [cameraLeadHardAuditBusy, setCameraLeadHardAuditBusy] = useState(false)
  const [cameraLeadVideoTruthBusy, setCameraLeadVideoTruthBusy] = useState(false)
  const [cameraLeadLayerAudit, setCameraLeadLayerAudit] = useState(null)
  const [cameraLeadLayerAuditBusy, setCameraLeadLayerAuditBusy] = useState(false)
  const [hardAuditStartedAtMs, setHardAuditStartedAtMs] = useState(0)
  const [hardAuditTimerNowMs, setHardAuditTimerNowMs] = useState(0)
  const [cameraAssessmentConfirmPrompt, setCameraAssessmentConfirmPrompt] = useState(false)
  const [cameraHuntRunStarted, setCameraHuntRunStarted] = useState(Boolean(cameraOnly))
  const [serviceAudit, setServiceAudit] = useState(null)
  const [serviceAuditBusy, setServiceAuditBusy] = useState(false)
  const [redTeamState, setRedTeamState] = useState({ state: 'IDLE', last_run: {}, last_preflight: {} })
  const [redTeamBusy, setRedTeamBusy] = useState(false)
  const [redTeamForm, setRedTeamForm] = useState({
    actionType: 'deauth_evidence_probe',
    confirmAuthorizedLab: false,
    targetSsid: '',
    bssid: '',
    clientMac: '',
    channel: '',
    maxDuration: 30,
    maxFrameCount: 3,
    reasonCode: '7',
    notes: '',
  })
  const [manualProbeIp, setManualProbeIp] = useState('')
  const selectedNetworkRef = useRef(null)
  const cameraHuntPollTickRef = useRef(0)
  const refreshInFlightRef = useRef(false)
  const serviceAuditProgressTimerRef = useRef(null)
  const showRankingPanel = isPanelVisible('ranking') && !cameraHuntMode
  const showPacketTruthPanel = isPanelVisible('packetTruth')
  const showClientsPanel = isPanelVisible('clients') && !cameraHuntMode
  const hardAuditActive = cameraHuntMode && (cameraLeadHardAuditBusy || cameraLeadVideoTruthBusy || cameraLeadLayerAuditBusy)
  const hardAuditTimer = getHardAuditTimerSnapshot(hardAuditStartedAtMs, hardAuditTimerNowMs, hardAuditActive)

  const bandSelection = bandMode === '24' ? ['2.4ghz'] : bandMode === '5' ? ['5ghz'] : ['2.4ghz', '5ghz']
  const availableSensorInterfaces = useMemo(() => {
    const sensors = status?.adapter?.sensors || []
    return sensors.map((sensor) => sensor.base_interface).filter(Boolean)
  }, [status?.adapter?.sensors])
  const selectedInterfaces = sensorScope === 'all' ? availableSensorInterfaces : sensorScope ? [sensorScope] : []
  const lockChannelOptions = useMemo(() => buildLockChannelOptions(channels || status?.channels), [channels, status?.channels])
  const sortedNetworks = useMemo(() => sortNetworks(networks, mode), [networks, mode])
  const confirmedNetworks = useMemo(() => sortedNetworks.filter((network) => !network.synthetic_identity), [sortedNetworks])
  const probableNetworks = useMemo(() => sortedNetworks.filter((network) => network.synthetic_identity), [sortedNetworks])
  const displayedNetworks = useMemo(
    () => (redLeadScope === 'all' ? sortedNetworks : confirmedNetworks),
    [redLeadScope, sortedNetworks, confirmedNetworks],
  )
  const wifiDeviceInventory = useMemo(
    () => (cameraHuntMode ? [] : buildWiFiDeviceInventory(displayedNetworks, clients)),
    [cameraHuntMode, displayedNetworks, clients],
  )
  const cameraCandidateNetworks = useMemo(
    () => sortedNetworks.filter((network) => isStrongCameraCandidate(network)),
    [sortedNetworks],
  )
  const cameraCandidateClients = useMemo(
    () => clients.filter((client) => isStrongCameraCandidate(client)),
    [clients],
  )
  const fusedCameraNetworks = useMemo(
    () => (cameraHuntResults?.leads || []).filter((item) => item?.leadKind !== 'client'),
    [cameraHuntResults],
  )
  const fusedCameraClients = useMemo(
    () => (cameraHuntResults?.leads || []).filter((item) => item?.leadKind === 'client'),
    [cameraHuntResults],
  )
  const retainedCameraLeads = useMemo(
    () => (cameraHuntResults?.leads || []).filter((item) => shouldDisplayCameraLead(item)),
    [cameraHuntResults],
  )
  const filteredBackendNearMisses = useMemo(
    () => (cameraHuntResults?.near_misses || []).filter((item) => shouldDisplayCameraNearMiss(item)),
    [cameraHuntResults],
  )
  const possibleCloudCameraLeads = useMemo(
    () => (cameraHuntResults?.possible_cloud_cameras || []).filter((item) => item?.cloud_camera_evidence?.bucket === 'possible_cloud_camera'),
    [cameraHuntResults],
  )
  const fallbackCameraLeads = useMemo(
    () => buildCameraLeads(sortedNetworks, clients, mode),
    [sortedNetworks, clients, mode],
  )
  const cameraLeads = useMemo(
    () => {
      if (!cameraHuntMode) return fallbackCameraLeads
      const merged = []
      const seen = new Set()
      for (const item of [...retainedCameraLeads, ...possibleCloudCameraLeads]) {
        const key = getEntitySelectionId(item, true)
        if (!key || seen.has(key)) continue
        seen.add(key)
        merged.push(item)
      }
      return [...merged].sort((left, right) => {
        const retainedDelta = Number(Boolean(right?.camera_detection?.retained)) - Number(Boolean(left?.camera_detection?.retained))
        if (retainedDelta) return retainedDelta
        const possibleCloudDelta = Number(right?.cloud_camera_evidence?.bucket === 'possible_cloud_camera') - Number(left?.cloud_camera_evidence?.bucket === 'possible_cloud_camera')
        if (possibleCloudDelta) return possibleCloudDelta
        const actionabilityDelta = getCameraActionabilityScore(right, mode) - getCameraActionabilityScore(left, mode)
        if (actionabilityDelta) return actionabilityDelta
        return getOperationalTargetScore(right, mode) - getOperationalTargetScore(left, mode)
      })
    },
    [cameraHuntMode, mode, retainedCameraLeads, possibleCloudCameraLeads, fallbackCameraLeads],
  )
  const cameraNearMisses = useMemo(
    () => (cameraHuntMode
      ? [...filteredBackendNearMisses]
        .sort((left, right) => getCameraActionabilityScore(right, mode) - getCameraActionabilityScore(left, mode))
      : []),
    [cameraHuntMode, filteredBackendNearMisses, mode],
  )
  const usingFallbackCameraLeads = cameraHuntMode && !retainedCameraLeads.length && !possibleCloudCameraLeads.length
  const fallbackSource = filteredBackendNearMisses.length ? 'near_misses' : 'none'
  const visibleNetworks = useMemo(
    () => (cameraHuntMode ? cameraCandidateNetworks : displayedNetworks),
    [cameraHuntMode, cameraCandidateNetworks, displayedNetworks],
  )
  const familySummary = useMemo(
    () => (showRankingPanel ? buildFamilySummary(confirmedNetworks) : []),
    [showRankingPanel, confirmedNetworks],
  )
  const selectedNetwork = useMemo(() => {
    if (!selectedNetworkId) return null
    if (cameraHuntMode) {
      const resolvedLead = cameraLeads.find((item) => getEntitySelectionId(item, true) === selectedNetworkId)
      if (resolvedLead) return resolvedLead
      const resolvedPossibleCloud = possibleCloudCameraLeads.find((item) => getEntitySelectionId(item, true) === selectedNetworkId)
      if (resolvedPossibleCloud) return resolvedPossibleCloud
      const resolvedNearMiss = cameraNearMisses.find((item) => getEntitySelectionId(item, true) === selectedNetworkId)
      if (resolvedNearMiss) return resolvedNearMiss
    }
    if (!cameraHuntMode) {
      const resolvedDevice = wifiDeviceInventory.find((item) => getEntitySelectionId(item, false) === selectedNetworkId)
      if (resolvedDevice) return resolvedDevice
    }
    const resolved = sortedNetworks.find((network) => getNetworkId(network) === selectedNetworkId)
    if (resolved) return resolved
    if (getEntitySelectionId(selectedNetworkSnapshot, cameraHuntMode) === selectedNetworkId) return selectedNetworkSnapshot
    return null
  }, [cameraHuntMode, cameraLeads, possibleCloudCameraLeads, cameraNearMisses, wifiDeviceInventory, sortedNetworks, selectedNetworkId, selectedNetworkSnapshot])
  const displaySelectedNetwork = useMemo(() => {
    if (!selectedNetwork || !cameraHuntMode) return selectedNetwork
    const leadId = getCameraLeadId(selectedNetwork)
    const withHardAudit = withCameraHardAudit(
      selectedNetwork,
      cameraLeadHardAudit?.lead_id === leadId ? cameraLeadHardAudit?.hard_audit : null,
    )
    return withCameraLayerAudit(
      withHardAudit,
      cameraLeadLayerAudit?.lead_id === leadId ? cameraLeadLayerAudit?.layer_audit : null,
    )
  }, [selectedNetwork, cameraHuntMode, cameraLeadHardAudit, cameraLeadLayerAudit])
  const inspectedNetwork = cameraHuntMode ? (displaySelectedNetwork || selectedNetwork) : selectedNetwork
  const showSelectedNetworkPanel = cameraHuntMode ? !!inspectedNetwork : (isPanelVisible('selectedNetwork') || !!inspectedNetwork)
  const cameraAttackAudit = useMemo(() => {
    if (!cameraHuntMode || !selectedNetwork) return null
    const targetId = getRedTeamTargetId(selectedNetwork, true)
    const serviceTargetId = String(serviceAudit?.target_id || '').trim().toLowerCase()
    return serviceTargetId && serviceTargetId === targetId ? serviceAudit : null
  }, [cameraHuntMode, selectedNetwork, serviceAudit])
  const cameraAttackAssessment = useMemo(
    () => (cameraHuntMode && inspectedNetwork ? buildCameraAttackAssessment(inspectedNetwork, cameraAttackAudit, adversaryReplayState?.last_run) : null),
    [cameraHuntMode, inspectedNetwork, cameraAttackAudit, adversaryReplayState?.last_run],
  )
  const relatedClients = useMemo(() => {
    const baseClients = focusedBssid ? clients.filter((client) => client.associated_bssid === focusedBssid) : clients
    if (!cameraHuntMode) return baseClients
    return baseClients.filter((client) => isStrongCameraCandidate(client))
  }, [clients, focusedBssid, cameraHuntMode])

  const networkClientMap = useMemo(() => {
    if (cameraHuntMode || (!showPacketTruthPanel && !showClientsPanel && !selectedNetworkId)) return {}
    const entries = {}
    for (const network of sortedNetworks) {
      entries[getNetworkId(network)] = getRelatedClientsForNetwork(network, clients, clientAttributionFilter)
    }
    return entries
  }, [cameraHuntMode, showPacketTruthPanel, showClientsPanel, selectedNetworkId, sortedNetworks, clients, clientAttributionFilter])
  const missionRankings = useMemo(
    () => {
      if (cameraHuntMode) return cameraLeads.slice(0, 6)
      if (!showRankingPanel) return []
      return buildMissionRankings(sortedNetworks, mode)
    },
    [cameraHuntMode, cameraLeads, showRankingPanel, sortedNetworks, mode],
  )
  const environmentMap = useMemo(() => buildEnvironmentMap(confirmedNetworks, channels || status?.channels), [confirmedNetworks, channels, status?.channels])
  const vendorRiskSummary = useMemo(
    () => (showRankingPanel ? buildVendorRiskSummary(confirmedNetworks, clients) : []),
    [showRankingPanel, confirmedNetworks, clients],
  )
  const anomalyLeads = useMemo(
    () => (showRankingPanel ? buildAnomalyLeads(confirmedNetworks, clients) : []),
    [showRankingPanel, confirmedNetworks, clients],
  )
  const clientClusters = useMemo(
    () => (showRankingPanel ? buildClientClusters(clients) : []),
    [showRankingPanel, clients],
  )
  const attackableTargets = useMemo(
    () => (cameraHuntMode ? buildCameraAttackableTargets(cameraLeads, sortedNetworks, mode) : buildAttackableTargets(sortedNetworks)),
    [cameraHuntMode, cameraLeads, sortedNetworks, mode],
  )
  const handshakeAnalysisEnabled = !!features.handshakeAnalysis
  const offlineEvidencePolicy = status?.feature_flags?.offlineEvidenceAnalysis || {}
  const offlineEvidenceEnabled = !!offlineEvidencePolicy.enabled && !!features.offlineEvidenceAnalysis
  const processingSummary = status?.processing_pipeline?.summary || {}
  const authEvidence = status?.authentication_evidence || { quality_counts: {}, sessions: [] }
  const redTeamActionProfile = useMemo(() => getRedTeamActionProfile(redTeamForm.actionType), [redTeamForm.actionType])
  const redTeamEvidenceIndicator = useMemo(
    () => buildRedTeamEvidenceIndicator(redTeamForm.actionType, redTeamState?.last_run),
    [redTeamForm.actionType, redTeamState?.last_run],
  )
  const preferredReplayPcap = useMemo(() => {
    if (!pcaps.length) return null
    const ranked = [...pcaps]
      .filter((item) => String(item?.path || '').trim())
      .sort((left, right) => {
        const leftReplayArtifact = String(left?.path || '').includes('/adversary_replay/')
        const rightReplayArtifact = String(right?.path || '').includes('/adversary_replay/')
        if (leftReplayArtifact !== rightReplayArtifact) return Number(leftReplayArtifact) - Number(rightReplayArtifact)
        const capturedDelta = Number(right?.captured_at || 0) - Number(left?.captured_at || 0)
        if (capturedDelta) return capturedDelta
        return String(right?.path || '').localeCompare(String(left?.path || ''))
      })
    return ranked[0] || null
  }, [pcaps])
  const effectiveReplayCapturePath = useMemo(
    () => String(importedCapturePath || preferredReplayPcap?.path || '').trim(),
    [importedCapturePath, preferredReplayPcap],
  )
  const selectedReplayPcap = useMemo(() => {
    const currentPath = effectiveReplayCapturePath
    if (!currentPath) return preferredReplayPcap
    return pcaps.find((item) => String(item?.path || '').trim() === currentPath) || preferredReplayPcap || { path: currentPath }
  }, [effectiveReplayCapturePath, pcaps, preferredReplayPcap])
  const redTeamPcapLoaded = !!effectiveReplayCapturePath
  const redTeamPcapSourceLabel = selectedReplayPcap?.path
    ? (String(selectedReplayPcap.path).trim() === String(preferredReplayPcap?.path || '').trim() ? 'retained mk7 capture' : 'manual operator path')
    : 'none selected'
  const redTeamRunBlockers = useMemo(() => {
    if (cameraHuntMode) {
      return [
        !redTeamForm.confirmAuthorizedLab ? 'Confirm owned-lab camera/device scope.' : '',
        !selectedNetwork ? 'Select a retained camera lead.' : '',
      ].filter(Boolean)
    }
    return [
      !redTeamForm.confirmAuthorizedLab ? 'Confirm this is your owned lab network/device.' : '',
      !selectedNetwork ? 'Select a retained WiFi target.' : '',
      !status?.capture_active ? 'Start WiFi MK7 live capture.' : '',
    ].filter(Boolean)
  }, [cameraHuntMode, redTeamForm.confirmAuthorizedLab, selectedNetwork, status?.capture_active])
  const redTeamCanRun = redTeamRunBlockers.length === 0
  const backendStatus = useMemo(
    () => (cameraHuntMode
      ? { ...(status || {}), camera_hunt_pipeline: cameraHuntResults?.pipeline || status?.camera_hunt_pipeline || {} }
      : status),
    [status, cameraHuntMode, cameraHuntResults?.pipeline],
  )
  const backendActivity = useMemo(
    () => buildBackendActivity(
      backendStatus,
      cameraHuntMode,
      handshakeAnalysisEnabled,
      sortedNetworks,
      clients,
    ),
    [backendStatus, cameraHuntMode, handshakeAnalysisEnabled, sortedNetworks, clients],
  )
  const handshakeEvidence = useMemo(
    () => authEvidence?.sessions || [],
    [authEvidence],
  )
  const handshakeSummary = useMemo(
    () => buildHandshakeSummary(authEvidence),
    [authEvidence],
  )
  const passwordRiskTargets = useMemo(
    () => buildPasswordRiskTargets(sortedNetworks),
    [sortedNetworks],
  )
  const evidenceQueue = useMemo(
    () => buildEvidenceQueue(authEvidence?.sessions || [], sortedNetworks),
    [authEvidence, sortedNetworks],
  )
  const coverageRows = useMemo(
    () => (cameraHuntMode ? [] : buildCoverageRows(sortedNetworks, authEvidence?.sessions || [])),
    [cameraHuntMode, sortedNetworks, authEvidence],
  )
  const coverageMap = useMemo(
    () => (cameraHuntMode ? new Map() : buildCoverageMap(coverageRows)),
    [cameraHuntMode, coverageRows],
  )
  const operatorSummary = useMemo(
    () => (showPacketTruthPanel ? buildOperatorSummary(visibleNetworks, coverageRows, handshakeSummary) : []),
    [showPacketTruthPanel, visibleNetworks, coverageRows, handshakeSummary],
  )

  useEffect(() => {
    if (cameraOnly) {
      setCameraHuntMode(true)
    }
  }, [cameraOnly])

  useEffect(() => {
    setSelectedDetailTab('core')
  }, [selectedNetworkId, cameraHuntMode])

  useEffect(() => {
    setCameraLeadAnalysis(null)
  }, [selectedNetworkId, cameraHuntMode])

  useEffect(() => {
    setCameraLeadProbe(null)
  }, [selectedNetworkId, cameraHuntMode])

  useEffect(() => {
    setCameraLeadHardAudit(null)
  }, [selectedNetworkId, cameraHuntMode])

  useEffect(() => {
    setCameraLeadLayerAudit(null)
  }, [selectedNetworkId, cameraHuntMode])

  useEffect(() => {
    if (!cameraHuntMode || !selectedNetworkId) return
    const liveLead = (cameraHuntResults?.leads || []).find((item) => getEntitySelectionId(item, true) === selectedNetworkId)
    if (!liveLead) return
    const leadId = getCameraLeadId(liveLead)
    if ((cameraLeadHardAuditBusy || cameraLeadVideoTruthBusy) && liveLead?.hard_audit) {
      setCameraLeadHardAudit({ lead_id: leadId, hard_audit: liveLead.hard_audit })
    }
    if ((cameraLeadLayerAuditBusy || cameraLeadVideoTruthBusy) && liveLead?.hard_audit?.layer_audit) {
      setCameraLeadLayerAudit({ lead_id: leadId, layer_audit: liveLead.hard_audit.layer_audit })
    }
    if ((cameraLeadProbeBusy || cameraLeadHardAuditBusy || cameraLeadVideoTruthBusy) && liveLead?.active_fingerprint) {
      setCameraLeadProbe({ lead_id: leadId, active_fingerprint: liveLead.active_fingerprint })
    }
  }, [
    cameraHuntResults,
    cameraHuntMode,
    selectedNetworkId,
    cameraLeadHardAuditBusy,
    cameraLeadLayerAuditBusy,
    cameraLeadProbeBusy,
    cameraLeadVideoTruthBusy,
  ])

  useEffect(() => {
    setCameraAssessmentConfirmPrompt(false)
  }, [selectedNetworkId, cameraHuntMode])

  useEffect(() => {
    setServiceAudit(null)
  }, [selectedNetworkId, cameraHuntMode])

  useEffect(() => {
    setManualProbeIp('')
  }, [selectedNetworkId, cameraHuntMode])

  useEffect(() => {
    if (cameraHuntMode || !selectedNetwork) return
    setRedTeamForm((current) => ({
      ...current,
      targetSsid: String(selectedNetwork.ssid || current.targetSsid || ''),
      bssid: String(selectedNetwork.bssid || current.bssid || ''),
      clientMac: String(selectedNetwork.mac || current.clientMac || ''),
      channel: selectedNetwork.channel ? String(selectedNetwork.channel) : current.channel,
    }))
  }, [selectedNetwork, cameraHuntMode])

  useEffect(() => {
    if (importedCapturePath.trim()) return
    if (!preferredReplayPcap?.path) return
    setImportedCapturePath(String(preferredReplayPcap.path))
  }, [importedCapturePath, preferredReplayPcap])

  function applyOperatorSnapshot(snapshot, { includeData = true, includeRedTeam = false } = {}) {
    const nextStatus = snapshot?.status || {}
    const nextChannels = snapshot?.channels || {}
    setStatus(nextStatus)
    setChannels(nextChannels)
    setError(nextStatus?.last_error || '')
    if (includeData) {
      setNetworks(snapshot?.networks || [])
      setClients(snapshot?.clients || [])
      setPcaps(snapshot?.pcaps || [])
      setCameraHuntResults({ leads: [], pipeline: {} })
    }
    if (includeRedTeam) {
      setRedTeamState(snapshot?.redteam || { state: 'IDLE', last_run: {}, last_preflight: {} })
      setAdversaryReplayState(snapshot?.adversary_replay || { state: 'IDLE', last_run: {} })
    }
  }

  async function refresh({ prepare = false, includeData = true, lightStatus = false, forceFullData = false } = {}) {
    if (lightStatus && cameraHuntMode) {
      const [huntStatus, nextChannels] = await Promise.all([
        fetchWiFiMk7CameraHuntStatus(),
        fetchWiFiMk7ChannelsLight(),
      ])
      const nextStatus = huntStatus?.status || {}
      setStatus((current) => ({ ...(current || {}), ...nextStatus }))
      setChannels(nextChannels)
      setError(nextStatus?.last_error || '')
      return
    }

    if (!cameraHuntMode) {
      const includeRedTeam = forceFullData || selectedDetailTab === 'redteam'
      const snapshot = await fetchWiFiMk7OperatorSnapshot({
        prepare,
        light: lightStatus,
        includeData,
        includeRedTeam,
      })
      applyOperatorSnapshot(snapshot, { includeData, includeRedTeam })
      return
    }

    const requests = [
      fetchWiFiMk7Status(prepare, lightStatus),
      lightStatus ? fetchWiFiMk7ChannelsLight() : fetchWiFiMk7Channels(),
    ]
    const cameraMode = cameraHuntMode
    const cameraLeanData = cameraMode && includeData && !forceFullData
    if (includeData) {
      if (cameraLeanData) {
        requests.push(fetchWiFiMk7Pcap(), fetchWiFiMk7CameraHuntResults())
      } else {
        requests.push(fetchWiFiMk7Networks(), fetchWiFiMk7Clients(), fetchWiFiMk7Pcap())
        if (cameraMode) {
          requests.push(fetchWiFiMk7CameraHuntResults())
        }
      }
    }
    const results = await Promise.all(requests)
    const nextStatus = results[0]
    const nextChannels = results[1]
    setStatus(nextStatus)
    setChannels(nextChannels)
    setError(nextStatus?.last_error || '')

    if (includeData) {
      if (cameraLeanData) {
        const nextPcaps = results[2]?.pcaps || []
        setPcaps(nextPcaps)
        setCameraHuntResults(results[3] || { leads: [], pipeline: {} })
      } else {
        const nextNetworks = results[2]?.networks || []
        const nextClients = results[3]?.clients || []
        const nextPcaps = results[4]?.pcaps || []
        setNetworks(nextNetworks)
        setClients(nextClients)
        setPcaps(nextPcaps)
        if (cameraMode) {
          setCameraHuntResults(results[5] || { leads: [], pipeline: {} })
        } else {
          setCameraHuntResults({ leads: [], pipeline: {} })
        }
      }
    }
  }

  async function handleImportedAnalysis(replay = false) {
    if (!offlineEvidencePolicy.enabled) {
      setError(offlineEvidencePolicy.warning || 'Offline authentication-evidence analysis is disabled by project configuration.')
      return
    }
    if (!features.offlineEvidenceAnalysis) {
      setOperatorNote('Offline capture replay is disabled for public v1. Use live WiFi MK7 capture for validation.')
      return
    }
    if (!importedCapturePath.trim()) {
      setOperatorNote('Provide an approved .pcap or .pcapng path for offline analysis.')
      return
    }
    setImportBusy(true)
    setError('')
    try {
      const result = await runWiFiMk7ImportedAnalysis({ capturePath: importedCapturePath.trim(), replay })
      setImportedAnalysis(result)
      if (result?.ok) {
        setOperatorNote(`Imported analysis complete for ${result.path}`)
      } else {
        setError(result?.error || 'Imported analysis failed.')
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setImportBusy(false)
    }
  }

  async function handleAdversaryReplay() {
    if (!offlineEvidencePolicy.enabled) {
      setError(offlineEvidencePolicy.warning || 'Offline adversary replay is disabled by project configuration.')
      return
    }
    if (!effectiveReplayCapturePath) {
      setOperatorNote('Provide an approved .pcap or .pcapng path for adversary replay.')
      return
    }
    setAdversaryReplayBusy(true)
    setError('')
    try {
      const result = await runWiFiMk7AdversaryReplay({
        capturePath: effectiveReplayCapturePath,
        confirmAuthorizedLab: adversaryReplayAuthorized,
        replayLabel: adversaryReplayLabel.trim(),
        resetBeforeReplay: adversaryReplayReset,
      })
      setAdversaryReplayState(result || { state: 'FAILED_PARSE', last_run: {} })
      if (result?.ok) {
        await refresh({ prepare: false, includeData: true, forceFullData: true })
        setOperatorNote(result?.message || 'Adversary replay completed.')
      } else {
        setOperatorNote(result?.error || result?.message || `Adversary replay blocked: ${result?.state || 'unknown state'}`)
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setAdversaryReplayBusy(false)
    }
  }

  async function runReplayBackedRedTeamWorkflow({
    replayLabel,
    noteOnSuccess,
    noteOnBlocked,
  } = {}) {
    if (!effectiveReplayCapturePath) {
      setOperatorNote('Offline capture replay is disabled for public v1. Use live WiFi MK7 capture for this workflow.')
      return false
    }
    const result = await runWiFiMk7AdversaryReplay({
      capturePath: effectiveReplayCapturePath,
      confirmAuthorizedLab: redTeamForm.confirmAuthorizedLab,
      replayLabel: replayLabel || adversaryReplayLabel.trim(),
      resetBeforeReplay: adversaryReplayReset,
    })
    setAdversaryReplayState(result || { state: 'FAILED_PARSE', last_run: {} })
    if (result?.ok) {
      await refresh({ prepare: false, includeData: true, forceFullData: true })
      setOperatorNote(result?.message || noteOnSuccess || 'Replay-backed red-team evidence completed.')
      return true
    }
    setOperatorNote(result?.error || result?.message || noteOnBlocked || `Replay-backed red-team workflow blocked: ${result?.state || 'unknown state'}`)
    return false
  }

  async function handleReplayLoadedRedTeamPcap() {
    setAdversaryReplayAuthorized(redTeamForm.confirmAuthorizedLab)
    setAdversaryReplayLabel((current) => current || `${selectedNetwork?.ssid || selectedNetwork?.mac || selectedNetwork?.bssid || 'wifi-target'} redteam replay`)
    setSelectedDetailTab('redteam')
    setAdversaryReplayBusy(true)
    setError('')
    try {
      await runReplayBackedRedTeamWorkflow({
        replayLabel: adversaryReplayLabel.trim() || `${selectedNetwork?.ssid || selectedNetwork?.mac || selectedNetwork?.bssid || 'wifi-target'} redteam replay`,
        noteOnSuccess: 'Replay-backed red-team evidence completed.',
        noteOnBlocked: 'Replay-backed red-team workflow blocked.',
      })
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setAdversaryReplayBusy(false)
    }
  }

  async function handleAnalyzeCameraLead() {
    if (cameraLeadInteractionLocked) {
      setOperatorNote('Camera Hunt is still running. Wait for Camera Hunt Complete before opening a lead.')
      return
    }
    if (!cameraHuntMode || !selectedNetwork) {
      setOperatorNote('Select a retained camera lead first.')
      return
    }
    const leadId = getCameraLeadId(selectedNetwork)
    if (!leadId) {
      setError('Selected camera lead is missing a stable identifier.')
      return
    }
    setCameraLeadAnalysisBusy(true)
    setError('')
    try {
      const result = await analyzeWiFiMk7CameraLead({ leadId, seconds: 30 })
      setCameraLeadAnalysis(result)
      if (result?.ok) {
        setSelectedDetailTab('analysis')
        setOperatorNote(result?.observation_status || 'Camera lead analysis complete.')
      } else {
        setError(result?.error || 'Camera lead analysis failed.')
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setCameraLeadAnalysisBusy(false)
    }
  }

  async function handleProbeCameraLead() {
    if (cameraLeadInteractionLocked) {
      setOperatorNote('Camera Hunt is still running. Wait for Camera Hunt Complete before probing a lead.')
      return
    }
    if (!cameraHuntMode || !selectedNetwork) {
      setOperatorNote('Select a retained camera lead first.')
      return
    }
    const leadId = getCameraLeadId(selectedNetwork)
    if (!leadId) {
      setError('Selected camera lead is missing a stable identifier.')
      return
    }
    setCameraLeadProbeBusy(true)
    setError('')
    try {
      const result = await probeWiFiMk7CameraLead({ leadId })
      setCameraLeadProbe(result)
      if (result?.ok) {
        setSelectedDetailTab('probe')
        const summary = result?.active_fingerprint?.summary || {}
        const verdict = summary?.camera_positive ? 'camera-positive probe evidence retained.' : 'no strong camera-positive probe evidence retained.'
        setOperatorNote(`${leadId} probe complete: ${verdict}`)
      } else {
        setError(result?.error || 'Camera lead probe failed.')
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setCameraLeadProbeBusy(false)
    }
  }

  async function handleProbeCameraIp() {
    if (cameraLeadInteractionLocked) {
      setOperatorNote('Camera Hunt is still running. Wait for Camera Hunt Complete before manual probe actions.')
      return
    }
    if (!manualProbeIp.trim()) {
      setOperatorNote('Provide a reachable local IP for manual probe validation.')
      return
    }
    setCameraLeadProbeBusy(true)
    setError('')
    try {
      const result = await probeWiFiMk7CameraIp({ ip: manualProbeIp.trim() })
      setCameraLeadProbe(result)
      if (result?.ok) {
        setSelectedDetailTab('probe')
        const summary = result?.active_fingerprint?.summary || {}
        const verdict = summary?.camera_positive ? 'camera-positive probe evidence retained.' : 'no strong camera-positive probe evidence retained.'
        setOperatorNote(`${manualProbeIp.trim()} probe complete: ${verdict}`)
      } else {
        setError(result?.error || 'Manual IP probe failed.')
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setCameraLeadProbeBusy(false)
    }
  }

  async function handleHardAuditCameraLead() {
    if (cameraLeadInteractionLocked) {
      setOperatorNote('Camera Hunt is still running. Wait for Camera Hunt Complete before Hard Audit.')
      return
    }
    if (!cameraHuntMode || !selectedNetwork) {
      setOperatorNote('Select a retained camera lead first.')
      return
    }
    const leadId = getCameraLeadId(selectedNetwork)
    if (!leadId) {
      setError('Selected camera lead is missing a stable identifier.')
      return
    }
    setCameraLeadHardAuditBusy(true)
    setHardAuditStartedAtMs(Date.now())
    setHardAuditTimerNowMs(Date.now())
    setCameraLeadLayerAudit(null)
    setError('')
    setSelectedDetailTab('stream')
    setCameraLeadHardAudit({
      lead_id: leadId,
      hard_audit: buildCameraAuditSeed(
        'Hard audit started. Running probe, media capture, endpoint truth, and layer classification.',
        'Maintain idle baseline briefly, then open live view when prompted by the stage rail.',
      ),
    })
    try {
      const result = await startWiFiMk7VideoTruthTest({ leadId, seconds: HARD_AUDIT_DURATION_SECONDS })
      setCameraLeadHardAudit(result)
      if (result?.analysis) setCameraLeadAnalysis(result.analysis)
      if (result?.active_fingerprint) setCameraLeadProbe(result)
      let layerResult = null
      if (result?.ok) {
        try {
          setCameraLeadLayerAuditBusy(true)
          layerResult = await auditLayersWiFiMk7CameraLead({ leadId })
          if (layerResult) {
            setCameraLeadLayerAudit(layerResult)
            if (layerResult?.hard_audit) setCameraLeadHardAudit(layerResult)
          }
        } catch (layerErr) {
          layerResult = null
          setOperatorNote(`Layer classification was partial for ${leadId}. Hard Audit evidence is still retained.`)
        } finally {
          setCameraLeadLayerAuditBusy(false)
        }
      }
      await refresh({ prepare: false, includeData: true, forceFullData: cameraHuntMode })
      const mergedLead = withCameraLayerAudit(
        withCameraHardAudit(
          selectedNetwork,
          layerResult?.hard_audit || result?.hard_audit || null,
        ),
        layerResult?.layer_audit || result?.layer_audit || null,
      )
      const artifacts = getCameraVisualArtifacts(mergedLead)
      const evidenceLevel = getCameraMediaEvidenceLevel(mergedLead)
      if (result?.ok) {
        const assessmentNote = redTeamForm.confirmAuthorizedLab
          ? 'Owned-lab assessment remains available in the RED TEAM tab if you want to escalate further.'
          : 'Assessment remains gated behind owned-lab confirmation in the RED TEAM tab.'
        setOperatorNote(
          artifacts.length
            ? `${leadId} hard audit complete. Media saved (${artifacts.length}) and ${evidenceLevel.label.toLowerCase()} retained. ${assessmentNote}`
            : `${leadId} hard audit complete. ${evidenceLevel.label} retained with endpoint truth and layer classification. ${assessmentNote}`,
        )
      } else {
        setError(result?.error || 'Hard audit did not complete cleanly.')
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setCameraLeadHardAuditBusy(false)
      setHardAuditStartedAtMs(0)
      setHardAuditTimerNowMs(0)
    }
  }

  async function handleAuditCameraLayers() {
    if (cameraLeadInteractionLocked) {
      setOperatorNote('Camera Hunt is still running. Wait for Camera Hunt Complete before Audit Layers.')
      return
    }
    if (!cameraHuntMode || !selectedNetwork) {
      setOperatorNote('Select a retained camera lead first.')
      return
    }
    const leadId = getCameraLeadId(selectedNetwork)
    if (!leadId) {
      setError('Selected camera lead is missing a stable identifier.')
      return
    }
    setCameraLeadLayerAuditBusy(true)
    setError('')
    try {
      const result = await auditLayersWiFiMk7CameraLead({ leadId })
      setCameraLeadLayerAudit(result)
      if (result?.hard_audit) setCameraLeadHardAudit(result)
      if (result?.ok) {
        setSelectedDetailTab('layers')
        setOperatorNote(`${leadId} layered audit complete. Media plane and next recovery path are now classified.`)
      } else {
        setError(result?.error || 'Layered audit did not complete cleanly.')
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setCameraLeadLayerAuditBusy(false)
    }
  }

  async function handleRunCameraMediaEvidence() {
    if (cameraLeadInteractionLocked) {
      setOperatorNote('Camera Hunt is still running. Wait for Camera Hunt Complete before capturing media evidence.')
      return
    }
    if (!cameraHuntMode || !selectedNetwork) {
      setOperatorNote('Select a retained camera lead first.')
      return
    }
    const leadId = getCameraLeadId(selectedNetwork)
    if (!leadId) {
      setError('Selected camera lead is missing a stable identifier.')
      return
    }
    setCameraLeadVideoTruthBusy(true)
    setError('')
    setSelectedDetailTab('stream')
    setCameraLeadLayerAudit(null)
    setCameraLeadHardAudit({
      lead_id: leadId,
      hard_audit: buildCameraAuditSeed(
        'Media evidence capture started. Profiling live-view traffic, local media paths, and packet evidence.',
        'Keep the camera app open and live view active while the stage rail advances through baseline, trigger, and correlation.',
      ),
    })
    setOperatorNote('Running authorized media evidence capture. This will reuse the retained camera lead and test for real stream, snapshot, and truth-correlation evidence.')
    try {
      const result = await startWiFiMk7VideoTruthTest({ leadId, seconds: 40 })
      setCameraLeadHardAudit(result)
      if (result?.analysis) setCameraLeadAnalysis(result.analysis)
      if (result?.active_fingerprint) setCameraLeadProbe(result)
      if (result?.layer_audit) setCameraLeadLayerAudit(result)
      await refresh({ prepare: false, includeData: true, forceFullData: true })
      const mergedLead = withCameraLayerAudit(
        withCameraHardAudit(selectedNetwork, result?.hard_audit || null),
        result?.layer_audit || null,
      )
      const artifacts = getCameraVisualArtifacts(mergedLead)
      const evidenceLevel = getCameraMediaEvidenceLevel(mergedLead)
      if (result?.ok) {
        setOperatorNote(
          artifacts.length
            ? `${leadId} media evidence captured. ${evidenceLevel.label} is now retained for operator review.`
            : `${leadId} media evidence test completed. ${evidenceLevel.label} remains the current posture.`,
        )
      } else {
        setError(result?.error || 'Authorized media evidence test did not complete cleanly.')
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setCameraLeadVideoTruthBusy(false)
    }
  }

  async function handleRunHardAudit() {
    if (cameraHuntMode || !selectedNetwork) {
      setOperatorNote('Select a retained WiFi device first.')
      return
    }
    const targetId = getEntitySelectionId(selectedNetwork, false)
    if (!targetId) {
      setError('Selected WiFi target is missing a stable identifier.')
      return
    }
    setServiceAuditBusy(true)
    setError('')
    setSelectedDetailTab('audit')
    startServiceAuditProgress(targetId)
    try {
      const result = await runWiFiMk7HardAudit({ targetId })
      clearServiceAuditProgressTimer()
      setServiceAudit(result)
      await refresh({ prepare: false, includeData: true, forceFullData: false })
      setSelectedDetailTab('audit')
      if (result?.ok) {
        setOperatorNote(`${targetId} hard audit complete. Ports, services, access posture, destination evidence, and trace were retained.`)
      } else {
        setError(result?.error || result?.final_verdict?.explanation || 'Hard audit did not complete cleanly.')
      }
    } catch (err) {
      clearServiceAuditProgressTimer()
      setError(String(err.message || err))
    } finally {
      clearServiceAuditProgressTimer()
      setServiceAuditBusy(false)
    }
  }

  function handleSelectRedTeamAction(actionType, notes = '') {
    const profile = getRedTeamActionProfile(actionType)
    setSelectedDetailTab('redteam')
    setRedTeamForm((current) => ({
      ...current,
      actionType,
      targetSsid: selectedNetwork?.ssid || current.targetSsid || '',
      bssid: selectedNetwork?.bssid || selectedNetwork?.associated_bssid || current.bssid || '',
      clientMac: selectedNetwork?.mac || selectedNetwork?.client_mac || current.clientMac || '',
      channel: selectedNetwork?.channel || current.channel || '',
      notes: notes || current.notes,
    }))
    setOperatorNote(`${profile.label} selected for ${selectedNetwork?.ssid || selectedNetwork?.bssid || selectedNetwork?.mac || 'selected target'}. ${profile.expected}`)
  }

  async function handleRedTeamPreflight() {
    if (!selectedNetwork) {
      setOperatorNote(cameraHuntMode ? 'Select a retained camera lead first.' : 'Select a retained WiFi target first.')
      return
    }
    setRedTeamBusy(true)
    setError('')
    try {
      const targetId = getRedTeamTargetId(selectedNetwork, cameraHuntMode)
      const result = await runWiFiMk7RedTeamPreflight({
        targetId,
        actionType: redTeamForm.actionType,
        confirmAuthorizedLab: redTeamForm.confirmAuthorizedLab,
        channel: Number(redTeamForm.channel || selectedNetwork.channel || 0),
      })
      setRedTeamState((current) => ({ ...current, ...result, last_preflight: result }))
      setOperatorNote(result?.state === 'READY'
        ? (cameraHuntMode
          ? 'Camera Red Team preflight passed. This receive-only workflow will validate and retain real packet evidence for the selected camera lead.'
          : 'Red Team Validation preflight passed. This receive-only workflow will validate and retain real packet evidence from the current owned-lab session.')
        : `${cameraHuntMode ? 'Camera Red Team' : 'Red Team Validation'} blocked: ${result?.state || 'unknown state'}`)
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setRedTeamBusy(false)
    }
  }

  async function handleRunRedTeamValidation() {
    if (!selectedNetwork) {
      setOperatorNote(cameraHuntMode ? 'Select a retained camera lead first.' : 'Select a retained WiFi target first.')
      return
    }
    setRedTeamBusy(true)
    setError('')
    try {
      if (cameraHuntMode) {
        const targetId = getRedTeamTargetId(selectedNetwork, true)
        const auditResult = await runWiFiMk7ServiceAudit({
          targetId,
          allowInfrastructure: false,
        }).catch(() => null)
        if (auditResult && (auditResult.ok || auditResult.final_verdict || auditResult.target_validation)) {
          setServiceAudit(auditResult)
        }
        setSelectedDetailTab('redteam')
        if (!offlineEvidenceEnabled || !effectiveReplayCapturePath) {
          setOperatorNote('Camera red validation completed live service audit. Offline capture replay is disabled for public v1.')
          return
        }
        await runReplayBackedRedTeamWorkflow({
          replayLabel: adversaryReplayLabel.trim() || `${selectedNetwork?.ssid || selectedNetwork?.mac || selectedNetwork?.bssid || 'camera-lead'} camera red validation`,
          noteOnSuccess: 'Camera red validation replay completed.',
          noteOnBlocked: 'Camera red validation replay blocked.',
        })
        return
      }
      if (!status?.capture_active) {
        setOperatorNote('Start WiFi MK7 live capture before running public v1 validation.')
        return
      }
      const targetId = getRedTeamTargetId(selectedNetwork, cameraHuntMode)
      const preflight = await runWiFiMk7RedTeamPreflight({
        targetId,
        actionType: redTeamForm.actionType,
        confirmAuthorizedLab: redTeamForm.confirmAuthorizedLab,
        channel: Number(redTeamForm.channel || selectedNetwork.channel || 0),
      })
      setRedTeamState((current) => ({ ...current, ...preflight, last_preflight: preflight }))
      if (preflight?.state !== 'READY') {
        if (offlineEvidenceEnabled && effectiveReplayCapturePath) {
          await runReplayBackedRedTeamWorkflow({
            replayLabel: adversaryReplayLabel.trim() || `${selectedNetwork?.ssid || selectedNetwork?.mac || targetId} redteam validation`,
            noteOnSuccess: 'Live red-team validation was not ready, so the loaded adversary PCAP was replayed through WiFi MK7.',
            noteOnBlocked: 'Adversary replay blocked.',
          })
          return
        }
        setOperatorNote(preflight?.message || `${cameraHuntMode ? 'Camera Red Team' : 'Red Team Validation'} blocked: ${preflight?.state || 'unknown state'}`)
        return
      }
      const result = await runWiFiMk7RedTeamValidation({
        targetId,
        actionType: redTeamForm.actionType,
        confirmAuthorizedLab: redTeamForm.confirmAuthorizedLab,
        channel: Number(redTeamForm.channel || selectedNetwork.channel || 0),
        maxDuration: Number(redTeamForm.maxDuration || 30),
        maxFrameCount: Number(redTeamForm.maxFrameCount || 3),
        reasonCode: redTeamForm.reasonCode,
        notes: redTeamForm.notes,
      })
      setRedTeamState(result || { state: 'FAILED_CAPTURE_ERROR', last_run: {} })
      setSelectedDetailTab('redteam')
      if (result?.ok) {
        setOperatorNote(result?.message || `${cameraHuntMode ? 'Camera Red Team' : 'Red Team Validation'} completed.`)
      } else {
        setOperatorNote(result?.message || `${cameraHuntMode ? 'Camera Red Team' : 'Red Team Validation'} blocked: ${result?.state || 'unknown state'}`)
      }
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setRedTeamBusy(false)
    }
  }

  function handleOpenCameraAttackAssessment() {
    if (!cameraHuntMode || !selectedNetwork) {
      setOperatorNote('Select a retained camera lead first.')
      return
    }
    setSelectedDetailTab('redteam')
    setCameraAssessmentConfirmPrompt(true)
    setRedTeamForm((current) => ({ ...current, confirmAuthorizedLab: false }))
    setOperatorNote('Opened RED TEAM ATTACK. Confirm Lab Owned in the assessment gate, then run assessment.')
  }

  useEffect(() => {
    let cancelled = false

    async function initialize() {
      try {
        setInitializing(true)
        setNetworks([])
        setClients([])
        setPcaps([])
        setCameraHuntResults({ leads: [], pipeline: {} })
        setCameraHuntRunStarted(Boolean(cameraOnly))
        setSelectedNetworkId('')
        setSelectedNetworkSnapshot(null)
        setFocusedBssid('')
        setExpandedNetworks({})
        setCameraHuntMode(Boolean(cameraOnly))
        if (!cameraOnly) {
          const snapshot = await fetchWiFiMk7OperatorSnapshot({
            prepare: true,
            light: false,
            includeData: false,
            includeRedTeam: true,
          }).catch(() => null)
          if (snapshot) {
            applyOperatorSnapshot(snapshot, { includeData: false, includeRedTeam: true })
          } else {
            await refresh({ prepare: true, includeData: false })
          }
        } else {
          await refresh({ prepare: true, includeData: false })
        }
      } catch (err) {
        if (!cancelled) {
          setError(String(err.message || err))
        }
      } finally {
        if (!cancelled) setInitializing(false)
      }
    }

    initialize()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    let timer = null

    async function poll() {
      if (refreshInFlightRef.current) return
      refreshInFlightRef.current = true
      try {
        const auditBusy = cameraHuntMode
          ? (cameraLeadHardAuditBusy || cameraLeadVideoTruthBusy || cameraLeadLayerAuditBusy)
          : serviceAuditBusy
        if (auditBusy) {
          await refresh({ prepare: false, includeData: true, forceFullData: true })
          return
        }
        const scanning = status?.capture_active
        if (scanning) {
          cameraHuntPollTickRef.current += 1
          const includeData = cameraHuntMode
            ? cameraHuntPollTickRef.current % 6 === 0
            : cameraHuntPollTickRef.current % 4 === 0
          const forceFullData = cameraHuntMode && includeData && cameraHuntPollTickRef.current % 24 === 0
          await refresh({ prepare: false, includeData, lightStatus: !includeData, forceFullData })
          return
        }
        cameraHuntPollTickRef.current = 0
        await refresh({ prepare: false, includeData: true, forceFullData: cameraHuntMode })
      } catch (err) {
        if (!cancelled) {
          setError(String(err.message || err))
        }
      } finally {
        refreshInFlightRef.current = false
      }
    }

    async function schedulePoll() {
      await poll()
      if (cancelled) return
      const auditBusy = cameraHuntMode
        ? (cameraLeadHardAuditBusy || cameraLeadVideoTruthBusy || cameraLeadLayerAuditBusy)
        : serviceAuditBusy
      const runtimeActive = hasActiveRuntimeTools(status)
      const activeInterval = auditBusy ? 1200 : (cameraHuntMode ? 3500 : 2000)
      const drainInterval = auditBusy ? 1200 : (cameraHuntMode ? 2200 : 1800)
      const settledIdleInterval = auditBusy ? 1200 : (cameraHuntMode ? 9000 : 7000)
      timer = window.setTimeout(
        schedulePoll,
        (status?.capture_active || auditBusy)
          ? activeInterval
          : (runtimeActive ? drainInterval : settledIdleInterval),
      )
    }

    schedulePoll()
    return () => {
      cancelled = true
      if (timer) window.clearTimeout(timer)
    }
  }, [
    status?.capture_active,
    cameraHuntMode,
    selectedDetailTab,
    cameraLeadHardAuditBusy,
    cameraLeadVideoTruthBusy,
    cameraLeadLayerAuditBusy,
    serviceAuditBusy,
  ])

  useEffect(() => {
    if (!hardAuditActive) {
      setHardAuditTimerNowMs(0)
      return undefined
    }
    setHardAuditTimerNowMs(Date.now())
    const timer = window.setInterval(() => {
      setHardAuditTimerNowMs(Date.now())
    }, 250)
    return () => window.clearInterval(timer)
  }, [hardAuditActive])

  useEffect(() => () => {
    if (serviceAuditProgressTimerRef.current) {
      window.clearInterval(serviceAuditProgressTimerRef.current)
      serviceAuditProgressTimerRef.current = null
    }
  }, [])

  function clearServiceAuditProgressTimer() {
    if (serviceAuditProgressTimerRef.current) {
      window.clearInterval(serviceAuditProgressTimerRef.current)
      serviceAuditProgressTimerRef.current = null
    }
  }

  function startServiceAuditProgress(targetId) {
    clearServiceAuditProgressTimer()
    let activeStageIndex = 0
    setServiceAudit(buildRunningWiFiHardAuditState(targetId, activeStageIndex))
    serviceAuditProgressTimerRef.current = window.setInterval(() => {
      activeStageIndex = Math.min(activeStageIndex + 1, WIFI_HARD_AUDIT_PROGRESS_PLAN.length - 1)
      setServiceAudit((current) => {
        if (String(current?.target_id || '').trim() !== String(targetId || '').trim()) return current
        if (String(current?.status || '').toLowerCase() !== 'running') return current
        return buildRunningWiFiHardAuditState(targetId, activeStageIndex)
      })
      if (activeStageIndex >= WIFI_HARD_AUDIT_PROGRESS_PLAN.length - 1) {
        clearServiceAuditProgressTimer()
      }
    }, 1400)
  }

  function handleSelectNetwork(network) {
    if (cameraLeadInteractionLocked) return
    const networkId = getEntitySelectionId(network, cameraHuntMode)
    if (cameraHuntMode && selectedNetworkId && selectedNetworkId === networkId) {
      setSelectedNetworkId('')
      setSelectedNetworkSnapshot(null)
      return
    }
    setSelectedNetworkId(networkId)
    setSelectedNetworkSnapshot(network || null)
    if (!cameraHuntMode && network) {
      setRedTeamForm((current) => ({
        ...current,
        targetSsid: network.ssid || current.targetSsid || '',
        bssid: network.bssid || network.associated_bssid || current.bssid || '',
        clientMac: network.mac || network.client_mac || current.clientMac || '',
        channel: network.channel || current.channel || '',
      }))
    }
    if (networkId) {
      setExpandedNetworks({ [networkId]: true })
    }
    window.requestAnimationFrame(() => {
      selectedNetworkRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    })
  }

  function toggleExpandedNetwork(bssid) {
    setExpandedNetworks((current) => ({ ...current, [bssid]: !current[bssid] }))
  }

  async function handleStart() {
    if (privilegeBlocked) {
      setError(privilegeRemediation)
      return
    }
    setCameraHuntMode(false)
    setCameraHuntRunStarted(false)
    setBusy(true)
    setOperatorNote('')
    setNetworks([])
    setClients([])
    setPcaps([])
    setCameraHuntResults({ leads: [], pipeline: {} })
    setCameraLeadHardAudit(null)
    setCameraLeadLayerAudit(null)
    setSelectedNetworkId('')
    setSelectedNetworkSnapshot(null)
    setFocusedBssid('')
    setExpandedNetworks({})
    try {
      await clearWiFiMk7Session()
      const result = await startWiFiMk7Session({
        bands: bandSelection,
        dwellMs,
        durationSeconds: scanDurationSeconds,
        scanMode,
        scanScenario,
        lockedChannels: scanMode === 'lock' && lockedChannel ? [Number(lockedChannel)] : [],
        interfaces: selectedInterfaces,
        cameraHunt: false,
      })
      setStatus((current) => ({ ...(current || {}), ...result }))
      if (isHandshakeFocusedScanMode(scanMode)) {
        setOperatorNote('Handshake-first sweep active. Channel dwell now prioritizes EAPOL, authentication bursts, and repeated auth-heavy channels for stronger evidence retention.')
      }
      await refresh({ prepare: false, includeData: false })
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleHuntCameras() {
    if (privilegeBlocked) {
      setError(privilegeRemediation)
      return
    }
    setCameraHuntMode(true)
    setCameraHuntRunStarted(true)
    setBusy(true)
    setOperatorNote('')
    setNetworks([])
    setClients([])
    setPcaps([])
    setCameraHuntResults({ leads: [], pipeline: {} })
    setCameraLeadHardAudit(null)
    setCameraLeadLayerAudit(null)
    setSelectedNetworkId('')
    setSelectedNetworkSnapshot(null)
    setFocusedBssid('')
    setExpandedNetworks({})
    try {
      await clearWiFiMk7Session()
      const result = await startWiFiMk7Session({
        bands: bandSelection,
        dwellMs,
        durationSeconds: scanDurationSeconds,
        scanMode,
        scanScenario,
        lockedChannels: scanMode === 'lock' && lockedChannel ? [Number(lockedChannel)] : [],
        interfaces: selectedInterfaces,
        cameraHunt: true,
      })
      setStatus((current) => ({ ...(current || {}), ...result }))
      setOperatorNote('Camera hunt active. Lead selection and follow-up audits stay locked until the scan completes.')
      await refresh({ prepare: false, includeData: false })
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStop() {
    setBusy(true)
    try {
      await stopWiFiMk7Session()
      setOperatorNote('Stop requested. The current channel capture will finish before results are retained.')
      await refresh({ prepare: false, includeData: false })
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleClear() {
    setBusy(true)
    try {
      await clearWiFiMk7Session()
      setNetworks([])
      setClients([])
      setPcaps([])
      setCameraHuntResults({ leads: [], pipeline: {} })
      setCameraLeadHardAudit(null)
      setCameraLeadLayerAudit(null)
      setCameraHuntRunStarted(Boolean(cameraOnly))
      setSelectedNetworkId('')
      setSelectedNetworkSnapshot(null)
      setFocusedBssid('')
      setExpandedNetworks({})
      setCameraHuntMode(Boolean(cameraOnly))
      setOperatorNote('Cleared retained SSIDs, clients, and PCAP references for this WiFi MK7 session.')
      await refresh({ prepare: false, includeData: false })
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  function handleTask(taskKey) {
    if (!selectedNetwork) return
    if (taskKey === 'focus') {
      if (!selectedNetwork?.bssid) {
        setOperatorNote('Client focus is only available for access-point records.')
        return
      }
      const nextFocused = focusedBssid === selectedNetwork.bssid ? '' : selectedNetwork.bssid
      setFocusedBssid(nextFocused)
      setOperatorNote(nextFocused ? `Client focus set to ${selectedNetwork.ssid || selectedNetwork.bssid}.` : 'Client focus cleared.')
      return
    }
    if (taskKey === 'export') {
      const baseId = String(selectedNetwork.bssid || selectedNetwork.mac || selectedNetwork.associated_bssid || 'device').replaceAll(':', '')
      const base = `${(selectedNetwork.ssid || selectedNetwork.mac || 'device').replace(/[^a-z0-9_-]+/gi, '_').toLowerCase()}_${baseId}`
      downloadJson(`${base}_wifi_mk7.json`, {
        exported_at: new Date().toISOString(),
        mode,
        network: selectedNetwork,
        related_clients: clients.filter((client) => client.associated_bssid === selectedNetwork.bssid),
        retained_pcaps: pcaps,
        last_scan_summary: status?.last_scan_summary || {},
      })
      setOperatorNote(`Exported evidence bundle for ${selectedNetwork.ssid || selectedNetwork.bssid}.`)
      return
    }
    const task = buildTaskPresets(selectedNetwork).find((item) => item.key === taskKey)
    if (task?.targetTab && onPivot) {
      onPivot(task.targetTab)
      setOperatorNote(`${task.label} queued for ${selectedNetwork.ssid || selectedNetwork.bssid}.`)
    }
  }

  const adapter = status?.adapter || {}
  const inventory = status?.inventory || {}
  const scan = status?.scan || {}
  const preferredInterfaceLabel = adapter?.preferred_interface || adapter?.base_interface || 'configured adapter'
  const privilegeBlocked = Boolean(adapter?.detected && adapter?.privilege_required && !status?.sensor_ready)
  const privilegeRemediation = adapter?.remediation || `Start the backend with sudo or grant CAP_NET_ADMIN/root privileges to the backend process for ${preferredInterfaceLabel}.`
  const pipelineActive = !!status?.camera_hunt_pipeline?.active
  const processingRunning = !!status?.processing_pipeline?.running
  const scanStarted = Boolean(scan?.started_at)
  const captureActive = Boolean((status?.capture_active && (scanStarted || pipelineActive || processingRunning)) || pipelineActive || processingRunning)
  const cameraHuntComplete = Boolean(cameraHuntMode && cameraHuntRunStarted && !captureActive && !busy)
  const cameraLeadInteractionLocked = Boolean(cameraHuntMode && !cameraHuntComplete)
  const progressPercent = Number(scan?.progress_percent || 0)
  const elapsedSeconds = Number(scan?.elapsed_seconds || 0)
  const targetSeconds = Number(scan?.target_seconds || scanDurationSeconds || DEFAULT_SCAN_DURATION_SECONDS)
  const remainingSeconds = Math.max(0, targetSeconds - elapsedSeconds)
  const realtimeStageRail = backendActivity.stageRail || []
  const stageCompletedCount = realtimeStageRail.filter((phase) => phase.visualState === 'complete').length
  const activeStage = realtimeStageRail.find((phase) => phase.visualState === 'active') || null
  const stageProgressPercent = realtimeStageRail.length
    ? Math.round(
      (
        (stageCompletedCount + (activeStage ? Math.max(0, Math.min(100, Number(activeStage.percent || 0))) / 100 : 0))
        / realtimeStageRail.length
      ) * 100,
    )
    : 0
  const timerProgressPercent = targetSeconds > 0 ? (elapsedSeconds / targetSeconds) * 100 : 0
  const accurateProgressPercent = Math.max(
    progressPercent,
    timerProgressPercent,
    backendActivity.hasPhasedPipeline ? stageProgressPercent : 0,
  )
  const effectiveProgressPercent = captureActive
    ? Math.max(0, Math.min(100, accurateProgressPercent))
    : (cameraHuntComplete ? 100 : 0)
  const progressDisplay = captureActive || cameraHuntComplete
    ? `${effectiveProgressPercent.toFixed(1)}%`
    : '0%'
  const currentBackendPhase = activeStage?.label || backendActivity.currentPhase || (captureActive ? 'Active Scan' : 'Idle')
  const realtimeProgressDetail = captureActive
    ? `${Math.ceil(elapsedSeconds)}s elapsed · ${Math.ceil(remainingSeconds)}s left · ${currentBackendPhase}`
    : (cameraHuntComplete
      ? 'Camera Hunt Complete · lead review and audits unlocked'
      : `${Math.round(scanDurationSeconds / 60)} minute scan preset · ${cameraHuntMode ? 'camera hunt pipeline ready' : 'wifi hunt ready'}`)
  const mk7SensorMetrics = [
    {
      label: 'Adapter',
      value: adapter?.detected ? 'MK7AC' : 'Not Ready',
      detail: adapter?.monitor_interface ? `${adapter.monitor_interface} ready` : (adapter?.detail || 'No WiFi sensor'),
    },
    {
      label: 'Mode',
      value: adapter?.mode || 'Managed',
      detail: adapter?.monitor_supported ? 'monitor capable' : 'capability unknown',
    },
    {
      label: 'Interface',
      value: adapter?.monitor_interface || adapter?.base_interface || '--',
      detail: adapter?.base_interface ? `base ${adapter.base_interface}` : 'no base iface',
    },
    {
      label: 'Monitors',
      value: (adapter?.monitor_interfaces || []).length || 0,
      detail: (adapter?.monitor_interfaces || []).join(', ') || 'single-source',
    },
    {
      label: 'Bands',
      value: fmtBandList(adapter?.bands),
      detail: '2.4 / 5 GHz',
    },
  ]
  const mk7RunMetrics = [
    {
      label: 'Timer',
      value: captureActive ? `${Math.ceil(remainingSeconds)}s` : `${Math.round(scanDurationSeconds / 60)} min`,
      detail: captureActive ? 'remaining' : 'preset',
    },
    {
      label: 'Capture',
      value: captureActive ? 'Scanning' : (cameraHuntComplete ? 'Complete' : 'Idle'),
      detail: captureActive ? `cycle ${scan?.cycle || 1}` : (cameraHuntComplete ? 'review unlocked' : 'awaiting operator'),
    },
    {
      label: 'Rate',
      value: status?.packet_rate_pps ?? 0,
      detail: 'pps',
    },
    {
      label: 'Retained',
      value: inventory?.network_count ?? 0,
      detail: 'SSID retained',
    },
  ]

  useEffect(() => {
    if (cameraHuntComplete) {
      setOperatorNote('Camera Hunt Complete. Select a camera lead to run Hard Audit.')
    }
  }, [cameraHuntComplete])

  return (
    <main className="workspace category-workspace">
      <div className="main-column">
        {isPanelVisible('guidance') ? (
          <Panel kicker="Operator Guidance" title={cameraOnly ? 'Camera Hunt Native 802.11 Intelligence' : 'WIFI-MK7 Native 802.11 Intelligence'}>
            <div className="hero-command-surface mk7-command-deck">
              <div className="hero-command-head">
                <span className="hero-command-kicker">Native Packet Recon</span>
                <span className="hero-command-state">{captureActive ? (cameraOnly ? 'Camera Hunt Active' : 'Live Scan Active') : 'Sensor Ready'}</span>
              </div>
              <div className="hero-command-meta">
                <div className="hero-command-primary-note">
                  {captureActive
                    ? (cameraOnly
                      ? 'Timed camera-hunt scan running. Results update from retained packet-native 802.11 observations and video-device scoring.'
                      : 'Timed MK7 scan running. Results update from retained packet-native 802.11 observations.')
                    : (cameraOnly
                      ? 'Packet-native 802.11 camera validation only. This page isolates video-device detection from general WiFi Hunt.'
                      : 'Packet-native 802.11 truth only. This page does not use the HackRF SDR workflow.')}
                </div>
                <div className="hero-command-notes">
                  <span className="hero-command-note">Empty table until first retained cycle</span>
                  <span className="hero-command-note">Adaptive mode revisits hot channels</span>
                  <span className="hero-command-note">Lock mode holds one channel</span>
                  <span className="hero-command-note">Stop retains current results</span>
                </div>
              </div>
              <div className="pill-row">
                <Pill text="red-team truth layer" tone="cyan" />
                <Pill text="packet-backed" tone="green" />
                <Pill text={scanMode} tone="neutral" />
                {cameraHuntMode ? <Pill text="camera hunt" tone="danger" /> : null}
              </div>
            </div>
          </Panel>
        ) : null}

        <section className="mk7-telemetry-board">
          <div className="mk7-telemetry-group">
            <div className="mk7-telemetry-group-head">Sensor</div>
            <div className="mk7-telemetry-strip sensor">
              {mk7SensorMetrics.map((item) => (
                <div key={`mk7-sensor-metric:${item.label}`} className="mk7-telemetry-card" title={`${item.label}: ${item.value} · ${item.detail}`}>
                  <span>{item.label}</span>
                  <strong>{item.value ?? '--'}</strong>
                  <small>{item.detail}</small>
                </div>
              ))}
            </div>
          </div>
          <div className="mk7-telemetry-group">
            <div className="mk7-telemetry-group-head">Run</div>
            <div className="mk7-telemetry-strip run">
              {mk7RunMetrics.map((item) => (
                <div key={`mk7-run-metric:${item.label}`} className="mk7-telemetry-card" title={`${item.label}: ${item.value} · ${item.detail}`}>
                  <span>{item.label}</span>
                  <strong>{item.value ?? '--'}</strong>
                  <small>{item.detail}</small>
                </div>
              ))}
            </div>
          </div>
        </section>

        {error ? <section className="error-banner">{error}</section> : null}
        {privilegeBlocked ? (
          <section className="error-banner soft-warning">
            Monitor mode cannot be enabled on <code>{preferredInterfaceLabel}</code>. {privilegeRemediation}
          </section>
        ) : null}
        {!adapter?.detected ? (
          <section className="error-banner soft-warning">
            WIFI-MK7 adapter not detected. Connect the MK7AC adapter on <code>{preferredInterfaceLabel}</code> to enable monitor mode and packet capture.
          </section>
        ) : null}

        {isPanelVisible('controls') ? (
          <Panel kicker="Sensor Control" title={cameraOnly ? 'Camera Hunt Control' : 'MK7AC Scan Control'} className="wifi-control-panel">
            <div className="mk7-control-stack">
              <div className="control-strip mk7-control-grid">
                <label className="control-card compact">
                  <span className="control-label">Band Set</span>
                  <select value={bandMode} disabled={busy || captureActive} onChange={(event) => setBandMode(event.target.value)}>
                    <option value="both">2.4 GHz + 5 GHz</option>
                    <option value="24">2.4 GHz only</option>
                    <option value="5">5 GHz only</option>
                  </select>
                </label>
                <label className="control-card compact">
                  <span className="control-label">Duration</span>
                  <select value={scanDurationSeconds} disabled={busy || captureActive} onChange={(event) => setScanDurationSeconds(Number(event.target.value))}>
                    {SCAN_DURATION_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </label>
                <label className="control-card compact">
                  <span className="control-label">Scan Mode</span>
                  <select value={scanMode} disabled={busy || captureActive} onChange={(event) => setScanMode(event.target.value)}>
                    <option value="broad">Broad recon</option>
                    <option value="handshake_hunt">Handshake-first evidence hunt</option>
                    <option value="adaptive">Adaptive hot-channel dwell</option>
                    <option value="adaptive_handshake_hunt">Adaptive handshake hunt</option>
                    <option value="residential_dfs">Residential + DFS</option>
                    <option value="adaptive_residential_dfs">Adaptive residential + DFS</option>
                    <option value="lock">Lock channel</option>
                  </select>
                </label>
                <label className="control-card compact">
                  <span className="control-label">Scenario</span>
                  <select value={scanScenario} disabled={busy || captureActive} onChange={(event) => setScanScenario(event.target.value)}>
                    <option value="passive_observation">Passive observation</option>
                    <option value="idle">Idle baseline</option>
                    <option value="app_open">App open</option>
                    <option value="live_view">Live view</option>
                    <option value="motion">Motion event</option>
                    <option value="doorbell">Doorbell press</option>
                    <option value="reboot">Post-reboot</option>
                  </select>
                </label>
                <div className="scan-progress-panel compact sleek">
                  <div className="scan-progress-head">
                    <div className="scan-progress-title-block">
                      <strong>{captureActive ? 'Scanning' : (cameraHuntComplete ? 'Camera Hunt Complete' : 'Idle')}</strong>
                      <small>{cameraHuntMode ? 'camera hunt telemetry' : 'wifi hunt telemetry'}</small>
                    </div>
                    <span className="scan-progress-percentage">{progressDisplay}</span>
                  </div>
                  <div className={`scan-progress-track wide ${captureActive ? 'active' : ''}`}>
                    <div className="scan-progress-fill" style={{ width: `${effectiveProgressPercent}%` }} />
                  </div>
                  <div className="scan-progress-meta">
                    <span>{captureActive ? currentBackendPhase : 'No active scan'}</span>
                    <span>{captureActive ? `${Math.ceil(remainingSeconds)}s left` : `${Math.round(scanDurationSeconds / 60)} minute preset`}</span>
                  </div>
                </div>
              </div>
              <div className="camera-hunt-evidence-board">
                <div className="camera-hunt-evidence-head">
                  <span className="backend-stage-kicker">Realtime Backend Progress</span>
                  <strong>{captureActive ? currentBackendPhase : (cameraHuntComplete ? 'Camera Hunt Complete' : 'Standby')} · {Math.round(effectiveProgressPercent)}%</strong>
                </div>
                <div className="guidance-item compact">
                  <strong>Status:</strong> {realtimeProgressDetail}
                </div>
                <div className="scan-progress-track" aria-hidden="true">
                  <div className="scan-progress-fill" style={{ width: `${effectiveProgressPercent}%` }} />
                </div>
                <div className="camera-inline-hard-audit-strip" style={{ marginTop: '0.75rem' }}>
                  {realtimeStageRail.length ? realtimeStageRail.map((phase) => (
                    <div key={`realtime-stage:${phase.id}`} className={`camera-inline-hard-node ${phase.visualState === 'complete' ? 'completed' : phase.visualState}`}>
                      <strong>{phase.label}</strong>
                      <span>{phase.visualState === 'active' ? `${Math.round(phase.percent || 0)}% · ${phase.role || 'active'}` : (phase.role || phase.status || 'pending')}</span>
                    </div>
                  )) : (
                    <div className="camera-hard-empty">
                      <strong>Backend Stages Idle</strong>
                      <span>Start a scan to watch channel sweep, capture, decode, and enrichment phases update in real time.</span>
                    </div>
                  )}
                </div>
                <div className="table-secondary" style={{ marginTop: '0.55rem' }}>
                  {captureActive
                    ? `Queue ${backendActivity.queueSummary} · Stages ${backendActivity.stageCounts} · Tools ${backendActivity.activeTools.join(', ') || 'none'}`
                    : (cameraHuntComplete
                      ? 'Camera Hunt Complete. Operator can now select a lead and run Hard Audit.'
                      : 'Next scan will run for 3 minutes and update this backend stage rail continuously.')}
                </div>
              </div>
              <div className="pill-row mk7-action-row">
                {!cameraOnly ? (
                  <button className="mini-action" disabled={busy || captureActive || !adapter?.detected || privilegeBlocked || (scanMode === 'lock' && !lockedChannel)} onClick={handleStart}>WIFI Hunt</button>
                ) : null}
                {cameraOnly ? (
                  <button className="mini-action danger" disabled={busy || captureActive || !adapter?.detected || privilegeBlocked || (scanMode === 'lock' && !lockedChannel)} onClick={handleHuntCameras}>Hunt Camera</button>
                ) : null}
                <button className="mini-action" disabled={busy || !captureActive} onClick={handleStop}>Stop</button>
                <button className="mini-action" disabled={busy || captureActive} onClick={handleClear}>Clear</button>
              </div>
              <div className="mk7-inline-note">
                {scanMode === 'adaptive'
                  ? `Adaptive mode revisits hot channels: ${(status?.channels?.hot_channels || []).join(', ') || 'waiting for first retained cycle'}`
                    : scanMode === 'residential_dfs'
                      ? 'Residential DFS mode adds common DFS residential channels.'
                      : scanMode === 'adaptive_residential_dfs'
                        ? `Adaptive residential DFS prioritizes hot channels and DFS coverage: ${(status?.channels?.hot_channels || []).join(', ') || 'waiting for first retained cycle'}`
                  : scanMode === 'lock'
                    ? `Lock mode holds channel ${lockedChannel || '--'}`
                    : 'Broad mode sweeps the full selected band set evenly.'}
              </div>
              <div className="mk7-inline-note">
                Scenario tag: {formatScenarioLabel(status?.scan?.scenario || scanScenario)}. Use consistent tags across repeated runs so the Stream tab can compare the same device under idle, app-open, live-view, and motion conditions.
              </div>
              {cameraHuntMode ? (
                <div className="guidance-item compact">
                  <strong>Lead Review:</strong> {cameraHuntComplete
                    ? 'Camera Hunt Complete. Lead selection and follow-up audits are now unlocked.'
                    : 'Lead selection is locked while Hunt Camera is running so the operator stays in acquisition mode.'}
                </div>
              ) : null}
              {(captureActive || cameraHuntMode) ? (
                <details className="backend-summary-details">
                  <summary>{cameraHuntMode ? 'Camera Hunt Activity' : 'Live Backend Activity'}</summary>
                  <div className="guidance-item compact">
                    <strong>Backend:</strong>{' '}
                    {captureActive
                      ? `channel ${backendActivity.currentChannel} · mode ${backendActivity.mode} · interfaces ${backendActivity.interfaces} · hot ${backendActivity.hotChannels}`
                      : `idle · last mode ${backendActivity.mode} · interfaces ${backendActivity.interfaces}`}
                    <div className="table-secondary">Detection: {backendActivity.detectionSummary}</div>
                    <div className="table-secondary">Pipeline: {backendActivity.processingTopology}</div>
                    <div className="table-secondary">Queue {backendActivity.queueSummary} · Stages {backendActivity.stageCounts}</div>
                    <div className="table-secondary">Tools: {backendActivity.activeTools.join(', ') || 'none'}</div>
                    {cameraHuntMode ? <div className="table-secondary">Auto Probe: {status?.camera_hunt_auto_probe?.attempted ?? 0} attempted · {status?.camera_hunt_auto_probe?.positive ?? 0} positive</div> : null}
                  </div>
                </details>
              ) : null}
              {operatorNote ? <div className="guidance-item compact"><strong>Operator Note:</strong> {operatorNote}</div> : null}
              <details className="compact-advanced">
                <summary>Advanced Controls</summary>
                <div className="compact-advanced-grid">
                  {scanMode === 'lock' ? (
                    <div className="guidance-item compact">
                      <strong>Locked Channel:</strong>{' '}
                      <select value={lockedChannel} disabled={busy || captureActive} onChange={(event) => setLockedChannel(event.target.value)}>
                        <option value="">Select channel</option>
                        {lockChannelOptions.map((channel) => (
                          <option key={channel} value={channel}>{channel}</option>
                        ))}
                      </select>
                    </div>
                  ) : null}
                  <div className="guidance-item compact">
                    <strong>Dwell:</strong>{' '}
                    <select value={dwellMs} disabled={busy || captureActive} onChange={(event) => setDwellMs(Number(event.target.value))}>
                      {[250, 500, 1000].map((value) => (
                        <option key={value} value={value}>{value} ms</option>
                      ))}
                    </select>
                  </div>
                  <div className="guidance-item compact">
                    <strong>Sensor Scope:</strong>{' '}
                    <select value={sensorScope} disabled={busy || captureActive} onChange={(event) => setSensorScope(event.target.value)}>
                      <option value="all">all monitor sources</option>
                      {availableSensorInterfaces.map((item) => (
                        <option key={item} value={item}>{item}</option>
                      ))}
                    </select>
                  </div>
                  <div className="guidance-item compact">
                    <strong>Client Attribution:</strong>{' '}
                    <select value={clientAttributionFilter} disabled={busy || captureActive} onChange={(event) => setClientAttributionFilter(event.target.value)}>
                      <option value="confirmed">confirmed only</option>
                      <option value="strong">confirmed + strong</option>
                      <option value="all">all inferred</option>
                    </select>
                  </div>
                </div>
              </details>
            </div>
          </Panel>
        ) : null}

        {showSelectedNetworkPanel ? (
          <div ref={selectedNetworkRef}>
          <Panel kicker={cameraHuntMode ? 'Red Team Camera Window' : 'Red Team Operator Window'} title={cameraHuntMode ? 'Selected Camera Lead' : inspectedNetwork ? `${inspectedNetwork.ssid || '<hidden>'} Detail` : 'Selected SSID Detail'}>
            {inspectedNetwork ? (
              <div className="guidance-list">
                <div className="pill-row">
                  <Pill text="selection active" tone="cyan" />
                  <Pill text={cameraHuntMode ? (inspectedNetwork.mac || inspectedNetwork.bssid || inspectedNetwork.record_id) : (inspectedNetwork.bssid || inspectedNetwork.record_id)} tone="neutral" />
                  {!cameraHuntMode ? (
                    <button className={`mini-action ${serviceAuditBusy ? 'active' : ''}`} onClick={handleRunHardAudit} disabled={serviceAuditBusy}>
                      {serviceAuditBusy ? 'Hard Auditing…' : 'Hard Audit'}
                    </button>
                  ) : null}
                  {cameraHuntMode ? (
                    <button className={`mini-action danger ${cameraLeadHardAuditBusy ? 'active' : ''}`} onClick={handleHardAuditCameraLead} disabled={cameraLeadHardAuditBusy || cameraLeadVideoTruthBusy || cameraLeadProbeBusy || cameraLeadAnalysisBusy || cameraLeadLayerAuditBusy || redTeamBusy || cameraLeadInteractionLocked}>
                      {cameraLeadHardAuditBusy ? 'Hard Auditing...' : 'Hard Audit'}
                    </button>
                  ) : null}
                  <button className="mini-action" onClick={() => {
                    setSelectedNetworkId('')
                    setSelectedNetworkSnapshot(null)
                  }}>Close Detail</button>
                </div>
                {cameraHuntMode ? (
                  <div className="pill-row">
                    <input
                      className="control-input"
                      type="text"
                      value={manualProbeIp}
                      placeholder="Manual probe IP, e.g. 192.168.0.1"
                      onChange={(event) => setManualProbeIp(event.target.value)}
                    />
                    <button className={`mini-action ${cameraLeadProbeBusy ? 'active' : ''}`} onClick={handleProbeCameraIp} disabled={cameraLeadProbeBusy || cameraLeadInteractionLocked}>
                      {cameraLeadProbeBusy ? 'Probing IP...' : 'Probe IP'}
                    </button>
                  </div>
                ) : null}
                <div className="inspector-tabs">
                  <button type="button" className={`mini-action ${selectedDetailTab === 'core' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('core')}>Core</button>
                  <button type="button" className={`mini-action ${selectedDetailTab === 'evidence' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('evidence')}>Evidence</button>
                  {cameraHuntMode ? <button type="button" className={`mini-action ${selectedDetailTab === 'assessment' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('assessment')}>Assessment</button> : null}
                  {cameraHuntMode ? <button type="button" className={`mini-action ${selectedDetailTab === 'stream' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('stream')}>Stream</button> : null}
                  {!cameraHuntMode ? <button type="button" className={`mini-action ${selectedDetailTab === 'audit' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('audit')}>Hard Audit</button> : null}
                  <button type="button" className={`mini-action ${selectedDetailTab === 'redteam' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('redteam')}>{cameraHuntMode ? 'RED TEAM ATTACK' : 'Red Team'}</button>
                  {cameraHuntMode ? <button type="button" className={`mini-action ${selectedDetailTab === 'analysis' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('analysis')}>Analysis</button> : null}
                  {cameraHuntMode ? <button type="button" className={`mini-action ${selectedDetailTab === 'probe' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('probe')}>Probe</button> : null}
                  {cameraHuntMode ? <button type="button" className={`mini-action ${selectedDetailTab === 'layers' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('layers')}>Layers</button> : null}
                  <button type="button" className={`mini-action ${selectedDetailTab === 'intel' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('intel')}>Intel</button>
                  <button type="button" className={`mini-action ${selectedDetailTab === 'fingerprint' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('fingerprint')}>Fingerprint</button>
                  <button type="button" className={`mini-action ${selectedDetailTab === 'services' ? 'active' : ''}`} onClick={() => setSelectedDetailTab('services')}>Services</button>
                </div>
                {selectedDetailTab === 'core' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">{cameraHuntMode ? 'Camera Lead' : 'Core'}</div>
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Lead' : 'SSID'}</strong><span>{cameraHuntMode ? getCameraLeadIdentity(selectedNetwork) : (selectedNetwork.ssid || '<hidden>')}</span></div>
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Supporting ID' : 'BSSID'}</strong><span>{cameraHuntMode ? getCameraLeadSupportingId(selectedNetwork) : (selectedNetwork.bssid || 'Unresolved')}</span></div>
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Associated SSID</strong><span>{getCameraLeadAssociatedSsid(selectedNetwork)}</span></div> : null}
                      <div className="ssid-detail-row"><strong>Vendor</strong><span>{formatVendorCountry(selectedNetwork)}</span></div>
                      <div className="ssid-detail-row"><strong>Channel</strong><span>{selectedNetwork.channel || '--'} / {selectedNetwork.band || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Type</strong><span>{cameraHuntMode ? getCameraLeadLabel(selectedNetwork) : getPredictedNetworkLabel(selectedNetwork)}</span></div>
                      <div className="ssid-detail-row"><strong>Role</strong><span>{selectedNetwork.fingerprint?.role || '--'}</span></div>
                    </div>
                  </div>
                ) : null}
                {selectedDetailTab === 'evidence' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">{cameraHuntMode ? 'Camera Evidence' : 'Security & Evidence'}</div>
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Classification' : 'Exposure'}</strong><span>{cameraHuntMode ? (selectedNetwork.camera_detection?.classification || '--') : getExposureSummary(selectedNetwork)}</span></div>
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Confidence' : 'Security'}</strong><span>{cameraHuntMode ? `${selectedNetwork.camera_detection?.score ?? '--'} / 100` : (selectedNetwork.security || '--')}</span></div>
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Confirmation</strong><span>{formatCameraConfirmationLevel(selectedNetwork.camera_confirmation?.level)} · {selectedNetwork.camera_confirmation?.transport_path || 'unknown'}</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Hard Audit</strong><span>{getHardAuditStatus(selectedNetwork).label} · {getHardAuditStatus(selectedNetwork).detail}</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Outcome</strong><span>{formatCameraOutcomeClass(getCameraVisualAcquisition(selectedNetwork)?.outcome_class)}{getCameraVisualAcquisition(selectedNetwork)?.summary ? ` · ${getCameraVisualAcquisition(selectedNetwork).summary}` : ''}</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Video/Image Proof</strong><span>{selectedNetwork.active_fingerprint?.summary?.video_or_image_proof ? `${selectedNetwork.active_fingerprint.summary.visual_artifact_count || 0} artifact${Number(selectedNetwork.active_fingerprint.summary.visual_artifact_count || 0) === 1 ? '' : 's'} retained` : (selectedNetwork.active_fingerprint ? 'not captured' : 'not probed')}</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Cloud Leak Audit</strong><span>{formatCameraCloudLeakage(selectedNetwork)}</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Cloud Evidence Mode</strong><span>{formatCloudCameraEvidence(selectedNetwork)}</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Next Evidence</strong><span>{(selectedNetwork.cloud_camera_evidence?.required_evidence || []).slice(0, 2).join(' · ') || '--'}</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Probe Hits</strong><span>{Number(selectedNetwork.active_fingerprint?.summary?.http_hits || 0) + Number(selectedNetwork.active_fingerprint?.summary?.onvif_hits || 0) + Number(selectedNetwork.active_fingerprint?.summary?.rtsp_hits || 0) + Number(selectedNetwork.active_fingerprint?.summary?.snapshot_hits || 0)} positives</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Evidence Policy</strong><span>{`${getCameraEvidencePolicy(selectedNetwork)?.counts?.visual_evidence ?? 0} visual · ${getCameraEvidencePolicy(selectedNetwork)?.counts?.packet_evidence ?? 0} packet · ${getCameraEvidencePolicy(selectedNetwork)?.counts?.protocol_evidence ?? 0} protocol · ${getCameraEvidencePolicy(selectedNetwork)?.counts?.owner_assisted_evidence ?? 0} owner-assisted`}</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Family Match</strong><span>{selectedNetwork.camera_detection?.family_match || '--'}{selectedNetwork.camera_detection?.family_match_confidence ? ` · ${selectedNetwork.camera_detection.family_match_confidence}` : ''}</span></div> : null}
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Behavior' : 'PMF'}</strong><span>{cameraHuntMode ? (selectedNetwork.camera_detection?.behavior || '--') : (String(selectedNetwork.pmf || '').toLowerCase() === 'true' ? 'enabled' : 'not seen')}</span></div>
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Mode</strong><span>{String(selectedNetwork.camera_detection?.detection_mode || '--').replaceAll('_', ' ')}</span></div> : null}
                      {!cameraHuntMode && handshakeAnalysisEnabled ? (
                        <div className="ssid-detail-row"><strong>Handshake</strong><span>{getHandshakeEvidenceState(selectedNetwork)} · {selectedNetwork.handshake_evidence?.frame_count ?? selectedNetwork.handshake_eapol_count ?? selectedNetwork.eapol_count ?? 0} EAPOL</span></div>
                      ) : null}
                      {!cameraHuntMode ? (
                        <div className="ssid-detail-row"><strong>DDI State</strong><span>{getDdiStateLabel(selectedNetwork.ddi_resolution?.resolution_state)}{selectedNetwork.ddi_resolution?.validated_candidates?.[0]?.candidate_ip ? ` · ${selectedNetwork.ddi_resolution.validated_candidates[0].candidate_ip}` : ''}</span></div>
                      ) : null}
                      {!cameraHuntMode ? (
                        <div className="ssid-detail-row"><strong>DDI Candidates</strong><span>{(selectedNetwork.ddi_resolution?.candidate_ips || []).slice(0, 2).map((item) => `${item.candidate_ip} ${item.confidence || 'LOW'}`).join(' · ') || 'no candidate IP retained'}</span></div>
                      ) : null}
                      {!cameraHuntMode ? (
                        <div className="ssid-detail-row"><strong>DDI Explain</strong><span>{selectedNetwork.ddi_resolution?.explanation || 'No DDI explanation retained yet.'}</span></div>
                      ) : null}
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Evidence' : 'WPS'}</strong><span>{cameraHuntMode ? getCameraLeadEvidence(selectedNetwork) : (selectedNetwork.security_posture?.wps_present ? 'observable' : 'not seen')}</span></div>
                      {!cameraHuntMode ? (
                        <div className="ssid-detail-row"><strong>Artifacts</strong><span>{getEvidenceArtifacts(selectedNetwork).length ? `${getEvidenceArtifacts(selectedNetwork).length} retained` : 'no retained artifacts yet'}</span></div>
                      ) : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Suppression</strong><span>{(selectedNetwork.camera_detection?.suppression_reasons || selectedNetwork.pipeline_suppression_reasons || []).slice(0, 2).join(' · ') || '--'}</span></div> : null}
                      {!cameraHuntMode ? <div className="ssid-detail-row"><strong>Segmentation</strong><span>{selectedNetwork.security_posture?.segmentation || '--'}</span></div> : null}
                      {!cameraHuntMode ? <div className="ssid-detail-row"><strong>Password Risk</strong><span>{selectedNetwork.password_risk?.risk || '--'} · {selectedNetwork.password_risk?.score ?? '--'} / 100</span></div> : null}
                      {!cameraHuntMode ? <div className="ssid-detail-row"><strong>Auth Evidence</strong><span>{selectedNetwork.authentication_evidence?.quality || 'NONE'} · {selectedNetwork.authentication_evidence?.eapol_frame_count ?? 0} EAPOL</span></div> : null}
                      {!cameraHuntMode ? <div className="ssid-detail-row"><strong>Opportunity</strong><span>{selectedNetwork.observation_opportunity?.level || 'LOW'} · {selectedNetwork.observation_opportunity?.score ?? 0} / 100</span></div> : null}
                    </div>
                    {!cameraHuntMode ? (
                      (() => {
                        const destinationOverride = serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null
                        const destination = getDestinationAnalysis(selectedNetwork, destinationOverride)
                        const endpoints = destination?.external_endpoints || []
                        const summary = getExternalDestinationSummary(selectedNetwork, destinationOverride)
                        return (
                          <>
                            <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>External Destinations</div>
                            <div className="table-secondary">{summary.primary}</div>
                            <div className="table-secondary">{destination?.assessment || summary.secondary}</div>
                            {endpoints.length ? (
                              <div className="camera-hunt-evidence-list">
                                {endpoints.slice(0, 6).map((endpoint) => (
                                  <div key={`edda-evidence:${endpoint.ip}`} className="camera-hunt-evidence-row active">
                                    <strong>{`${countryCodeToFlag(endpoint?.country) ? `${countryCodeToFlag(endpoint?.country)} ` : ''}${endpoint?.country || 'UNKNOWN'} · ${endpoint?.ip || '--'}`}</strong>
                                    <span>{endpoint?.org || endpoint?.asn || endpoint?.domain || '--'}</span>
                                    <small>{`${endpoint?.behavior || 'external_session'} · ${(endpoint?.domains || []).slice(0, 2).join(', ') || (endpoint?.tls_server_names || []).slice(0, 2).join(', ') || (endpoint?.http_hosts || []).slice(0, 2).join(', ') || 'no domain retained'} · ${(endpoint?.protocols || []).join(', ') || endpoint?.protocol || 'IP'}`}</small>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', width: '100%', marginTop: '0.35rem' }}>
                                      <div className="scan-progress-track" style={{ width: '7rem' }} aria-hidden="true">
                                        <div className="scan-progress-fill" style={{ width: `${getEndpointConfidencePercent(endpoint)}%` }} />
                                      </div>
                                      <small>{endpoint?.confidence || 'LOW'} · {endpoint?.confidence_score ?? 0} / 100 · {endpoint?.packet_count ?? 0} pkts · {fmtBytes(endpoint?.total_bytes || 0)}</small>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div className="empty-box">{summary.secondary}</div>
                            )}
                            <div className="table-secondary">{`Limitations: ${getExternalDestinationLimitations(selectedNetwork, destinationOverride).join(' · ')}`}</div>
                          </>
                        )
                      })()
                    ) : null}
                    <div className="table-secondary">{cameraHuntMode ? ((selectedNetwork.camera_detection?.indicators || []).join(' · ') || 'No strong camera indicators retained yet.') : (selectedNetwork.security_posture?.summary || getPostureDetail(selectedNetwork))}</div>
                    {cameraHuntMode ? <div className="table-secondary">{selectedNetwork.camera_confirmation?.summary || 'No confirmation model retained yet.'}</div> : null}
                    {cameraHuntMode ? <div className="table-secondary">{selectedNetwork.active_fingerprint?.summary?.camera_positive_summary || 'No active probe summary retained yet.'}</div> : null}
                    {cameraHuntMode ? <div className="table-secondary">{selectedNetwork.camera_detection?.vendor_explainer || 'No vendor-specific explainer retained.'}</div> : null}
                    {cameraHuntMode ? <div className="table-secondary">{(selectedNetwork.camera_confirmation?.blockers || []).join(' · ') || 'No confirmation blockers retained.'}</div> : null}
                    {cameraHuntMode ? <div className="table-secondary">{(selectedNetwork.camera_detection?.suppression_reasons || selectedNetwork.pipeline_suppression_reasons || []).join(' · ') || 'No suppression penalties retained.'}</div> : null}
                    {!cameraHuntMode ? <div className="table-secondary">{getPasswordRiskSummary(selectedNetwork)}</div> : null}
                    {!cameraHuntMode ? <div className="table-secondary">{selectedNetwork.observation_opportunity?.summary || 'No observation opportunity cues retained yet.'}</div> : null}
                  </div>
                ) : null}
                {selectedDetailTab === 'assessment' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">Device Assessment v1</div>
                    <div className="table-secondary">{selectedNetwork.device_assessment?.summary || 'No structured assessment retained yet.'}</div>
                    <div className="table-secondary">Overall confidence: {selectedNetwork.device_assessment?.overall_confidence || 'LOW'}</div>
                    {getAssessmentSections(selectedNetwork).length ? (
                      <div className="assessment-section-list">
                        {getAssessmentSections(selectedNetwork).map(([sectionKey, section]) => (
                          <div key={sectionKey} className="assessment-section-card">
                            <div className="ranking-head">
                              <strong>{section?.title || sectionKey}</strong>
                              <span>{section?.confidence || 'LOW'}</span>
                            </div>
                            <div className="table-secondary">{section?.summary || 'No section summary retained.'}</div>
                            <div className="detail-grid ssid-detail-grid tight assessment-answer-grid">
                              {(section?.answers || []).map((answer) => (
                                <div key={`${sectionKey}:${answer?.key || answer?.question}`} className="ssid-detail-row assessment-answer-row">
                                  <strong>{answer?.question || answer?.key || '--'}</strong>
                                  <span>{formatAssessmentValue(answer)}</span>
                                  <small>{answer?.confidence || 'LOW'}{answer?.unknown_reason ? ` · ${answer.unknown_reason}` : ''}</small>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="empty-box">No structured device assessment is attached to this lead yet.</div>
                    )}
                  </div>
                ) : null}
                {selectedDetailTab === 'stream' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    {(() => {
                      const streamEntity = cameraHuntMode ? (inspectedNetwork || selectedNetwork) : selectedNetwork
                      const streamArtifacts = getCameraVisualArtifacts(streamEntity)
                      const primaryStreamArtifact = getPrimaryCameraMediaArtifact(streamEntity)
                      const streamMediaEvidence = getCameraMediaEvidenceLevel(streamEntity)
                      const captureMonitor = getCameraCaptureMonitor(streamEntity, hardAuditActive, hardAuditTimer)
                      const topologyNodes = getCameraTopologyNodes(streamEntity)
                      const protocolHintSummary = getCameraProtocolHintSummary(streamEntity)
                      const serviceHintSummary = getCameraServiceHintSummary(streamEntity)
                      const sessionSnapshot = getOperatorLeadSnapshot(streamEntity)
                      return (
                        <>
                    <div className="snapshot-head">Stream State</div>
                    {cameraHuntMode ? (
                      <>
                        <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Authorized Media Evidence</div>
                        <div className="detail-grid ssid-detail-grid tight">
                          <div className="ssid-detail-row"><strong>Evidence Level</strong><span><Pill text={streamMediaEvidence.label} tone={streamMediaEvidence.tone} /></span></div>
                          <div className="ssid-detail-row"><strong>Action</strong><span>{cameraLeadHardAuditBusy ? 'running hard audit' : 'ready for hard audit'}</span></div>
                          <div className="ssid-detail-row"><strong>Capture Status</strong><span>{captureMonitor.statusLabel} · {captureMonitor.stageLabel}</span></div>
                          <div className="ssid-detail-row"><strong>Lead Type</strong><span>{getCameraLeadKindLabel(streamEntity)} · {getCameraLeadAssociatedSsid(streamEntity)}</span></div>
                          <div className="ssid-detail-row"><strong>Vendor / OUI</strong><span>{streamEntity.vendor || streamEntity.fingerprint?.vendor_family || '--'} · {getLeadOui(streamEntity)}</span></div>
                          <div className="ssid-detail-row"><strong>TLS / DNS Hints</strong><span>{protocolHintSummary}</span></div>
                          <div className="ssid-detail-row"><strong>Service Exposure</strong><span>{serviceHintSummary}</span></div>
                          <div className="ssid-detail-row"><strong>Session Context</strong><span>{sessionSnapshot}</span></div>
                          <div className="ssid-detail-row"><strong>Visual Artifacts</strong><span>{streamArtifacts.length} retained</span></div>
                          <div className="ssid-detail-row"><strong>Truth State</strong><span>{streamEntity.hard_audit?.video_truth_test?.status || getCameraVideoTruth(streamEntity).video_confirmed || 'not run'}</span></div>
                        </div>
                        <div className={`camera-inline-hard-audit ${hardAuditActive ? 'audit-live' : ''}`} style={{ marginTop: '0.7rem' }}>
                          <div className="camera-inline-hard-audit-head">
                            <strong>Capture Progress</strong>
                            <span>{captureMonitor.timer.label} · {captureMonitor.stageLabel}</span>
                          </div>
                          <div className={`scan-progress-track camera-capture-progress-track ${hardAuditActive ? 'active' : ''}`} aria-hidden="true">
                            <div className="scan-progress-fill camera-capture-progress-fill" style={{ width: `${captureMonitor.progress}%` }} />
                          </div>
                          <div className="table-secondary">{captureMonitor.timer.summary}</div>
                          <div className="table-secondary">{captureMonitor.detail}</div>
                          <div className="table-secondary">{captureMonitor.promptMessage}</div>
                        </div>
                        <div className="camera-inline-hard-audit" style={{ marginTop: '0.7rem' }}>
                          <div className="camera-inline-hard-audit-head">
                            <strong>Capture Topology</strong>
                            <span>{topologyNodes.length} nodes</span>
                          </div>
                          <div className="camera-inline-hard-audit-strip">
                            {topologyNodes.map((node) => (
                              <div key={`capture-topology:${node.id}`} className={`camera-inline-hard-node ${node.state}`}>
                                <strong>{node.label}</strong>
                                <span>{node.detail}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div className="table-secondary">{streamMediaEvidence.summary}</div>
                        <div className="table-secondary">{streamEntity.hard_audit?.video_truth_test?.summary || 'Run Hard Audit to test the retained stream/snapshot path and save real media artifacts when they are returned.'}</div>
                        {primaryStreamArtifact ? (
                          <div className="camera-inline-visual-board" style={{ marginTop: '0.7rem' }}>
                            <div className="camera-inline-visual-head">
                              <strong>Saved Media Evidence</strong>
                              <span>{primaryStreamArtifact.savedLabel}</span>
                            </div>
                            <div className="camera-inline-visual-card camera-inline-visual-card-primary">
                              {primaryStreamArtifact.previewKind === 'image' ? (
                                <a href={primaryStreamArtifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link">
                                  <img src={primaryStreamArtifact.url} alt="Saved camera snapshot evidence" className="camera-inline-visual-preview camera-inline-visual-preview-primary" loading="lazy" />
                                </a>
                              ) : primaryStreamArtifact.previewKind === 'video' ? (
                                <a href={primaryStreamArtifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link">
                                  <video className="camera-inline-visual-preview camera-inline-visual-preview-primary" src={primaryStreamArtifact.url} controls preload="metadata" />
                                </a>
                              ) : (
                                <a href={primaryStreamArtifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link camera-inline-visual-fallback camera-inline-visual-fallback-primary">
                                  Open Saved Artifact
                                </a>
                              )}
                              <div className="camera-inline-visual-meta">
                                <strong>{primaryStreamArtifact.savedLabel}</strong>
                                <span>{primaryStreamArtifact.targetIp || primaryStreamArtifact.protocol || 'artifact'}</span>
                                <small>{primaryStreamArtifact.path}</small>
                              </div>
                            </div>
                          </div>
                        ) : null}
                        <div className="camera-inline-actions" style={{ marginTop: '0.7rem' }}>
                          <button className={`mini-action danger ${cameraLeadHardAuditBusy ? 'active' : ''}`} onClick={handleHardAuditCameraLead} disabled={cameraLeadHardAuditBusy || cameraLeadVideoTruthBusy || cameraLeadProbeBusy || cameraLeadAnalysisBusy || cameraLeadLayerAuditBusy || redTeamBusy || cameraLeadInteractionLocked}>
                            {cameraLeadHardAuditBusy ? 'Hard Auditing...' : 'Hard Audit'}
                          </button>
                        </div>
                        {streamArtifacts.length ? (
                          <div className="camera-inline-visual-board" style={{ marginTop: '0.7rem' }}>
                            <div className="camera-inline-visual-head">
                              <strong>Retained Media</strong>
                              <span>{streamArtifacts.length} artifact{streamArtifacts.length === 1 ? '' : 's'}</span>
                            </div>
                            <div className="camera-inline-visual-grid">
                              {streamArtifacts.slice(0, 3).map((artifact) => (
                                <div key={`detail-stream-artifact:${artifact.path}`} className="camera-inline-visual-card">
                                  {artifact.previewKind === 'image' ? (
                                    <a href={artifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link">
                                      <img src={artifact.url} alt="Camera media evidence artifact" className="camera-inline-visual-preview" loading="lazy" />
                                    </a>
                                  ) : artifact.previewKind === 'video' ? (
                                    <a href={artifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link">
                                      <video className="camera-inline-visual-preview" src={artifact.url} controls preload="metadata" />
                                    </a>
                                  ) : (
                                    <a href={artifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link camera-inline-visual-fallback">
                                      Open Artifact
                                    </a>
                                  )}
                                  <div className="camera-inline-visual-meta">
                                    <strong>{artifact.savedLabel}</strong>
                                    <span>{artifact.targetIp || artifact.protocol || 'artifact'}</span>
                                    <span>{artifact.pathHint || artifact.path.split('/').slice(-1)[0]}</span>
                                    <small>{artifact.hash ? artifact.hash.slice(0, 18) : artifact.path}</small>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        ) : null}
                      </>
                    ) : null}
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>Camera Verdict</strong><span>{formatCameraConfirmationLevel(selectedNetwork.camera_confirmation?.level)} · {selectedNetwork.camera_confirmation?.sensor_verdict || 'unconfirmed_sensor_use'}</span></div>
                      <div className="ssid-detail-row"><strong>Outcome</strong><span>{formatCameraOutcomeClass(getCameraVisualAcquisition(selectedNetwork)?.outcome_class)}{getCameraVisualAcquisition(selectedNetwork)?.summary ? ` · ${getCameraVisualAcquisition(selectedNetwork).summary}` : ''}</span></div>
                      <div className="ssid-detail-row"><strong>Vendor Plugin</strong><span>{getCameraVisualAcquisition(selectedNetwork)?.vendor_profile?.label || 'Generic camera'}{getCameraVisualAcquisition(selectedNetwork)?.vendor_profile?.plugin_id ? ` · ${getCameraVisualAcquisition(selectedNetwork).vendor_profile.plugin_id}` : ''}</span></div>
                      <div className="ssid-detail-row"><strong>Path</strong><span>{selectedNetwork.camera_confirmation?.transport_path || 'unknown'}</span></div>
                      <div className="ssid-detail-row"><strong>State</strong><span>{formatStreamStateLabel(selectedNetwork.stream_state?.state || 'unknown')}</span></div>
                      <div className="ssid-detail-row"><strong>Confidence</strong><span>{selectedNetwork.stream_state?.confidence || 'LOW'}</span></div>
                      <div className="ssid-detail-row"><strong>Transport</strong><span>{selectedNetwork.stream_state?.transport || 'unknown'}</span></div>
                      <div className="ssid-detail-row"><strong>Local Protocols</strong><span>{(selectedNetwork.camera_confirmation?.local_protocols || []).join(', ') || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Cloud Protocols</strong><span>{(selectedNetwork.camera_confirmation?.cloud_protocols || []).join(', ') || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Probe Candidate IPs</strong><span>{getLeadCandidateIps(selectedNetwork).length ? (
                        <span className="ip-chip-row">
                          {getLeadCandidateIps(selectedNetwork).map((ip) => (
                            <button
                              key={ip}
                              type="button"
                              className="ip-chip"
                              title={`Copy ${ip}`}
                              onClick={() => copyText(ip)}
                            >
                              {ip}
                            </button>
                          ))}
                        </span>
                      ) : '--'}</span></div>
                      <div className="ssid-detail-row"><strong>IP Inference</strong><span>{getLeadCandidateIps(selectedNetwork).length ? 'candidate IPs retained' : 'no IP inferred yet'}</span></div>
                      <div className="ssid-detail-row"><strong>Protocols</strong><span>{(selectedNetwork.stream_state?.protocols || []).join(', ') || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>HTTP</strong><span>{selectedNetwork.stream_state?.metrics?.http_confidence ?? 0} / 100</span></div>
                      <div className="ssid-detail-row"><strong>RTSP</strong><span>{selectedNetwork.stream_state?.metrics?.rtsp_confidence ?? 0} / 100</span></div>
                      <div className="ssid-detail-row"><strong>TLS</strong><span>{selectedNetwork.stream_state?.metrics?.tls_confidence ?? 0} / 100</span></div>
                      <div className="ssid-detail-row"><strong>Bytes</strong><span>{selectedNetwork.stream_state?.metrics?.total_bytes ?? 0}</span></div>
                      <div className="ssid-detail-row"><strong>Packets</strong><span>{selectedNetwork.stream_state?.metrics?.total_packets ?? 0}</span></div>
                      <div className="ssid-detail-row"><strong>Flow</strong><span>{selectedNetwork.stream_state?.metrics?.long_lived_flow ? 'long-lived' : 'short'} · up {Math.round(Number(selectedNetwork.stream_state?.metrics?.uplink_ratio || 0) * 100)}%</span></div>
                      <div className="ssid-detail-row"><strong>EAPOL</strong><span>{selectedNetwork.stream_state?.metrics?.eapol_frame_count ?? 0}</span></div>
                      <div className="ssid-detail-row"><strong>Artifacts</strong><span>{selectedNetwork.stream_state?.metrics?.object_hits ?? 0}</span></div>
                      <div className="ssid-detail-row"><strong>Bridge</strong><span>{(getCameraVisualAcquisition(selectedNetwork)?.bridge_targets || []).slice(0, 2).join(' · ') || 'not retained'}</span></div>
                      <div className="ssid-detail-row"><strong>Recorder Replay</strong><span>{getCameraVisualAcquisition(selectedNetwork)?.inputs?.recorder_replay?.detail || 'not retained'}</span></div>
                    </div>
                    <div className="table-secondary">{selectedNetwork.camera_confirmation?.summary || 'No camera confirmation summary retained yet.'}</div>
                    <div className="table-secondary">{getCameraVisualAcquisition(selectedNetwork)?.summary || 'No visual acquisition summary retained yet.'}</div>
                    <div className="table-secondary">{getLeadCandidateIps(selectedNetwork).length ? `Candidate IPs: ${getLeadCandidateIps(selectedNetwork).join(', ')}` : getLeadIpReason(selectedNetwork)}</div>
                    <div className="table-secondary">{(selectedNetwork.camera_confirmation?.identity_reasons || []).join(' · ') || 'No identity-level confirmation retained.'}</div>
                    <div className="table-secondary">{(selectedNetwork.camera_confirmation?.service_reasons || []).join(' · ') || 'No service-level confirmation retained.'}</div>
                    <div className="table-secondary">{(selectedNetwork.camera_confirmation?.behavior_reasons || []).join(' · ') || 'No scenario-based confirmation retained.'}</div>
                    <div className="table-secondary">{selectedNetwork.camera_confirmation?.next_step || 'No confirmation workflow guidance retained.'}</div>
                    <div className="table-secondary">{selectedNetwork.stream_state?.summary || 'No stream-state summary retained yet.'}</div>
                    <div className="table-secondary">{(getCameraVisualAcquisition(selectedNetwork)?.local_capture_paths || []).join(' · ') || 'No vendor-local capture path retained.'}</div>
                    <div className="table-secondary">{(getCameraVisualAcquisition(selectedNetwork)?.owner_assisted_workflow || []).join(' · ') || 'No owner-assisted workflow retained.'}</div>
                    <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Scenario Delta</div>
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>Current Mode</strong><span>{formatScenarioLabel(selectedNetwork.scenario_delta?.current_mode || 'passive_observation')}</span></div>
                      <div className="ssid-detail-row"><strong>Observed Scenarios</strong><span>{(selectedNetwork.scenario_delta?.available_scenarios || []).map((value) => formatScenarioLabel(value)).join(', ') || 'Current only'}</span></div>
                      <div className="ssid-detail-row"><strong>Idle vs Live</strong><span>{selectedNetwork.scenario_delta?.idle_vs_live_view || 'UNKNOWN'}</span></div>
                      <div className="ssid-detail-row"><strong>Motion vs Idle</strong><span>{selectedNetwork.scenario_delta?.motion_vs_idle || 'UNKNOWN'}</span></div>
                      <div className="ssid-detail-row"><strong>App Open Delta</strong><span>{selectedNetwork.scenario_delta?.app_open_delta || 'UNKNOWN'}</span></div>
                      <div className="ssid-detail-row"><strong>Observed Behavior</strong><span>{selectedNetwork.scenario_delta?.observed_behavior || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Cloud Endpoints</strong><span>{(selectedNetwork.scenario_delta?.cloud_endpoints || []).slice(0, 2).join(', ') || '--'}</span></div>
                    </div>
                    <div className="table-secondary">{selectedNetwork.scenario_delta?.summary || 'No scenario delta summary retained yet.'}</div>
                    <div className="table-secondary">{selectedNetwork.scenario_delta?.comparisons?.idle_vs_live_view?.summary || 'Idle vs live-view comparison not retained yet.'}</div>
                    <div className="table-secondary">{selectedNetwork.scenario_delta?.comparisons?.motion_vs_idle?.summary || 'Motion delta comparison not retained yet.'}</div>
                    <div className="table-secondary">{selectedNetwork.scenario_delta?.comparisons?.app_open_delta?.summary || 'App-open comparison not retained yet.'}</div>
                    <div className="table-secondary">{selectedNetwork.scenario_delta?.next_step || 'No next-step guidance retained.'}</div>
                        </>
                      )
                    })()}
                  </div>
                ) : null}
                {!cameraHuntMode && selectedDetailTab === 'audit' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">Hard Audit</div>
                    {(() => {
                      const audit = getServiceAudit(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null)
                      const ddi = getDdiResolution(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null)
                      const ports = audit?.ports || {}
                      const services = audit?.services || {}
                      const trace = audit?.test_trace || []
                      const completeness = audit?.port_audit_completeness || {}
                      const ddiEvidence = ddi?.evidence || []
                      const ddiNegatives = ddi?.negative_evidence || []
                      const artifacts = getEvidenceArtifacts(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null)
                      const destination = getDestinationAnalysis(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null)
                      const destinationSummary = getExternalDestinationSummary(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null)
                      return audit && Object.keys(audit).length ? (
                        <>
                          <div className="detail-grid ssid-detail-grid tight">
                            <div className="ssid-detail-row"><strong>Status</strong><span>{getServiceAuditStatus(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null).label} · {getServiceAuditStatus(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null).detail}</span></div>
                            <div className="ssid-detail-row"><strong>DDI State</strong><span>{getDdiStateLabel(ddi?.resolution_state)}{ddi?.validated_candidates?.length ? ` · ${ddi.validated_candidates.map((item) => item.candidate_ip).slice(0, 2).join(', ')}` : ''}</span></div>
                            <div className="ssid-detail-row"><strong>Target IP</strong><span>{audit?.target_validation?.target_ip || ddi?.validated_candidates?.[0]?.candidate_ip || '--'}</span></div>
                            <div className="ssid-detail-row"><strong>Validation</strong><span>{audit?.target_validation?.validation_method || 'ddi_evidence_policy'} · {Math.round(Number((audit?.target_validation?.confidence_score ?? ddi?.confidence_summary?.highest_score ?? 0)) * 100)}%</span></div>
                            <div className="ssid-detail-row"><strong>Exposure</strong><span>{String(audit?.service_exposure_classification || 'UNKNOWN').replaceAll('_', ' ')}</span></div>
                            <div className="ssid-detail-row"><strong>Ports Tested</strong><span>{completeness?.ports_tested ?? 0}</span></div>
                            <div className="ssid-detail-row"><strong>Services Identified</strong><span>{completeness?.services_identified ?? 0}</span></div>
                            <div className="ssid-detail-row"><strong>Auth Surfaces</strong><span>{completeness?.auth_surfaces_checked ?? 0}</span></div>
                            <div className="ssid-detail-row"><strong>Completeness</strong><span>{completeness?.level || 'LOW'}</span></div>
                            <div className="ssid-detail-row"><strong>External Endpoints</strong><span>{destination?.summary?.external_endpoint_count ?? 0}</span></div>
                            <div className="ssid-detail-row"><strong>External Summary</strong><span>{destinationSummary.primary}</span></div>
                          </div>
                          <div className="table-secondary">{ddi?.explanation || audit?.target_validation?.explanation || 'No DDI explanation retained.'}</div>
                          <div className="table-secondary">{audit?.final_verdict?.explanation || 'No final verdict retained.'}</div>
                          <div className="table-secondary">{completeness?.reason || 'No audit completeness reason retained.'}</div>
                          <div className="table-secondary">{destination?.assessment || destinationSummary.secondary}</div>
                          <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>External Destinations</div>
                          <div className="camera-hunt-evidence-list">
                            {(destination?.external_endpoints || []).slice(0, 8).map((endpoint) => (
                              <div key={`audit-edda:${endpoint.ip}`} className="camera-hunt-evidence-row active">
                                <strong>{`${countryCodeToFlag(endpoint?.country) ? `${countryCodeToFlag(endpoint?.country)} ` : ''}${endpoint?.country || 'UNKNOWN'} · ${endpoint?.ip || '--'}`}</strong>
                                <span>{endpoint?.org || endpoint?.asn || endpoint?.domain || '--'}</span>
                                <small>{`${endpoint?.behavior || 'external_session'} · ${(endpoint?.domains || []).slice(0, 2).join(', ') || (endpoint?.tls_server_names || []).slice(0, 2).join(', ') || (endpoint?.http_hosts || []).slice(0, 2).join(', ') || 'no domain retained'} · ports ${(endpoint?.observed_ports || []).join(', ') || '--'}`}</small>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', width: '100%', marginTop: '0.35rem' }}>
                                  <div className="scan-progress-track" style={{ width: '7rem' }} aria-hidden="true">
                                    <div className="scan-progress-fill" style={{ width: `${getEndpointConfidencePercent(endpoint)}%` }} />
                                  </div>
                                  <small>{endpoint?.confidence || 'LOW'} · {endpoint?.confidence_score ?? 0} / 100 · {endpoint?.packet_count ?? 0} pkts · {fmtBytes(endpoint?.total_bytes || 0)}</small>
                                </div>
                              </div>
                            ))}
                            {!(destination?.external_endpoints || []).length ? (
                              <div className="camera-hunt-evidence-row">
                                <strong>External Destinations</strong>
                                <span>{destinationSummary.primary}</span>
                                <small>{destinationSummary.secondary}</small>
                              </div>
                            ) : null}
                          </div>
                          <div className="table-secondary">{`Limitations: ${getExternalDestinationLimitations(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null).join(' · ')}`}</div>
                          <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>DDI Candidates</div>
                          <div className="matrix-table-wrap compact analyst-table-wrap">
                            <table className="matrix-table coverage-table">
                              <thead>
                                <tr>
                                  <th>IP</th>
                                  <th>Status</th>
                                  <th>Confidence</th>
                                  <th>Sources</th>
                                  <th>Hints</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(ddi?.candidate_ips || []).slice(0, 8).map((item) => (
                                  <tr key={`ddi-candidate:${item.candidate_ip}`}>
                                    <td>{item.candidate_ip}</td>
                                    <td>{item.status || '--'}</td>
                                    <td>{item.confidence || '--'} · {Math.round(Number(item.confidence_score || 0) * 100)}%</td>
                                    <td>{(item.source_types || []).join(', ') || '--'}</td>
                                    <td>{(item.host_hints || []).slice(0, 2).join(' · ') || '--'}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>DDI Evidence</div>
                          <div className="camera-hunt-evidence-list">
                            {ddiEvidence.slice(0, 6).map((item, index) => (
                              <div key={`ddi-evidence:${index}:${item.frame_number || index}`} className="camera-hunt-evidence-row active">
                                <strong>{item.method || 'evidence'} · frame {item.frame_number || '--'}</strong>
                                <span>{item.timestamp || '--'}</span>
                                <small>{item.explanation || item.pcap_file || 'No explanation retained.'}</small>
                              </div>
                            ))}
                            {!ddiEvidence.length ? (
                              <div className="camera-hunt-evidence-row">
                                <strong>Negative Evidence</strong>
                                <span>{getDdiStateLabel(ddi?.resolution_state)}</span>
                                <small>{(ddiNegatives[0]?.explanation || ddi?.explanation || 'No DDI evidence retained.').toString()}</small>
                              </div>
                            ) : null}
                          </div>
                          <div className="matrix-table-wrap compact analyst-table-wrap">
                            <table className="matrix-table coverage-table">
                              <thead>
                                <tr>
                                  <th>Port</th>
                                  <th>State</th>
                                  <th>Service</th>
                                  <th>Access</th>
                                  <th>Evidence</th>
                                </tr>
                              </thead>
                              <tbody>
                                {Object.entries(ports).slice(0, 10).map(([port, entry]) => (
                                  <tr key={`audit-port:${port}`}>
                                    <td>{port}</td>
                                    <td>{entry?.state || '--'}</td>
                                    <td>{services?.[port]?.service_type || '--'}</td>
                                    <td>{services?.[port]?.access_posture || '--'}</td>
                                    <td>{entry?.evidence || services?.[port]?.evidence || '--'}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Evidence Artifacts</div>
                          <div className="camera-hunt-evidence-list">
                            {artifacts.slice(0, 6).map((artifact) => (
                              <div key={`wifi-artifact:${artifact.path}`} className="camera-hunt-evidence-row active">
                                <strong>{artifact.label}</strong>
                                <span><a href={artifact.url} target="_blank" rel="noreferrer">{artifact.path.split('/').slice(-1)[0]}</a></span>
                                <small>{artifact.path}</small>
                              </div>
                            ))}
                            {!artifacts.length ? (
                              <div className="camera-hunt-evidence-row">
                                <strong>Artifacts</strong>
                                <span>none retained</span>
                                <small>No WiFi Hunt evidence artifacts are linked to this target yet.</small>
                              </div>
                            ) : null}
                          </div>
                          <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Test Trace</div>
                          <div className="camera-hunt-evidence-list">
                            {trace.slice(0, 8).map((item) => (
                              <div key={item.test_id} className="camera-hunt-evidence-row active">
                                <strong>{item.test_type} · {item.target}</strong>
                                <span>{item.result}</span>
                                <small>{item.evidence} · {item.explanation}</small>
                              </div>
                            ))}
                          </div>
                        </>
                      ) : (
                        <div className="empty-box">Run `Hard Audit` on this device to validate open ports, identify services, classify access posture, correlate external destinations, and retain a full audit trace.</div>
                      )
                    })()}
                  </div>
                ) : null}
                {selectedDetailTab === 'redteam' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">{cameraHuntMode ? 'Hunt Camera Adversary Assessment' : 'WiFi MK7 Red Team Validation'}</div>
                    <div className="table-secondary">
                      {cameraHuntMode
                        ? 'Receive-only, evidence-backed camera adversary assessment for owned-lab activity. This pane runs replay-backed Wi-Fi attack evidence checks plus safe camera service validation to tell the operator whether the camera appears hardened, weak, exposed, or still inconclusive.'
                        : 'Receive-only, evidence-backed validation for owned-lab activity. This pane does not inject frames or start transmit tooling; it validates and retains real packet evidence already present in the active MK7 session.'}
                    </div>
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Selected Lead' : 'Selected Target'}</strong><span>{cameraHuntMode ? getCameraLeadIdentity(selectedNetwork) : (selectedNetwork.ssid || '<hidden>')}</span></div>
                      <div className="ssid-detail-row"><strong>BSSID</strong><span>{selectedNetwork.bssid || selectedNetwork.associated_bssid || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Client MAC</strong><span>{selectedNetwork.mac || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Channel</strong><span>{selectedNetwork.channel || '--'} / {selectedNetwork.band || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>PMF</strong><span>{String(selectedNetwork.pmf || '').toLowerCase() === 'true' ? 'enabled' : 'not seen'}</span></div>
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Assessment State' : 'Validation State'}</strong><span>{cameraHuntMode ? (adversaryReplayState?.state || 'IDLE') : (redTeamState?.state || 'IDLE')}</span></div>
                    </div>
                    <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Replay PCAP</div>
                    <div className="camera-hunt-evidence-list">
                      <div className={`camera-hunt-evidence-row ${redTeamPcapLoaded ? 'active' : ''}`}>
                        <strong>PCAP Loaded / Selected</strong>
                        <span>{redTeamPcapLoaded ? 'loaded' : 'not selected'}</span>
                        <small>{redTeamPcapLoaded ? effectiveReplayCapturePath : 'A retained WiFi MK7 capture will be auto-selected when available.'}</small>
                      </div>
                      <div className={`camera-hunt-evidence-row ${selectedReplayPcap?.path ? 'active' : ''}`}>
                        <strong>PCAP Source</strong>
                        <span>{redTeamPcapSourceLabel}</span>
                        <small>{selectedReplayPcap?.path ? `${selectedReplayPcap.path}${selectedReplayPcap?.packet_count ? ` · ${selectedReplayPcap.packet_count} packets` : ''}` : 'No approved replay capture is selected.'}</small>
                      </div>
                    </div>
                    {cameraHuntMode && cameraAssessmentConfirmPrompt ? (
                      <>
                        <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Assessment Gate</div>
                        <div className="camera-hunt-evidence-list">
                          <div className={`camera-hunt-evidence-row ${redTeamForm.confirmAuthorizedLab ? 'active' : ''}`}>
                            <strong>Lab Ownership Confirmation</strong>
                            <span>{redTeamForm.confirmAuthorizedLab ? 'confirmed' : 'required'}</span>
                            <small>Check the owned-lab confirmation below before running the camera assessment. Replay stays blocked until this is explicitly confirmed for the selected device.</small>
                          </div>
                        </div>
                      </>
                    ) : null}
                    <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Operator Readiness</div>
                    <div className="camera-hunt-evidence-list">
                      <div className={`camera-hunt-evidence-row ${status?.capture_active ? 'active' : ''}`}>
                        <strong>Capture Running</strong>
                        <span>{status?.capture_active ? 'ready' : 'blocked'}</span>
                        <small>{status?.capture_active ? 'Live MK7 packet capture is active.' : `Start a ${cameraHuntMode ? 'Hunt Camera' : 'WiFi MK7'} capture before running validation.`}</small>
                      </div>
                      <div className={`camera-hunt-evidence-row ${scanMode === 'lock' && lockedChannel ? 'active' : ''}`}>
                        <strong>Channel Lock</strong>
                        <span>{scanMode === 'lock' && lockedChannel ? `locked ${lockedChannel}` : 'blocked'}</span>
                        <small>{scanMode === 'lock' && lockedChannel ? 'Preflight can validate against the locked target channel.' : 'Switch WiFi MK7 to lock mode and lock the target channel for a deterministic evidence window.'}</small>
                      </div>
                      <div className={`camera-hunt-evidence-row ${selectedNetwork?.channel && String(selectedNetwork.channel) === String(lockedChannel || '') ? 'active' : ''}`}>
                        <strong>Target Channel Match</strong>
                        <span>{selectedNetwork?.channel && String(selectedNetwork.channel) === String(lockedChannel || '') ? 'ready' : 'review'}</span>
                        <small>{`target channel ${selectedNetwork?.channel || '--'} · locked channel ${lockedChannel || '--'}`}</small>
                      </div>
                      <div className={`camera-hunt-evidence-row ${Number(selectedNetwork?.authentication_evidence?.eapol_frame_count ?? selectedNetwork?.handshake_eapol_count ?? 0) > 0 ? 'active' : ''}`}>
                        <strong>EAPOL Visibility</strong>
                        <span>{Number(selectedNetwork?.authentication_evidence?.eapol_frame_count ?? selectedNetwork?.handshake_eapol_count ?? 0) > 0 ? 'present' : 'not yet seen'}</span>
                        <small>{`${selectedNetwork?.authentication_evidence?.eapol_frame_count ?? selectedNetwork?.handshake_eapol_count ?? 0} EAPOL frame(s) currently retained for this ${cameraHuntMode ? 'lead' : 'target'}.`}</small>
                      </div>
                    </div>
                    {!cameraHuntMode ? (
                      <>
                        <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Operator Actions</div>
                        <div className="pill-row">
                          <button
                            type="button"
                            className={`mini-action danger ${redTeamForm.actionType === 'deauth_evidence_probe' ? 'active' : ''}`}
                            onClick={() => handleSelectRedTeamAction('deauth_evidence_probe', 'Operator-selected deauth evidence validation.')}
                          >
                            Deauth Evidence
                          </button>
                          <button
                            type="button"
                            className={`mini-action ${redTeamForm.actionType === 'disassociation_evidence_probe' ? 'active' : ''}`}
                            onClick={() => handleSelectRedTeamAction('disassociation_evidence_probe', 'Operator-selected disassociation evidence validation.')}
                          >
                            Disassoc Evidence
                          </button>
                        </div>
                        <div className="table-secondary">
                          Primary action: <strong>{redTeamActionProfile.label}</strong> · filter <code>{redTeamActionProfile.filter}</code>
                        </div>
                        <div className={`guidance-item compact ${redTeamCanRun ? '' : 'soft-warning'}`}>
                          <strong>Operator Action Status:</strong>{' '}
                          {redTeamCanRun
                            ? `${redTeamActionProfile.label} is selected and ready to run for ${selectedNetwork?.ssid || selectedNetwork?.bssid || selectedNetwork?.mac || 'this target'}.`
                            : `Blocked until: ${redTeamRunBlockers.join(' / ')}`}
                        </div>
                        <div className="pill-row">
                          <label className="control-card compact" style={{ minWidth: '18rem' }}>
                            <span className="control-label">Action</span>
                            <select value={redTeamForm.actionType} onChange={(event) => setRedTeamForm((current) => ({ ...current, actionType: event.target.value }))}>
                              <option value="deauth_evidence_probe">Deauth Evidence Probe</option>
                              <option value="disassociation_evidence_probe">Disassociation Evidence Probe</option>
                            </select>
                          </label>
                          <label className="control-card compact" style={{ minWidth: '10rem' }}>
                            <span className="control-label">Channel</span>
                            <input type="number" min="0" max="196" value={redTeamForm.channel} onChange={(event) => setRedTeamForm((current) => ({ ...current, channel: event.target.value }))} />
                          </label>
                          <label className="control-card compact" style={{ minWidth: '10rem' }}>
                            <span className="control-label">Max Duration</span>
                            <input type="number" min="5" max="120" value={redTeamForm.maxDuration} onChange={(event) => setRedTeamForm((current) => ({ ...current, maxDuration: event.target.value }))} />
                          </label>
                          <label className="control-card compact" style={{ minWidth: '10rem' }}>
                            <span className="control-label">Max Frames</span>
                            <input type="number" min="1" max="10" value={redTeamForm.maxFrameCount} onChange={(event) => setRedTeamForm((current) => ({ ...current, maxFrameCount: event.target.value }))} />
                          </label>
                        </div>
                        <div className="pill-row">
                          <label className="control-card compact" style={{ minWidth: '12rem' }}>
                            <span className="control-label">Reason Code</span>
                            <input type="text" value={redTeamForm.reasonCode} onChange={(event) => setRedTeamForm((current) => ({ ...current, reasonCode: event.target.value }))} />
                          </label>
                          <label className="control-card compact" style={{ flex: '1 1 20rem' }}>
                            <span className="control-label">Operator Notes</span>
                            <input type="text" value={redTeamForm.notes} onChange={(event) => setRedTeamForm((current) => ({ ...current, notes: event.target.value }))} placeholder="owned-lab window / purpose" />
                          </label>
                        </div>
                      </>
                    ) : (
                      <div className="pill-row">
                        <label className="control-card compact" style={{ flex: '1 1 20rem' }}>
                          <span className="control-label">Assessment Notes</span>
                          <input type="text" value={redTeamForm.notes} onChange={(event) => setRedTeamForm((current) => ({ ...current, notes: event.target.value }))} placeholder="owned-lab camera assessment window / purpose" />
                        </label>
                      </div>
                    )}
                    <label className="guidance-item compact" style={{ marginTop: '0.7rem' }}>
                      <input
                        type="checkbox"
                        checked={redTeamForm.confirmAuthorizedLab}
                        onChange={(event) => {
                          const checked = event.target.checked
                          setRedTeamForm((current) => ({ ...current, confirmAuthorizedLab: checked }))
                          if (checked) {
                            setCameraAssessmentConfirmPrompt(false)
                            setOperatorNote(
                              cameraHuntMode
                                ? 'Owned-lab scope confirmed. Run Assessment is now enabled for this selected camera device.'
                                : 'Owned-lab scope confirmed. Run Validation is now enabled when live capture is active for this selected WiFi target.',
                            )
                          }
                        }}
                        style={{ marginRight: '0.55rem' }}
                      />
                      <strong>{cameraHuntMode ? 'Lab Owned: I confirm this selected camera/device belongs to my owned lab' : 'I confirm this is my owned lab network/device'}</strong>
                    </label>
                    <div className="pill-row">
                      {!cameraHuntMode ? (
                        <button type="button" className={`mini-action ${redTeamBusy ? 'active' : ''}`} onClick={handleRedTeamPreflight} disabled={redTeamBusy}>
                          {redTeamBusy ? 'Running...' : 'Run Preflight'}
                        </button>
                      ) : null}
                      <button
                        type="button"
                        className={`mini-action danger ${redTeamBusy ? 'active' : ''}`}
                        onClick={handleRunRedTeamValidation}
                        disabled={redTeamBusy || !redTeamCanRun}
                      >
                        {redTeamBusy ? (cameraHuntMode ? 'Assessing...' : 'Validating...') : (cameraHuntMode ? 'Run Assessment' : 'Run Validation')}
                      </button>
                    </div>
                    {!cameraHuntMode ? (
                      <>
                        <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Preflight Checklist</div>
                        <div className="camera-hunt-evidence-list">
                          {(redTeamState?.last_preflight?.checks || []).map((check) => (
                            <div key={`rt-preflight:${check.id}`} className={`camera-hunt-evidence-row ${check.ok ? 'active' : ''}`}>
                              <strong>{check.label}</strong>
                              <span>{check.ok ? 'pass' : 'block'}</span>
                              <small>{check.detail}</small>
                            </div>
                          ))}
                          {!(redTeamState?.last_preflight?.checks || []).length ? (
                            <div className="camera-hunt-evidence-row">
                              <strong>Preflight Idle</strong>
                              <span>not run</span>
                              <small>Run preflight to validate scope, target recency, active capture, channel lock, and evidence readiness for the selected target.</small>
                            </div>
                          ) : null}
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Assessment Scope</div>
                        <div className="camera-hunt-evidence-list">
                          <div className={`camera-hunt-evidence-row ${redTeamForm.confirmAuthorizedLab ? 'active' : ''}`}>
                            <strong>Owned-Lab Scope</strong>
                            <span>{redTeamForm.confirmAuthorizedLab ? 'confirmed' : 'required'}</span>
                            <small>Camera assessment runs only after the operator confirms the selected device belongs to the owned lab.</small>
                          </div>
                          <div className={`camera-hunt-evidence-row ${redTeamPcapLoaded ? 'active' : ''}`}>
                            <strong>Replay Evidence</strong>
                            <span>{redTeamPcapLoaded ? 'ready' : 'missing'}</span>
                            <small>The camera assessment uses retained PCAP evidence plus safe camera service validation. No WiFi adversary runbook is exposed in Hunt Camera.</small>
                          </div>
                        </div>
                      </>
                    )}
                    <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Result Badges</div>
                    <div className="pill-row">
                      {(redTeamState?.last_run?.result_badges || []).map((badge) => (
                        <Pill key={badge} text={badge} tone={getRedTeamBadgeTone(badge)} />
                      ))}
                      {!(redTeamState?.last_run?.result_badges || []).length ? <Pill text={redTeamState?.state || 'IDLE'} tone={getRedTeamBadgeTone(redTeamState?.state)} /> : null}
                    </div>
                    {!cameraHuntMode ? (
                      <>
                        <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Action Evidence Status</div>
                        <div className="camera-hunt-evidence-list">
                          <div className={`camera-hunt-evidence-row ${redTeamEvidenceIndicator.tone === 'green' ? 'active' : ''}`}>
                            <strong>{redTeamEvidenceIndicator.status}</strong>
                            <span>{redTeamActionProfile.label}</span>
                            <small>{redTeamEvidenceIndicator.summary}</small>
                          </div>
                          <div className="camera-hunt-evidence-row active">
                            <strong>Operator Readout</strong>
                            <span>{redTeamState?.last_run?.state || redTeamState?.state || 'IDLE'}</span>
                            <small>{redTeamEvidenceIndicator.detail}</small>
                          </div>
                        </div>
                      </>
                    ) : null}
                    <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Packet Evidence Counters</div>
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>Window Packets</strong><span>{redTeamState?.last_run?.packet_counters?.window_packets ?? 0}</span></div>
                      <div className="ssid-detail-row"><strong>Matching Frames</strong><span>{redTeamState?.last_run?.packet_counters?.matching_packets ?? 0}</span></div>
                      <div className="ssid-detail-row"><strong>EAPOL Packets</strong><span>{redTeamState?.last_run?.packet_counters?.eapol_packets ?? 0}</span></div>
                      <div className="ssid-detail-row"><strong>Effect</strong><span>{redTeamState?.last_run?.observed_effects?.effect_observed ? 'observed' : 'not observed'}</span></div>
                    </div>
                    {cameraHuntMode ? (
                      <>
                        <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Attack Verdict</div>
                        <div className="pill-row">
                          <Pill text={cameraAttackAssessment?.verdict || 'INCONCLUSIVE'} tone={cameraAttackAssessment?.tone || 'warning'} />
                        </div>
                        <div className="table-secondary">{cameraAttackAssessment?.summary || 'No camera adversary assessment has been computed yet.'}</div>
                        <div className="camera-hunt-evidence-list">
                          {(cameraAttackAssessment?.findings || []).map((finding, index) => (
                            <div key={`camera-attack-finding:${index}`} className="camera-hunt-evidence-row active">
                              <strong>{index === 0 ? 'Evidence' : index === 1 ? 'IP Evidence' : index === 2 ? 'Protocol Surface' : index === 3 ? 'Protection' : 'Camera Summary'}</strong>
                              <span>{cameraAttackAssessment?.verdict || 'INCONCLUSIVE'}</span>
                              <small>{finding}</small>
                            </div>
                          ))}
                        </div>
                      </>
                    ) : null}
                    <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Detection Mapping</div>
                    <div className="camera-hunt-evidence-list">
                      <div className="camera-hunt-evidence-row active">
                        <strong>{redTeamState?.last_run?.detection_mapping?.mapping?.expected_detection || redTeamActionProfile.expected}</strong>
                        <span>{redTeamState?.last_run?.detection_mapping?.wireshark_filter || redTeamActionProfile.filter}</span>
                        <small>{redTeamState?.last_run?.detection_mapping?.mapping?.defensive_control || redTeamActionProfile.defensive}</small>
                      </div>
                    </div>
                    <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Live Event Timeline</div>
                    <div className="camera-hunt-evidence-list">
                      {(redTeamState?.last_run?.timeline || []).map((item, index) => (
                        <div key={`rt-timeline:${index}:${item.state}`} className="camera-hunt-evidence-row active">
                          <strong>{item.state}</strong>
                          <span>{item.at || '--'}</span>
                          <small>{item.detail}</small>
                        </div>
                      ))}
                      {!(redTeamState?.last_run?.timeline || []).length ? (
                        <div className="camera-hunt-evidence-row">
                          <strong>Timeline Idle</strong>
                          <span>no run yet</span>
                          <small>The validation timeline will show preflight, evidence window build, and final observed-effect state.</small>
                        </div>
                      ) : null}
                    </div>
                    <div className="snapshot-head" style={{ marginTop: '0.7rem' }}>Evidence Artifacts</div>
                    <div className="camera-hunt-evidence-list">
                      {Object.entries(redTeamState?.last_run?.evidence_files || {}).map(([label, path]) => (
                        <div key={`rt-artifact:${label}`} className="camera-hunt-evidence-row active">
                          <strong>{label}</strong>
                          <span>{path ? <a href={`/api/wifi_mk7/artifact?path=${encodeURIComponent(path)}`} target="_blank" rel="noreferrer">{String(path).split('/').slice(-1)[0]}</a> : 'missing'}</span>
                          <small>{path || 'No retained path.'}</small>
                        </div>
                      ))}
                      {cameraHuntMode ? Object.entries(adversaryReplayState?.last_run?.evidence_files || {}).map(([label, path]) => (
                        <div key={`camera-rt-replay-artifact:${label}`} className="camera-hunt-evidence-row active">
                          <strong>{label}</strong>
                          <span>{path ? <a href={`/api/wifi_mk7/artifact?path=${encodeURIComponent(path)}`} target="_blank" rel="noreferrer">{String(path).split('/').slice(-1)[0]}</a> : 'missing'}</span>
                          <small>{path || 'No retained path.'}</small>
                        </div>
                      )) : null}
                      {!Object.keys(redTeamState?.last_run?.evidence_files || {}).length && !(cameraHuntMode && Object.keys(adversaryReplayState?.last_run?.evidence_files || {}).length) ? (
                        <div className="camera-hunt-evidence-row">
                          <strong>Artifacts</strong>
                          <span>none retained</span>
                          <small>Run validation to retain {cameraHuntMode ? 'camera red-team' : 'red-team'} evidence files under the active WiFi Hunt session.</small>
                        </div>
                      ) : null}
                    </div>
                  </div>
                ) : null}
                {cameraHuntMode && selectedDetailTab === 'analysis' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">30s Lead Analysis</div>
                    {cameraLeadAnalysis?.ok ? (
                      <>
                        <div className="detail-grid ssid-detail-grid tight">
                          <div className="ssid-detail-row"><strong>Status</strong><span>{cameraLeadAnalysis.observation_status || '--'}</span></div>
                          <div className="ssid-detail-row"><strong>Samples</strong><span>{cameraLeadAnalysis.analysis?.sample_count ?? 0} windows</span></div>
                          <div className="ssid-detail-row"><strong>Confidence</strong><span>avg {formatPercent(cameraLeadAnalysis.analysis?.avg_confidence || 0)} · max {formatPercent(cameraLeadAnalysis.analysis?.max_confidence || 0)}</span></div>
                          <div className="ssid-detail-row"><strong>Score</strong><span>avg {cameraLeadAnalysis.analysis?.avg_score ?? '--'} · max {cameraLeadAnalysis.analysis?.max_score ?? '--'}</span></div>
                          <div className="ssid-detail-row"><strong>Protocols</strong><span>{(cameraLeadAnalysis.analysis?.protocols || []).join(', ') || '--'}</span></div>
                          <div className="ssid-detail-row"><strong>Services</strong><span>{(cameraLeadAnalysis.analysis?.services || []).join(', ') || '--'}</span></div>
                          <div className="ssid-detail-row"><strong>Families</strong><span>{(cameraLeadAnalysis.analysis?.matched_families || []).join(', ') || '--'}</span></div>
                          <div className="ssid-detail-row"><strong>Packet Span</strong><span>{cameraLeadAnalysis.analysis?.packet_span?.min ?? 0} to {cameraLeadAnalysis.analysis?.packet_span?.max ?? 0}</span></div>
                          <div className="ssid-detail-row"><strong>Mode</strong><span>{String(selectedNetwork.camera_detection?.detection_mode || '--').replaceAll('_', ' ')}</span></div>
                          <div className="ssid-detail-row"><strong>mDNS/DNS</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.['mDNS/DNS'] ?? 0} / 100</span></div>
                          <div className="ssid-detail-row"><strong>HTTP</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.HTTP ?? 0} / 100</span></div>
                          <div className="ssid-detail-row"><strong>TLS</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.TLS ?? 0} / 100</span></div>
                          <div className="ssid-detail-row"><strong>RTSP</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.RTSP ?? 0} / 100</span></div>
                        </div>
                        <div className="table-secondary">{cameraLeadAnalysis.analysis?.latest_summary || 'No passive protocol summary retained.'}</div>
                        <div className="table-secondary">{(cameraLeadAnalysis.analysis?.indicators || []).join(' · ') || 'No strong camera indicators retained across this analysis window.'}</div>
                        <div className="table-secondary">{selectedNetwork.camera_detection?.vendor_explainer || 'No vendor-specific explainer retained.'}</div>
                        <div className="table-secondary">{cameraLeadAnalysis.analysis?.recommendation || 'No recommendation retained.'}</div>
                      </>
                    ) : (
                      <div className="empty-box">Run `Hard Audit` on this lead to execute probe, media capture, and layer classification in one pipeline.</div>
                    )}
                  </div>
                ) : null}
                {cameraHuntMode && selectedDetailTab === 'probe' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">Active Probe Workflow</div>
                    {cameraLeadProbe?.active_fingerprint ? (
                      <>
                        <div className="detail-grid ssid-detail-grid tight">
                          <div className="ssid-detail-row"><strong>Candidate IPs</strong><span>{(cameraLeadProbe.active_fingerprint?.candidate_ips || []).join(', ') || '--'}</span></div>
                          <div className="ssid-detail-row"><strong>IP Inference</strong><span>{cameraLeadProbe.active_fingerprint?.candidate_ips?.length ? 'candidate IPs retained' : 'no IP inferred yet'}</span></div>
                          <div className="ssid-detail-row"><strong>HTTP Findings</strong><span>{cameraLeadProbe.active_fingerprint?.summary?.http_hits ?? 0} positive IPs</span></div>
                          <div className="ssid-detail-row"><strong>ONVIF Findings</strong><span>{cameraLeadProbe.active_fingerprint?.summary?.onvif_hits ?? 0} positive IPs</span></div>
                          <div className="ssid-detail-row"><strong>RTSP Findings</strong><span>{cameraLeadProbe.active_fingerprint?.summary?.rtsp_hits ?? 0} positive IPs</span></div>
                          <div className="ssid-detail-row"><strong>Snapshot Findings</strong><span>{cameraLeadProbe.active_fingerprint?.summary?.snapshot_hits ?? 0} positive IPs</span></div>
                          <div className="ssid-detail-row"><strong>RTSP Frames</strong><span>{cameraLeadProbe.active_fingerprint?.summary?.rtsp_frame_hits ?? 0} retained</span></div>
                          <div className="ssid-detail-row"><strong>Video/Image Proof</strong><span>{cameraLeadProbe.active_fingerprint?.summary?.video_or_image_proof ? 'YES' : 'NO'}</span></div>
                          <div className="ssid-detail-row"><strong>Proof Level</strong><span>{String(cameraLeadProbe.active_fingerprint?.summary?.proof_level || 'NO_PROOF').replaceAll('_', ' ')}</span></div>
                          <div className="ssid-detail-row"><strong>Visual Artifacts</strong><span>{cameraLeadProbe.active_fingerprint?.summary?.visual_artifact_count ?? 0} retained</span></div>
                          <div className="ssid-detail-row"><strong>Camera-Positive</strong><span>{cameraLeadProbe.active_fingerprint?.summary?.camera_positive ? 'YES' : 'NO'}</span></div>
                          <div className="ssid-detail-row"><strong>Matched Families</strong><span>{formatProbeFamilies(cameraLeadProbe.active_fingerprint?.summary?.matched_families || []) || '--'}</span></div>
                        </div>
                        <div className="table-secondary">{cameraLeadProbe.active_fingerprint?.candidate_ip_reason || 'No IP inference reason retained.'}</div>
                        <div className="table-secondary">{cameraLeadProbe.active_fingerprint?.summary?.camera_positive_summary || 'No camera-positive summary retained.'}</div>
                        <div className="table-secondary">{cameraLeadProbe.recommendation || cameraLeadProbe.error || 'No recommendation retained.'}</div>
                        {(cameraLeadProbe.active_fingerprint?.probes || []).map((probe) => (
                          <div key={`probe:${probe.ip}`} className="ranking-card compact">
                            <div className="ranking-head">
                              <strong>{probe.ip}</strong>
                              <span>{probe.http?.camera_hint || probe.onvif?.camera_hint || probe.rtsp?.camera_hint ? 'camera-positive' : 'no confirm'}</span>
                            </div>
                            <div className="table-secondary">HTTP: {summarizeHttpProbe(probe.http)}</div>
                            <div className="table-secondary">ONVIF: {summarizeOnvifProbe(probe.onvif)}</div>
                            <div className="table-secondary">RTSP: {summarizeRtspProbe(probe.rtsp)}</div>
                            <div className="table-secondary">Snapshot: {summarizeSnapshotProbe(probe.snapshot)}</div>
                          </div>
                        ))}
                      </>
                    ) : (
                      <div className="empty-box">Run `Hard Audit` to surface candidate IPs, confirm HTTP/ONVIF/RTSP behavior, and retain media artifacts when available.</div>
                    )}
                  </div>
                ) : null}
                {selectedDetailTab === 'intel' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">{cameraHuntMode ? 'Analysis' : 'Intel'}</div>
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>Target Score</strong><span>{selectedNetwork.target_score?.score ?? getPacketTruthScore(selectedNetwork, mode)} · {selectedNetwork.target_score?.priority || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Confidence</strong><span>{getNetworkConfidenceLabel(selectedNetwork)}</span></div>
                      <div className="ssid-detail-row"><strong>Behavior</strong><span>{selectedNetwork.behavior_analysis?.summary || selectedNetwork.traffic_pattern || '--'} · {selectedNetwork.mobility_class || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Activity</strong><span>{selectedNetwork.behavior_analysis?.activity_pattern || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>RSSI Variance</strong><span>{selectedNetwork.rssi_variance_db ?? '--'} dB</span></div>
                      <div className="ssid-detail-row"><strong>Camera</strong><span>{selectedNetwork.camera_detection?.classification || 'Not camera'} · {selectedNetwork.camera_detection?.score ?? '--'} / 100</span></div>
                      {cameraHuntMode ? (
                        <div className="ssid-detail-row"><strong>Flow</strong><span>up {Math.round(Number(selectedNetwork.behavior_analysis?.flow_summary?.uplink_ratio || 0) * 100)}% · {selectedNetwork.behavior_analysis?.flow_summary?.packet_rate_pps ?? '--'} pps · {selectedNetwork.behavior_analysis?.flow_summary?.duration_seconds ?? '--'} s</span></div>
                      ) : null}
                      <div className="ssid-detail-row"><strong>Risk</strong><span>{selectedNetwork.risk_profile?.risk || '--'} · {selectedNetwork.risk_profile?.risk_score ?? '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Anomaly</strong><span>{selectedNetwork.anomaly_profile?.summary || '--'}</span></div>
                    </div>
                    <div className="table-secondary">{cameraHuntMode ? ((selectedNetwork.camera_detection?.indicators || []).join(' · ') || 'camera hunt passive analysis') : (getMissionReasons(selectedNetwork, mode).join(' · ') || 'general passive WiFi priority')}</div>
                    {cameraHuntMode ? <div className="table-secondary">{`Basis: ${(selectedNetwork.pipeline_confidence_basis || []).join(' / ') || 'Passive'}${(selectedNetwork.camera_detection?.matched_families || []).length ? ` · families ${(selectedNetwork.camera_detection?.matched_families || []).join(', ')}` : ''}`}</div> : null}
                    {cameraHuntMode ? <div className="table-secondary">{`Family match: ${selectedNetwork.camera_detection?.family_match || '--'}${selectedNetwork.camera_detection?.family_match_confidence ? ` · ${selectedNetwork.camera_detection.family_match_confidence}` : ''} · camera confidence ${selectedNetwork.camera_detection?.camera_confidence_score ?? selectedNetwork.camera_detection?.score ?? '--'} / 100`}</div> : null}
                  </div>
                ) : null}
                {selectedDetailTab === 'fingerprint' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">Fingerprint</div>
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>WPS</strong><span>{selectedNetwork.wps_manufacturer || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Model</strong><span>{selectedNetwork.wps_model_name || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Device Name</strong><span>{selectedNetwork.wps_device_name || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>WiFi Cap</strong><span>{selectedNetwork.he_capable ? 'HE ' : ''}{selectedNetwork.vht_capable ? 'VHT ' : ''}{selectedNetwork.ht_capable ? 'HT' : ''}{!selectedNetwork.he_capable && !selectedNetwork.vht_capable && !selectedNetwork.ht_capable ? '--' : ''}</span></div>
                      <div className="ssid-detail-row"><strong>Frame / Retry</strong><span>{selectedNetwork.avg_frame_len ?? '--'} bytes · {selectedNetwork.retry_count ?? 0} retries</span></div>
                      <div className="ssid-detail-row"><strong>History</strong><span>{selectedNetwork.historical_captures ?? 0} captures · {selectedNetwork.historical_days_seen ?? 0} days</span></div>
                    </div>
                    <div className="table-secondary">Country source: {selectedNetwork.vendor_country_source || 'IEEE OUI registration'} · supply-chain evidence only.</div>
                  </div>
                ) : null}
                {selectedDetailTab === 'services' ? (
                  <div className="guidance-item ssid-detail-card compact">
                    <div className="snapshot-head">{cameraHuntMode ? 'Protocol Hints' : 'Services'}</div>
                    <div className="detail-grid ssid-detail-grid tight">
                      <div className="ssid-detail-row"><strong>Protocols</strong><span>{(selectedNetwork.service_exposure?.protocols || []).join(', ') || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Service Hints' : 'Services'}</strong><span>{(selectedNetwork.service_exposure?.services || []).join(', ') || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>{cameraHuntMode ? 'Protocol Evidence' : 'Exposure'}</strong><span>{selectedNetwork.service_exposure?.summary || '--'}</span></div>
                      <div className="ssid-detail-row"><strong>Cloud</strong><span>{(selectedNetwork.service_exposure?.cloud_endpoints || []).slice(0, 2).join(', ') || '--'}</span></div>
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>mDNS/DNS</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.['mDNS/DNS'] ?? 0} / 100</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>HTTP</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.HTTP ?? 0} / 100</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>TLS</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.TLS ?? 0} / 100</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>RTSP</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.RTSP ?? 0} / 100</span></div> : null}
                      {cameraHuntMode ? <div className="ssid-detail-row"><strong>Vendor / WPS</strong><span>{selectedNetwork.service_exposure?.protocol_confidence?.['vendor/WPS'] ?? 0} / 100</span></div> : null}
                      {!cameraHuntMode ? <div className="ssid-detail-row"><strong>Evidence Tier</strong><span>{selectedNetwork.evidence_tier || '--'}</span></div> : null}
                      {!cameraHuntMode ? <div className="ssid-detail-row"><strong>Attack ETA</strong><span>{selectedNetwork.password_risk?.attack_feasibility?.cpu_only_eta || '--'} · dict p {selectedNetwork.password_risk?.attack_feasibility?.dictionary_success_probability ?? '--'}</span></div> : null}
                    </div>
                    <div className="table-secondary">{cameraHuntMode ? 'Camera hunt relies heavily on visible RTSP, ONVIF, mDNS, HTTP, or TLS identity hints when available.' : (selectedNetwork.risk_profile?.summary || 'No elevated service risk observed yet.')}</div>
                    {cameraHuntMode && (selectedNetwork.service_exposure?.service_inventory || []).length ? (
                      <div className="matrix-table-wrap compact analyst-table-wrap">
                        <table className="matrix-table coverage-table">
                          <thead>
                            <tr>
                              <th>Service</th>
                              <th>Port</th>
                              <th>Proto</th>
                              <th>Source</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(selectedNetwork.service_exposure?.service_inventory || []).slice(0, 6).map((entry, index) => (
                              <tr key={`svc:${index}`} title={entry.detail || 'No additional detail retained.'}>
                                <td>{entry.service || '--'}</td>
                                <td>{entry.port || '--'}</td>
                                <td>{entry.transport || '--'}</td>
                                <td>{entry.source || '--'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : null}
                    {!cameraHuntMode ? <div className="table-secondary">{selectedNetwork.evidence_reason || '--'}</div> : null}
                  </div>
                ) : null}
                <div className="pill-row">
                  <Pill text={`score ${selectedNetwork.target_score?.score ?? getPacketTruthScore(selectedNetwork)}`} tone="cyan" />
                  <Pill text={cameraHuntMode ? getCameraLeadLabel(selectedNetwork) : getPredictedNetworkLabel(selectedNetwork)} tone="neutral" />
                  <Pill text={getRoleBadge(cameraHuntMode ? getCameraLeadLabel(selectedNetwork) : getPredictedNetworkLabel(selectedNetwork)).text} tone={getRoleBadge(cameraHuntMode ? getCameraLeadLabel(selectedNetwork) : getPredictedNetworkLabel(selectedNetwork)).tone} />
                  <Pill text={cameraHuntMode ? (selectedNetwork.camera_detection?.confidence_tier || getNetworkConfidenceLabel(selectedNetwork)) : getNetworkConfidenceLabel(selectedNetwork)} tone={getConfidenceTone(cameraHuntMode ? (selectedNetwork.camera_detection?.confidence_tier || getNetworkConfidenceLabel(selectedNetwork)) : getNetworkConfidenceLabel(selectedNetwork))} />
                  {cameraHuntMode ? <Pill text={formatCameraConfirmationLevel(selectedNetwork.camera_confirmation?.level)} tone={selectedNetwork.camera_confirmation?.level === 'artifact_confirmed' ? 'danger' : (selectedNetwork.camera_confirmation?.level === 'confirmed' ? 'cyan' : 'neutral')} /> : null}
                  {!cameraHuntMode ? <Pill text={`pw risk ${selectedNetwork.password_risk?.risk || 'LOW'}`} tone={getPasswordRiskTone(selectedNetwork.password_risk?.risk)} /> : null}
                  {selectedNetwork.camera_detection?.detected ? <Pill text="camera detected" tone="danger" /> : null}
                  {!cameraHuntMode && handshakeAnalysisEnabled && getHandshakeStatus(selectedNetwork) !== 'Not Observed' ? <Pill text={`auth ${getHandshakeStatus(selectedNetwork).toLowerCase()}`} tone={getHandshakeTone(selectedNetwork)} /> : null}
                </div>
                {!cameraHuntMode ? (
                  <div className="ssid-task-grid">
                    {buildTaskPresets(selectedNetwork).map((task) => (
                      <button key={task.key} className="ssid-task-card" onClick={() => handleTask(task.key)}>
                        <strong>{task.label}</strong>
                        <span>{task.detail}</span>
                      </button>
                    ))}
                  </div>
                ) : null}
              </div>
            ) : (
              <div className="empty-box">{cameraHuntMode ? 'Click a camera lead after the scan completes to open the camera detail window.' : 'Click an SSID after the scan completes to open the operator detail window.'}</div>
            )}
          </Panel>
          </div>
        ) : null}

        {isPanelVisible('packetTruth') ? (
          <Panel
            kicker="Packet Truth"
            title={cameraHuntMode ? 'Observed Camera Leads 2.0' : 'Observed WiFi Devices'}
            action={
              <div className="table-mode-toggle">
                {!cameraHuntMode ? (
                  <>
                    <button type="button" className={`mini-action ${redLeadScope === 'all' ? 'active' : ''}`} onClick={() => setRedLeadScope('all')}>All Leads</button>
                    <button type="button" className={`mini-action ${redLeadScope === 'confirmed' ? 'active' : ''}`} onClick={() => setRedLeadScope('confirmed')}>Confirmed</button>
                  </>
                ) : null}
              </div>
            }
          >
            {!cameraHuntMode ? (
              <div className="operator-summary-strip">
                {operatorSummary.map((item) => (
                  <div key={`operator-summary:${item.label}`} className="operator-summary-card" title={`${item.value} ${item.detail}`}>
                    <span>{item.label}</span>
                    <strong>{item.value}</strong>
                    <small>{item.detail}</small>
                  </div>
                ))}
              </div>
            ) : null}
            {cameraHuntMode && !cameraLeads.length && cameraNearMisses.length ? (
              <div className="table-secondary">
                Showing camera-qualified near misses because this run did not retain a fully confirmed camera lead.
              </div>
            ) : null}
            <div className={`table-wrap ${cameraHuntMode ? 'camera-hunt-table-wrap' : 'wifi-device-table-wrap'}`}>
              <table className={`operator-network-table ${cameraHuntMode ? 'camera-hunt-table' : ''}`}>
                <thead>
                  <tr>
                    <th>{cameraHuntMode ? 'Camera Lead' : 'Device'}</th>
                    {cameraHuntMode ? <th>Audit</th> : <th>Grp</th>}
                    {cameraHuntMode ? <th>Associated SSID</th> : null}
                    <th>{cameraHuntMode ? 'Type' : 'Conf'}</th>
                    <th>{cameraHuntMode ? 'Path' : 'Why'}</th>
                    <th>Score</th>
                    <th>{cameraHuntMode ? 'Vendor' : 'RF / IP'}</th>
                    {!cameraHuntMode ? <th>Ext</th> : null}
                    {!cameraHuntMode ? <th>Vendor</th> : null}
                    {cameraHuntMode ? <th>Pkts</th> : null}
                  </tr>
                </thead>
                <tbody>
                  {(cameraHuntMode ? cameraLeads : wifiDeviceInventory).map((network, index) => (
                    (() => {
                      const networkId = getEntitySelectionId(network, cameraHuntMode) || network.mac || `camera-lead-${index}`
                      const relatedNetworkClients = networkClientMap[networkId] || []
                      const coverageRow = coverageMap.get(networkId)
                      const rowAlert = cameraHuntMode && isCameraLeadRedAlert(network)
                      const classification = getDeviceClassification(network)
                      const groupColor = getDeviceGroupColor(network)
                      const serviceAuditOverride = serviceAudit?.target_id === getEntitySelectionId(network, false) ? serviceAudit : null
                      const deviceEvidence = getDeviceAuditEvidence(network, serviceAuditOverride)
                      const compactWhy = getCompactObservedWhy(network, serviceAuditOverride)
                      return (
                      <>
                      {!cameraHuntMode && network.inventory_group_divider ? (
                        <tr key={`${networkId}:group`} className="coverage-row">
                          <td colSpan="8" className="table-secondary" style={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                            {network.inventory_group_label || classification.group_label}
                          </td>
                        </tr>
                      ) : null}
                      <tr
                        key={networkId}
                        className={[
                          getEntitySelectionId(selectedNetwork, cameraHuntMode) === networkId ? 'selected-ssid-row' : '',
                          rowAlert ? 'camera-lead-alert-row' : '',
                        ].filter(Boolean).join(' ')}
                        title={!cameraHuntMode ? getNetworkObservationTooltip(network, coverageRow) : getCameraAuditTooltip(network)}
                      >
                        <td>
                          <div className="network-primary-cell" style={!cameraHuntMode ? { borderLeft: `4px solid ${groupColor}`, paddingLeft: '0.65rem' } : undefined}>
                            {!cameraHuntMode && relatedNetworkClients.length ? (
                              <button
                                className={`mini-action ${expandedNetworks[networkId] ? 'active' : ''} has-related-clients`}
                                onClick={() => toggleExpandedNetwork(networkId)}
                              >
                                {expandedNetworks[networkId] ? 'Hide Clients' : 'Show Clients'}
                              </button>
                            ) : null}
                            <button
                              className={getEntitySelectionId(selectedNetwork, cameraHuntMode) === networkId ? 'mini-action active' : 'mini-action'}
                              onClick={(event) => {
                                event.stopPropagation()
                                handleSelectNetwork(network)
                              }}
                              disabled={cameraLeadInteractionLocked}
                            >
                              <span className="ssid-button-content">
                                {Number(network.camera_detection?.confidence || 0) >= 0.7 ? <span className="camera-flag prominent" title={`High-confidence camera-like network (${formatPercent(network.camera_detection?.confidence || 0)})`}>📷</span> : null}
                                {!cameraHuntMode ? <span aria-hidden="true" style={{ width: '0.65rem', height: '0.65rem', borderRadius: '999px', background: groupColor, display: 'inline-block' }} /> : null}
                                <span>{shortText(cameraHuntMode ? getCameraLeadIdentity(network) : getWiFiInventoryLabel(network), cameraHuntMode ? 28 : 24)}</span>
                              </span>
                            </button>
                          </div>
                          <div className="table-secondary">{cameraHuntMode ? getCameraLeadSupportingId(network) : getCompactObservedSupportLine(network)}</div>
                        </td>
                        <td>
                          {cameraHuntMode ? (
                            <>
                              <Pill text={getHardAuditStatus(network).label} tone={getHardAuditStatus(network).tone} />
                              <div className="table-secondary">{getCameraEvidenceQuality(network)} · {getProbeStatus(network).label}</div>
                            </>
                          ) : (
                            <>
                              <Pill text={network.inventory_group_pill || classification.group_label} tone={getWiFiInventoryTone(network)} />
                              <div className="table-secondary">{shortText((classification.classification_signals || [])[0] || 'packet-truth', 20)}</div>
                            </>
                          )}
                        </td>
                        {cameraHuntMode ? (
                          <td>
                            {getCameraLeadAssociatedSsid(network)}
                            <div className="table-secondary">{network.leadKind === 'client' ? (network.associated_bssid || '--') : '--'}</div>
                          </td>
                        ) : null}
                        <td>
                          {cameraHuntMode ? getCameraLeadLabel(network) : classification.confidence}
                          <div className="pill-row compact-inline-pills">
                            {cameraHuntMode ? (
                              <>
                                <Pill text={getRoleBadge(getCameraLeadLabel(network)).text} tone={getRoleBadge(getCameraLeadLabel(network)).tone} />
                                <Pill text={network.camera_detection?.confidence_tier || getNetworkConfidenceLabel(network)} tone={getConfidenceTone(network.camera_detection?.confidence_tier || getNetworkConfidenceLabel(network))} />
                              </>
                            ) : (
                              <Pill text={network.inventory_kind === 'client' ? 'client' : 'ap'} tone="neutral" />
                            )}
                          </div>
                        </td>
                        <td>
                          {cameraHuntMode ? (network.leadKind === 'client' ? 'Client' : 'Network') : compactWhy.primary}
                          {cameraHuntMode ? (
                            <div className="table-secondary">{getCompactCameraPathSummary(network)}</div>
                          ) : (
                            <div className="table-secondary">{compactWhy.secondary}</div>
                          )}
                        </td>
                        <td>
                          {cameraHuntMode ? (network.camera_detection?.score ?? network.target_score?.score ?? getPacketTruthScore(network)) : (network.target_score?.score ?? getPacketTruthScore(network))}
                        </td>
                        {!cameraHuntMode ? (
                          <td>
                            <div>{getCompactObservedRfIp(network)}</div>
                            <div className="table-secondary">{shortText(deviceEvidence.ip.summary, 22)}</div>
                          </td>
                        ) : null}
                        {!cameraHuntMode ? (
                          <td>
                            {(() => {
                              const destinationSummary = getExternalDestinationSummary(network, serviceAuditOverride)
                              return (
                                <>
                                  <div>{shortText(destinationSummary.primary, 20)}</div>
                                  <div className="table-secondary">{shortText(destinationSummary.secondary, 18)}</div>
                                </>
                              )
                            })()}
                          </td>
                        ) : null}
                        {!cameraHuntMode ? (
                          <td>
                            {shortText(network.vendor || '--', 18)}
                            <div className="table-secondary">{getCompactObservedVendorCategory(network)}</div>
                          </td>
                        ) : null}
                        {cameraHuntMode ? <td>{network.packet_count || 0}</td> : null}
                      </tr>
                      {!cameraHuntMode && getEntitySelectionId(selectedNetwork, cameraHuntMode) === networkId ? (
                        <tr key={`${networkId}:wifi-inline`} className="camera-inline-detail-row">
                          <td colSpan="8">
                            <div className="camera-inline-detail">
                              <div className="camera-inline-actions">
                                <button className={`mini-action ${serviceAuditBusy ? 'active' : ''}`} onClick={handleRunHardAudit} disabled={serviceAuditBusy}>
                                  {serviceAuditBusy ? 'Hard Auditing…' : 'Hard Audit'}
                                </button>
                              </div>
                              {getServiceAuditStages(network, serviceAudit?.target_id === getEntitySelectionId(network, false) ? serviceAudit : null).length ? (
                                <div className="camera-inline-hard-audit">
                                  <div className="camera-inline-hard-audit-head">
                                    <strong>Hard Audit Topology</strong>
                                    <span>{getServiceAuditStatus(network, serviceAudit?.target_id === getEntitySelectionId(network, false) ? serviceAudit : null).detail}</span>
                                  </div>
                                  <div className="camera-inline-hard-audit-strip">
                                    {getServiceAuditStages(network, serviceAudit?.target_id === getEntitySelectionId(network, false) ? serviceAudit : null).map((stage) => {
                                      const processingStageId = getServiceAuditProcessingStageId(network, serviceAudit?.target_id === getEntitySelectionId(network, false) ? serviceAudit : null)
                                      const processing = serviceAuditBusy && stage.id === processingStageId
                                      return (
                                      <div key={`${networkId}:svc:${stage.id}`} className={`camera-inline-hard-node ${stage.status} ${processing ? 'processing' : ''}`.trim()}>
                                        <strong>{stage.label}</strong>
                                        <span>{processing ? `processing · ${stage.detail || stage.status}` : (stage.detail || stage.status)}</span>
                                      </div>
                                      )
                                    })}
                                  </div>
                                </div>
                              ) : null}
                              <div className="camera-inline-grid">
                                <div className="camera-inline-card">
                                  <strong>Classification</strong>
                                  <span>{classification.group_label} · {classification.confidence} · {classification.method || 'passive_packet_truth'}</span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Why</strong>
                                  <span>{classification.explanation} {(classification.classification_signals || []).length ? `· ${(classification.classification_signals || []).join(', ')}` : ''}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>IP Evidence</strong>
                                  <span>{deviceEvidence.ip.summary}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Credentials / Login</strong>
                                  <span>{deviceEvidence.creds.summary}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Security</strong>
                                  <span>{network.security || '--'} · PMF {String(network.pmf || '').toLowerCase() === 'true' ? 'on' : 'off'}</span>
                                </div>
                                {handshakeAnalysisEnabled ? (
                                  <div className="camera-inline-card">
                                    <strong>Handshake</strong>
                                    <span>{getHandshakeStatus(network)} · {network.handshake_eapol_count ?? network.eapol_count ?? 0} EAPOL</span>
                                  </div>
                                ) : null}
                                <div className="camera-inline-card">
                                  <strong>Password Risk</strong>
                                  <span>{getPasswordRiskLabel(network)} · {getPasswordRiskSummary(network)}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Coverage</strong>
                                  <span>{`${coverageRow?.visits ?? network.observation_capture_count ?? 0} visits · ${coverageRow?.retainedFrames ?? network.frame_count_total ?? network.packet_count ?? 0} frames`}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Opportunity</strong>
                                  <span>{`${coverageRow?.observationLevel || network.observation_opportunity?.level || 'LOW'} · ${coverageRow?.observationScore ?? network.observation_opportunity?.score ?? 0}/100`}</span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Services</strong>
                                  <span>{(network.service_exposure?.protocols || []).join(', ') || 'No retained protocol evidence'}{network.service_exposure?.summary ? ` · ${network.service_exposure.summary}` : ''}</span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Audit Artifacts</strong>
                                  <span>{getEvidenceArtifacts(network, serviceAuditOverride).map((artifact) => artifact.label).join(' · ') || 'No retained audit artifacts yet.'}</span>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      ) : null}
                      {cameraHuntMode && getEntitySelectionId(selectedNetwork, cameraHuntMode) === networkId ? (
                        <tr key={`${networkId}:camera-inline`} className="camera-inline-detail-row">
                          <td colSpan="9">
                            <div className="camera-inline-detail">
                              {(() => {
                                const displayNetwork = withCameraLayerAudit(
                                  withCameraHardAudit(network, cameraLeadHardAudit?.lead_id === getCameraLeadId(network) ? cameraLeadHardAudit?.hard_audit : null),
                                  cameraLeadLayerAudit?.lead_id === getCameraLeadId(network) ? cameraLeadLayerAudit?.layer_audit : null,
                                )
                                const operatorPrompt = getCameraOperatorPrompt(displayNetwork)
                                return (
                              <>
                              <div className="camera-inline-actions">
                                <button className={`mini-action danger ${cameraLeadHardAuditBusy ? 'active' : ''}`} onClick={handleHardAuditCameraLead} disabled={cameraLeadHardAuditBusy || cameraLeadVideoTruthBusy || cameraLeadProbeBusy || cameraLeadAnalysisBusy || cameraLeadLayerAuditBusy || redTeamBusy || cameraLeadInteractionLocked}>
                                  {cameraLeadHardAuditBusy ? 'Hard Auditing…' : 'Hard Audit'}
                                </button>
                              </div>
                              <div className="camera-inline-stage-strip">
                                {buildCameraLeadStageList(displayNetwork).map((stage) => (
                                  <div key={`${networkId}:${stage.label}`} className={`camera-inline-stage ${stage.state}`}>
                                    <strong>{stage.label}</strong>
                                    <span>{stage.detail}</span>
                                  </div>
                                ))}
                              </div>
                              {operatorPrompt?.state ? (
                                <div className="camera-inline-operator-prompt">
                                  <div className="camera-inline-hard-audit-head">
                                    <strong>Operator Prompt State</strong>
                                    <span>{String(operatorPrompt.state || 'idle').replaceAll('_', ' ')}</span>
                                  </div>
                                  <div className="camera-inline-operator-strip">
                                    {[
                                      { id: 'baseline', label: 'Baseline' },
                                      { id: 'trigger', label: 'Trigger' },
                                      { id: 'post_trigger', label: 'Post Trigger' },
                                    ].map((step) => {
                                      const current = String(operatorPrompt.state || '')
                                      const isComplete = ['baseline_complete', 'trigger_complete', 'post_trigger_complete', 'complete'].includes(current) && step.id === 'baseline'
                                        || ['trigger_complete', 'post_trigger_complete', 'complete'].includes(current) && step.id === 'trigger'
                                        || ['post_trigger_complete', 'complete'].includes(current) && step.id === 'post_trigger'
                                      const isActive = (current === step.id)
                                      return (
                                        <div key={`${networkId}:prompt:${step.id}`} className={`camera-inline-hard-node ${isComplete ? 'completed' : isActive ? 'active' : 'pending'}`}>
                                          <strong>{step.label}</strong>
                                          <span>{isActive ? 'operator action' : isComplete ? 'captured' : 'queued'}</span>
                                        </div>
                                      )
                                    })}
                                  </div>
                                  <div className="table-secondary">{operatorPrompt.message || 'No operator prompt retained.'}</div>
                                </div>
                              ) : null}
                              {(getCameraHardAuditStages(displayNetwork).length || cameraLeadHardAuditBusy) ? (
                                <div className="camera-inline-hard-audit">
                                  <div className="camera-inline-hard-audit-head">
                                    <strong>Hard Audit Pipeline</strong>
                                    <span>{cameraLeadHardAuditBusy ? 'running' : `${getCameraHardAuditProgress(displayNetwork)}% complete`}</span>
                                  </div>
                                  <div className="camera-inline-hard-audit-strip">
                                    {(getCameraHardAuditStages(displayNetwork).length ? getCameraHardAuditStages(displayNetwork) : [
                                      { id: 'boot', label: 'Bootstrap', status: cameraLeadHardAuditBusy ? 'active' : 'pending', detail: 'Waiting for staged evidence.' },
                                    ]).map((stage) => (
                                      <div key={`${networkId}:hard:${stage.id}`} className={`camera-inline-hard-node ${stage.status}`}>
                                        <strong>{stage.label}</strong>
                                        <span>{stage.detail || stage.status}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              ) : null}
                              {getCameraLayerAuditRows(displayNetwork).length ? (
                                <div className="camera-inline-hard-audit">
                                  <div className="camera-inline-hard-audit-head">
                                    <strong>Audit Layers</strong>
                                    <span>{getCameraLayerAudit(displayNetwork).media_plane_detected || 'unclassified'} · {getCameraLayerAudit(displayNetwork).image_feasible_now ? 'image feasible now' : 'image not feasible yet'}</span>
                                  </div>
                                  <div className="camera-inline-hard-audit-strip">
                                    {getCameraLayerAuditRows(displayNetwork).map((layer) => (
                                      <div key={`${networkId}:layer:${layer.id}`} className={`camera-inline-hard-node ${layer.status === 'complete' ? 'completed' : layer.status}`}>
                                        <strong>{layer.label}</strong>
                                        <span>{layer.detail || layer.status}</span>
                                      </div>
                                    ))}
                                  </div>
                                  <div className="table-secondary">{getCameraLayerAudit(displayNetwork).summary || 'No layered audit summary retained yet.'}</div>
                                  <div className="table-secondary">{(getCameraLayerAudit(displayNetwork).blockers || []).join(' · ') || 'No blockers retained.'}</div>
                                  <div className="table-secondary">{(getCameraLayerAudit(displayNetwork).next_actions || []).join(' · ') || 'No next action retained.'}</div>
                                  <div className="table-secondary">{getCameraVerdictGuidance(displayNetwork) || 'No remediation guidance retained.'}</div>
                                </div>
                              ) : null}
                              <div className="camera-inline-grid">
                                <div className="camera-inline-card">
                                  <strong>Identity</strong>
                                  <span>{getCameraLeadIdentity(network)} · {network.vendor || '--'}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Association</strong>
                                  <span>{getCameraLeadAssociatedSsid(network)} · {getCameraLeadSupportingId(network)}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>IP Evidence</strong>
                                  <span>{getLeadCandidateIps(network).length ? getLeadCandidateIps(network).join(', ') : getLeadIpReason(network)}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Probe</strong>
                                  <span>{getProbeStatus(displayNetwork).label} · {getProbeStatus(displayNetwork).detail}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Verdict</strong>
                                  <span>{getCameraVerdictSummary(displayNetwork)}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Evidence</strong>
                                  <span>{getCameraEvidenceQuality(displayNetwork)} · {getCameraLeadEvidence(displayNetwork)}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Video Capability</strong>
                                  <span>{getVideoEvidenceSummary(displayNetwork)}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Video Class</strong>
                                  <span>{String(getCameraVideoEvidence(displayNetwork).video_device_class || 'UNKNOWN').replaceAll('_', ' ')}</span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Transport</strong>
                                  <span>
                                    local {String(getCameraVideoEvidence(displayNetwork).local_stream_available || 'no').toUpperCase()}
                                    {' · '}
                                    cloud {String(getCameraVideoEvidence(displayNetwork).cloud_stream_detected || 'no').toUpperCase()}
                                  </span>
                                </div>
                                <div className="camera-inline-card">
                                  <strong>Artifact</strong>
                                  <span>{String(getCameraVideoEvidence(displayNetwork).artifact_possible || 'no').toUpperCase()} · {getCameraVideoEvidence(displayNetwork).artifact_reason || 'no justified artifact path'}</span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Path</strong>
                                  <span>{displayNetwork.camera_confirmation?.summary || displayNetwork.stream_state?.summary || getCompactCameraPathSummary(displayNetwork)}</span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Signals</strong>
                                  <span>{getCameraLeadSecondarySummary(displayNetwork)}</span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Live-View Correlation</strong>
                                  <span>{getCameraVideoEvidence(displayNetwork).correlation?.summary || 'live-view correlation not retained yet'} · conf {Math.round(Number(getCameraVideoEvidence(displayNetwork).correlation?.correlation_confidence || 0) * 100)}%</span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Traffic Delta</strong>
                                  <span>
                                    idle {fmtBytes(getCameraVideoEvidence(displayNetwork).traffic_profile?.baseline_bytes || 0)} → live {fmtBytes(getCameraVideoEvidence(displayNetwork).traffic_profile?.live_bytes || 0)}
                                    {' · '}
                                    {getCameraVideoEvidence(displayNetwork).traffic_profile?.bandwidth_classification || 'none'}
                                    {' · '}
                                    {Math.round(Number(getCameraVideoEvidence(displayNetwork).traffic_profile?.duration_seconds || 0))}s
                                  </span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Endpoint Evidence</strong>
                                  <span>{getVideoEvidenceEndpoints(displayNetwork).join(' · ') || 'No endpoint set retained yet.'}</span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Flow Intel</strong>
                                  <span>
                                    {(() => {
                                      const traffic = getCameraHardAuditTraffic(displayNetwork)
                                      const debug = traffic.debug || {}
                                      return `pkts ${debug.total_packets ?? 0} · mac ${debug.packets_from_mac ?? 0} · flows ${debug.flows_built ?? 0} · endpoints ${(traffic.endpoints || []).length || 0}`
                                    })()}
                                  </span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Flow Endpoints</strong>
                                  <span>
                                    {(() => {
                                      const traffic = getCameraHardAuditTraffic(displayNetwork)
                                      const endpoints = (traffic.endpoints || []).slice(0, 4)
                                      return endpoints.length
                                        ? endpoints.map((endpoint) => `${endpoint.domain || endpoint.endpoint_ip}:${endpoint.port}/${endpoint.protocol} ${fmtBytes(endpoint.total_bytes || 0)} ${endpoint.stream_candidate ? 'stream' : 'flow'}`).join(' · ')
                                        : (traffic.explanation || 'No flow endpoints retained.')
                                    })()}
                                  </span>
                                </div>
                                <div className="camera-inline-card wide">
                                  <strong>Negative Evidence</strong>
                                  <span>{getCameraNegativeEvidence(displayNetwork).join(' · ') || 'No negative evidence retained.'}</span>
                                </div>
                              </div>
                              {getCameraVisualArtifacts(displayNetwork).length ? (
                                <div className="camera-inline-visual-board">
                                  <div className="camera-inline-visual-head">
                                    <strong>Visual Evidence</strong>
                                    <span>{getCameraVisualArtifacts(displayNetwork).length} artifact{getCameraVisualArtifacts(displayNetwork).length === 1 ? '' : 's'}</span>
                                  </div>
                                  <div className="camera-inline-visual-grid">
                                    {getCameraVisualArtifacts(displayNetwork).slice(0, 3).map((artifact) => (
                                      <div key={`${networkId}:artifact:${artifact.path}`} className="camera-inline-visual-card">
                                        {artifact.previewKind === 'image' ? (
                                          <a href={artifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link">
                                            <img src={artifact.url} alt="Camera evidence artifact" className="camera-inline-visual-preview" loading="lazy" />
                                          </a>
                                        ) : artifact.previewKind === 'video' ? (
                                          <a href={artifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link">
                                            <video className="camera-inline-visual-preview" src={artifact.url} controls preload="metadata" />
                                          </a>
                                        ) : (
                                          <a href={artifact.url} target="_blank" rel="noreferrer" className="camera-inline-visual-link camera-inline-visual-fallback">
                                            Open Artifact
                                          </a>
                                        )}
                                        <div className="camera-inline-visual-meta">
                                          <strong>{artifact.savedLabel}</strong>
                                          <span>{artifact.targetIp || artifact.protocol || 'artifact'}</span>
                                          <span>{artifact.pathHint || artifact.path.split('/').slice(-1)[0]}</span>
                                          <small>{artifact.hash ? artifact.hash.slice(0, 18) : artifact.path}</small>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              ) : (
                                <div className="camera-inline-visual-empty">
                                  <strong>Visual Evidence</strong>
                                  <span>No snapshot artifact retained yet. Hard Audit only promotes this when a real image payload is returned and stored.</span>
                                </div>
                              )}
                              {Object.keys(getCameraVideoTruth(displayNetwork)).length ? (
                                <div className="camera-inline-video-truth">
                                  <div className="camera-inline-video-truth-head">
                                    <strong>Video Truth Correlation</strong>
                                    <span>{getCameraVideoTruth(displayNetwork).video_confirmed || 'INCONCLUSIVE'} · conf {Math.round(Number(getCameraVideoTruth(displayNetwork).correlation_confidence || 0) * 100)}%</span>
                                  </div>
                                  <div className="camera-inline-grid">
                                    <div className="camera-inline-card">
                                      <strong>Baseline</strong>
                                      <span>{fmtBytes(getCameraVideoTruth(displayNetwork).metrics?.baseline_bytes_per_sec || 0)}/s · {getCameraVideoTruth(displayNetwork).metrics?.baseline_packet_rate_pps ?? 0} pps</span>
                                    </div>
                                    <div className="camera-inline-card">
                                      <strong>Trigger</strong>
                                      <span>{fmtBytes(getCameraVideoTruth(displayNetwork).metrics?.live_bytes_per_sec || 0)}/s · {getCameraVideoTruth(displayNetwork).metrics?.live_packet_rate_pps ?? 0} pps</span>
                                    </div>
                                    <div className="camera-inline-card">
                                      <strong>Delta</strong>
                                      <span>{fmtBytes(getCameraVideoTruth(displayNetwork).metrics?.delta_bytes || 0)} · {getCameraVideoTruth(displayNetwork).metrics?.flow_count ?? 0} flows</span>
                                    </div>
                                    <div className="camera-inline-card">
                                      <strong>Stream Flows</strong>
                                      <span>{getCameraVideoTruth(displayNetwork).metrics?.stream_flows_detected ?? 0} detected</span>
                                    </div>
                                    <div className="camera-inline-card wide">
                                      <strong>Timing</strong>
                                      <span>
                                        trigger {getCameraVideoTruth(displayNetwork).timing?.trigger_timestamp ? new Date(Number(getCameraVideoTruth(displayNetwork).timing.trigger_timestamp) * 1000).toLocaleTimeString() : '--'}
                                        {' · '}
                                        delay {getCameraVideoTruth(displayNetwork).timing?.correlation_delay_seconds ?? '--'}s
                                      </span>
                                    </div>
                                    <div className="camera-inline-card wide">
                                      <strong>Truth Reason</strong>
                                      <span>{getCameraVideoTruth(displayNetwork).status_reason || 'No truth reasoning retained yet.'}</span>
                                    </div>
                                    <div className="camera-inline-card wide">
                                      <strong>Truth Endpoints</strong>
                                      <span>{(getCameraVideoTruth(displayNetwork).flow_evidence || []).slice(0, 4).map((entry) => `${entry.domain || entry.endpoint_ip}:${entry.port}/${entry.protocol} ${fmtBytes(entry.total_bytes || 0)}`).join(' · ') || 'No correlated endpoints retained.'}</span>
                                    </div>
                                  </div>
                                </div>
                              ) : null}
                              <div className="camera-inline-protocol-grid">
                                {getCameraProtocolEvidence(displayNetwork).map((entry) => (
                                  <div key={`${networkId}:proto:${entry.label}`} className="camera-inline-protocol-card">
                                    <strong>{entry.label}</strong>
                                    <span>{entry.detail}</span>
                                  </div>
                                ))}
                              </div>
                              </>
                                )
                              })()}
                            </div>
                          </td>
                        </tr>
                      ) : null}
                      {!cameraHuntMode && expandedNetworks[networkId] ? (
                        <tr key={`${networkId}:clients`} className="network-client-row">
                          <td colSpan="8">
                            <div className="nested-client-panel">
                              <div className="nested-client-head">
                                <strong>Related Clients</strong>
                                <span>{relatedNetworkClients.length || 0} shown</span>
                              </div>
                              {relatedNetworkClients.length ? (
                                <div className="nested-client-list">
                                  {relatedNetworkClients.map((client) => (
                                    <div key={`${networkId}:${client.mac}`} className="nested-client-card">
                                      <div className="nested-client-line">
                                        <strong>{client.mac}</strong>
                                        <div className="pill-row">
                                          <Pill text={client.attribution.level} tone={client.attribution.level === 'Confirmed' ? 'green' : client.attribution.level === 'Strong' ? 'cyan' : 'neutral'} />
                                          <Pill text={`score ${client.target_score?.score ?? getPacketTruthScore(client)}`} tone="cyan" />
                                          <Pill text={getRoleBadge(getPredictedClientLabel(client)).text} tone={getRoleBadge(getPredictedClientLabel(client)).tone} />
                                          <Pill text={client.fingerprint?.confidence_tier || client.target_score?.confidence_tier || 'LOW'} tone={getConfidenceTone(client.fingerprint?.confidence_tier || client.target_score?.confidence_tier || 'LOW')} />
                                          <Pill text={getRedClientValue(client).label} tone={getRedClientValue(client).tone} />
                                        </div>
                                      </div>
                                      <div className="table-secondary">
                                        {client.vendor || '--'} / {client.vendor_country || client.vendor_country_code || '--'} · {getPredictedClientLabel(client)} · {client.fingerprint?.confidence_tier || '--'} · {client.behavior_analysis?.summary || client.traffic_pattern || '--'} · RSSI {client.rssi_dbm ?? '--'}
                                      </div>
                                      <div className="table-secondary">
                                        {client.attribution.reason} · {client.packet_count || 0} packets · {client.probe_request_count || 0} probes · {client.association_count || 0} assoc/auth · {client.mobility_class || '--'} · avg frame {client.avg_frame_len ?? '--'} bytes · history {client.historical_captures ?? 0} captures · risk {client.risk_profile?.risk || '--'} {client.risk_profile?.risk_score ?? '--'}
                                      </div>
                                      <div className="table-secondary">Why it matters: {getRedPriorityReasons(client).join(' · ') || getRedClientValue(client).reason}</div>
                                      {client.dhcp_hostnames?.length ? <div className="table-secondary">Hostnames: {client.dhcp_hostnames.join(', ')}</div> : null}
                                      {(client.service_exposure?.protocols || []).length ? <div className="table-secondary">Protocols: {(client.service_exposure?.protocols || []).join(', ')} · {client.service_exposure?.summary || '--'}</div> : null}
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <div className="empty-box">No clients met the current attribution filter for this observed network.</div>
                              )}
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </>
                      )
                    })()
                  ))}
                  {!(cameraHuntMode ? cameraLeads : visibleNetworks).length && (
                    <tr>
                      <td colSpan={cameraHuntMode ? 9 : 8} className="empty-cell">{cameraHuntMode ? 'No confirmed or possible cloud camera leads are visible in this run.' : 'No retained SSIDs. Start Session to begin a timed scan.'}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
        ) : null}

        {redLeadScope !== 'all' && !cameraHuntMode ? (
        <Panel kicker="Probable" title="SSID-Only Observations">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>SSID</th>
                  <th>Channel</th>
                  <th>Band</th>
                  <th>Exposure</th>
                  <th>RSSI</th>
                  <th>Score</th>
                </tr>
              </thead>
              <tbody>
                {probableNetworks.map((network) => (
                  <tr key={getNetworkId(network)}>
                    <td>{network.ssid || '<hidden>'}</td>
                    <td>{network.channel || '--'}</td>
                    <td>{network.band || '--'}</td>
                    <td>{getExposureSummary(network)}</td>
                    <td>{network.rssi_dbm ?? '--'}</td>
                    <td>{network.target_score?.score ?? getPacketTruthScore(network)}</td>
                  </tr>
                ))}
                {!probableNetworks.length ? (
                  <tr>
                    <td colSpan="6" className="empty-cell">No probable SSID-only observations retained.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('clients') && !cameraHuntMode ? (
          <Panel kicker="Clients" title={focusedBssid ? 'Clients For Selected SSID' : 'Observed Clients'}>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Client</th>
                    <th>Vendor</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Prediction</th>
                    <th>Associated BSSID</th>
                    <th>Probe Requests</th>
                    <th>Assoc/Auth</th>
                    <th>RSSI</th>
                    <th>PCAP/PCAPNG</th>
                  </tr>
                </thead>
                <tbody>
                  {relatedClients.map((client) => (
                    <tr key={client.mac}>
                      <td>
                        <div>{client.mac}</div>
                        <div className="pill-row compact-inline-pills">
                          <Pill text={getRoleBadge(getPredictedClientLabel(client)).text} tone={getRoleBadge(getPredictedClientLabel(client)).tone} />
                          <Pill text={client.fingerprint?.confidence_tier || client.target_score?.confidence_tier || 'LOW'} tone={getConfidenceTone(client.fingerprint?.confidence_tier || client.target_score?.confidence_tier || 'LOW')} />
                          <Pill text={getRedClientValue(client).label} tone={getRedClientValue(client).tone} />
                        </div>
                        <div className="table-secondary">{getClientSummary(client)}</div>
                        <div className="table-secondary">Why it matters: {getRedPriorityReasons(client).join(' · ') || getRedClientValue(client).reason}</div>
                      </td>
                      <td>{client.vendor || '--'}</td>
                      <td>{client.fingerprint?.device_type || client.device_type || '--'}</td>
                      <td>{client.target_score?.score ?? getPacketTruthScore(client)}</td>
                      <td>{getPredictedClientLabel(client)}</td>
                      <td>{client.associated_bssid || '--'}</td>
                      <td>{client.probe_request_count || 0}</td>
                      <td>{client.association_count || 0}</td>
                      <td>{client.rssi_dbm ?? '--'} / {client.mobility_class || '--'}</td>
                      <td>
                        <Pill text={getPcapSavedStatus(client).label} tone={getPcapSavedStatus(client).saved ? 'green' : 'warning'} />
                        <div className="table-secondary">{getPcapSavedStatus(client).detail}</div>
                      </td>
                    </tr>
                  ))}
                  {!relatedClients.length && (
                    <tr>
                      <td colSpan="10" className="empty-cell">No retained clients yet.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
        ) : null}
      </div>

      <div className="side-column">
        <Panel
          kicker={cameraHuntMode ? 'Camera Hunt Backend' : 'WiFi Recon Backend'}
          title={backendActivity.summaryTitle}
        >
          <div className="guidance-list">
            {cameraHuntMode ? (
              <div className="backend-stage-hud" title={`Current phase ${backendActivity.currentPhase || 'idle'} · ${backendActivity.processingTopology}`}>
                <div className="backend-stage-hud-head">
                  <div>
                    <span className="backend-stage-kicker">Live Pipeline</span>
                    <strong>{captureActive ? (backendActivity.currentPhase || 'active capture') : 'standby'}</strong>
                  </div>
                  <div className={`backend-stage-status ${captureActive ? 'live' : 'idle'}`}>
                    <span className="backend-stage-status-dot" />
                    {captureActive ? 'tracking' : 'idle'}
                  </div>
                </div>
                <div className="backend-stage-rail">
                  {(backendActivity.stageRail || []).map((phase) => (
                    <div key={phase.id} className={`backend-stage-node ${phase.visualState}`} title={`${phase.label} · ${phase.role || 'phase'} · ${phase.percent}%`}>
                      <div className="backend-stage-node-core">
                        <span className="backend-stage-node-ring" />
                        <span className="backend-stage-node-fill" style={{ '--phase-percent': `${Math.max(6, Math.min(100, phase.percent || 0))}%` }} />
                        <span className="backend-stage-node-label">{phase.shortLabel}</span>
                      </div>
                      <div className="backend-stage-node-meta">
                        <strong>{Math.round(phase.percent || 0)}%</strong>
                        <small>{phase.role || `${phase.seconds || 0}s window`}</small>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="backend-stage-links" aria-hidden="true">
                  {(backendActivity.stageRail || []).slice(0, -1).map((phase, index) => (
                    <span key={`link:${phase.id}:${index}`} className={captureActive ? 'active' : ''} style={{ '--link-delay': `${index * 180}ms` }} />
                  ))}
                </div>
                <div className="backend-signal-stream" aria-hidden="true">
                  {Array.from({ length: backendActivity.livePulseCount || 6 }).map((_, index) => (
                    <span key={`pulse:${index}`} className={captureActive ? 'active' : ''} style={{ '--pulse-delay': `${index * 120}ms` }} />
                  ))}
                </div>
                {!cameraHuntMode ? (
                <>
                <div className="backend-scan-visuals">
                  <div className="backend-radar-card" title={`Radar view of current hot channels: ${backendActivity.hotChannels || '--'}`}>
                    <div className="backend-radar-head">
                      <span className="backend-stage-kicker">Channel Radar</span>
                      <strong>{(backendActivity.hotChannels || '--').split(', ').slice(0, 3).join(', ') || '--'}</strong>
                    </div>
                    <div className={`backend-radar ${captureActive ? 'live' : ''}`}>
                      <span className="backend-radar-ring ring-a" />
                      <span className="backend-radar-ring ring-b" />
                      <span className="backend-radar-ring ring-c" />
                      <span className="backend-radar-axis axis-h" />
                      <span className="backend-radar-axis axis-v" />
                      <span className="backend-radar-sweep" />
                      {(backendActivity.radarBlips || []).map((blip) => (
                        <span
                          key={`blip:${blip.channel}`}
                          className="backend-radar-blip"
                          style={{
                            '--blip-x': `${blip.x}px`,
                            '--blip-y': `${blip.y}px`,
                            '--blip-scale': String(0.8 + blip.strength),
                          }}
                          title={`ch ${blip.channel} · ${blip.frames} frames · ${blip.visits} visits`}
                        />
                      ))}
                    </div>
                  </div>
                  <div className="backend-image-card" title={`Evidence-based media recoverability from real protocol, decrypt, and artifact signals: ${backendActivity.imageRecovery?.summary || '--'}`}>
                    <div className="backend-radar-head">
                      <span className="backend-stage-kicker">Media Recoverability</span>
                      <strong>{backendActivity.imageRecovery?.score ?? 0}% · {backendActivity.imageRecovery?.level || 'LOW'}</strong>
                    </div>
                    <div className={`backend-image-meter ${String(backendActivity.imageRecovery?.level || 'LOW').toLowerCase()}`}>
                      <span
                        className={captureActive ? 'active' : ''}
                        style={{ '--image-strength': `${Math.max(6, backendActivity.imageRecovery?.score || 0)}%` }}
                      />
                    </div>
                    <div className="backend-image-summary">{backendActivity.imageRecovery?.summary || 'No retained payload evidence yet.'}</div>
                    <div className="backend-image-reasons">
                      {(backendActivity.imageRecovery?.reasons || []).map((reason) => (
                        <span key={reason}>{reason}</span>
                      ))}
                    </div>
                  </div>
                  <div className="backend-pulsemap-card" title="Per-channel pulse map for the current retained scan window.">
                    <div className="backend-radar-head">
                      <span className="backend-stage-kicker">Pulse Map</span>
                      <strong>{backendActivity.pulseChannels?.length || 0} active channels</strong>
                    </div>
                    <div className="backend-pulsemap-list">
                      {(backendActivity.pulseChannels || []).map((item, index) => (
                        <div key={`channel:${item.channel}`} className="backend-pulsemap-row">
                          <div className="backend-pulsemap-meta">
                            <strong>ch {item.channel}</strong>
                            <small>{item.frames} frames · {fmtBytes(item.bytes || 0)} · recover {item.imagePotential || 0}%</small>
                          </div>
                          <div className="backend-pulsemap-track">
                            <span
                              className={`${captureActive ? 'active' : ''} ${(item.imagePotential || 0) >= 60 ? 'high' : (item.imagePotential || 0) >= 35 ? 'medium' : 'low'}`.trim()}
                              style={{
                                '--channel-strength': `${Math.max(8, Math.min(100, Math.round(item.frames / Math.max(1, backendActivity.pulseChannels?.[0]?.frames || 1) * 100)))}%`,
                                '--channel-delay': `${index * 90}ms`,
                                '--image-strength': `${Math.max(4, item.imagePotential || 0)}%`,
                                '--byte-strength': `${Math.max(5, Math.min(100, Math.round((item.bytes || 0) / Math.max(1, backendActivity.strongestChannelBytes || 1) * 100)))}%`,
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="backend-evidence-strip">
                  <div className="backend-evidence-card" title="How far the current run has progressed from RF presence to plausible image recovery.">
                    <div className="backend-radar-head">
                      <span className="backend-stage-kicker">Evidence Ladder</span>
                      <strong>{backendActivity.recoverabilityGauge?.label || 'Metadata'} · {backendActivity.recoverabilityGauge?.score ?? 0}%</strong>
                    </div>
                    <div className="backend-evidence-ladder">
                      {(backendActivity.evidenceLadder || []).map((stage, index) => (
                        <div key={`ladder:${stage.label}:${index}`} className={`backend-evidence-step ${stage.active ? 'active' : ''}`}>
                          <div className="backend-evidence-step-head">
                            <strong>{stage.label}</strong>
                            <span>{stage.score}%</span>
                          </div>
                          <div className="backend-evidence-step-track">
                            <span style={{ '--evidence-strength': `${Math.max(5, stage.score)}%` }} />
                          </div>
                          <small>{stage.detail}</small>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="backend-timeline-card" title="Top leads ranked by current image-recovery likelihood and continuity across retained slices.">
                    <div className="backend-radar-head">
                      <span className="backend-stage-kicker">Continuity Timeline</span>
                      <strong>{backendActivity.topRecoverableLeads?.length || 0} active leads</strong>
                    </div>
                    <div className="backend-timeline-list">
                      {(backendActivity.topRecoverableLeads || []).map((lead) => (
                        <div key={lead.id} className="backend-timeline-row">
                          <div className="backend-timeline-meta">
                            <strong>{lead.label}</strong>
                            <small>ch {lead.channel} · {lead.score}% · {fmtBytes(lead.bytes)} · {lead.dataFrames} data</small>
                          </div>
                          <div className="backend-timeline-spark" aria-hidden="true">
                            {(lead.spark || []).map((height, index) => (
                              <span key={`${lead.id}:spark:${index}`} style={{ '--spark-height': `${height}%`, '--spark-delay': `${index * 120}ms` }} className={captureActive ? 'active' : ''} />
                            ))}
                          </div>
                          <div className="backend-timeline-caption">
                            <span>{lead.kind}</span>
                            <span>{lead.confidence}% camera</span>
                            <span>{lead.continuity}% continuity</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="backend-evidence-strip backend-evidence-strip-secondary">
                  <div className="backend-blocker-card" title="Primary blockers keeping current leads from becoming recoverable image artifacts.">
                    <div className="backend-radar-head">
                      <span className="backend-stage-kicker">Why Not Recoverable Yet</span>
                      <strong>{backendActivity.recoveryBlockers?.length || 0} blockers</strong>
                    </div>
                    <div className="backend-blocker-list">
                      {(backendActivity.recoveryBlockers || []).map((blocker) => (
                        <div key={blocker.label} className="backend-blocker-row">
                          <strong>{blocker.label}</strong>
                          <span>{blocker.count} lead{blocker.count === 1 ? '' : 's'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="backend-matrix-card" title="Live media-path matrix for the highest-value camera leads.">
                    <div className="backend-radar-head">
                      <span className="backend-stage-kicker">Media Path Matrix</span>
                      <strong>{backendActivity.mediaPathMatrix?.length || 0} leads</strong>
                    </div>
                    <div className="backend-matrix-grid">
                      <div className="backend-matrix-header">
                        <span>Lead</span>
                        {['Identity', 'Continuity', 'HTTP', 'RTSP', 'TLS', 'Decrypt', 'Objects', 'Image'].map((label) => (
                          <span key={`matrix-head:${label}`}>{label}</span>
                        ))}
                      </div>
                      {(backendActivity.mediaPathMatrix || []).map((row) => (
                        <div key={row.id} className="backend-matrix-row">
                          <strong>{row.label}</strong>
                          {row.cells.map((cell) => (
                            <span
                              key={`${row.id}:${cell.label}`}
                              className={cell.score >= 70 ? 'high' : cell.score >= 35 ? 'medium' : 'low'}
                              title={`${cell.label}: ${cell.score}%`}
                            >
                              {cell.score}
                            </span>
                          ))}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                </>
                ) : null}
              </div>
            ) : null}
            <div className={`camera-hunt-evidence-board camera-hunt-runtime-board ${hardAuditActive ? 'audit-live' : ''}`}>
              <div className="camera-hunt-evidence-head">
                <span className="backend-stage-kicker">Runtime Apps</span>
                <strong>{hardAuditActive ? `${hardAuditTimer.label} · ` : ''}{backendActivity.runtimeSummary?.activeCount || 0} active · {backendActivity.runtimeSummary?.cleanupState || 'idle'}</strong>
              </div>
              <div className="camera-hunt-evidence-list">
                {(backendActivity.runtimeApps || []).map((tool) => (
                  <div key={`runtime:${tool.name}`} className={`camera-hunt-evidence-row ${tool.active || (hardAuditActive && backendActivity.runtimeSummary?.activeCount) ? 'active' : ''}`}>
                    <strong>{tool.name}</strong>
                    <span>{tool.state}</span>
                    <small>{tool.detail || 'no runtime metadata retained'}</small>
                  </div>
                ))}
              </div>
              <div className="table-secondary">{hardAuditActive ? hardAuditTimer.summary : (backendActivity.runtimeSummary?.summary || 'Runtime status unavailable.')}</div>
            </div>
            {cameraHuntMode ? (
              <>
                <div className="camera-hunt-evidence-board">
                  <div className="camera-hunt-evidence-head">
                    <span className="backend-stage-kicker">Evidence Ladder</span>
                    <strong>{backendActivity.recoverabilityGauge?.label || 'Metadata'} · {backendActivity.recoverabilityGauge?.score ?? 0}%</strong>
                  </div>
                  <div className="camera-hunt-evidence-list">
                    {(backendActivity.evidenceLadder || []).map((stage) => (
                      <div key={`camera-ladder:${stage.label}`} className={`camera-hunt-evidence-row ${stage.active ? 'active' : ''}`}>
                        <strong>{stage.label}</strong>
                        <span>{stage.score}%</span>
                        <small>{stage.detail}</small>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : null}
            {!cameraHuntMode ? (
              <>
                <div className="backend-stage-hud" title={`Current phase ${backendActivity.currentPhase || 'idle'} · ${backendActivity.processingTopology}`}>
                  <div className="backend-stage-hud-head">
                    <div>
                      <span className="backend-stage-kicker">WiFi Hunt Pipeline</span>
                      <strong>{captureActive ? (backendActivity.currentPhase || 'active capture') : 'standby'}</strong>
                    </div>
                    <div className={`backend-stage-status ${captureActive ? 'live' : 'idle'}`}>
                      <span className="backend-stage-status-dot" />
                      {captureActive ? 'tracking' : 'idle'}
                    </div>
                  </div>
                  <div className="backend-stage-rail">
                    {(backendActivity.stageRail || []).map((phase) => (
                      <div key={`wifi-stage:${phase.id}`} className={`backend-stage-node ${phase.visualState}`} title={`${phase.label} · ${phase.role || 'phase'} · ${phase.percent}%`}>
                        <div className="backend-stage-node-core">
                          <span className="backend-stage-node-ring" />
                          <span className="backend-stage-node-fill" style={{ '--phase-percent': `${Math.max(6, Math.min(100, phase.percent || 0))}%` }} />
                          <span className="backend-stage-node-label">{phase.shortLabel}</span>
                        </div>
                        <div className="backend-stage-node-meta">
                          <strong>{Math.round(phase.percent || 0)}%</strong>
                          <small>{phase.role || `${phase.seconds || 0}s window`}</small>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="backend-stage-links" aria-hidden="true">
                    {(backendActivity.stageRail || []).slice(0, -1).map((phase, index) => (
                      <span key={`wifi-link:${phase.id}:${index}`} className={captureActive ? 'active' : ''} style={{ '--link-delay': `${index * 180}ms` }} />
                    ))}
                  </div>
                  <div className="backend-signal-stream" aria-hidden="true">
                    {Array.from({ length: backendActivity.livePulseCount || 6 }).map((_, index) => (
                      <span key={`wifi-pulse:${index}`} className={captureActive ? 'active' : ''} style={{ '--pulse-delay': `${index * 120}ms` }} />
                    ))}
                  </div>
                </div>
                <div className="camera-hunt-evidence-board">
                  <div className="camera-hunt-evidence-head">
                    <span className="backend-stage-kicker">Hard Audit Topology</span>
                    <strong>{selectedNetwork ? (selectedNetwork.ssid || selectedNetwork.bssid || selectedNetwork.mac || 'selected target') : 'No selected target'}</strong>
                  </div>
                  {(selectedNetwork ? getServiceAuditStages(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null) : []).length ? (
                    <div className="camera-hunt-evidence-list">
                      {getServiceAuditStages(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null).map((stage) => {
                        const processingStageId = getServiceAuditProcessingStageId(selectedNetwork, serviceAudit?.target_id === getEntitySelectionId(selectedNetwork, false) ? serviceAudit : null)
                        const processing = serviceAuditBusy && stage.id === processingStageId
                        return (
                        <div key={`wifi-audit-stage:${stage.id}`} className={`camera-hunt-evidence-row ${stage.status === 'completed' || stage.status === 'active' ? 'active' : ''} ${processing ? 'processing' : ''}`.trim()}>
                          <strong>{stage.label}</strong>
                          <span>{processing ? 'processing' : stage.status}</span>
                          <small>{stage.detail || 'no detail retained'}</small>
                        </div>
                        )
                      })}
                    </div>
                  ) : (
                    <div className="camera-hard-empty">
                      <strong>Hard Audit Idle</strong>
                      <span>Select a WiFi device and run `Hard Audit` to validate ports, services, access posture, and external destination evidence.</span>
                    </div>
                  )}
                </div>
                <div className="camera-hunt-evidence-board">
                  <div className="camera-hunt-evidence-head">
                    <span className="backend-stage-kicker">Top WiFi Targets</span>
                    <strong>{attackableTargets.length || 0} retained</strong>
                  </div>
                  <div className="camera-hunt-top-leads">
                    {(attackableTargets || []).slice(0, 4).map((lead) => (
                      <div key={`wifi-top:${lead.id}`} className="camera-hunt-top-lead">
                        <strong>{lead.label}</strong>
                        <span>{lead.type} · {lead.score}</span>
                        <small>{lead.proximity} · {lead.why}</small>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : null}
          </div>
        </Panel>
        {cameraHuntMode ? (
          <Panel kicker="Evidence Escalation" title="Hard Audit Pipeline">
            <div className="guidance-list">
              <div className="camera-hunt-evidence-board" title={getCameraHardAuditPipeline(inspectedNetwork || {}).summary || 'No hard audit running.'}>
                <div className="camera-hunt-evidence-head">
                  <span className="backend-stage-kicker">Hard Audit Ladder</span>
                  <strong>{inspectedNetwork ? getCameraLeadIdentity(inspectedNetwork) : 'No selected lead'}</strong>
                </div>
                {(inspectedNetwork ? getCameraHardAuditStages(inspectedNetwork) : []).length ? (
                  <>
                    <div className="camera-hunt-evidence-list">
                      {getCameraHardAuditStages(inspectedNetwork).map((stage) => {
                        const processingStageId = getCameraHardAuditProcessingStageId(inspectedNetwork)
                        const processing = hardAuditActive && stage.id === processingStageId
                        return (
                        <div
                          key={`camera-hard-ladder:${stage.id}`}
                          className={`camera-hunt-evidence-row ${stage.status === 'completed' || stage.status === 'active' ? 'active' : ''} ${processing ? 'processing' : ''}`.trim()}
                        >
                          <strong>{stage.label}</strong>
                          <span>{processing ? 'processing' : stage.status}</span>
                          <small>{stage.detail || 'no detail retained'}</small>
                        </div>
                        )
                      })}
                    </div>
                    <div className="backend-signal-stream" aria-hidden="true">
                      {Array.from({ length: 8 }).map((_, index) => (
                        <span key={`hard-pulse:${index}`} className={(cameraLeadHardAuditBusy || String(getCameraHardAuditPipeline(inspectedNetwork || {}).status || '') === 'running') ? 'active' : ''} style={{ '--pulse-delay': `${index * 90}ms` }} />
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="camera-hard-empty">
                    <strong>Hard Audit Idle</strong>
                    <span>Select a lead and run `Hard Audit` to watch staged evidence escalation.</span>
                  </div>
                )}
                <div className="guidance-item compact">
                  <strong>Summary:</strong> {getCameraHardAuditPipeline(inspectedNetwork || {}).summary || 'No hard-audit summary retained.'}
                </div>
              </div>
              <div className="camera-hunt-evidence-board">
                <div className="camera-hunt-evidence-head">
                  <span className="backend-stage-kicker">Media Plane</span>
                  <strong>{getCameraLayerAudit(inspectedNetwork || {}).media_plane_detected || 'Not Classified'}</strong>
                </div>
                {getCameraLayerAuditRows(inspectedNetwork || {}).length ? (
                  <div className="camera-hunt-evidence-list">
                    {getCameraLayerAuditRows(inspectedNetwork || {}).map((layer) => (
                      <div key={`camera-layer:${layer.id}`} className={`camera-hunt-evidence-row ${layer.status === 'complete' || layer.status === 'partial' ? 'active' : ''}`}>
                        <strong>{layer.label}</strong>
                        <span>{layer.status}</span>
                        <small>{layer.detail || 'no detail retained'}</small>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="camera-hard-empty">
                    <strong>Layer Audit Idle</strong>
                    <span>`Hard Audit` now includes layer classification and will show when media artifacts are saved.</span>
                  </div>
                )}
                <div className="guidance-item compact">
                  <strong>Recovery Path:</strong> {getCameraLayerAudit(inspectedNetwork || {}).evidence_recovery_path || 'Not classified yet'}
                </div>
              </div>
            </div>
          </Panel>
        ) : null}
        {!cameraHuntMode && handshakeAnalysisEnabled ? (
          <Panel kicker="Coverage Audit" title="Per-SSID Observation Coverage">
            <div className="guidance-list">
              <div className="guidance-item compact">
                <strong>Scope:</strong> Real per-SSID observation coverage from retained frames and observed authentication evidence sessions.
              </div>
              <div className="matrix-table-wrap compact">
                <table className="matrix-table coverage-table">
                  <thead>
                    <tr>
                      <th>SSID</th>
                      <th>Ch</th>
                      <th>Visits</th>
                      <th>Frames</th>
                      <th>EAPOL Sessions</th>
                      <th>Opportunity</th>
                      <th>Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {coverageRows.length ? coverageRows.slice(0, 10).map((row) => (
                      <tr
                        key={`coverage:${row.id}`}
                        className="coverage-row"
                        title={`Red Team Observation: ${row.redObservation}`}
                        onClick={() => handleSelectNetwork(row.network)}
                      >
                        <td>
                          <button type="button" className="coverage-link" onClick={(event) => { event.stopPropagation(); handleSelectNetwork(row.network) }}>
                            {row.ssid}
                          </button>
                          <div className="table-secondary">{row.network?.bssid || 'unresolved'}</div>
                        </td>
                        <td>{row.channel}</td>
                        <td>{row.visits}</td>
                        <td>{row.retainedFrames}</td>
                        <td>{row.sessionCount}</td>
                        <td>
                          <strong>{row.observationLevel}</strong>
                          <div className="table-secondary">{row.observationScore}/100</div>
                        </td>
                        <td>
                          <strong>{row.evidenceQuality}</strong>
                          <div className="table-secondary">{row.network?.authentication_evidence?.eapol_frame_count ?? 0} EAPOL</div>
                        </td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="7" className="empty-cell">No per-SSID coverage retained yet.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </Panel>
        ) : null}
        {!cameraHuntMode ? (
          <Panel
            kicker="Analyst Console"
            title="Evidence and Risk"
          >
            <div className="analyst-console">
              <details className="backend-summary-details" open>
                <summary>Evidence Sessions</summary>
                <div className="analyst-section-grid">
                  <div className="guidance-item compact">
                    <strong>Summary:</strong> {handshakeSummary.sessionCount} sessions · {handshakeSummary.networkCount} networks · {handshakeSummary.clientCount} clients · {handshakeSummary.totalEapolFrames} EAPOL
                  </div>
                  {true ? (
                    <div className="guidance-item compact">
                      <strong>Read:</strong> {handshakeSummary.sessionCount
                        ? `Observed evidence is real on ${handshakeSummary.sessionCount} sessions. Work highest-risk SSIDs first.`
                        : 'No observed authentication evidence yet. Focus on high-opportunity SSIDs and coverage gaps.'}
                    </div>
                  ) : null}
                </div>
                <div className="matrix-table-wrap compact analyst-table-wrap">
                  <table className="matrix-table coverage-table">
                    <thead>
                      <tr>
                        <th>SSID</th>
                        <th>Client</th>
                        <th>Quality</th>
                        <th>EAPOL</th>
                        <th>Opportunity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {evidenceQueue.length ? evidenceQueue.map((session) => (
                        <tr key={`auth-evidence:${session.bssid}:${session.client_mac}:${session.start_time}`} title={`Observed session ${session.quality || 'NONE'} · first ${fmtTime(session.start_time)} · last ${fmtTime(session.last_time)}`}>
                          <td>
                            <strong>{session.ssid || session.network?.ssid || '<hidden>'}</strong>
                            <div className="table-secondary">{session.bssid || 'unresolved'}</div>
                          </td>
                          <td>{session.client_mac || '--'}</td>
                          <td>{session.quality || 'NONE'}</td>
                          <td>{session.frame_count ?? 0}</td>
                          <td>{session.network?.observation_opportunity?.level || 'LOW'} {session.network?.observation_opportunity?.score ?? 0}/100</td>
                        </tr>
                      )) : (
                        <tr>
                          <td colSpan="5" className="empty-cell">No authentication evidence queue entries retained yet.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </details>

              <details className="backend-summary-details" open>
                <summary>Password Risk Queue</summary>
                <div className="guidance-item compact">
                  <strong>Queue:</strong> {passwordRiskTargets.filter((item) => item?.password_risk?.risk === 'CRITICAL').length} critical · {passwordRiskTargets.filter((item) => item?.password_risk?.risk === 'HIGH').length} high · {passwordRiskTargets.filter((item) => item?.password_risk?.risk === 'MEDIUM').length} medium
                </div>
                <div className="matrix-table-wrap compact analyst-table-wrap">
                  <table className="matrix-table coverage-table">
                    <thead>
                      <tr>
                        <th>SSID</th>
                        <th>Risk</th>
                        <th>Evidence</th>
                        <th>Opportunity</th>
                        <th>ETA</th>
                      </tr>
                    </thead>
                    <tbody>
                      {passwordRiskTargets.length ? passwordRiskTargets.map((network) => (
                        <tr key={`pw-risk:${getNetworkId(network)}`} title={getNetworkObservationTooltip(network, coverageMap.get(getNetworkId(network)))}>
                          <td>
                            <strong>{network.ssid || '<hidden>'}</strong>
                            <div className="table-secondary">{network.bssid || 'unresolved'} · {network.security || '--'}</div>
                          </td>
                          <td>{network.password_risk?.risk || 'LOW'} {network.password_risk?.score ?? '--'}/100</td>
                          <td>{network.authentication_evidence?.quality || 'NONE'} · {network.authentication_evidence?.eapol_frame_count ?? 0}</td>
                          <td>{network.observation_opportunity?.level || 'LOW'} {network.observation_opportunity?.score ?? 0}/100</td>
                          <td>{network.password_risk?.attack_feasibility?.cpu_only_eta || '--'}</td>
                        </tr>
                      )) : (
                        <tr>
                          <td colSpan="5" className="empty-cell">No ranked password-risk targets retained yet.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </details>

            </div>
          </Panel>
        ) : null}
        {false && isPanelVisible('channelPlan') ? (
          <Panel kicker="Channel Plan" title="Sweep Coverage">
            <pre className="json-box">{JSON.stringify(channels || status?.channels || {}, null, 2)}</pre>
          </Panel>
        ) : null}
        {false && isPanelVisible('evidence') ? (
          <Panel kicker="Evidence" title="Recent PCAPs">
            <pre className="json-box">{pcaps.length ? JSON.stringify(pcaps.slice(0, 10), null, 2) : 'No retained PCAP references yet.'}</pre>
          </Panel>
        ) : null}
        {false && isPanelVisible('timeline') ? (
          <Panel kicker="Timeline" title="Sensor State">
            <div className="guidance-list">
              <div className="guidance-item"><strong>Armed:</strong> {status?.armed ? 'yes' : 'no'}</div>
              <div className="guidance-item"><strong>Capture Active:</strong> {status?.capture_active ? 'yes' : 'no'}</div>
              <div className="guidance-item"><strong>Last Start:</strong> {fmtTime(status?.last_started_at)}</div>
              <div className="guidance-item"><strong>Last Sweep:</strong> {fmtTime(status?.last_sweep_at)}</div>
            </div>
          </Panel>
        ) : null}
      </div>
    </main>
  )
}
