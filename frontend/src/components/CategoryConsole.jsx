import { useEffect, useMemo, useRef, useState } from 'react'
import { Metric, Panel, Pill } from './ui'
import SpectrumCanvas from './SpectrumCanvas'
import RealtimeTopologyRail from './RealtimeTopologyRail'
import SignalTable from './SignalTable'
import DeviceList from './DeviceList'
import { freq } from '../lib/runtime'
import { usePanelPreferences } from '../lib/viewPreferences'
import { countBy, getPrioritySignals, matchDevicesForSignals, metricDetailSignal, summarizeCommon } from '../lib/categoryIntel'
import {
  fetchBandIntel,
  clearBleDecoder,
  fetchBleDecoderStatus,
  fetchCorrelations,
  fetchIntelDeviceDetail,
  fetchSignalDetail,
  startBleDecoder,
  stopBleDecoder,
} from '../lib/api'

function InspectorDrawer({ title, defaultOpen = false, children }) {
  return (
    <details className="inspector-drawer" open={defaultOpen}>
      <summary>{title}</summary>
      <div className="inspector-drawer-body">{children}</div>
    </details>
  )
}

function renderRows(items, emptyMessage, renderLabel, renderValue) {
  if (!items.length) {
    return <div className="empty-box">{emptyMessage}</div>
  }

  return (
    <div className="intel-stack">
      {items.map((item, index) => (
        <div key={`${renderLabel(item)}-${index}`} className="intel-row">
          <span>{renderLabel(item)}</span>
          <strong>{renderValue(item)}</strong>
        </div>
      ))}
    </div>
  )
}

function formatRelativeTime(timestamp) {
  if (!timestamp) return '--'
  const delta = Math.max(0, Math.round(Date.now() / 1000 - Number(timestamp)))
  if (delta < 60) return `${delta}s ago`
  if (delta < 3600) return `${Math.round(delta / 60)}m ago`
  return `${Math.round(delta / 3600)}h ago`
}

function formatAbsoluteDateTime(timestamp) {
  if (!timestamp) return '--'
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleString()
}

function formatObservedTime(timestampOrRecord) {
  const raw = typeof timestampOrRecord === 'object' && timestampOrRecord !== null
    ? (timestampOrRecord?.last_seen || timestampOrRecord?.timestamp || timestampOrRecord?.first_seen || null)
    : timestampOrRecord
  if (!raw) return '--'
  const millis = Number(raw) > 1e12 ? Number(raw) : Number(raw) * 1000
  const date = new Date(millis)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleString()
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

function downloadCsv(filename, rows) {
  if (!rows?.length) return
  const headers = [...new Set(rows.flatMap((row) => Object.keys(row || {})))]
  const escapeCell = (value) => {
    const stringValue = value === null || value === undefined ? '' : String(value)
    return `"${stringValue.replaceAll('"', '""')}"`
  }
  const csv = [
    headers.join(','),
    ...rows.map((row) => headers.map((header) => escapeCell(row?.[header])).join(',')),
  ].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function buildSweepCsvRows(tab, signals, devices) {
  const signalRows = (signals || []).map((signal) => ({
    row_type: 'signal',
    tab,
    signal_id: signal?.signal_id || '',
    protocol: signal?.protocol || signal?.rf_protocol || '',
    frequency_mhz: signal?.frequency_mhz || signal?.freq_mhz || '',
    mac_address: signal?.mac_address || signal?.ble_mac || signal?.device_mac || '',
    vendor: signal?.vendor || signal?.rf_vendor_candidate || signal?.brand || '',
    product: signal?.product || signal?.device_type || signal?.device_class || '',
    device_id: signal?.device_id || '',
    confidence: signal?.confidence || signal?.rf_confidence || '',
    last_seen: signal?.last_seen || signal?.timestamp || '',
  }))
  const deviceRows = (devices || []).map((device) => ({
    row_type: 'device',
    tab,
    device_id: device?.device_id || '',
    protocols: (device?.protocols || []).join('|'),
    mac_address: device?.mac_address || '',
    vendor: device?.vendor || device?.brand || '',
    product: device?.product || device?.device_type || device?.device_class || '',
    frequencies_mhz: (device?.frequencies || []).join('|'),
    confidence: device?.confidence || device?.device_confidence || '',
    last_seen: device?.last_seen || '',
  }))
  return [...signalRows, ...deviceRows]
}

function buildHeartbeatSegments(lastUpdate) {
  const ageSec = lastUpdate ? Math.max(0, (Date.now() - lastUpdate) / 1000) : 999
  return [0, 1, 2, 3, 4].map((threshold, index) => ({
    key: index,
    active: ageSec <= threshold + 1,
  }))
}

function getOpsDeckState({ activeSweep, streamingConfirmed, bleDecoderRunning, runtimeWarning }) {
  if (runtimeWarning && !streamingConfirmed && !activeSweep?.running && !bleDecoderRunning) {
    return {
      label: 'Sensor Attention',
      tone: 'warn',
      detail: runtimeWarning,
    }
  }
  if (activeSweep?.running) {
    return {
      label: 'Sweep Live',
      tone: 'live',
      detail: activeSweep.currentLabel
        ? `${activeSweep.currentLabel} · ${freq(activeSweep.currentFrequencyMHz)}`
        : 'Band sweep is active',
    }
  }
  if (bleDecoderRunning) {
    return {
      label: 'Decode Live',
      tone: 'live',
      detail: 'Bluetooth decoder is actively consuming SDR traffic.',
    }
  }
  if (streamingConfirmed) {
    return {
      label: 'Monitoring',
      tone: 'ready',
      detail: 'HackRF stream is live and waiting for the next operator sweep.',
    }
  }
  return {
    label: 'Standby',
    tone: 'idle',
    detail: 'Start Session to arm the HackRF path, then run a focused sweep.',
  }
}

function summarizeEvidenceRows(signals, devices) {
  const counts = new Map()
  ;[...signals, ...devices].forEach((item) => {
    const key = item?.evidence_tier || 'unknown'
    counts.set(key, (counts.get(key) || 0) + 1)
  })
  return [...counts.entries()].map(([label, count]) => ({ label, count }))
}

function summarizeBrandLeads(signals, devices) {
  const hasDecodedBleEvidence = (item) => {
    const protocols = [item?.protocol, item?.rf_protocol, ...(item?.protocols || [])]
      .filter(Boolean)
      .map((value) => String(value).toUpperCase())
    const bleLike = protocols.includes('BLE') || protocols.includes('BLUETOOTH_LE') || String(item?.channel_family || '').toLowerCase() === 'ble'
    if (!bleLike) return true
    return Number(item?.ble_decoded_evidence_score || 0) >= 0.45 || Boolean(item?.manufacturer_confirmed)
  }
  const suspiciousDevices = (devices || []).filter((item) =>
    item?.spam_like
    || (
      item?.privacy_state === 'randomized'
      && !item?.vendor
      && !item?.probable_vendor_family
      && !item?.product
      && !item?.probable_product_family
      && Number(item?.service_hint_count || 0) === 0
      && !item?.manufacturer_data_present
    ))
  if (suspiciousDevices.length >= 4) {
    return [
      {
        label: 'Possible BLE spam / synthetic advertiser source',
        count: suspiciousDevices.length,
      },
    ]
  }
  const counts = new Map()
  ;[...(devices || []), ...(signals || [])].forEach((item) => {
    if (!hasDecodedBleEvidence(item)) return
    const vendor =
      item?.vendor
      || item?.brand
      || item?.rf_vendor_candidate
      || item?.lora_lab_profile_candidates?.[0]?.vendor
    const product =
      item?.product
      || item?.device_type
      || item?.device
      || item?.device_class
      || item?.product_category_hint
      || item?.lora_lab_profile_name
      || item?.lora_lab_profile_candidates?.[0]?.profile_name
    const normalizedVendor = vendor && !String(vendor).toLowerCase().includes('unknown') ? vendor : null
    const normalizedProduct = product && !String(product).toLowerCase().includes('unknown') ? product : null
    if (!normalizedVendor && !normalizedProduct) return
    if (item?.spam_like) return
    const label = normalizedProduct ? `${normalizedVendor || 'Unknown'} · ${normalizedProduct}` : String(normalizedVendor)
    counts.set(label, (counts.get(label) || 0) + 1)
  })
  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8)
}

function getVendorPostureLabel(signal) {
  const protocols = [signal?.protocol, signal?.rf_protocol].filter(Boolean).map((value) => String(value).toUpperCase())
  const bleLike = protocols.includes('BLE') || protocols.includes('BLUETOOTH_LE') || String(signal?.channel_family || '').toLowerCase() === 'ble'
  if (bleLike && Number(signal?.ble_decoded_evidence_score || 0) < 0.45 && !signal?.manufacturer_confirmed) {
    return 'Unknown'
  }
  return signal?.vendor || signal?.rf_vendor_candidate || 'Unknown'
}

function formatPercent(value) {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return '--'
  return `${Math.round(numeric * 100)}%`
}

function getBleVerdictTier(indicators) {
  const verdictLabel = String(indicators?.attack_verdict?.label || 'none').toLowerCase()
  const verdictConfidence = Number(indicators?.attack_verdict?.confidence || 0)
  const metrics = indicators?.attack_metrics || {}
  const decoderStatus = indicators?.decoder_status || {}
  const packetCount = Number(metrics?.decoder_packet_count ?? decoderStatus?.packet_count ?? 0)
  const recentMacs = Number(metrics?.recent_unique_mac_count ?? decoderStatus?.spam_summary?.recent_unique_mac_count ?? 0)

  if (verdictLabel !== 'none' && verdictConfidence >= 0.7 && packetCount >= 8 && recentMacs >= 8) {
    return { label: 'VERIFIED', tone: 'red', detail: 'decoder-backed bluetooth attack evidence' }
  }
  if (verdictLabel !== 'none' || indicators?.attack_leads?.length) {
    return { label: 'SUSPICIOUS', tone: 'amber', detail: 'under verification' }
  }
  return { label: 'RF-ONLY', tone: 'neutral', detail: 'no verified bluetooth attack evidence' }
}

function getBleDecoderHealth(status) {
  const packetCount = Number(status?.packet_count || 0)
  const emptyCaptureCount = Number(status?.empty_capture_count || 0)
  const trustedCount = Number(status?.trusted_identity_count || 0)
  const lastError = status?.last_error || ''

  if (lastError) {
    return { label: 'Degraded', detail: lastError, tone: 'red' }
  }
  if (!status?.running) {
    return { label: 'Idle', detail: 'decoder not running', tone: 'neutral' }
  }
  if (packetCount === 0 && emptyCaptureCount >= 3) {
    return { label: 'Degraded', detail: 'empty captures only, rf posture only', tone: 'amber' }
  }
  if (packetCount > 0 && trustedCount === 0) {
    return { label: 'Limited', detail: 'decoder sees packets but trust is low', tone: 'amber' }
  }
  return { label: 'Healthy', detail: 'decoder-backed bluetooth evidence available', tone: 'green' }
}

function buildBleOperatorSummary(indicators, mode) {
  const verdict = indicators?.attack_verdict || {}
  const metrics = indicators?.attack_metrics || {}
  const decoderStatus = indicators?.decoder_status || {}
  const spamSummary = decoderStatus?.spam_summary || {}
  const attackLeads = indicators?.attack_leads || []
  const verdictTier = getBleVerdictTier(indicators)
  const decoderHealth = getBleDecoderHealth(decoderStatus)

  const topClass = attackClasses[0]?.label || null
  const topLead = attackLeads[0]?.label || null
  const evidenceSource = verdictTier.label === 'VERIFIED'
    ? 'decoder-verified'
    : verdictTier.label === 'SUSPICIOUS'
      ? 'mixed rf and partial decoder evidence'
      : 'rf posture only'

  const summaryLabel = verdict?.label && verdict.label !== 'none'
    ? verdict.label
    : (topClass || topLead || 'No verified bluetooth adversary posture')

  const recentMacs = Number(metrics?.recent_unique_mac_count ?? spamSummary?.recent_unique_mac_count ?? 0)
  const randomizedRatio = Number(metrics?.recent_randomized_event_ratio ?? spamSummary?.randomized_event_ratio ?? 0)
  const scanRspRatio = Number(metrics?.recent_scan_response_ratio ?? spamSummary?.scan_response_ratio ?? 0)

  return {
    tier: verdictTier.label,
    tierTone: verdictTier.tone,
    summaryLabel,
    evidenceSource,
    decoderHealth: decoderHealth.label,
    decoderDetail: decoderHealth.detail,
    toolClass: verdict?.probable_tool_class || spamSummary?.probable_tool_class || '--',
    recentMacs,
    randomizedRatio,
    scanRspRatio,
    triggerDetail: topClass || topLead || 'no strong bluetooth attack trigger yet',
  }
}

function buildBleAttackAlertRow(tab, mode, indicators, currentFreq, enabled) {
  if (!enabled) return null
  if (tab !== 'BLE') return null

  const verdict = indicators?.attack_verdict || {}
  const leads = indicators?.attack_leads || []
  const decoderStatus = indicators?.decoder_status || {}
  const spamSummary = decoderStatus?.spam_summary || {}

  const verdictLabel = verdict?.label && verdict.label !== 'none' ? verdict.label : null
  const fallbackLabel = spamSummary?.alert && spamSummary.alert !== 'none' ? spamSummary.alert : null
  const attackLabel = verdictLabel || fallbackLabel
  if (!attackLabel) return null

  const confidence = Number(verdict?.confidence || spamSummary?.alert_confidence || 0)
  const toolClass = verdict?.probable_tool_class || spamSummary?.probable_tool_class || null
  const leadsSummary = leads.slice(0, 2).map((item) => item?.label).filter(Boolean).join(' · ')
  const recentMacs = Number(indicators?.attack_metrics?.recent_unique_mac_count ?? spamSummary?.recent_unique_mac_count ?? 0)
  const spamRatio = Number(indicators?.attack_metrics?.recent_randomized_event_ratio ?? spamSummary?.spam_event_ratio ?? 0)

  return {
    signal_id: 'ble-attack-alert',
    attack_alert_row: true,
    protocol: 'BLE',
    frequency_mhz: currentFreq || null,
    confidence,
    rf_band: '2.4GHz',
    attack_mac_label: toolClass && toolClass.toLowerCase().includes('flipper')
      ? 'FLIPPER ZERO BLE SPAM'
      : 'BLUETOOTH SPAM',
    attack_tool_class: toolClass || 'Unknown tool class',
    attack_vendor_detail: toolClass ? `confidence ${Math.round(Number(verdict?.tool_class_confidence || 0) * 100)}%` : 'tool class unresolved',
    attack_product_label: attackLabel,
    attack_product_detail: leadsSummary || `${recentMacs} recent advertisers · spam ratio ${Math.round(spamRatio * 100)}%`,
    attack_detail: leadsSummary || 'Bluetooth offensive spam posture detected',
    spam_like: true,
  }
}

function mergeIotSignals(current, incoming) {
  const merged = new Map()
  ;[...(current || []), ...(incoming || [])].forEach((signal) => {
    if (!signal) return
    const key = signal.signal_id || `${signal.protocol || 'UNKNOWN'}-${signal.frequency_mhz || signal.freq_mhz || 'na'}-${signal.device_id || 'none'}`
    const existing = merged.get(key)
    if (!existing) {
      merged.set(key, signal)
      return
    }
    const existingSeen = Number(existing.last_seen || existing.timestamp || 0)
    const nextSeen = Number(signal.last_seen || signal.timestamp || 0)
    merged.set(key, nextSeen >= existingSeen ? { ...existing, ...signal } : { ...signal, ...existing })
  })
  return [...merged.values()]
}

function mergeIotDevices(current, incoming) {
  const merged = new Map()
  ;[...(current || []), ...(incoming || [])].forEach((device) => {
    if (!device) return
    const key = device.device_id || `${(device.protocols || []).join('-')}-${(device.frequencies || []).join('-')}`
    const existing = merged.get(key)
    if (!existing) {
      merged.set(key, device)
      return
    }
    const existingSeen = Number(existing.last_seen || 0)
    const nextSeen = Number(device.last_seen || 0)
    merged.set(key, nextSeen >= existingSeen ? { ...existing, ...device } : { ...device, ...existing })
  })
  return [...merged.values()]
}

function buildBleInventorySignals(signals, devices) {
  const isPlaceholderDeviceId = (value) => /^DEV-\d+$/i.test(String(value || ''))
  const bleSignals = (signals || [])
    .filter((signal) => isStrictBleSignal(signal))
    .sort((left, right) => {
      const rightScore = Number(right?.trust_score || right?.ble_decoded_evidence_score || right?.confidence || 0)
      const leftScore = Number(left?.trust_score || left?.ble_decoded_evidence_score || left?.confidence || 0)
      return rightScore - leftScore
    })

  const projected = (devices || [])
    .filter((device) => {
      if (!device?.mac_address) return false
      const seenCount = Number(device?.seen_count || 0)
      const evidenceScore = Number(device?.best_evidence_score || device?.ble_decoded_evidence_score || 0)
      const trustScore = Number(device?.trust_score || 0)
      const suspicious = Boolean(device?.spam_like)
      const trusted = Boolean(device?.trusted_identity)
      return trusted || suspicious || seenCount > 0 || evidenceScore >= 0.12 || trustScore >= 0.18
    })
    .map((device) => ({
      signal_id: `ble-id-${device.mac_address}`,
      protocol: 'BLE',
      rf_protocol: 'BLUETOOTH_LE',
      frequency_mhz: device?.frequencies?.[0] || null,
      rf_band: '2.4GHz',
      mac_address: device.mac_address,
      vendor: device.vendor || null,
      product: device.product || null,
      device_id: device.device_id || `BLE-${device.mac_address}`,
      device_type: device.device_type || 'BLE Device',
      device_category: device.device_category || 'Short-Range Wireless Device',
      confidence: device.confidence || device.device_confidence || 0.9,
      last_seen: device.last_seen || null,
      identity_source: 'ble_decoder_identity',
      trusted_identity: Boolean(device.trusted_identity),
      trust_reasons: device.trust_reasons || [],
      privacy_state: device.privacy_state || null,
      seen_count: device.seen_count || 0,
      best_evidence_score: device.best_evidence_score || 0,
      trust_score: device.trust_score || 0,
      paired_scan_response: Boolean(device.paired_scan_response),
      paired_scan_response_count: device.paired_scan_response_count || 0,
      scan_response_seen_count: device.scan_response_seen_count || 0,
      crc_valid_count: device.crc_valid_count || 0,
      evidence_tier: device.evidence_tier || 'identity_supported',
      ble_identity_basis: device.ble_identity_basis || 'decoded_mac',
      ble_decoded_evidence_score: device.ble_decoded_evidence_score || 0.28,
      ble_payload: device.ble_payload || null,
    }))

  const existingDeviceKeys = new Set(
    projected.flatMap((signal) => [
      signal?.device_id,
      signal?.mac_address,
    ].filter(Boolean)),
  )

  const preferredSignals = bleSignals.filter((signal) => {
    const hasMac = Boolean(signal?.mac_address || signal?.ble_mac || signal?.device_mac)
    const decodedEvidence = Number(signal?.ble_decoded_evidence_score || 0)
    const trusted = Boolean(signal?.trusted_identity) || Number(signal?.trust_score || 0) >= 0.72
    const suspicious = Boolean(signal?.spam_like)
    const placeholderOnly = isPlaceholderDeviceId(signal?.device_id) && !hasMac

    if (hasMac) return true
    if (trusted && decodedEvidence >= 0.45) return true
    if (suspicious && decodedEvidence >= 0.45) return true
    if (placeholderOnly) return false
    return false
  })

  const grouped = new Map()
  ;[...projected, ...preferredSignals].forEach((signal) => {
    if (isPlaceholderDeviceId(signal?.device_id) && !signal?.mac_address && !signal?.spam_like) {
      return
    }
    const groupKey =
      signal?.mac_address
      || signal?.device_id
      || signal?.correlation_entity_id
      || `${signal?.ble_role || signal?.device_role_hint || 'ble'}-${Math.round(Number(signal?.frequency_mhz || signal?.freq_mhz || 0))}`

    if (!groupKey) return

    if (existingDeviceKeys.has(groupKey) && !String(signal?.signal_id || '').startsWith('ble-id-') && !signal?.mac_address) {
      return
    }

    const existing = grouped.get(groupKey)
    if (!existing) {
      grouped.set(groupKey, signal)
      return
    }

    const existingScore = Number(existing?.trust_score || existing?.ble_decoded_evidence_score || existing?.confidence || 0)
    const nextScore = Number(signal?.trust_score || signal?.ble_decoded_evidence_score || signal?.confidence || 0)
    const existingSeen = Number(existing?.last_seen || existing?.timestamp || 0)
    const nextSeen = Number(signal?.last_seen || signal?.timestamp || 0)
    grouped.set(groupKey, nextScore > existingScore || (nextScore === existingScore && nextSeen >= existingSeen) ? { ...existing, ...signal } : { ...signal, ...existing })
  })

  return [...grouped.values()]
    .filter((signal) => Boolean(signal?.mac_address || signal?.ble_mac || signal?.device_mac))
}

function isStrictBleSignal(signal) {
  const protocol = String(signal?.protocol || '').toUpperCase()
  const rfProtocol = String(signal?.rf_protocol || '').toUpperCase()
  const channelFamily = String(signal?.channel_family || '').toLowerCase()
  const rfBand = String(signal?.rf_band || signal?.band || '').toLowerCase()
  const negativeNeedles = ['WIFI', 'IEEE_802.11', 'ZIGBEE', 'LORA', 'LORAWAN', 'SUBGHZ']

  if ([protocol, rfProtocol].some((value) => negativeNeedles.some((needle) => value.includes(needle)))) {
    return false
  }
  if (['wifi', 'zigbee', 'lora', 'subghz'].includes(channelFamily)) {
    return false
  }
  if (protocol === 'BLE' || protocol === 'BLUETOOTH' || rfProtocol === 'BLUETOOTH_LE') {
    return true
  }
  if (channelFamily === 'ble') {
    return true
  }
  return rfBand === '2.4ghz' && Number(signal?.ble_channel) >= 37 && Number(signal?.ble_channel) <= 39
}

function getSweepStorageKey(tab) {
  return `ghostredrecon:sweep:${tab}`
}

function clearStoredSweepData() {
  try {
    const keysToRemove = []
    for (let index = 0; index < window.sessionStorage.length; index += 1) {
      const key = window.sessionStorage.key(index)
      if (key && key.startsWith('ghostredrecon:sweep:')) {
        keysToRemove.push(key)
      }
    }
    keysToRemove.forEach((key) => window.sessionStorage.removeItem(key))
  } catch {
    // ignore session storage failures
  }
}

function getSweepProfileKey(label, frequencyMHz) {
  return `${label || 'unknown'}@${Number(frequencyMHz || 0).toFixed(3)}`
}

function getSweepFreshnessTone(completedAt) {
  if (!completedAt) return { label: 'No Scan', tone: 'unknown' }
  const ageMs = Date.now() - Number(completedAt)
  if (ageMs <= 15 * 60 * 1000) return { label: 'Fresh', tone: 'fresh' }
  return { label: 'Stale', tone: 'stale' }
}

function HeartbeatPanel({ lastUpdate, fftAgeMs, stale }) {
  const segments = buildHeartbeatSegments(lastUpdate)
  return (
    <Panel kicker="Telemetry" title="Stream Heartbeat" className="dashboard-panel">
      <div className="heartbeat-strip">
        {segments.map((segment) => (
          <div key={segment.key} className={segment.active ? 'heartbeat-bar active' : 'heartbeat-bar'} />
        ))}
      </div>
      <div className="device-meta">
        Last band update: {lastUpdate ? new Date(lastUpdate).toLocaleTimeString() : 'waiting'}
      </div>
      <div className={stale ? 'error-inline staleness-warning' : 'device-meta'}>
        FFT age: {fftAgeMs < 1000 ? `${fftAgeMs} ms` : `${(fftAgeMs / 1000).toFixed(1)} s`}
        {stale ? ' · SDR stream may be stale' : ''}
      </div>
    </Panel>
  )
}

function BleIdentityPanel({ identities, selectedIdentity, onSelectIdentity, onExportIdentity }) {
  return (
    <Panel
      kicker="BLE"
      title="Advertiser Identities"
      className="dashboard-panel"
      action={selectedIdentity ? <button className="mini-action" onClick={() => onExportIdentity(selectedIdentity)}>Export Evidence</button> : null}
    >
      {identities?.length ? (
        <div className="device-list">
          {identities.map((item) => (
            <button
              key={item.mac_address}
              className={selectedIdentity?.mac_address === item.mac_address ? 'device-card selected-card' : 'device-card'}
              onClick={() => onSelectIdentity(item)}
            >
              <div className="device-title">{item.device_name || item.probable_product_family || item.device_hint || 'Unknown advertiser'}</div>
              <div className="device-meta">{item.mac_address}</div>
              <div className="device-meta">
                seen {item.seen_count || 0}
                {item.channels?.length ? ` · ch ${item.channels.join('/')}` : ''}
                {item.last_rssi ? ` · ${item.last_rssi} dBm` : ''}
              </div>
              <div className="device-meta">
                {(item.probable_vendor_family || item.vendor || 'Unknown vendor')}
                {item.privacy_state ? ` · ${item.privacy_state}` : ''}
                {item.apple_findmy_like ? ' · Apple Find My-like' : item.tracker_like ? ' · tracker-like' : item.beacon_like ? ' · beacon-like' : ''}
              </div>
              <div className="device-meta">
                evidence {item.evidence_quality || 'unknown'}
                {typeof item.best_evidence_score === 'number' ? ` · ${(item.best_evidence_score * 100).toFixed(0)}%` : ''}
                {item.service_hint_count ? ` · ${item.service_hint_count} service hints` : ''}
                {item.scan_response_seen_count ? ` · ${item.scan_response_seen_count} scan rsp` : ''}
              </div>
              <div className="device-meta">
                {item.trusted_identity ? 'trusted identity' : 'untrusted'}
                {item.paired_scan_response ? ` · paired rsp ${item.paired_scan_response_count || 1}` : ''}
                {item.trust_reasons?.length ? ` · ${item.trust_reasons.join(', ')}` : ''}
              </div>
            </button>
          ))}
        </div>
      ) : (
        <div className="empty-box">No BLE advertiser identities yet.</div>
      )}
    </Panel>
  )
}

function BleDecoderPanel({ status, busy, onStart, onStop }) {
  const running = !!status?.running
  const captureCount = Number(status?.capture_count || 0)
  const packetCount = Number(status?.packet_count || 0)
  const lowEvidenceCount = Number(status?.low_evidence_event_count || 0)
  const qualityRatio = packetCount > 0 ? Math.max(0, 1 - (lowEvidenceCount / packetCount)) : 0
  const trustedCount = Number(status?.trusted_identity_count || 0)
  const activityRows = Object.entries(status?.channel_activity || {}).sort((a, b) => Number(a[0]) - Number(b[0]))
  const decoderHealth = getBleDecoderHealth(status)

  return (
    <Panel
      kicker="BLE"
      title="Decoder Status"
      className="dashboard-panel"
      action={running
        ? <button className="mini-action" disabled={busy} onClick={onStop}>Stop Decoder</button>
        : <button className="mini-action" disabled={busy} onClick={onStart}>Start Decoder</button>}
    >
      <div className="detail-grid">
        <Metric label="Backend" value={status?.backend_label || '--'} detail={status?.backend_id || 'no backend'} />
        <Metric label="State" value={running ? 'RUNNING' : 'IDLE'} detail={status?.last_error || 'ready'} />
        <Metric label="Health" value={decoderHealth.label} detail={decoderHealth.detail} />
        <Metric label="Events" value={status?.decoded_event_count || 0} detail={`trusted ${trustedCount}`} />
        <Metric label="Captures" value={captureCount} detail={`empty ${status?.empty_capture_count || 0}`} />
        <Metric label="Packets" value={packetCount} detail={`low evidence ${lowEvidenceCount}`} />
        <Metric label="Quality" value={`${Math.round(qualityRatio * 100)}%`} detail={status?.last_event_at ? `last event ${formatRelativeTime(status.last_event_at)}` : 'no event yet'} />
      </div>
      {decoderHealth.label !== 'Healthy' ? (
        <div className="error-inline staleness-warning">{decoderHealth.label}: {decoderHealth.detail}</div>
      ) : null}
      <div className="intel-stack">
        {activityRows.map(([channel, stats]) => (
          <div key={`ble-activity-${channel}`} className="intel-row">
            <span>ch {channel}</span>
            <strong>{Number(stats?.score || 0).toFixed(2)} {stats?.last_hit_at ? `· ${formatRelativeTime(stats.last_hit_at)}` : ''}</strong>
          </div>
        ))}
        {!activityRows.length ? <div className="empty-box">No BLE channel activity yet.</div> : null}
      </div>
    </Panel>
  )
}

function BleAttackPanel({ indicators, mode }) {
  const attackLeads = indicators?.attack_leads || []
  const metrics = indicators?.attack_metrics || {}
  const verdict = indicators?.attack_verdict || {}
  const decoderStatus = indicators?.decoder_status || {}
  const spamSummary = decoderStatus?.spam_summary || {}
  const verdictTier = getBleVerdictTier(indicators)
  const operatorSummary = buildBleOperatorSummary(indicators, mode)
  return (
    <Panel kicker="BLE" title="Adversary Posture / Churn" className="dashboard-panel">
      <div className="detail-grid">
        <Metric label="Operator State" value={operatorSummary.summaryLabel} detail={operatorSummary.evidenceSource} />
        <Metric label="Evidence Source" value={operatorSummary.tier} detail={operatorSummary.decoderHealth === 'Healthy' ? 'decoder healthy' : operatorSummary.decoderDetail} />
        <Metric label="Top Trigger" value={operatorSummary.triggerDetail} detail={operatorSummary.toolClass !== '--' ? operatorSummary.toolClass : 'tool class unresolved'} />
      </div>
      <div className="detail-grid">
        <Metric label="Verdict Tier" value={verdictTier.label} detail={verdictTier.detail} />
        <Metric
          label="Attack Verdict"
          value={verdict?.label && verdict.label !== 'none' ? verdict.label : 'No attack verdict'}
          detail={verdict?.confidence
            ? `confidence ${Math.round(Number(verdict.confidence) * 100)}%`
            : 'awaiting stronger posture'}
        />
        <Metric
          label="Tool Class"
          value={verdict?.probable_tool_class || spamSummary?.probable_tool_class || '--'}
          detail={verdict?.tool_class_confidence ? `confidence ${Math.round(Number(verdict.tool_class_confidence) * 100)}%` : (spamSummary?.probable_tool_class ? 'decoder-derived lead' : 'no tool-class lead')}
        />
      </div>
      {verdictTier.label !== 'VERIFIED' && attackLeads.length ? (
        <div className="error-inline staleness-warning">
          Operator note: current bluetooth posture is not yet verified as an attack. Treat as suspicious until decoder evidence strengthens.
        </div>
      ) : null}
      <div className="detail-grid">
        <Metric label="Flood Signals" value={metrics.flood_signal_count ?? 0} detail={formatPercent(metrics.flood_signal_ratio)} />
        <Metric label="RF-only BLE" value={metrics.rf_only_signal_count ?? 0} detail={formatPercent(metrics.rf_only_signal_ratio)} />
        <Metric label="Randomized IDs" value={metrics.randomized_identity_count ?? 0} detail={formatPercent(metrics.randomized_identity_ratio)} />
        <Metric label="Active Frequencies" value={metrics.unique_frequency_count ?? 0} detail={`${metrics.frequency_span_mhz ?? 0} MHz span`} />
        <Metric label="Decoder Packets" value={metrics.decoder_packet_count ?? 0} detail={`empty ${metrics.decoder_empty_capture_count ?? 0}`} />
      </div>
      <div className="intel-stack">
        {attackLeads.map((item) => (
          <div key={item.label} className="intel-row">
            <span>{item.label}</span>
            <strong>{item.count}{item.detail ? ` · ${item.detail}` : ''}</strong>
          </div>
        ))}
        {!attackLeads.length ? <div className="empty-box">No BLE attack or anomaly leads surfaced yet.</div> : null}
      </div>
    </Panel>
  )
}

function BleRoleBoard({ signals, devices, onSelectSignal, onSelectDevice }) {
  const roleSignals = signals.filter((signal) => signal.ble_role || signal.device_role_hint)
  const roleDevices = devices.filter((device) => device.ble_role || device.device_role_hint)

  return (
    <Panel kicker="BLE" title="Role / Mode Board" className="dashboard-panel">
      {roleSignals.length || roleDevices.length ? (
        <div className="relationship-board">
          <div className="relationship-column">
            <div className="table-note">Signal Roles</div>
            {roleSignals.slice(0, 6).map((signal) => (
              <button
                key={`ble-signal-${signal.signal_id}`}
                className="relationship-card relationship-button"
                onClick={() => onSelectSignal(signal)}
              >
                <strong>{signal.ble_role || signal.device_role_hint || 'Unknown BLE role'}</strong>
                <div className="device-meta">
                  {freq(signal.frequency_mhz || signal.freq_mhz)} · {(Number(signal.ble_role_confidence || signal.device_role_confidence || 0)).toFixed(2)}
                </div>
                <div className="device-meta">
                  {signal.ble_operating_mode_hint || signal.behavior_profile_hint || 'No mode hint'}
                </div>
              </button>
            ))}
          </div>
          <div className="relationship-column">
            <div className="table-note">Device Roles</div>
            {roleDevices.slice(0, 6).map((device) => (
              <button
                key={`ble-device-${device.device_id}`}
                className="relationship-card relationship-button"
                onClick={() => onSelectDevice(device)}
              >
                <strong>{device.ble_role || device.device_role_hint || device.device_id}</strong>
                <div className="device-meta">{device.device_id}</div>
                <div className="device-meta">
                  {(device.protocols || []).join(' / ') || 'No protocols'}
                </div>
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="empty-box">No BLE role or operating-mode hints yet.</div>
      )}
    </Panel>
  )
}

function ChannelPosturePanel({ title, rows, emptyMessage }) {
  return (
    <Panel kicker="Channel" title={title} className="dashboard-panel">
      {renderRows(
        rows || [],
        emptyMessage,
        (item) => item.label,
        (item) => item.count,
      )}
    </Panel>
  )
}

function BleTimelinePanel({ identity }) {
  return (
    <Panel kicker="BLE" title="Evidence Timeline" className="dashboard-panel">
      {identity?.timeline?.length ? (
        <div className="timeline-list">
          {identity.timeline
            .slice()
            .reverse()
            .map((event, index) => (
              <div key={`${identity.mac_address}-${index}`} className="timeline-item">
                <div className="timeline-dot" />
                <div>
                  <strong>{formatRelativeTime(event.timestamp)}</strong>
                  <div className="device-meta">
                    ch {event.channel || '--'} · {event.frequency ? `${event.frequency} MHz` : '--'} · {event.rssi ?? '--'} dBm
                  </div>
                  {event.device_name ? <div className="device-meta">{event.device_name}</div> : null}
                </div>
              </div>
            ))}
        </div>
      ) : (
        <div className="empty-box">Select a BLE identity to inspect its recent evidence timeline.</div>
      )}
    </Panel>
  )
}

function CompactMatrixPanel({ kicker, title, columns, rows, emptyMessage, className = '' }) {
  return (
    <Panel kicker={kicker} title={title} className={className}>
      {rows?.length ? (
        <div className="matrix-table-wrap">
          <table className="matrix-table">
            <thead>
              <tr>
                {columns.map((column) => (
                  <th key={`${title}-${column.key}`}>{column.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${title}-row-${index}`}>
                  {columns.map((column) => (
                    <td key={`${title}-${index}-${column.key}`}>{row[column.key] ?? '--'}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-box">{emptyMessage}</div>
      )}
    </Panel>
  )
}

function BleDeviceInventoryTable({ devices, onSelectDevice }) {
  const renderEvidenceSummary = (device) => {
    const seenCount = Number(device?.seen_count || 0)
    const evidenceScore = typeof device?.best_evidence_score === 'number'
      ? ` · ${Math.round(device.best_evidence_score * 100)}%`
      : ''
    if (seenCount > 0) {
      return `seen ${seenCount}${evidenceScore}`
    }
    if (device?.spam_like) {
      return `spam-like${evidenceScore}`
    }
    if (device?.trusted_identity) {
      return `trusted${evidenceScore}`
    }
    return `provisional${evidenceScore}`
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Identity</th>
            <th>Vendor / Product</th>
            <th>Privacy</th>
            <th>Evidence</th>
            <th>Observed</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((device, index) => (
            <tr key={`${device.device_id || device.mac_address || 'ble-device'}-${index}`}>
              <td>
                <div className="table-primary">{device.mac_address || '--'}</div>
                <div className="table-secondary">{device.mac_address ? (device.device_id || 'BLE device') : 'BLE device'}</div>
              </td>
              <td>
                <div className="table-primary">{device.vendor || device.probable_vendor_family || '--'}</div>
                <div className="table-secondary">{device.product || device.device_type || device.probable_product_family || '--'}</div>
              </td>
              <td>
                <div className="table-primary">{device.privacy_state || '--'}</div>
                <div className="table-secondary">{device.trusted_identity ? 'trusted identity' : 'provisional identity'}</div>
              </td>
              <td>
                <div className="table-primary">{renderEvidenceSummary(device)}</div>
                <div className="table-secondary">
                  {device.paired_scan_response ? `paired rsp ${device.paired_scan_response_count || 1}` : (device.trust_reasons?.join(', ') || device.evidence_tier || '--')}
                </div>
              </td>
              <td>
                <div className="table-primary">{formatObservedTime(device)}</div>
                <div className="table-secondary">{device.channels?.length ? `ch ${device.channels.join('/')}` : '--'}</div>
              </td>
              <td>
                <div className="row-actions">
                  <button className="mini-action" onClick={() => onSelectDevice(device)}>Inspect</button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!devices.length ? <div className="empty-box">No BLE devices available.</div> : null}
    </div>
  )
}

function BleIdentityTablePanel({ identities, selectedIdentity, onSelectIdentity, onExportIdentity }) {
  const columns = [
    { key: 'identity', label: 'Identity' },
    { key: 'vendor', label: 'Vendor / Product' },
    { key: 'evidence', label: 'Evidence' },
    { key: 'actions', label: 'Action' },
  ]
  const rows = (identities || []).slice(0, 10).map((item) => ({
    identity: (
      <div>
        <div className="table-primary">{item.device_name || item.probable_product_family || item.device_hint || 'Unknown advertiser'}</div>
        <div className="table-secondary">{item.mac_address || '--'}{item.channels?.length ? ` · ch ${item.channels.join('/')}` : ''}</div>
      </div>
    ),
    vendor: (
      <div>
        <div className="table-primary">{item.probable_vendor_family || item.vendor || 'Unknown vendor'}</div>
        <div className="table-secondary">{item.privacy_state || 'privacy unknown'}{item.apple_findmy_like ? ' · Apple Find My-like' : item.tracker_like ? ' · tracker-like' : item.beacon_like ? ' · beacon-like' : ''}</div>
      </div>
    ),
    evidence: (
      <div>
        <div className="table-primary">{item.evidence_quality || 'unknown'}</div>
        <div className="table-secondary">seen {item.seen_count || 0}{typeof item.best_evidence_score === 'number' ? ` · ${Math.round(item.best_evidence_score * 100)}%` : ''}</div>
      </div>
    ),
    actions: (
      <div className="matrix-action-row">
        <button className={selectedIdentity?.mac_address === item.mac_address ? 'mini-action active' : 'mini-action'} onClick={() => onSelectIdentity(item)}>Inspect</button>
        <button className="mini-action" onClick={() => onExportIdentity(item)}>Export</button>
      </div>
    ),
  }))

  return (
    <CompactMatrixPanel
      kicker="BLE"
      title="Advertiser Identities"
      columns={columns}
      rows={rows}
      emptyMessage="No BLE advertiser identities yet."
      className="dashboard-panel dashboard-panel-full"
    />
  )
}

function BleInsightMatrixPanel({ mode, selectedIdentity, signals, devices }) {
  const roleSignal = (signals || []).find((signal) => signal.ble_role || signal.device_role_hint)
  const roleDevice = (devices || []).find((device) => device.ble_role || device.device_role_hint)
  const timeline = selectedIdentity?.timeline?.slice().reverse().slice(0, 4) || []
  const columns = [
    { key: 'feature', label: 'Feature' },
    { key: 'status', label: 'Status' },
    { key: 'detail', label: 'Detail' },
  ]
  const rows = [
    {
      feature: 'Detection / Fingerprint Posture',
      status: selectedIdentity ? (selectedIdentity.probable_vendor_family || selectedIdentity.vendor || 'Unknown') : '--',
      detail: selectedIdentity
        ? `${selectedIdentity.probable_product_family || selectedIdentity.device_hint || 'Unknown product'} · ${(selectedIdentity.channels || []).join('/') || 'no channel history'} · ${selectedIdentity.privacy_state || 'privacy unknown'}`
        : 'Select a BLE identity to inspect vendor and fingerprint posture.',
    },
    {
      feature: 'Role / Mode Board',
      status: roleSignal?.ble_role || roleSignal?.device_role_hint || roleDevice?.ble_role || roleDevice?.device_role_hint || '--',
      detail: roleSignal
        ? `${roleSignal.ble_operating_mode_hint || roleSignal.behavior_profile_hint || 'No mode hint'} · ${(Number(roleSignal.ble_role_confidence || roleSignal.device_role_confidence || 0)).toFixed(2)}`
        : (roleDevice ? `${(roleDevice.protocols || []).join(' / ') || 'No protocols'}` : 'No BLE role or operating-mode hints yet.'),
    },
    {
      feature: 'Evidence Timeline',
      status: timeline.length ? `${timeline.length} recent events` : '--',
      detail: timeline.length
        ? timeline.map((event) => `ch ${event.channel || '--'} · ${formatRelativeTime(event.timestamp)}`).join(' · ')
        : 'Select a BLE identity to inspect its recent evidence timeline.',
    },
  ]

  return (
    <CompactMatrixPanel
      kicker="BLE"
      title="BLE Recon Matrix"
      columns={columns}
      rows={rows}
      emptyMessage="No BLE insight matrix available yet."
      className="dashboard-panel dashboard-panel-full"
    />
  )
}

function BleOperationsMatrixPanel({ mode, protocolPosture, vendorPosture, brandLeads, correlatedEntities, prioritySignals, evidenceRows }) {
  const columns = [
    { key: 'domain', label: 'Domain' },
    { key: 'summary', label: 'Summary' },
    { key: 'detail', label: 'Detail' },
  ]
  const rows = [
    {
      domain: 'Protocol',
      summary: protocolPosture.length ? protocolPosture.slice(0, 3).map((item) => item.label).join(', ') : '--',
      detail: protocolPosture.length ? `${protocolPosture.slice(0, 3).map((item) => item.count).join(' · ')} detections` : 'No classified families yet.',
    },
    {
      domain: 'Vendor',
      summary: vendorPosture.length ? vendorPosture.slice(0, 3).map((item) => item.label).join(', ') : '--',
      detail: vendorPosture.length ? `${vendorPosture.slice(0, 3).map((item) => item.count).join(' · ')} resolved vendors` : 'No vendor hints yet.',
    },
    {
      domain: 'Identity',
      summary: brandLeads.length ? brandLeads.slice(0, 2).map((item) => item.label).join(' | ') : '--',
      detail: brandLeads.length ? 'Top brand / product leads' : 'No brand or product detections surfaced yet.',
    },
    {
      domain: 'Fusion',
      summary: correlatedEntities?.length ? `${correlatedEntities.length} matched entities` : '--',
      detail: correlatedEntities?.length ? correlatedEntities.slice(0, 2).map((item) => item.primary_vendor || item.entity_id).join(' · ') : 'No fused devices available.',
    },
    {
      domain: 'Hot Targets',
      summary: prioritySignals.length ? prioritySignals.slice(0, 3).map((signal) => metricDetailSignal(signal)).join(' | ') : '--',
      detail: prioritySignals.length ? 'Highest-priority retained detections' : 'No live targets in this band yet.',
    },
    {
      domain: 'Integrity',
      summary: evidenceRows.length ? evidenceRows.slice(0, 3).map((item) => `${item.label}:${item.count}`).join(' · ') : '--',
      detail: evidenceRows.length ? 'Evidence tiers observed' : 'No evidence tiers available in this band yet.',
    },
  ]

  return (
    <CompactMatrixPanel
      kicker="BLE"
      title="Recon Operations Matrix"
      columns={columns}
      rows={rows}
      emptyMessage="No BLE operational data surfaced yet."
      className="dashboard-panel dashboard-panel-full"
    />
  )
}

function ZigbeeMeshBoard({ meshNodes, devices, onSelectDevice }) {
  return (
    <Panel kicker="Zigbee" title="Node / Mesh Relationship Board" className="dashboard-panel">
      {meshNodes?.length || devices?.length ? (
        <div className="relationship-board">
          <div className="relationship-column">
            <div className="table-note">Mesh Nodes</div>
            {(meshNodes || []).slice(0, 8).map((node) => (
              <div key={node.label} className="relationship-card">
                <strong>{node.label}</strong>
                <div className="device-meta">{node.count} observations</div>
              </div>
            ))}
          </div>
          <div className="relationship-column">
            <div className="table-note">Matched Entities</div>
            {(devices || []).slice(0, 8).map((device) => (
              <button key={device.device_id} className="relationship-card relationship-button" onClick={() => onSelectDevice(device)}>
                <strong>{device.vendor || device.device_type || device.device_id}</strong>
                <div className="device-meta">{device.device_id}</div>
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="empty-box">No mesh/node relationships visible yet.</div>
      )}
    </Panel>
  )
}

function ZigbeePosturePanel({ signals }) {
  const posture = { coordinator: 0, trust_center: 0, leaf_node: 0, unknown: 0 }

  signals.forEach((signal) => {
    const haystack = JSON.stringify(signal).toLowerCase()
    if (haystack.includes('trust center')) {
      posture.trust_center += 1
    } else if (haystack.includes('coordinator')) {
      posture.coordinator += 1
    } else if (haystack.includes('leaf') || haystack.includes('end device') || haystack.includes('node')) {
      posture.leaf_node += 1
    } else {
      posture.unknown += 1
    }
  })

  return (
    <Panel kicker="Zigbee" title="Coordinator / Leaf Posture" className="dashboard-panel">
      {renderRows(
        Object.entries(posture).map(([label, count]) => ({ label, count })),
        'No Zigbee posture hints yet.',
        (item) => item.label.replace('_', ' '),
        (item) => item.count,
      )}
    </Panel>
  )
}

function WifiHeatmapPanel({ rows }) {
  const peak = Math.max(1, ...(rows || []).map((item) => Number(item.count) || 0))
  return (
    <Panel kicker="WiFi" title="Channel Pressure Heatmap" className="dashboard-panel">
      {rows?.length ? (
        <div className="heatmap-grid">
          {rows.map((item) => {
            const ratio = Math.max(0.12, (Number(item.count) || 0) / peak)
            return (
              <div key={item.label} className="heatmap-cell">
                <div className="heatmap-head">
                  <strong>{item.label}</strong>
                  <span>{item.count}</span>
                </div>
                <div className="heatmap-bar">
                  <div className="heatmap-fill" style={{ width: `${Math.round(ratio * 100)}%` }} />
                </div>
              </div>
            )
          })}
        </div>
      ) : (
        <div className="empty-box">No WiFi channel pressure data yet.</div>
      )}
    </Panel>
  )
}

function WifiTimelinePanel({ history }) {
  const latest = history.slice(-8)
  return (
    <Panel kicker="WiFi" title="Channel Dwell / Pressure Timeline" className="dashboard-panel">
      {latest.length ? (
        <div className="timeline-list">
          {latest.map((entry, index) => (
            <div key={`wifi-${index}-${entry.timestamp}`} className="timeline-item">
              <div className="timeline-dot" />
              <div>
                <strong>{new Date(entry.timestamp).toLocaleTimeString()}</strong>
                <div className="device-meta">
                  {(entry.rows || []).map((item) => `${item.label}:${item.count}`).join(' · ') || 'No channel pressure'}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-box">No WiFi dwell history collected yet.</div>
      )}
    </Panel>
  )
}

function LoraRolePanel({ rolePosture }) {
  const items = Object.entries(rolePosture || {}).map(([label, count]) => ({ label, count }))
  return (
    <Panel kicker="LoRa" title="Gateway / End-Device Posture" className="dashboard-panel">
      {renderRows(
        items,
        'No LoRa role hints yet.',
        (item) => item.label.replace('_', ' '),
        (item) => item.count,
      )}
    </Panel>
  )
}

function LoraRoleQueues({ signals, onSelectSignal }) {
  const gatewaySignals = signals.filter((signal) => signal.lora_role_hint === 'gateway')
  const endDeviceSignals = signals.filter((signal) => signal.lora_role_hint === 'end_device')

  return (
    <Panel kicker="LoRa" title="Entity Queues" className="dashboard-panel">
      <div className="queue-grid">
        <div className="queue-column">
          <div className="table-note">Gateway Queue</div>
          {gatewaySignals.length ? gatewaySignals.slice(0, 8).map((signal, index) => (
            <button key={`gw-${index}-${signal.signal_id}`} className="queue-item" onClick={() => onSelectSignal(signal)}>
              <strong>{freq(signal.frequency_mhz || signal.freq_mhz)}</strong>
              <div className="device-meta">{signal.vendor || signal.device_type || 'Unknown gateway'}</div>
            </button>
          )) : <div className="empty-box">No gateway-role LoRa signals.</div>}
        </div>
        <div className="queue-column">
          <div className="table-note">End Device Queue</div>
          {endDeviceSignals.length ? endDeviceSignals.slice(0, 8).map((signal, index) => (
            <button key={`end-${index}-${signal.signal_id}`} className="queue-item" onClick={() => onSelectSignal(signal)}>
              <strong>{freq(signal.frequency_mhz || signal.freq_mhz)}</strong>
              <div className="device-meta">{signal.vendor || signal.device_type || 'Unknown end device'}</div>
            </button>
          )) : <div className="empty-box">No end-device LoRa signals.</div>}
        </div>
      </div>
    </Panel>
  )
}

function LoraTimelinePanel({ signals }) {
  const timeline = [...signals]
    .filter((signal) => signal.lora_role_hint)
    .sort((a, b) => (Number(b.last_seen) || 0) - (Number(a.last_seen) || 0))
    .slice(0, 8)

  return (
    <Panel kicker="LoRa" title="Recent Activity Timeline" className="dashboard-panel">
      {timeline.length ? (
        <div className="timeline-list">
          {timeline.map((signal, index) => (
            <div key={`${signal.signal_id}-${index}`} className="timeline-item">
              <div className="timeline-dot" />
              <div>
                <strong>{signal.lora_role_hint} · {(Number(signal.lora_role_confidence || 0)).toFixed(2)}</strong>
                <div className="device-meta">
                  {freq(signal.frequency_mhz || signal.freq_mhz)} · {formatRelativeTime(signal.last_seen)}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-box">No recent LoRa role activity yet.</div>
      )}
    </Panel>
  )
}

function IotCorrelationPanel({ entities, correlations }) {
  const source = entities?.length ? entities : correlations

  return (
    <Panel kicker="Correlation" title="Cross-Protocol Entities" className="dashboard-panel">
      {source?.length ? (
        <div className="intel-stack">
          {source.slice(0, 10).map((entity) => (
            <div key={entity.entity_id} className="advisory-card">
              <div className="device-title">{entity.primary_vendor || entity.entity_id}</div>
              <div className="device-meta">
                {(entity.protocols || []).join(' / ') || 'No protocols'}
              </div>
              <div className="device-meta">
                {(entity.device_ids || []).length} devices · {(entity.signal_ids || []).length} signals
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-box">No cross-protocol entities have been linked yet.</div>
      )}
    </Panel>
  )
}

function IotLinkedBoard({ entities, onSelectDevice }) {
  return (
    <Panel kicker="IoT" title="Linked Entity Board" className="dashboard-panel">
      {entities?.length ? (
        <div className="linked-board">
          {entities.slice(0, 8).map((entity) => (
            <div key={entity.entity_id} className="linked-card">
              <div className="device-title">{entity.primary_vendor || entity.entity_id}</div>
              <div className="pill-row">
                {(entity.protocols || []).map((protocol) => <Pill key={`${entity.entity_id}-${protocol}`} text={protocol} tone="cyan" />)}
              </div>
              <div className="device-meta">{(entity.device_ids || []).length} devices · {(entity.signal_ids || []).length} signals</div>
              <div className="device-meta">{(entity.frequencies || []).slice(0, 4).join(', ') || 'No frequencies'}</div>
              {entity.device_ids?.length ? (
                <div className="linked-actions">
                  {entity.device_ids.slice(0, 3).map((deviceId) => (
                    <button
                      key={deviceId}
                      className="mini-action"
                      onClick={() => onSelectDevice({ device_id: deviceId, correlation_entity_id: entity.entity_id, correlation_protocols: entity.protocols })}
                    >
                      {deviceId}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-box">No linked multi-band entities available yet.</div>
      )}
    </Panel>
  )
}

function IotEdgeBoard({ entities, onSelectEdge }) {
  const edges = []
  entities.slice(0, 10).forEach((entity) => {
    ;(entity.protocols || []).forEach((protocol) => {
      edges.push({
        id: `${entity.entity_id}-${protocol}`,
        entityId: entity.entity_id,
        protocol,
        vendor: entity.primary_vendor,
      })
    })
  })

  return (
    <Panel kicker="IoT" title="Correlation Edge Board" className="dashboard-panel">
      {edges.length ? (
        <div className="linked-board">
          {edges.map((edge) => (
            <button key={edge.id} className="relationship-card relationship-button" onClick={() => onSelectEdge(edge)}>
              <strong>{edge.vendor || edge.entityId}</strong>
              <div className="device-meta">{edge.entityId}</div>
              <div className="device-meta">edge → {edge.protocol}</div>
            </button>
          ))}
        </div>
      ) : (
        <div className="empty-box">No clickable correlation edges yet.</div>
      )}
    </Panel>
  )
}

function renderBandSpecificPanels(tab, indicators, correlatedEntities, context) {
  if (tab === 'BLE') {
    return {
      primary: [
        <BleDecoderPanel
          key="ble-decoder"
          status={context.bleDecoderStatus}
          busy={context.bleDecoderBusy}
          onStart={context.onStartBleDecoder}
          onStop={context.onStopBleDecoder}
        />,
        <BleAttackPanel key="ble-attack" indicators={indicators} mode={context.mode} />,
      ],
      secondary: [
        <BleIdentityTablePanel
          key="ble-identities"
          identities={indicators.advertiser_identities}
          selectedIdentity={context.selectedIdentity}
          onSelectIdentity={context.onSelectIdentity}
          onExportIdentity={context.onExportIdentity}
        />,
        <BleInsightMatrixPanel
          key="ble-insight"
          mode={context.mode}
          selectedIdentity={context.selectedIdentity}
          signals={context.signals}
          devices={context.matchedDevices}
        />,
      ],
    }
  }

  if (tab === 'ZIGBEE') {
    return {
      primary: [
        <ZigbeePosturePanel key="zigbee-posture" signals={context.signals} />,
        <ChannelPosturePanel
          key="zigbee-channels"
          title="Mesh Channel Posture"
          rows={indicators.channel_posture}
          emptyMessage="No Zigbee channel posture yet."
        />,
      ],
      secondary: [
        <ZigbeeMeshBoard key="zigbee-mesh" meshNodes={indicators.mesh_nodes} devices={context.matchedDevices} onSelectDevice={context.onSelectDevice} />,
      ],
    }
  }

  if (tab === 'WIFI') {
    return {
      primary: [
        <ChannelPosturePanel
          key="wifi-posture"
          title="WiFi Channel Posture"
          rows={indicators.channel_posture}
          emptyMessage="No WiFi channel posture yet."
        />,
        <WifiHeatmapPanel key="wifi-heatmap" rows={indicators.channel_posture} />,
      ],
      secondary: [
        <WifiTimelinePanel key="wifi-timeline" history={context.wifiHistory} />,
      ],
    }
  }

  if (tab === 'LORA') {
    return {
      primary: [
        <LoraRolePanel key="lora-role" rolePosture={indicators.role_posture} />,
      ],
      secondary: [
        <LoraRoleQueues key="lora-queues" signals={context.signals} onSelectSignal={context.onSelectSignal} />,
        <LoraTimelinePanel key="lora-timeline" signals={context.signals} />,
      ],
    }
  }

  if (tab === 'IOT') {
    return {
      primary: [
        <IotCorrelationPanel key="iot-correlation" entities={indicators.cross_protocol_entities} correlations={correlatedEntities} />,
      ],
      secondary: [
        <IotLinkedBoard key="iot-linked" entities={correlatedEntities} onSelectDevice={context.onSelectDevice} />,
        <IotEdgeBoard key="iot-edge" entities={correlatedEntities} onSelectEdge={context.onSelectEdge} />,
      ],
    }
  }

  return {
    primary: [
      (
        <Panel key="band-derived" kicker="Band Intel" title="Derived Indicators" className="dashboard-panel">
          <div className="intel-stack">
            {Object.entries(indicators || {})
              .filter(([, value]) => value !== null && value !== undefined)
              .slice(0, 8)
              .map(([key, value]) => (
                <div key={key} className="intel-row">
                  <span>{key}</span>
                  <strong>{Array.isArray(value) ? value.length : typeof value === 'object' ? Object.keys(value).length : String(value)}</strong>
                </div>
              ))}
          </div>
        </Panel>
      ),
    ],
    secondary: [],
  }
}

export default function CategoryConsole({
  mode = 'RED',
  layoutMode = 'laptop',
  tab,
  title,
  subtitle,
  signals,
  devices,
  fft,
  fftTimestamp,
  system,
  rfHealth,
  selectedSignal,
  selectedDevice,
  onSelectSignal,
  onSelectDevice,
  onTune,
  busy,
  config,
  focusMetricLabel,
  lastStreamUpdate,
  sweepState,
  sweepResetNonce,
  onRunSweep,
  onStopSweep,
  onClearSweepResults,
}) {
  const { isPanelVisible } = usePanelPreferences(tab)
  const tabToneClass = `category-tone-${String(tab || '').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
  const [bandIntel, setBandIntel] = useState(null)
  const [bandIntelError, setBandIntelError] = useState('')
  const [correlations, setCorrelations] = useState([])
  const [selectedIdentity, setSelectedIdentity] = useState(null)
  const [selectedEdge, setSelectedEdge] = useState(null)
  const [wifiHistory, setWifiHistory] = useState([])
  const [bandLastUpdate, setBandLastUpdate] = useState(null)
  const [liveSelectedSignal, setLiveSelectedSignal] = useState(selectedSignal)
  const [liveSelectedDevice, setLiveSelectedDevice] = useState(selectedDevice)
  const [sweepSignalArchive, setSweepSignalArchive] = useState([])
  const [sweepDeviceArchive, setSweepDeviceArchive] = useState([])
  const [lastSweepMeta, setLastSweepMeta] = useState(null)
  const [sweepProfileCounts, setSweepProfileCounts] = useState({})
  const [bleDecoderStatus, setBleDecoderStatus] = useState(null)
  const [bleDecoderBusy, setBleDecoderBusy] = useState(false)
  const [bleSweepDurationMinutes, setBleSweepDurationMinutes] = useState('1')
  const [bleInventoryView, setBleInventoryView] = useState('devices')
  const bleAutoStartAttemptRef = useRef(0)

  useEffect(() => {
    let cancelled = false

    async function loadBleStatus() {
      if (tab !== 'BLE') {
        if (!cancelled) {
          setBleDecoderStatus(null)
        }
        return
      }
      try {
        const payload = await fetchBleDecoderStatus()
        if (!cancelled) {
          setBleDecoderStatus(payload)
        }
      } catch {
        if (!cancelled) {
          setBleDecoderStatus(null)
        }
      }
    }

    loadBleStatus()
    const timer = setInterval(loadBleStatus, 4000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [tab])

  useEffect(() => {
    let cancelled = false

    async function loadBandIntel() {
      const bleDecoderRunning = tab === 'BLE' && !!bleDecoderStatus?.running
      if (!rfHealth?.sdr_streaming_confirmed && !bleDecoderRunning) {
        if (!cancelled) {
          setBandIntel(null)
          setBandIntelError('')
          setBandLastUpdate(null)
        }
        return
      }
      try {
        const payload = await fetchBandIntel(tab)
        if (!cancelled) {
          setBandIntel(payload)
          setBandIntelError('')
          setBandLastUpdate(Date.now())
          const sweepPayload = payload?.sweep || {}
          setSweepSignalArchive(sweepPayload?.archive_signals || [])
          setSweepDeviceArchive(sweepPayload?.archive_devices || [])
          setSweepProfileCounts(sweepPayload?.profile_counts || {})
          setLastSweepMeta(sweepPayload?.last_sweep_meta || null)
          if (tab === 'WIFI') {
            setWifiHistory((current) => [
              ...current.slice(-11),
              {
                timestamp: Date.now(),
                rows: payload?.indicators?.channel_posture || [],
              },
            ])
          }
        }
      } catch (err) {
        if (!cancelled) {
          setBandIntel(null)
          setBandIntelError(String(err.message || err))
        }
      }
    }

    loadBandIntel()
    const timer = setInterval(loadBandIntel, 4000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [bleDecoderStatus?.running, rfHealth?.sdr_streaming_confirmed, tab, sweepState?.tab])

  useEffect(() => {
    setSweepSignalArchive([])
    setSweepDeviceArchive([])
    setLastSweepMeta(null)
    setSweepProfileCounts({})
    clearStoredSweepData()
  }, [sweepResetNonce])

  useEffect(() => {
    if (sweepState?.tab !== tab || sweepState?.running || !sweepState?.completed) {
      return
    }
    const meta = {
      completedAt: Date.now(),
      signalCount: sweepSignalArchive.length,
      deviceCount: sweepDeviceArchive.length,
      profilesScanned: sweepState.total || config.channels?.length || 0,
      finalLabel: sweepState.currentLabel || null,
      finalFrequencyMHz: sweepState.currentFrequencyMHz || null,
      tab,
    }
    setLastSweepMeta(meta)
  }, [config.channels?.length, sweepDeviceArchive, sweepProfileCounts, sweepSignalArchive, sweepState, tab])

  useEffect(() => {
    setLiveSelectedSignal(selectedSignal)
  }, [selectedSignal])

  useEffect(() => {
    setLiveSelectedDevice(selectedDevice)
  }, [selectedDevice])

  useEffect(() => {
    let cancelled = false

    async function refreshSelectedSignal() {
      if (!selectedSignal?.signal_id) {
        setLiveSelectedSignal(selectedSignal)
        return
      }
      try {
        const payload = await fetchSignalDetail(selectedSignal.signal_id)
        if (!cancelled && payload?.signal) {
          setLiveSelectedSignal(payload.signal)
        }
      } catch {
        if (!cancelled) {
          setLiveSelectedSignal(selectedSignal)
        }
      }
    }

    refreshSelectedSignal()
    const timer = setInterval(refreshSelectedSignal, 1500)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [selectedSignal])

  useEffect(() => {
    let cancelled = false

    async function refreshSelectedDevice() {
      if (!selectedDevice?.device_id) {
        setLiveSelectedDevice(selectedDevice)
        return
      }
      try {
        const payload = await fetchIntelDeviceDetail(selectedDevice.device_id)
        if (!cancelled && payload?.device) {
          setLiveSelectedDevice(payload.device)
        }
      } catch {
        if (!cancelled) {
          setLiveSelectedDevice(selectedDevice)
        }
      }
    }

    refreshSelectedDevice()
    const timer = setInterval(refreshSelectedDevice, 1800)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [selectedDevice])

  useEffect(() => {
    let cancelled = false

    async function loadCorrelations() {
      if (tab !== 'IOT' || !rfHealth?.sdr_streaming_confirmed) {
        setCorrelations([])
        return
      }

      try {
        const payload = await fetchCorrelations()
        if (!cancelled) {
          setCorrelations(payload.entities || [])
        }
      } catch {
        if (!cancelled) {
          setCorrelations([])
        }
      }
    }

    loadCorrelations()
    const timer = setInterval(loadCorrelations, 5000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [rfHealth?.sdr_streaming_confirmed, tab])

  const channels = config.channels || []
  const currentFreq = Number(system?.active_freq_mhz || rfHealth?.sdr_freq_mhz || config.defaultFrequencyMHz)
  const currentLabel = channels.find((channel) => Math.abs(Number(channel.frequencyMHz) - currentFreq) < 0.01)?.label
  const indicators = bandIntel?.indicators || {}
  const correlatedEntities = useMemo(() => bandIntel?.correlated_entities || [], [bandIntel])
  const bandCapability = bandIntel?.capability || { state: 'ready', production_ready: true, can_sweep: true, reason: '', detail: '' }
  const activeSweep = bandIntel?.sweep?.state || (sweepState?.tab === tab ? sweepState : null)
  const showSweepIntel = Boolean(activeSweep?.running)
  const visibleIndicators = showSweepIntel ? indicators : {}
  const resolvedIdentity = useMemo(() => {
    if (!selectedIdentity?.mac_address) return null
    return (visibleIndicators.advertiser_identities || []).find((item) => item.mac_address === selectedIdentity.mac_address) || selectedIdentity
  }, [selectedIdentity, visibleIndicators.advertiser_identities])
  const sideIntelPayload = useMemo(() => {
    if (tab === 'IOT') {
      return {
        indicators: visibleIndicators,
        correlated_entities: correlatedEntities,
        correlations,
        selected_edge: selectedEdge,
      }
    }
    return visibleIndicators
  }, [correlatedEntities, correlations, selectedEdge, tab, visibleIndicators])

  function handleExportIdentity(identity) {
    if (!identity?.mac_address) return
    downloadJson(`ble-evidence-${identity.mac_address.replaceAll(':', '-')}.json`, {
      exported_at: new Date().toISOString(),
      band: 'BLE',
      identity,
    })
  }

  function handleExportBleEvidenceBundle() {
    if (tab !== 'BLE') return
    downloadJson(`ble-evidence-bundle-${new Date().toISOString().replaceAll(':', '-').slice(0, 19)}.json`, {
      exported_at: new Date().toISOString(),
      mode,
      tab,
      decoder_status: visibleIndicators.decoder_status || bleDecoderStatus,
      attack_verdict: visibleIndicators.attack_verdict || null,
      attack_leads: visibleIndicators.attack_leads || [],
      attack_classes: visibleIndicators.attack_classes || [],
      attack_metrics: visibleIndicators.attack_metrics || {},
      advertiser_identities: visibleIndicators.advertiser_identities || [],
      devices: displayDevices,
      signals: tableSignals,
    })
  }

  function handleDeleteSignalRow(signal) {
    if (!signal || signal.attack_alert_row) return
    const nextSignals = sweepSignalArchive.filter((item) => {
      if (!item) return false
      if (signal.signal_id && item.signal_id) return item.signal_id !== signal.signal_id
      if (signal.mac_address && item.mac_address) return item.mac_address !== signal.mac_address
      return item !== signal
    })
    const nextMeta = lastSweepMeta
      ? {
        ...lastSweepMeta,
        signalCount: nextSignals.length,
        deviceCount: sweepDeviceArchive.length,
      }
      : null
    setSweepSignalArchive(nextSignals)
    setLastSweepMeta(nextMeta)
    if (selectedSignalLive?.signal_id === signal.signal_id) {
      setLiveSelectedSignal(null)
    }
    if (selectedSignal?.signal_id === signal.signal_id) {
      onSelectSignal?.(null)
    }
  }

  const selectedSignalLive = liveSelectedSignal
  const selectedDeviceLive = liveSelectedDevice
  const streamingConfirmed = !!rfHealth?.sdr_streaming_confirmed
  const bleDecoderRunning = tab === 'BLE' && !!bleDecoderStatus?.running
  const bleCaptureExpected = tab === 'BLE'
    && !!rfHealth?.hackrf?.available
    && !!system?.session_active
    && !streamingConfirmed
  const runtimeWarning = !rfHealth?.hackrf?.available
    ? 'SDR not connected. Please connect SDR.'
    : ((bleDecoderRunning || bleCaptureExpected)
      ? 'BLE capture is active. Streaming pause is expected on the Bluetooth tab while the decoder uses the HackRF.'
      : (!streamingConfirmed ? (rfHealth?.sdr_fault_reason || 'SDR connected but not streaming. Start an SDR session.') : ''))
  const operationalTab = ['SUB-GHZ', 'BLE', 'LORA', 'ZIGBEE', 'IOT', 'WIFI'].includes(tab)
  const sweepProgress = activeSweep?.durationMs
    ? Math.min(100, Math.max(0, (((Date.now() - Number(activeSweep.startedAt || Date.now())) / Number(activeSweep.durationMs)) * 100)))
    : (activeSweep?.total ? Math.min(100, Math.max(0, (activeSweep.currentIndex / activeSweep.total) * 100)) : 0)
  const liveBleSignals = tab === 'BLE' ? buildBleInventorySignals(bandIntel?.signals || [], bandIntel?.devices || []) : []
  const liveBleDevices = tab === 'BLE'
    ? (bandIntel?.devices || []).filter((device) => device?.mac_address)
    : []
  const retainedSweepSignals = sweepSignalArchive.length ? sweepSignalArchive : []
  const retainedSweepDevices = sweepDeviceArchive.length ? sweepDeviceArchive : []
  const displaySignals = (activeSweep?.running || retainedSweepSignals.length)
    ? sweepSignalArchive
    : (tab === 'BLE' ? liveBleSignals : [])
  const displayDevices = (activeSweep?.running || retainedSweepDevices.length)
    ? sweepDeviceArchive
    : (tab === 'BLE' ? liveBleDevices : [])
  const runSweepRecommended = operationalTab
    && !!system?.session_active
    && streamingConfirmed
    && !activeSweep?.running
    && !busy
    && bandCapability.can_sweep !== false
  const inventoryStateLabel = activeSweep?.running
    ? 'LIVE SWEEP'
    : (retainedSweepSignals.length ? 'RETAINED RESULTS' : (tab === 'BLE' && liveBleSignals.length ? 'LIVE DECODER' : 'NO SWEEP'))
  const inventoryStateTone = activeSweep?.running
    ? 'cyan'
    : (retainedSweepSignals.length ? 'green' : (tab === 'BLE' && liveBleSignals.length ? 'red' : 'neutral'))
  const tableSignals = useMemo(() => {
    const rows = [...displaySignals]
    const attackRow = buildBleAttackAlertRow(
      tab,
      mode,
      visibleIndicators,
      currentFreq,
      Boolean(activeSweep?.running || (tab === 'BLE' && liveBleSignals.length > 0)),
    )
    if (attackRow) {
      rows.unshift(attackRow)
    }
    return rows
  }, [activeSweep?.running, currentFreq, displaySignals, liveBleSignals.length, mode, tab, visibleIndicators])
  const summary = summarizeCommon(displaySignals)
  const prioritySignals = getPrioritySignals(displaySignals)
  const matchedDevices = matchDevicesForSignals(displaySignals, displayDevices)
  const vendorPosture = countBy(displaySignals, (signal) => getVendorPostureLabel(signal))
  const protocolPosture = countBy(displaySignals, (signal) => signal.protocol || signal.rf_protocol || 'Unknown')
  const evidenceRows = useMemo(() => summarizeEvidenceRows(displaySignals, displayDevices), [displaySignals, displayDevices])
  const brandLeads = useMemo(() => summarizeBrandLeads(displaySignals, displayDevices), [displaySignals, displayDevices])
  const bleDeviceInventory = useMemo(() => {
    if (tab !== 'BLE') return []
    return [...displayDevices]
      .filter((device) => device?.mac_address)
      .sort((left, right) => {
        const rightScore = Number(right?.trust_score || right?.best_evidence_score || right?.confidence || 0)
        const leftScore = Number(left?.trust_score || left?.best_evidence_score || left?.confidence || 0)
        if (rightScore !== leftScore) return rightScore - leftScore
        return Number(right?.last_seen || 0) - Number(left?.last_seen || 0)
      })
  }, [displayDevices, tab])
  const freshness = useMemo(() => getSweepFreshnessTone(lastSweepMeta?.completedAt), [lastSweepMeta?.completedAt])
  const scanSummary = useMemo(() => {
    const topProtocol = protocolPosture?.[0]?.label || '--'
    const topVendor = vendorPosture?.find((entry) => entry.label && entry.label !== 'Unknown')?.label || vendorPosture?.[0]?.label || '--'
    const topProductLead = brandLeads?.[0]?.label || '--'
    return { topProtocol, topVendor, topProductLead }
  }, [brandLeads, protocolPosture, vendorPosture])
  const heartbeatSegments = useMemo(() => buildHeartbeatSegments(lastStreamUpdate || bandLastUpdate), [bandLastUpdate, lastStreamUpdate])
  const opsDeckState = useMemo(
    () => getOpsDeckState({ activeSweep, streamingConfirmed, bleDecoderRunning, runtimeWarning }),
    [activeSweep, bleDecoderRunning, runtimeWarning, streamingConfirmed],
  )
  const bandPanels = useMemo(
    () => renderBandSpecificPanels(tab, visibleIndicators, correlatedEntities.length ? correlatedEntities : correlations, {
      selectedIdentity: resolvedIdentity,
      onSelectIdentity: setSelectedIdentity,
      onExportIdentity: handleExportIdentity,
      matchedDevices,
      onSelectDevice,
      signals: displaySignals,
      onSelectSignal,
      wifiHistory,
      onSelectEdge: setSelectedEdge,
      bleDecoderStatus,
      bleDecoderBusy,
      onStartBleDecoder: handleStartBleDecoder,
      onStopBleDecoder: handleStopBleDecoder,
      mode,
    }),
    [
      bleDecoderBusy,
      bleDecoderStatus,
      correlations,
      correlatedEntities,
      displaySignals,
      matchedDevices,
      mode,
      onSelectDevice,
      onSelectSignal,
      resolvedIdentity,
      tab,
      visibleIndicators,
      wifiHistory,
    ],
  )
  const primaryIntelPanels = useMemo(() => {
    const basePanels = [
      (
        <Panel key="evidence-tiers" kicker="Integrity" title="Evidence Tiers" className="dashboard-panel">
          <div className="intel-stack">
            {evidenceRows.map((item) => (
              <div key={item.label} className="intel-row">
                <span>{item.label}</span>
                <strong>{item.count}</strong>
              </div>
            ))}
            {!evidenceRows.length && <div className="empty-box">No evidence tiers available in this band yet.</div>}
          </div>
        </Panel>
      ),
      (
        <Panel key="hot-targets" kicker="Priority" title="Hot Targets" className="dashboard-panel">
          <div className="intel-stack">
            {prioritySignals.map((signal, index) => (
              <button key={`${tab}-${signal.freq_mhz || 'sig'}-${index}`} className="intel-target" onClick={() => onSelectSignal(signal)}>
                <div>
                  <strong>{metricDetailSignal(signal)}</strong>
                  <div className="device-meta">{freq(signal.freq_mhz || signal.frequency_mhz)}</div>
                </div>
                <span>{signal.confidence || '--'}</span>
              </button>
            ))}
            {!prioritySignals.length && <div className="empty-box">{activeSweep?.completed ? 'Sweep completed with no retained targets.' : 'No live targets in this band yet.'}</div>}
          </div>
        </Panel>
      ),
      ...bandPanels.primary,
    ]
    if (tab !== 'BLE') {
      basePanels.push(
        <Panel key="protocols" kicker="Protocol" title="Observed Families" className="dashboard-panel">
          <div className="intel-stack">
            {protocolPosture.map((item) => (
              <div key={item.label} className="intel-row"><span>{item.label}</span><strong>{item.count}</strong></div>
            ))}
            {!protocolPosture.length && <div className="empty-box">No classified families yet.</div>}
          </div>
        </Panel>,
      )
    }
    return basePanels
  }, [activeSweep?.completed, bandPanels.primary, evidenceRows, onSelectSignal, prioritySignals, protocolPosture, tab])
  const secondaryIntelPanels = useMemo(() => {
    const panels = [
      (
        <Panel key="readiness" kicker="Readiness" title="Preflight / Freshness" className="dashboard-panel">
          <div className="intel-stack">
            <div className="intel-row">
              <span>Ready to start</span>
              <strong>{rfHealth?.preflight?.ready_to_start ? 'yes' : 'no'}</strong>
            </div>
            <div className="intel-row">
              <span>Ready for live intel</span>
              <strong>{rfHealth?.preflight?.ready_for_live_intel ? 'yes' : 'no'}</strong>
            </div>
            <div className="intel-row">
              <span>Stale timeout</span>
              <strong>{rfHealth?.data_validity?.stale_timeout_sec ?? '--'}s</strong>
            </div>
            <div className="intel-row">
              <span>Prune timeout</span>
              <strong>{rfHealth?.data_validity?.prune_timeout_sec ?? '--'}s</strong>
            </div>
          </div>
        </Panel>
      ),
      ...bandPanels.secondary,
    ]
    if (tab === 'BLE') {
      panels.push(
        <BleOperationsMatrixPanel
          key="ble-ops"
          mode={mode}
          protocolPosture={protocolPosture}
          vendorPosture={vendorPosture}
          brandLeads={brandLeads}
          correlatedEntities={matchedDevices}
          prioritySignals={prioritySignals}
          evidenceRows={evidenceRows}
        />,
      )
    } else {
      panels.push(
        <Panel key="vendors" kicker="Vendor" title="Resolved Vendors" className="dashboard-panel">
          <div className="intel-stack">
            {vendorPosture.map((item) => (
              <div key={item.label} className="intel-row"><span>{item.label}</span><strong>{item.count}</strong></div>
            ))}
            {!vendorPosture.length && <div className="empty-box">No vendor hints yet.</div>}
          </div>
        </Panel>,
        <Panel key="brands" kicker="Identity" title="Top Brand / Product Leads" className="dashboard-panel">
          <div className="intel-stack">
            {brandLeads.map((item) => (
              <div key={item.label} className="intel-row">
                <span>{item.label}</span>
                <strong>{item.count}</strong>
              </div>
            ))}
            {!brandLeads.length && <div className="empty-box">No brand or product-family leads surfaced yet.</div>}
          </div>
        </Panel>,
        <Panel key="fusion" kicker="Fusion" title="Matched Entities" className="dashboard-panel">
          <DeviceList devices={matchedDevices} onSelect={onSelectDevice} layoutMode={layoutMode} />
        </Panel>,
      )
    }
    if (tab === 'WIFI') {
      panels.push(
        <Panel key="wifi-adjacent" kicker="Coexistence" title="Adjacent-Band Pressure" className="dashboard-panel">
          <div className="intel-stack">
            <div className="intel-row">
              <span>Adjacent-band events</span>
              <strong>{visibleIndicators.adjacent_band_pressure || 0}</strong>
            </div>
            {(visibleIndicators.coexistence_vendors || []).map((item) => (
              <div key={item.label} className="intel-row">
                <span>{item.label}</span>
                <strong>{item.count}</strong>
              </div>
            ))}
            {!visibleIndicators.adjacent_band_pressure && !(visibleIndicators.coexistence_vendors || []).length ? (
              <div className="empty-box">No adjacent-band pressure detected yet.</div>
            ) : null}
          </div>
        </Panel>,
      )
    }
    return panels
  }, [
    bandPanels.secondary,
    brandLeads,
    evidenceRows,
    layoutMode,
    matchedDevices,
    mode,
    onSelectDevice,
    prioritySignals,
    protocolPosture,
    rfHealth?.data_validity?.prune_timeout_sec,
    rfHealth?.data_validity?.stale_timeout_sec,
    rfHealth?.preflight?.ready_for_live_intel,
    rfHealth?.preflight?.ready_to_start,
    tab,
    vendorPosture,
    visibleIndicators.adjacent_band_pressure,
    visibleIndicators.coexistence_vendors,
  ])
  const topologyNodes = useMemo(() => {
    const signalNodes = tableSignals.slice(0, 4).map((signal, index) => ({
      group: 'Signal',
      label: metricDetailSignal(signal),
      detail: freq(signal.freq_mhz || signal.frequency_mhz || currentFreq),
      tone: index === 0 ? 'hot' : 'neutral',
      active: selectedSignal?.signal_id && selectedSignal.signal_id === signal.signal_id,
    }))
    const deviceNodes = matchedDevices.slice(0, 3).map((device) => ({
      group: 'Entity',
      label: device.vendor || device.product || device.device_id || 'Linked entity',
      detail: (device.protocols || []).join(' / ') || 'entity link',
      tone: 'ready',
      active: selectedDevice?.device_id && selectedDevice.device_id === device.device_id,
    }))
    return [
      {
        group: 'Sensor',
        label: 'HackRF SDR',
        detail: streamingConfirmed ? 'live stream' : 'standby',
        tone: streamingConfirmed ? 'live' : 'warn',
        active: streamingConfirmed,
      },
      {
        group: 'Focus',
        label: currentLabel || freq(currentFreq),
        detail: activeSweep?.running ? 'active profile' : focusMetricLabel,
        tone: activeSweep?.running ? 'ready' : 'neutral',
        active: Boolean(activeSweep?.running),
      },
      ...signalNodes,
      ...deviceNodes,
    ]
  }, [activeSweep?.running, currentFreq, currentLabel, focusMetricLabel, matchedDevices, selectedDevice?.device_id, selectedSignal?.signal_id, streamingConfirmed, tableSignals])
  const topologyEdges = useMemo(() => [
    { label: 'Signals', value: summary.count },
    { label: 'Entities', value: matchedDevices.length },
    { label: 'Protocols', value: summary.protocols },
    { label: 'Top lead', value: scanSummary.topProductLead || '--' },
    { label: 'Feed', value: bleDecoderRunning ? 'BLE decode' : streamingConfirmed ? 'streaming' : 'idle' },
  ], [bleDecoderRunning, matchedDevices.length, scanSummary.topProductLead, streamingConfirmed, summary.count, summary.protocols])

  async function handleStartBleDecoder() {
    try {
      setBleDecoderBusy(true)
      const payload = await startBleDecoder()
      setBleDecoderStatus(payload)
      setBandIntelError('')
    } catch (err) {
      setBandIntelError(String(err.message || err))
    } finally {
      setBleDecoderBusy(false)
    }
  }

  async function handleStopBleDecoder() {
    try {
      setBleDecoderBusy(true)
      const payload = await stopBleDecoder()
      setBleDecoderStatus(payload)
      setBandIntelError('')
    } catch (err) {
      setBandIntelError(String(err.message || err))
    } finally {
      setBleDecoderBusy(false)
    }
  }

  async function handleClearLocalSweepResults() {
    try {
      await onClearSweepResults?.()
    } catch {
      // parent handler already reports the failure state
    }
    setSweepSignalArchive([])
    setSweepDeviceArchive([])
    setLastSweepMeta(null)
    setSweepProfileCounts({})
    setSelectedIdentity(null)
    setSelectedEdge(null)
    setLiveSelectedSignal(null)
    setLiveSelectedDevice(null)
    clearStoredSweepData()
    if (tab === 'BLE') {
      setBandIntel(null)
      setBandIntelError('')
      try {
        const payload = await clearBleDecoder()
        setBleDecoderStatus(payload)
      } catch {
        // ignore decoder clear failures during local clear
      }
    }
  }

  useEffect(() => {
    if (tab !== 'BLE') return
    if (!system?.session_active) {
      bleAutoStartAttemptRef.current = 0
      return
    }
    if (!rfHealth?.hackrf?.available) return
    if (bleDecoderStatus?.running || bleDecoderBusy) return
    const now = Date.now()
    if (now - bleAutoStartAttemptRef.current < 12000) return

    let cancelled = false
    bleAutoStartAttemptRef.current = now

    async function ensureBleDecoder() {
      try {
        setBleDecoderBusy(true)
        const payload = await startBleDecoder()
        if (!cancelled) {
          setBleDecoderStatus(payload)
          setBandIntelError('')
        }
      } catch (err) {
        if (!cancelled) {
          setBandIntelError(String(err.message || err))
        }
      } finally {
        if (!cancelled) {
          setBleDecoderBusy(false)
        }
      }
    }

    ensureBleDecoder()

    return () => {
      cancelled = true
    }
  }, [bleDecoderBusy, bleDecoderStatus?.running, rfHealth?.hackrf?.available, system?.session_active, tab])

  return (
    <main className={`workspace category-workspace ${tabToneClass}`}>
      <div className="main-column">
        {runtimeWarning ? <section className="error-banner soft-warning">{runtimeWarning}</section> : null}
        {isPanelVisible('opsDeck') ? (
          <section className={`sdr-ops-deck sdr-ops-deck-${opsDeckState.tone}`}>
            <div className="sdr-ops-brief">
              <div className="sdr-ops-kicker">{title} Command Center</div>
              <div className="sdr-ops-headline-row">
                <strong>{opsDeckState.label}</strong>
                <span className={`sdr-ops-state-pill ${opsDeckState.tone}`}>{tab}</span>
              </div>
              <p>{opsDeckState.detail}</p>
              <div className="sdr-ops-tag-row">
                <span className="sdr-ops-tag">{summary.count} detections</span>
                <span className="sdr-ops-tag">{matchedDevices.length} entities</span>
                <span className="sdr-ops-tag">{currentLabel || freq(currentFreq)}</span>
                <span className="sdr-ops-tag">{streamingConfirmed ? 'live feed' : 'stream idle'}</span>
              </div>
            </div>
            <div className="sdr-live-visual">
              <div className="sdr-live-visual-head">
                <span>Realtime Scan</span>
                <strong>{activeSweep?.running ? 'ACTIVE' : bleDecoderRunning ? 'DECODER LIVE' : 'STANDBY'}</strong>
              </div>
              <SpectrumCanvas bins={fft || []} canvasId={`sdr-spectrum-${tab.toLowerCase()}`} />
              <div className="heartbeat-strip sdr-heartbeat-strip">
                {heartbeatSegments.map((segment) => (
                  <div key={segment.key} className={segment.active ? 'heartbeat-bar active' : 'heartbeat-bar'} />
                ))}
              </div>
              <div className="sdr-live-caption">
                {lastStreamUpdate ? `Last stream update ${new Date(lastStreamUpdate).toLocaleTimeString()}` : 'Waiting for live FFT / stream telemetry'}
              </div>
            </div>
            <div className="sdr-ops-summary-grid">
              <div className="sdr-ops-summary-card">
                <span>Protocols</span>
                <strong>{summary.protocols}</strong>
                <small>{scanSummary.topProtocol}</small>
              </div>
              <div className="sdr-ops-summary-card">
                <span>Vendors</span>
                <strong>{summary.vendors}</strong>
                <small>{scanSummary.topVendor}</small>
              </div>
              <div className="sdr-ops-summary-card">
                <span>Confidence</span>
                <strong>{summary.highestConfidence}</strong>
                <small>top lead</small>
              </div>
              <div className="sdr-ops-summary-card">
                <span>Focus</span>
                <strong>{currentLabel || freq(currentFreq)}</strong>
                <small>{focusMetricLabel}</small>
              </div>
            </div>
          </section>
        ) : null}
        {operationalTab && isPanelVisible('sweepControls') ? (
          <section className="iot-sweep-banner">
            <div className="iot-sweep-head">
              <div>
                <div className="iot-sweep-kicker">
                  {activeSweep?.completed ? `${tab} Sweep Complete` : activeSweep?.running ? `${tab} Sweep Running` : `${tab} Sweep Controls`}
                </div>
                <strong>
                  {bandCapability.can_sweep === false
                    ? bandCapability.reason || `${tab} sweep is not operator-ready on this host`
                    : activeSweep?.completed
                    ? 'Sweep results ready for analysis'
                    : activeSweep?.running
                      ? `Scanning ${activeSweep.currentLabel || '--'} at ${freq(activeSweep.currentFrequencyMHz)}`
                      : 'Start Session to arm the SDR, then click Run Sweep to collect live results for this band'}
                </strong>
                {bandCapability.can_sweep === false && bandCapability.detail ? (
                  <div className="iot-sweep-capability-note">{bandCapability.detail}</div>
                ) : null}
              </div>
              <div className="iot-sweep-meta">
                {activeSweep
                  ? `Step ${activeSweep.currentIndex || 0} / ${activeSweep.total || 0} · cycle ${activeSweep.cycle || 1}`
                  : lastSweepMeta
                    ? `Last scan ${formatAbsoluteDateTime(lastSweepMeta.completedAt)}`
                    : `${(config.channels || []).length} configured profiles`}
              </div>
            </div>
            <div className="iot-sweep-toolbar">
              <div className="iot-sweep-progress compact">
                <div className="iot-sweep-progress-bar" style={{ width: `${sweepProgress}%` }} />
              </div>
              <div className="iot-sweep-foot compact">
                {bandCapability.can_sweep === false
                  ? 'Backend capability gate is blocking this sweep until the required decoder path is installed.'
                  : activeSweep?.completed
                  ? `${sweepSignalArchive.length} signals and ${sweepDeviceArchive.length} devices retained from the sweep`
                  : activeSweep?.running
                    ? (activeSweep?.durationMinutes
                      ? `${activeSweep.durationMinutes} minute timed sweep · dwell ${(Number(activeSweep.dwellMs || 0) / 1000).toFixed(1)}s per profile`
                      : `Dwell ${(Number(activeSweep.dwellMs || 0) / 1000).toFixed(1)}s per profile`)
                    : 'No live sweep is running. Session start alone does not populate this table.'}
              </div>
              <div className="iot-sweep-rack">
                {(config.channels || []).map((channel) => {
                  const active = Number(channel.frequencyMHz) === Number(activeSweep?.currentFrequencyMHz)
                  const profileStats = sweepProfileCounts?.[getSweepProfileKey(channel.label, channel.frequencyMHz)] || null
                  return (
                    <div key={`iot-sweep-${channel.label}`} className={active ? 'iot-sweep-pill active' : 'iot-sweep-pill'}>
                      <span>{channel.label}</span>
                      <strong>{freq(channel.frequencyMHz)}</strong>
                      <small>{profileStats ? `${profileStats.signals} sig · ${profileStats.devices} dev` : '0 sig · 0 dev'}</small>
                    </div>
                  )
                })}
              </div>
              {tab === 'BLE' ? (
                <div className="iot-sweep-duration inline">
                  <label className="control-label" htmlFor="ble-sweep-duration">Sweep Duration</label>
                  <select
                    id="ble-sweep-duration"
                    className="iot-sweep-duration-select"
                    value={bleSweepDurationMinutes}
                    disabled={busy || activeSweep?.running}
                    onChange={(event) => setBleSweepDurationMinutes(event.target.value)}
                  >
                    <option value="1">1 Minute</option>
                    <option value="5">5 Minutes</option>
                    <option value="10">10 Minutes</option>
                  </select>
                </div>
              ) : null}
              <div className="iot-sweep-actions">
                <button
                  className={runSweepRecommended ? 'iot-sweep-action primary prompt-action' : 'iot-sweep-action primary'}
                  disabled={busy || !rfHealth?.hackrf?.available || !rfHealth?.sdr_streaming_confirmed || bandCapability.can_sweep === false}
                  onClick={() => onRunSweep?.(tab === 'BLE' ? { durationMinutes: Number(bleSweepDurationMinutes || 1) } : undefined)}
                >
                  Run Sweep
                </button>
                {activeSweep?.running ? (
                  <button
                    className="iot-sweep-action stop"
                    disabled={busy}
                    onClick={() => onStopSweep?.()}
                  >
                    Stop Sweep
                  </button>
                ) : null}
                <button
                  className="iot-sweep-action"
                  disabled={busy || (!sweepSignalArchive.length && !sweepDeviceArchive.length)}
                  onClick={handleClearLocalSweepResults}
                >
                  Clear Sweep Results
                </button>
                <button
                  className="iot-sweep-action"
                  disabled={!sweepSignalArchive.length && !sweepDeviceArchive.length}
                  onClick={() => downloadJson(`${tab.toLowerCase().replaceAll('-', '_')}_sweep_results.json`, {
                    exported_at: new Date().toISOString(),
                    tab,
                    sweep: activeSweep,
                    last_sweep_meta: lastSweepMeta,
                    profile_counts: sweepProfileCounts,
                    signals: sweepSignalArchive,
                    devices: sweepDeviceArchive,
                  })}
                >
                  Export JSON
                </button>
                <button
                  className="iot-sweep-action"
                  disabled={!sweepSignalArchive.length && !sweepDeviceArchive.length}
                  onClick={() => downloadCsv(
                    `${tab.toLowerCase().replaceAll('-', '_')}_sweep_results.csv`,
                    buildSweepCsvRows(tab, sweepSignalArchive, sweepDeviceArchive),
                  )}
                >
                  Export CSV
                </button>
              </div>
            </div>
            {lastSweepMeta && !activeSweep?.running ? (
              <div className="iot-sweep-lastscan">
                <div className="iot-sweep-lastscan-head">
                  <strong>Last Scan</strong>
                  <span className={`iot-sweep-badge ${freshness.tone}`}>{freshness.label}</span>
                </div>
                <div className="iot-sweep-lastscan-row">
                  <span>Completed</span>
                  <strong>{formatAbsoluteDateTime(lastSweepMeta.completedAt)}</strong>
                </div>
                <div className="iot-sweep-lastscan-row">
                  <span>Final profile</span>
                  <strong>{lastSweepMeta.finalLabel || '--'} {lastSweepMeta.finalFrequencyMHz ? `· ${freq(lastSweepMeta.finalFrequencyMHz)}` : ''}</strong>
                </div>
                <div className="iot-sweep-lastscan-row">
                  <span>Results</span>
                  <strong>Realtime-only mode · rerun sweep to inspect fresh results</strong>
                </div>
                <div className="iot-sweep-summary">
                  <div className="iot-sweep-summary-card">
                    <span>Top Protocol</span>
                    <strong>{scanSummary.topProtocol}</strong>
                  </div>
                  <div className="iot-sweep-summary-card">
                    <span>Top Vendor Lead</span>
                    <strong>{scanSummary.topVendor}</strong>
                  </div>
                  <div className="iot-sweep-summary-card">
                    <span>Top Product Lead</span>
                    <strong>{scanSummary.topProductLead}</strong>
                  </div>
                </div>
              </div>
            ) : null}
          </section>
        ) : null}
        <section className="metrics-grid compact-metrics">
          <Metric label="Band" value={tab} detail={subtitle} />
          <Metric label="Signals" value={summary.count} detail="Recon detections" />
          <Metric label="Protocols" value={summary.protocols} detail="Observed families" />
          <Metric label="Vendors" value={summary.vendors} detail="Resolved recon hints" />
          <Metric label="Peak Confidence" value={summary.highestConfidence} detail="Highest current confidence" />
          <Metric label={focusMetricLabel} value={currentLabel || freq(currentFreq)} detail="Active capture focus" />
          <Metric label="Live Feed" value={bleDecoderRunning ? 'BLE DECODING' : streamingConfirmed ? 'STREAMING' : 'NOT STREAMING'} detail={streamingConfirmed && lastStreamUpdate ? new Date(lastStreamUpdate).toLocaleTimeString() : (runtimeWarning || 'Awaiting telemetry')} />
        </section>

        {tab !== 'ZIGBEE' && isPanelVisible('channelProfiles') ? (
          <section className="control-strip compact-channel-strip">
            <div className="control-card grow">
              <div className="control-label">Channel Profiles</div>
              <div className="channel-rack">
                {channels.map((channel) => {
                  const isActive = Math.abs(Number(channel.frequencyMHz) - currentFreq) < 0.01
                  return (
                    <button
                      key={`${tab}-${channel.label}`}
                      className={isActive ? 'channel-pill active' : 'channel-pill'}
                      disabled={busy || !rfHealth?.hackrf?.available}
                      onClick={() => onTune(channel.frequencyMHz, `${tab} ${channel.label}`)}
                    >
                      <span>{channel.label}</span>
                      <strong>{freq(channel.frequencyMHz)}</strong>
                    </button>
                  )
                })}
              </div>
            </div>
          </section>
        ) : null}

        {isPanelVisible('inventory') ? (
          <Panel
            kicker={title}
            title={tab === 'BLE' ? 'Bluetooth Inventory' : 'Signal Inventory'}
            action={(
              <div className="pill-row">
                <Pill text={inventoryStateLabel} tone={inventoryStateTone} />
                <Pill text={tab === 'BLE' && bleInventoryView === 'devices' ? `${bleDeviceInventory.length} devices` : `${tableSignals.length} detections`} tone="cyan" />
                {tab === 'BLE' ? <button className={bleInventoryView === 'devices' ? 'mini-action active' : 'mini-action'} onClick={() => setBleInventoryView('devices')}>Devices</button> : null}
                {tab === 'BLE' ? <button className={bleInventoryView === 'signals' ? 'mini-action active' : 'mini-action'} onClick={() => setBleInventoryView('signals')}>Signals</button> : null}
                {tab === 'BLE' ? <button className="mini-action" onClick={handleExportBleEvidenceBundle}>Export BLE Bundle</button> : null}
              </div>
            )}
          >
          {tab === 'BLE' && bleInventoryView === 'devices' ? (
            <BleDeviceInventoryTable devices={bleDeviceInventory.slice(0, 80)} onSelectDevice={onSelectDevice} />
          ) : (
            <SignalTable
              signals={tableSignals.slice(0, 80)}
              selectedSignal={selectedSignal}
              onSelect={onSelectSignal}
              onDelete={handleDeleteSignalRow}
              mode={mode}
              tab={tab}
              layoutMode={layoutMode}
            />
          )}
          </Panel>
        ) : null}

        {isPanelVisible('primaryIntel') ? (
        <section className="dashboard-grid sdr-dashboard-grid">
          {primaryIntelPanels}
        </section>
        ) : null}

        {isPanelVisible('secondaryIntel') ? (
        <section className="dashboard-grid sdr-dashboard-grid sdr-dashboard-grid-secondary">
          {secondaryIntelPanels}
        </section>
        ) : null}
      </div>

      {isPanelVisible('inspector') ? (
      <section className="category-inline-inspector">
        <Panel kicker="Inspector" title={selectedSignal?.protocol || `${title} Inspector`} className="inspector-panel">
          <div className="detail-grid">
            <Metric label="Selected Signal" value={selectedSignalLive?.signal_id || '--'} detail={selectedSignalLive?.protocol || 'No signal selected'} />
            <Metric label="Selected Device" value={selectedDeviceLive?.device_id || selectedEdge?.entityId || '--'} detail={selectedDeviceLive?.vendor || selectedDeviceLive?.device_type || 'No device selected'} />
            <Metric label="Last Update" value={bandLastUpdate ? new Date(bandLastUpdate).toLocaleTimeString() : '--'} detail={streamingConfirmed ? 'live backend feed' : 'stream idle'} />
            <Metric label="Backend State" value={bandIntelError ? 'DEGRADED' : 'READY'} detail={bandIntelError || 'Inspector available'} />
          </div>
          <InspectorDrawer title="Signal Payload" defaultOpen>
            <pre className="json-box">{selectedSignalLive ? JSON.stringify(selectedSignalLive, null, 2) : `Select a ${title} signal to inspect the live payload.`}</pre>
          </InspectorDrawer>
          <InspectorDrawer title="Band Intelligence">
            {bandIntelError ? <div className="error-inline">{bandIntelError}</div> : null}
            <pre className="json-box">{streamingConfirmed ? (bandIntel ? JSON.stringify(sideIntelPayload, null, 2) : 'Band intelligence is loading from the live backend.') : 'Live band intelligence is unavailable until the SDR is connected and streaming.'}</pre>
          </InspectorDrawer>
          <InspectorDrawer title="Hardware Events">
            {(rfHealth?.event_timeline || []).length ? (
              <div className="timeline-list">
                {(rfHealth?.event_timeline || []).slice().reverse().slice(0, 8).map((event, index) => (
                  <div key={`${event.timestamp}-${index}`} className="timeline-item">
                    <div className="timeline-dot" />
                    <div>
                      <strong>{event.category}</strong>
                      <div className="device-meta">{event.message}</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-box">No hardware events recorded yet.</div>
            )}
          </InspectorDrawer>
          <InspectorDrawer title="Entity Payload">
            <pre className="json-box">{selectedDeviceLive ? JSON.stringify(selectedDeviceLive, null, 2) : selectedEdge ? JSON.stringify(selectedEdge, null, 2) : 'Select a matched device or correlation edge to inspect the entity payload.'}</pre>
          </InspectorDrawer>
        </Panel>
      </section>
      ) : null}
      <div className="side-column topology-side-column">
        <RealtimeTopologyRail
          kicker={`${title} Topology`}
          title="Live Data Flow"
          tone={activeSweep?.running || bleDecoderRunning ? 'cyan' : 'neutral'}
          stateLabel={activeSweep?.running ? 'LIVE' : bleDecoderRunning ? 'DECODE' : 'READY'}
          subtitle={activeSweep?.running ? `Scanning ${activeSweep.currentLabel || currentLabel || freq(currentFreq)}` : 'Watching sensor, profile, and entity flow in realtime.'}
          lastUpdate={lastStreamUpdate || bandLastUpdate}
          nodes={topologyNodes}
          edges={topologyEdges}
        />
      </div>
    </main>
  )
}
