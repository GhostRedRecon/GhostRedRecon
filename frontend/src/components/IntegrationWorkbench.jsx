import { useEffect, useState } from 'react'
import { Metric, Panel, Pill } from './ui'
import { usePanelPreferences } from '../lib/viewPreferences'
import RealtimeTopologyRail from './RealtimeTopologyRail'
import {
  captureWbHuntPeak,
  decodeWbHuntSignal,
  fetchIntegrationStatus,
  startRtl433,
  startRtl433Sweep,
  startWbHunt,
  startWbHuntAutoDecode,
  stopRtl433,
  stopWbHunt,
  stopWbHuntAutoDecode,
  updateWbHuntRow,
} from '../lib/api'

function formatDateTime(timestamp) {
  if (!timestamp) return '--'
  const date = new Date(Number(timestamp) * 1000)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleString()
}

function formatFreqs(values) {
  return (values || []).map((value) => `${Number(value).toFixed(3)} MHz`).join(' · ')
}

function formatMtime(timestamp) {
  if (!timestamp) return '--'
  return new Date(timestamp * 1000).toLocaleString()
}

function formatCaptureTime(value) {
  if (!value) return '--'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString()
}

function formatTimeline(value) {
  if (!value) return '--'
  const date = new Date(Number(value) * 1000)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleString()
}

export default function IntegrationWorkbench({ integrationKey, tabKey, title, subtitle, onPivot }) {
  const { isPanelVisible } = usePanelPreferences(tabKey)
  const [payload, setPayload] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [selectedFreqMHz, setSelectedFreqMHz] = useState(433.92)
  const [dwellSeconds, setDwellSeconds] = useState(4)
  const [selectedProfileKey, setSelectedProfileKey] = useState('eu_ism')
  const [selectedWbRowId, setSelectedWbRowId] = useState('')
  const [selectedDecodeDwellSeconds, setSelectedDecodeDwellSeconds] = useState(4)
  const [wbDecodeResult, setWbDecodeResult] = useState(null)
  const [wbFilterMode, setWbFilterMode] = useState('all')
  const [wbSortMode, setWbSortMode] = useState('strongest')
  const [wbAutoDecodeEnabled, setWbAutoDecodeEnabled] = useState(true)
  const [wbAutoDecodeMode, setWbAutoDecodeMode] = useState('top5')
  const [wbAutoDecodeLimit, setWbAutoDecodeLimit] = useState(5)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const next = await fetchIntegrationStatus(integrationKey)
        if (!cancelled) {
          setPayload(next)
          setError('')
          if (integrationKey === 'rtl433' && next?.target_frequencies_mhz?.length) {
            setSelectedFreqMHz((current) => {
              const currentNum = Number(current)
              return next.target_frequencies_mhz.includes(currentNum)
                ? currentNum
                : next.target_frequencies_mhz[0]
            })
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(String(err.message || err))
        }
      }
    }

    load()
    const timer = window.setInterval(load, 5000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [integrationKey])

  useEffect(() => {
    if (integrationKey !== 'wb_hunt') return
    const tableRows = payload?.manager?.table_rows || []
    if (!tableRows.length) {
      setSelectedWbRowId('')
      return
    }
    if (!selectedWbRowId || !tableRows.some((row) => row.row_id === selectedWbRowId)) {
      setSelectedWbRowId(tableRows[0].row_id)
    }
  }, [integrationKey, payload, selectedWbRowId])

  useEffect(() => {
    if (integrationKey !== 'wb_hunt' || !selectedWbRowId) return
    const selectedRow = (payload?.manager?.table_rows || []).find((row) => row.row_id === selectedWbRowId)
    if (selectedRow?.last_decode_result) {
      setWbDecodeResult((current) => {
        if (current?.row_id === selectedRow.row_id && current?.requested_at === selectedRow.last_decode_at) {
          return current
        }
        return {
          ...selectedRow.last_decode_result,
          row_id: selectedRow.row_id,
          requested_at: selectedRow.last_decode_at || Date.now(),
        }
      })
    }
  }, [integrationKey, payload, selectedWbRowId])

  const status = payload?.status || {}
  const process = payload?.process || {}
  const runtime = payload?.runtime || {}
  const rfHealth = runtime?.rf_health || {}
  const manager = payload?.manager || {}
  const decoderOwnsSdr = integrationKey === 'rtl433' && !!manager.running
  const decoderReady = integrationKey === 'rtl433'
    ? status.installed && !busy && !manager.running
    : status.installed && !busy
  const hopTotal = manager.sweep_frequencies?.length || payload?.target_frequencies_mhz?.length || 0
  const wbHuntOwnsSdr = integrationKey === 'wb_hunt' && !!manager.running
  const toneClass = integrationKey === 'wb_hunt' ? 'category-tone-wb-hunt' : 'category-tone-sub-ghz'
  const topologyNodes = integrationKey === 'wb_hunt'
    ? [
      { group: 'Sensor', label: 'HackRF SDR', detail: wbHuntOwnsSdr ? 'wb hunt owns sdr' : 'shared runtime', tone: wbHuntOwnsSdr ? 'live' : 'neutral', active: wbHuntOwnsSdr },
      { group: 'Profile', label: manager.profile?.label || 'Sweep profile', detail: selectedProfileKey, tone: 'ready', active: !!manager.running },
      ...filteredWbRows.slice(0, 4).map((row, index) => ({
        group: 'Peak',
        label: `${Number(row.peak_mhz).toFixed(3)} MHz`,
        detail: row.family || row.recommended_tab || 'unknown emitter',
        tone: index === 0 ? 'hot' : 'neutral',
        active: selectedWbRowId === row.row_id,
      })),
    ]
    : [
      { group: 'Sensor', label: 'HackRF SDR', detail: decoderOwnsSdr ? 'decoder owns sdr' : 'shared runtime', tone: decoderOwnsSdr ? 'live' : 'neutral', active: decoderOwnsSdr },
      { group: 'Decoder', label: 'rtl_433', detail: manager.running ? `hop ${manager.current_index || 0}/${hopTotal || 0}` : 'idle', tone: manager.running ? 'ready' : 'neutral', active: manager.running },
      ...(manager.recent_events || []).slice(0, 4).map((event, index) => ({
        group: 'Event',
        label: event.model || event.type || event.protocol || 'Decoded row',
        detail: event._rtl433_freq_mhz ? `${Number(event._rtl433_freq_mhz).toFixed(3)} MHz` : '--',
        tone: index === 0 ? 'hot' : 'neutral',
        active: index === 0,
      })),
    ]
  const topologyEdges = integrationKey === 'wb_hunt'
    ? [
      { label: 'Rows', value: manager.row_count || 0 },
      { label: 'Verified', value: manager.verified_detection_count || 0 },
      { label: 'Queue', value: manager.queue?.pending_count || 0 },
      { label: 'Top family', value: manager.top_family || '--' },
    ]
    : [
      { label: 'Events', value: manager.event_count || 0 },
      { label: 'Captures', value: manager.capture_count || 0 },
      { label: 'Frequencies', value: hopTotal || 0 },
      { label: 'Top product', value: manager.top_products?.[0]?.[0] || '--' },
    ]
  const wbTableRows = manager.table_rows || []
  const workbenchState = integrationKey === 'wb_hunt'
    ? (manager.running
      ? { label: 'Wideband Sweep Live', tone: 'live', detail: manager.profile?.label || 'WB Hunt is scanning the configured profile.' }
      : manager.queue?.running
        ? { label: 'Auto Decode Queue', tone: 'ready', detail: `${manager.queue.pending_count || 0} rows pending decode.` }
        : manager.completed
          ? { label: 'Results Retained', tone: 'ready', detail: `${manager.row_count || 0} rows available for triage.` }
          : { label: 'Standby', tone: 'idle', detail: 'Start Hunt to run one wideband pass and populate the operator queue.' })
    : (manager.running
      ? { label: 'Decoder Sweep Live', tone: 'live', detail: `Hop ${manager.current_index || 0}/${hopTotal || 0} is active.` }
      : manager.completed
        ? { label: 'Decode Sweep Complete', tone: 'ready', detail: `${manager.event_count || 0} decoded events retained.` }
        : { label: 'Standby', tone: 'idle', detail: 'Start Decoder to run the 433/868 sweep or single-frequency decode.' })
  let filteredWbRows = wbTableRows.slice()
  if (wbFilterMode === 'strongest') {
    filteredWbRows = filteredWbRows.filter((row) => Number(row.peak_db) > -65)
  } else if (wbFilterMode === 'subghz') {
    filteredWbRows = filteredWbRows.filter((row) => Number(row.peak_mhz) < 1000)
  } else if (wbFilterMode === '24ghz') {
    filteredWbRows = filteredWbRows.filter((row) => Number(row.peak_mhz) >= 2400 && Number(row.peak_mhz) <= 2485)
  } else if (wbFilterMode === 'undecoded') {
    filteredWbRows = filteredWbRows.filter((row) => !['decoded', 'ignore', 'false_positive'].includes(String(row.decode_status || row.retention_state || 'new')))
  } else if (wbFilterMode === 'high-confidence') {
    filteredWbRows = filteredWbRows.filter((row) => row.confidence === 'high')
  }
  if (wbSortMode === 'latest') {
    filteredWbRows.sort((left, right) => String(right.captured_at).localeCompare(String(left.captured_at)))
  } else if (wbSortMode === 'priority') {
    filteredWbRows.sort((left, right) => String(right.operator_priority || '').localeCompare(String(left.operator_priority || '')))
  } else {
    filteredWbRows.sort((left, right) => Number(right.peak_db || -999) - Number(left.peak_db || -999))
  }
  const selectedWbRow = filteredWbRows.find((row) => row.row_id === selectedWbRowId) || filteredWbRows[0] || null

  function formatSweepStatus() {
    if (integrationKey !== 'rtl433') return ''
    if (manager.running) {
      return `Decoder sweep is running. Hop ${manager.current_index || 0}/${hopTotal || 0}.`
    }
    if (manager.status_detail === 'completed_with_backend_error') {
      return `Decoder sweep stopped with a backend error. ${manager.last_error || 'Check the decoder logs below.'}`
    }
    if (manager.status_detail === 'completed_no_events') {
      return `Decoder sweep completed, but no supported rtl_433 products were decoded. Review logs and tried frequencies below.`
    }
    if (manager.completed) {
      return `Decoder sweep complete${manager.completed_at ? ` at ${formatDateTime(manager.completed_at)}` : ''}. Review decoded rows below.`
    }
    if (status.installed) {
      return 'Click Start Decoder to auto-hop 433.92, 868.30, 868.95, and 869.525 MHz.'
    }
    return 'rtl_433 is not installed on this host.'
  }

  function formatWbHuntStatus() {
    if (integrationKey !== 'wb_hunt') return ''
    if (manager.running) {
      return `WB Hunt is running ${manager.profile?.label ? `with ${manager.profile.label}` : 'with the selected profile'}. Rows will populate after the sweep, then ${wbAutoDecodeEnabled ? 'auto decode will begin for the strongest candidates.' : 'the queue will stay idle until you start decode.'}`
    }
    if (manager.queue?.running) {
      return `WB Hunt finished and auto decode is running. ${manager.queue.pending_count || 0} rows remain${manager.queue.current_row_id ? `; decoding ${manager.queue.current_row_id}` : ''}.`
    }
    if (manager.status_detail === 'completed_with_error') {
      return `WB Hunt stopped with a HackRF error. ${manager.last_error || 'Review the retained log lines below.'}`
    }
    if (manager.status_detail === 'completed_with_detections') {
      const completedDecodes = (manager.table_rows || []).filter((row) => Number(row.decode_attempts || 0) > 0).length
      if (completedDecodes) {
        return `WB Hunt complete${manager.completed_at ? ` at ${formatDateTime(manager.completed_at)}` : ''}. ${completedDecodes} rows were already processed by automation; review decoded evidence and remaining pivots below.`
      }
      return `WB Hunt complete${manager.completed_at ? ` at ${formatDateTime(manager.completed_at)}` : ''}. Review the strongest peaks and pivot targets below.`
    }
    if (manager.status_detail === 'completed_with_weak_peaks') {
      return 'WB Hunt completed, but only weak peaks were retained. Re-run with a narrower profile or move closer to the emitter.'
    }
    if (manager.status_detail === 'completed_no_peaks') {
      return 'WB Hunt completed and no usable peaks were retained. Check antenna placement, gain, and profile selection before retrying.'
    }
    if (status.installed) {
      return `Click Start Hunt to run one wideband pass, populate the signal table, and ${wbAutoDecodeEnabled ? 'auto decode the top candidates.' : 'leave rows ready for manual decode.'}`
    }
    return 'hackrf_sweep is not installed on this host.'
  }

  async function handleStartDecoder(freqMHz) {
    setBusy(true)
    try {
      await startRtl433(freqMHz)
      const next = await fetchIntegrationStatus('rtl433')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStopDecoder() {
    setBusy(true)
    try {
      await stopRtl433()
      const next = await fetchIntegrationStatus('rtl433')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStartDecoderSweep() {
    setBusy(true)
    try {
      await startRtl433Sweep(dwellSeconds)
      const next = await fetchIntegrationStatus('rtl433')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStartWbHunt() {
    setBusy(true)
    try {
      await startWbHunt(selectedProfileKey, {
        autoDecode: wbAutoDecodeEnabled,
        autoDecodeMode: wbAutoDecodeMode,
        autoDecodeDwellSeconds: selectedDecodeDwellSeconds,
        autoDecodeLimit: wbAutoDecodeLimit,
      })
      const next = await fetchIntegrationStatus('wb_hunt')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStopWbHunt() {
    setBusy(true)
    try {
      await stopWbHunt()
      const next = await fetchIntegrationStatus('wb_hunt')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleCapturePeak(lead) {
    setBusy(true)
    try {
      await captureWbHuntPeak(lead.peak_mhz, lead.family, `Captured from WB Hunt at ${Number(lead.peak_mhz).toFixed(3)} MHz`)
      setError('')
      if (onPivot) {
        onPivot('Signal Lab')
      }
      const next = await fetchIntegrationStatus(integrationKey)
      setPayload(next)
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleDecodeSelectedSignal() {
    if (!selectedWbRow) return
    setBusy(true)
    try {
      const result = await decodeWbHuntSignal(selectedWbRow.peak_mhz, selectedDecodeDwellSeconds)
      setWbDecodeResult({
        ...result,
        row_id: selectedWbRow.row_id,
        requested_at: Date.now(),
      })
      const next = await fetchIntegrationStatus('wb_hunt')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleUpdateSelectedRow(updates) {
    if (!selectedWbRow) return
    setBusy(true)
    try {
      await updateWbHuntRow(selectedWbRow.row_id, updates)
      const next = await fetchIntegrationStatus('wb_hunt')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleMarkHighPriority(row) {
    setBusy(true)
    try {
      const tags = Array.from(new Set([...(row.tags || []), 'high-value', 'recon-first']))
      await updateWbHuntRow(row.row_id, {
        operatorPriority: 'high',
        retentionState: row.retention_state || 'triaged',
        tags,
      })
      const next = await fetchIntegrationStatus('wb_hunt')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleRowDecode(row) {
    setSelectedWbRowId(row.row_id)
    setBusy(true)
    try {
      const result = await decodeWbHuntSignal(row.peak_mhz, selectedDecodeDwellSeconds)
      setWbDecodeResult({ ...result, row_id: row.row_id, requested_at: Date.now() })
      const next = await fetchIntegrationStatus('wb_hunt')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStartAutoDecode() {
    setBusy(true)
    try {
      await startWbHuntAutoDecode(wbAutoDecodeMode, selectedDecodeDwellSeconds, wbAutoDecodeLimit)
      const next = await fetchIntegrationStatus('wb_hunt')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  async function handleStopAutoDecode() {
    setBusy(true)
    try {
      await stopWbHuntAutoDecode()
      const next = await fetchIntegrationStatus('wb_hunt')
      setPayload(next)
      setError('')
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="workspace integration-workspace">
      <div className="main-column">
      <section className={`sdr-ops-deck sdr-ops-deck-${workbenchState.tone} ${toneClass}`}>
        <div className="sdr-ops-brief">
          <div className="sdr-ops-kicker">{title} Command Center</div>
          <div className="sdr-ops-headline-row">
            <strong>{workbenchState.label}</strong>
            <span className={`sdr-ops-state-pill ${workbenchState.tone}`}>{title}</span>
          </div>
          <p>{workbenchState.detail}</p>
          <div className="sdr-ops-tag-row">
            <span className="sdr-ops-tag">{status.installed ? 'tool ready' : 'tool missing'}</span>
            <span className="sdr-ops-tag">{process.running ? 'host process active' : 'host idle'}</span>
            <span className="sdr-ops-tag">{rfHealth?.sdr_streaming_confirmed ? 'hackrf streaming' : 'hackrf idle'}</span>
            <span className="sdr-ops-tag">{integrationKey === 'wb_hunt' ? `${manager.row_count || 0} rows` : `${manager.event_count || 0} events`}</span>
          </div>
        </div>
        <div className="sdr-ops-summary-grid">
          <div className="sdr-ops-summary-card">
            <span>Runtime</span>
            <strong>{process.running ? 'RUNNING' : 'IDLE'}</strong>
            <small>{decoderOwnsSdr ? 'decoder owns SDR' : wbHuntOwnsSdr ? 'wb hunt owns SDR' : 'shared runtime'}</small>
          </div>
          <div className="sdr-ops-summary-card">
            <span>{integrationKey === 'wb_hunt' ? 'Rows' : 'Events'}</span>
            <strong>{integrationKey === 'wb_hunt' ? (manager.row_count || 0) : (manager.event_count || 0)}</strong>
            <small>{integrationKey === 'wb_hunt' ? (manager.top_family || 'no family lead') : `${hopTotal || 0} sweep freqs`}</small>
          </div>
          <div className="sdr-ops-summary-card">
            <span>Ownership</span>
            <strong>{decoderOwnsSdr ? 'DECODER' : wbHuntOwnsSdr ? 'WB HUNT' : (runtime.session_active ? 'SESSION' : 'NONE')}</strong>
            <small>{rfHealth?.sdr_fault_reason || 'runtime snapshot'}</small>
          </div>
          <div className="sdr-ops-summary-card">
            <span>Last Start</span>
            <strong>{formatDateTime(manager.started_at || rfHealth?.sdr_last_started_at)}</strong>
            <small>{manager.last_error || rfHealth?.sdr_last_error || 'no recent process error'}</small>
          </div>
        </div>
      </section>
      <section className="metrics-grid">
        <Metric label="Integration" value={title} detail={subtitle} />
        <Metric label="Installed" value={status.installed ? 'YES' : 'NO'} detail={status.path || 'binary not found'} />
        <Metric label="Process" value={process.running ? 'RUNNING' : 'IDLE'} detail={process.running ? 'host process detected' : 'no process detected'} />
        <Metric label="RF Ownership" value={decoderOwnsSdr ? 'DECODER ACTIVE' : wbHuntOwnsSdr ? 'WB HUNT ACTIVE' : (runtime.session_active ? 'SESSION ACTIVE' : 'IDLE')} detail={decoderOwnsSdr ? 'rtl_433 is using the HackRF directly' : wbHuntOwnsSdr ? 'hackrf_sweep is using the HackRF directly' : (rfHealth?.sdr_fault_reason || 'runtime snapshot')} />
        {integrationKey === 'rtl433' ? (
          <Metric label="Decoded Events" value={manager.event_count || 0} detail={manager.running ? `${manager.mode === 'sweep' ? 'auto sweep' : 'single frequency'} @ ${manager.freq_mhz || '--'} MHz` : (manager.completed ? 'last sweep retained' : 'decoder idle')} />
        ) : null}
        {integrationKey === 'wb_hunt' ? (
          <Metric label="Sweep Rows" value={manager.row_count || 0} detail={manager.running ? `${manager.profile?.label || 'WB Hunt'} in progress` : (manager.completed ? 'last hunt retained' : 'hunt idle')} />
        ) : null}
        {integrationKey === 'wb_hunt' ? (
          <Metric label="Verified Detections" value={manager.verified_detection_count || 0} detail={manager.top_family ? `top family: ${manager.top_family}` : 'no detections retained'} />
        ) : null}
      </section>

      {error ? <section className="error-banner">{error}</section> : null}

      <section className="dashboard-grid">
        {isPanelVisible('hostReadiness') ? (
        <Panel kicker="Integration Status" title="Host Readiness" className="dashboard-panel">
          <div className="detail-grid">
            <Metric label="Binary" value={status.installed ? 'AVAILABLE' : 'MISSING'} detail={status.detail || 'no version detail'} />
            <Metric label="Runtime" value={decoderOwnsSdr ? 'DECODER OWNS SDR' : wbHuntOwnsSdr ? 'WB HUNT OWNS SDR' : (rfHealth?.sdr_streaming_confirmed ? 'STREAMING' : 'IDLE')} detail={decoderOwnsSdr ? `hop ${manager.current_index || 0}/${hopTotal || 0} · one-pass sweep` : wbHuntOwnsSdr ? `${manager.profile?.label || 'WB Hunt'} · one-pass sweep` : (rfHealth?.sdr_freq_mhz ? `${rfHealth.sdr_freq_mhz} MHz` : 'no active tune')} />
            <Metric label="Last Start" value={formatDateTime(manager.started_at || rfHealth?.sdr_last_started_at)} detail={manager.running ? 'decoder session' : 'from SDR telemetry'} />
            <Metric label="Last Error" value={(manager.last_error || rfHealth?.sdr_last_error) ? 'PRESENT' : 'NONE'} detail={manager.last_error || rfHealth?.sdr_last_error || 'no recent process error'} />
          </div>
          <div className="pill-row">
            <Pill text={status.installed ? 'tool-installed' : 'tool-missing'} tone={status.installed ? 'green' : 'amber'} />
            <Pill text={process.running ? 'process-running' : 'process-idle'} tone={process.running ? 'green' : 'neutral'} />
            <Pill text={decoderOwnsSdr ? 'decoder-controls-sdr' : wbHuntOwnsSdr ? 'wb-hunt-controls-sdr' : (rfHealth?.sdr_streaming_confirmed ? 'sdr-streaming' : 'sdr-idle')} tone={decoderOwnsSdr || wbHuntOwnsSdr || rfHealth?.sdr_streaming_confirmed ? 'green' : 'amber'} />
            {integrationKey === 'rtl433' ? <Pill text={manager.running ? 'decoder-running' : manager.status_detail === 'completed_with_backend_error' ? 'decoder-error' : manager.completed ? 'sweep-complete' : 'decoder-idle'} tone={manager.status_detail === 'completed_with_backend_error' ? 'amber' : (manager.running || manager.completed ? 'green' : 'neutral')} /> : null}
            {integrationKey === 'wb_hunt' ? <Pill text={manager.running ? 'hunt-running' : manager.status_detail === 'completed_with_error' ? 'hunt-error' : manager.status_detail === 'completed_no_peaks' ? 'hunt-no-peaks' : manager.completed ? 'hunt-complete' : 'hunt-idle'} tone={manager.status_detail === 'completed_with_error' ? 'amber' : (manager.running || manager.completed ? 'green' : 'neutral')} /> : null}
          </div>
          {integrationKey === 'rtl433' ? (
            <div className="guidance-list" style={{ marginTop: '0.85rem' }}>
              <div className="guidance-item">
                <strong>Operator:</strong> {formatSweepStatus()}
              </div>
              <div className="guidance-item">
                <strong>Behavior:</strong> Start Decoder stops the normal SDR session if needed, takes control of the HackRF, and performs one full EU 433/868 sweep.
              </div>
              <div className="guidance-item">
                <strong>Single Frequency:</strong>{' '}
                <select
                  value={selectedFreqMHz}
                  disabled={!decoderReady}
                  onChange={(event) => setSelectedFreqMHz(Number(event.target.value))}
                >
                  {(payload?.target_frequencies_mhz || [433.92]).map((freqMHz) => (
                    <option key={freqMHz} value={freqMHz}>
                      {Number(freqMHz).toFixed(3)} MHz
                    </option>
                  ))}
                </select>
              </div>
              <div className="guidance-item">
                <strong>Auto Sweep Dwell:</strong>{' '}
                <select
                  value={dwellSeconds}
                  disabled={!decoderReady}
                  onChange={(event) => setDwellSeconds(Number(event.target.value))}
                >
                  {[3, 4, 5, 6].map((seconds) => (
                    <option key={seconds} value={seconds}>
                      {seconds}s
                    </option>
                  ))}
                </select>
              </div>
              <div className="pill-row">
                <button className="mini-action" disabled={!decoderReady} onClick={handleStartDecoderSweep}>Start Decoder</button>
                <button className="mini-action" disabled={!decoderReady} onClick={() => handleStartDecoder(selectedFreqMHz)}>Single Frequency</button>
                <button className="mini-action" disabled={busy || !manager.running} onClick={handleStopDecoder}>Stop Decoder</button>
              </div>
            </div>
          ) : null}
          {integrationKey === 'wb_hunt' ? (
            <div className="guidance-list" style={{ marginTop: '0.85rem' }}>
              <div className="guidance-item">
                <strong>Operator:</strong> {formatWbHuntStatus()}
              </div>
              <div className="guidance-item">
                <strong>Scan Profile:</strong>{' '}
                <select
                  value={selectedProfileKey}
                  disabled={!status.installed || busy || manager.running}
                  onChange={(event) => setSelectedProfileKey(event.target.value)}
                >
                  {Object.entries(manager.profiles || {}).map(([profileKey, profile]) => (
                    <option key={profileKey} value={profileKey}>
                      {profile.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="guidance-item">
                <strong>Automation:</strong>{' '}
                <select
                  value={wbAutoDecodeEnabled ? 'enabled' : 'disabled'}
                  disabled={!status.installed || busy || manager.running || manager.queue?.running}
                  onChange={(event) => setWbAutoDecodeEnabled(event.target.value === 'enabled')}
                >
                  <option value="enabled">Scan + Auto Decode</option>
                  <option value="disabled">Scan Only</option>
                </select>
              </div>
              <div className="guidance-item">
                <strong>Behavior:</strong> Start Hunt takes temporary control of the HackRF, runs one wideband sweep pass, populates the full-width signal table, and {wbAutoDecodeEnabled ? 'then automatically decodes the strongest rows in the background.' : 'retains the strongest peaks for manual follow-up.'}
              </div>
              <div className="guidance-item">
                <strong>Recommended:</strong> Use `EU 433 / 868 Focused Sweep` for cheap EU IoT, `EU Utility / Meter Sweep` for 868-metering work, and `2.4 GHz Smart-Home Sweep` for Bluetooth/Zigbee/WiFi triage.
              </div>
              <div className="pill-row">
                <button className="mini-action" disabled={!status.installed || busy || manager.running} onClick={handleStartWbHunt}>Start Hunt</button>
                <button className="mini-action" disabled={busy || !manager.running} onClick={handleStopWbHunt}>Stop Hunt</button>
              </div>
            </div>
          ) : null}
        </Panel>
        ) : null}

        {isPanelVisible('targetProfile') ? (
        <Panel kicker="Target Profile" title="Recommended Frequencies" className="dashboard-panel">
          <div className="guidance-list">
            <div className="guidance-item"><strong>Focus:</strong> {formatFreqs(payload?.target_frequencies_mhz)}</div>
            {(payload?.recommended_use || []).map((item, index) => (
              <div key={`${integrationKey}-use-${index}`} className="guidance-item">{item}</div>
            ))}
            {payload?.installation_hint ? (
              <div className="guidance-item"><strong>Host note:</strong> {payload.installation_hint}</div>
            ) : null}
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('workflow') && integrationKey === 'rtl433' ? (
          <Panel kicker="Sweep Trail" title="Attempted Frequencies" className="dashboard-panel">
            {manager.attempted_frequencies?.length ? (
              <div className="intel-stack">
                {manager.attempted_frequencies.map((freq, index) => (
                  <div key={`${freq}-${index}`} className="intel-row">
                    <span>{Number(freq).toFixed(3)} MHz</span>
                    <strong>{manager.frequency_hits?.find(([hitFreq]) => hitFreq === Number(freq).toFixed(3)) ? 'decoded' : 'no decode'}</strong>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-box">No decoder sweep has been run yet.</div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('workflow') && integrationKey === 'wb_hunt' ? (
          <Panel kicker="Signal Queue" title="Detected Signal Table" className="dashboard-panel dashboard-panel-full">
            {filteredWbRows.length ? (
              <>
                <div className="wb-hunt-toolbar">
                  <div className="guidance-item">
                    <strong>Filter:</strong>{' '}
                    <select value={wbFilterMode} disabled={busy} onChange={(event) => setWbFilterMode(event.target.value)}>
                      <option value="all">All Signals</option>
                      <option value="strongest">Strongest Only</option>
                      <option value="subghz">Sub-GHz Only</option>
                      <option value="24ghz">2.4 GHz Only</option>
                      <option value="undecoded">Undecoded Only</option>
                      <option value="high-confidence">High Confidence Only</option>
                    </select>
                  </div>
                  <div className="guidance-item">
                    <strong>Sort:</strong>{' '}
                    <select value={wbSortMode} disabled={busy} onChange={(event) => setWbSortMode(event.target.value)}>
                      <option value="strongest">Strongest First</option>
                      <option value="latest">Latest First</option>
                      <option value="priority">Priority First</option>
                    </select>
                  </div>
                  <div className="guidance-item">
                    <strong>Auto Decode:</strong>{' '}
                    <select value={wbAutoDecodeMode} disabled={busy || manager.queue?.running} onChange={(event) => setWbAutoDecodeMode(event.target.value)}>
                      <option value="top5">Decode Top 5</option>
                      <option value="new">Auto Decode New Rows</option>
                    </select>
                  </div>
                  <div className="guidance-item">
                    <strong>Limit:</strong>{' '}
                    <select value={wbAutoDecodeLimit} disabled={busy || manager.queue?.running} onChange={(event) => setWbAutoDecodeLimit(Number(event.target.value))}>
                      {[3, 5, 10].map((count) => (
                        <option key={count} value={count}>{count}</option>
                      ))}
                    </select>
                  </div>
                  <div className="guidance-item">
                    <strong>Dwell:</strong>{' '}
                    <select
                      value={selectedDecodeDwellSeconds}
                      disabled={busy || manager.queue?.running}
                      onChange={(event) => setSelectedDecodeDwellSeconds(Number(event.target.value))}
                    >
                      {[3, 4, 5, 6].map((seconds) => (
                        <option key={seconds} value={seconds}>
                          {seconds}s
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="pill-row">
                    <button className="mini-action" disabled={busy || manager.running || manager.queue?.running} onClick={handleStartAutoDecode}>Start Auto Decode</button>
                    <button className="mini-action" disabled={busy || !manager.queue?.running} onClick={handleStopAutoDecode}>Stop Queue</button>
                  </div>
                </div>
                <div className="wb-hunt-table-wrap">
                <table className="wb-hunt-table">
                  <thead>
                    <tr>
                      <th>Seen</th>
                      <th>Timeline</th>
                      <th>Family</th>
                      <th>Risk</th>
                      <th>Tags</th>
                      <th>Peak</th>
                      <th>Center</th>
                      <th>Window Range</th>
                      <th>Power</th>
                      <th>Confidence</th>
                      <th>Evidence</th>
                      <th>Decoder Path</th>
                      <th>State</th>
                      <th>Status</th>
                      <th>Shortcuts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredWbRows.map((row) => {
                      const isSelected = selectedWbRow?.row_id === row.row_id
                      const decodeStatus = row.row_id === manager.queue?.current_row_id
                        ? 'decoding'
                        : wbDecodeResult?.row_id === row.row_id
                          ? wbDecodeResult.status
                          : (row.decode_status || 'new')
                      return (
                        <tr
                          key={row.row_id}
                          className={isSelected ? 'selected' : ''}
                          onClick={() => setSelectedWbRowId(row.row_id)}
                        >
                          <td>
                            <strong>{formatCaptureTime(row.captured_at)}</strong>
                            <div className="wb-hunt-cell-detail">{row.row_id}</div>
                          </td>
                          <td>
                            <strong>First: {formatCaptureTime(row.captured_at)}</strong>
                            <div className="wb-hunt-cell-detail">Last decode: {formatTimeline(row.last_decode_at)} · Attempts: {row.decode_attempts || 0}</div>
                          </td>
                          <td>{row.family}</td>
                          <td>{row.risk_label || '--'}</td>
                          <td>
                            <div className="wb-tag-list">
                              {(row.tags || []).map((tag) => <span key={`${row.row_id}-${tag}`} className="wb-tag">{tag}</span>)}
                            </div>
                          </td>
                          <td>{Number(row.peak_mhz).toFixed(3)} MHz</td>
                          <td>{Number(row.center_mhz).toFixed(3)} MHz</td>
                          <td>{Number(row.hz_low / 1_000_000).toFixed(3)} - {Number(row.hz_high / 1_000_000).toFixed(3)} MHz</td>
                          <td>{Number(row.peak_db).toFixed(1)} dB</td>
                          <td>{row.confidence}</td>
                          <td>
                            <strong>{row.evidence_summary?.live_signals || 0} signals · {row.evidence_summary?.matched_devices || 0} devices</strong>
                            <div className="wb-hunt-cell-detail">Vendor: {row.evidence_summary?.top_vendor_hint || '--'} · Protocol: {row.evidence_summary?.protocol_confidence || '--'}</div>
                          </td>
                          <td>{row.recommended_tab}</td>
                          <td>{row.retention_state || 'new'}</td>
                          <td>{decodeStatus}</td>
                          <td>
                            <div className="wb-action-stack">
                              <button className="mini-action" disabled={busy || manager.running} onClick={(event) => { event.stopPropagation(); handleRowDecode(row) }}>Decode</button>
                              <button className="mini-action" disabled={busy} onClick={(event) => { event.stopPropagation(); handleCapturePeak(row) }}>Capture IQ</button>
                              <button className="mini-action" disabled={busy} onClick={(event) => { event.stopPropagation(); onPivot?.('Signal Lab') }}>Open Signal Lab</button>
                              <button className="mini-action" disabled={busy} onClick={(event) => { event.stopPropagation(); onPivot?.(row.recommended_tab) }}>Pivot Tab</button>
                              <button className="mini-action" disabled={busy} onClick={(event) => { event.stopPropagation(); handleMarkHighPriority(row) }}>Mark High Priority</button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
                </div>
              </>
            ) : (
              <div className="empty-box">Run WB Hunt to populate a selectable signal table.</div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('workflow') && integrationKey === 'wb_hunt' ? (
          <Panel kicker="Selected Signal" title="Decode Workbench" className="dashboard-panel">
            {selectedWbRow ? (
              <div className="wb-hunt-detail">
                <div className="detail-grid">
                  <Metric label="Peak" value={`${Number(selectedWbRow.peak_mhz).toFixed(3)} MHz`} detail={`center ${Number(selectedWbRow.center_mhz).toFixed(3)} MHz`} />
                  <Metric label="Window" value={`${Number(selectedWbRow.hz_low / 1_000_000).toFixed(3)}-${Number(selectedWbRow.hz_high / 1_000_000).toFixed(3)} MHz`} detail={`${selectedWbRow.bin_width_khz} kHz bins`} />
                  <Metric label="Power" value={`${Number(selectedWbRow.peak_db).toFixed(1)} dB`} detail={`captured ${formatCaptureTime(selectedWbRow.captured_at)}`} />
                  <Metric label="Family" value={selectedWbRow.family} detail={selectedWbRow.confidence} />
                  <Metric label="Suggested Decoder" value={selectedWbRow.recommended_tab} detail={selectedWbRow.action} />
                  <Metric label="Risk" value={selectedWbRow.risk_label || '--'} detail={(selectedWbRow.tags || []).join(' · ')} />
                </div>
                <div className="guidance-list" style={{ marginTop: '0.85rem' }}>
                  <div className="guidance-item">
                    <strong>Operator:</strong> {manager.queue?.running ? 'Auto decode is active. The selected row will update when its decode pass completes.' : 'Click Decode Selected Signal to run the best available decoder path for this exact peak.'}
                  </div>
                  <div className="guidance-item">
                    <strong>Dwell:</strong>{' '}
                    <select
                      value={selectedDecodeDwellSeconds}
                      disabled={busy}
                      onChange={(event) => setSelectedDecodeDwellSeconds(Number(event.target.value))}
                    >
                      {[3, 4, 5, 6].map((seconds) => (
                        <option key={seconds} value={seconds}>
                          {seconds}s
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="pill-row">
                    <button className="mini-action" disabled={busy || manager.running} onClick={handleDecodeSelectedSignal}>Decode Selected Signal</button>
                    {onPivot ? <button className="mini-action" disabled={busy} onClick={() => onPivot(selectedWbRow.recommended_tab)}>Pivot</button> : null}
                    <button className="mini-action" disabled={busy} onClick={() => handleCapturePeak(selectedWbRow)}>Capture</button>
                    <button className="mini-action" disabled={busy} onClick={() => handleUpdateSelectedRow({ retentionState: 'triaged' })}>Mark Triaged</button>
                    <button className="mini-action" disabled={busy} onClick={() => handleUpdateSelectedRow({ retentionState: 'needs_capture' })}>Needs Capture</button>
                    <button className="mini-action" disabled={busy} onClick={() => handleUpdateSelectedRow({ retentionState: 'false_positive' })}>False Positive</button>
                    <button className="mini-action" disabled={busy} onClick={() => handleUpdateSelectedRow({ retentionState: 'ignore' })}>Ignore</button>
                  </div>
                </div>
                <pre className="json-box">{JSON.stringify(selectedWbRow, null, 2)}</pre>
              </div>
            ) : (
              <div className="empty-box">Select a signal row to inspect and decode it.</div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('workflow') && integrationKey === 'wb_hunt' ? (
          <Panel kicker="Queue Status" title="Auto Decode Queue" className="dashboard-panel">
            {manager.queue ? (
              <div className="intel-stack">
                <div className="intel-row">
                  <span>Mode</span>
                  <strong>{manager.queue.mode || 'idle'}</strong>
                </div>
                <div className="intel-row">
                  <span>Pending</span>
                  <strong>{manager.queue.pending_count || 0}</strong>
                </div>
                <div className="intel-row">
                  <span>Current Row</span>
                  <strong>{manager.queue.current_row_id || '--'}</strong>
                </div>
                {(manager.queue.pending_rows || []).length ? (
                  <div className="wb-queue-list">
                    {manager.queue.pending_rows.map((row) => (
                      <div key={row.row_id} className="intel-row">
                        <span>{row.family || row.row_id}</span>
                        <strong>{row.decode_status || row.retention_state || '--'}</strong>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ) : (
              <div className="empty-box">No auto decode queue state yet.</div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('workflow') && integrationKey === 'wb_hunt' ? (
          <Panel kicker="Decode Result" title="Automated Decode Output" className="dashboard-panel dashboard-panel-full">
            {wbDecodeResult ? (
              <div className="wb-result-split">
                <div className="intel-stack">
                  <div className="intel-row">
                    <span>Status</span>
                    <strong>{wbDecodeResult.status || '--'}</strong>
                  </div>
                  <div className="intel-row">
                    <span>Decoder</span>
                    <strong>{wbDecodeResult.decoder || wbDecodeResult.strategy?.recommended_tab || '--'}</strong>
                  </div>
                  <div className="intel-row">
                    <span>Message</span>
                    <strong>{wbDecodeResult.message || wbDecodeResult.strategy?.action || '--'}</strong>
                  </div>
                  {wbDecodeResult.decode_freq_mhz ? (
                    <div className="intel-row">
                      <span>Decode Frequency</span>
                      <strong>{Number(wbDecodeResult.decode_freq_mhz).toFixed(3)} MHz</strong>
                    </div>
                  ) : null}
                  {wbDecodeResult.signal_count !== undefined ? (
                    <div className="intel-row">
                      <span>Live Signals</span>
                      <strong>{wbDecodeResult.signal_count} signals · {wbDecodeResult.matched_device_count || 0} matched devices</strong>
                    </div>
                  ) : null}
                  {wbDecodeResult.top_products?.length ? (
                    <div className="intel-row">
                      <span>Top Product</span>
                      <strong>{wbDecodeResult.top_products[0][0]} · {wbDecodeResult.top_products[0][1]} hits</strong>
                    </div>
                  ) : null}
                  {wbDecodeResult.signals?.[0] ? (
                    <div className="intel-row">
                      <span>Top Signal</span>
                      <strong>{wbDecodeResult.signals[0].protocol || wbDecodeResult.signals[0].rf_protocol || '--'}</strong>
                    </div>
                  ) : null}
                </div>
                <pre className="json-box">{JSON.stringify(wbDecodeResult, null, 2)}</pre>
              </div>
            ) : (
              <div className="empty-box">Select a signal row and run decode. Sub-GHz rows auto-run rtl_433; BLE, Zigbee, LoRa, and WiFi rows now retune the live session and return band-specific evidence snapshots.</div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('artifacts') && integrationKey === 'wb_hunt' ? (
          <Panel kicker="Analyst Trail" title="Recent Artifacts" className="dashboard-panel dashboard-panel-full">
            {payload?.recent_reports?.length ? (
              <div className="intel-stack">
                {payload.recent_reports.map((report) => (
                  <div key={report.path} className="intel-row">
                    <span>{report.name}</span>
                    <strong>{new Date(report.mtime * 1000).toLocaleString()}</strong>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-box">No recent related reports on disk.</div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('artifacts') && integrationKey === 'rtl433' ? (
          <Panel kicker="Decoder Summary" title="Top Decoded Products" className="dashboard-panel">
            {manager.top_products?.length ? (
              <div className="intel-stack">
                {manager.top_products.map(([product, count]) => (
                  <div key={`${product}-${count}`} className="intel-row">
                    <span>{product}</span>
                    <strong>{count} hits</strong>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-box">
                {manager.status_detail === 'completed_with_backend_error'
                  ? 'No products were listed because rtl_433 failed while trying to use the HackRF. Check the recent decoder logs below.'
                  : 'Start Decoder and wait for supported 433/868 MHz traffic. Top decoded products will be listed here automatically.'}
              </div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('artifacts') && integrationKey === 'rtl433' ? (
          <Panel kicker="Live Decode" title="Decoded Rows" className="dashboard-panel">
            {manager.recent_events?.length ? (
              <div className="intel-stack">
                {manager.recent_events.slice(0, 12).map((event, index) => (
                  <div key={`${event._ingested_at || index}-${index}`} className="intel-row">
                    <span>
                      {event.brand ? `${event.brand} · ` : ''}
                      {event.model || event.type || event.protocol || 'Decoded device'}
                    </span>
                    <strong>{event._rtl433_freq_mhz ? `${Number(event._rtl433_freq_mhz).toFixed(3)} MHz` : (event.id || event.channel || event.frequency || event.time || event.code || '--')}</strong>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-box">
                {status.installed
                  ? 'No decoded rtl_433 events yet. Start Decoder to auto-hop EU 433/868 frequencies once and wait for matching ISM traffic.'
                  : 'rtl_433 is not installed on this host, so live decode rows are unavailable.'}
              </div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('artifacts') && integrationKey === 'rtl433' ? (
          <Panel kicker="Frequency Coverage" title="Sweep Hit Map" className="dashboard-panel">
            {manager.frequency_hits?.length ? (
              <div className="intel-stack">
                {manager.frequency_hits.map(([freq, count]) => (
                  <div key={`${freq}-${count}`} className="intel-row">
                    <span>{freq} MHz</span>
                    <strong>{count} events</strong>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-box">No decoded events have been attributed to the EU 433/868 sweep yet.</div>
            )}
          </Panel>
        ) : null}

        {isPanelVisible('artifacts') && integrationKey === 'rtl433' && manager.recent_logs?.length ? (
          <Panel kicker="Decoder Logs" title="Recent rtl_433 Logs" className="dashboard-panel">
            <div className="intel-stack">
              {manager.recent_logs.slice(0, 10).map((line, index) => (
                <div key={`${integrationKey}-log-${index}`} className="intel-row">
                  <span>log</span>
                  <strong>{line}</strong>
                </div>
              ))}
            </div>
          </Panel>
        ) : null}

        {isPanelVisible('artifacts') && integrationKey === 'rtl433' && manager.recent_events?.length ? (
          <Panel kicker="Decoded Event" title="Latest Event JSON" className="dashboard-panel">
            <pre className="json-box">{JSON.stringify(manager.recent_events[0], null, 2)}</pre>
          </Panel>
        ) : null}

        {isPanelVisible('artifacts') && payload?.recent_projects?.length ? (
          <Panel kicker="Project Files" title="Recent Related Files" className="dashboard-panel">
            <div className="intel-stack">
              {payload.recent_projects.map((file) => (
                <div key={file.path} className="intel-row">
                  <span>{file.name}</span>
                  <strong>{formatMtime(file.mtime)}</strong>
                </div>
              ))}
            </div>
          </Panel>
        ) : null}

        {isPanelVisible('processes') && process.matches?.length ? (
          <Panel kicker="Process Detail" title="Running Host Processes" className="dashboard-panel">
            <div className="intel-stack">
              {process.matches.slice(0, 5).map((line, index) => (
                <div key={`${integrationKey}-proc-${index}`} className="intel-row">
                  <span>proc</span>
                  <strong>{line}</strong>
                </div>
              ))}
            </div>
          </Panel>
        ) : null}
      </section>
      </div>
      <div className="side-column topology-side-column">
        <RealtimeTopologyRail
          kicker={`${title} Topology`}
          title="Live Data Flow"
          tone={manager.running || manager.queue?.running ? 'cyan' : 'neutral'}
          stateLabel={manager.running ? 'LIVE' : manager.queue?.running ? 'QUEUE' : 'READY'}
          subtitle={integrationKey === 'wb_hunt' ? 'Watching peak, family, and decode flow in realtime.' : 'Watching decoder, frequency, and event flow in realtime.'}
          lastUpdate={(manager.completed_at ? Number(manager.completed_at) * 1000 : 0) || (manager.started_at ? Number(manager.started_at) * 1000 : 0)}
          nodes={topologyNodes}
          edges={topologyEdges}
        />
      </div>
    </main>
  )
}
