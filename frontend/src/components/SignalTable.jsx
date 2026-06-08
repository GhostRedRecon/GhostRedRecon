import { Pill } from './ui'
import { freq, fmt } from '../lib/runtime'

function formatObservedTime(signal) {
  const raw = signal?.last_seen || signal?.timestamp || signal?.first_seen || null
  if (!raw) return '--'
  const millis = Number(raw) > 1e12 ? Number(raw) : Number(raw) * 1000
  const date = new Date(millis)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleString()
}

function getBrandLead(signal) {
  return (
    signal.vendor
    || signal.rf_vendor_candidate
    || signal.vendor_hint
    || signal.brand
    || signal.manufacturer
    || signal.lora_lab_profile_candidates?.[0]?.vendor
    || '--'
  )
}

function getProductLead(signal) {
  return (
    signal.product
    || signal.device
    || signal.device_type
    || signal.device_class
    || signal.product_category_hint
    || signal.rf_device_class
    || signal.lora_device_type_hint
    || signal.lora_lab_profile_candidates?.[0]?.profile_name
    || '--'
  )
}

function getMacLead(signal) {
  if (signal?.attack_alert_row) {
    return signal?.attack_mac_label || 'ATTACK ALERT'
  }
  return (
    signal.mac_address
    || signal.ble_mac
    || signal.device_mac
    || '--'
  )
}

function getMacTrust(signal) {
  if (signal?.attack_alert_row) {
    return {
      text: 'attack',
      tone: 'red',
      detail: signal?.attack_detail || 'BLE spam or flood posture detected',
    }
  }

  if (!signal?.mac_address && !signal?.ble_mac && !signal?.device_mac) {
    return null
  }

  if (signal.trusted_identity) {
    return {
      text: 'trusted',
      tone: 'green',
      detail: signal.trust_reasons?.length ? signal.trust_reasons.join(', ') : 'payload-backed identity',
    }
  }

  if (signal.privacy_state === 'randomized') {
    return {
      text: 'randomized',
      tone: 'amber',
      detail: 'rotating BLE address',
    }
  }

  if ((Number(signal.seen_count) || 0) >= 3 || (Number(signal.best_evidence_score) || 0) >= 0.42 || signal.paired_scan_response) {
    return {
      text: 'repeat_seen',
      tone: 'cyan',
      detail: signal.paired_scan_response
        ? `paired rsp ${signal.paired_scan_response_count || 1}`
        : `seen ${signal.seen_count || 0}`,
    }
  }

  return {
    text: 'provisional',
    tone: 'neutral',
    detail: signal.ble_identity_basis === 'decoded' ? 'weak decoded evidence' : 'early decode candidate',
  }
}

function getTrustRank(signal) {
  if (signal?.attack_alert_row) return -1
  const trust = getMacTrust(signal)
  if (!trust) return 4
  if (trust.text === 'trusted') return 0
  if (trust.text === 'repeat_seen') return 1
  if (trust.text === 'randomized') return 2
  if (trust.text === 'provisional') return 3
  return 4
}

function getSeverity(signal, mode, tab) {
  if (signal?.attack_alert_row) return 'alert'
  if (signal?.trusted_identity || Number(signal?.trust_score || 0) >= 0.72) return 'confirmed'
  if (signal?.spam_like || signal?.privacy_state === 'randomized' || Number(signal?.trust_score || 0) >= 0.32) return 'suspicious'
  return 'normal'
}

function getBleThreatLabel(signal) {
  if (signal?.attack_alert_row) {
    return signal.attack_product_label || 'Bluetooth attack'
  }

  const decodedEvidence = Number(signal?.ble_decoded_evidence_score || 0)
  const trusted = Boolean(signal?.trusted_identity) || Number(signal?.trust_score || 0) >= 0.72
  const role = signal?.ble_role || signal?.device_role_hint || signal?.protocol || 'BLE'

  if (role === 'ble_advertising_flood') {
    if (signal?.spam_like || trusted || decodedEvidence >= 0.45) {
      return 'BLE advertising flood'
    }
    return 'Unverified BLE advertiser cluster'
  }

  if (signal?.spam_like && !trusted && decodedEvidence < 0.45) {
    return 'Suspicious BLE advertiser'
  }

  return role
}

function getBleThreatDetail(signal) {
  if (signal?.attack_alert_row) {
    return 'defensive alert'
  }

  const decodedEvidence = Number(signal?.ble_decoded_evidence_score || 0)
  if ((signal?.ble_role || signal?.device_role_hint) === 'ble_advertising_flood' && !signal?.spam_like && decodedEvidence < 0.45) {
    return 'rf-only posture, decoder unverified'
  }

  return signal?.spam_like ? 'suspicious advertiser' : (signal?.rf_protocol || signal?.protocol)
}

function getRowClassName(signal, selectedSignal) {
  const classes = []
  if (selectedSignal === signal) classes.push('selected-row')
  if (signal?.attack_alert_row) classes.push('signal-attack-row')
  else if (signal?.spam_like) classes.push('signal-spam-row')
  return classes.join(' ')
}

export default function SignalTable({ signals, selectedSignal, onSelect, onDelete, mode, tab }) {
  const columns = tab === 'BLE'
    ? [
      { key: 'signalId', label: 'Signal ID' },
      { key: 'freq', label: 'Freq' },
      { key: 'threat', label: 'Threat' },
      { key: 'identity', label: 'MAC / Identity' },
      { key: 'lead', label: 'Tool / Vendor' },
      { key: 'evidence', label: 'Evidence' },
      { key: 'status', label: 'Status' },
      { key: 'observed', label: 'Observed' },
      { key: 'actions', label: 'Actions' },
    ]
    : [
      { key: 'signalId', label: 'Signal ID' },
      { key: 'freq', label: 'Freq' },
      { key: 'protocol', label: 'Protocol' },
      { key: 'identity', label: tab === 'BLE' ? 'MAC / Identity' : 'Identity' },
      { key: 'brand', label: 'Brand Lead' },
      { key: 'product', label: 'Product Lead' },
      { key: 'status', label: 'Status' },
      { key: 'observed', label: 'Observed' },
      { key: 'actions', label: 'Actions' },
    ]
  const sortedSignals = [...signals].sort((left, right) => {
    const trustDelta = getTrustRank(left) - getTrustRank(right)
    if (trustDelta !== 0) return trustDelta

    const rightTrustScore = Number(right.trust_score) || 0
    const leftTrustScore = Number(left.trust_score) || 0
    if (rightTrustScore !== leftTrustScore) return rightTrustScore - leftTrustScore

    const rightConfidence = Number(right.confidence) || 0
    const leftConfidence = Number(left.confidence) || 0
    if (rightConfidence !== leftConfidence) return rightConfidence - leftConfidence

    const rightSeen = Number(right.seen_count) || 0
    const leftSeen = Number(left.seen_count) || 0
    if (rightSeen !== leftSeen) return rightSeen - leftSeen

    const rightLastSeen = Number(right.last_seen || right.timestamp) || 0
    const leftLastSeen = Number(left.last_seen || left.timestamp) || 0
    return rightLastSeen - leftLastSeen
  })

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => <th key={column.key}>{column.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {sortedSignals.map((signal, index) => {
            const macTrust = getMacTrust(signal)
            const trustDetail = macTrust?.detail
            const trustScore = Number(signal.trust_score)
            const severity = getSeverity(signal, mode, tab)
            return (
              <tr
                key={`${signal.signal_id || signal.mac_address || signal.freq_mhz || signal.frequency_mhz || 'f'}-${index}`}
                className={`${getRowClassName(signal, selectedSignal)} severity-${severity}`.trim()}
                onClick={() => onSelect(signal)}
              >
                <td>
                  <div className="table-primary">{fmt(signal.signal_id || signal.device_id || '--')}</div>
                  <div className="table-secondary">{fmt(signal.attack_alert_row ? 'synthetic row' : 'inventory reading')}</div>
                </td>
                <td>{freq(signal.freq_mhz || signal.frequency_mhz)}</td>
                {tab === 'BLE' ? (
                  <>
                    <td>
                      <div className="table-primary">{fmt(getBleThreatLabel(signal))}</div>
                      <div className="table-secondary">{fmt(getBleThreatDetail(signal))}</div>
                    </td>
                    <td>
                      <div className="table-primary">{fmt(getMacLead(signal))}</div>
                      {macTrust ? <div className="table-secondary"><Pill text={macTrust.text} tone={macTrust.tone} /></div> : null}
                      <div className="table-secondary">
                        {fmt(
                          Number.isFinite(trustScore) && trustScore > 0
                            ? `${trustDetail || signal.identity_source} | trust ${Math.round(trustScore * 100)}%`
                            : (trustDetail || signal.identity_source),
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="table-primary">{fmt(signal?.attack_alert_row ? (signal.attack_tool_class || '--') : (getBrandLead(signal)))}</div>
                      <div className="table-secondary">{fmt(signal?.attack_alert_row ? signal.attack_vendor_detail : (signal.vendor_confidence || signal.match_confidence || signal.vendor_source))}</div>
                    </td>
                    <td>
                      <div className="table-primary">
                        <Pill text={severity.toUpperCase()} tone={severity === 'alert' ? 'red' : severity === 'confirmed' ? 'green' : severity === 'suspicious' ? 'amber' : 'neutral'} />
                      </div>
                      <div className="table-secondary">{fmt(signal?.attack_alert_row ? signal.attack_product_detail : `${signal.confidence || '--'} · ${signal.rf_band || signal.band || '--'}`)}</div>
                    </td>
                    <td>
                      <div className="table-primary">{fmt(signal?.attack_alert_row ? 'ALERT' : (signal.vendor || 'Unknown'))}</div>
                      <div className="table-secondary">{fmt(signal?.attack_alert_row ? 'attack posture' : (signal.product || signal.device_type || signal.rf_band || '--'))}</div>
                    </td>
                    <td>
                      <div className="table-primary">{formatObservedTime(signal)}</div>
                      <div className="table-secondary">{fmt(signal?.attack_alert_row ? 'attack window' : 'last observed')}</div>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="mini-action"
                          onClick={(event) => {
                            event.stopPropagation()
                            onSelect(signal)
                          }}
                        >
                          Analyze
                        </button>
                        <button
                          className="mini-action danger"
                          disabled={signal?.attack_alert_row || !onDelete}
                          onClick={(event) => {
                            event.stopPropagation()
                            onDelete?.(signal)
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </>
                ) : (
                  <>
                    <td>
                      <div className="table-primary">{fmt(signal.protocol)}</div>
                      {signal.rf_protocol && signal.rf_protocol !== signal.protocol ? <div className="table-secondary">{fmt(signal.rf_protocol)}</div> : null}
                    </td>
                    <td>
                      <div className="table-primary">{fmt(getMacLead(signal))}</div>
                      {macTrust ? <div className="table-secondary"><Pill text={macTrust.text} tone={macTrust.tone} /></div> : null}
                      <div className="table-secondary">
                        {fmt(
                          Number.isFinite(trustScore) && trustScore > 0
                            ? `${trustDetail || signal.identity_source} | trust ${Math.round(trustScore * 100)}%`
                            : (trustDetail || signal.identity_source),
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="table-primary">{fmt(getBrandLead(signal))}</div>
                      <div className="table-secondary">{fmt(signal.vendor_confidence || signal.match_confidence)}</div>
                    </td>
                    <td>
                      <div className="table-primary">{fmt(getProductLead(signal))}</div>
                      <div className="table-secondary">{fmt(signal.lora_lab_profile_candidates?.[0]?.profile_name)}</div>
                    </td>
                    <td>
                      <div className="table-primary">
                        <Pill text={severity.toUpperCase()} tone={severity === 'alert' ? 'red' : severity === 'confirmed' ? 'green' : severity === 'suspicious' ? 'amber' : 'neutral'} />
                      </div>
                      <div className="table-secondary">{fmt(`${signal.confidence || '--'} · ${signal.rf_band || signal.band || '--'}`)}</div>
                    </td>
                    <td>
                      <div className="table-primary">{formatObservedTime(signal)}</div>
                      <div className="table-secondary">last observed</div>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="mini-action"
                          onClick={(event) => {
                            event.stopPropagation()
                            onSelect(signal)
                          }}
                        >
                          Analyze
                        </button>
                        <button
                          className="mini-action danger"
                          disabled={signal?.attack_alert_row || !onDelete}
                          onClick={(event) => {
                            event.stopPropagation()
                            onDelete?.(signal)
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </>
                )}
              </tr>
            )
          })}
          {!signals.length && (
            <tr>
              <td colSpan={columns.length} className="empty-cell">No signals visible yet.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
