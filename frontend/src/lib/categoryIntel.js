import { fmt } from './runtime'

export function summarizeCommon(signals) {
  const vendors = new Set()
  const protocols = new Set()
  let highestConfidence = 0
  let averageConfidence = 0

  signals.forEach((signal) => {
    if (signal.protocol) protocols.add(signal.protocol)
    if (signal.vendor || signal.rf_vendor_candidate) vendors.add(signal.vendor || signal.rf_vendor_candidate)
    highestConfidence = Math.max(highestConfidence, Number(signal.confidence) || 0)
    averageConfidence += Number(signal.confidence) || 0
  })

  return {
    count: signals.length,
    protocols: protocols.size,
    vendors: vendors.size,
    highestConfidence: highestConfidence ? highestConfidence.toFixed(3) : '--',
    averageConfidence: signals.length ? (averageConfidence / signals.length).toFixed(3) : '--',
  }
}

export function countBy(signals, mapper, limit = 6) {
  const counts = new Map()
  signals.forEach((signal) => {
    const key = mapper(signal)
    if (!key) return
    counts.set(key, (counts.get(key) || 0) + 1)
  })
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([label, count]) => ({ label, count }))
}

export function getPrioritySignals(signals, limit = 8) {
  return [...signals]
    .sort((a, b) => (Number(b.confidence) || 0) - (Number(a.confidence) || 0))
    .slice(0, limit)
}

export function matchDevicesForSignals(signals, devices, limit = 10) {
  if (!signals.length || !devices.length) return []
  const vendors = new Set(
    signals
      .map((signal) => (signal.vendor || signal.rf_vendor_candidate || '').toLowerCase())
      .filter(Boolean),
  )

  const matched = devices.filter((device) => {
    const haystack = JSON.stringify(device).toLowerCase()
    return [...vendors].some((vendor) => haystack.includes(vendor))
  })

  return matched.slice(0, limit)
}

export function metricDetailSignal(signal) {
  return `${fmt(signal.protocol)} / ${fmt(signal.device || signal.device_class)}`
}
