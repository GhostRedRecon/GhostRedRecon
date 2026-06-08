import { useEffect, useState } from 'react'

const STORAGE_KEY = 'ghostredrecon:wifi-mk7-features'
const EVENT_NAME = 'ghostredrecon:wifi-mk7-features:changed'

const PUBLIC_V1_LOCKED_FEATURES = new Set(['handshakeAnalysis', 'offlineEvidenceAnalysis'])

const DEFAULTS = {
  handshakeAnalysis: false,
  offlineEvidenceAnalysis: false,
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

export function getResolvedWiFiMk7FeaturePreferences() {
  const stored = readStoredPreferences()
  return {
    handshakeAnalysis: PUBLIC_V1_LOCKED_FEATURES.has('handshakeAnalysis')
      ? false
      : (typeof stored.handshakeAnalysis === 'boolean' ? stored.handshakeAnalysis : DEFAULTS.handshakeAnalysis),
    offlineEvidenceAnalysis: PUBLIC_V1_LOCKED_FEATURES.has('offlineEvidenceAnalysis')
      ? false
      : (typeof stored.offlineEvidenceAnalysis === 'boolean' ? stored.offlineEvidenceAnalysis : DEFAULTS.offlineEvidenceAnalysis),
  }
}

export function setWiFiMk7FeaturePreference(key, value) {
  const current = readStoredPreferences()
  const next = {
    ...current,
    [key]: PUBLIC_V1_LOCKED_FEATURES.has(key) ? false : !!value,
  }
  writeStoredPreferences(next)
  return next
}

export function useWiFiMk7FeaturePreferences() {
  const [features, setFeatures] = useState(() => getResolvedWiFiMk7FeaturePreferences())

  useEffect(() => {
    function handleChange() {
      setFeatures(getResolvedWiFiMk7FeaturePreferences())
    }

    window.addEventListener(EVENT_NAME, handleChange)
    window.addEventListener('storage', handleChange)
    return () => {
      window.removeEventListener(EVENT_NAME, handleChange)
      window.removeEventListener('storage', handleChange)
    }
  }, [])

  return {
    features,
    setFeature: (key, value) => setWiFiMk7FeaturePreference(key, value),
  }
}
