# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/rf_normalizer.py
# VERSION:      v1.0.0 (PRODUCTION - PROTOCOL-AWARE RF NORMALIZER)
# UPDATED:      2026-03-24
# =============================================================================

"""
# 🧠 ARCHITECTURE OVERVIEW

Device (fusion/intelligence output)
        ↓
RF Normalizer (THIS FILE)
        ↓
Normalized RF Signature
        ↓
RF Matcher (YAML intelligence)
        ↓
Intel API exposure

This module converts noisy RF observations into stable,
protocol-aware representations for matching.

# 🎯 PURPOSE

- Normalize raw RF frequency distributions
- Handle protocol-specific RF behavior (BLE, WiFi, Zigbee, LoRa)
- Provide stable features for matching engine

# 🧩 RESPONSIBILITIES

- Compute center frequency (protocol-aware)
- Compute spread, min/max
- Infer RF band
- Provide normalized RF structure

# ⚙️ DESIGN PRINCIPLES

- NON-DESTRUCTIVE → does not modify original device
- PROTOCOL-AWARE → adapts per RF protocol
- LIGHTWEIGHT → fast, no heavy computation
- SAFE → handles malformed data gracefully

# 📦 OUTPUT SCHEMA

{
    "center_freq": float,
    "min_freq": float,
    "max_freq": float,
    "spread": float,
    "protocols": list,
    "band": str
}

# 📜 CHANGELOG

v1.0.0
- Initial implementation
- Protocol-aware normalization (BLE, WiFi, Zigbee, default)
- Band inference
"""

from typing import Dict, Any, List


# =============================================================================
# MAIN NORMALIZER
# =============================================================================
def normalize_rf(device: Dict[str, Any]) -> Dict[str, Any] | None:

    freqs = device.get("frequencies") or []
    protocols = device.get("protocols") or []

    if not isinstance(freqs, list) or not freqs:
        return None

    # Filter valid frequencies
    freqs = sorted([f for f in freqs if isinstance(f, (int, float))])

    if not freqs:
        return None

    # -------------------------------------------------------------------------
    # PROTOCOL-AWARE CENTER FREQUENCY
    # -------------------------------------------------------------------------
    if "BLE" in protocols:
        center = _median(freqs)

    elif "WIFI" in protocols:
        center = (freqs[0] + freqs[-1]) / 2

    elif "ZIGBEE" in protocols:
        center = _snap_zigbee_channel(freqs)

    else:
        # LoRa / Sub-GHz / Unknown
        center = sum(freqs) / len(freqs)

    fmin = freqs[0]
    fmax = freqs[-1]

    return {
        "center_freq": round(center, 2),
        "min_freq": fmin,
        "max_freq": fmax,
        "spread": round(fmax - fmin, 2),
        "protocols": protocols,
        "band": _infer_band(center),
    }


# =============================================================================
# HELPERS
# =============================================================================
def _median(values: List[float]) -> float:
    n = len(values)
    mid = n // 2
    if n % 2 == 0:
        return (values[mid - 1] + values[mid]) / 2
    return values[mid]


def _infer_band(freq: float) -> str:
    if freq < 1000:
        return "subGHz"
    elif 2000 <= freq <= 2500:
        return "2.4GHz"
    return "unknown"


def _snap_zigbee_channel(freqs: List[float]) -> float:
    zigbee_channels = [
        2405, 2410, 2415, 2420, 2425, 2430,
        2435, 2440, 2445, 2450, 2455, 2460,
        2465, 2470, 2475
    ]

    avg = sum(freqs) / len(freqs)

    return min(zigbee_channels, key=lambda ch: abs(ch - avg))
