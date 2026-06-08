# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       BLE IDENTITY ENGINE
# FILE:         backend/intel/identity/ble_identity_engine.py
# VERSION:      v1.0.0 (MAC EXTRACTION + FINGERPRINT BASE)
# UPDATED:      2026-03-23
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
# SignalEngine
#     ↓
# BLEIdentityEngine (THIS FILE)
#     ├── BLE signal filtering
#     ├── MAC extraction (when possible)
#     ├── Pseudo-ID fallback (RSSI + freq fingerprint)
#     ├── Vendor inference (OUI-ready)
#     └── Identity output → DeviceFusion
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Extract BLE device identity from RF signals
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# ✔ Detect BLE-like signals
# ✔ Extract MAC address (if available)
# ✔ Generate stable fallback IDs
# ✔ Build fingerprint
# ✔ Infer vendor (future-ready)
# ✔ Output identity objects
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. MAC IS NOT ALWAYS AVAILABLE (BLE RANDOMIZATION)
# 2. FALLBACK ID MUST BE STABLE
# 3. NO HARD DEPENDENCY ON FULL DECODING
# 4. IDENTITY MUST BE LIGHTWEIGHT + FAST
#
# =============================================================================
# 📦 IDENTITY OUTPUT SCHEMA
# =============================================================================
#
# {
#     device_id: str
#     mac: str (optional)
#     vendor: str (optional)
#     identity_confidence: float
#     fingerprint: dict
# }
#
# =============================================================================

from __future__ import annotations

import hashlib
from typing import Dict, Any, List


class BLEIdentityEngine:

    VERSION = "1.0.0"

    def __init__(self):
        pass

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================
    def process(self, signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        identities = []

        for sig in signals:

            if not self._is_ble_signal(sig):
                continue

            identity = self._extract_identity(sig)

            if identity:
                identities.append(identity)

        return identities

    # =========================================================================
    # BLE DETECTION
    # =========================================================================
    def _is_ble_signal(self, sig: Dict[str, Any]) -> bool:

        freq = sig.get("frequency_mhz")
        proto = sig.get("protocol")

        # Protocol hint
        if proto == "BLE":
            return True

        # Frequency fallback (BLE band)
        try:
            if freq and 2400 <= float(freq) <= 2485:
                return True
        except Exception:
            pass

        return False

    # =========================================================================
    # IDENTITY EXTRACTION
    # =========================================================================
    def _extract_identity(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        # ---------------------------------------------------------------------
        # Attempt MAC extraction (if raw payload exists)
        # ---------------------------------------------------------------------
        mac = self._extract_mac(sig)

        if mac:
            device_id = mac
            confidence = 0.9
        else:
            device_id = self._generate_pseudo_id(sig)
            confidence = 0.4

        fingerprint = self._build_fingerprint(sig)

        return {
            "device_id": device_id,
            "mac": mac,
            "vendor": None,  # filled later
            "identity_confidence": confidence,
            "fingerprint": fingerprint,
        }

    # =========================================================================
    # MAC EXTRACTION (BASIC)
    # =========================================================================
    def _extract_mac(self, sig: Dict[str, Any]):

        # Placeholder: depends on demod layer
        payload = sig.get("raw_bytes") or sig.get("payload")

        if not payload:
            return None

        try:
            # VERY BASIC heuristic (6-byte address)
            if isinstance(payload, (bytes, bytearray)) and len(payload) >= 6:
                mac_bytes = payload[:6]
                mac = ":".join(f"{b:02X}" for b in mac_bytes)
                return mac
        except Exception:
            pass

        return None

    # =========================================================================
    # FALLBACK ID (CRITICAL)
    # =========================================================================
    def _generate_pseudo_id(self, sig: Dict[str, Any]) -> str:

        freq = sig.get("frequency_mhz", 0)
        power = sig.get("power_db", 0)

        base = f"{round(freq,1)}|{round(power,1)}"

        return "BLE-" + hashlib.md5(base.encode()).hexdigest()[:8]

    # =========================================================================
    # FINGERPRINT
    # =========================================================================
    def _build_fingerprint(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        return {
            "frequency": round(sig.get("frequency_mhz", 0), 1),
            "power": round(sig.get("power_db", 0), 1),
            "protocol": sig.get("protocol"),
        }
