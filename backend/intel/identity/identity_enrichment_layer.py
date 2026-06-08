# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/identity_enrichment_layer.py
# VERSION:      v3.0.0 (SIGINT HARDWARE IDENTITY ENGINE - STABLE)
# UPDATED:      2026-03-24
# =============================================================================

from __future__ import annotations

import hashlib
from typing import Dict, List, Any


class IdentityEnrichmentLayer:
    """
    SIGINT Identity Enrichment Layer (v3)

    PURPOSE:
    --------
    Extracts hardware-level identity from RF signals.

    DESIGN:
    -------
    - Stateless processing (safe for pipeline)
    - Deterministic fingerprint generation
    - Protocol-aware enrichment
    - Supports both single-frequency + multi-frequency signals

    OUTPUT:
    -------
    Adds:
        hardware_id
        hardware_confidence
        identity_source
    """

    VERSION = "3.0.0"

    # =========================================================================
    # ENTRYPOINT
    # =========================================================================
    def process(self, signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        if not isinstance(signals, list):
            return []

        enriched = []

        for sig in signals:

            if not isinstance(sig, dict):
                continue

            try:
                sig = self._process_signal(sig)
            except Exception:
                pass

            enriched.append(sig)

        return enriched

    # =========================================================================
    # SIGNAL ROUTER
    # =========================================================================
    def _process_signal(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        protocol = str(sig.get("protocol", "")).upper()

        if protocol == "LORA":
            return self._process_lora(sig)

        if protocol == "BLE":
            return self._process_ble(sig)

        if protocol == "WIFI":
            return self._process_wifi(sig)

        return sig

    # =========================================================================
    # 🔥 LORA HARDWARE FINGERPRINTING (CORE ENGINE)
    # =========================================================================
    def _process_lora(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        # ---------------------------------------------------------
        # SUPPORT BOTH INPUT FORMATS
        # ---------------------------------------------------------
        if "frequencies" in sig:
            freqs = sig.get("frequencies") or []
        else:
            f = sig.get("frequency_mhz")
            freqs = [f] if f else []

        if not freqs:
            return sig

        # ---------------------------------------------------------
        # NORMALIZATION
        # ---------------------------------------------------------
        rounded = sorted(set(round(f, 1) for f in freqs if f))

        if not rounded:
            return sig

        # ---------------------------------------------------------
        # FEATURE EXTRACTION
        # ---------------------------------------------------------
        freq_min = min(rounded)
        freq_max = max(rounded)
        spread = round(freq_max - freq_min, 2)
        diversity = len(rounded)

        center_freq = round((freq_min + freq_max) / 2, 1)

        # ---------------------------------------------------------
        # SIGNATURE (STABLE)
        # ---------------------------------------------------------
        signature = f"LORA|{center_freq}|{spread}|{diversity}"

        hardware_id = self._hash(signature)

        # ---------------------------------------------------------
        # CONFIDENCE MODEL (IMPROVED)
        # ---------------------------------------------------------
        base = 0.35
        diversity_score = min(0.4, diversity * 0.04)
        spread_score = min(0.25, spread * 0.03)

        confidence = min(1.0, base + diversity_score + spread_score)

        # ---------------------------------------------------------
        # ATTACH
        # ---------------------------------------------------------
        sig["hardware_id"] = f"HW-{hardware_id}"
        sig["hardware_confidence"] = round(confidence, 3)
        sig["identity_source"] = "lora_rf_fingerprint_v3"

        return sig

    # =========================================================================
    # BLE (READY FOR MAC/OUI EXTENSION)
    # =========================================================================
    def _process_ble(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        freq = sig.get("frequency_mhz")
        power = sig.get("avg_power_dbm", -50)

        key = f"BLE|{round(freq or 0,1)}|{round(power,1)}"

        sig["hardware_id"] = f"HW-{self._hash(key)}"
        sig["hardware_confidence"] = 0.35
        sig["identity_source"] = "ble_pattern_v1"

        return sig

    # =========================================================================
    # WIFI (PLACEHOLDER BUT FIXED)
    # =========================================================================
    def _process_wifi(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        freq = sig.get("frequency_mhz")
        bandwidth = sig.get("bandwidth", 20)

        key = f"WIFI|{round(freq or 0,1)}|{bandwidth}"

        sig["hardware_id"] = f"HW-{self._hash(key)}"
        sig["hardware_confidence"] = 0.35
        sig["identity_source"] = "wifi_pattern_v1"

        return sig

    # =========================================================================
    # HASH
    # =========================================================================
    def _hash(self, text: str) -> str:
        return hashlib.sha1(text.encode()).hexdigest()[:12]
