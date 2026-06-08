# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/identity_enrichment_layer.py
# VERSION:      v3.1.0 (SIGINT IDENTITY ENRICHMENT + BLE PARSER)
# UPDATED:      2026-03-24
# =============================================================================

from __future__ import annotations

import hashlib
from typing import Dict, List, Any

# 🔥 NEW: BLE PARSER
try:
    from backend.intel.identity.ble_advertisement_parser import BLEAdvertisementParser
except Exception:
    BLEAdvertisementParser = None


class IdentityEnrichmentLayer:
    """
    SIGINT Identity Enrichment Layer (v3.1)

    PURPOSE:
    --------
    Extracts hardware-level identity + BLE identity signals from RF data.

    DESIGN:
    -------
    - Stateless processing
    - Deterministic fingerprinting
    - Protocol-aware enrichment
    - BLE identity extraction (NEW)
    - Safe fallback if metadata missing

    PIPELINE ORDER (CRITICAL):
    -------------------------
    1. BLE parsing (extract MAC / vendor hints)
    2. Hardware fingerprinting (LoRa / WiFi / BLE patterns)

    OUTPUT:
    -------
    Adds:
        hardware_id
        hardware_confidence
        identity_source
        mac_address (if available)
        device_name (if available)
        manufacturer_data (if available)
    """

    VERSION = "3.1.0"

    # =========================================================================
    # INIT
    # =========================================================================
    def __init__(self):

        # 🔥 BLE parser (optional safe load)
        self.ble_parser = BLEAdvertisementParser() if BLEAdvertisementParser else None

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
                # ---------------------------------------------------------
                # 🔥 STEP 1: BLE PARSING (NEW - MUST COME FIRST)
                # ---------------------------------------------------------
                if self.ble_parser:
                    sig = self.ble_parser.process(sig)

                # ---------------------------------------------------------
                # STEP 2: PROTOCOL-SPECIFIC HARDWARE ENRICHMENT
                # ---------------------------------------------------------
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

        if "frequencies" in sig:
            freqs = sig.get("frequencies") or []
        else:
            f = sig.get("frequency_mhz")
            freqs = [f] if f else []

        if not freqs:
            return sig

        rounded = sorted(set(round(f, 1) for f in freqs if f))

        if not rounded:
            return sig

        freq_min = min(rounded)
        freq_max = max(rounded)
        spread = round(freq_max - freq_min, 2)
        diversity = len(rounded)
        center_freq = round((freq_min + freq_max) / 2, 1)

        signature = f"LORA|{center_freq}|{spread}|{diversity}"
        hardware_id = self._hash(signature)

        base = 0.35
        diversity_score = min(0.4, diversity * 0.04)
        spread_score = min(0.25, spread * 0.03)

        confidence = min(1.0, base + diversity_score + spread_score)

        sig["hardware_id"] = f"HW-{hardware_id}"
        sig["hardware_confidence"] = round(confidence, 3)
        sig["identity_source"] = "lora_rf_fingerprint_v3"

        return sig

    # =========================================================================
    # BLE HARDWARE PATTERN (ENHANCED)
    # =========================================================================
    def _process_ble(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        freq = sig.get("frequency_mhz")
        power = sig.get("avg_power_dbm", -50)

        mac = sig.get("mac_address")

        # Prefer MAC-based identity if available
        if mac:
            key = f"BLE|{mac}"
            confidence = 0.7  # strong identity anchor
            source = "ble_mac_identity"
        else:
            key = f"BLE|{round(freq or 0,1)}|{round(power,1)}"
            confidence = 0.35
            source = "ble_pattern_v1"

        sig["hardware_id"] = f"HW-{self._hash(key)}"
        sig["hardware_confidence"] = confidence
        sig["identity_source"] = source

        return sig

    # =========================================================================
    # WIFI HARDWARE PATTERN
    # =========================================================================
    def _process_wifi(self, sig: Dict[str, Any]) -> Dict[str, Any]:

        freq = sig.get("frequency_mhz")
        bandwidth = sig.get("bandwidth", 20)

        mac = sig.get("mac_address")

        if mac:
            key = f"WIFI|{mac}"
            confidence = 0.7
            source = "wifi_mac_identity"
        else:
            key = f"WIFI|{round(freq or 0,1)}|{bandwidth}"
            confidence = 0.35
            source = "wifi_pattern_v1"

        sig["hardware_id"] = f"HW-{self._hash(key)}"
        sig["hardware_confidence"] = confidence
        sig["identity_source"] = source

        return sig

    # =========================================================================
    # HASH
    # =========================================================================
    def _hash(self, text: str) -> str:
        return hashlib.sha1(text.encode()).hexdigest()[:12]
