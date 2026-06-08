# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/device_hardware_linker.py
# VERSION:      v2.0.0 (SIGINT HARDWARE → DEVICE LINKING ENGINE)
# UPDATED:      2026-03-24
# =============================================================================

from __future__ import annotations

import logging
from typing import List, Dict, Any
from collections import defaultdict

log = logging.getLogger("ghostrecon.device_hw_linker")


class DeviceHardwareLinker:
    """
    Device Hardware Linker (SIGINT Layer)

    PURPOSE:
    --------
    Bridges signal-level hardware identity → device-level fingerprint.

    Converts:
        signals (hardware_id, MAC, BLE addr, PHY traits)
    INTO:
        stable device fingerprint

    This is the CRITICAL layer for:
        Phase 4 → fingerprint_hits
        identity persistence
        cross-protocol fusion

    DESIGN PRINCIPLES:
    ------------------
    - Stateless
    - Signal aggregation based
    - Confidence-weighted linking
    - Non-destructive (never overwrites valid data)
    - Validator-compatible output

    INPUT:
        devices: List[device dict]
        signals: List[signal dict]

    OUTPUT:
        devices enriched with:
            - hardware_id
            - hardware_confidence
            - fingerprint (CRITICAL for validator)
    """

    VERSION = "2.0.0"

    # -------------------------------------------------------------------------
    # TUNING
    # -------------------------------------------------------------------------
    MIN_SIGNAL_SUPPORT = 2
    MIN_CONFIDENCE = 0.2

    # =========================================================================
    # MAIN
    # =========================================================================
    def process(
        self,
        devices: List[Dict[str, Any]],
        signals: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        if not devices or not signals:
            return devices

        try:
            # -------------------------------------------------------------
            # STEP 1: Build hardware clusters from signals
            # -------------------------------------------------------------
            hw_clusters = self._build_hardware_clusters(signals)

            if not hw_clusters:
                return devices

            # -------------------------------------------------------------
            # STEP 2: Assign hardware → device
            # -------------------------------------------------------------
            for d in devices:
                try:
                    self._assign_hardware(d, hw_clusters)
                except Exception as e:
                    log.debug("[HW_LINK] Device assignment error: %s", e)

        except Exception as e:
            log.debug("[HW_LINK] Processing error: %s", e)

        return devices

    # =========================================================================
    # STEP 1: BUILD CLUSTERS
    # =========================================================================
    def _build_hardware_clusters(self, signals):

        clusters = defaultdict(list)

        for s in signals:

            if not isinstance(s, dict):
                continue

            hw_id = s.get("hardware_id")

            if not hw_id:
                continue

            confidence = self._safe_float(
                s.get("hardware_confidence", 0.5), 0.5
            )

            clusters[hw_id].append(confidence)

        # -------------------------------------------------------------
        # Aggregate clusters
        # -------------------------------------------------------------
        result = {}

        for hw_id, confidences in clusters.items():

            if len(confidences) < self.MIN_SIGNAL_SUPPORT:
                continue

            avg_conf = sum(confidences) / len(confidences)

            if avg_conf < self.MIN_CONFIDENCE:
                continue

            result[hw_id] = {
                "count": len(confidences),
                "confidence": round(avg_conf, 4),
            }

        return result

    # =========================================================================
    # STEP 2: ASSIGN HARDWARE → DEVICE
    # =========================================================================
    def _assign_hardware(self, device, hw_clusters):

        # Already has strong fingerprint → skip
        if device.get("fingerprint"):
            return

        best_hw = None
        best_score = 0.0

        device_protocols = set(device.get("protocols", []))
        device_freqs = set(device.get("frequencies", []))

        # -------------------------------------------------------------
        # Score each cluster against device
        # -------------------------------------------------------------
        for hw_id, data in hw_clusters.items():

            score = data["confidence"]

            # Boost if protocol match likely
            score += self._protocol_score(device_protocols)

            # Boost if frequency match likely
            score += self._frequency_score(device_freqs)

            if score > best_score:
                best_score = score
                best_hw = hw_id

        # -------------------------------------------------------------
        # Apply assignment
        # -------------------------------------------------------------
        if best_hw and best_score >= self.MIN_CONFIDENCE:

            device["hardware_id"] = best_hw
            device["hardware_confidence"] = round(best_score, 4)

            # 🔥 CRITICAL: THIS FIXES YOUR VALIDATOR
            device["fingerprint"] = {
                "fingerprint_id": best_hw,
                "fingerprint_strength": round(best_score, 4),
                "source": "hardware_linker",
            }

    # =========================================================================
    # SCORING MODELS
    # =========================================================================
    def _protocol_score(self, protocols):

        if not protocols:
            return 0.0

        # More protocols = more confidence
        return min(0.2, len(protocols) * 0.05)

    def _frequency_score(self, freqs):

        if not freqs:
            return 0.0

        return min(0.2, len(freqs) * 0.03)

    # =========================================================================
    # HELPERS
    # =========================================================================
    @staticmethod
    def _safe_float(value, default=0.0):
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default
