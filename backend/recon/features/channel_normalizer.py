# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF CHANNEL NORMALIZATION ENGINE
# FILE:         backend/recon/features/channel_normalizer.py
#
# VERSION:      v2.0.0
# UPDATED:      2026-03-12
# AUTHOR:       GhostRecon RF Intelligence Layer
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# The RFChannelNormalizer aligns emitter frequencies with known protocol
# channel grids.
#
# RF transmitters operate on standardized channel centers, but SDR detection
# often produces slightly inaccurate frequencies due to:
#
# • FFT bin resolution
# • oscillator drift
# • spectral fragmentation
#
# The normalizer reduces these errors by snapping emitters to known RF
# channel grids.
#
#
# RF PROCESSING PIPELINE
#
# HackRF SDR
#     ↓
# LiveFFT
#     ↓
# PeakDetector
#     ↓
# BurstDetector
#     ↓
# EmitterCluster
#     ↓
# RFEmitterTracker
#     ↓
# RFEmitterLifecycleManager
#     ↓
# RFChannelNormalizer      ← THIS MODULE
#     ↓
# ModulationDetector
#     ↓
# FrameStructureDetector
#     ↓
# FeatureExtractor
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. CHANNEL GRID NORMALIZATION
# -----------------------------------------------------------------------------
# Major RF protocols use fixed channel grids.
#
# WiFi:   2412 + 5n MHz
# Zigbee: 2405 + 5n MHz
# BLE:    2402 / 2426 / 2480 MHz
#
# Normalizing to these grids improves classification accuracy.
#
#
# 2. LOW CPU OVERHEAD
# -----------------------------------------------------------------------------
# This module executes on every emitter and must remain lightweight.
#
#
# 3. TOLERANCE WINDOWS
# -----------------------------------------------------------------------------
# Frequency matching uses tolerance windows to handle SDR jitter.
#
#
# 4. PROTOCOL AGNOSTIC MODE
# -----------------------------------------------------------------------------
# If the protocol is unknown, the normalizer attempts detection across
# multiple channel grids.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • snapping emitters to known channel centers
# • identifying WiFi channel numbers
# • identifying BLE advertising channels
# • identifying Zigbee channels
# • detecting common sub-GHz bands
#
#
# This module is NOT responsible for:
#
# • protocol classification
# • device inference
# • behavioral analysis
#
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v1.x
#     initial grid normalization
#
# v2.x
#     configuration integration
#     sub-GHz detection
#     confidence scoring
#
#
# =============================================================================
# ENTERPRISE CODE CONVENTIONS
# =============================================================================
#
# • deterministic channel mapping
# • configuration-driven tolerances
# • minimal CPU cost
# • stable output schema
#
# =============================================================================

from recon.configuration import ReconConfig


class RFChannelNormalizer:

    VERSION = "2.0.0"

    WIFI_CHANNELS = {
        1: 2412,
        2: 2417,
        3: 2422,
        4: 2427,
        5: 2432,
        6: 2437,
        7: 2442,
        8: 2447,
        9: 2452,
        10: 2457,
        11: 2462
    }

    ZIGBEE_CHANNELS = {
        ch: 2405 + (ch - 11) * 5
        for ch in range(11, 27)
    }

    BLE_CHANNELS = {
        37: 2402,
        38: 2426,
        39: 2480
    }

    # -------------------------------------------------------------------------

    def normalize(self, freq_mhz, rf_features):

        protocol = rf_features.get("rf_protocol")

        # ---------------------------------------------------------
        # Protocol-guided normalization
        # ---------------------------------------------------------

        if protocol == "wifi":
            return self._normalize_wifi(freq_mhz)

        if protocol == "zigbee":
            return self._normalize_zigbee(freq_mhz)

        if protocol == "ble":
            return self._normalize_ble(freq_mhz)

        # ---------------------------------------------------------
        # Fallback normalization
        # ---------------------------------------------------------

        result = self._normalize_wifi(freq_mhz)

        if result:
            return result

        result = self._normalize_zigbee(freq_mhz)

        if result:
            return result

        result = self._normalize_ble(freq_mhz)

        if result:
            return result

        result = self._detect_subghz(freq_mhz)

        if result:
            return result

        return None

    # -------------------------------------------------------------------------

    def _normalize_wifi(self, freq_mhz):

        best = None
        best_dist = None

        for ch, center in self.WIFI_CHANNELS.items():

            dist = abs(freq_mhz - center)

            if dist <= ReconConfig.WIFI_TOLERANCE:

                if best_dist is None or dist < best_dist:

                    best = (ch, center, dist)
                    best_dist = dist

        if best:

            ch, center, dist = best

            confidence = max(0.5, 1 - dist / ReconConfig.WIFI_TOLERANCE)

            return {

                "rf_channel_type": "wifi",
                "wifi_channel": ch,
                "rf_channel_center_mhz": center,
                "channel_confidence": round(confidence, 3)

            }

        return None

    # -------------------------------------------------------------------------

    def _normalize_zigbee(self, freq_mhz):

        best = None
        best_dist = None

        for ch, center in self.ZIGBEE_CHANNELS.items():

            dist = abs(freq_mhz - center)

            if dist <= ReconConfig.ZIGBEE_TOLERANCE:

                if best_dist is None or dist < best_dist:

                    best = (ch, center, dist)
                    best_dist = dist

        if best:

            ch, center, dist = best

            confidence = max(0.5, 1 - dist / ReconConfig.ZIGBEE_TOLERANCE)

            return {

                "rf_channel_type": "zigbee",
                "zigbee_channel": ch,
                "rf_channel_center_mhz": center,
                "channel_confidence": round(confidence, 3)

            }

        return None

    # -------------------------------------------------------------------------

    def _normalize_ble(self, freq_mhz):

        best = None
        best_dist = None

        for ch, center in self.BLE_CHANNELS.items():

            dist = abs(freq_mhz - center)

            if dist <= ReconConfig.BLE_TOLERANCE:

                if best_dist is None or dist < best_dist:

                    best = (ch, center, dist)
                    best_dist = dist

        if best:

            ch, center, dist = best

            confidence = max(0.5, 1 - dist / ReconConfig.BLE_TOLERANCE)

            return {

                "rf_channel_type": "ble",
                "ble_channel": ch,
                "rf_channel_center_mhz": center,
                "channel_confidence": round(confidence, 3)

            }

        return None

    # -------------------------------------------------------------------------

    def _detect_subghz(self, freq_mhz):

        if 430 <= freq_mhz <= 435:

            return {
                "rf_channel_type": "subghz",
                "rf_band": "433MHz",
                "rf_channel_center_mhz": 433.92
            }

        if 860 <= freq_mhz <= 870:

            return {
                "rf_channel_type": "subghz",
                "rf_band": "868MHz"
            }

        if 902 <= freq_mhz <= 928:

            return {
                "rf_channel_type": "subghz",
                "rf_band": "915MHz"
            }

        return None
