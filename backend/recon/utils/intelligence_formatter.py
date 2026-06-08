# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF INTELLIGENCE FORMATTER
# FILE:         backend/recon/utils/intelligence_formatter.py
#
# VERSION:      v2.0.0 (SIGINT INTELLIGENCE FORMATTER)
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# HackRF SDR
#     ↓
# SDRController
#     ↓
# AdaptiveSweepController
#     ↓
# LiveFFT
#     ↓
# ReconEngine
#     ↓
# SignalEngine
#     ↓
# RFIntelligenceFormatter  ← THIS MODULE
#     ↓
# Intel API
#     ↓
# Console / Dashboard
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. INTELLIGENCE ABSTRACTION
# Raw RF telemetry must be converted into operator-readable intelligence.
#
# 2. MINIMAL OUTPUT NOISE
# Internal RF processing metrics must not leak into operator output.
#
# 3. PROTOCOL-AWARE OUTPUT
# Frequencies should be mapped to protocol channels when possible.
#
# 4. RED TEAM RELEVANCE
# Output must highlight attack surfaces and device types.
#
# 5. NON-DESTRUCTIVE
# Formatter must never modify underlying signal intelligence.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • converting RF emitters → intelligence objects
# • mapping frequencies to protocol channels
# • resolving RF bands
# • summarizing devices for operators
#
#
# This module is NOT responsible for:
#
# • signal detection
# • protocol classification
# • RF hardware control
#
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v1.x
#     initial intelligence formatting
#
# v2.x
#     batch formatting
#     band detection
#     extended channel mapping
#
#
# =============================================================================
# ENTERPRISE CODE CONVENTIONS
# =============================================================================
#
# • defensive input validation
# • deterministic formatting
# • stable intelligence schema
#
# =============================================================================


class RFIntelligenceFormatter:

    VERSION = "2.0.0"

    # -------------------------------------------------------------------------
    # PUBLIC API
    # -------------------------------------------------------------------------

    def format_signals(self, signals):

        if not signals:
            return []

        results = []

        for s in signals:

            try:
                results.append(self.format_signal(s))
            except Exception:
                continue

        return results

    # -------------------------------------------------------------------------

    def format_signal(self, signal):

        if not isinstance(signal, dict):
            return {}

        freq = signal.get("freq_mhz")
        protocol = signal.get("rf_protocol")
        vendor = signal.get("vendor")

        category = signal.get("device_category")
        device_type = signal.get("device_type")

        bandwidth = signal.get("bandwidth_mhz")
        confidence = signal.get("confidence", 0)

        band = self._resolve_band(freq)

        channel = self._resolve_channel(freq, protocol)

        attack_surface = self._infer_attack_surface(protocol)

        return {

            "signal_id": signal.get("signal_id"),

            "protocol": protocol,

            "frequency_mhz": freq,
            "rf_band": band,
            "channel": channel,

            "bandwidth_mhz": bandwidth,

            "device_category": category,
            "device_type": device_type,

            "vendor": vendor,

            "confidence": confidence,

            "redteam_surface": attack_surface

        }

    # -------------------------------------------------------------------------
    # BAND RESOLUTION
    # -------------------------------------------------------------------------

    def _resolve_band(self, freq):

        if not freq:
            return None

        if 2400 <= freq <= 2500:
            return "2.4GHz"

        if 5000 <= freq <= 6000:
            return "5GHz"

        if 430 <= freq <= 435:
            return "433MHz"

        if 860 <= freq <= 870:
            return "868MHz"

        return "unknown"

    # -------------------------------------------------------------------------
    # CHANNEL RESOLUTION
    # -------------------------------------------------------------------------

    def _resolve_channel(self, freq, protocol):

        if not freq:
            return None

        # WiFi 2.4 GHz
        if protocol == "WiFi":

            wifi_channels = {
                2412: 1, 2417: 2, 2422: 3, 2427: 4,
                2432: 5, 2437: 6, 2442: 7, 2447: 8,
                2452: 9, 2457: 10, 2462: 11
            }

            for center, ch in wifi_channels.items():

                if abs(freq - center) < 3:
                    return ch

        # BLE Advertising
        if protocol == "BLE":

            if abs(freq - 2402) < 1:
                return "ADV-37"

            if abs(freq - 2426) < 1:
                return "ADV-38"

            if abs(freq - 2480) < 1:
                return "ADV-39"

        # Zigbee
        if protocol == "Zigbee":

            base = 2405
            step = 5

            for ch in range(11, 27):

                center = base + (ch - 11) * step

                if abs(freq - center) < 2:
                    return ch

        return None

    # -------------------------------------------------------------------------
    # RED TEAM SURFACE MAPPING
    # -------------------------------------------------------------------------

    def _infer_attack_surface(self, protocol):

        surfaces = {

            "WiFi": [
                "wifi_deauth",
                "wifi_evil_twin",
                "wifi_handshake_capture",
                "wifi_beacon_spoof"
            ],

            "BLE": [
                "ble_tracking",
                "ble_spoofing",
                "ble_replay",
                "ble_impersonation"
            ],

            "Zigbee": [
                "zigbee_join_attack",
                "zigbee_packet_replay",
                "zigbee_device_spoof"
            ],

            "LoRa": [
                "lora_replay",
                "lora_gateway_impersonation"
            ],

            "OOK Remote": [
                "rf_replay_attack",
                "rf_bruteforce"
            ]

        }

        return surfaces.get(protocol, [])
