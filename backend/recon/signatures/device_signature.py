# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/recon/rf_device_signature_engine.py
#
# VERSION:      v3.0.0 (RF DEVICE INTELLIGENCE ENGINE)
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# RFDeviceSignatureEngine infers device classes from RF intelligence features.
#
# The engine transforms RF signal observations into device intelligence
# useful for red-team reconnaissance.
#
#
# RF INTELLIGENCE PIPELINE
#
# RFProtocolFingerprintEngine
#        ↓
# RFPacketTimingFingerprintEngine
#        ↓
# RFDeviceSignatureEngine   ← THIS MODULE
#        ↓
# RFDeviceFusionEngine
#        ↓
# RFEmitterIdentityEngine
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. MULTI-FEATURE RF INFERENCE
# Device classification uses protocol, modulation, timing, and behavior.
#
# 2. PASSIVE RF INTELLIGENCE
# Device inference relies purely on RF observation.
#
# 3. RED-TEAM FOCUS
# Device categories prioritize attack-relevant targets.
#
# 4. LIGHTWEIGHT CLASSIFICATION
# Heuristics must be efficient for real-time scanning.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# RFDeviceSignatureEngine IS responsible for:
#
# • device class inference
# • behavioral device identification
# • RF feature fusion
# • red-team attack surface hints
#
#
# RFDeviceSignatureEngine is NOT responsible for:
#
# • vendor identification
# • packet decoding
# • SDR control
#
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v2.x
#     basic device classification
#
# v3.x
#     multi-feature fusion
#     expanded device classes
#     attack surface mapping
#
# =============================================================================

from typing import Optional, Dict, Any


class RFDeviceSignatureEngine:

    VERSION = "3.0.0"

    # ---------------------------------------------------------------------
    # PUBLIC API
    # ---------------------------------------------------------------------

    def infer(self, freq_mhz: float, rf_features: Dict[str, Any]) -> Optional[Dict[str, Any]]:

        if not rf_features:
            return None

        protocol = rf_features.get("rf_protocol")
        modulation = rf_features.get("modulation_guess")
        bandwidth = rf_features.get("bandwidth_mhz")

        interval = rf_features.get("rf_interval_mean")
        periodicity = rf_features.get("rf_periodicity_score")

        behavior = rf_features.get("rf_behavior_pattern")

        # -------------------------------------------------------------
        # WIFI DEVICES
        # -------------------------------------------------------------

        if protocol == "WiFi":

            if periodicity and periodicity > 0.85:

                return self._result(
                    "WiFi Access Point",
                    0.9,
                    ["wifi_deauth", "wifi_evil_twin", "wifi_handshake_capture"]
                )

            if bandwidth and bandwidth > 15:

                return self._result(
                    "WiFi IoT Device",
                    0.75,
                    ["wifi_sniff", "wifi_device_tracking"]
                )

            return self._result(
                "WiFi Client Device",
                0.7,
                ["wifi_tracking"]
            )

        # -------------------------------------------------------------
        # BLE DEVICES
        # -------------------------------------------------------------

        if protocol == "BLE":

            if interval and 0.1 <= interval <= 1.2:

                return self._result(
                    "BLE Beacon / Tracker",
                    0.85,
                    ["ble_tracking", "ble_spoof"]
                )

            if behavior == "burst":

                return self._result(
                    "BLE Wearable Device",
                    0.75,
                    ["ble_tracking"]
                )

            return self._result(
                "BLE Peripheral Device",
                0.7,
                ["ble_scan"]
            )

        # -------------------------------------------------------------
        # ZIGBEE DEVICES
        # -------------------------------------------------------------

        if protocol == "Zigbee":

            if interval and interval > 5:

                return self._result(
                    "Zigbee Sensor",
                    0.85,
                    ["zigbee_sniff", "zigbee_key_extract"]
                )

            return self._result(
                "Zigbee Smart Device",
                0.75,
                ["zigbee_sniff"]
            )

        # -------------------------------------------------------------
        # LORA DEVICES
        # -------------------------------------------------------------

        if protocol == "LoRa":

            return self._result(
                "LoRaWAN Node",
                0.9,
                ["lora_replay", "lora_jamming"]
            )

        # -------------------------------------------------------------
        # SUB-GHZ DEVICES
        # -------------------------------------------------------------

        if 430 <= freq_mhz <= 435:

            if modulation == "OOK":

                if behavior == "burst":

                    return self._result(
                        "Garage Remote / Key Fob",
                        0.85,
                        ["rf_replay", "signal_spoof"]
                    )

                return self._result(
                    "SubGHz Remote",
                    0.75,
                    ["rf_replay"]
                )

            if modulation == "FSK_like":

                if interval and interval > 10:

                    return self._result(
                        "Weather Station / Sensor",
                        0.75,
                        ["rf_sniff"]
                    )

        # -------------------------------------------------------------
        # INDUSTRIAL / SMART METER
        # -------------------------------------------------------------

        if 860 <= freq_mhz <= 870:

            if modulation == "FSK_like":

                return self._result(
                    "Smart Meter / Industrial Sensor",
                    0.8,
                    ["rf_sniff"]
                )

        return None

    # ---------------------------------------------------------------------
    # RESULT BUILDER
    # ---------------------------------------------------------------------

    def _result(self, device_class: str, confidence: float, attack_surface):

        return {

            "rf_device_class": device_class,

            "rf_device_confidence": round(confidence, 2),

            "rf_attack_surface": attack_surface

        }
