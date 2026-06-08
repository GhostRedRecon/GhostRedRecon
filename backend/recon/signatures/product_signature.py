# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/recon/rf_product_signature_engine.py
#
# VERSION:      v2.0.0 (RF PRODUCT INTELLIGENCE ENGINE)
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# RFProductSignatureEngine attempts to identify specific commercial
# RF devices using passive RF signal intelligence.
#
# The engine compares RF signal observations against a database
# of known product RF signatures.
#
#
# RF INTELLIGENCE PIPELINE
#
# RFProtocolFingerprintEngine
#        ↓
# RFPacketTimingFingerprintEngine
#        ↓
# RFDeviceSignatureEngine
#        ↓
# RFDeviceFusionEngine
#        ↓
# RFProductSignatureEngine  ← THIS MODULE
#        ↓
# SignalEngine
#        ↓
# Intel API
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. PASSIVE IDENTIFICATION
# Product identification works without packet decoding.
#
# 2. MULTI-FEATURE MATCHING
# Matching uses protocol, band, device class, modulation,
# and timing characteristics.
#
# 3. CONFIDENCE SCORING
# Identification produces probabilistic confidence scores.
#
# 4. EXTENSIBLE SIGNATURE DATABASE
# Product signatures can be expanded easily.
#
# 5. RED-TEAM RELEVANCE
# Focus on attack-relevant devices.
#
# =============================================================================

from typing import Optional, Dict, Any


class RFProductSignatureEngine:

    VERSION = "2.0.0"

    # ---------------------------------------------------------------------
    # PRODUCT SIGNATURE DATABASE
    # ---------------------------------------------------------------------

    PRODUCT_SIGNATURES = [

        {
            "product": "Apple AirTag",
            "protocol": "BLE",
            "device_class": "BLE Beacon / Tracker",
            "band": 2.4,
            "interval": 2.0
        },

        {
            "product": "Xiaomi Aqara Motion Sensor",
            "protocol": "Zigbee",
            "device_class": "Zigbee Sensor",
            "band": 2.4,
            "interval": 5.0
        },

        {
            "product": "Tuya Zigbee Smart Plug",
            "protocol": "Zigbee",
            "device_class": "Zigbee Smart Device",
            "band": 2.4,
            "interval": 10.0
        },

        {
            "product": "Philips Hue Bulb",
            "protocol": "Zigbee",
            "device_class": "Zigbee Smart Device",
            "band": 2.4,
            "interval": 7.0
        },

        {
            "product": "DJI Drone Telemetry",
            "protocol": "WiFi",
            "device_class": "WiFi IoT Device",
            "band": 2.4,
            "interval": 0.1
        },

        {
            "product": "Garage Door Remote",
            "protocol": "SubGHz",
            "device_class": "Garage Remote / Key Fob",
            "band": 433,
            "interval": 0.5
        },

        {
            "product": "LoRa Sensor Node",
            "protocol": "LoRa",
            "device_class": "LoRaWAN Node",
            "band": 868,
            "interval": 60
        }

    ]

    # ---------------------------------------------------------------------
    # PUBLIC API
    # ---------------------------------------------------------------------

    def identify(self, rf_features: Dict[str, Any]) -> Optional[Dict[str, Any]]:

        protocol = rf_features.get("rf_protocol")
        freq = rf_features.get("freq_mhz")
        device_class = rf_features.get("rf_device_class")
        interval = rf_features.get("rf_interval_mean")

        if not protocol or not freq:
            return None

        best_match = None
        best_score = 0

        for sig in self.PRODUCT_SIGNATURES:

            score = self._match_signature(sig, protocol, freq, device_class, interval)

            if score > best_score:
                best_score = score
                best_match = sig

        if best_match and best_score > 0.55:

            return {
                "rf_product_name": best_match["product"],
                "rf_product_confidence": round(best_score, 2)
            }

        return None

    # ---------------------------------------------------------------------
    # SIGNATURE MATCHING
    # ---------------------------------------------------------------------

    def _match_signature(self, sig, protocol, freq, device_class, interval):

        score = 0

        # protocol
        if sig["protocol"] == protocol:
            score += 0.35

        # band
        band = sig["band"]

        if band == 2.4 and 2400 <= freq <= 2500:
            score += 0.15

        if band == 433 and 430 <= freq <= 435:
            score += 0.15

        if band == 868 and 860 <= freq <= 870:
            score += 0.15

        # device class
        if device_class and device_class == sig["device_class"]:
            score += 0.2

        # timing
        if interval and sig.get("interval"):

            expected = sig["interval"]

            diff = abs(interval - expected)

            if diff < expected * 0.3:
                score += 0.15

        return min(score, 1.0)
