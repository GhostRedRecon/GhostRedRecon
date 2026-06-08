# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/recon/rf_vendor_signature_engine.py
#
# VERSION:      v2.0.0 (GLOBAL RF VENDOR INTELLIGENCE ENGINE)
# UPDATED:      2026-03-12
#
# =============================================================================

from typing import Dict, Any, List


class RFVendorSignatureEngine:

    VERSION = "2.0.0"

    # ---------------------------------------------------------------------
    # INITIALIZATION
    # ---------------------------------------------------------------------

    def __init__(self):

        self.vendor_catalog = self._build_vendor_catalog()

    # ---------------------------------------------------------------------
    # MAIN INFERENCE
    # ---------------------------------------------------------------------

    def infer(self, freq_mhz: float, rf_features: Dict[str, Any]) -> Dict[str, Any]:

        protocol = rf_features.get("rf_protocol")
        timing_protocol = rf_features.get("rf_timing_protocol")
        behavior = rf_features.get("rf_behavior_pattern")
        bandwidth = rf_features.get("bandwidth_mhz")

        rf_band = self._detect_band(freq_mhz)

        candidates = []

        for vendor in self.vendor_catalog:

            score = 0.0
            reasons = []

            sig = vendor["signature"]

            if protocol and protocol in sig["protocols"]:
                score += 0.30
                reasons.append(f"protocol match {protocol}")

            if timing_protocol and timing_protocol in sig["timing"]:
                score += 0.25
                reasons.append(f"timing pattern {timing_protocol}")

            if behavior and behavior in sig["behavior"]:
                score += 0.20
                reasons.append(f"behavior signature {behavior}")

            if bandwidth and sig["bandwidth_min"] <= bandwidth <= sig["bandwidth_max"]:
                score += 0.15
                reasons.append("bandwidth profile match")

            if rf_band and rf_band in sig["bands"]:
                score += 0.10
                reasons.append(f"rf band {rf_band}")

            if score > 0.35:

                candidates.append({
                    "vendor": vendor["name"],
                    "device_family": vendor["device_family"],
                    "confidence": round(score, 2),
                    "reasons": reasons
                })

        if not candidates:

            return {
                "rf_vendor_candidate": "Unknown",
                "rf_vendor_confidence": 0.0
            }

        candidates.sort(key=lambda x: x["confidence"], reverse=True)

        best = candidates[0]

        return {
            "rf_vendor_candidate": best["vendor"],
            "rf_device_family_candidate": best["device_family"],
            "rf_vendor_confidence": best["confidence"],
            "rf_vendor_reason": best["reasons"],
            "rf_vendor_candidates": candidates[:3]
        }

    # ---------------------------------------------------------------------
    # RF BAND DETECTION
    # ---------------------------------------------------------------------

    def _detect_band(self, freq):

        if 2400 <= freq <= 2500:
            return "2.4ghz"

        if 5000 <= freq <= 6000:
            return "5ghz"

        if 430 <= freq <= 435:
            return "433mhz"

        if 860 <= freq <= 870:
            return "868mhz"

        return "unknown"

    # ---------------------------------------------------------------------
    # VENDOR CATALOG
    # ---------------------------------------------------------------------

    def _build_vendor_catalog(self) -> List[Dict[str, Any]]:

        return [

            {
                "name": "Xiaomi / Aqara",
                "device_family": "Zigbee Smart Home",
                "signature": {
                    "protocols": ["Zigbee"],
                    "timing": ["Zigbee Poll"],
                    "behavior": ["Zigbee Sensor"],
                    "bands": ["2.4ghz"],
                    "bandwidth_min": 1,
                    "bandwidth_max": 5
                }
            },

            {
                "name": "Philips Hue",
                "device_family": "Zigbee Lighting",
                "signature": {
                    "protocols": ["Zigbee"],
                    "timing": ["Zigbee Poll"],
                    "behavior": ["Zigbee Bridge"],
                    "bands": ["2.4ghz"],
                    "bandwidth_min": 1,
                    "bandwidth_max": 5
                }
            },

            {
                "name": "Tuya Smart Life",
                "device_family": "IoT Ecosystem",
                "signature": {
                    "protocols": ["WiFi", "Zigbee"],
                    "timing": ["Zigbee Poll", "WiFi Beacon"],
                    "behavior": ["IoT Device"],
                    "bands": ["2.4ghz"],
                    "bandwidth_min": 1,
                    "bandwidth_max": 20
                }
            },

            {
                "name": "TP-Link",
                "device_family": "WiFi Router",
                "signature": {
                    "protocols": ["WiFi"],
                    "timing": ["WiFi Beacon"],
                    "behavior": ["WiFi Access Point"],
                    "bands": ["2.4ghz", "5ghz"],
                    "bandwidth_min": 18,
                    "bandwidth_max": 80
                }
            },

            {
                "name": "Apple Ecosystem",
                "device_family": "BLE Devices",
                "signature": {
                    "protocols": ["BLE"],
                    "timing": ["BLE Advertising"],
                    "behavior": ["BLE Beacon"],
                    "bands": ["2.4ghz"],
                    "bandwidth_min": 1,
                    "bandwidth_max": 5
                }
            },

            {
                "name": "Amazon",
                "device_family": "Smart Speakers",
                "signature": {
                    "protocols": ["WiFi", "BLE"],
                    "timing": ["WiFi Beacon"],
                    "behavior": ["Smart Speaker"],
                    "bands": ["2.4ghz"],
                    "bandwidth_min": 18,
                    "bandwidth_max": 40
                }
            },

        ]
