# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/phy/rf_protocol_classifier.py
# VERSION:      v2.0.0 (DATABASE-DRIVEN RF CLASSIFIER)
# LAST UPDATED: 2026-03-07
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# HackRF
#   ↓
# SDRController
#   ↓
# LiveFFT
#   ↓
# ReconEngine
#   ↓
# RFProtocolClassifier
#   ↓
# RFProtocolDatabase
#   ↓
# DeviceIdentityEngine
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# ✔ Database-driven protocol classification
# ✔ Global spectrum support (EU / US / ASIA)
# ✔ Passive RF inference
# ✔ Lightweight CPU usage
# ✔ Expandable device intelligence
#
# =============================================================================
# RESPONSIBILITY
# =============================================================================
#
# RFProtocolClassifier is responsible for:
#
#   • Determining RF protocol families
#   • Inferring possible device classes
#   • Matching RF characteristics
#
# It does NOT perform:
#
#   ✘ SDR capture
#   ✘ FFT processing
#   ✘ Signal lifecycle management
#
# =============================================================================

from backend.intel.phy.rf_protocol_database import PROTOCOL_FAMILIES


class RFProtocolClassifier:

    VERSION = "2.0.0"

    def __init__(self):

        self.database = PROTOCOL_FAMILIES

    # -------------------------------------------------------------------------
    # CLASSIFY SIGNAL
    # -------------------------------------------------------------------------

    def classify(self, freq_mhz, rf_features):

        bw_hz = rf_features.get("estimated_bandwidth_hz", 0)
        bw_khz = bw_hz / 1000 if bw_hz else 0

        for proto, data in self.database.items():

            # ---------------------------------------------------------------
            # Multi-band protocols (LoRa, drones, etc.)
            # ---------------------------------------------------------------

            if "bands_mhz" in data:

                for band in data["bands_mhz"]:

                    if band[0] <= freq_mhz <= band[1]:

                        return self._build_result(proto, data)

                continue

            # ---------------------------------------------------------------
            # Single band protocols
            # ---------------------------------------------------------------

            band = data.get("band_mhz")

            if not band:
                continue

            if not (band[0] <= freq_mhz <= band[1]):
                continue

            # Bandwidth check if available
            bw_range = data.get("bandwidth_khz")

            if bw_range and bw_khz:

                if not (bw_range[0] <= bw_khz <= bw_range[1]):
                    continue

            return self._build_result(proto, data)

        # ------------------------------------------------------------------
        # Unknown protocol
        # ------------------------------------------------------------------

        return {

            "protocol": "UNKNOWN",
            "modulation": None,
            "devices": [],
            "security": None

        }

    # -------------------------------------------------------------------------
    # RESULT BUILDER
    # -------------------------------------------------------------------------

    def _build_result(self, proto, data):

        return {

            "protocol": proto,
            "modulation": data.get("modulation"),
            "devices": data.get("devices", []),
            "security": data.get("security")

        }
