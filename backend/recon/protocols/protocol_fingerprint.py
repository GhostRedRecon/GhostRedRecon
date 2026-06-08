# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       PROTOCOL FINGERPRINT ENGINE
# FILE:         backend/recon/protocols/protocol_fingerprint.py
#
# VERSION:      v8.0.0 (SIGINT FEATURE ENGINE — ROBUST + CLASSIFIER-READY)
# UPDATED:      2026-03-17
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# ReconEngine → ProtocolFingerprintEngine → ProtocolClassifier
#
# This module extracts RF-native features:
#   → morphology
#   → channel alignment
#   → protocol likelihoods
#   → observability
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. RF-TRUTH FIRST
#    Never fabricate signals — only derive
#
# 2. PARTIAL DATA RESILIENCE
#    Works even when bandwidth / bursts missing
#
# 3. STRONG SIGNAL GENERATION
#    Extract signals classifier can trust
#
# 4. EXPLAINABILITY
#    Every feature must be interpretable
#
# =============================================================================
# RESPONSIBILITY
# =============================================================================
#
# ✔ Extract RF features
# ✔ Generate protocol likelihoods
# ✔ Provide classifier-ready signals
#
# ✖ No classification decisions
#
# =============================================================================

import copy
import logging


class ProtocolFingerprintEngine:

    VERSION = "8.0.0"

    WIFI_CHANNELS = [2412,2437,2462]
    BLE_ADV_CHANNELS = [2402,2426,2480]
    ZIGBEE_CHANNELS = [2405 + 5*i for i in range(16)]
    LORA_HINTS = [433.92,868.1,915.0]

    def __init__(self):
        self.logger = logging.getLogger("ghostrecon.fingerprint")

    # =========================================================================
    # PUBLIC
    # =========================================================================

    def enrich_emitters(self, emitters):
        return [self._safe_enrich(e) for e in (emitters or [])]

    def _safe_enrich(self, e):
        try:
            return self._enrich(e)
        except Exception as ex:
            self.logger.warning("Fingerprint error: %s", ex)
            out = dict(e)
            out["rf_protocol_features_error"] = str(ex)
            return out

    # =========================================================================
    # CORE
    # =========================================================================

    def _enrich(self, emitter):

        out = copy.deepcopy(emitter)

        freq = self._f(emitter, "rf_frequency_mhz", "frequency_mhz")
        bw = self._f(emitter, "rf_bandwidth_mhz", "bandwidth_mhz")
        bursts = self._i(emitter, "rf_burst_count", "burst_count")

        band = self._band(freq)

        # ---------------------------------------------------------------------
        # FALLBACK FEATURE SYNTHESIS (CRITICAL FIX)
        # ---------------------------------------------------------------------

        if bw is None:
            # approximate based on band
            if band == "2.4GHz":
                bw = 2.0
            elif band == "SubGHz":
                bw = 0.5

        # ---------------------------------------------------------------------
        # MORPHOLOGY
        # ---------------------------------------------------------------------

        is_wideband = bw >= 8
        is_midband = 2 <= bw < 8
        is_narrowband = bw < 2

        is_bursty = bursts > 2
        is_continuous = not is_bursty

        # ---------------------------------------------------------------------
        # ALIGNMENT
        # ---------------------------------------------------------------------

        wifi_align = self._align(freq, self.WIFI_CHANNELS, 3)
        ble_align = self._align(freq, self.BLE_ADV_CHANNELS, 2)
        zigbee_align = self._align(freq, self.ZIGBEE_CHANNELS, 2)

        # ---------------------------------------------------------------------
        # STRONG RF SIGNALS
        # ---------------------------------------------------------------------

        scores = {
            "WiFi": 0.0,
            "BLE": 0.0,
            "Zigbee": 0.0,
            "LoRa": 0.0,
            "SubGHz": 0.0,
        }

        # WiFi
        if is_wideband:
            scores["WiFi"] += 0.4
        if wifi_align:
            scores["WiFi"] += 0.2
        if band in ("2.4GHz", "5GHz"):
            scores["WiFi"] += 0.1

        # BLE
        if is_narrowband and band == "2.4GHz":
            scores["BLE"] += 0.3
        if ble_align:
            scores["BLE"] += 0.3
        if is_bursty:
            scores["BLE"] += 0.1

        # Zigbee
        if is_midband:
            scores["Zigbee"] += 0.3
        if zigbee_align:
            scores["Zigbee"] += 0.3

        # LoRa
        if is_narrowband and band == "SubGHz":
            scores["LoRa"] += 0.4

        # SubGHz
        if band == "SubGHz":
            scores["SubGHz"] += 0.3

        # ---------------------------------------------------------------------
        # RANKING
        # ---------------------------------------------------------------------

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        candidates = [p for p, s in ranked if s > 0.2]

        if not candidates:
            candidates = ["Unknown"]

        # ---------------------------------------------------------------------
        # CONFIDENCE (NEW)
        # ---------------------------------------------------------------------

        top_score = ranked[0][1]
        confidence = min(top_score, 1.0)

        # ---------------------------------------------------------------------
        # OUTPUT
        # ---------------------------------------------------------------------

        features = {
            "band": band,
            "bandwidth_mhz": bw,
            "is_wideband": is_wideband,
            "is_midband": is_midband,
            "is_narrowband": is_narrowband,
            "is_bursty": is_bursty,
            "alignment": {
                "wifi": wifi_align,
                "ble": ble_align,
                "zigbee": zigbee_align,
            },
            "protocol_likelihoods": scores,
            "confidence": round(confidence, 2),
        }

        out["rf_protocol_features"] = features
        out["rf_protocol_candidates"] = candidates
        out["rf_protocol_fingerprint_version"] = self.VERSION

        return out

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _band(self, f):
        if not f:
            return "unknown"
        if 2400 <= f <= 2500:
            return "2.4GHz"
        if 300 <= f <= 1000:
            return "SubGHz"
        return "other"

    def _align(self, f, channels, tol):
        if f is None:
            return False
        return any(abs(f - ch) <= tol for ch in channels)

    def _f(self, data, *keys):
        for k in keys:
            try:
                v = data.get(k)
                if v is not None:
                    return float(v)
            except:
                continue
        return None

    def _i(self, data, *keys):
        for k in keys:
            try:
                v = data.get(k)
                if v is not None:
                    return int(v)
            except:
                continue
        return 0
