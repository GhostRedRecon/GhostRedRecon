# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/protocol/protocol_classifier.py
# VERSION:      v7.0.0 (SIGINT-GRADE MULTI-PROTOCOL CLASSIFIER)
# UPDATED:      2026-03-23
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
# ReconEngine
#     ↓
# SignalEngine
#     ↓
# ProtocolClassifier (THIS FILE - FAST SIGINT LAYER)
#     ↓
# ProtocolEngine (temporal fusion / overrides)
#     ↓
# DeviceFusion → DeviceIntelligence → API
#
# -----------------------------------------------------------------------------
# ROLE
# -----------------------------------------------------------------------------
# High-speed probabilistic protocol classifier for real-world RF environments.
#
# Supports:
#   ✔ WiFi (802.11)
#   ✔ BLE (Bluetooth Low Energy)
#   ✔ Zigbee (802.15.4)
#   ✔ LoRa
#   ✔ Sub-GHz FSK / OOK
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Convert RF signal metadata into a reliable protocol hypothesis using:
#   - spectral features
#   - temporal behavior
#   - RF band awareness
#   - channel intelligence
#   - protocol-specific heuristics
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# ✔ Multi-protocol classification (WiFi / BLE / Zigbee / LoRa / FSK)
# ✔ 2.4GHz separation (WiFi vs BLE vs Zigbee)
# ✔ Sub-GHz separation (LoRa vs FSK)
# ✔ Channel-aware scoring
# ✔ Industrial IoT detection patterns
# ✔ Fail-safe operation
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. ZERO BREAKAGE
#    classify(data) API unchanged
#
# 2. FAIL-SAFE
#    Never crash on bad input
#
# 3. WEAK-TRUTH > UNKNOWN
#
# 4. MULTI-EVIDENCE FUSION
#    Band + BW + Behavior + Shape + Channel
#
# 5. SIGINT REALISM
#    Built for noisy RF (homes, offices, industrial)
#
# =============================================================================
# 📦 OUTPUT
# =============================================================================
#
# {
#   "protocol": str,
#   "protocol_confidence": float
# }
#
# =============================================================================


class ProtocolClassifier:

    VERSION = "7.0.0"

    UNKNOWN_THRESHOLD = 0.22
    LOW_CONFIDENCE_FLOOR = 0.10
    MAX_CONFIDENCE = 0.95

    # =========================================================================
    # PUBLIC API
    # =========================================================================
    def classify(self, data):

        if isinstance(data, list):
            return [self._classify_single(d) for d in data]

        return self._classify_single(data)

    # =========================================================================
    # CORE
    # =========================================================================
    def _classify_single(self, d):

        if not isinstance(d, dict):
            return self._unknown()

        # ---------------------------------------------------------------------
        # INPUT NORMALIZATION
        # ---------------------------------------------------------------------
        freq = self._f(
            d.get("frequency_mhz"),
            d.get("rf_frequency_mhz"),
            d.get("center_freq_mhz"),
        )

        rf_band = d.get("rf_band") or self._band(freq)

        bw = self._f(d.get("bandwidth_estimate_mhz")) or 0.0
        bw_class = str(d.get("bandwidth_class") or self._bw_class(bw)).lower()

        signal_type = str(d.get("signal_type") or "").lower()
        engine = str(d.get("engine") or "").lower()

        burst_ratio = self._bounded(self._f(d.get("burst_ratio")), 0, 1)
        periodicity = self._bounded(self._f(d.get("periodicity")), 0, 1)
        temporal = self._bounded(self._f(d.get("temporal_consistency")), 0, 1)

        freq_variance = self._f(d.get("freq_variance")) or 0.0
        peak_density = self._bounded(self._f(d.get("peak_density")), 0, 1)

        spectral_flatness = self._bounded(self._f(d.get("spectral_flatness")), 0, 1)
        edge_steepness = self._bounded(self._f(d.get("edge_steepness")), 0, 1)
        shape_score = self._bounded(self._f(d.get("shape_score")), 0, 1)

        wifi_channel = d.get("wifi_channel")

        # ---------------------------------------------------------------------
        # PROTOCOL SCORES
        # ---------------------------------------------------------------------
        scores = {
            "WIFI": 0.0,
            "BLE": 0.0,
            "ZIGBEE": 0.0,
            "LORA": 0.0,
            "SUBGHZ_FSK": 0.0,
        }

        # ---------------------------------------------------------------------
        # 1. RF BAND PRIORS
        # ---------------------------------------------------------------------
        if rf_band == "2.4GHz":
            scores["WIFI"] += 0.15
            scores["BLE"] += 0.15
            scores["ZIGBEE"] += 0.15

        elif rf_band == "subGHz":
            scores["LORA"] += 0.25
            scores["SUBGHZ_FSK"] += 0.25

        # ---------------------------------------------------------------------
        # 2. BANDWIDTH INTELLIGENCE (CRITICAL)
        # ---------------------------------------------------------------------
        if bw >= 5:
            scores["WIFI"] += 0.45

        elif 1.5 <= bw <= 3:
            scores["ZIGBEE"] += 0.40
            scores["BLE"] += 0.10

        elif 0.2 <= bw < 1.5:
            scores["BLE"] += 0.25
            scores["SUBGHZ_FSK"] += 0.15

        elif bw < 0.2:
            scores["LORA"] += 0.35
            scores["SUBGHZ_FSK"] += 0.25

        # ---------------------------------------------------------------------
        # 3. SIGNAL BEHAVIOR
        # ---------------------------------------------------------------------
        if signal_type == "wideband":
            scores["WIFI"] += 0.25

        elif signal_type == "burst":
            scores["BLE"] += 0.25
            scores["ZIGBEE"] += 0.15

        elif signal_type == "periodic":
            scores["LORA"] += 0.25
            scores["SUBGHZ_FSK"] += 0.15

        elif signal_type == "continuous":
            scores["WIFI"] += 0.20

        # ---------------------------------------------------------------------
        # 4. FREQUENCY VARIANCE (BLE HOPPING)
        # ---------------------------------------------------------------------
        if freq_variance > 0.4:
            scores["BLE"] += 0.30

        elif freq_variance < 0.05:
            scores["WIFI"] += 0.08
            scores["LORA"] += 0.08

        # ---------------------------------------------------------------------
        # 5. TEMPORAL FEATURES
        # ---------------------------------------------------------------------
        if burst_ratio > 0.6:
            scores["BLE"] += 0.20
            scores["ZIGBEE"] += 0.10

        if periodicity > 0.6:
            scores["LORA"] += 0.20

        if temporal > 0.6:
            scores["LORA"] += 0.10
            scores["WIFI"] += 0.05

        # ---------------------------------------------------------------------
        # 6. SPECTRAL SHAPE
        # ---------------------------------------------------------------------
        if spectral_flatness > 0.5 and bw >= 5:
            scores["WIFI"] += 0.15

        if shape_score > 0.5 and bw < 0.3:
            scores["LORA"] += 0.15

        if edge_steepness > 0.4 and bw >= 5:
            scores["WIFI"] += 0.10

        # ---------------------------------------------------------------------
        # 7. CHANNEL INTELLIGENCE
        # ---------------------------------------------------------------------

        # WiFi channel hint
        if wifi_channel:
            scores["WIFI"] += 0.40

        # Zigbee channel detection
        if freq and 2405 <= freq <= 2480:
            if ((freq - 2405) % 5) < 1:
                scores["ZIGBEE"] += 0.25

        # BLE advertising channels
        if freq in (2402, 2426, 2480):
            scores["BLE"] += 0.35

        # ---------------------------------------------------------------------
        # 8. PENALTIES
        # ---------------------------------------------------------------------
        if rf_band == "2.4GHz":
            scores["LORA"] -= 0.15
            scores["SUBGHZ_FSK"] -= 0.15

        if rf_band == "subGHz":
            scores["WIFI"] -= 0.15
            scores["BLE"] -= 0.10
            scores["ZIGBEE"] -= 0.10

        # ---------------------------------------------------------------------
        # 9. NORMALIZATION
        # ---------------------------------------------------------------------
        scores = {k: max(0.0, v) for k, v in scores.items()}
        total = sum(scores.values())

        if total <= 0:
            return self._unknown()

        norm = {k: v / total for k, v in scores.items()}
        protocol = max(norm, key=norm.get)
        confidence = norm[protocol]

        if confidence < self.UNKNOWN_THRESHOLD:
            return self._unknown()

        confidence = max(self.LOW_CONFIDENCE_FLOOR, min(self.MAX_CONFIDENCE, confidence))

        return {
            "protocol": protocol,
            "protocol_confidence": round(confidence, 3),
        }

    # =========================================================================
    # HELPERS
    # =========================================================================
    def _band(self, f):
        if f is None:
            return "unknown"
        if 2400 <= f <= 2500:
            return "2.4GHz"
        if 300 <= f <= 1000:
            return "subGHz"
        return "unknown"

    def _bw_class(self, bw):
        if bw < 0.25:
            return "narrow"
        if bw < 2:
            return "medium"
        return "wide"

    def _f(self, *vals):
        for v in vals:
            try:
                if v is not None:
                    return float(v)
            except:
                continue
        return None

    def _bounded(self, v, lo, hi):
        if v is None:
            return 0.0
        return max(lo, min(hi, v))

    def _unknown(self):
        return {
            "protocol": "UNKNOWN_PROTOCOL",
            "protocol_confidence": 0.10,
        }
