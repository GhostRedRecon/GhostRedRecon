# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/signal_features.py
# VERSION:      v4.0.0 (SIGINT PHASE 2.5 - BURST-AWARE FEATURE ENGINE)
# UPDATED:      2026-03-22
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
# ReconEngine (FFT + BURST)
#     ↓
# SignalEngine
#     ↓
# SignalFeatureBuilder (THIS FILE)
#     ↓
# ProtocolClassifier
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Transform raw RF detections into SIGINT-grade features:
#
# ✔ Protocol classification (Phase 2)
# ✔ Device inference (Phase 3)
# ✔ Behavioral modeling (Phase 4)
#
# =============================================================================
# 🔄 CHANGES IN v4.0.0
# =============================================================================
#
# 🔥 ADDED:
#   ✔ Burst-aware features (duration, repetition, SNR)
#   ✔ WiFi channel detection
#   ✔ Signal type classification (continuous vs burst)
#   ✔ Duty cycle estimation
#   ✔ Behavior scoring (periodicity, burstiness)
#
# 🛡️ PRESERVED:
#   ✔ ALL existing features (no breaking changes)
#
# =============================================================================

import time
from collections import defaultdict
from typing import Dict, List, Tuple


class SignalFeatureBuilder:

    VERSION = "4.0.0"

    def __init__(self):
        self._history: Dict[str, List[Tuple[float, float, float, dict]]] = defaultdict(list)
        self._max_history = 30

    # =========================================================================
    # PUBLIC ENTRY (NON-BREAKING)
    # =========================================================================
    def update(self, signal_id: str, freq_mhz: float, power_db: float, metadata=None) -> Dict:

        try:
            now = time.time()
            metadata = metadata or {}

            hist = self._history[signal_id]
            hist.append((now, freq_mhz, power_db, metadata))

            if len(hist) > self._max_history:
                hist.pop(0)

            return self._extract_features(hist)

        except Exception:
            return {}

    # =========================================================================
    # FEATURE EXTRACTION
    # =========================================================================
    def _extract_features(self, hist):

        if not hist:
            return {}

        try:
            timestamps = [x[0] for x in hist]
            freqs = [x[1] for x in hist]
            powers = [x[2] for x in hist]
            metas = [x[3] for x in hist]
            latest_meta = metas[-1] if metas and isinstance(metas[-1], dict) else {}

            current_freq = freqs[-1]

            # -------------------------------------------------------------
            # BAND
            # -------------------------------------------------------------
            band = self._detect_band(current_freq)

            # -------------------------------------------------------------
            # WIFI CHANNEL DETECTION (🔥 NEW)
            # -------------------------------------------------------------
            wifi_channel = self._estimate_wifi_channel(current_freq) if band == "2.4GHz" else None

            # -------------------------------------------------------------
            # BANDWIDTH
            # -------------------------------------------------------------
            freq_min = min(freqs)
            freq_max = max(freqs)
            bandwidth = max(freq_max - freq_min, 0.1)

            # CLASS
            if bandwidth > 10:
                bandwidth_class = "wide"
            elif bandwidth > 2:
                bandwidth_class = "medium"
            else:
                bandwidth_class = "narrow"

            # -------------------------------------------------------------
            # TEMPORAL
            # -------------------------------------------------------------
            duration = max(timestamps[-1] - timestamps[0], 1e-6)
            intervals = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]

            avg_interval = sum(intervals) / len(intervals) if intervals else 0
            burst_interval_ms = avg_interval * 1000

            # -------------------------------------------------------------
            # POWER
            # -------------------------------------------------------------
            power_mean = sum(powers) / len(powers)
            power_std = (sum((p - power_mean) ** 2 for p in powers) / len(powers)) ** 0.5

            # -------------------------------------------------------------
            # FREQUENCY VARIANCE
            # -------------------------------------------------------------
            freq_mean = sum(freqs) / len(freqs)
            freq_variance = sum((f - freq_mean) ** 2 for f in freqs) / len(freqs)

            # NORMALIZE
            freq_variance_norm = min(freq_variance / 5.0, 1.0)

            # -------------------------------------------------------------
            # BURST FEATURES (🔥 CRITICAL)
            # -------------------------------------------------------------
            burst_count = sum(1 for m in metas if m.get("engine") == "burst")
            burst_ratio = burst_count / len(hist)

            avg_duration = self._safe_avg([m.get("duration_ms") for m in metas])
            avg_snr = self._safe_avg([m.get("snr") for m in metas])

            # -------------------------------------------------------------
            # BEHAVIOR
            # -------------------------------------------------------------
            periodicity = 1.0 - min(self._variance(intervals) / 0.05, 1.0) if intervals else 0
            burstiness = min(burst_ratio * 2.0, 1.0)

            duty_cycle = min(len(hist) / 30.0, 1.0)

            # -------------------------------------------------------------
            # SIGNAL TYPE (🔥 HUGE IMPACT)
            # -------------------------------------------------------------
            if burst_ratio > 0.6:
                signal_type = "burst"
            elif periodicity > 0.7:
                signal_type = "periodic"
            else:
                signal_type = "continuous"

            # -------------------------------------------------------------
            # OUTPUT (NON-BREAKING + NEW)
            # -------------------------------------------------------------
            recon_bandwidth = self._safe_float(latest_meta.get("bandwidth_estimate_mhz"), None)
            recon_peak_density = self._safe_float(latest_meta.get("peak_density"), None)
            history_peak_density = len(hist) / duration

            return {
                # EXISTING (unchanged)
                "rf_frequency_mhz": current_freq,
                "band": band,
                "bandwidth_estimate_mhz": recon_bandwidth if recon_bandwidth is not None else bandwidth,
                "bandwidth_class": bandwidth_class,
                "peak_density": recon_peak_density if recon_peak_density is not None else min(history_peak_density, float(len(hist))),
                "history_peak_density": history_peak_density,
                "signal_density": len(hist),
                "burst_interval_ms": burst_interval_ms,
                "temporal_consistency": periodicity,
                "power_mean_db": power_mean,
                "power_std_db": power_std,
                "signal_stability": 1.0 - min(power_std / 10.0, 1.0),
                "freq_variance": freq_variance_norm,

                # NEW SIGINT FEATURES
                "wifi_channel": wifi_channel,
                "burst_ratio": burst_ratio,
                "avg_burst_duration_ms": avg_duration,
                "avg_snr": avg_snr,
                "burstiness": burstiness,
                "periodicity": periodicity,
                "duty_cycle": duty_cycle,
                "signal_type": signal_type,
            }

        except Exception:
            return {}

    # =========================================================================
    # HELPERS
    # =========================================================================
    def _estimate_wifi_channel(self, freq):
        try:
            return int((freq - 2407) / 5)
        except:
            return None

    def _variance(self, arr):
        if not arr:
            return 0
        mean = sum(arr) / len(arr)
        return sum((x - mean) ** 2 for x in arr) / len(arr)

    def _safe_avg(self, arr):
        vals = [x for x in arr if x is not None]
        if not vals:
            return None
        return sum(vals) / len(vals)

    def _safe_float(self, value, default=None):
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    def _detect_band(self, freq):
        if 2400 <= freq <= 2500:
            return "2.4GHz"
        if 5000 <= freq <= 6000:
            return "5GHz"
        if 400 <= freq <= 1000:
            return "SUB_GHZ"
        return "UNKNOWN"

    # =========================================================================
    # DEBUG
    # =========================================================================
    def get_stats(self):
        return {
            "tracked_signals": len(self._history),
            "version": self.VERSION,
        }
