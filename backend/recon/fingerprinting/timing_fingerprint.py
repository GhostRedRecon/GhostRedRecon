# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF PACKET TIMING FINGERPRINT ENGINE
# FILE:         backend/recon/fingerprinting/timing_fingerprint.py
#
# VERSION:      v3.1.0
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# RFPacketTimingFingerprintEngine extracts behavioral intelligence
# from RF transmission timing patterns.
#
# Many RF protocols transmit signals at deterministic intervals.
#
# This module analyzes burst timestamps to detect:
#
# • periodic transmitters
# • burst transmitters
# • telemetry devices
# • RF remote controls
#
#
# RF PROCESSING PIPELINE
#
# BurstDetector
#     ↓
# RFEmitterTracker
#     ↓
# RFPacketTimingFingerprintEngine   ← THIS MODULE
#     ↓
# ProtocolFingerprintEngine
#     ↓
# RFDeviceFusionEngine
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. PASSIVE RF ANALYSIS
# Timing intelligence derived purely from observed RF timestamps.
#
# 2. MEMORY SAFE
# Bounded history buffers prevent memory growth.
#
# 3. ROBUST STATISTICS
# Median-based metrics resist SDR timing noise.
#
# 4. PROTOCOL AWARENESS
# Known RF protocols exhibit characteristic timing intervals.
#
# =============================================================================

import statistics
import hashlib
from collections import defaultdict, deque
from typing import Dict, Any, Optional


class RFPacketTimingFingerprintEngine:

    VERSION = "3.1.0"

    MAX_HISTORY = 120
    MIN_INTERVAL_SAMPLES = 6

    # ---------------------------------------------------------------------

    def __init__(self):

        self.signal_timestamps = defaultdict(
            lambda: deque(maxlen=self.MAX_HISTORY)
        )

    # ---------------------------------------------------------------------
    # MAIN UPDATE
    # ---------------------------------------------------------------------

    def update(self, signal_id: str, timestamp: float) -> Optional[Dict[str, Any]]:

        history = self.signal_timestamps[signal_id]
        history.append(timestamp)

        if len(history) < self.MIN_INTERVAL_SAMPLES:
            return None

        intervals = self._compute_intervals(history)

        if not intervals:
            return None

        mean_interval = statistics.mean(intervals)

        jitter = self._interval_jitter(intervals)

        periodicity = self._periodicity_score(mean_interval, jitter)

        variance = statistics.pvariance(intervals)

        fingerprint = {

            "rf_interval_mean": round(mean_interval, 4),

            "rf_interval_jitter": round(jitter, 6),

            "rf_interval_variance": round(variance, 6),

            "rf_periodicity_score": round(periodicity, 3),

            "rf_interval_samples": len(intervals),

        }

        fingerprint["rf_timing_fingerprint"] = self._build_fingerprint(
            mean_interval,
            jitter,
            periodicity
        )

        behavior = self._classify_behavior(mean_interval, periodicity)

        if behavior:
            fingerprint.update(behavior)

        device_hint = self._infer_device(mean_interval, periodicity)

        if device_hint:
            fingerprint.update(device_hint)

        return fingerprint

    # ---------------------------------------------------------------------
    # INTERVAL CALCULATION
    # ---------------------------------------------------------------------

    def _compute_intervals(self, history):

        return [

            history[i] - history[i - 1]

            for i in range(1, len(history))

            if history[i] > history[i - 1]

        ]

    # ---------------------------------------------------------------------
    # ROBUST JITTER (MAD)
    # ---------------------------------------------------------------------

    def _interval_jitter(self, intervals):

        if len(intervals) < 3:
            return 0

        median = statistics.median(intervals)

        deviations = [abs(i - median) for i in intervals]

        return statistics.median(deviations)

    # ---------------------------------------------------------------------
    # PERIODICITY SCORE
    # ---------------------------------------------------------------------

    def _periodicity_score(self, mean, jitter):

        if mean == 0:
            return 0

        cv = jitter / mean

        score = max(0, 1 - cv)

        return min(score, 1)

    # ---------------------------------------------------------------------
    # TIMING FINGERPRINT
    # ---------------------------------------------------------------------

    def _build_fingerprint(self, mean, jitter, periodicity):

        signature = f"{mean:.3f}-{jitter:.4f}-{periodicity:.2f}"

        return hashlib.sha256(signature.encode()).hexdigest()[:16]

    # ---------------------------------------------------------------------
    # BEHAVIOR CLASSIFICATION
    # ---------------------------------------------------------------------

    def _classify_behavior(self, interval, periodicity):

        if interval < 0.05:
            return {"rf_behavior_pattern": "burst"}

        if periodicity > 0.85:
            return {"rf_behavior_pattern": "highly_periodic"}

        if periodicity > 0.6:
            return {"rf_behavior_pattern": "periodic"}

        return None

    # ---------------------------------------------------------------------
    # DEVICE INFERENCE
    # ---------------------------------------------------------------------

    def _infer_device(self, interval, periodicity):

        if 0.08 <= interval <= 0.12 and periodicity > 0.8:

            return {
                "rf_timing_protocol": "WiFi Beacon",
                "rf_timing_device": "WiFi Access Point",
                "rf_timing_confidence": 0.9
            }

        if 0.09 <= interval <= 1.2 and periodicity > 0.7:

            return {
                "rf_timing_protocol": "BLE Advertising",
                "rf_timing_device": "BLE Device",
                "rf_timing_confidence": 0.8
            }

        if 2 <= interval <= 15 and periodicity > 0.6:

            return {
                "rf_timing_protocol": "Zigbee Poll",
                "rf_timing_device": "Zigbee Sensor",
                "rf_timing_confidence": 0.8
            }

        if 10 <= interval <= 120 and periodicity > 0.5:

            return {
                "rf_timing_protocol": "IoT Telemetry",
                "rf_timing_device": "IoT Sensor",
                "rf_timing_confidence": 0.7
            }

        if interval < 0.05 and periodicity < 0.4:

            return {
                "rf_timing_protocol": "RF Burst",
                "rf_timing_device": "Remote Control",
                "rf_timing_confidence": 0.6
            }

        return None
