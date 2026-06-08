# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF PHYSICAL FINGERPRINT ENGINE
# FILE:         backend/recon/fingerprinting/physical_fingerprint.py
#
# VERSION:      v2.1.0
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# RFPhysicalFingerprintEngine analyzes analog RF imperfections to identify
# individual transmitters.
#
# These imperfections arise from:
#
# • oscillator instability
# • PLL drift
# • temperature effects
# • manufacturing tolerances
#
# Unlike coarse hardware fingerprints, this engine models **drift dynamics**
# across multiple signal observations.
#
#
# RF PROCESSING PIPELINE
#
# FeatureExtractor
#     ↓
# RFHardwareFingerprintEngine
#     ↓
# RFPhysicalFingerprintEngine   ← THIS MODULE
#     ↓
# TimingFingerprintEngine
#     ↓
# DeviceFusionEngine
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. ROBUST STATISTICS
# Median-based statistics reduce SDR noise sensitivity.
#
# 2. MULTI-OBSERVATION STABILITY
# Fingerprints require multiple signal observations.
#
# 3. PROTOCOL INDEPENDENCE
# Works across all RF protocols.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • estimating oscillator drift magnitude
# • measuring drift variability
# • estimating drift trend
# • generating RF physical fingerprints
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v1.x basic drift metrics
# v2.x dynamic physical fingerprints
# v2.1 robust statistical drift modeling
#
# =============================================================================

import statistics
import hashlib
from collections import defaultdict, deque


class RFPhysicalFingerprintEngine:

    VERSION = "2.1.0"

    HISTORY_SIZE = 60
    MIN_OBSERVATIONS = 15

    # ---------------------------------------------------------------------

    def __init__(self):

        self.freq_history = defaultdict(
            lambda: deque(maxlen=self.HISTORY_SIZE)
        )

    # ---------------------------------------------------------------------
    # PUBLIC UPDATE
    # ---------------------------------------------------------------------

    def update(self, emitter_id, frequency_mhz):

        history = self.freq_history[emitter_id]

        history.append(frequency_mhz)

        if len(history) < self.MIN_OBSERVATIONS:
            return None

        drift = self._drift_magnitude(history)

        variability = self._drift_variability(history)

        slope = self._drift_trend(history)

        fingerprint = self._generate_fingerprint(
            drift,
            variability,
            slope
        )

        return {

            "rf_oscillator_drift": drift,

            "rf_drift_variability": variability,

            "rf_drift_trend": slope,

            "rf_physical_fingerprint": fingerprint

        }

    # ---------------------------------------------------------------------
    # DRIFT MAGNITUDE (MAD)
    # ---------------------------------------------------------------------

    def _drift_magnitude(self, history):

        median = statistics.median(history)

        deviations = [abs(f - median) for f in history]

        return round(statistics.median(deviations), 6)

    # ---------------------------------------------------------------------
    # DRIFT VARIABILITY
    # ---------------------------------------------------------------------

    def _drift_variability(self, history):

        if len(history) < 5:
            return 0

        diffs = [

            history[i] - history[i - 1]

            for i in range(1, len(history))

        ]

        return round(statistics.pstdev(diffs), 9)

    # ---------------------------------------------------------------------
    # DRIFT TREND (LINEAR REGRESSION)
    # ---------------------------------------------------------------------

    def _drift_trend(self, history):

        if len(history) < 5:
            return 0

        x = list(range(len(history)))

        mean_x = statistics.mean(x)
        mean_y = statistics.mean(history)

        numerator = sum(
            (xi - mean_x) * (yi - mean_y)
            for xi, yi in zip(x, history)
        )

        denominator = sum(
            (xi - mean_x) ** 2
            for xi in x
        )

        if denominator == 0:
            return 0

        return round(numerator / denominator, 9)

    # ---------------------------------------------------------------------
    # FINGERPRINT
    # ---------------------------------------------------------------------

    def _generate_fingerprint(self, drift, variability, slope):

        signature = f"{drift:.6f}-{variability:.9f}-{slope:.9f}"

        return hashlib.sha256(signature.encode()).hexdigest()[:16]
