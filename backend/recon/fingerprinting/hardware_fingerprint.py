# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF HARDWARE FINGERPRINT ENGINE
# FILE:         backend/recon/fingerprinting/hardware_fingerprint.py
#
# VERSION:      v2.1.0
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# RFHardwareFingerprintEngine extracts persistent hardware-level RF signatures
# from transmitters.
#
# RF transmitters exhibit unique imperfections caused by:
#
# • oscillator drift
# • amplifier instability
# • transmit power fluctuations
# • timing jitter
#
# These imperfections produce a stable RF hardware identity which allows
# GhostRecon to track physical transmitters even when protocols are encrypted.
#
#
# RF PROCESSING PIPELINE
#
# HackRF SDR
#     ↓
# PeakDetector
#     ↓
# BurstDetector
#     ↓
# EmitterCluster
#     ↓
# RFEmitterTracker
#     ↓
# FeatureExtractor
#     ↓
# RFHardwareFingerprintEngine     ← THIS MODULE
#     ↓
# ProtocolFingerprintEngine
#     ↓
# DeviceFusionEngine
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. PASSIVE RF IDENTIFICATION
# Fingerprints derived solely from RF observations.
#
# 2. PROTOCOL INDEPENDENT
# Hardware fingerprints must remain valid across protocols.
#
# 3. STABLE SIGNATURES
# Robust statistics ensure SDR noise does not corrupt fingerprints.
#
# 4. REAL-TIME SAFE
# Lightweight rolling statistics suitable for continuous scanning.
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • estimating oscillator drift
# • estimating transmit power instability
# • estimating frequency offset
# • estimating timing jitter
# • generating persistent RF hardware fingerprints
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v1.x  basic drift and variance
# v2.x  multi-metric fingerprints
# v2.1  robust statistical estimation
#
# =============================================================================

import statistics
import hashlib
import time
from collections import deque


class RFHardwareFingerprintEngine:

    VERSION = "2.1.0"

    HISTORY = 50
    MIN_OBSERVATIONS = 15

    # ---------------------------------------------------------------------

    def __init__(self):

        self.freq_history = {}
        self.power_history = {}
        self.time_history = {}

    # ---------------------------------------------------------------------
    # PUBLIC UPDATE
    # ---------------------------------------------------------------------

    def update(self, emitter):

        emitter_id = emitter.get("rf_emitter_id")

        if emitter_id is None:
            return None

        freq = emitter.get("freq_mhz")
        power = emitter.get("power_db")

        if freq is None or power is None:
            return None

        freq_hist = self.freq_history.setdefault(
            emitter_id,
            deque(maxlen=self.HISTORY)
        )

        power_hist = self.power_history.setdefault(
            emitter_id,
            deque(maxlen=self.HISTORY)
        )

        time_hist = self.time_history.setdefault(
            emitter_id,
            deque(maxlen=self.HISTORY)
        )

        freq_hist.append(freq)
        power_hist.append(power)
        time_hist.append(time.time())

        if len(freq_hist) < self.MIN_OBSERVATIONS:
            return None

        drift = self._freq_drift(freq_hist)
        pinstability = self._power_instability(power_hist)
        offset = self._freq_offset(freq_hist)
        jitter = self._timing_jitter(time_hist)

        fingerprint = self._build_fingerprint(
            drift,
            pinstability,
            offset,
            jitter
        )

        return {

            "rf_hardware_fingerprint": fingerprint,

            "rf_frequency_drift": drift,

            "rf_power_instability": pinstability,

            "rf_frequency_offset": offset,

            "rf_timing_jitter": jitter,

        }

    # ---------------------------------------------------------------------
    # FINGERPRINT HASH
    # ---------------------------------------------------------------------

    def _build_fingerprint(self, drift, power, offset, jitter):

        signature = f"{drift:.4f}-{power:.4f}-{offset:.4f}-{jitter:.4f}"

        return hashlib.sha256(signature.encode()).hexdigest()[:16]

    # ---------------------------------------------------------------------
    # FREQUENCY DRIFT (MAD)
    # ---------------------------------------------------------------------

    def _freq_drift(self, history):

        median = statistics.median(history)

        deviations = [abs(f - median) for f in history]

        return round(statistics.median(deviations), 6)

    # ---------------------------------------------------------------------
    # POWER INSTABILITY
    # ---------------------------------------------------------------------

    def _power_instability(self, history):

        if len(history) < 3:
            return 0

        mean_power = statistics.mean(history)

        if mean_power == 0:
            return 0

        std_power = statistics.stdev(history)

        return round(std_power / abs(mean_power), 6)

    # ---------------------------------------------------------------------
    # FREQUENCY OFFSET
    # ---------------------------------------------------------------------

    def _freq_offset(self, history):

        median = statistics.median(history)

        deviations = [abs(f - median) for f in history]

        return round(statistics.mean(deviations), 6)

    # ---------------------------------------------------------------------
    # TIMING JITTER
    # ---------------------------------------------------------------------

    def _timing_jitter(self, history):

        if len(history) < 4:
            return 0

        intervals = [
            history[i] - history[i - 1]
            for i in range(1, len(history))
        ]

        median = statistics.median(intervals)

        deviations = [abs(i - median) for i in intervals]

        return round(statistics.median(deviations), 6)
