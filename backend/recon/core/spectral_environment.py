# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       SPECTRAL ENVIRONMENT ANALYZER
# FILE:         backend/recon/core/spectral_environment.py
#
# VERSION:      v13.0.0
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# SpectralEnvironmentAnalyzer models the RF spectral environment for each
# observed FFT frame.
#
# It provides contextual information used by PeakDetector and SweepController
# to adapt detection thresholds and scanning behaviour.
#
#
# RF PROCESSING PIPELINE
#
# LiveFFT
#     ↓
# SpectralEnvironmentAnalyzer   ← THIS MODULE
#     ↓
# PeakDetector
#     ↓
# EmitterCluster
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. ADAPTIVE RF DETECTION
# -----------------------------------------------------------------------------
# Detection thresholds should adapt to the current RF environment.
#
#
# 2. LOW LATENCY
# -----------------------------------------------------------------------------
# Metrics must be computed quickly to avoid blocking SDR processing.
#
#
# 3. NOISE TOLERANCE
# -----------------------------------------------------------------------------
# Algorithms must tolerate SDR noise floor variation.
#
#
# 4. SWEEP INTELLIGENCE
# -----------------------------------------------------------------------------
# Environment metrics inform sweep controller behaviour.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • estimating noise floor
# • computing spectral flatness
# • measuring spectral variance
# • detecting RF occupancy
# • tracking persistence across sweeps
#
#
# This module is NOT responsible for:
#
# • RF peak detection
# • emitter clustering
# • protocol classification
#
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v10.x
#     baseline spectral metrics
#
# v12.x
#     persistence-aware environment model
#
# v13.x
#     RF occupancy estimation
#     dynamic detection threshold
#     environment classification
#
#
# =============================================================================
# ENTERPRISE CODE CONVENTIONS
# =============================================================================
#
# • deterministic output
# • minimal CPU overhead
# • sweep-aware operation
# • SDR noise tolerant metrics
#
# =============================================================================

from __future__ import annotations
import numpy as np
import time
from collections import deque
from typing import Dict, Any, Optional


class SpectralEnvironmentAnalyzer:

    VERSION = "13.0.0"

    def __init__(
        self,
        history_size: int = 200,
        persistence_time_sec: float = 2.0,
    ):

        self._history = deque(maxlen=history_size)

        self._current_freq = None

        self._freq_start_time = None

        self._persistence_time = persistence_time_sec

        self._last_metrics: Optional[Dict[str, Any]] = None

    # ---------------------------------------------------------------------

    def ingest(self, bins_db: list[float], center_freq_hz: float) -> Dict[str, Any]:

        now = time.time()

        if self._current_freq != center_freq_hz:

            self._history.clear()

            self._current_freq = center_freq_hz

            self._freq_start_time = now

        # -------------------------------------------------------------
        # Persistence
        # -------------------------------------------------------------

        dwell = 0

        if self._freq_start_time:

            dwell = now - self._freq_start_time

        persistence_score = min(dwell / self._persistence_time, 1.0)

        persistent_mode = persistence_score >= 1.0

        if not bins_db:
            return {}

        spectrum_db = np.array(bins_db, dtype=np.float64)

        # -------------------------------------------------------------
        # Linear power conversion
        # -------------------------------------------------------------

        linear = np.power(10.0, spectrum_db / 10.0)

        linear = np.maximum(linear, 1e-12)

        # -------------------------------------------------------------
        # Spectral flatness
        # -------------------------------------------------------------

        geometric_mean = np.exp(np.mean(np.log(linear)))

        arithmetic_mean = np.mean(linear)

        flatness = float(geometric_mean / arithmetic_mean)

        # -------------------------------------------------------------
        # Noise floor
        # -------------------------------------------------------------

        noise_floor_db = float(np.percentile(spectrum_db, 30))

        # -------------------------------------------------------------
        # Variance
        # -------------------------------------------------------------

        variance = float(np.var(spectrum_db))

        # -------------------------------------------------------------
        # RF occupancy
        # -------------------------------------------------------------

        threshold = noise_floor_db + 6

        active_bins = np.sum(spectrum_db > threshold)

        occupancy = active_bins / len(spectrum_db)

        # -------------------------------------------------------------
        # Environment classification
        # -------------------------------------------------------------

        if occupancy < 0.05:
            env_class = "quiet"

        elif occupancy < 0.2:
            env_class = "normal"

        elif occupancy < 0.5:
            env_class = "dense"

        else:
            env_class = "jammed"

        metrics = {

            "env_noise_floor_db": round(noise_floor_db, 3),

            "env_spectral_flatness": round(flatness, 5),

            "env_spectral_variance": round(variance, 3),

            "env_rf_occupancy": round(occupancy, 3),

            "env_detection_threshold_db": round(noise_floor_db + 6, 3),

            "env_environment_class": env_class,

            "env_persistent_mode": persistent_mode,

            "env_persistence_score": round(persistence_score, 3)

        }

        self._history.append(metrics)

        self._last_metrics = metrics

        return metrics

    # ---------------------------------------------------------------------

    def get_state(self) -> Dict[str, Any]:

        return {

            "current_freq_hz": self._current_freq,

            "history_depth": len(self._history),

            "persistent_mode": (
                self._last_metrics.get("env_persistent_mode")
                if self._last_metrics
                else False
            ),

            "environment_class": (
                self._last_metrics.get("env_environment_class")
                if self._last_metrics
                else None
            ),
        }
