# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       ADAPTIVE RF ENVIRONMENT CALIBRATION ENGINE
# FILE:         backend/recon/core/rf_environment_calibrator.py
#
# VERSION:      v1.0.0
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# RFEnvironmentCalibrator observes the RF spectrum and dynamically adapts
# detection thresholds used by the RF intelligence pipeline.
#
# RF PIPELINE
#
# HackRF SDR
#     ↓
# LiveFFT
#     ↓
# SpectralEnvironmentAnalyzer
#     ↓
# RFEnvironmentCalibrator   ← THIS MODULE
#     ↓
# PeakDetector
#     ↓
# BurstDetector
#     ↓
# EmitterCluster
#     ↓
# FeatureExtractor
#     ↓
# ProtocolClassifier
#
#
# The calibrator measures RF conditions such as:
#
# • noise floor
# • spectrum variance
# • peak density
# • band occupancy
#
# It then dynamically adjusts detection thresholds in ReconConfig.
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. NON-INTRUSIVE
# The calibrator does not alter signal detection directly.
#
# 2. ADAPTIVE THRESHOLDS
# Detection thresholds automatically adapt to RF conditions.
#
# 3. STABLE OPERATION
# Uses smoothing to prevent oscillating thresholds.
#
# 4. SDR-AWARE
# Designed for noisy SDR environments (HackRF / RTL-SDR).
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • monitoring spectrum noise levels
# • estimating RF environment conditions
# • calibrating detection thresholds
#
#
# This module is NOT responsible for:
#
# • detecting RF peaks
# • clustering emitters
# • protocol classification
#
# =============================================================================

import statistics
import logging
import time

from backend.recon.configuration import ReconConfig


class RFEnvironmentCalibrator:

    VERSION = "1.0.0"

    # calibration window
    WINDOW_SIZE = 20

    # update interval
    UPDATE_INTERVAL = 2.0

    def __init__(self):

        self.logger = logging.getLogger("ghostrecon.environment")

        self.noise_history = []
        self.power_history = []
        self.peak_history = []

        self.last_update = 0

    # -------------------------------------------------------------------------
    # INGEST FFT FRAME
    # -------------------------------------------------------------------------

    def ingest(self, bins):

        if not bins:
            return

        try:

            noise = statistics.median(bins)
            power = statistics.mean(bins)

            self.noise_history.append(noise)
            self.power_history.append(power)

            if len(self.noise_history) > self.WINDOW_SIZE:
                self.noise_history.pop(0)
                self.power_history.pop(0)

        except Exception as e:

            self.logger.warning("Calibration ingest error: %s", e)

    # -------------------------------------------------------------------------
    # RECORD PEAK DENSITY
    # -------------------------------------------------------------------------

    def record_peaks(self, peak_count, fft_size):

        if fft_size == 0:
            return

        density = peak_count / fft_size

        self.peak_history.append(density)

        if len(self.peak_history) > self.WINDOW_SIZE:
            self.peak_history.pop(0)

    # -------------------------------------------------------------------------
    # CALIBRATION UPDATE
    # -------------------------------------------------------------------------

    def update(self):

        now = time.time()

        if now - self.last_update < self.UPDATE_INTERVAL:
            return

        self.last_update = now

        if len(self.noise_history) < 5:
            return

        try:

            avg_noise = statistics.mean(self.noise_history)
            avg_power = statistics.mean(self.power_history)

            if self.peak_history:
                avg_density = statistics.mean(self.peak_history)
            else:
                avg_density = 0

            self._adjust_thresholds(avg_noise, avg_power, avg_density)

        except Exception as e:

            self.logger.warning("Calibration update failed: %s", e)

    # -------------------------------------------------------------------------
    # THRESHOLD ADJUSTMENT
    # -------------------------------------------------------------------------

    def _adjust_thresholds(self, noise, power, peak_density):

        # estimated SNR
        snr = abs(power - noise)

        # dynamic SNR threshold
        if snr < 1:
            ReconConfig.SNR_BASE_THRESHOLD = 6.0

        elif snr < 2:
            ReconConfig.SNR_BASE_THRESHOLD = 5.0

        elif snr < 4:
            ReconConfig.SNR_BASE_THRESHOLD = 4.0

        else:
            ReconConfig.SNR_BASE_THRESHOLD = 3.5

        # adjust CFAR window based on density
        if peak_density > 0.1:

            ReconConfig.CFAR_NOISE_CELLS = min(
                ReconConfig.CFAR_NOISE_CELLS + 4,
                64
            )

        elif peak_density < 0.01:

            ReconConfig.CFAR_NOISE_CELLS = max(
                ReconConfig.CFAR_NOISE_CELLS - 2,
                16
            )

        # logging
        self.logger.debug(
            "RF calibration update | noise=%.2f power=%.2f density=%.3f snr=%.2f",
            noise,
            power,
            peak_density,
            snr
        )

    # -------------------------------------------------------------------------
    # ENVIRONMENT SNAPSHOT
    # -------------------------------------------------------------------------

    def get_environment_state(self):

        if not self.noise_history:
            return {}

        return {

            "noise_floor": statistics.mean(self.noise_history),
            "avg_power": statistics.mean(self.power_history),
            "peak_density": statistics.mean(self.peak_history) if self.peak_history else 0,
            "snr_threshold": ReconConfig.SNR_BASE_THRESHOLD,
            "cfar_noise_cells": ReconConfig.CFAR_NOISE_CELLS
        }
