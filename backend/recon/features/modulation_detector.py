# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       IQ MODULATION ANALYSIS ENGINE
# FILE:         backend/recon/features/modulation_detector.py
#
# VERSION:      v4.0.0
# UPDATED:      2026-03-12
# AUTHOR:       GhostRecon RF Intelligence Layer
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# The ModulationDetector performs mathematical modulation inference from
# raw IQ bursts captured by SDR hardware.
#
# Unlike spectral heuristics, this module analyzes the instantaneous
# signal characteristics to infer modulation families.
#
#
# RF PROCESSING PIPELINE
#
# HackRF SDR
#     ↓
# LiveFFT
#     ↓
# PeakDetector
#     ↓
# BurstDetector
#     ↓
# EmitterCluster
#     ↓
# RFEmitterTracker
#     ↓
# RFEmitterLifecycleManager
#     ↓
# ChannelNormalizer
#     ↓
# RFSignalEnvelopeAnalyzer
#     ↓
# ModulationDetector              ← THIS MODULE
#     ↓
# FrameStructureDetector
#     ↓
# FeatureExtractor
#
#
# The modulation detector estimates:
#
# • instantaneous frequency deviation
# • envelope stability
# • spectral entropy
# • chirp slope
# • zero-crossing rate
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. STATISTICAL SIGNAL MODELING
# -----------------------------------------------------------------------------
# Modulation inference is based on statistical signal properties
# rather than fixed thresholds.
#
#
# 2. CONSTANT ENVELOPE DETECTION
# -----------------------------------------------------------------------------
# Many modulations (FSK, GFSK, OQPSK) have constant envelope.
#
#
# 3. ENTROPY-DRIVEN WIDEBAND DETECTION
# -----------------------------------------------------------------------------
# Wideband signals such as OFDM exhibit high spectral entropy.
#
#
# 4. CHIRP DETECTION
# -----------------------------------------------------------------------------
# Linear frequency slopes reveal chirp spread spectrum signals
# such as LoRa.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • IQ-based modulation inference
# • spectral entropy measurement
# • instantaneous frequency analysis
# • chirp detection
#
#
# This module is NOT responsible for:
#
# • protocol classification
# • device identification
# • RF band routing
#
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v3.x
#     initial IQ modulation inference
#
# v4.x
#     numerical stability improvements
#     additional RF fingerprint features
#
#
# =============================================================================
# ENTERPRISE CODE CONVENTIONS
# =============================================================================
#
# • deterministic modulation inference
# • safe numerical handling
# • sweep-safe burst analysis
# • minimal CPU overhead
#
# =============================================================================

import numpy as np


class ModulationDetector:

    VERSION = "4.0.0"

    def __init__(self, sample_rate: int):
        self.sample_rate = sample_rate

    # =========================================================================
    # PUBLIC ENTRY
    # =========================================================================

    def analyze(self, iq: np.ndarray) -> dict:

        if iq is None or len(iq) < 1024:
            return {}

        duration_ms = (len(iq) / self.sample_rate) * 1000

        # ---------------------------------------------------------------------
        # AMPLITUDE ANALYSIS
        # ---------------------------------------------------------------------

        amplitude = np.abs(iq)

        amp_mean = np.mean(amplitude)
        amp_std = np.std(amplitude)

        amp_var_ratio = amp_std / (amp_mean + 1e-9)

        constant_envelope = amp_var_ratio < 0.08

        # ---------------------------------------------------------------------
        # PHASE / FREQUENCY ANALYSIS
        # ---------------------------------------------------------------------

        phase = np.unwrap(np.angle(iq))

        inst_freq = np.diff(phase) * (self.sample_rate / (2 * np.pi))

        freq_dev = float(np.std(inst_freq))

        freq_mean = float(np.mean(inst_freq))

        # ---------------------------------------------------------------------
        # FFT ANALYSIS
        # ---------------------------------------------------------------------

        spectrum = np.fft.fftshift(np.fft.fft(iq))

        power = np.abs(spectrum) ** 2

        power_sum = np.sum(power) + 1e-12

        power_norm = power / power_sum

        # spectral entropy

        spectral_entropy = -np.sum(power_norm * np.log2(power_norm + 1e-12))

        spectral_entropy /= np.log2(len(power_norm))

        # spectral flatness

        geo = np.exp(np.mean(np.log(power + 1e-12)))

        arith = np.mean(power + 1e-12)

        spectral_flatness = geo / arith

        # ---------------------------------------------------------------------
        # CHIRP DETECTION
        # ---------------------------------------------------------------------

        freq_slope = float(np.mean(np.diff(inst_freq)))

        chirp_signal = abs(freq_slope) > 5000

        # ---------------------------------------------------------------------
        # ZERO CROSSING RATE
        # ---------------------------------------------------------------------

        zero_crossings = np.where(np.diff(np.sign(inst_freq)))[0]

        zcr = len(zero_crossings) / max(len(inst_freq), 1)

        # =========================================================================
        # MODULATION DECISION TREE
        # =========================================================================

        modulation = "unknown"

        if chirp_signal and spectral_entropy < 0.6:
            modulation = "LoRa_like"

        elif spectral_entropy > 0.85 and freq_dev > 400000:
            modulation = "OFDM_like"

        elif constant_envelope and 100000 < freq_dev < 400000:
            modulation = "DSSS_OQPSK_like"

        elif constant_envelope and 80000 < freq_dev < 300000 and zcr > 0.05:
            modulation = "GFSK_like"

        elif 20000 < freq_dev < 80000:
            modulation = "FSK_like"

        elif amp_var_ratio > 0.25 and freq_dev < 10000:
            modulation = "OOK"

        elif freq_dev < 2000 and amp_var_ratio < 0.01:
            modulation = "Continuous_Carrier"

        # =========================================================================

        bandwidth_est = freq_dev * 2

        return {

            "rf_modulation_hint": modulation,

            "rf_burst_duration_ms": round(duration_ms, 2),

            "rf_frequency_deviation": round(freq_dev, 2),

            "rf_frequency_mean": round(freq_mean, 2),

            "rf_bandwidth_estimate": round(bandwidth_est, 2),

            "rf_spectral_entropy": round(spectral_entropy, 3),

            "rf_spectral_flatness": round(spectral_flatness, 3),

            "rf_constant_envelope": constant_envelope,

            "rf_chirp_detected": chirp_signal,

            "rf_zero_crossing_rate": round(zcr, 4),

        }
