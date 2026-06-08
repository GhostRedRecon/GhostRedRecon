# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF SIGNAL ENVELOPE ANALYZER
# FILE:         backend/recon/features/envelope_analyzer.py
#
# VERSION:      v2.0.0
# UPDATED:      2026-03-12
# AUTHOR:       GhostRecon RF Intelligence Layer
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# The RFSignalEnvelopeAnalyzer extracts spectral envelope features from
# clustered RF emitters.
#
# Spectral peaks often represent fragmented views of the underlying
# RF transmission. This module compresses those fragments into
# compact signal intelligence features.
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
# RFSignalEnvelopeAnalyzer        ← THIS MODULE
#     ↓
# ChannelNormalizer
#     ↓
# ModulationDetector
#     ↓
# FeatureExtractor
#
#
# The envelope analyzer extracts:
#
# • signal bandwidth
# • spectral centroid
# • spectral spread
# • spectral entropy
# • spectral flatness
# • carrier density
# • peak spacing
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. SPECTRAL COMPRESSION
# -----------------------------------------------------------------------------
# Large rf_channels lists are compressed into compact RF feature vectors.
#
#
# 2. MODULATION AWARENESS
# -----------------------------------------------------------------------------
# Spectral patterns reveal modulation families such as OFDM, DSSS,
# narrowband, and chirp-based signals.
#
#
# 3. LOW CPU COST
# -----------------------------------------------------------------------------
# Analysis must remain lightweight to support real-time SDR scanning.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • computing spectral envelope statistics
# • estimating carrier density
# • detecting spectral grids
# • generating modulation hints
#
#
# This module is NOT responsible for:
#
# • protocol classification
# • device inference
# • vendor inference
#
#
# =============================================================================
# VERSIONING STRATEGY
# =============================================================================
#
# v1.x
#     basic spectral envelope features
#
# v2.x
#     entropy analysis
#     spectral flatness
#     carrier spacing detection
#
#
# =============================================================================
# ENTERPRISE CODE CONVENTIONS
# =============================================================================
#
# • deterministic spectral metrics
# • minimal CPU overhead
# • safe numerical handling
#
# =============================================================================

import numpy as np
import statistics


class RFSignalEnvelopeAnalyzer:

    VERSION = "2.0.0"

    # -------------------------------------------------------------------------

    def analyze(self, emitter):

        rf_channels = emitter.get("rf_channels")

        if not rf_channels or len(rf_channels) < 3:
            return {}

        try:

            channels = np.array(sorted(rf_channels))

            bandwidth = float(np.max(channels) - np.min(channels))

            centroid = float(np.mean(channels))

            spread = float(np.std(channels))

            density = len(channels) / max(bandwidth, 0.001)

            entropy = self._spectral_entropy(channels)

            flatness = self._spectral_flatness(channels)

            spacing = self._peak_spacing(channels)

            modulation = self._detect_modulation(
                bandwidth,
                density,
                flatness,
                spacing
            )

            return {

                "rf_bandwidth_mhz": round(bandwidth, 3),

                "rf_spectral_centroid": round(centroid, 3),

                "rf_spectral_spread": round(spread, 3),

                "rf_carrier_density": round(density, 3),

                "rf_spectral_entropy": round(entropy, 3),

                "rf_spectral_flatness": round(flatness, 3),

                "rf_peak_spacing": round(spacing, 4),

                "rf_modulation_hint": modulation

            }

        except Exception:

            return {}

    # -------------------------------------------------------------------------

    def _spectral_entropy(self, channels):

        hist, _ = np.histogram(channels, bins=10, density=True)

        hist = hist[hist > 0]

        entropy = -np.sum(hist * np.log(hist))

        return float(entropy)

    # -------------------------------------------------------------------------

    def _spectral_flatness(self, channels):

        geo = np.exp(np.mean(np.log(channels + 1e-9)))

        arith = np.mean(channels + 1e-9)

        return float(geo / arith)

    # -------------------------------------------------------------------------

    def _peak_spacing(self, channels):

        if len(channels) < 2:
            return 0

        diffs = np.diff(channels)

        return float(np.mean(diffs))

    # -------------------------------------------------------------------------

    def _detect_modulation(self, bandwidth, density, flatness, spacing):

        if bandwidth > 10 and flatness > 0.6 and density > 0.5:
            return "OFDM"

        if spacing > 0.1 and spacing < 1:
            return "DSSS"

        if bandwidth < 1:
            return "NARROWBAND"

        return "UNKNOWN"
