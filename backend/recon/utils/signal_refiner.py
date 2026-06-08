# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       RF SIGNAL REFINEMENT ENGINE
# FILE:         backend/recon/utils/signal_refiner.py
#
# VERSION:      v2.0.0 (SIGINT SIGNAL REFINEMENT ENGINE)
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# HackRF SDR
#     ↓
# SDRController
#     ↓
# AdaptiveSweepController
#     ↓
# LiveFFT
#     ↓
# SpectralEnvironmentAnalyzer
#     ↓
# PeakDetector
#     ↓
# RFOFDMSuppressor
#     ↓
# EmitterClusterEngine
#     ↓
# RFChannelAggregator
#     ↓
# RFSignalRefiner        ← THIS MODULE
#     ↓
# RFSignalEnvelopeAnalyzer
#     ↓
# RFChannelNormalizer
#     ↓
# RFProtocolFingerprintEngine
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. SIGNAL STABILITY
# Emitters must remain stable even if spectral bins fluctuate.
#
# 2. FRAGMENT MERGING
# Adjacent spectral fragments belonging to the same emitter must be merged.
#
# 3. NOISE SUPPRESSION
# Very small spectral clusters are likely noise and should be discarded.
#
# 4. LOW CPU COST
# Must run continuously inside the SDR pipeline.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • merging fragmented RF channels
# • estimating center frequency
# • estimating signal bandwidth
# • suppressing noise emitters
#
# This module is NOT responsible for:
#
# • protocol detection
# • device classification
# • RF hardware control
#
# =============================================================================
# ENTERPRISE CODE CONVENTIONS
# =============================================================================
#
# • defensive input validation
# • deterministic emitter refinement
# • stable output schema
#
# =============================================================================

import statistics


class RFSignalRefiner:

    VERSION = "2.0.0"

    MIN_CHANNELS = 3
    MAX_GAP_MHZ = 2.0
    MIN_BANDWIDTH = 0.05

    # -------------------------------------------------------------------------
    # MAIN REFINEMENT
    # -------------------------------------------------------------------------

    def refine(self, emitters):

        if not emitters:
            return []

        refined = []

        for emitter in emitters:

            if not isinstance(emitter, dict):
                continue

            channels = emitter.get("rf_channels")

            if not channels or len(channels) < self.MIN_CHANNELS:
                refined.append(emitter)
                continue

            try:

                merged = self._merge_channels(sorted(channels))

                center = statistics.mean(merged)

                bandwidth = max(merged) - min(merged)

                if bandwidth < self.MIN_BANDWIDTH:
                    continue

                spread = statistics.pstdev(merged)

                refined_emitter = emitter.copy()

                refined_emitter["rf_center_freq"] = round(center, 6)
                refined_emitter["rf_bandwidth_estimate"] = round(bandwidth, 6)
                refined_emitter["rf_spectral_spread"] = round(spread, 6)

                refined.append(refined_emitter)

            except Exception:
                refined.append(emitter)

        return refined

    # -------------------------------------------------------------------------
    # CHANNEL MERGING
    # -------------------------------------------------------------------------

    def _merge_channels(self, channels):

        if not channels:
            return []

        merged = [channels[0]]

        for ch in channels[1:]:

            if abs(ch - merged[-1]) <= self.MAX_GAP_MHZ:
                merged.append(ch)

        return merged
