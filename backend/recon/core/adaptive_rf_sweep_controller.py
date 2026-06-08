# =============================================================================
# PROJECT:      GHOSTRECON
# MODULE:       ADAPTIVE RF SWEEP CONTROLLER
# FILE:         backend/recon/core/adaptive_rf_sweep_controller.py
#
# VERSION:      v1.0.0
# UPDATED:      2026-03-12
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
#
# AdaptiveRFSweepController dynamically optimizes SDR scanning order
# based on RF activity intelligence.
#
# Traditional scanners sweep frequencies sequentially which wastes time
# on inactive spectrum.
#
# This controller prioritizes high-activity frequencies to maximize
# device discovery efficiency.
#
#
# RF PROCESSING PIPELINE
#
# ReconEngine
#     ↓
# RFGraphIntelligence
#     ↓
# AdaptiveRFSweepController   ← THIS MODULE
#     ↓
# SDRController.retune()
#
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. ACTIVITY PRIORITIZATION
# -----------------------------------------------------------------------------
# Frequencies with higher RF activity are scanned more frequently.
#
#
# 2. FAST DISCOVERY
# -----------------------------------------------------------------------------
# Hot channels are revisited quickly.
#
#
# 3. SDR SAFE OPERATION
# -----------------------------------------------------------------------------
# Retuning frequency respects SDR stabilization time.
#
#
# 4. RED TEAM OPTIMIZATION
# -----------------------------------------------------------------------------
# Focus on WiFi, BLE, IoT and Sub-GHz control bands.
#
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# This module IS responsible for:
#
# • ranking RF channels by activity
# • optimizing scan order
# • scheduling SDR retunes
#
#
# This module is NOT responsible for:
#
# • RF signal detection
# • protocol classification
#
# =============================================================================

import time


class AdaptiveRFSweepController:

    VERSION = "1.0.0"

    DEFAULT_DWELL = 60

    def __init__(self, sdr_controller):

        self.sdr = sdr_controller

        self.activity_scores = {}

        self.scan_frequencies = [
            433.92,
            868.3,
            915.0,
            2402,
            2412,
            2426,
            2437,
            2462,
            2480
        ]

        self.last_tune = None

    # ---------------------------------------------------------------------

    def update_activity(self, freq, score):

        if freq not in self.activity_scores:
            self.activity_scores[freq] = score
        else:
            self.activity_scores[freq] = (
                0.7 * self.activity_scores[freq]
                + 0.3 * score
            )

    # ---------------------------------------------------------------------

    def next_frequency(self):

        if not self.activity_scores:
            return self.scan_frequencies[0]

        ranked = sorted(
            self.scan_frequencies,
            key=lambda f: self.activity_scores.get(f, 0),
            reverse=True
        )

        return ranked[0]

    # ---------------------------------------------------------------------

    def tune_next(self):

        freq = self.next_frequency()

        self.sdr.start(freq_mhz=freq)

        self.last_tune = time.time()

        return freq
