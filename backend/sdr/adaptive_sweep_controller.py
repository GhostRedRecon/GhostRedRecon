# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/sdr/adaptive_sweep_controller.py
# VERSION:      v1.0.0 (ADAPTIVE RF SWEEP INTELLIGENCE CONTROLLER)
# LAST UPDATED: 2026-03-09
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# AdaptiveSweepController dynamically selects RF frequencies to scan based on
# observed RF activity within the environment.
#
# Traditional SDR scanners use fixed sweep lists:
#
#   433 → 868 → 915 → 2.4GHz
#
# This wastes time scanning empty spectrum.
#
# AdaptiveSweepController instead uses intelligence from RFHeatmapEngine to:
#
#   • prioritize active frequencies
#   • revisit persistent emitters
#   • explore unknown spectrum
#
# This allows GhostRecon to behave like a real RF reconnaissance system.
#
# =============================================================================
# COMPLETE ARCHITECTURE
# =============================================================================
#
# HackRF SDR
#     ↓
# SDRController
#     ↓
# AdaptiveSweepController (THIS FILE)
#     ↓
# frequency selection
#     ↓
# LiveFFT
#     ↓
# ReconEngine
#     ↓
# SignalEngine
#     ↓
# RFHeatmapEngine
#     ↓
# AdaptiveSweepController (feedback loop)
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# AdaptiveSweepController IS responsible for:
#
# ✔ selecting next frequency to scan
# ✔ prioritizing active RF regions
# ✔ balancing exploration vs exploitation
# ✔ avoiding wasted sweeps
#
# AdaptiveSweepController is NOT responsible for:
#
# ✘ RF signal detection
# ✘ device inference
# ✘ RF fingerprinting
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. INTELLIGENCE DRIVEN SWEEPING
# -----------------------------------------------------------------------------
# Frequency scanning decisions should be driven by observed RF activity.
#
#
# 2. EXPLORE vs EXPLOIT
# -----------------------------------------------------------------------------
# The controller balances:
#
# exploit → revisit known active frequencies
# explore → scan new spectrum
#
#
# 3. HEATMAP FEEDBACK LOOP
# -----------------------------------------------------------------------------
# RFHeatmapEngine informs the controller where signals are likely to appear.
#
#
# 4. SDR FRIENDLY
# -----------------------------------------------------------------------------
# The system avoids excessive frequency hopping which can destabilize SDR
# hardware.
#
# =============================================================================

import random
import time
from typing import List


class AdaptiveSweepController:

    CONTROLLER_VERSION = "1.0.0"

    # default fallback sweep bands
    DEFAULT_SCAN_BANDS = [
        315.0,
        433.92,
        868.3,
        915.0,
        2402.0,
        2426.0,
        2462.0
    ]

    EXPLORE_RATIO = 0.30

    # -------------------------------------------------------------------------
    # INIT
    # -------------------------------------------------------------------------

    def __init__(self, heatmap_engine):

        self.heatmap_engine = heatmap_engine

        self.last_frequency = None
        self.last_scan_time = 0

    # -------------------------------------------------------------------------
    # NEXT FREQUENCY
    # -------------------------------------------------------------------------

    def next_frequency(self) -> float:

        active_bins = self.heatmap_engine.get_active_bins()

        explore = random.random() < self.EXPLORE_RATIO

        # -------------------------------------------------------------
        # EXPLORE NEW FREQUENCIES
        # -------------------------------------------------------------

        if explore or not active_bins:

            freq = random.choice(self.DEFAULT_SCAN_BANDS)

            self.last_frequency = freq
            self.last_scan_time = time.time()

            return freq

        # -------------------------------------------------------------
        # EXPLOIT KNOWN ACTIVE REGIONS
        # -------------------------------------------------------------

        best_bin = active_bins[0]

        freq = best_bin["center_freq_mhz"]

        self.last_frequency = freq
        self.last_scan_time = time.time()

        return freq

    # -------------------------------------------------------------------------
    # FULL SWEEP PLAN
    # -------------------------------------------------------------------------

    def get_sweep_plan(self, limit: int = 10) -> List[float]:

        active = self.heatmap_engine.get_priority_frequencies(limit)

        plan = []

        for f in active:
            plan.append(f)

        while len(plan) < limit:

            plan.append(random.choice(self.DEFAULT_SCAN_BANDS))

        return plan

    # -------------------------------------------------------------------------
    # CONTROLLER STATE
    # -------------------------------------------------------------------------

    def get_state(self):

        return {
            "controller_version": self.CONTROLLER_VERSION,
            "last_frequency": self.last_frequency,
            "last_scan_time": self.last_scan_time
        }
