# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/environment/rf_heatmap_engine.py
# VERSION:      v1.0.0 (RF ENVIRONMENT HEATMAP INTELLIGENCE ENGINE)
# LAST UPDATED: 2026-03-09
#
# =============================================================================
# PROJECT CONTEXT
# =============================================================================
#
# RFHeatmapEngine models the RF environment over time by maintaining a
# frequency-domain activity map. It records where signals appear, how often
# they occur, and how persistent they are.
#
# This allows GhostRecon to move beyond simple signal detection and instead
# build an understanding of the RF ecosystem present in an environment.
#
# The heatmap enables advanced capabilities such as:
#
#   • RF activity density mapping
#   • persistent emitter detection
#   • channel occupancy modeling
#   • adaptive sweep prioritization
#   • anomaly detection
#
# RFHeatmapEngine operates independently of specific signals and instead
# observes the RF spectrum as a whole.
#
# =============================================================================
# COMPLETE ARCHITECTURE
# =============================================================================
#
# HackRF SDR
#     ↓
# SDRController
#     ↓
# LiveFFT
#     ↓
# ReconEngine
#     ├ emitter clustering
#     ├ RF feature extraction
#     ↓
# SignalEngine
#     ├ signal lifecycle
#     ├ protocol inference
#     ├ device intelligence
#     ↓
# RFHeatmapEngine (THIS FILE)
#     ├ frequency bin tracking
#     ├ RF activity density modeling
#     ├ persistence scoring
#     ├ anomaly detection
#     └ sweep prioritization signals
#     ↓
# AdaptiveSweepController (future)
#
# =============================================================================
# RESPONSIBILITIES
# =============================================================================
#
# RFHeatmapEngine IS responsible for:
#
# ✔ modeling RF activity across the spectrum
# ✔ tracking persistent emitters
# ✔ measuring channel occupancy
# ✔ identifying high-interest RF regions
# ✔ supporting adaptive scanning logic
#
# RFHeatmapEngine IS NOT responsible for:
#
# ✘ signal detection
# ✘ protocol inference
# ✘ device identification
# ✘ SDR hardware control
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# 1. PASSIVE SPECTRUM MODELING
# -----------------------------------------------------------------------------
# The engine observes signals but does not influence them. It passively
# accumulates RF observations into a long-term environmental model.
#
#
# 2. FREQUENCY BINNING
# -----------------------------------------------------------------------------
# RF spectrum is discretized into bins (default 1 MHz) to maintain a manageable
# heatmap representation.
#
#
# 3. TEMPORAL DECAY
# -----------------------------------------------------------------------------
# Older observations slowly decay so that the heatmap reflects recent RF
# activity rather than stale information.
#
#
# 4. LOW COMPUTE OVERHEAD
# -----------------------------------------------------------------------------
# Updates must remain lightweight so the heatmap can run continuously during
# real-time recon operations.
#
#
# 5. ADAPTIVE SCANNING SUPPORT
# -----------------------------------------------------------------------------
# The heatmap provides scoring signals used by future sweep controllers to
# prioritize interesting frequency regions.
#
# =============================================================================

import time
import threading
from typing import Dict, List


class RFHeatmapEngine:

    ENGINE_VERSION = "1.0.0"

    # Default bin size
    BIN_SIZE_MHZ = 1.0

    # Activity decay factor
    DECAY_FACTOR = 0.995

    # Minimum observation threshold
    ACTIVITY_THRESHOLD = 5

    # -------------------------------------------------------------------------
    # INIT
    # -------------------------------------------------------------------------

    def __init__(self):

        self.lock = threading.Lock()

        # frequency_bin -> activity data
        self.heatmap: Dict[int, Dict] = {}

        self.last_decay = time.time()

    # -------------------------------------------------------------------------
    # BIN HELPER
    # -------------------------------------------------------------------------

    def _freq_to_bin(self, freq_mhz: float) -> int:

        return int(freq_mhz // self.BIN_SIZE_MHZ)

    # -------------------------------------------------------------------------
    # UPDATE HEATMAP
    # -------------------------------------------------------------------------

    def observe_signal(self, signal: Dict):

        freq = signal.get("freq_mhz")

        if freq is None:
            return

        now = time.time()

        bin_id = self._freq_to_bin(freq)

        with self.lock:

            entry = self.heatmap.get(bin_id)

            if entry is None:

                entry = {
                    "bin": bin_id,
                    "center_freq_mhz": (bin_id + 0.5) * self.BIN_SIZE_MHZ,
                    "activity_score": 1.0,
                    "observations": 1,
                    "first_seen": now,
                    "last_seen": now,
                    "max_power": signal.get("power_db", -999),
                }

                self.heatmap[bin_id] = entry

            else:

                entry["activity_score"] += 1.0
                entry["observations"] += 1
                entry["last_seen"] = now

                power = signal.get("power_db")

                if power is not None:
                    entry["max_power"] = max(entry["max_power"], power)

    # -------------------------------------------------------------------------
    # DECAY OLD ACTIVITY
    # -------------------------------------------------------------------------

    def decay(self):

        now = time.time()

        with self.lock:

            for entry in self.heatmap.values():

                entry["activity_score"] *= self.DECAY_FACTOR

            self.last_decay = now

    # -------------------------------------------------------------------------
    # GET ACTIVE BINS
    # -------------------------------------------------------------------------

    def get_active_bins(self) -> List[Dict]:

        with self.lock:

            bins = [
                b for b in self.heatmap.values()
                if b["activity_score"] >= self.ACTIVITY_THRESHOLD
            ]

        bins.sort(key=lambda x: x["activity_score"], reverse=True)

        return bins

    # -------------------------------------------------------------------------
    # GET FULL HEATMAP
    # -------------------------------------------------------------------------

    def get_heatmap(self) -> List[Dict]:

        with self.lock:

            data = list(self.heatmap.values())

        data.sort(key=lambda x: x["center_freq_mhz"])

        return data

    # -------------------------------------------------------------------------
    # PRIORITY FREQUENCIES
    # -------------------------------------------------------------------------

    def get_priority_frequencies(self, limit: int = 10) -> List[float]:

        bins = self.get_active_bins()

        freqs = [b["center_freq_mhz"] for b in bins[:limit]]

        return freqs

    # -------------------------------------------------------------------------
    # ANOMALY DETECTION
    # -------------------------------------------------------------------------

    def detect_anomalies(self) -> List[Dict]:

        anomalies = []

        with self.lock:

            for entry in self.heatmap.values():

                if entry["observations"] < 3:
                    continue

                # sudden high power signals
                if entry["max_power"] > -20:

                    anomalies.append({
                        "freq_mhz": entry["center_freq_mhz"],
                        "reason": "high_power_emitter",
                        "power": entry["max_power"]
                    })

        return anomalies

    # -------------------------------------------------------------------------
    # ENGINE STATE
    # -------------------------------------------------------------------------

    def get_state(self):

        with self.lock:

            return {
                "engine_version": self.ENGINE_VERSION,
                "tracked_bins": len(self.heatmap),
                "last_decay": self.last_decay
            }
