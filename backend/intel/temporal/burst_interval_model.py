# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/temporal/burst_interval_model.py
# VERSION:      v1.0.0 (TEMPORAL INTELLIGENCE CORE)
# LAST UPDATED: 2026-02-26
#
# =============================================================================
# PURPOSE
# =============================================================================
# Computes high-resolution burst interval intelligence per emitter.
#
# Produces:
#   - mean_interval
#   - interval_std
#   - coefficient_of_variation
#   - interval_entropy
#   - precision_ratio
#   - burst_rate_per_min
#
# Designed to separate:
#   - Smart meters
#   - Industrial telemetry
#   - Weather sensors
#   - BLE beacons
#   - Remotes
#   - Mesh nodes
# =============================================================================

from __future__ import annotations
import math
import time
from typing import Dict, List


class BurstIntervalModel:

    def __init__(self, max_history: int = 200):
        self._timestamps: Dict[str, List[float]] = {}
        self._max_history = max_history

    # -------------------------------------------------------------------------
    # UPDATE
    # -------------------------------------------------------------------------

    def update(self, emitter_id: str, timestamp: float):

        history = self._timestamps.setdefault(emitter_id, [])
        history.append(timestamp)

        if len(history) > self._max_history:
            history.pop(0)

    # -------------------------------------------------------------------------
    # PROFILE
    # -------------------------------------------------------------------------

    def profile(self, emitter_id: str) -> Dict[str, float]:

        history = self._timestamps.get(emitter_id, [])

        if len(history) < 5:
            return {}

        intervals = [
            history[i] - history[i - 1]
            for i in range(1, len(history))
        ]

        if not intervals:
            return {}

        mean_interval = sum(intervals) / len(intervals)

        variance = sum(
            (x - mean_interval) ** 2 for x in intervals
        ) / len(intervals)

        std = math.sqrt(variance)

        if mean_interval > 0:
            coeff_var = std / mean_interval
        else:
            coeff_var = 0.0

        entropy = self._compute_entropy(intervals)

        precision_ratio = self._precision_ratio(intervals)

        burst_rate = 60.0 / mean_interval if mean_interval > 0 else 0

        return {
            "mean_interval_sec": round(mean_interval, 4),
            "interval_std_sec": round(std, 4),
            "interval_cv": round(coeff_var, 4),
            "interval_entropy": round(entropy, 4),
            "interval_precision_ratio": round(precision_ratio, 4),
            "burst_rate_per_min": round(burst_rate, 2),
        }

    # -------------------------------------------------------------------------
    # ENTROPY
    # -------------------------------------------------------------------------

    def _compute_entropy(self, intervals: List[float]) -> float:

        if len(intervals) < 5:
            return 0.0

        rounded = [round(x, 2) for x in intervals]
        freq = {}

        for value in rounded:
            freq[value] = freq.get(value, 0) + 1

        total = len(rounded)

        entropy = 0.0

        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

    # -------------------------------------------------------------------------
    # PRECISION RATIO
    # -------------------------------------------------------------------------

    def _precision_ratio(self, intervals: List[float]) -> float:

        """
        Measures how many intervals are near the dominant interval.
        High value (~1.0) = extremely precise periodic signal.
        Low value (~0.0) = highly irregular.
        """

        if len(intervals) < 5:
            return 0.0

        rounded = [round(x, 2) for x in intervals]

        dominant = max(set(rounded), key=rounded.count)

        match_count = sum(
            1 for x in rounded if abs(x - dominant) < 0.02
        )

        return match_count / len(intervals)
