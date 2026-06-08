"""Temporal burst detector for RF peaks."""

from __future__ import annotations

import itertools
import time
from typing import Iterable


class BurstDetector:
    """Link nearby spectral peaks across frames into short RF bursts."""

    def __init__(self) -> None:
        self.active_bursts: list[dict] = []
        self.completed_bursts: list[dict] = []
        self._id_gen = itertools.count()
        self.freq_tolerance_mhz = 0.5
        self.timeout_sec = 0.3
        self.min_hits = 2

    def update(self, peaks: Iterable[dict]) -> list[dict]:
        now = time.time()

        for peak in peaks or []:
            matched = False
            for burst in self.active_bursts:
                if abs(float(peak["freq_mhz"]) - float(burst["freq_mhz"])) < self.freq_tolerance_mhz:
                    self._update_burst(burst, peak, now)
                    matched = True
                    break
            if not matched:
                self.active_bursts.append(self._create_burst(peak, now))

        self._cleanup(now)
        completed = self.completed_bursts[:]
        self.completed_bursts.clear()
        return completed

    def _create_burst(self, peak: dict, now: float) -> dict:
        power = float(peak["power"])
        return {
            "id": next(self._id_gen),
            "start_time": now,
            "last_seen": now,
            "freq_mhz": float(peak["freq_mhz"]),
            "peak_power": power,
            "avg_power": power,
            "num_hits": 1,
        }

    @staticmethod
    def _update_burst(burst: dict, peak: dict, now: float) -> None:
        power = float(peak["power"])
        burst["last_seen"] = now
        burst["num_hits"] += 1
        burst["peak_power"] = max(float(burst["peak_power"]), power)
        burst["avg_power"] = ((float(burst["avg_power"]) * (burst["num_hits"] - 1)) + power) / burst["num_hits"]
        burst["freq_mhz"] = float(burst["freq_mhz"]) * 0.7 + float(peak["freq_mhz"]) * 0.3

    def _cleanup(self, now: float) -> None:
        still_active: list[dict] = []
        for burst in self.active_bursts:
            if now - float(burst["last_seen"]) > self.timeout_sec:
                if int(burst["num_hits"]) >= self.min_hits:
                    self.completed_bursts.append(burst)
            else:
                still_active.append(burst)
        self.active_bursts = still_active
