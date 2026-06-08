"""Stable identity tracker for RF emitter candidates."""

from __future__ import annotations

import itertools
import time
from typing import Iterable


class EmitterTracker:
    """Maintain stable emitter identities across cluster updates."""

    def __init__(self) -> None:
        self.tracked: list[dict] = []
        self._id_gen = itertools.count()
        self.freq_tolerance_mhz = 1.5
        self.min_confidence = 2
        self.max_idle_time = 3.0

    def update(self, emitters: Iterable[dict]) -> list[dict]:
        now = time.time()
        for emitter in emitters or []:
            matched = False
            for tracked in self.tracked:
                if abs(float(emitter["freq_mhz"]) - float(tracked["freq_mhz"])) < self.freq_tolerance_mhz:
                    self._update_tracked(tracked, emitter, now)
                    matched = True
                    break
            if not matched:
                self.tracked.append(self._create_tracked(emitter, now))

        self._cleanup(now)
        return list(self.tracked)

    def _create_tracked(self, emitter: dict, now: float) -> dict:
        return {
            "id": next(self._id_gen),
            "first_seen": now,
            "last_seen": now,
            "freq_mhz": float(emitter["freq_mhz"]),
            "confidence": 1,
            "burst_count": int(emitter.get("burst_count", 1)),
            "avg_power": float(emitter["avg_power"]),
            "peak_power": float(emitter["peak_power"]),
        }

    @staticmethod
    def _update_tracked(tracked: dict, emitter: dict, now: float) -> None:
        tracked["last_seen"] = now
        tracked["confidence"] += 1
        tracked["freq_mhz"] = float(tracked["freq_mhz"]) * 0.7 + float(emitter["freq_mhz"]) * 0.3
        tracked["burst_count"] += int(emitter.get("burst_count", 1))
        tracked["peak_power"] = max(float(tracked["peak_power"]), float(emitter["peak_power"]))
        tracked["avg_power"] = (float(tracked["avg_power"]) + float(emitter["avg_power"])) / 2

    def _cleanup(self, now: float) -> None:
        self.tracked = [
            item
            for item in self.tracked
            if now - float(item["last_seen"]) <= self.max_idle_time and int(item["confidence"]) >= self.min_confidence
        ]
