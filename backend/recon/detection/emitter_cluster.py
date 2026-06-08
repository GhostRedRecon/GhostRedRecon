"""Cluster RF bursts into active emitter candidates."""

from __future__ import annotations

import itertools
import time
from typing import Iterable


class EmitterCluster:
    """Aggregate completed bursts into persistent emitter candidates."""

    def __init__(self) -> None:
        self.emitters: list[dict] = []
        self._id_gen = itertools.count()
        self.freq_tolerance_mhz = 1.0
        self.inactivity_timeout = 2.0

    def update(self, bursts: Iterable[dict]) -> list[dict]:
        now = time.time()
        for burst in bursts or []:
            matched = False
            for emitter in self.emitters:
                if abs(float(burst["freq_mhz"]) - float(emitter["freq_mhz"])) < self.freq_tolerance_mhz:
                    self._update_emitter(emitter, burst, now)
                    matched = True
                    break
            if not matched:
                self.emitters.append(self._create_emitter(burst, now))

        self._cleanup(now)
        return list(self.emitters)

    def _create_emitter(self, burst: dict, now: float) -> dict:
        return {
            "id": next(self._id_gen),
            "first_seen": now,
            "last_seen": now,
            "freq_mhz": float(burst["freq_mhz"]),
            "burst_count": 1,
            "avg_power": float(burst["avg_power"]),
            "peak_power": float(burst["peak_power"]),
        }

    @staticmethod
    def _update_emitter(emitter: dict, burst: dict, now: float) -> None:
        emitter["last_seen"] = now
        emitter["burst_count"] += 1
        emitter["peak_power"] = max(float(emitter["peak_power"]), float(burst["peak_power"]))
        emitter["avg_power"] = (
            float(emitter["avg_power"]) * (emitter["burst_count"] - 1) + float(burst["avg_power"])
        ) / emitter["burst_count"]
        emitter["freq_mhz"] = float(emitter["freq_mhz"]) * 0.8 + float(burst["freq_mhz"]) * 0.2

    def _cleanup(self, now: float) -> None:
        self.emitters = [
            emitter for emitter in self.emitters if now - float(emitter["last_seen"]) < self.inactivity_timeout
        ]
