"""Lifecycle filtering for tracked RF emitters."""

from __future__ import annotations

import time
from typing import Iterable


class EmitterLifecycle:
    """Convert tracked emitters into active signal records."""

    def __init__(self) -> None:
        self.active_timeout = 1.0
        self.stale_timeout = 3.0

    def process(self, tracked_emitters: Iterable[dict]) -> list[dict]:
        now = time.time()
        active_signals: list[dict] = []

        for emitter in tracked_emitters or []:
            age = now - float(emitter["last_seen"])
            if age < self.active_timeout:
                emitter["state"] = "ACTIVE"
                active_signals.append(
                    {
                        "id": emitter["id"],
                        "freq_mhz": float(emitter["freq_mhz"]),
                        "power": float(emitter["avg_power"]),
                        "state": "ACTIVE",
                    }
                )
            elif age < self.stale_timeout:
                emitter["state"] = "STALE"
            else:
                emitter["state"] = "DEAD"

        return active_signals
