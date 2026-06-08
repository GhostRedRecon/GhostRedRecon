# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/models/signal_record.py
# VERSION:      v8.0.0 (LIFECYCLE-AWARE SIGNAL ENTITY)
# LAST UPDATED: 2026-02-24
#
# =============================================================================
# ARCHITECTURE OVERVIEW
# =============================================================================
# Encapsulates signal lifecycle, scoring, and intelligence metadata.
#
# DESIGN PRINCIPLES:
#   ✔ Deterministic lifecycle transitions
#   ✔ Backward-compatible JSON contract
#   ✔ Encapsulated state mutation
#   ✔ Thread-safe mutation handled by SignalEngine
# =============================================================================

import time
from typing import Dict, Any, List
from .signal_state import SignalState


class SignalRecord:

    def __init__(self, signal_id: str):
        now = time.time()

        self.signal_id = signal_id
        self.first_seen = now
        self.last_seen = now

        self.hit_count = 0
        self.state = SignalState.NEW
        self.stability_score = 0.0

        self.data: Dict[str, Any] = {}
        self.entropy_history: List[float] = []
        self.bitstream_history: List[str] = []

    # -------------------------------------------------------------------------

    def update_timestamp(self):
        self.last_seen = time.time()
        self.hit_count += 1

    # -------------------------------------------------------------------------

    def transition(self, new_state: SignalState):
        self.state = new_state

    # -------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        Backward-compatible export format.
        """
        base = {
            "signal_id": self.signal_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hit_count": self.hit_count,
            "lifecycle_state": self.state.value,
            "stability_score": round(self.stability_score, 3),
        }

        base.update(self.data)
        return base
