# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/targeting/targeting_engine.py
# VERSION:      v1.0.0 (SIGINT TARGET TRACKING ENGINE)
# UPDATED:      2026-03-25
# =============================================================================

from __future__ import annotations
import time
from typing import Dict, Any, List


class TargetingEngine:
    """
    Target Tracking Engine

    Tracks devices using fingerprint_id
    """

    VERSION = "1.0.0"

    def __init__(self):

        # 🔥 Targets you want to track
        self.targets: Dict[str, Dict[str, Any]] = {}

        # Runtime state
        self.active_targets: Dict[str, Dict[str, Any]] = {}

    # =========================================================================
    def add_target(self, fingerprint_id: str, label: str = "unknown"):
        self.targets[fingerprint_id] = {
            "label": label,
            "added_at": time.time()
        }

    # =========================================================================
    def process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        now = time.time()

        for e in events:

            fid = e.get("fingerprint_id")
            if not fid:
                continue

            if fid not in self.targets:
                continue

            target_info = self.targets[fid]

            state = self.active_targets.get(fid)
            rssi = e.get("rssi")

            if not state:
                state = {
                    "first_seen": now,
                    "last_seen": now,
                    "rssi_history": [],
                    "status": "new"
                }
                self.active_targets[fid] = state

            state["last_seen"] = now

            if isinstance(rssi, (int, float)):
                state["rssi_history"].append(rssi)
                if len(state["rssi_history"]) > 20:
                    state["rssi_history"] = state["rssi_history"][-20:]

            # 🔥 CLASSIFY PROXIMITY
            proximity = self._estimate_proximity(rssi)

            # 🔥 MOVEMENT DETECTION
            movement = self._detect_movement(state["rssi_history"])

            e["target"] = {
                "is_target": True,
                "label": target_info["label"],
                "proximity": proximity,
                "movement": movement
            }

        return events

    # =========================================================================
    def _estimate_proximity(self, rssi):

        if rssi is None:
            return "unknown"

        if rssi > -60:
            return "near"
        elif rssi > -75:
            return "mid"
        else:
            return "far"

    # =========================================================================
    def _detect_movement(self, rssi_list):

        if len(rssi_list) < 5:
            return "unknown"

        delta = max(rssi_list) - min(rssi_list)

        if delta > 10:
            return "moving"

        return "stable"
