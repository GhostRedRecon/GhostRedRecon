# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/alerts/alert_engine.py
# VERSION:      v1.0.0 (SIGINT ALERT ENGINE)
# UPDATED:      2026-03-25
# =============================================================================

from __future__ import annotations
import time
from typing import Dict, Any, List


class AlertEngine:
    """
    Alert Engine

    Generates alerts based on target tracking
    """

    VERSION = "1.0.0"

    def __init__(self):

        self.last_seen: Dict[str, float] = {}
        self.alert_cooldown = 5.0

    # =========================================================================
    def process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        now = time.time()

        for e in events:

            target = e.get("target")
            if not target:
                continue

            fid = e.get("fingerprint_id")
            if not fid:
                continue

            last = self.last_seen.get(fid, 0)

            if now - last < self.alert_cooldown:
                continue

            self.last_seen[fid] = now

            self._emit_alert(e)

        return events

    # =========================================================================
    def _emit_alert(self, event):

        target = event["target"]
        fid = event.get("fingerprint_id")

        print("\n🚨 TARGET ALERT 🚨")
        print(f"Fingerprint: {fid}")
        print(f"Label: {target['label']}")
        print(f"Proximity: {target['proximity']}")
        print(f"Movement: {target['movement']}")
        print(f"RSSI: {event.get('rssi')}")
        print("-" * 40)
