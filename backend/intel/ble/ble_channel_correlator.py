# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/ble/ble_channel_correlator.py
# VERSION:      v2.0.0 (BLE CHANNEL CORRELATION ENGINE)
# UPDATED:      2026-03-25
# =============================================================================

from __future__ import annotations

import time
from typing import Dict, Any, List


class BLEChannelCorrelator:

    VERSION = "2.0.0"

    TIME_WINDOW = 2.0        # seconds
    RSSI_THRESHOLD = 8       # dB

    def __init__(self):
        self.history: List[Dict[str, Any]] = []

    # =========================================================================
    def process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        now = time.time()

        # add to history
        for e in events:
            e["_seen_ts"] = now
            self.history.append(e)

        # cleanup old
        self.history = [
            e for e in self.history
            if now - e["_seen_ts"] < self.TIME_WINDOW
        ]

        # correlate
        for event in events:
            self._correlate_event(event)

        return events

    # =========================================================================
    def _correlate_event(self, event: Dict[str, Any]):

        matched_channels = set()
        matched_devices = set()

        for other in self.history:

            if other is event:
                continue

            # ---------------------------------------------------------
            # SAME DEVICE MATCH
            # ---------------------------------------------------------
            if self._is_same_device(event, other):

                if other.get("channel"):
                    matched_channels.add(other["channel"])

                if other.get("device_id"):
                    matched_devices.add(other["device_id"])

        if matched_channels:
            matched_channels.add(event.get("channel"))
            event["channels_seen"] = sorted(list(matched_channels))

        if matched_devices:
            matched_devices.add(event.get("device_id"))
            event["correlated_devices"] = list(matched_devices)

    # =========================================================================
    def _is_same_device(self, a: Dict[str, Any], b: Dict[str, Any]) -> bool:

        # identity match
        if a.get("device_id") and a.get("device_id") == b.get("device_id"):
            return True

        # fingerprint match
        if a.get("device_hint") == b.get("device_hint"):
            score = 0.0

            # time proximity
            if abs(a.get("timestamp", 0) - b.get("timestamp", 0)) < self.TIME_WINDOW:
                score += 0.4

            # RSSI similarity
            if a.get("rssi") is not None and b.get("rssi") is not None:
                if abs(a["rssi"] - b["rssi"]) < self.RSSI_THRESHOLD:
                    score += 0.3

            # UUID overlap
            u1 = set(a.get("service_uuids") or [])
            u2 = set(b.get("service_uuids") or [])

            if u1 and u2:
                score += 0.3 * (len(u1 & u2) / len(u1 | u2))

            return score >= 0.6

        return False
