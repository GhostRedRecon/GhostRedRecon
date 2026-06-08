# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/behavior/behavior_profiler.py
# VERSION:      v2.0.0 (SIGINT BEHAVIOR ENGINE)
# UPDATED:      2026-03-25
# =============================================================================

from __future__ import annotations

import math
import time
from typing import Dict, Any, List, Optional


class BehaviorProfiler:
    VERSION = "2.0.0"

    PROFILE_TIMEOUT_SEC = 900

    # 🔥 LOWERED (CRITICAL FIX)
    MIN_EVENTS_FOR_CLASSIFICATION = 3

    def __init__(self):
        self.profiles: Dict[str, Dict[str, Any]] = {}

    # =========================================================================
    def process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        now = time.time()

        for event in events:
            device_id = event.get("device_id")
            if not device_id:
                continue

            profile = self.profiles.get(device_id)
            if profile is None:
                profile = self._new_profile(device_id, now)
                self.profiles[device_id] = profile

            self._update_profile(profile, event, now)

            label, confidence = self._classify(profile)

            event["behavior_profile"] = label
            event["behavior_confidence"] = confidence
            event["behavior_features"] = self._export_features(profile)

        self.cleanup(now)
        return events

    # =========================================================================
    def _new_profile(self, device_id: str, now: float) -> Dict[str, Any]:
        return {
            "device_id": device_id,
            "first_seen": now,
            "last_seen": now,
            "events_seen": 0,
            "timestamps": [],
            "intervals": [],
            "rssi_values": [],
            "channels": set(),
            "uuid_counts": {},
            "manufacturer_ids": {},
            "device_names": {},
            "macs": set(),
            "randomized_macs": 0,

            # 🔥 NEW FEATURES
            "burst_count": 0,
            "last_event_time": None,
        }

    # =========================================================================
    def _update_profile(self, profile: Dict[str, Any], event: Dict[str, Any], now: float) -> None:

        ts = float(event.get("timestamp") or now)
        last_ts = profile["timestamps"][-1] if profile["timestamps"] else None

        # 🔥 INTERVAL + BURST DETECTION
        if last_ts is not None:
            dt = ts - last_ts

            if 0 < dt < 120:
                profile["intervals"].append(dt)
                if len(profile["intervals"]) > 64:
                    profile["intervals"] = profile["intervals"][-64:]

            # 🔥 BURST DETECTION
            if dt < 1.5:
                profile["burst_count"] += 1

        profile["timestamps"].append(ts)
        if len(profile["timestamps"]) > 128:
            profile["timestamps"] = profile["timestamps"][-128:]

        profile["last_seen"] = now
        profile["events_seen"] += 1

        # 🔥 RSSI
        rssi = event.get("rssi")
        if isinstance(rssi, (int, float)):
            profile["rssi_values"].append(float(rssi))
            if len(profile["rssi_values"]) > 64:
                profile["rssi_values"] = profile["rssi_values"][-64:]

        # 🔥 CHANNELS
        channel = event.get("channel")
        if channel is not None:
            profile["channels"].add(channel)

        # 🔥 MAC TRACKING
        mac = event.get("mac_address")
        if mac:
            if mac not in profile["macs"]:
                try:
                    first_octet = int(mac.split(":")[0], 16)
                    is_random = bool(first_octet & 0b11000000)
                    if is_random:
                        profile["randomized_macs"] += 1
                except Exception:
                    pass
            profile["macs"].add(mac)

        # 🔥 UUIDs
        for uuid in event.get("service_uuids") or []:
            key = str(uuid).upper()
            profile["uuid_counts"][key] = profile["uuid_counts"].get(key, 0) + 1

        # 🔥 MANUFACTURER
        mid = event.get("manufacturer_id")
        if mid:
            key = str(mid).upper()
            profile["manufacturer_ids"][key] = profile["manufacturer_ids"].get(key, 0) + 1

        # 🔥 DEVICE NAME
        name = event.get("device_name")
        if name:
            key = str(name).strip()
            if key:
                profile["device_names"][key] = profile["device_names"].get(key, 0) + 1

    # =========================================================================
    def _classify(self, profile: Dict[str, Any]) -> tuple[str, float]:

        n = profile["events_seen"]

        # 🔥 EARLY CLASSIFICATION MODE (NEW)
        if n < self.MIN_EVENTS_FOR_CLASSIFICATION:
            return "learning", round(0.2 + (n * 0.1), 3)

        interval_mean = self._mean(profile["intervals"])
        interval_std = self._std(profile["intervals"])
        rssi_std = self._std(profile["rssi_values"])
        channel_count = len(profile["channels"])
        uuid_count = len(profile["uuid_counts"])
        mac_count = len(profile["macs"])
        burst_count = profile.get("burst_count", 0)

        randomized_ratio = (
            profile["randomized_macs"] / mac_count if mac_count > 0 else 0.0
        )

        periodicity = 0.0
        if interval_mean and interval_mean > 0:
            periodicity = max(0.0, 1.0 - min(1.0, interval_std / interval_mean))

        # 🔥 NEW SCORES
        stationary_score = 0.0
        mobile_score = 0.0
        tracker_score = 0.0
        iot_score = 0.0

        # =========================
        # TEMPORAL BEHAVIOR
        # =========================
        stationary_score += 0.30 * periodicity
        tracker_score += 0.30 * periodicity
        iot_score += 0.25 * periodicity

        if burst_count > 3:
            tracker_score += 0.25
            mobile_score += 0.15

        # =========================
        # RSSI BEHAVIOR
        # =========================
        if rssi_std < 3:
            stationary_score += 0.30
            iot_score += 0.20
        elif rssi_std > 8:
            mobile_score += 0.35

        # =========================
        # UUID LOGIC
        # =========================
        if uuid_count == 0:
            tracker_score += 0.20
        elif 1 <= uuid_count <= 3:
            iot_score += 0.25
        elif uuid_count > 5:
            mobile_score += 0.20

        # =========================
        # MAC ROTATION
        # =========================
        if randomized_ratio > 0.5:
            mobile_score += 0.25
            tracker_score += 0.20

        # =========================
        # CHANNEL SPREAD
        # =========================
        if channel_count >= 3:
            mobile_score += 0.15

        # =========================
        scores = {
            "stationary_beacon": stationary_score,
            "mobile_device": mobile_score,
            "tracker_like": tracker_score,
            "periodic_iot": iot_score,
        }

        label = max(scores, key=scores.get)
        confidence = min(1.0, scores[label])

        # 🔥 RELAXED THRESHOLD
        if confidence < 0.35:
            return "unknown_ble", round(confidence, 3)

        return label, round(confidence, 3)

    # =========================================================================
    def _export_features(self, profile: Dict[str, Any]) -> Dict[str, Any]:

        interval_mean = self._mean(profile["intervals"])
        interval_std = self._std(profile["intervals"])

        return {
            "events_seen": profile["events_seen"],
            "mac_count": len(profile["macs"]),
            "randomized_macs": profile["randomized_macs"],
            "burst_count": profile.get("burst_count", 0),
            "interval_mean": interval_mean,
            "interval_std": interval_std,
            "rssi_std": self._std(profile["rssi_values"]),
            "channels_seen": list(profile["channels"]),
            "uuid_count": len(profile["uuid_counts"]),
        }

    # =========================================================================
    def cleanup(self, now: Optional[float] = None) -> None:
        now = now or time.time()
        expired = [
            device_id
            for device_id, profile in self.profiles.items()
            if now - profile["last_seen"] > self.PROFILE_TIMEOUT_SEC
        ]
        for device_id in expired:
            self.profiles.pop(device_id, None)

    # =========================================================================
    def _mean(self, values: List[float]) -> Optional[float]:
        if not values:
            return None
        return sum(values) / len(values)

    def _std(self, values: List[float]) -> float:
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))
