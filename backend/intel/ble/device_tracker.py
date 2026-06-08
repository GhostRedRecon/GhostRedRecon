# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/ble/device_tracker.py
# VERSION:      v3.0.0 (RSSI FINGERPRINTING ENGINE)
# UPDATED:      2026-03-25
# =============================================================================

from __future__ import annotations

import time
import hashlib
from typing import Dict, Any, List, Optional


class BLEDeviceTracker:

    VERSION = "3.0.0"

    MATCH_TIME_WINDOW = 6.0
    MATCH_THRESHOLD = 0.58
    DEVICE_TIMEOUT = 120

    def __init__(self):

        self.devices: Dict[str, Dict[str, Any]] = {}
        self.mac_to_device: Dict[str, str] = {}

        self._device_counter = 0

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================
    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:

        mac = event.get("mac_address")
        now = time.time()

        if not mac:
            return event

        rssi = self._safe_float(event.get("rssi"))

        # ---------------------------------------------------------
        # EXISTING MAC
        # ---------------------------------------------------------
        if mac in self.mac_to_device:
            device_id = self.mac_to_device[mac]
            device = self.devices[device_id]

            self._update_device(device, event, now, rssi)

            event["device_id"] = device_id
            event["identity_confidence"] = device["confidence"]

            return event

        # ---------------------------------------------------------
        # MATCH SEARCH
        # ---------------------------------------------------------
        best_id = None
        best_score = 0.0

        for device_id, device in self.devices.items():
            score = self._compute_similarity(event, device, rssi)

            if score > best_score:
                best_score = score
                best_id = device_id

        # ---------------------------------------------------------
        # MATCH FOUND
        # ---------------------------------------------------------
        if best_id and best_score >= self.MATCH_THRESHOLD:

            device = self.devices[best_id]

            device["macs"].add(mac)
            self.mac_to_device[mac] = best_id

            self._update_device(device, event, now, rssi)

            device["confidence"] = min(1.0, device["confidence"] + 0.1)

            event["device_id"] = best_id
            event["identity_confidence"] = device["confidence"]

            return event

        # ---------------------------------------------------------
        # NEW DEVICE
        # ---------------------------------------------------------
        device_id = self._generate_device_id()

        fingerprint = self._build_fingerprint(event)

        self.devices[device_id] = {
            "device_id": device_id,
            "macs": {mac},
            "first_seen": now,
            "last_seen": now,
            "seen_count": 1,
            "confidence": 0.5,

            # fingerprint
            "fingerprint": fingerprint,
            "intervals": [],
            "last_event_time": now,

            # 🔥 RSSI PROFILE
            "rssi_values": [rssi] if rssi is not None else [],
            "rssi_avg": rssi,
            "rssi_var": 0.0,

            # identity hints
            "device_name": event.get("device_name"),
            "manufacturer_id": event.get("manufacturer_id"),
            "service_uuids": event.get("service_uuids"),
            "service_data_keys": event.get("service_data_keys"),
            "vendor": event.get("vendor"),
            "device_hint": event.get("device_hint"),
            "appearance": event.get("appearance"),
            "pdu_type_label": event.get("pdu_type_label"),
            "payload_signature": event.get("payload_signature"),
            "privacy_state": event.get("privacy_state"),
            "tracker_like": bool(event.get("tracker_like")),
            "beacon_like": bool(event.get("beacon_like")),
        }

        self.mac_to_device[mac] = device_id

        event["device_id"] = device_id
        event["identity_confidence"] = 0.5

        return event

    # =========================================================================
    # UPDATE DEVICE
    # =========================================================================
    def _update_device(self, device, event, now, rssi):

        dt = now - device["last_event_time"]
        device["last_event_time"] = now
        device["last_seen"] = now
        device["seen_count"] += 1

        # interval tracking
        if dt > 0:
            device["intervals"].append(dt)
            if len(device["intervals"]) > 20:
                device["intervals"] = device["intervals"][-20:]

        # 🔥 RSSI UPDATE
        if rssi is not None:
            device["rssi_values"].append(rssi)

            if len(device["rssi_values"]) > 30:
                device["rssi_values"] = device["rssi_values"][-30:]

            avg = sum(device["rssi_values"]) / len(device["rssi_values"])
            var = sum((x - avg) ** 2 for x in device["rssi_values"]) / len(device["rssi_values"])

            device["rssi_avg"] = avg
            device["rssi_var"] = var

            # stable RSSI boost
            if var < 4:
                device["confidence"] = min(1.0, device["confidence"] + 0.03)

        # fingerprint reinforcement
        new_fp = self._build_fingerprint(event)
        if new_fp == device["fingerprint"]:
            device["confidence"] = min(1.0, device["confidence"] + 0.02)
        if event.get("service_data_keys"):
            device["service_data_keys"] = sorted(
                set(list(device.get("service_data_keys") or []) + list(event.get("service_data_keys") or []))
            )
        device["appearance"] = event.get("appearance") or device.get("appearance")
        device["pdu_type_label"] = event.get("pdu_type_label") or device.get("pdu_type_label")
        device["payload_signature"] = event.get("payload_signature") or device.get("payload_signature")
        device["privacy_state"] = event.get("privacy_state") or device.get("privacy_state")
        device["tracker_like"] = bool(device.get("tracker_like") or event.get("tracker_like"))
        device["beacon_like"] = bool(device.get("beacon_like") or event.get("beacon_like"))

    # =========================================================================
    # SIMILARITY ENGINE (RSSI ADDED)
    # =========================================================================
    def _compute_similarity(self, event, device, rssi):

        score = 0.0
        now = time.time()

        # time correlation
        if now - device["last_seen"] < self.MATCH_TIME_WINDOW:
            score += 0.2

        # fingerprint
        if self._build_fingerprint(event) == device["fingerprint"]:
            score += 0.35

        # interval match
        if device["intervals"]:
            avg_interval = sum(device["intervals"]) / len(device["intervals"])
            current_dt = now - device["last_event_time"]

            if abs(current_dt - avg_interval) < 0.05:
                score += 0.15

        # UUID similarity
        u1 = set(event.get("service_uuids") or [])
        u2 = set(device.get("service_uuids") or [])

        if u1 and u2:
            score += 0.1 * (len(u1 & u2) / len(u1 | u2))

        sd1 = set(event.get("service_data_keys") or [])
        sd2 = set(device.get("service_data_keys") or [])
        if sd1 and sd2:
            score += 0.08 * (len(sd1 & sd2) / len(sd1 | sd2))

        if event.get("manufacturer_id") and event.get("manufacturer_id") == device.get("manufacturer_id"):
            score += 0.12

        if event.get("payload_signature") and event.get("payload_signature") == device.get("payload_signature"):
            score += 0.18

        if event.get("privacy_state") == "randomized" and device.get("privacy_state") == "randomized":
            score += 0.05

        if event.get("tracker_like") and device.get("tracker_like"):
            score += 0.05

        if event.get("beacon_like") and device.get("beacon_like"):
            score += 0.05

        # 🔥 RSSI SIMILARITY
        if rssi is not None and device.get("rssi_avg") is not None:
            diff = abs(rssi - device["rssi_avg"])

            if diff < 5:
                score += 0.2
            elif diff < 10:
                score += 0.1

        return round(score, 3)

    # =========================================================================
    # FINGERPRINT
    # =========================================================================
    def _build_fingerprint(self, event):

        parts = []

        if event.get("manufacturer_id"):
            parts.append(str(event["manufacturer_id"]))

        if event.get("service_data_keys"):
            parts.extend(sorted(event["service_data_keys"]))

        if event.get("service_uuids"):
            parts.extend(sorted(event["service_uuids"]))

        if event.get("appearance"):
            parts.append(str(event["appearance"]))

        if event.get("pdu_type_label"):
            parts.append(str(event["pdu_type_label"]))

        if event.get("payload_signature"):
            parts.append(str(event["payload_signature"]))

        if event.get("privacy_state"):
            parts.append(str(event["privacy_state"]))

        if event.get("device_hint"):
            parts.append(event["device_hint"])

        raw = "|".join(parts)
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    # =========================================================================
    def _generate_device_id(self):
        self._device_counter += 1
        return f"DEV-{self._device_counter:04d}"

    # =========================================================================
    def cleanup(self):

        now = time.time()
        expired = []

        for device_id, device in self.devices.items():
            if now - device["last_seen"] > self.DEVICE_TIMEOUT:
                expired.append(device_id)

        for device_id in expired:
            dev = self.devices.pop(device_id, None)
            if dev:
                for mac in dev["macs"]:
                    self.mac_to_device.pop(mac, None)

    # =========================================================================
    def _safe_float(self, v):
        try:
            return float(v)
        except Exception:
            return None
