# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/ble_fingerprinting_engine.py
# VERSION:      v1.0.0 (SIGINT FINGERPRINT ENGINE)
# UPDATED:      2026-03-25
# =============================================================================

from __future__ import annotations
import math
import hashlib
from typing import Dict, Any, List


class BLEFingerprintingEngine:
    """
    BLE Fingerprinting Engine

    PURPOSE:
    - Identify devices beyond MAC address
    - Generate persistent fingerprint IDs
    - Match devices across sessions

    CORE IDEA:
    UUID + Timing + RF = Device Identity
    """

    VERSION = "1.0.0"

    def __init__(self):
        self.fingerprint_db: Dict[str, Dict[str, Any]] = {}

    # =========================================================================
    def process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        for e in events:

            device_id = e.get("global_device_id")
            if not device_id:
                continue

            fingerprint = self._build_fingerprint(e)

            match_id, confidence = self._match_fingerprint(fingerprint)

            if not match_id:
                match_id = self._generate_fingerprint_id(fingerprint)
                self.fingerprint_db[match_id] = fingerprint

            # Attach to event
            e["fingerprint_id"] = match_id
            e["fingerprint_confidence"] = confidence
            e["fingerprint_components"] = fingerprint["components"]

        return events

    # =========================================================================
    def _build_fingerprint(self, event: Dict[str, Any]) -> Dict[str, Any]:

        uuids = event.get("service_uuids") or []
        rssi = event.get("rssi")
        features = event.get("behavior_features") or {}

        interval_mean = features.get("interval_mean")
        interval_std = features.get("interval_std")
        rssi_std = features.get("rssi_std")

        uuid_sig = self._uuid_signature(uuids)
        timing_sig = self._timing_signature(interval_mean, interval_std)
        rf_sig = self._rf_signature(rssi, rssi_std)

        return {
            "uuid_sig": uuid_sig,
            "timing_sig": timing_sig,
            "rf_sig": rf_sig,
            "components": {
                "uuid_score": uuid_sig["score"],
                "timing_score": timing_sig["score"],
                "rf_score": rf_sig["score"],
            }
        }

    # =========================================================================
    def _uuid_signature(self, uuids: List[str]) -> Dict[str, Any]:

        if not uuids:
            return {"hash": "none", "score": 0.3}

        norm = sorted([str(u).upper() for u in uuids])
        h = hashlib.md5("".join(norm).encode()).hexdigest()[:8]

        score = min(1.0, len(norm) / 5)

        return {"hash": h, "score": score}

    # =========================================================================
    def _timing_signature(self, mean: float, std: float) -> Dict[str, Any]:

        if not mean:
            return {"bucket": "unknown", "score": 0.3}

        if mean < 1:
            bucket = "fast"
        elif mean < 5:
            bucket = "medium"
        else:
            bucket = "slow"

        stability = 1.0 if std and std < mean else 0.5

        return {"bucket": bucket, "score": stability}

    # =========================================================================
    def _rf_signature(self, rssi: float, std: float) -> Dict[str, Any]:

        if rssi is None:
            return {"bucket": "unknown", "score": 0.3}

        if rssi > -60:
            strength = "strong"
        elif rssi > -80:
            strength = "medium"
        else:
            strength = "weak"

        stability = 1.0 if std and std < 5 else 0.5

        return {"bucket": strength, "score": stability}

    # =========================================================================
    def _match_fingerprint(self, fp: Dict[str, Any]):

        best_match = None
        best_score = 0.0

        for fid, existing in self.fingerprint_db.items():

            score = self._compare(fp, existing)

            if score > best_score:
                best_score = score
                best_match = fid

        if best_score > 0.7:
            return best_match, round(best_score, 3)

        return None, 0.0

    # =========================================================================
    def _compare(self, a: Dict[str, Any], b: Dict[str, Any]) -> float:

        score = 0.0

        # UUID match
        if a["uuid_sig"]["hash"] == b["uuid_sig"]["hash"]:
            score += 0.4

        # Timing match
        if a["timing_sig"]["bucket"] == b["timing_sig"]["bucket"]:
            score += 0.3

        # RF match
        if a["rf_sig"]["bucket"] == b["rf_sig"]["bucket"]:
            score += 0.3

        return score

    # =========================================================================
    def _generate_fingerprint_id(self, fp: Dict[str, Any]) -> str:

        raw = (
            fp["uuid_sig"]["hash"]
            + fp["timing_sig"]["bucket"]
            + fp["rf_sig"]["bucket"]
        )

        return "fp_" + hashlib.md5(raw.encode()).hexdigest()[:6]
