# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/protocol/zigbee_ble_inference.py
# VERSION:      v2.0.0 (STATEFUL ASSIST LAYER — CLEANED)
# LAST UPDATED: 2026-03-03
#
# =============================================================================
# ARCHITECTURE ROLE
# =============================================================================
#
# ProtocolEngine (strict stateless)
#     ↓
# ZigbeeBLEInferenceEngine (THIS FILE — stateful assist)
#
# =============================================================================
# RESPONSIBILITY
# =============================================================================
# ✔ Only assists when protocol == UNKNOWN_PROTOCOL
# ✔ Accumulates evidence across frames
# ✔ Promotes: CANDIDATE → PROBABLE → CONFIRMED
# ✔ Uses burst behavior + width + alignment
# ✔ No duplication of strict classifier logic
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
# ✔ No demodulation
# ✔ No exploit logic
# ✔ No replay logic
# ✔ No identity mutation
# ✔ Conservative promotion
# ✔ UI thrash prevention
# ✔ TTL-based evidence reset
# =============================================================================

import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

from .protocol_engine import (
    ZIGBEE_CHANNELS_MHZ,
    BLE_ADV_CHANNELS_MHZ,
)


@dataclass
class Evidence:
    first_seen: float
    last_seen: float
    hits: int
    zigbee_votes: int
    ble_votes: int


class ZigbeeBLEInferenceEngine:

    def __init__(self, ttl_seconds: float = 30.0):
        self._ttl = float(ttl_seconds)

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def infer(self, record: Dict[str, Any]) -> Dict[str, Any]:

        proto = record.get("protocol_signature", "")
        if proto and proto != "UNKNOWN_PROTOCOL":
            return {}

        freq = float(record.get("freq_mhz", 0))
        width = float(record.get("rf_width_mhz", 0))
        duty = record.get("burst_duty_cycle")

        if not (2400 <= freq <= 2500):
            return {}

        evidence = self._load(record)

        if self._expired(evidence):
            evidence = self._new()

        evidence.hits += 1
        evidence.last_seen = time.time()

        # Zigbee vote
        if 1.6 <= width <= 3.2 and any(abs(freq - ch) <= 2.0 for ch in ZIGBEE_CHANNELS_MHZ):
            if duty is None or duty <= 0.25:
                evidence.zigbee_votes += 1

        # BLE vote
        if 0.7 <= width <= 1.5 and any(abs(freq - ch) <= 1.5 for ch in BLE_ADV_CHANNELS_MHZ):
            if duty is None or duty <= 0.20:
                evidence.ble_votes += 1

        decision = self._decide(evidence)

        updates = {
            "zigbee_ble_evidence": asdict(evidence),
        }

        if decision:
            updates.update(decision)

        return updates

    # =========================================================================
    # INTERNALS
    # =========================================================================

    def _new(self) -> Evidence:
        now = time.time()
        return Evidence(now, now, 0, 0, 0)

    def _expired(self, e: Evidence) -> bool:
        return (time.time() - e.last_seen) > self._ttl

    def _load(self, record: Dict[str, Any]) -> Evidence:
        blob = record.get("zigbee_ble_evidence")
        if isinstance(blob, dict):
            return Evidence(
                blob.get("first_seen", time.time()),
                blob.get("last_seen", time.time()),
                blob.get("hits", 0),
                blob.get("zigbee_votes", 0),
                blob.get("ble_votes", 0),
            )
        return self._new()

    def _decide(self, e: Evidence) -> Optional[Dict[str, Any]]:

        if e.hits < 2:
            return None

        if e.zigbee_votes >= 4:
            return {
                "protocol_signature": "IEEE_802.15.4_ZIGBEE",
                "protocol_confidence": 0.85,
            }

        if e.ble_votes >= 4:
            return {
                "protocol_signature": "BLE_ADVERTISING",
                "protocol_confidence": 0.85,
            }

        if e.zigbee_votes >= 2:
            return {
                "protocol_signature": "IEEE_802.15.4_ZIGBEE_PROBABLE",
                "protocol_confidence": 0.65,
            }

        if e.ble_votes >= 2:
            return {
                "protocol_signature": "BLE_ADVERTISING_PROBABLE",
                "protocol_confidence": 0.65,
            }

        return None
