# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/cross_session_identity_engine.py
# VERSION:      v1.1.0 (ROBUST GLOBAL ID FUSION)
# UPDATED:      2026-03-25
# =============================================================================

import hashlib
import time
from typing import Dict, Any, List, Optional

from backend.intel.persistence.persistent_identity_store import PersistentIdentityStore


class CrossSessionIdentityEngine:
    """
    Cross-Session Identity Engine

    Architecture:
    - Receives enriched BLE events after tracking / identity / behavior stages
    - Builds a more stable global device identity using multiple weak signals
    - Persists cross-session records into the persistent identity store
    - Returns the original events augmented with `global_device_id`

    Design Principles:
    - Never rely on a single BLE field such as MAC or vendor
    - Prefer multi-factor, coarse-grained signals
    - Stay resilient when packets are sparse
    - Preserve determinism where possible
    - Avoid collapsing all sparse devices into one identifier

    Responsibilities:
    - Generate global IDs for tracked devices
    - Persist device history across sessions
    - Merge incremental event intelligence into a persistent record
    """

    VERSION = "1.1.0"

    def __init__(self):
        self.store = PersistentIdentityStore()

    # =========================================================================
    def process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        for event in events:

            device_id = event.get("device_id")
            if not device_id:
                continue

            global_id = self._generate_global_id(event)

            existing = self._get_existing_record(global_id)

            record = self._build_record(event, existing)

            self.store.upsert_device(global_id, record)

            event["global_device_id"] = global_id

        return events

    # =========================================================================
    def _build_record(
        self,
        event: Dict[str, Any],
        existing: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:

        ts = float(event.get("timestamp") or time.time())

        existing = existing or {}

        first_seen = existing.get("first_seen", ts)
        last_seen = ts

        mac_history = self._merge_unique(
            existing.get("mac_history", []),
            [event.get("mac_address")]
        )

        uuid_history = self._merge_unique(
            existing.get("uuid_history", []),
            event.get("service_uuids") or []
        )

        behavior_history = self._merge_unique(
            existing.get("behavior_history", []),
            [event.get("behavior_profile")]
        )

        last_behavior = event.get("behavior_profile") or existing.get("last_behavior")

        confidence = max(
            float(existing.get("confidence", 0.0) or 0.0),
            float(event.get("behavior_confidence", 0.5) or 0.5)
        )

        return {
            "first_seen": first_seen,
            "last_seen": last_seen,
            "mac_history": mac_history,
            "uuid_history": uuid_history,
            "behavior_history": behavior_history,
            "last_behavior": last_behavior,
            "confidence": confidence,
        }

    # =========================================================================
    def _generate_global_id(self, event: Dict[str, Any]) -> str:
        """
        Generate a more discriminative global ID.

        Strategy:
        - Use multiple weak but useful features
        - Prefer coarse buckets instead of exact volatile values
        - Keep deterministic output when enough metadata exists
        - Fall back to MAC when metadata is sparse
        """

        parts: List[str] = []

        # ---------------------------------------------------------
        # Device tracker identity (if available)
        # ---------------------------------------------------------
        device_id = event.get("device_id")
        if device_id:
            parts.append(f"dev:{str(device_id)}")

        # ---------------------------------------------------------
        # MAC contribution (partial only, not trusted as sole identity)
        # ---------------------------------------------------------
        mac = event.get("mac_address")
        privacy_state = event.get("privacy_state")
        if mac:
            mac_norm = str(mac).upper().replace("-", ":")
            mac_parts = mac_norm.split(":")
            if len(mac_parts) >= 3 and privacy_state != "randomized":
                # partial prefix reduces total collapse while avoiding over-trust
                parts.append(f"macp:{''.join(mac_parts[:3])}")

            # also encode whether the address looks randomized/static-like
            rand_state = self._mac_randomization_state(mac_norm)
            if rand_state:
                parts.append(f"macflag:{rand_state}")

        # ---------------------------------------------------------
        # UUIDs are strong if present
        # ---------------------------------------------------------
        uuids = event.get("service_uuids") or []
        normalized_uuids = sorted(
            str(u).strip().upper()
            for u in uuids
            if u is not None and str(u).strip()
        )
        if normalized_uuids:
            parts.extend(f"uuid:{u}" for u in normalized_uuids[:8])

        # ---------------------------------------------------------
        # Device name
        # ---------------------------------------------------------
        name = event.get("device_name")
        if name:
            n = str(name).strip().lower()
            if n:
                parts.append(f"name:{n[:32]}")

        # ---------------------------------------------------------
        # Device hint
        # ---------------------------------------------------------
        hint = event.get("device_hint")
        if hint:
            h = str(hint).strip().lower()
            if h:
                parts.append(f"hint:{h}")

        # ---------------------------------------------------------
        # Manufacturer
        # ---------------------------------------------------------
        manufacturer = event.get("manufacturer_id")
        if manufacturer is not None:
            m = str(manufacturer).strip().upper()
            if m:
                parts.append(f"mfg:{m}")
        if event.get("service_data_keys"):
            parts.extend(f"sd:{key}" for key in sorted(event.get("service_data_keys") or [])[:4])
        if event.get("payload_signature"):
            parts.append(f"ps:{event.get('payload_signature')}")
        if event.get("probable_product_family"):
            parts.append(f"pf:{str(event.get('probable_product_family')).strip().lower()[:32]}")

        # ---------------------------------------------------------
        # Channel pattern signal
        # ---------------------------------------------------------
        channel = event.get("channel")
        if channel is not None and privacy_state != "randomized":
            try:
                parts.append(f"ch:{int(channel)}")
            except Exception:
                pass

        # ---------------------------------------------------------
        # Coarse RSSI bucket
        # ---------------------------------------------------------
        rssi = event.get("rssi")
        if isinstance(rssi, (int, float)):
            try:
                bucket = int(float(rssi) // 5)
                parts.append(f"rssi:{bucket}")
            except Exception:
                pass

        # ---------------------------------------------------------
        # Fallbacks
        # ---------------------------------------------------------
        if not parts:
            if mac:
                parts.append(f"fallback_mac:{mac}")
            else:
                parts.append(f"fallback_ts:{int(time.time() * 1000)}")

        base = "|".join(parts)
        return hashlib.sha256(base.encode()).hexdigest()[:16]

    # =========================================================================
    def _get_existing_record(self, global_id: str) -> Optional[Dict[str, Any]]:
        try:
            devices = self.store.get_all_devices()
        except Exception:
            return None

        for record in devices:
            if record.get("global_id") == global_id:
                return record

        return None

    # =========================================================================
    def _merge_unique(self, existing: List[Any], new_values: List[Any]) -> List[Any]:
        merged: List[Any] = []

        for value in (existing or []):
            if value is None:
                continue
            if value not in merged:
                merged.append(value)

        for value in (new_values or []):
            if value is None:
                continue
            if value not in merged:
                merged.append(value)

        return merged

    # =========================================================================
    def _mac_randomization_state(self, mac: str) -> Optional[str]:
        try:
            first_octet = int(mac.split(":")[0], 16)
        except Exception:
            return None

        # locally administered bit
        is_local = bool(first_octet & 0b00000010)
        # multicast bit
        is_multicast = bool(first_octet & 0b00000001)

        if is_multicast:
            return "multicast"
        if is_local:
            return "local"
        return "global"
