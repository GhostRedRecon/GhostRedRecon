from __future__ import annotations

from typing import Any, Dict, List, Optional


class ZigbeeDeviceIntelligenceEngine:
    VERSION = "1.0.0"

    def enrich_emitters(self, emitters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self._enrich_single(emitter) for emitter in (emitters or [])]

    def _enrich_single(self, emitter: Dict[str, Any]) -> Dict[str, Any]:
        emitter = dict(emitter or {})

        protocol = str(emitter.get("rf_protocol") or emitter.get("protocol") or "").upper()
        channel_family = str(emitter.get("channel_family") or "").lower()
        zigbee_channel = emitter.get("zigbee_channel")

        if (
            protocol not in {"ZIGBEE", "IEEE_802.15.4", "IEEE_802.15.4_ZIGBEE", "IEEE_802154_ZIGBEE"}
            and channel_family != "zigbee"
            and zigbee_channel is None
        ):
            return emitter

        observation_count = self._as_int(
            emitter.get("rf_observation_count"),
            emitter.get("observation_count"),
            emitter.get("signal_count"),
            default=0,
        )
        stability = self._as_float(
            emitter.get("rf_signal_stability"),
            emitter.get("signal_stability"),
            default=0.0,
        )
        continuity = self._as_float(
            emitter.get("rf_identity_continuity_score"),
            default=0.0,
        )
        duty_cycle = self._as_float(
            emitter.get("rf_duty_cycle"),
            emitter.get("burst_ratio"),
            default=0.0,
        )
        periodicity = self._as_float(
            emitter.get("rf_burst_periodicity"),
            emitter.get("periodicity"),
        )

        role = "unknown"
        confidence = 0.0
        mode = "zigbee_general"

        if observation_count >= 8 and stability >= 0.70 and continuity >= 0.50:
            role = "coordinator"
            confidence = 0.76
            mode = "mesh_infrastructure"
        elif observation_count >= 5 and stability >= 0.55:
            role = "router"
            confidence = 0.64
            mode = "mesh_router"
        elif duty_cycle <= 0.30 or (periodicity is not None and periodicity >= 0.2):
            role = "end_device"
            confidence = 0.61
            mode = "low_power_endpoint"

        if role == "unknown":
            return emitter

        emitter["zigbee_intel_version"] = self.VERSION
        emitter["zigbee_role"] = role
        emitter["zigbee_role_confidence"] = round(confidence, 4)
        emitter["zigbee_operating_mode_hint"] = mode
        emitter["zigbee_mesh_like"] = role in {"coordinator", "router"}

        if emitter.get("device_role_hint") is None:
            emitter["device_role_hint"] = role
        if emitter.get("device_role_confidence") is None:
            emitter["device_role_confidence"] = round(confidence, 4)
        if emitter.get("product_category_hint") is None:
            emitter["product_category_hint"] = {
                "coordinator": "zigbee_gateway",
                "router": "zigbee_router",
                "end_device": "zigbee_sensor",
            }.get(role, "zigbee_iot")
        if emitter.get("product_category_confidence") is None:
            emitter["product_category_confidence"] = round(confidence * 0.92, 4)
        if emitter.get("behavior_profile_hint") is None:
            emitter["behavior_profile_hint"] = mode
        if emitter.get("rf_device_class") is None:
            emitter["rf_device_class"] = {
                "coordinator": "Zigbee Coordinator",
                "router": "Zigbee Router",
                "end_device": "Zigbee End Device",
            }.get(role, "Zigbee Device")

        return emitter

    @staticmethod
    def _as_float(*values: Any, default: Optional[float] = 0.0) -> Optional[float]:
        for value in values:
            try:
                if value is None:
                    continue
                return float(value)
            except Exception:
                continue
        return default

    @staticmethod
    def _as_int(*values: Any, default: int = 0) -> int:
        for value in values:
            try:
                if value is None:
                    continue
                return int(value)
            except Exception:
                continue
        return default
