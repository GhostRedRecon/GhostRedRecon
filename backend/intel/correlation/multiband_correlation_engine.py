from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional, Set


class MultiBandCorrelationEngine:
    VERSION = "1.0.0"

    def __init__(self) -> None:
        self._last_entities: List[Dict[str, Any]] = []
        self._last_run_ts: float = 0.0

    def process(
        self,
        signals: List[Dict[str, Any]],
        devices: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        normalized_signals = [signal for signal in signals or [] if isinstance(signal, dict)]
        normalized_devices = [device for device in devices or [] if isinstance(device, dict)]

        groups: Dict[str, Dict[str, Any]] = {}

        for device in normalized_devices:
            keys = self._device_keys(device)
            if not keys:
                continue
            entity = self._get_or_create_entity(groups, keys, device)
            self._attach_device(entity, device)

        for signal in normalized_signals:
            keys = self._signal_keys(signal)
            if not keys:
                continue
            entity = self._get_or_create_entity(groups, keys, signal)
            self._attach_signal(entity, signal)

        entities = []
        seen_entities: Set[int] = set()
        for entity in groups.values():
            entity_ref = id(entity)
            if entity_ref in seen_entities:
                continue
            seen_entities.add(entity_ref)
            final = self._finalize_entity(entity)
            if final is not None:
                entities.append(final)

        entities.sort(
            key=lambda item: (
                float(item.get("confidence") or 0.0),
                len(item.get("protocols") or []),
                len(item.get("signal_ids") or []),
            ),
            reverse=True,
        )

        self._last_entities = entities
        self._last_run_ts = time.time()
        return entities

    def get_state(self) -> Dict[str, Any]:
        return {
            "engine_version": self.VERSION,
            "entity_count": len(self._last_entities),
            "last_run_ts": self._last_run_ts,
            "entities": list(self._last_entities),
        }

    def _get_or_create_entity(
        self,
        groups: Dict[str, Dict[str, Any]],
        keys: List[str],
        seed: Dict[str, Any],
    ) -> Dict[str, Any]:
        existing = None
        for key in keys:
            if key in groups:
                existing = groups[key]
                break

        if existing is None:
            entity_id = self._entity_id_from_keys(keys)
            existing = {
                "entity_id": entity_id,
                "_keys": set(keys),
                "basis": set(),
                "protocols": set(),
                "channel_families": set(),
                "vendors": set(),
                "rf_bands": set(),
                "device_types": set(),
                "device_ids": set(),
                "signal_ids": set(),
                "frequencies": set(),
                "primary_vendor": None,
                "last_seen": 0.0,
            }

        for key in keys:
            groups[key] = existing
        existing["_keys"].update(keys)
        return existing

    def _attach_device(self, entity: Dict[str, Any], device: Dict[str, Any]) -> None:
        device_id = device.get("device_id")
        if device_id:
            entity["device_ids"].add(str(device_id))
            entity["basis"].add("device_id")

        vendor = device.get("vendor")
        if vendor:
            entity["vendors"].add(str(vendor))
            entity["primary_vendor"] = entity["primary_vendor"] or str(vendor)

        device_type = device.get("device_type") or device.get("device_category")
        if device_type:
            entity["device_types"].add(str(device_type))

        channel_family = str(device.get("channel_family") or "").strip().lower()
        if channel_family:
            entity["channel_families"].add(channel_family)
        protocols = self._sanitize_protocols(device.get("protocols") or [], channel_family)
        for protocol in protocols:
            if protocol:
                entity["protocols"].add(str(protocol).upper())

        for band in device.get("rf_bands") or []:
            if band:
                entity["rf_bands"].add(str(band))

        for freq in device.get("frequencies") or []:
            normalized = self._safe_round(freq, 3)
            if normalized is not None:
                entity["frequencies"].add(normalized)

        entity["last_seen"] = max(
            self._safe_float(device.get("last_seen"), 0.0),
            entity["last_seen"],
        )

    def _attach_signal(self, entity: Dict[str, Any], signal: Dict[str, Any]) -> None:
        signal_id = signal.get("signal_id")
        if signal_id:
            entity["signal_ids"].add(str(signal_id))
            entity["basis"].add("signal_id")

        channel_family = str(signal.get("channel_family") or "").strip().lower()
        if channel_family:
            entity["channel_families"].add(channel_family)
        protocols = self._sanitize_protocols(
            [signal.get("protocol") or signal.get("rf_protocol")],
            channel_family,
        )
        for protocol in protocols:
            entity["protocols"].add(str(protocol).upper())

        vendor = signal.get("vendor") or signal.get("rf_vendor_candidate")
        if vendor:
            entity["vendors"].add(str(vendor))
            entity["primary_vendor"] = entity["primary_vendor"] or str(vendor)

        band = signal.get("rf_band")
        if band:
            entity["rf_bands"].add(str(band))

        signal_type = signal.get("device_type") or signal.get("device_category")
        if signal_type:
            entity["device_types"].add(str(signal_type))

        freq = self._safe_round(signal.get("frequency_mhz") or signal.get("freq_mhz"), 3)
        if freq is not None:
            entity["frequencies"].add(freq)

        entity["last_seen"] = max(
            self._safe_float(signal.get("last_seen"), 0.0),
            entity["last_seen"],
        )

    def _finalize_entity(self, entity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        dominant_family = self._dominant_family(entity)
        protocols = self._finalize_protocols(entity["protocols"], dominant_family)
        device_ids = sorted(entity["device_ids"])
        signal_ids = sorted(entity["signal_ids"])
        frequencies = sorted(entity["frequencies"])

        if not device_ids and not signal_ids:
            return None

        confidence = 0.35
        if len(protocols) > 1:
            confidence += 0.25
        if entity["primary_vendor"]:
            confidence += 0.15
        if len(device_ids) > 0:
            confidence += 0.15
        if len(signal_ids) > 1:
            confidence += 0.10

        return {
            "entity_id": entity["entity_id"],
            "confidence": round(min(confidence, 0.95), 3),
            "basis": sorted(entity["basis"]),
            "protocols": protocols,
            "channel_family": dominant_family,
            "vendors": sorted(entity["vendors"]),
            "primary_vendor": entity["primary_vendor"],
            "device_types": sorted(entity["device_types"]),
            "rf_bands": sorted(entity["rf_bands"]),
            "device_ids": device_ids,
            "signal_ids": signal_ids,
            "frequencies": frequencies,
            "cross_protocol": len(protocols) > 1,
            "last_seen": entity["last_seen"],
        }

    def _device_keys(self, device: Dict[str, Any]) -> List[str]:
        keys: Set[str] = set()
        channel_family = str(device.get("channel_family") or "").strip().lower()

        for field in ["hardware_id", "mac_address", "identity_id", "device_id"]:
            value = device.get(field)
            if value:
                keys.add(f"{field}:{str(value).strip().lower()}")

        vendor = str(device.get("vendor") or "").strip().lower()
        product = str(device.get("product") or device.get("device_type") or "").strip().lower()
        if vendor and product:
            keys.add(f"vendor_product:{vendor}:{product}")

        frequencies = sorted(
            {
                self._safe_round(freq, 1)
                for freq in device.get("frequencies") or []
                if self._safe_round(freq, 1) is not None
            }
        )
        protocols = sorted(
            {
                str(proto).strip().upper()
                for proto in device.get("protocols") or []
                if proto
            }
        )
        if vendor and protocols and frequencies:
            keys.add(
                "vendor_proto_freq:"
                + vendor
                + ":"
                + ",".join(protocols[:3])
                + ":"
                + ",".join(str(freq) for freq in frequencies[:4])
            )
        return sorted(keys)

    def _signal_keys(self, signal: Dict[str, Any]) -> List[str]:
        keys: Set[str] = set()

        for field in ["device_id"]:
            value = signal.get(field)
            if value:
                keys.add(f"{field}:{str(value).strip().lower()}")

        vendor = str(signal.get("vendor") or signal.get("rf_vendor_candidate") or "").strip().lower()
        protocol = str(signal.get("protocol") or signal.get("rf_protocol") or "").strip().upper()
        frequency = self._safe_round(signal.get("frequency_mhz") or signal.get("freq_mhz"), 1)
        channel_family = str(signal.get("channel_family") or "").strip().lower()
        dense_24ghz_family = channel_family in {"ble", "zigbee", "wifi"}
        if vendor and protocol and frequency is not None:
            keys.add(f"vendor_proto_freq:{vendor}:{protocol}:{frequency}")
        elif protocol and frequency is not None and not dense_24ghz_family:
            keys.add(f"proto_freq:{protocol}:{frequency}")
        if channel_family and frequency is not None and not dense_24ghz_family:
            keys.add(f"family_freq:{channel_family}:{frequency}")

        rf_band = str(signal.get("rf_band") or "").strip().lower()
        if rf_band and frequency is not None and not channel_family and not dense_24ghz_family:
            keys.add(f"band_freq:{rf_band}:{frequency}")

        return sorted(keys)

    @staticmethod
    def _entity_id_from_keys(keys: List[str]) -> str:
        seed = "|".join(sorted(keys))
        digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]
        return f"ENTITY-{digest.upper()}"

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    @classmethod
    def _safe_round(cls, value: Any, places: int) -> Optional[float]:
        try:
            if value is None:
                return None
            return round(float(value), places)
        except Exception:
            return None

    @staticmethod
    def _sanitize_protocols(protocols: List[Any], channel_family: str) -> List[str]:
        normalized = []
        for protocol in protocols:
            label = str(protocol or "").strip().upper().replace("-", "_")
            if not label:
                continue
            if label == "BLUETOOTH_LE":
                label = "BLE"
            elif label == "IEEE_802.11":
                label = "WIFI"
            elif label == "IEEE_802.15.4":
                label = "ZIGBEE"
            normalized.append(label)

        if channel_family == "ble":
            normalized = [label for label in normalized if label in {"BLE", "UNKNOWN_PROTOCOL"}]
        elif channel_family == "zigbee":
            normalized = [label for label in normalized if label in {"ZIGBEE", "UNKNOWN_PROTOCOL"}]
        elif channel_family == "wifi":
            normalized = [label for label in normalized if label in {"WIFI", "UNKNOWN_PROTOCOL"}]

        return normalized

    @staticmethod
    def _dominant_family(entity: Dict[str, Any]) -> Optional[str]:
        families = {
            str(family).strip().lower()
            for family in entity.get("channel_families") or set()
            if str(family).strip()
        }
        if not families:
            return None
        for preferred in ("ble", "zigbee", "wifi"):
            if preferred in families:
                return preferred
        return sorted(families)[0]

    @classmethod
    def _finalize_protocols(cls, protocols: Set[str], channel_family: Optional[str]) -> List[str]:
        normalized = cls._sanitize_protocols(list(protocols), channel_family or "")
        if channel_family == "ble":
            normalized = [proto for proto in normalized if proto in {"BLE", "UNKNOWN_PROTOCOL"}]
        elif channel_family == "zigbee":
            normalized = [proto for proto in normalized if proto in {"ZIGBEE", "UNKNOWN_PROTOCOL"}]
        elif channel_family == "wifi":
            normalized = [proto for proto in normalized if proto in {"WIFI", "UNKNOWN_PROTOCOL"}]
        return sorted({proto for proto in normalized if proto})
