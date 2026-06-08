from __future__ import annotations

from typing import Any, Dict, List


def clean_hex(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    return "".join(char for char in text if char in "0123456789abcdef")


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes"}


def _service_uuid_list(raw_values: Any) -> List[str]:
    uuids: List[str] = []
    for item in (raw_values or []):
        normalized = clean_hex(item)
        if not normalized:
            continue
        if len(normalized) >= 4:
            uuids.append(normalized[:4])
    return sorted(set(uuids))


def normalize_observation(obs: Dict[str, Any]) -> Dict[str, Any]:
    mac = str(obs.get("mac") or obs.get("address") or "").strip().lower()
    manufacturer_data = clean_hex(
        obs.get("manufacturer_data")
        or obs.get("manufacturer_data_prefix")
        or ""
    )
    name = str(obs.get("name") or "").strip()
    if not name:
        name = "Unknown BLE Device"
    company_id = obs.get("company_id")
    if company_id is None:
        company_id = obs.get("manufacturer_company_id")
    return {
        "mac": mac,
        "mac_prefix": mac[:8],
        "address_type": str(obs.get("address_type") or "unknown").strip().lower(),
        "rssi": obs.get("rssi") if obs.get("rssi") is not None else (obs.get("avg_rssi") if obs.get("avg_rssi") is not None else -100),
        "connectable": _coerce_bool(obs.get("connectable")),
        "manufacturer_data": manufacturer_data,
        "manufacturer_prefix": manufacturer_data[:8],
        "service_uuids": _service_uuid_list(obs.get("service_uuids")),
        "company_id": company_id,
        "name": name,
        "timestamp": obs.get("timestamp") or obs.get("last_seen"),
        "observation_count": int(obs.get("observation_count") or 1),
        "advertising_interval_ms": obs.get("advertising_interval_ms"),
    }
