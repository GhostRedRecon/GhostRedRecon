from __future__ import annotations

from typing import Any, Dict, List


CLASSIFICATION_LABELS = {
    "named_ble_device": {"device_type": "Named", "protocol": "BLE", "vendor": "", "ui_tone": "green", "icon": "📛"},
    "mobile_apple": {"device_type": "Mobile", "protocol": "BLE", "vendor": "Apple", "ui_tone": "cyan", "icon": "📱"},
    "vendor_microsoft": {"device_type": "Mobile", "protocol": "BLE", "vendor": "Microsoft", "ui_tone": "cyan", "icon": "💻"},
    "mobile_android_family": {"device_type": "Mobile", "protocol": "BLE", "vendor": "Unknown", "ui_tone": "cyan", "icon": "📱"},
    "beacon_device": {"device_type": "Beacon", "protocol": "BLE", "vendor": "Unknown", "ui_tone": "amber", "icon": "📡"},
    "iot_candidate": {"device_type": "IoT", "protocol": "BLE", "vendor": "Unknown", "ui_tone": "green", "icon": "🔌"},
    "mobile_privacy_device": {"device_type": "Mobile", "protocol": "BLE", "vendor": "Unknown", "ui_tone": "neutral", "icon": "📱"},
    "unknown_candidate": {"device_type": "Unknown", "protocol": "BLE", "vendor": "Unknown", "ui_tone": "neutral", "icon": "❓"},
}


def classify_cluster(cluster: List[Dict[str, Any]]) -> str:
    ref = cluster[0] if cluster else {}
    uuids = set(ref.get("service_uuids") or [])
    company = ref.get("company_id")
    connectable = bool(ref.get("connectable"))
    name = str(ref.get("name") or "").strip()
    address_type = str(ref.get("address_type") or "unknown").strip().lower()

    if name and "unknown" not in name.lower():
        return "named_ble_device"
    if company == 76:
        return "mobile_apple"
    if company == 6:
        return "vendor_microsoft"
    if "fe2c" in uuids or "0201" in uuids:
        return "mobile_android_family"
    if not connectable:
        return "beacon_device"
    if connectable and address_type == "public":
        return "iot_candidate"
    if address_type == "random":
        return "mobile_privacy_device"
    return "unknown_candidate"
