#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import urlopen


IOT_WIFI_HINTS = {
    "camera",
    "plug",
    "bulb",
    "thermostat",
    "vacuum",
    "speaker",
    "doorbell",
    "robot",
    "appliance",
    "printer",
    "sensor",
    "iot",
}

IOT_TEXT_HINTS = {
    "iot",
    "sensor",
    "meter",
    "telemetry",
    "tracker",
    "beacon",
    "gateway",
    "hub",
    "camera",
    "plug",
    "bulb",
    "thermostat",
    "alarm",
    "lock",
    "appliance",
    "leak",
    "flow",
    "parking",
    "utility",
    "mesh",
}

FAMILY_CONFLICT_TOKENS = {
    "ble": {"wifi", "access point", "zigbee", "lora", "lorawan", "wifi_device", "zigbee_sensor", "zigbee_iot"},
    "zigbee": {"wifi", "access point", "ble", "bluetooth", "lora", "lorawan", "wifi_device", "asset_tracker"},
    "wifi": {"ble", "bluetooth", "zigbee", "lora", "lorawan", "asset_tracker", "zigbee_sensor", "zigbee_iot"},
}


def fetch_json(url: str) -> dict:
    with urlopen(url, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def score_signal(signal: dict) -> bool:
    protocol = str(signal.get("protocol") or "").lower()
    rf_protocol = str(signal.get("rf_protocol") or "").lower()
    family = str(signal.get("channel_family") or "").lower()
    haystack = str(signal).lower()

    if protocol in {"ble", "zigbee", "thread", "lora"}:
        return True
    if rf_protocol in {"bluetooth_le", "ieee_802.15.4", "ieee_802.15.4_zigbee", "wireless_mbus"}:
        return True
    if family in {"ble", "zigbee", "wifi"}:
        if family != "wifi":
            return True
        return any(token in haystack for token in IOT_WIFI_HINTS)
    if any(token in haystack for token in IOT_TEXT_HINTS):
        return True
    return False


def record_family(record: dict) -> str:
    protocol = str(record.get("protocol") or "").lower()
    rf_protocol = str(record.get("rf_protocol") or "").lower()
    protocols = {str(item or "").lower() for item in record.get("protocols") or []}
    channel_family = str(record.get("channel_family") or "").lower()
    if channel_family in {"ble", "zigbee", "wifi"}:
        return channel_family
    if protocol == "ble" or rf_protocol == "bluetooth_le" or "ble" in protocols:
        return "ble"
    if protocol == "zigbee" or rf_protocol in {"ieee_802.15.4", "ieee_802.15.4_zigbee"} or "zigbee" in protocols:
        return "zigbee"
    if protocol == "wifi" or "802.11" in rf_protocol or "wifi" in protocols:
        return "wifi"
    return ""


def label_is_pure(record: dict) -> bool:
    family = record_family(record)
    if family not in FAMILY_CONFLICT_TOKENS:
        return True
    haystack = " ".join(
        str(record.get(field) or "")
        for field in ("product", "device_type", "device_category", "product_category_hint")
    ).lower()
    return not any(token in haystack for token in FAMILY_CONFLICT_TOKENS[family])


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate IoT aggregate-band detection posture.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100")
    parser.add_argument("--limit", type=int, default=250)
    parser.add_argument("--snapshot", action="append", default=[], help="Optional saved /api/intel/band/IOT snapshot JSON path")
    args = parser.parse_args()

    if args.snapshot:
        signals = []
        devices_by_id = {}
        entities_by_id = {}
        for snapshot_path in args.snapshot:
            payload = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
            for signal in payload.get("signals") or []:
                if isinstance(signal, dict):
                    signals.append(signal)
            for device in payload.get("devices") or []:
                if not isinstance(device, dict):
                    continue
                device_id = str(device.get("device_id") or f"anon-{len(devices_by_id)}")
                devices_by_id[device_id] = device
            for entity in payload.get("correlated_entities") or []:
                if not isinstance(entity, dict):
                    continue
                entity_id = str(entity.get("entity_id") or f"anon-{len(entities_by_id)}")
                entities_by_id[entity_id] = entity
        devices = list(devices_by_id.values())
        entities = list(entities_by_id.values())
    else:
        payload = fetch_json(f"{args.base_url}/api/intel/band/IOT?limit={args.limit}")
        signals = payload.get("signals") or []
        devices = payload.get("devices") or []
        entities = payload.get("correlated_entities") or []

    scored_signals = [signal for signal in signals if score_signal(signal)]
    wifi_iot_signals = [
        signal for signal in signals
        if str(signal.get("protocol") or "").lower() == "wifi" and any(token in str(signal).lower() for token in IOT_WIFI_HINTS)
    ]
    subghz_iot_signals = [
        signal for signal in signals
        if 0 < float(signal.get("frequency_mhz") or signal.get("freq_mhz") or 0.0) < 1000
    ]
    typed_devices = [
        device for device in devices
        if device.get("device_type") or device.get("device_category") or device.get("lora_identity_family")
    ]
    pure_labeled_signals = [signal for signal in signals if label_is_pure(signal)]
    pure_labeled_devices = [device for device in devices if label_is_pure(device)]
    matched_profile_devices = [
        device for device in devices
        if device.get("matched_product_profile") or device.get("matched_device_profile") or device.get("matched_burst_signature")
    ]
    multi_protocol_devices = [
        device for device in devices
        if isinstance(device.get("protocols"), list) and len(device.get("protocols")) > 1
    ]
    utility_devices = [
        device for device in devices
        if any(token in str(device).lower() for token in {"meter", "utility", "wireless m-bus", "wmbus"})
    ]
    family_counts = {}
    for device in devices:
        family = (
            device.get("lora_identity_family")
            or device.get("device_category")
            or device.get("device_type")
            or "unknown"
        )
        family_counts[str(family)] = family_counts.get(str(family), 0) + 1

    total_signals = len(signals) or 1
    total_devices = len(devices) or 1
    validation = {
        "signal_count": len(signals),
        "device_count": len(devices),
        "entity_count": len(entities),
        "iot_signal_ratio": round(len(scored_signals) / total_signals, 4),
        "typed_device_ratio": round(len(typed_devices) / total_devices, 4),
        "signal_label_purity_ratio": round(len(pure_labeled_signals) / total_signals, 4),
        "device_label_purity_ratio": round(len(pure_labeled_devices) / total_devices, 4),
        "matched_profile_ratio": round(len(matched_profile_devices) / total_devices, 4),
        "multi_protocol_device_ratio": round(len(multi_protocol_devices) / total_devices, 4),
        "utility_meter_ratio": round(len(utility_devices) / total_devices, 4),
        "wifi_iot_signal_ratio": round(len(wifi_iot_signals) / total_signals, 4),
        "subghz_iot_signal_ratio": round(len(subghz_iot_signals) / total_signals, 4),
        "family_counts": family_counts,
        "consistency_score": round(
            (
                0.40 * (len(scored_signals) / total_signals)
                + 0.15 * (len(typed_devices) / total_devices)
                + 0.10 * (len(pure_labeled_signals) / total_signals)
                + 0.05 * (len(pure_labeled_devices) / total_devices)
                + 0.10 * (len(matched_profile_devices) / total_devices)
                + 0.15 * min(len(wifi_iot_signals) / total_signals, 1.0)
                + 0.15 * min(len(subghz_iot_signals) / total_signals, 1.0)
            ),
            4,
        ),
    }

    print(json.dumps({"iot_validation": validation}, indent=2))


if __name__ == "__main__":
    main()
