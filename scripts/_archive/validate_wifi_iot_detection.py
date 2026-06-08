#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import urlopen


WIFI_IOT_HINTS = {
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
    "iot",
    "sensor",
    "gateway",
    "hub",
}

CONFLICT_TOKENS = {"zigbee", "ble", "bluetooth", "lora", "lorawan", "asset_tracker", "zigbee_sensor", "zigbee_iot"}
INFRASTRUCTURE_TOKENS = {"access point", "ap", "router", "ssid", "base station", "wifi infrastructure"}


def fetch_json(url: str) -> dict:
    with urlopen(url, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def is_wifi_signal(signal: dict) -> bool:
    protocol = str(signal.get("protocol") or "").lower()
    rf_protocol = str(signal.get("rf_protocol") or "").lower()
    family = str(signal.get("channel_family") or "").lower()
    return protocol == "wifi" or "802.11" in rf_protocol or family == "wifi"


def is_wifi_iot_device(device: dict) -> bool:
    protocols = {str(item or "").upper() for item in device.get("protocols") or []}
    if "WIFI" not in protocols:
        return False
    haystack = " ".join(
        str(device.get(field) or "")
        for field in ("product", "device_type", "device_category", "product_category_hint", "behavior_profile_hint")
    ).lower()
    if any(token in haystack for token in INFRASTRUCTURE_TOKENS):
        return False
    return any(token in haystack for token in WIFI_IOT_HINTS)


def label_is_pure(record: dict) -> bool:
    haystack = " ".join(
        str(record.get(field) or "")
        for field in ("product", "device_type", "device_category", "product_category_hint")
    ).lower()
    return not any(token in haystack for token in CONFLICT_TOKENS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate WiFi IoT detection posture.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100")
    parser.add_argument("--limit", type=int, default=250)
    parser.add_argument("--snapshot", action="append", default=[], help="Optional saved /api/intel/band/WIFI snapshot JSON path")
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
                if isinstance(device, dict):
                    devices_by_id[str(device.get("device_id") or f"anon-{len(devices_by_id)}")] = device
            for entity in payload.get("correlated_entities") or []:
                if isinstance(entity, dict):
                    entities_by_id[str(entity.get("entity_id") or f"anon-{len(entities_by_id)}")] = entity
        devices = list(devices_by_id.values())
        entities = list(entities_by_id.values())
    else:
        payload = fetch_json(f"{args.base_url}/api/intel/band/WIFI?limit={args.limit}")
        signals = payload.get("signals") or []
        devices = payload.get("devices") or []
        entities = payload.get("correlated_entities") or []

    wifi_signals = [signal for signal in signals if is_wifi_signal(signal)]
    wifi_iot_signals = [signal for signal in wifi_signals if any(token in str(signal).lower() for token in WIFI_IOT_HINTS)]
    pure_signals = [signal for signal in wifi_signals if label_is_pure(signal)]
    pure_devices = [device for device in devices if label_is_pure(device)]
    wifi_iot_devices = [device for device in devices if is_wifi_iot_device(device)]
    matched_profile_devices = [
        device for device in devices
        if device.get("matched_product_profile") or device.get("matched_device_profile") or device.get("matched_burst_signature")
    ]

    total_signals = len(signals) or 1
    total_devices = len(devices) or 1

    validation = {
        "signal_count": len(signals),
        "device_count": len(devices),
        "entity_count": len(entities),
        "wifi_signal_ratio": round(len(wifi_signals) / total_signals, 4),
        "wifi_iot_signal_ratio": round(len(wifi_iot_signals) / total_signals, 4),
        "wifi_iot_device_ratio": round(len(wifi_iot_devices) / total_devices, 4),
        "signal_label_purity_ratio": round(len(pure_signals) / max(len(wifi_signals), 1), 4),
        "device_label_purity_ratio": round(len(pure_devices) / total_devices, 4),
        "matched_profile_ratio": round(len(matched_profile_devices) / total_devices, 4),
        "consistency_score": round(
            (
                0.35 * (len(wifi_signals) / total_signals)
                + 0.20 * (len(wifi_iot_signals) / total_signals)
                + 0.20 * (len(wifi_iot_devices) / total_devices)
                + 0.15 * (len(pure_signals) / max(len(wifi_signals), 1))
                + 0.10 * (len(pure_devices) / total_devices)
            ),
            4,
        ),
    }

    print(json.dumps({"wifi_iot_validation": validation}, indent=2))


if __name__ == "__main__":
    main()
