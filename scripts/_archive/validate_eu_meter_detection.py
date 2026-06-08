#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import urlopen


METER_TOKENS = {
    "meter",
    "wireless m-bus",
    "wmbus",
    "utility",
    "water meter",
    "gas meter",
    "heat meter",
    "consumption",
}

WMBUS_PROTOCOLS = {
    "wireless_mbus",
    "wmbus",
}

WMBUS_RF_PROTOCOLS = {
    "wireless_mbus",
}


def signal_wmbus_evidence(signal: dict) -> bool:
    protocol = str(signal.get("protocol") or "").lower()
    rf_protocol = str(signal.get("rf_protocol") or "").lower()
    frame_hint = str(signal.get("rf_frame_protocol_hint") or signal.get("metadata", {}).get("rf_frame_protocol_hint") or "").lower()
    frame_structure = str(signal.get("rf_frame_structure") or signal.get("metadata", {}).get("rf_frame_structure") or "").lower()
    profile = str(signal.get("rf_subghz_profile") or signal.get("subghz_profile") or signal.get("metadata", {}).get("rf_subghz_profile") or "").lower()
    chirp = float(signal.get("spectral_chirp_hint") or signal.get("metadata", {}).get("spectral_chirp_hint") or 0.0)

    if protocol in WMBUS_PROTOCOLS or rf_protocol in WMBUS_RF_PROTOCOLS:
        return True
    if frame_hint in {"wirelessmbus", "wireless_mbus", "wmbus"} and chirp <= 0.35:
        return True
    if profile == "wireless_mbus_like" and frame_structure == "metering_burst" and chirp <= 0.35:
        return True
    return False


def fetch_json(url: str) -> dict:
    with urlopen(url, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def is_meter_signal(signal: dict) -> bool:
    protocol = str(signal.get("protocol") or "").lower()
    rf_protocol = str(signal.get("rf_protocol") or "").lower()
    haystack = str(signal).lower()
    if protocol in WMBUS_PROTOCOLS or rf_protocol in WMBUS_RF_PROTOCOLS:
        return True
    return any(token in haystack for token in METER_TOKENS)


def is_meter_device(device: dict) -> bool:
    protocols = {str(item or "").lower() for item in device.get("protocols") or []}
    haystack = str(device).lower()
    if protocols & WMBUS_PROTOCOLS:
        return True
    return any(token in haystack for token in METER_TOKENS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate EU meter / Wireless M-Bus detection posture.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100")
    parser.add_argument("--limit", type=int, default=250)
    parser.add_argument("--snapshot", action="append", default=[], help="Optional saved /api/intel/band/sub-ghz snapshot JSON path")
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
        payload = fetch_json(f"{args.base_url}/api/intel/band/sub-ghz?limit={args.limit}")
        signals = payload.get("signals") or []
        devices = payload.get("devices") or []
        entities = payload.get("correlated_entities") or []

    meter_signals = [signal for signal in signals if is_meter_signal(signal)]
    meter_devices = [device for device in devices if is_meter_device(device)]
    wmbus_signals = [signal for signal in signals if signal_wmbus_evidence(signal)]
    wmbus_devices = [
        device for device in devices
        if {str(item or "").lower() for item in device.get("protocols") or []} & WMBUS_PROTOCOLS
    ]
    typed_meter_devices = [
        device for device in meter_devices
        if device.get("device_type") or device.get("product") or device.get("device_category")
    ]

    total_signals = len(signals) or 1
    total_devices = len(devices) or 1
    validation = {
        "signal_count": len(signals),
        "device_count": len(devices),
        "entity_count": len(entities),
        "meter_signal_ratio": round(len(meter_signals) / total_signals, 4),
        "meter_device_ratio": round(len(meter_devices) / total_devices, 4),
        "wireless_mbus_signal_ratio": round(len(wmbus_signals) / total_signals, 4),
        "wireless_mbus_device_ratio": round(len(wmbus_devices) / total_devices, 4),
        "typed_meter_device_ratio": round(len(typed_meter_devices) / total_devices, 4),
        "consistency_score": round(
            (
                0.34 * (len(meter_signals) / total_signals)
                + 0.25 * (len(meter_devices) / total_devices)
                + 0.14 * (len(wmbus_signals) / total_signals)
                + 0.12 * (len(wmbus_devices) / total_devices)
                + 0.15 * (len(typed_meter_devices) / total_devices)
            ),
            4,
        ),
    }

    print(json.dumps({"eu_meter_validation": validation}, indent=2))


if __name__ == "__main__":
    main()
