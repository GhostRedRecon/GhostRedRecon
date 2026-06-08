#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys


def fetch_json(url: str) -> dict:
    result = subprocess.run(
        ["curl", "-fsS", url],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"curl failed for {url}")
    return json.loads(result.stdout)


def safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate BLE detection consistency from GhostRedRecon API.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100", help="GhostRedRecon backend base URL")
    parser.add_argument("--limit", type=int, default=250, help="BLE intel record limit")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    try:
        health = fetch_json(f"{base_url}/health")
        payload = fetch_json(f"{base_url}/api/intel/band/BLE?limit={args.limit}")
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1

    signals = payload.get("signals") or []
    devices = payload.get("devices") or []
    entities = payload.get("correlated_entities") or []

    ble_signals = [
        signal for signal in signals
        if str(signal.get("protocol") or "").upper() == "BLE"
        or str(signal.get("rf_protocol") or "").upper() == "BLUETOOTH_LE"
    ]
    adv_channel_signals = [
        signal for signal in signals
        if signal.get("ble_channel") in {37, 38, 39}
    ]
    polluted_devices = [
        device for device in devices
        if any(
            proto not in {"BLE", "BLUETOOTH_LE", "UNKNOWN_PROTOCOL"}
            for proto in [str(item).upper() for item in (device.get("protocols") or [])]
        )
    ]
    ble_role_devices = [
        device for device in devices
        if device.get("ble_role") or device.get("device_role_hint")
    ]
    impure_entities = [
        entity for entity in entities
        if any(
            proto not in {"BLE", "BLUETOOTH_LE", "UNKNOWN_PROTOCOL"}
            for proto in [str(item).upper() for item in (entity.get("protocols") or [])]
        )
    ]
    duplicated_entity_ids = len({entity.get("entity_id") for entity in entities if entity.get("entity_id")}) != len(
        [entity for entity in entities if entity.get("entity_id")]
    )

    report = {
        "status": "ok",
        "health": health,
        "ble_validation": {
            "signal_count": len(signals),
            "device_count": len(devices),
            "entity_count": len(entities),
            "ble_signal_ratio": safe_ratio(len(ble_signals), len(signals)),
            "adv_channel_ratio": safe_ratio(len(adv_channel_signals), len(signals)),
            "ble_role_device_ratio": safe_ratio(len(ble_role_devices), len(devices)),
            "polluted_device_ratio": safe_ratio(len(polluted_devices), len(devices)),
            "correlation_purity_ratio": round(1.0 - safe_ratio(len(impure_entities), len(entities)), 4) if entities else 0.0,
            "duplicate_entity_ids": duplicated_entity_ids,
        },
    }

    score = 0.0
    score += report["ble_validation"]["ble_signal_ratio"] * 0.35
    score += report["ble_validation"]["adv_channel_ratio"] * 0.20
    score += report["ble_validation"]["ble_role_device_ratio"] * 0.20
    score += (1.0 - report["ble_validation"]["polluted_device_ratio"]) * 0.10
    score += report["ble_validation"]["correlation_purity_ratio"] * 0.15
    report["ble_validation"]["consistency_score"] = round(score, 4)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
