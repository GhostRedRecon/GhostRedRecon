#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ZIGBEE_PROTOCOLS = {"ZIGBEE", "IEEE_802.15.4", "IEEE_802.15.4_ZIGBEE", "IEEE_802154_ZIGBEE"}
ZIGBEE_ALLOWED_PROTOCOLS = ZIGBEE_PROTOCOLS | {"UNKNOWN_PROTOCOL"}


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
    parser = argparse.ArgumentParser(description="Validate Zigbee detection consistency from GhostRedRecon API.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100", help="GhostRedRecon backend base URL")
    parser.add_argument("--limit", type=int, default=250, help="Zigbee intel record limit")
    parser.add_argument("--snapshot", action="append", default=[], help="Optional snapshot JSON file(s) to validate as an aggregate sweep")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    try:
        health = fetch_json(f"{base_url}/health")
        if args.snapshot:
            payload = {
                "signals": [],
                "devices": [],
                "correlated_entities": [],
            }
            for snapshot_path in args.snapshot:
                snapshot = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
                payload["signals"].extend(snapshot.get("signals") or [])
                payload["devices"].extend(snapshot.get("devices") or [])
                payload["correlated_entities"].extend(snapshot.get("correlated_entities") or [])
        else:
            payload = fetch_json(f"{base_url}/api/intel/band/ZIGBEE?limit={args.limit}")
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1

    signals = payload.get("signals") or []
    devices = payload.get("devices") or []
    entities = payload.get("correlated_entities") or []

    zigbee_signals = [
        signal for signal in signals
        if str(signal.get("protocol") or "").upper() in ZIGBEE_PROTOCOLS
        or str(signal.get("rf_protocol") or "").upper() == "IEEE_802.15.4"
    ]
    channel_hits = [signal for signal in signals if signal.get("zigbee_channel") is not None]
    polluted_devices = [
        device for device in devices
        if any(
            str(proto).upper() not in ZIGBEE_ALLOWED_PROTOCOLS
            for proto in (device.get("protocols") or [])
        )
    ]
    role_devices = [
        device for device in devices
        if device.get("device_role_hint") or str(device.get("device_category") or "").lower().startswith("zigbee")
    ]
    impure_entities = [
        entity for entity in entities
        if any(
            str(proto).upper() not in ZIGBEE_ALLOWED_PROTOCOLS
            for proto in (entity.get("protocols") or [])
        )
    ]
    duplicated_entity_ids = len({entity.get("entity_id") for entity in entities if entity.get("entity_id")}) != len(
        [entity for entity in entities if entity.get("entity_id")]
    )

    report = {
        "status": "ok",
        "health": health,
        "zigbee_validation": {
            "signal_count": len(signals),
            "device_count": len(devices),
            "entity_count": len(entities),
            "zigbee_signal_ratio": safe_ratio(len(zigbee_signals), len(signals)),
            "channel_ratio": safe_ratio(len(channel_hits), len(signals)),
            "role_device_ratio": safe_ratio(len(role_devices), len(devices)),
            "polluted_device_ratio": safe_ratio(len(polluted_devices), len(devices)),
            "correlation_purity_ratio": round(1.0 - safe_ratio(len(impure_entities), len(entities)), 4) if entities else 0.0,
            "duplicate_entity_ids": duplicated_entity_ids,
        },
    }

    score = 0.0
    score += report["zigbee_validation"]["zigbee_signal_ratio"] * 0.35
    score += report["zigbee_validation"]["channel_ratio"] * 0.25
    score += report["zigbee_validation"]["role_device_ratio"] * 0.15
    score += (1.0 - report["zigbee_validation"]["polluted_device_ratio"]) * 0.10
    score += report["zigbee_validation"]["correlation_purity_ratio"] * 0.15
    report["zigbee_validation"]["consistency_score"] = round(score, 4)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
