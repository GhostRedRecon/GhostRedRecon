#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


LORA_PROTOCOLS = {"LORA", "LORA_PHY"}
SUBGHZ_PROTOCOLS = LORA_PROTOCOLS | {"SUBGHZ", "SUBGHZ_FSK", "SUBGHZ_OOK", "FSK", "OOK"}
ALLOWED_PROTOCOLS = SUBGHZ_PROTOCOLS | {"UNKNOWN_PROTOCOL"}


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


def is_subghz_signal(signal: dict) -> bool:
    protocol = str(signal.get("protocol") or "").upper()
    rf_protocol = str(signal.get("rf_protocol") or "").upper()
    try:
        freq = float(signal.get("frequency_mhz") or signal.get("freq_mhz") or 0.0)
    except Exception:
        freq = 0.0
    return protocol in SUBGHZ_PROTOCOLS or rf_protocol in SUBGHZ_PROTOCOLS or (0.0 < freq < 1000.0)


def is_lora_signal(signal: dict) -> bool:
    protocol = str(signal.get("protocol") or "").upper()
    rf_protocol = str(signal.get("rf_protocol") or "").upper()
    profile = str(signal.get("subghz_profile") or signal.get("rf_subghz_profile") or "").lower()
    return protocol in LORA_PROTOCOLS or rf_protocol in LORA_PROTOCOLS or "lora" in profile


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate LoRa/Sub-GHz detection consistency from GhostRedRecon API.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100", help="GhostRedRecon backend base URL")
    parser.add_argument("--limit", type=int, default=250, help="Sub-GHz intel record limit")
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
            payload = fetch_json(f"{base_url}/api/intel/band/sub-ghz?limit={args.limit}")
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1

    signals = payload.get("signals") or []
    devices = payload.get("devices") or []
    entities = payload.get("correlated_entities") or []

    subghz_signals = [signal for signal in signals if is_subghz_signal(signal)]
    lora_signals = [signal for signal in signals if is_lora_signal(signal)]
    recurring_signals = [
        signal for signal in signals
        if (signal.get("periodicity") is not None)
        or (signal.get("subghz_periodicity") is not None)
        or float(signal.get("burst_recurrence_score") or 0.0) >= 0.4
    ]
    role_devices = [
        device for device in devices
        if device.get("lora_role")
        or device.get("subghz_role")
        or device.get("device_role_hint")
        or str(device.get("device_category") or "").lower().startswith(("lora", "subghz"))
    ]
    polluted_devices = [
        device for device in devices
        if any(
            str(proto).upper() not in ALLOWED_PROTOCOLS
            for proto in (device.get("protocols") or [])
        )
    ]
    impure_entities = [
        entity for entity in entities
        if any(
            str(proto).upper() not in ALLOWED_PROTOCOLS
            for proto in (entity.get("protocols") or [])
        )
    ]
    duplicated_entity_ids = len({entity.get("entity_id") for entity in entities if entity.get("entity_id")}) != len(
        [entity for entity in entities if entity.get("entity_id")]
    )

    report = {
        "status": "ok",
        "health": health,
        "lora_validation": {
            "signal_count": len(signals),
            "device_count": len(devices),
            "entity_count": len(entities),
            "subghz_signal_ratio": safe_ratio(len(subghz_signals), len(signals)),
            "lora_signal_ratio": safe_ratio(len(lora_signals), len(signals)),
            "recurrence_signal_ratio": safe_ratio(len(recurring_signals), len(signals)),
            "role_device_ratio": safe_ratio(len(role_devices), len(devices)),
            "polluted_device_ratio": safe_ratio(len(polluted_devices), len(devices)),
            "correlation_purity_ratio": round(1.0 - safe_ratio(len(impure_entities), len(entities)), 4) if entities else 1.0,
            "duplicate_entity_ids": duplicated_entity_ids,
        },
    }

    score = 0.0
    score += report["lora_validation"]["subghz_signal_ratio"] * 0.25
    score += report["lora_validation"]["lora_signal_ratio"] * 0.20
    score += report["lora_validation"]["recurrence_signal_ratio"] * 0.20
    score += report["lora_validation"]["role_device_ratio"] * 0.15
    score += (1.0 - report["lora_validation"]["polluted_device_ratio"]) * 0.10
    score += report["lora_validation"]["correlation_purity_ratio"] * 0.10
    report["lora_validation"]["consistency_score"] = round(score, 4)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
