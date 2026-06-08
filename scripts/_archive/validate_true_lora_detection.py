#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


LORA_PROTOCOLS = {"LORA", "LORA_PHY"}
LORA_ALLOWED_PROTOCOLS = LORA_PROTOCOLS | {"UNKNOWN_PROTOCOL"}
LORA_CENTERS = [
    433.175, 433.375, 433.775, 433.92,
    867.10, 867.30, 867.50, 867.70, 867.90,
    868.10, 868.30, 868.50, 869.525,
    903.90, 904.10, 904.30, 904.50, 904.70, 904.90, 905.10, 905.30,
    923.30,
]


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


def nearest_distance(freq: float, centers: list[float]) -> float | None:
    if not centers:
        return None
    return min(abs(freq - center) for center in centers)


def signal_meta(signal: dict) -> dict:
    meta = signal.get("metadata")
    return meta if isinstance(meta, dict) else {}


def signal_freq(signal: dict) -> float:
    try:
        return float(signal.get("frequency_mhz") or signal.get("freq_mhz") or signal_meta(signal).get("frequency_mhz") or 0.0)
    except Exception:
        return 0.0


def is_lora_signal(signal: dict) -> bool:
    protocol = str(signal.get("protocol") or "").upper()
    rf_protocol = str(signal.get("rf_protocol") or "").upper()
    profile = str(signal.get("subghz_profile") or signal_meta(signal).get("subghz_profile") or signal_meta(signal).get("rf_subghz_profile") or "").lower()
    modulation = str(signal_meta(signal).get("rf_modulation_hint") or "").lower()
    frame_structure = str(signal_meta(signal).get("rf_frame_structure") or "").lower()
    chirp = bool(signal_meta(signal).get("rf_chirp_detected"))
    return (
        protocol in LORA_PROTOCOLS
        or rf_protocol in LORA_PROTOCOLS
        or "lora" in profile
        or modulation == "lora_like"
        or frame_structure == "chirp"
        or chirp
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate true LoRa detection consistency from GhostRedRecon API.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100", help="GhostRedRecon backend base URL")
    parser.add_argument("--limit", type=int, default=250, help="LoRa intel record limit")
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
            payload = fetch_json(f"{base_url}/api/intel/band/lora?limit={args.limit}")
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1

    signals = payload.get("signals") or []
    devices = payload.get("devices") or []
    entities = payload.get("correlated_entities") or []

    lora_signals = [signal for signal in signals if is_lora_signal(signal)]
    center_hits = []
    chirp_hits = []
    periodic_hits = []
    for signal in signals:
        freq = signal_freq(signal)
        distance = nearest_distance(freq, LORA_CENTERS)
        if distance is not None and distance <= 1.2:
            center_hits.append(signal)
        meta = signal_meta(signal)
        if bool(meta.get("rf_chirp_detected")) or str(meta.get("rf_frame_structure") or "").lower() == "chirp" or str(meta.get("rf_modulation_hint") or "").lower() == "lora_like":
            chirp_hits.append(signal)
        periodicity = meta.get("periodicity") if meta.get("periodicity") is not None else signal.get("periodicity")
        try:
            periodicity_value = float(periodicity or 0.0)
        except Exception:
            periodicity_value = 0.0
        if periodicity_value >= 0.6:
            periodic_hits.append(signal)

    role_devices = [
        device for device in devices
        if device.get("lora_role") or device.get("lora_operating_mode_hint") or device.get("device_role_hint") == "end_device"
    ]
    typed_devices = [device for device in devices if device.get("lora_device_type_hint") or device.get("lora_identity_family")]
    meter_like_devices = [device for device in devices if device.get("lora_meter_like")]
    mesh_like_devices = [device for device in devices if device.get("lora_mesh_like")]
    lorawan_like_devices = [device for device in devices if device.get("lora_lorawan_like")]
    matched_profile_devices = [device for device in devices if device.get("lora_lab_profile_name")]
    polluted_devices = [
        device for device in devices
        if any(str(proto).upper() not in LORA_ALLOWED_PROTOCOLS for proto in (device.get("protocols") or []))
    ]
    impure_entities = [
        entity for entity in entities
        if any(str(proto).upper() not in LORA_ALLOWED_PROTOCOLS for proto in (entity.get("protocols") or []))
    ]
    duplicated_entity_ids = len({entity.get("entity_id") for entity in entities if entity.get("entity_id")}) != len(
        [entity for entity in entities if entity.get("entity_id")]
    )
    identity_family_counts = {}
    bandplan_counts = {}
    cadence_counts = {}
    matched_profile_counts = {}
    for device in devices:
        bandplan = str(device.get("lora_bandplan") or "").strip()
        if bandplan:
            bandplan_counts[bandplan] = bandplan_counts.get(bandplan, 0) + 1
        cadence = str(device.get("lora_cadence_class") or "").strip()
        if cadence:
            cadence_counts[cadence] = cadence_counts.get(cadence, 0) + 1
        profile_name = str(device.get("lora_lab_profile_name") or "").strip()
        if profile_name:
            matched_profile_counts[profile_name] = matched_profile_counts.get(profile_name, 0) + 1
        family = str(device.get("lora_identity_family") or "").strip()
        if not family:
            continue
        identity_family_counts[family] = identity_family_counts.get(family, 0) + 1

    report = {
        "status": "ok",
        "health": health,
        "true_lora_validation": {
            "signal_count": len(signals),
            "device_count": len(devices),
            "entity_count": len(entities),
            "lora_signal_ratio": safe_ratio(len(lora_signals), len(signals)),
            "lora_center_ratio": safe_ratio(len(center_hits), len(signals)),
            "chirp_evidence_ratio": safe_ratio(len(chirp_hits), len(signals)),
            "periodic_lora_ratio": safe_ratio(len(periodic_hits), len(signals)),
            "role_device_ratio": safe_ratio(len(role_devices), len(devices)),
            "typed_device_ratio": safe_ratio(len(typed_devices), len(devices)),
            "matched_lab_profile_ratio": safe_ratio(len(matched_profile_devices), len(devices)),
            "meter_like_ratio": safe_ratio(len(meter_like_devices), len(devices)),
            "mesh_like_ratio": safe_ratio(len(mesh_like_devices), len(devices)),
            "lorawan_like_ratio": safe_ratio(len(lorawan_like_devices), len(devices)),
            "polluted_device_ratio": safe_ratio(len(polluted_devices), len(devices)),
            "correlation_purity_ratio": round(1.0 - safe_ratio(len(impure_entities), len(entities)), 4) if entities else 1.0,
            "duplicate_entity_ids": duplicated_entity_ids,
            "identity_family_counts": identity_family_counts,
            "bandplan_counts": bandplan_counts,
            "cadence_counts": cadence_counts,
            "matched_profile_counts": matched_profile_counts,
        },
    }

    score = 0.0
    score += report["true_lora_validation"]["lora_signal_ratio"] * 0.25
    score += report["true_lora_validation"]["lora_center_ratio"] * 0.20
    score += report["true_lora_validation"]["chirp_evidence_ratio"] * 0.20
    score += report["true_lora_validation"]["periodic_lora_ratio"] * 0.10
    score += report["true_lora_validation"]["role_device_ratio"] * 0.15
    score += report["true_lora_validation"]["typed_device_ratio"] * 0.03
    score += report["true_lora_validation"]["matched_lab_profile_ratio"] * 0.05
    score += report["true_lora_validation"]["lorawan_like_ratio"] * 0.02
    score += (1.0 - report["true_lora_validation"]["polluted_device_ratio"]) * 0.03
    score += report["true_lora_validation"]["correlation_purity_ratio"] * 0.05
    report["true_lora_validation"]["consistency_score"] = round(score, 4)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
