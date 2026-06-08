#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import yaml


def fetch_payload(snapshot_path: str | None, payload_path: str | None) -> dict:
    if snapshot_path:
        return json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
    if payload_path:
        return json.loads(Path(payload_path).read_text(encoding="utf-8"))
    raise RuntimeError("snapshot or payload path required")


def choose_devices(devices: List[Dict[str, Any]], family: str | None) -> List[Dict[str, Any]]:
    selected = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        protocols = {str(v).upper() for v in (device.get("protocols") or [])}
        if "LORA" not in protocols and not device.get("lora_identity_family") and not device.get("lora_bandplan"):
            continue
        if family and str(device.get("lora_identity_family") or "").strip().lower() != family:
            continue
        selected.append(device)
    return selected


def mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def build_profile(args, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    freqs: List[float] = []
    spans: List[float] = []
    counts: List[float] = []
    confidences: List[float] = []
    bandwidths: List[float] = []
    bandplans: Dict[str, int] = {}
    cadences: Dict[str, int] = {}
    families: Dict[str, int] = {}
    roles: Dict[str, int] = {}

    for device in devices:
        for freq in device.get("frequencies") or []:
            try:
                freqs.append(float(freq))
            except Exception:
                pass
        for key, bucket in [
            ("lora_bandplan", bandplans),
            ("lora_cadence_class", cadences),
            ("lora_identity_family", families),
            ("lora_role", roles),
        ]:
            value = str(device.get(key) or "").strip().lower()
            if value:
                bucket[value] = bucket.get(value, 0) + 1
        try:
            spans.append(float(device.get("lora_dwell_span_mhz") or 0.0))
        except Exception:
            pass
        try:
            counts.append(float(device.get("lora_frequency_count") or 0.0))
        except Exception:
            pass
        try:
            confidences.append(float(device.get("lora_lab_profile_confidence") or device.get("lora_device_type_confidence") or 0.0))
        except Exception:
            pass
        try:
            bandwidths.append(float(device.get("bandwidth_estimate_mhz") or 0.0))
        except Exception:
            pass

    def top(bucket: Dict[str, int], default: str) -> str:
        return max(bucket, key=bucket.get) if bucket else default

    center = mean(freqs)
    return {
        "profile_name": args.profile_name,
        "vendor": args.vendor,
        "product": args.product,
        "device_type": args.device_type,
        "bandplan": args.bandplan or top(bandplans, "unknown"),
        "region": args.region or top(bandplans, "unknown"),
        "center_freq_mhz": round(center, 4) if freqs else None,
        "dwell_span_mhz": round(mean(spans), 4) if spans else None,
        "frequency_count": round(mean(counts), 2) if counts else None,
        "bandwidth_mhz": round(mean(bandwidths), 4) if bandwidths else None,
        "cadence_class": args.cadence_class or top(cadences, "sporadic"),
        "identity_family": args.identity_family or top(families, "lora_end_device"),
        "role": args.role or top(roles, "end_device"),
        "profile_confidence": round(mean(confidences), 4) if confidences else None,
        "notes": args.notes or None,
        "tags": [tag.strip() for tag in (args.tags or "").split(",") if tag.strip()],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture a known LoRa device profile from a GhostRedRecon snapshot.")
    parser.add_argument("--snapshot", help="Path to a band snapshot JSON file")
    parser.add_argument("--payload", help="Path to a raw payload JSON file")
    parser.add_argument("--output", default="/home/ghost/Documents/GhostRedRecon/backend/config/lora_lab_device_profiles.yaml")
    parser.add_argument("--profile-name", required=True)
    parser.add_argument("--vendor", required=True)
    parser.add_argument("--product", required=True)
    parser.add_argument("--device-type", required=True)
    parser.add_argument("--bandplan")
    parser.add_argument("--region")
    parser.add_argument("--cadence-class")
    parser.add_argument("--identity-family")
    parser.add_argument("--role")
    parser.add_argument("--filter-family")
    parser.add_argument("--notes")
    parser.add_argument("--tags", help="Comma-separated tags like lab,eu868,meter")
    args = parser.parse_args()

    payload = fetch_payload(args.snapshot, args.payload)
    devices = choose_devices(payload.get("devices") or [], args.filter_family)
    if not devices:
        raise SystemExit("no LoRa devices found in payload")

    profile = build_profile(args, devices)
    out = Path(args.output)
    if out.exists():
        data = yaml.safe_load(out.read_text(encoding="utf-8")) or {}
    else:
        data = {}
    profiles = data.get("profiles") or []
    profiles = [entry for entry in profiles if isinstance(entry, dict) and entry.get("profile_name") != args.profile_name]
    profiles.append(profile)
    data["profiles"] = profiles
    out.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    print(json.dumps({"status": "ok", "profile": profile, "output": str(out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
