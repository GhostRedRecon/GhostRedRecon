#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

import yaml


DEFAULT_DB = Path("/home/ghost/Documents/GhostRedRecon/backend/config/lora_lab_device_profiles.yaml")


def main() -> int:
    if not DEFAULT_DB.exists():
        print(json.dumps({"status": "error", "error": f"profile db not found: {DEFAULT_DB}"}))
        return 1

    data = yaml.safe_load(DEFAULT_DB.read_text(encoding="utf-8")) or {}
    profiles = data.get("profiles") or []
    rows = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        rows.append(
            {
                "profile_name": profile.get("profile_name"),
                "vendor": profile.get("vendor"),
                "product": profile.get("product"),
                "device_type": profile.get("device_type"),
                "bandplan": profile.get("bandplan"),
                "identity_family": profile.get("identity_family"),
                "role": profile.get("role"),
                "center_freq_mhz": profile.get("center_freq_mhz"),
                "cadence_class": profile.get("cadence_class"),
                "tags": profile.get("tags") or [],
            }
        )

    print(json.dumps({"status": "ok", "count": len(rows), "profiles": rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
