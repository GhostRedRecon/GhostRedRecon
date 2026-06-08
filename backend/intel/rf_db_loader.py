# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/rf_db_loader.py
# VERSION:      v1.0.0 (YAML RF DATABASE LOADER)
# =============================================================================

import os
import yaml


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


# =============================================================================
# LOAD YAML DB
# =============================================================================
def load_yaml_db():

    # ---------------------------------------------------------
    # ENV override (recommended)
    # ---------------------------------------------------------
    env_path = os.getenv("GHOSTRECON_RF_BURST_DB")

    if env_path and os.path.exists(env_path):
        return _load_yaml(env_path)

    # ---------------------------------------------------------
    # Default fallback paths
    # ---------------------------------------------------------
    possible_paths = [
        os.path.join(BASE_DIR, "backend", "config", "rf_burst_signatures.yaml"),
        os.path.join(BASE_DIR, "backend", "intel", "rf_burst_signatures.yaml"),
        os.path.join(BASE_DIR, "rf_burst_signatures.yaml"),
        "backend/config/rf_burst_signatures.yaml",
        "backend/intel/rf_burst_signatures.yaml",
        "rf_burst_signatures.yaml",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return _load_yaml(path)

    print("[RF_DB] No YAML DB found")
    return []


# =============================================================================
# INTERNAL LOADER
# =============================================================================
def _load_yaml(path):

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)

            if isinstance(data, list):
                return data

            if isinstance(data, dict):
                # allow both formats
                return data.get("devices", []) or data.get("entries", [])

    except Exception as e:
        print(f"[RF_DB] Failed to load {path}: {e}")

    return []
