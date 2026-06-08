# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/api/device_api.py
# VERSION:      v2.0.0 (PHASE 3 - VERIFIED DEVICE INTELLIGENCE API)
# UPDATED:      2026-03-22
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
# FastAPI Router (THIS FILE)
#   ↓
# Runtime Resolution Layer
#   ↓
# Runtime-owned DeviceFusion Engine
#   ↓
# Fused Device Graph Export
#   ↓
# Device List / Device Summary / Device Detail / Top Devices
#   ↓
# Validator / UI / Operator Workflows
#
# HIGH-LEVEL ROLE
# -----------------------------------------------------------------------------
# This module is the READ-ONLY API surface for Phase 3 device-aware
# intelligence.
#
# It does not perform fusion logic itself.
# It resolves the live runtime instance, accesses the active device fusion
# engine, and returns JSON-safe device intelligence views to operators,
# validators, and downstream systems.
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# Expose Phase 3 fused device intelligence to external systems.
#
# Enables:
#   ✔ device visibility
#   ✔ red-team situational awareness
#   ✔ validator Phase 3 scoring
#   ✔ future UI / automation / reporting integration
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# CORE API RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Resolve runtime safely from app.state.runtime
# ✔ Resolve fused devices from runtime-owned DeviceFusion
# ✔ Trigger a safe runtime fusion refresh when available
# ✔ Return stable JSON-safe responses
# ✔ Expose device list, top devices, detail, and summary endpoints
#
# COMPATIBILITY RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Preserve existing /api/devices behavior
# ✔ Preserve lightweight, read-only responses
# ✔ Avoid breaking older validators and clients
# ✔ Support both runtime.run_device_fusion() and direct device_fusion access
#
# SAFETY RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Never crash if runtime is absent
# ✔ Never crash if fusion engine is absent
# ✔ Never mutate fusion state beyond safe refresh invocation
# ✔ Keep output stable even when device data is empty
#
# =============================================================================
# ❌ NON-RESPONSIBILITIES
# =============================================================================
#
# ✘ perform fusion logic
# ✘ classify protocols
# ✘ control SDR/runtime lifecycle
# ✘ inject device intelligence
# ✘ modify device state directly
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. READ-ONLY API SURFACE
# -----------------------------------------------------------------------------
# This file exposes fused device intelligence but does not own the fusion logic.
#
# 2. RUNTIME TRUTH
# -----------------------------------------------------------------------------
# All device data must come from the active runtime-owned fusion engine.
#
# 3. ZERO BREAKAGE POLICY
# -----------------------------------------------------------------------------
# Existing external behavior must continue to work:
#   - GET /api/devices
#   - GET /api/devices/top
#   - GET /api/device/{id}
#   - GET /api/devices/summary
#
# 4. FAIL-SAFE ACCESS
# -----------------------------------------------------------------------------
# Missing runtime or missing fusion must return empty-but-valid payloads,
# not server crashes.
#
# 5. VALIDATOR-FRIENDLY RESPONSES
# -----------------------------------------------------------------------------
# Responses should expose device_count and meaningful device payloads so Phase 3
# validation can measure real fused entities.
#
# 6. JSON-SAFE OUTPUT
# -----------------------------------------------------------------------------
# DeviceFusion may internally use richer structures, but this API only returns
# plain dict/list/scalar objects.
#
# =============================================================================
# 📦 OUTPUT SCHEMA
# =============================================================================
#
# GET /api/devices
# -----------------------------------------------------------------------------
# {
#   "device_count": int,
#   "devices": [
#       {
#           "device_id": str,
#           "identity_id": Optional[str],
#           "protocols": [str],
#           "frequencies": [float],
#           "device_type": str,
#           "device_category": str,
#           "vendor": Optional[str],
#           "confidence": float,
#           "stability_score": float,
#           "signal_count": int,
#           "emitter_count": int,
#           "rf_band_hints": [str],
#           "first_seen": float,
#           "last_seen": float,
#           "age": float,
#           "fingerprint": dict,
#       }
#   ]
# }
#
# GET /api/devices/top
# -----------------------------------------------------------------------------
# {
#   "device_count": int,
#   "top_devices": [...]
# }
#
# GET /api/device/{device_id}
# -----------------------------------------------------------------------------
# {device object}  OR  {"error": "device_not_found"}
#
# GET /api/devices/summary
# -----------------------------------------------------------------------------
# {
#   "device_count": int,
#   "protocol_distribution": {str: int},
#   "device_type_distribution": {str: int},
#   "average_confidence": float,
#   "average_stability_score": float,
#   "average_signal_count": float,
# }
#
# =============================================================================
# 🔍 API BEHAVIOR
# =============================================================================
#
# 1. Runtime resolution
#    - read active runtime from app.state.runtime
#
# 2. Fusion refresh
#    - if runtime exposes run_device_fusion(), call it safely
#    - else fall back to runtime.device_fusion.get_devices() when available
#
# 3. Device retrieval
#    - always return a list, even when empty
#
# 4. Device lookup
#    - match by device_id string, not by list index
#
# 5. Ranking
#    - top devices sorted by confidence first, then signal_count, then
#      stability_score to stay compatible and useful
#
# =============================================================================
# 🔄 CHANGES IN v2.0.0
# =============================================================================
#
# ✔ Preserved all existing endpoint paths
# ✔ Fixed single-device lookup bug (now resolves by device_id, not list index)
# ✔ Fixed top-device sorting bug (no longer depends on non-existent max_power)
# ✔ Added safe runtime resolution and absent-runtime handling
# ✔ Added direct fusion-engine fallback if run_device_fusion() is unavailable
# ✔ Added richer summary output while preserving existing summary endpoint
# ✔ Added full architecture, schema, design principles, and behavior docs
# ✔ Double-checked response shapes for validator compatibility
#
# =============================================================================
# 🧠 IMPORTANT NOTES
# =============================================================================
#
# - This API is READ-ONLY.
# - Device data is produced by DeviceFusion, not by this file.
# - If runtime/device fusion is not wired, responses remain valid but empty.
# - This file is intended to remain stable across Phase 3 and early Phase 4.
#
# =============================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api", tags=["Device Intelligence"])


# =============================================================================
# INTERNAL HELPERS
# =============================================================================

def _get_runtime(request: Request) -> Optional[Any]:
    return getattr(request.app.state, "runtime", None)



def _safe_devices_from_runtime(runtime: Any) -> List[Dict[str, Any]]:
    if runtime is None:
        return []

    # -------------------------------------------------------------------------
    # Preferred path: safe runtime fusion refresh hook
    # -------------------------------------------------------------------------
    try:
        if hasattr(runtime, "run_device_fusion") and callable(runtime.run_device_fusion):
            result = runtime.run_device_fusion()
            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                devices = result.get("devices")
                if isinstance(devices, list):
                    return devices
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # Fallback path: direct access to fusion engine
    # -------------------------------------------------------------------------
    fusion = getattr(runtime, "device_fusion", None)
    if fusion is None:
        return []

    try:
        if hasattr(fusion, "get_devices") and callable(fusion.get_devices):
            devices = fusion.get_devices()
            if isinstance(devices, list):
                return devices

        if hasattr(fusion, "export_graph") and callable(fusion.export_graph):
            graph = fusion.export_graph(__import__("time").time())
            if isinstance(graph, dict) and isinstance(graph.get("devices"), list):
                return graph["devices"]
    except Exception:
        pass

    return []



def _get_devices(request: Request) -> List[Dict[str, Any]]:
    runtime = _get_runtime(request)
    devices = _safe_devices_from_runtime(runtime)
    return devices if isinstance(devices, list) else []



def _find_device_by_id(devices: List[Dict[str, Any]], device_id: str) -> Optional[Dict[str, Any]]:
    for device in devices:
        if str(device.get("device_id")) == str(device_id):
            return device
    return None



def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


# =============================================================================
# GET ALL DEVICES
# =============================================================================
@router.get("/devices")
def get_devices(request: Request):
    devices = _get_devices(request)

    return {
        "device_count": len(devices),
        "devices": devices,
    }


# =============================================================================
# GET TOP DEVICES
# =============================================================================
@router.get("/devices/top")
def get_top_devices(request: Request, limit: int = 10):
    devices = _get_devices(request)

    devices.sort(
        key=lambda d: (
            _safe_float(d.get("confidence"), 0.0),
            _safe_float(d.get("signal_count"), 0.0),
            _safe_float(d.get("stability_score"), 0.0),
        ),
        reverse=True,
    )

    return {
        "device_count": len(devices),
        "top_devices": devices[:limit],
    }


# =============================================================================
# GET SINGLE DEVICE
# =============================================================================
@router.get("/device/{device_id}")
def get_device(device_id: str, request: Request):
    devices = _get_devices(request)
    device = _find_device_by_id(devices, device_id)

    if device is None:
        return {"error": "device_not_found"}

    return device


# =============================================================================
# DEVICE SUMMARY
# =============================================================================
@router.get("/devices/summary")
def get_device_summary(request: Request):
    devices = _get_devices(request)

    protocol_count: Dict[str, int] = {}
    device_type_count: Dict[str, int] = {}

    total_confidence = 0.0
    total_stability = 0.0
    total_signal_count = 0.0

    for device in devices:
        protocols = device.get("protocols") or []
        if isinstance(protocols, list):
            for proto in protocols:
                key = str(proto)
                protocol_count[key] = protocol_count.get(key, 0) + 1

        device_type = device.get("device_type") or "unknown"
        device_type_count[str(device_type)] = device_type_count.get(str(device_type), 0) + 1

        total_confidence += _safe_float(device.get("confidence"), 0.0)
        total_stability += _safe_float(device.get("stability_score"), 0.0)
        total_signal_count += _safe_float(device.get("signal_count"), 0.0)

    count = len(devices)

    return {
        "device_count": count,
        "protocol_distribution": protocol_count,
        "device_type_distribution": device_type_count,
        "average_confidence": round(total_confidence / count, 4) if count else 0.0,
        "average_stability_score": round(total_stability / count, 4) if count else 0.0,
        "average_signal_count": round(total_signal_count / count, 4) if count else 0.0,
    }
