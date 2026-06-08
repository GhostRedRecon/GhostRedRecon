import os
import subprocess
import threading
import time
from shutil import which
from typing import Any, Dict

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


def _command_status(command, version_args=None):
    path = which(command)
    if not path:
      return {"installed": False, "path": None, "detail": ""}
    try:
        result = subprocess.run(
            [command, *(version_args or ["--help"])],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip().splitlines()
        return {
            "installed": True,
            "path": path,
            "detail": output[0] if output else "",
        }
    except Exception as exc:
        return {
            "installed": True,
            "path": path,
            "detail": str(exc),
        }


def _process_running(token):
    try:
        result = subprocess.run(
            ["ps", "-ef"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        lines = [
            line.strip() for line in (result.stdout or "").splitlines()
            if token in line and "grep" not in line and "ps -ef" not in line
        ]
        return {"running": bool(lines), "matches": lines[:5]}
    except Exception as exc:
        return {"running": False, "matches": [str(exc)]}


def _recent_reports(prefix):
    report_dir = "/home/ghost/Documents/GhostRedRecon/rf_reports"
    if not os.path.isdir(report_dir):
        return []
    matches = []
    for name in os.listdir(report_dir):
        if not name.startswith(prefix):
            continue
        path = os.path.join(report_dir, name)
        try:
            matches.append({
                "name": name,
                "path": path,
                "mtime": os.path.getmtime(path),
            })
        except OSError:
            continue
    return sorted(matches, key=lambda item: item["mtime"], reverse=True)[:5]


def _recent_files(base_dir: str, suffixes: tuple[str, ...], limit: int = 8):
    if not os.path.isdir(base_dir):
        return []
    matches = []
    for root, _, files in os.walk(base_dir):
        for name in files:
            if suffixes and not name.lower().endswith(suffixes):
                continue
            path = os.path.join(root, name)
            try:
                matches.append({
                    "name": name,
                    "path": path,
                    "mtime": os.path.getmtime(path),
                })
            except OSError:
                continue
    return sorted(matches, key=lambda item: item["mtime"], reverse=True)[:limit]


def _merge_recent_files(directories: list[tuple[str, tuple[str, ...]]], limit: int = 10):
    merged = []
    for base_dir, suffixes in directories:
        merged.extend(_recent_files(base_dir, suffixes, limit=limit))
    deduped = {}
    for item in merged:
        deduped[item["path"]] = item
    return sorted(deduped.values(), key=lambda item: item["mtime"], reverse=True)[:limit]


def _runtime_snapshot(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        return {"available": False}
    rf_health = {}
    try:
        rf_router = __import__("backend.api.rf_api", fromlist=["rf_health"])
        rf_health = rf_router.rf_health(request)
    except Exception:
        rf_health = {}
    return {
        "available": True,
        "session_active": bool(getattr(runtime.session_controller, "is_active", lambda: False)()),
        "active_freq_mhz": getattr(getattr(runtime, "sdr", None), "freq_mhz", None),
        "rf_health": rf_health,
    }


def _wb_hunt_strategy(runtime, peak_mhz: float) -> Dict[str, Any]:
    manager = getattr(runtime, "hackrf_sweep", None)
    if manager is None:
        return {
            "family": "Unknown RF Hotspot",
            "recommended_tab": "Signal Lab",
            "action": "Capture and inspect this peak in Signal Lab.",
        }
    return manager._classify_peak(peak_mhz)


def _collect_band_snapshot(runtime, band: str, limit: int = 25) -> Dict[str, Any]:
    intel_router = __import__("backend.api.intel_api", fromlist=[
        "_get_enriched_signals",
        "_filter_signals_for_band",
        "_format_devices",
        "_get_devices",
        "_match_devices_for_signals",
        "_extract_band_indicators",
    ])
    raw_signals = intel_router._get_enriched_signals(
        runtime,
        limit=max(limit * 4, 200),
        active_only=True,
        sort_by="last_seen",
    )
    band_signals = intel_router._filter_signals_for_band(raw_signals, band)[:limit]
    devices = intel_router._format_devices(intel_router._get_devices(runtime))
    matched_devices = intel_router._match_devices_for_signals(band_signals, devices, band)
    return {
        "band": str(band or "").upper(),
        "signal_count": len(band_signals),
        "matched_device_count": len(matched_devices),
        "signals": band_signals,
        "devices": matched_devices[:20],
        "indicators": intel_router._extract_band_indicators(band, band_signals, matched_devices),
        "timestamp": time.time(),
    }


def _nearest_decode_frequency(peak_mhz: float, candidates: list[float], max_delta_mhz: float = 1.0) -> float:
    nearest = min(candidates, key=lambda candidate: abs(candidate - peak_mhz))
    if abs(nearest - peak_mhz) <= max_delta_mhz:
        return float(nearest)
    return round(float(peak_mhz), 3)


def _decode_band_key(recommended_tab: str) -> str:
    mapping = {
        "Bluetooth": "ble",
        "Bluetooth or Zigbee": "ble",
        "Zigbee": "zigbee",
        "LoRa": "lora",
        "WiFi": "wifi",
        "433/868 Decoder": "sub-ghz",
    }
    return mapping.get(recommended_tab, "")


def _find_table_row(runtime, row_id: str) -> Dict[str, Any]:
    manager = getattr(runtime, "hackrf_sweep", None)
    if manager is None:
        return {}
    state = manager.get_state()
    for row in state.get("table_rows", []):
        if str(row.get("row_id")) == str(row_id):
            return row
    return {}


def _wait_for_session_release(runtime, timeout_seconds: float = 4.0) -> None:
    session = getattr(runtime, "session_controller", None)
    if session is None:
        time.sleep(0.35)
        return
    deadline = time.time() + max(0.5, float(timeout_seconds or 4.0))
    while time.time() < deadline:
        if not session.is_active():
            time.sleep(0.35)
            return
        time.sleep(0.1)
    time.sleep(0.5)


def _execute_wb_decode(runtime, peak_mhz: float, dwell_seconds: float = 4.0) -> Dict[str, Any]:
    strategy = _wb_hunt_strategy(runtime, peak_mhz)
    recommended_tab = strategy.get("recommended_tab", "Signal Lab")
    response: Dict[str, Any] = {
        "status": "planned",
        "peak_mhz": float(peak_mhz),
        "strategy": strategy,
        "decoder": recommended_tab,
        "dwell_seconds": float(dwell_seconds or 4.0),
        "manager": runtime.hackrf_sweep.get_state(),
    }

    band_key = _decode_band_key(recommended_tab)

    if band_key and recommended_tab != "433/868 Decoder":
        decode_freq_mhz = round(float(peak_mhz), 3)
        response["decode_freq_mhz"] = decode_freq_mhz
        if getattr(runtime, "session_controller", None) and runtime.session_controller.is_active():
            runtime.session_controller.stop()
            response["session_stopped_for_decode"] = True
        else:
            response["session_stopped_for_decode"] = False
        session_start = runtime.session_controller.start(decode_freq_mhz)
        response["session_start"] = session_start
        time.sleep(max(1.0, min(float(dwell_seconds or 4.0), 6.0)))

        band_snapshot = _collect_band_snapshot(runtime, band_key, limit=25)
        response["band_snapshot"] = band_snapshot
        response["signals"] = band_snapshot.get("signals", [])[:12]
        response["devices"] = band_snapshot.get("devices", [])[:10]
        response["indicators"] = band_snapshot.get("indicators", {})
        response["matched_device_count"] = band_snapshot.get("matched_device_count", 0)
        response["signal_count"] = band_snapshot.get("signal_count", 0)
        response["status"] = "decoded" if band_snapshot.get("signal_count", 0) else "no_decode"
        response["message"] = (
            f"Collected {band_snapshot.get('signal_count', 0)} live {band_key.upper()} signals at {decode_freq_mhz} MHz."
            if band_snapshot.get("signal_count", 0)
            else f"No live {band_key.upper()} signals were retained during the dwell window at {decode_freq_mhz} MHz."
        )
        return response

    rtl433 = getattr(runtime, "rtl433", None)
    if rtl433 is None:
        response["status"] = "unavailable"
        response["message"] = "rtl_433 manager is unavailable."
        return response
    if not rtl433.is_installed():
        response["status"] = "unavailable"
        response["message"] = "rtl_433 is not installed on this host."
        return response

    if getattr(runtime, "session_controller", None) and runtime.session_controller.is_active():
        runtime.session_controller.stop()
        response["session_stopped_for_decode"] = True
    else:
        response["session_stopped_for_decode"] = False

    decode_freq_mhz = _nearest_decode_frequency(float(peak_mhz), [433.92, 868.30, 868.95, 869.525])
    response["decode_freq_mhz"] = decode_freq_mhz

    rtl433.stop()
    rtl433.events.clear()
    rtl433.logs.clear()
    start_result = rtl433.start(decode_freq_mhz)
    response["decode_start"] = start_result
    if start_result.get("status") not in {"started", "already_running"}:
        response["status"] = "failed"
        response["message"] = start_result.get("error") or "Failed to start rtl_433."
        response["rtl433"] = rtl433.get_state()
        return response

    time.sleep(max(1.0, min(float(dwell_seconds or 4.0), 10.0)))
    stop_result = rtl433.stop()
    rtl_state = rtl433.get_state()
    response["decode_stop"] = stop_result
    response["rtl433"] = rtl_state
    response["manager"] = runtime.hackrf_sweep.get_state()
    response["decoded_events"] = rtl_state.get("recent_events", [])[:12]
    response["top_products"] = rtl_state.get("top_products", [])
    response["top_brands"] = rtl_state.get("top_brands", [])
    response["signal_count"] = len(response["decoded_events"])
    response["matched_device_count"] = 0
    response["message"] = (
        "Decoded sub-GHz signal with rtl_433."
        if rtl_state.get("recent_events")
        else "No rtl_433 events were decoded for this frequency during the dwell window."
    )
    response["status"] = "decoded" if rtl_state.get("recent_events") else "no_decode"
    return response


@router.get("/rtl433")
def rtl433_status(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    manager_state = {}
    if runtime and getattr(runtime, "rtl433", None):
        try:
            manager_state = runtime.rtl433.get_state()
        except Exception as exc:
            manager_state = {"running": False, "last_error": str(exc), "recent_events": [], "recent_logs": []}
    return {
        "integration": "rtl_433",
        "title": "433 / 868 Decoder",
        "description": "Live decoded ISM view for cheap sensors, remotes, alarms, weather stations, and utility-style telemetry.",
        "status": _command_status("rtl_433", ["-V"]),
        "manager": manager_state,
        "process": _process_running("rtl_433"),
        "runtime": _runtime_snapshot(request),
        "target_frequencies_mhz": [433.92, 868.30, 868.95, 869.525],
        "recommended_use": [
            "Use for cheap ISM devices in EU 433 / 868 bands.",
            "Best fit for low-cost imported sensors, remotes, weather devices, and alarm traffic.",
            "Use alongside the existing Sub-GHz and IoT tabs for RF context plus decoder context.",
        ],
        "installation_hint": "Install rtl_433 on the host to enable live 433/868 decoded rows in this tab.",
        "recent_reports": _recent_reports("eu_meter_audit_") + _recent_reports("subghz_audit_"),
        "timestamp": time.time(),
    }


@router.get("/wb_hunt")
def wb_hunt_status(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    manager_state = {}
    if runtime and getattr(runtime, "hackrf_sweep", None):
        try:
            manager_state = runtime.hackrf_sweep.get_state()
        except Exception as exc:
            manager_state = {"running": False, "last_error": str(exc), "recent_rows": [], "recent_logs": []}
    return {
        "integration": "wb_hunt",
        "title": "WB Hunt",
        "description": "One-pass wideband reconnaissance with hackrf_sweep for peak hunting and suspicious RF discovery.",
        "status": _command_status("hackrf_sweep", ["-h"]),
        "manager": manager_state,
        "process": _process_running("hackrf_sweep"),
        "runtime": _runtime_snapshot(request),
        "target_frequencies_mhz": [433.92, 868.30, 2412.0],
        "recommended_use": [
            "Use for wideband peak hunting before protocol-specific sweeps.",
            "Best fit for finding unknown emitters, cheap IoT bursts, and high-power hotspots.",
            "Run WB Hunt first, then pivot into Bluetooth, Zigbee, LoRa, 433/868 Decoder, or capture a hotspot to Signal Lab.",
        ],
        "installation_hint": "hackrf_sweep is the native HackRF wideband hunt utility for this workflow.",
        "recent_reports": _recent_reports("subghz_audit_") + _recent_reports("eu_iot_audit_"),
        "timestamp": time.time(),
    }


@router.post("/wb_hunt/start")
def wb_hunt_start(
    request: Request,
    profile_key: str = "eu_ism",
    auto_decode: bool = True,
    auto_decode_mode: str = "top5",
    auto_decode_dwell_seconds: float = 4.0,
    auto_decode_limit: int = 5,
):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "hackrf_sweep", None):
        return {"status": "unavailable", "error": "Runtime or hackrf_sweep manager is unavailable."}
    if getattr(runtime, "session_controller", None) and runtime.session_controller.is_active():
        runtime.session_controller.stop()
        _wait_for_session_release(runtime)
    result = runtime.hackrf_sweep.start(profile_key)
    manager_state = runtime.hackrf_sweep.get_state()
    selected_mode = "new" if str(auto_decode_mode).lower() == "new" else "top5"
    chosen_limit = max(1, min(int(auto_decode_limit or 5), 20))
    dwell_seconds = max(1.0, min(float(auto_decode_dwell_seconds or 4.0), 10.0))
    auto_decode_requested = bool(auto_decode) and result.get("status") == "started"
    if auto_decode_requested and manager_state.get("started_at"):
        worker = threading.Thread(
            target=_schedule_auto_decode_after_hunt,
            args=(runtime, float(manager_state["started_at"]), selected_mode, dwell_seconds, chosen_limit),
            daemon=True,
        )
        worker.start()
    result["manager"] = manager_state
    result["session_stopped_for_hunt"] = True
    result["auto_decode"] = {
        "enabled": auto_decode_requested,
        "mode": selected_mode,
        "dwell_seconds": dwell_seconds,
        "limit": chosen_limit,
    }
    return result


@router.post("/wb_hunt/stop")
def wb_hunt_stop(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "hackrf_sweep", None):
        return {"status": "unavailable", "error": "Runtime or hackrf_sweep manager is unavailable."}
    result = runtime.hackrf_sweep.stop()
    result["manager"] = runtime.hackrf_sweep.get_state()
    return result


@router.post("/wb_hunt/capture_peak")
def wb_hunt_capture_peak(request: Request, peak_mhz: float, family: str = "", notes: str = ""):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "hackrf_sweep", None):
        return {"status": "unavailable", "error": "Runtime or hackrf_sweep manager is unavailable."}
    result = runtime.hackrf_sweep.capture_peak(peak_mhz=peak_mhz, family=family, notes=notes)
    result["manager"] = runtime.hackrf_sweep.get_state()
    return result


@router.post("/wb_hunt/decode_signal")
def wb_hunt_decode_signal(request: Request, peak_mhz: float, dwell_seconds: float = 4.0):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "hackrf_sweep", None):
        return {"status": "unavailable", "error": "Runtime or hackrf_sweep manager is unavailable."}

    response = _execute_wb_decode(runtime, peak_mhz=peak_mhz, dwell_seconds=dwell_seconds)
    return response


@router.post("/wb_hunt/row_update")
def wb_hunt_row_update(request: Request, row_id: str, retention_state: str = "", operator_priority: str = "", tags: str = ""):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "hackrf_sweep", None):
        return {"status": "unavailable", "error": "Runtime or hackrf_sweep manager is unavailable."}
    updates: Dict[str, Any] = {}
    if retention_state:
        updates["retention_state"] = retention_state
    if operator_priority:
        updates["operator_priority"] = operator_priority
    if tags:
        updates["tags"] = [part.strip() for part in tags.split(",") if part.strip()]
    annotation = runtime.hackrf_sweep.update_row_annotation(row_id, **updates)
    return {
        "status": "updated",
        "row_id": row_id,
        "annotation": annotation,
        "manager": runtime.hackrf_sweep.get_state(),
    }


def _candidate_queue_rows(runtime, mode: str, limit: int) -> list[dict]:
    rows = runtime.hackrf_sweep.get_state().get("table_rows", [])
    filtered = []
    for row in rows:
        retention_state = str(row.get("retention_state") or "new")
        if retention_state in {"false_positive", "ignore"}:
            continue
        if mode == "new" and retention_state != "new":
            continue
        filtered.append(row)
    filtered.sort(key=lambda row: float(row.get("peak_db", -999.0)), reverse=True)
    return filtered[:limit]


def _run_auto_decode_queue(runtime, dwell_seconds: float) -> None:
    manager = runtime.hackrf_sweep
    while True:
        row_id = manager.queue_next_row()
        if not row_id:
            break
        row = _find_table_row(runtime, row_id)
        if not row:
            manager.complete_queue_row(row_id, {"status": "failed", "message": "Queued row is no longer available."})
            continue
        result = _execute_wb_decode(runtime, peak_mhz=float(row.get("peak_mhz") or 0.0), dwell_seconds=dwell_seconds)
        result["row_id"] = row_id
        manager.complete_queue_row(row_id, result)
        if not manager.auto_decode_running and manager.auto_decode_stop_requested:
            break


def _schedule_auto_decode_after_hunt(runtime, started_at: float, mode: str, dwell_seconds: float, limit: int) -> None:
    manager = runtime.hackrf_sweep
    deadline = time.time() + 180.0
    while time.time() < deadline:
        state = manager.get_state()
        current_started_at = state.get("started_at")
        if current_started_at != started_at:
            return
        if state.get("running"):
            time.sleep(1.0)
            continue
        if state.get("status_detail") != "completed_with_detections":
            return
        rows = _candidate_queue_rows(runtime, mode, limit)
        row_ids = [str(row.get("row_id")) for row in rows if row.get("row_id")]
        if not row_ids:
            return
        manager.queue_rows(row_ids, mode)
        worker = threading.Thread(target=_run_auto_decode_queue, args=(runtime, dwell_seconds), daemon=True)
        worker.start()
        return


@router.post("/wb_hunt/auto_decode/start")
def wb_hunt_auto_decode_start(request: Request, mode: str = "top5", dwell_seconds: float = 4.0, limit: int = 5):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "hackrf_sweep", None):
        return {"status": "unavailable", "error": "Runtime or hackrf_sweep manager is unavailable."}
    selected_mode = "new" if str(mode).lower() == "new" else "top5"
    chosen_limit = max(1, min(int(limit or 5), 20))
    rows = _candidate_queue_rows(runtime, selected_mode, chosen_limit)
    row_ids = [str(row.get("row_id")) for row in rows if row.get("row_id")]
    queue = runtime.hackrf_sweep.queue_rows(row_ids, selected_mode)
    worker = threading.Thread(target=_run_auto_decode_queue, args=(runtime, float(dwell_seconds or 4.0)), daemon=True)
    worker.start()
    return {
        "status": "started",
        "mode": selected_mode,
        "queued_rows": rows,
        "queue": queue,
        "manager": runtime.hackrf_sweep.get_state(),
    }


@router.post("/wb_hunt/auto_decode/stop")
def wb_hunt_auto_decode_stop(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "hackrf_sweep", None):
        return {"status": "unavailable", "error": "Runtime or hackrf_sweep manager is unavailable."}
    queue = runtime.hackrf_sweep.request_queue_stop()
    return {
        "status": "stopped",
        "queue": queue,
        "manager": runtime.hackrf_sweep.get_state(),
    }


@router.post("/rtl433/start")
def rtl433_start(request: Request, freq_mhz: float = 433.92):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "rtl433", None):
        return {"status": "unavailable", "error": "Runtime or rtl_433 manager is unavailable."}
    result = runtime.rtl433.start(freq_mhz)
    result["manager"] = runtime.rtl433.get_state()
    return result


@router.post("/rtl433/start_sweep")
def rtl433_start_sweep(request: Request, dwell_seconds: float = 4.0):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "rtl433", None):
        return {"status": "unavailable", "error": "Runtime or rtl_433 manager is unavailable."}

    if getattr(runtime, "session_controller", None) and runtime.session_controller.is_active():
        runtime.session_controller.stop()

    result = runtime.rtl433.start_sweep([433.92, 868.30, 868.95, 869.525], dwell_seconds=dwell_seconds)
    result["manager"] = runtime.rtl433.get_state()
    result["session_stopped_for_decoder"] = True
    return result


@router.post("/rtl433/stop")
def rtl433_stop(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or not getattr(runtime, "rtl433", None):
        return {"status": "unavailable", "error": "Runtime or rtl_433 manager is unavailable."}
    result = runtime.rtl433.stop()
    result["manager"] = runtime.rtl433.get_state()
    return result


def _signal_lab_payload(request: Request):
    return {
        "integration": "signal_lab",
        "title": "Signal Lab",
        "description": "Offline signal inspection, burst analysis, and reverse-engineering workflow powered by Inspectrum.",
        "status": _command_status("inspectrum", ["--help"]),
        "process": _process_running("inspectrum"),
        "runtime": _runtime_snapshot(request),
        "target_frequencies_mhz": [433.92, 868.30, 2402.0],
        "recommended_use": [
            "Use for analyst-led offline waveform and burst inspection.",
            "Best fit after a live hunt finds a suspicious Sub-GHz or 2.4 GHz signal family.",
            "Use to label bursts and prepare protocol fingerprints for GhostRedRecon.",
        ],
        "installation_hint": "Inspectrum is the current offline signal-analysis backend for this workflow.",
        "recent_projects": _merge_recent_files([
            ("/home/ghost/Documents/GhostRedRecon/rf_lab", (".json", ".complex16s", ".coco", ".wav")),
            ("/home/ghost/Documents/GhostRedRecon/rf_reports", (".json", ".txt", ".log")),
        ], limit=10),
        "recent_reports": _recent_reports("lora_audit_") + _recent_reports("eu_iot_audit_"),
        "timestamp": time.time(),
    }


@router.get("/signal_lab")
def signal_lab_status(request: Request):
    return _signal_lab_payload(request)


@router.get("/urh")
def legacy_signal_lab_status(request: Request):
    return _signal_lab_payload(request)


@router.get("/kismet")
def kismet_status(request: Request):
    return {
        "integration": "kismet",
        "title": "Kismet RF Fusion",
        "description": "External RF fusion and wireless discovery workflow for WiFi, BLE, Zigbee, and multi-source telemetry.",
        "status": _command_status("kismet", ["--version"]),
        "process": _process_running("kismet"),
        "runtime": _runtime_snapshot(request),
        "target_frequencies_mhz": [2412.0, 2426.0, 2480.0],
        "recommended_use": [
            "Use for broader wireless correlation beyond the SDR-only pipeline.",
            "Best fit for WiFi/BLE/Zigbee correlation and external packet-source fusion.",
            "Use after baseline SDR sweeps when the operator needs stronger wireless ecosystem context.",
        ],
        "installation_hint": "Kismet is installed. Start a Kismet capture source separately if you want this tab to reflect a live external fusion process.",
        "recent_projects": _recent_files("/home/ghost/.kismet", (".kismet", ".conf", ".sqlite", ".pcapng"), limit=10),
        "recent_reports": _recent_reports("wifi_iot_audit_") + _recent_reports("zigbee_audit_") + _recent_reports("ble_audit_"),
        "timestamp": time.time(),
    }
