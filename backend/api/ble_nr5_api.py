from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Body, Query, Request

router = APIRouter(prefix="/api/ble_nr5", tags=["ble_nr5"])


def _get_manager(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    return getattr(runtime, "ble_nr5", None) if runtime else None


@router.get("/status")
def ble_nr5_status(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"service": "ble_nr5", "sensor_ready": False, "last_error": "Runtime or BLE NR5 controller unavailable."}
    return manager.get_status()


@router.post("/start")
def ble_nr5_start(
    request: Request,
    profile: str = Query("production_monitoring"),
    mission: str = Query("asset_discovery"),
    lab_mode: bool = Query(False),
    classic_sidecar: bool = Query(False),
    sensor_ids: str = Query(""),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    selected_sensors: List[str] = [item.strip() for item in sensor_ids.split(",") if item.strip()]
    return manager.start(
        profile=profile,
        mission=mission,
        lab_mode=lab_mode,
        classic_sidecar=classic_sidecar,
        sensor_ids=selected_sensors,
    )


@router.post("/stop")
def ble_nr5_stop(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.stop()


@router.post("/clear")
def ble_nr5_clear(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.clear_results()


@router.post("/scan")
def ble_nr5_scan(
    request: Request,
    duration_seconds: int = Query(60, ge=4, le=300),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.run_scan(duration_seconds=duration_seconds)


@router.post("/live_hunt/start")
def ble_nr5_live_hunt_start(
    request: Request,
    scan_seconds: int = Query(60, ge=4, le=300),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.start_live_hunt(scan_seconds=scan_seconds)


@router.post("/live_hunt/stop")
def ble_nr5_live_hunt_stop(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.stop_live_hunt()


@router.get("/devices")
def ble_nr5_devices(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "devices": []}
    return manager.get_devices()


@router.get("/queue")
def ble_nr5_queue(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "queue": []}
    return manager.get_queue()


@router.get("/timeline")
def ble_nr5_timeline(request: Request, limit: int = Query(80, ge=1, le=500)):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "events": []}
    return manager.get_timeline(limit=limit)


@router.get("/knowledge")
def ble_nr5_knowledge(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"loaded": False, "knowledge_base": {}}
    return manager.get_knowledge()


@router.get("/validation_framework")
def ble_nr5_validation_framework(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"modules": [], "tool_catalog": {}}
    return manager.get_validation_framework()


@router.get("/validation_runs")
def ble_nr5_validation_runs(request: Request, device_key: str = Query("")):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "runs": []}
    return manager.get_validation_runs(device_key=device_key)


@router.get("/tasks")
def ble_nr5_tasks(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "tasks": []}
    return manager.get_tasks()


@router.post("/workflow")
def ble_nr5_workflow(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.assign_workflow(
        device_key=str(payload.get("device_key") or ""),
        workflow=str(payload.get("workflow") or "monitor"),
        notes=str(payload.get("notes") or ""),
        source="manual",
    )


@router.post("/validate_result")
def ble_nr5_validate_result(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.record_validation_result(
        device_key=str(payload.get("device_key") or ""),
        pairable_verdict=str(payload.get("pairable_verdict") or ""),
        legacy_pin_risk=str(payload.get("legacy_pin_risk") or ""),
        manual_result=str(payload.get("manual_result") or ""),
        notes=str(payload.get("notes") or ""),
    )


@router.post("/active_validate")
def ble_nr5_active_validate(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.run_active_validation(device_key=str(payload.get("device_key") or ""))


@router.post("/validation_suite")
def ble_nr5_validation_suite(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
    device_key: str = Query(""),
    owned_target: bool = Query(False),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    body_device_key = str(payload.get("device_key") or "").strip()
    body_owned_target = payload.get("owned_target")
    return manager.run_validation_suite(
        device_key=body_device_key or str(device_key or ""),
        scenario_ids=[str(item) for item in (payload.get("scenario_ids") or [])],
        owned_target=bool(body_owned_target) if body_owned_target is not None else bool(owned_target),
        notes=str(payload.get("notes") or ""),
    )


@router.post("/gatt_test")
def ble_nr5_gatt_test(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.run_gatt_test(
        device_key=str(payload.get("device_key") or ""),
        notes=str(payload.get("notes") or ""),
        owned_target=bool(payload.get("owned_target")),
    )


@router.post("/hard_test")
def ble_nr5_hard_test(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.run_hard_ble_test(
        device_key=str(payload.get("device_key") or ""),
        notes=str(payload.get("notes") or ""),
        owned_target=bool(payload.get("owned_target")),
    )


@router.post("/observation")
def ble_nr5_record_observation(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or BLE NR5 controller unavailable."}
    return manager.record_observation(payload or {})
