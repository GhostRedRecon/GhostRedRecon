from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api/hunt_drones", tags=["hunt_drones"])


class HuntDronesSessionStart(BaseModel):
    session_name: str = "Hunt Drones Session"
    operator: str = ""
    location: str = ""
    notes: str = ""
    scan_profile: str = "passive_standard"
    evidence_path: str = ""


class HuntDronesReplayLoad(BaseModel):
    session_id: str


class HuntDronesCapabilityRequest(BaseModel):
    capability: str


def _get_manager(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    return getattr(runtime, "hunt_drones", None) if runtime else None


@router.get("/status")
def hunt_drones_status(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"service": "hunt_drones", "active": False, "last_error": "Runtime or Hunt Drones controller unavailable."}
    return manager.get_status()


@router.post("/start")
def hunt_drones_start(payload: HuntDronesSessionStart, request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or Hunt Drones controller unavailable."}
    return manager.start_session(
        session_name=payload.session_name,
        operator=payload.operator,
        location=payload.location,
        notes=payload.notes,
        scan_profile=payload.scan_profile,
        evidence_path=payload.evidence_path,
    )


@router.post("/stop")
def hunt_drones_stop(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or Hunt Drones controller unavailable."}
    return manager.stop_session()


@router.post("/clear")
def hunt_drones_clear(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or Hunt Drones controller unavailable."}
    return manager.clear_session()


@router.post("/delete")
def hunt_drones_delete(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or Hunt Drones controller unavailable."}
    return manager.delete_all_data()


@router.post("/scan")
def hunt_drones_scan(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or Hunt Drones controller unavailable."}
    return manager.run_passive_scan()


@router.get("/live")
def hunt_drones_live(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "active": False, "phase": "idle", "live_leads": []}
    return manager.get_live_detection_state()


@router.get("/detections")
def hunt_drones_detections(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "detections": []}
    detections = manager.get_detections()
    return {"count": len(detections), "detections": detections}


@router.get("/timeline")
def hunt_drones_timeline(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "events": []}
    events = manager.get_timeline()
    return {"count": len(events), "events": events}


@router.get("/operator_log")
def hunt_drones_operator_log(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "items": []}
    items = manager.get_operator_log()
    return {"count": len(items), "items": items}


@router.get("/topology")
def hunt_drones_topology(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"nodes": [], "edges": []}
    return manager.get_topology()


@router.get("/reports")
def hunt_drones_reports(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "reports": []}
    reports = manager.get_reports()
    return {"count": len(reports), "reports": reports}


@router.get("/evidence")
def hunt_drones_evidence(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"bundles": [], "counts": {}}
    return manager.get_evidence_summary()


@router.get("/targets/{target_id}")
def hunt_drones_target_detail(target_id: str, request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {}
    return manager.get_target_detail(target_id)


@router.get("/replay_sessions")
def hunt_drones_replay_sessions(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "sessions": []}
    sessions = manager.list_replay_sessions()
    return {"count": len(sessions), "sessions": sessions}


@router.post("/replay_load")
def hunt_drones_replay_load(payload: HuntDronesReplayLoad, request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or Hunt Drones controller unavailable."}
    return manager.load_replay_session(payload.session_id)


@router.post("/capability")
def hunt_drones_capability(payload: HuntDronesCapabilityRequest, request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "message": "Runtime or Hunt Drones controller unavailable."}
    return manager.request_disabled_capability(payload.capability)


@router.get("/settings")
def hunt_drones_settings(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"settings": {}}
    return {"settings": manager.get_settings()}
