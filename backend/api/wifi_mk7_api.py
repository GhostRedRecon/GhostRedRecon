from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pathlib import Path

router = APIRouter(prefix="/api/wifi_mk7", tags=["wifi_mk7"])


def _get_manager(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    return getattr(runtime, "wifi_mk7", None) if runtime else None


def _resolve_camera_artifact(manager, artifact_path: str) -> Path:
    if manager is None:
        raise HTTPException(status_code=503, detail="Runtime or WiFi MK7 controller unavailable.")
    raw = str(artifact_path or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Artifact path required.")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = (Path(manager.root_dir) / candidate).resolve()
    else:
        candidate = candidate.resolve()
    allowed_roots = [
        (Path(manager.root_dir) / "evidence" / "camera_images").resolve(),
        (Path(manager.root_dir) / "evidence" / "camera_protocol").resolve(),
    ]
    if not any(root == candidate or root in candidate.parents for root in allowed_roots):
        raise HTTPException(status_code=403, detail="Artifact path is outside the allowed evidence roots.")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return candidate


def _resolve_wifi_hunt_artifact(manager, artifact_path: str) -> Path:
    if manager is None:
        raise HTTPException(status_code=503, detail="Runtime or WiFi MK7 controller unavailable.")
    raw = str(artifact_path or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Artifact path required.")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = (Path(manager.root_dir) / candidate).resolve()
    else:
        candidate = candidate.resolve()
    allowed_roots = [
        (Path(manager.root_dir) / "evidence" / "wifi_hunt").resolve(),
        (Path(manager.root_dir) / "evidence" / "_wifi_hunt").resolve(),
        (Path(manager.root_dir) / "evidence" / "Audit").resolve(),
        (Path(manager.root_dir) / "evidence" / "_wifi_hunt" / "Audit").resolve(),
    ]
    if not any(candidate == root or root in candidate.parents for root in allowed_roots):
        raise HTTPException(status_code=403, detail="Artifact path is outside the allowed WiFi Hunt evidence roots.")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return candidate


@router.get("/status")
def wifi_mk7_status(request: Request, prepare: bool = Query(False), light: bool = Query(False)):
    manager = _get_manager(request)
    if manager is None:
        return {"service": "wifi_mk7", "sensor_ready": False, "last_error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.get_status(prepare=prepare, light=light)


@router.get("/operator_snapshot")
def wifi_mk7_operator_snapshot(
    request: Request,
    prepare: bool = Query(False),
    light: bool = Query(False),
    include_data: bool = Query(True),
    include_redteam: bool = Query(False),
):
    manager = _get_manager(request)
    if manager is None:
        return {
            "status": {"service": "wifi_mk7", "sensor_ready": False, "last_error": "Runtime or WiFi MK7 controller unavailable."},
            "channels": {},
            "networks": [],
            "clients": [],
            "pcaps": [],
            "redteam": {"state": "IDLE", "ok": False, "message": "Runtime or WiFi MK7 controller unavailable."},
            "adversary_replay": {"state": "IDLE", "ok": False, "message": "Runtime or WiFi MK7 controller unavailable."},
        }
    return manager.get_operator_snapshot(
        prepare=prepare,
        light=light,
        include_data=include_data,
        include_redteam=include_redteam,
    )


@router.post("/start")
def wifi_mk7_start(
    request: Request,
    bands: str = Query("2.4ghz,5ghz"),
    dwell_ms: int = Query(250, ge=100, le=2000),
    duration_seconds: int = Query(3600, ge=60, le=86400),
    scan_mode: str = Query("broad"),
    scan_scenario: str = Query("passive_observation"),
    locked_channels: str = Query(""),
    interfaces: str = Query(""),
    deep_packet_enrichment: bool = Query(False),
    camera_hunt: bool = Query(False),
    processing_enabled: bool = Query(True),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or WiFi MK7 controller unavailable."}
    requested_bands: List[str] = [item.strip() for item in bands.split(",") if item.strip()]
    selected_interfaces: List[str] = [item.strip() for item in interfaces.split(",") if item.strip()]
    selected_channels: List[int] = [int(item.strip()) for item in locked_channels.split(",") if item.strip().isdigit()]
    return manager.start(
        auto_scan=True,
        bands=requested_bands,
        dwell_ms=dwell_ms,
        duration_seconds=duration_seconds,
        scan_mode=scan_mode,
        scan_scenario=scan_scenario,
        locked_channels=selected_channels,
        interfaces=selected_interfaces,
        deep_packet_enrichment=deep_packet_enrichment,
        camera_hunt=camera_hunt,
        processing_enabled=processing_enabled,
    )


@router.post("/stop")
def wifi_mk7_stop(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.stop()


@router.post("/clear")
def wifi_mk7_clear(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.clear_results()


@router.post("/sweep")
def wifi_mk7_sweep(
    request: Request,
    bands: str = Query("2.4ghz,5ghz"),
    dwell_ms: int = Query(250, ge=100, le=2000),
    scan_mode: str = Query("broad"),
    scan_scenario: str = Query("passive_observation"),
    locked_channels: str = Query(""),
    interfaces: str = Query(""),
    deep_packet_enrichment: bool = Query(False),
    camera_hunt: bool = Query(False),
):
    manager = _get_manager(request)
    if manager is None:
        return {"status": "unavailable", "error": "Runtime or WiFi MK7 controller unavailable."}
    requested_bands: List[str] = [item.strip() for item in bands.split(",") if item.strip()]
    selected_interfaces: List[str] = [item.strip() for item in interfaces.split(",") if item.strip()]
    selected_channels: List[int] = [int(item.strip()) for item in locked_channels.split(",") if item.strip().isdigit()]
    return manager.sweep(
        bands=requested_bands,
        dwell_ms=dwell_ms,
        scan_mode=scan_mode,
        scan_scenario=scan_scenario,
        locked_channels=selected_channels,
        interfaces=selected_interfaces,
        deep_packet_enrichment=deep_packet_enrichment,
        camera_hunt=camera_hunt,
    )


@router.get("/networks")
def wifi_mk7_networks(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "networks": []}
    networks = manager.get_networks()
    return {"count": len(networks), "networks": networks}


@router.get("/clients")
def wifi_mk7_clients(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "clients": []}
    clients = manager.get_clients()
    return {"count": len(clients), "clients": clients}


@router.get("/targets")
def wifi_mk7_targets(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "targets": []}
    networks = manager.get_networks()
    clients = manager.get_clients()
    targets = sorted(
        [*networks, *clients],
        key=lambda item: (
            float((item.get("target_score") or {}).get("score") or 0.0),
            float((item.get("camera_detection") or {}).get("confidence") or 0.0),
            float(item.get("packet_count") or 0.0),
        ),
        reverse=True,
    )
    return {"count": len(targets), "targets": targets}


@router.post("/service_audit")
def wifi_mk7_service_audit(
    request: Request,
    target_id: str = Query(""),
    allow_infrastructure: bool = Query(False),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.run_service_audit(target_id, allow_infrastructure=allow_infrastructure)


@router.post("/hard_audit")
def wifi_mk7_hard_audit(
    request: Request,
    target_id: str = Query(""),
    allow_infrastructure: bool = Query(False),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.run_hard_audit(target_id, allow_infrastructure=allow_infrastructure)


@router.get("/camera_hunt/status")
def wifi_mk7_camera_hunt_status(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"active": False, "count": 0, "leads": [], "pipeline": {"active": False}, "toolchain": {}}
    channels = manager.get_channels(light=True)
    pipeline = manager.pipeline.status()
    toolchain = manager._toolchain_status()
    sensor = manager.sensor_snapshot or manager.monitor.ensure_monitor_interfaces(manager.scan_selected_interfaces)
    monitor_interface = sensor.get("monitor_interface")
    monitor_interfaces = sensor.get("monitor_interfaces") or ([monitor_interface] if monitor_interface else [])
    return {
        "active": bool(manager.scan_camera_hunt),
        "pipeline": pipeline,
        "toolchain": toolchain,
        "status": {
            "service": "wifi_mk7",
            "sensor_ready": bool(monitor_interface or monitor_interfaces),
            "capture_active": bool(manager._effective_capture_active()),
            "packet_rate_pps": manager.last_pps,
            "last_started_at": manager.last_started_at,
            "last_sweep_at": manager.last_sweep_at,
            "last_error": manager.last_error or ("" if (monitor_interface or monitor_interfaces) else sensor.get("detail", "")),
            "adapter": {
                "detected": bool(sensor.get("available")),
                "base_interface": sensor.get("base_interface"),
                "preferred_interface": sensor.get("preferred_interface") or manager.monitor.PREFERRED_INTERFACE,
                "monitor_interface": monitor_interface,
                "monitor_interfaces": monitor_interfaces,
                "mode": "Monitor Mode" if monitor_interface or monitor_interfaces else "Managed",
                "bands": sensor.get("bands") or ["2.4 GHz"],
                "monitor_supported": bool(sensor.get("monitor_supported")),
                "privilege_required": bool(sensor.get("privilege_required")),
                "remediation": sensor.get("remediation", ""),
                "detail": sensor.get("detail", ""),
                "sensors": sensor.get("sensors") or [],
            },
            "channels": channels,
            "capture": {
                "state": "Active" if manager._effective_capture_active() else ("Idle" if not manager.armed else "Ready"),
            },
            "inventory": {
                "network_count": len(manager.tracker.networks),
                "client_count": len(manager.tracker.clients),
                "pcap_count": len(manager.get_pcap_inventory()),
            },
            "scan": manager._scan_status_payload(),
            "camera_hunt": manager.scan_camera_hunt,
            "camera_hunt_pipeline": pipeline,
            "camera_hunt_auto_probe": manager.auto_probe_summary,
            "processing_pipeline": manager.processing_pipeline.status(),
            "toolchain": toolchain,
        },
    }


@router.get("/camera_hunt/results")
def wifi_mk7_camera_hunt_results(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "leads": [], "pipeline": {"active": False}}
    return manager.get_camera_hunt_results()


@router.get("/pcap")
def wifi_mk7_pcap(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"count": 0, "pcaps": []}
    pcaps = manager.get_pcap_inventory()
    return {"count": len(pcaps), "pcaps": pcaps}


@router.get("/evidence")
def wifi_mk7_evidence(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"session_manifest": {}, "targets": []}
    return {
        "session_manifest": manager.evidence.session_manifest(),
        "targets": list(manager.evidence.current_targets.values()),
    }


@router.get("/artifact")
def wifi_mk7_artifact(request: Request, path: str = Query("")):
    manager = _get_manager(request)
    artifact = _resolve_wifi_hunt_artifact(manager, path)
    return FileResponse(artifact)


@router.get("/channels")
def wifi_mk7_channels(request: Request, light: bool = Query(False)):
    manager = _get_manager(request)
    if manager is None:
        return {"state": "unavailable", "bands": []}
    return manager.get_channels(light=light)


@router.get("/redteam/status")
def wifi_mk7_redteam_status(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"state": "IDLE", "ok": False, "message": "Runtime or WiFi MK7 controller unavailable."}
    return manager.get_redteam_validation_status()


@router.post("/redteam/preflight")
def wifi_mk7_redteam_preflight(
    request: Request,
    target_id: str = Query(""),
    action_type: str = Query("deauth_evidence_probe"),
    confirm_authorized_lab: bool = Query(False),
    channel: int = Query(0, ge=0, le=196),
):
    manager = _get_manager(request)
    if manager is None:
        return {"state": "FAILED_CAPTURE_ERROR", "ok": False, "message": "Runtime or WiFi MK7 controller unavailable."}
    return manager.run_redteam_preflight(
        target_id=target_id,
        action_type=action_type,
        confirm_authorized_lab=confirm_authorized_lab,
        channel=channel,
    )


@router.post("/redteam/run")
def wifi_mk7_redteam_run(
    request: Request,
    target_id: str = Query(""),
    action_type: str = Query("deauth_evidence_probe"),
    confirm_authorized_lab: bool = Query(False),
    channel: int = Query(0, ge=0, le=196),
    max_duration: int = Query(30, ge=5, le=120),
    max_frame_count: int = Query(3, ge=1, le=10),
    reason_code: str = Query("7"),
    notes: str = Query(""),
):
    manager = _get_manager(request)
    if manager is None:
        return {"state": "FAILED_CAPTURE_ERROR", "ok": False, "message": "Runtime or WiFi MK7 controller unavailable."}
    return manager.run_redteam_validation(
        target_id=target_id,
        action_type=action_type,
        confirm_authorized_lab=confirm_authorized_lab,
        channel=channel,
        max_duration=max_duration,
        max_frame_count=max_frame_count,
        reason_code=reason_code,
        notes=notes,
    )


@router.get("/adversary_replay/status")
def wifi_mk7_adversary_replay_status(request: Request):
    manager = _get_manager(request)
    if manager is None:
        return {"state": "IDLE", "ok": False, "message": "Runtime or WiFi MK7 controller unavailable."}
    return manager.get_adversary_replay_status()


@router.post("/adversary_replay/run")
def wifi_mk7_adversary_replay_run(
    request: Request,
    capture_path: str = Query(""),
    confirm_authorized_lab: bool = Query(False),
    replay_label: str = Query(""),
    reset_before_replay: bool = Query(True),
):
    manager = _get_manager(request)
    if manager is None:
        return {"state": "FAILED_PARSE", "ok": False, "message": "Runtime or WiFi MK7 controller unavailable."}
    return manager.run_adversary_replay(
        capture_path=capture_path,
        confirm_authorized_lab=confirm_authorized_lab,
        replay_label=replay_label,
        reset_before_replay=reset_before_replay,
    )


@router.post("/imported_analysis")
def wifi_mk7_imported_analysis(
    request: Request,
    capture_path: str = Query(""),
    replay: bool = Query(False),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.analyze_imported_capture(capture_path, replay=replay)


@router.post("/camera_hunt/analyze_lead")
def wifi_mk7_camera_hunt_analyze_lead(
    request: Request,
    lead_id: str = Query(""),
    seconds: int = Query(30, ge=5, le=30),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.analyze_camera_lead(lead_id, seconds=seconds)


@router.post("/camera_hunt/probe_lead")
def wifi_mk7_camera_hunt_probe_lead(
    request: Request,
    lead_id: str = Query(""),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.probe_camera_lead(lead_id)


@router.post("/camera_hunt/probe_ip")
def wifi_mk7_camera_hunt_probe_ip(
    request: Request,
    ip: str = Query(""),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.probe_camera_ip(ip)


@router.post("/camera_hunt/validate_lead")
def wifi_mk7_camera_hunt_validate_lead(
    request: Request,
    lead_id: str = Query(""),
    seconds: int = Query(30, ge=5, le=30),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.validate_camera_lead(lead_id, seconds=seconds)


@router.post("/camera_hunt/hard_audit")
def wifi_mk7_camera_hunt_hard_audit(
    request: Request,
    lead_id: str = Query(""),
    seconds: int = Query(30, ge=5, le=30),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.hard_audit_camera_lead(lead_id, seconds=seconds)


@router.post("/camera_hunt/audit_layers")
def wifi_mk7_camera_hunt_audit_layers(
    request: Request,
    lead_id: str = Query(""),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.audit_camera_lead_layers(lead_id)


@router.post("/camera_hunt/video_truth_test")
def wifi_mk7_camera_hunt_video_truth_test(
    request: Request,
    lead_id: str = Query(""),
    seconds: int = Query(40, ge=20, le=60),
):
    manager = _get_manager(request)
    if manager is None:
        return {"ok": False, "error": "Runtime or WiFi MK7 controller unavailable."}
    return manager.video_truth_test_camera_lead(lead_id, seconds=seconds)


@router.get("/camera_hunt/artifact")
def wifi_mk7_camera_hunt_artifact(
    request: Request,
    path: str = Query(""),
):
    manager = _get_manager(request)
    target = _resolve_camera_artifact(manager, path)
    media_type = None
    suffix = target.suffix.lower()
    if suffix in {".jpg", ".jpeg"}:
        media_type = "image/jpeg"
    elif suffix == ".png":
        media_type = "image/png"
    elif suffix == ".bmp":
        media_type = "image/bmp"
    elif suffix == ".webp":
        media_type = "image/webp"
    elif suffix == ".json":
        media_type = "application/json"
    elif suffix == ".pcap":
        media_type = "application/vnd.tcpdump.pcap"
    elif suffix == ".pcapng":
        media_type = "application/octet-stream"
    elif suffix == ".txt":
        media_type = "text/plain; charset=utf-8"
    return FileResponse(target, media_type=media_type, filename=target.name)
