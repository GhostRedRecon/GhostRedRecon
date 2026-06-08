from backend.integrations.wifi_mk7.mk7_controller import WiFiMK7Controller
from backend.integrations.wifi_mk7.service_exposure_audit_engine import ServiceExposureAuditEngine


def test_service_exposure_audit_emits_progress_updates(monkeypatch):
    engine = ServiceExposureAuditEngine()
    progress = []
    monkeypatch.setattr(engine, "_connect_scan", lambda ip_value, port: {
        "port": int(port),
        "state": "open" if int(port) == 80 else "closed",
        "method": "tcp_connect",
        "timestamp": 1,
        "evidence": "mocked",
        "explanation": "mocked",
    })
    monkeypatch.setattr(engine, "_http_probe", lambda ip_value, port, secure: {
        "service_type": "https" if secure else "http",
        "response_observed": True,
        "banner_present": True,
        "parsed_result": {
            "status_code": 200,
            "reason": "OK",
            "headers": {},
            "server_banner": "mock",
            "redirect": "",
            "access_posture": "OPEN_NO_AUTH",
            "body_excerpt": "",
        },
        "timestamp": 1,
        "evidence": "HTTP 200",
        "explanation": "mocked",
    })

    result = engine.run(
        target_id="wifi-target-1",
        ip_value="192.168.0.25",
        target_mac="aa:bb:cc:dd:ee:ff",
        validation_method="ddi_evidence_policy",
        confidence_score=0.84,
        progress_callback=progress.append,
    )

    assert result["target_validation"]["target_ip"] == "192.168.0.25"
    assert progress
    assert progress[0]["id"] == "target_validation"
    assert any(entry["id"] == "port_discovery" for entry in progress)
    assert any(entry["id"] == "trace" for entry in progress)


def test_run_hard_audit_wraps_service_audit_metadata(monkeypatch):
    controller = WiFiMK7Controller.__new__(WiFiMK7Controller)
    monkeypatch.setattr(
        controller,
        "run_service_audit",
        lambda target_id, allow_infrastructure=False: {"ok": True, "target_id": target_id},
    )

    result = controller.run_hard_audit("ssid:aa:bb:cc:dd:ee:ff")

    assert result["ok"] is True
    assert result["target_id"] == "ssid:aa:bb:cc:dd:ee:ff"
    assert result["audit_kind"] == "wifi_hard_audit"
    assert "destination_analysis" in result["audit_scope"]
