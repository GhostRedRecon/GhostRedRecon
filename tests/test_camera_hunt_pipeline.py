from pathlib import Path

from backend.integrations.wifi_mk7.active_fingerprint_engine import ActiveFingerprintEngine
from backend.integrations.wifi_mk7.pipeline_controller import WiFiCameraPipelineController
from backend.integrations.wifi_mk7.wifi_intelligence_engine import WiFiIntelligenceEngine


def test_camera_decrypt_helper_is_available_in_live_scripts():
    repo_root = Path(__file__).resolve().parents[1]
    helper = repo_root / "scripts" / "ghostrecon_decrypt_test.py"
    assert helper.exists(), "Camera media evidence pipeline requires scripts/ghostrecon_decrypt_test.py."


def test_camera_hunt_excludes_router_vendor_family_near_miss(tmp_path):
    controller = WiFiCameraPipelineController(tmp_path)
    network = {
        "record_id": "5c:e9:31:5d:44:40",
        "bssid": "5c:e9:31:5d:44:40",
        "ssid": "DIGIFIBRA-teN9",
        "vendor": "TP-Link Systems Inc",
        "traffic_pattern": "periodic",
        "fingerprint": {"device_family": "isp-cpe", "device_type": "ISP Router / CPE"},
        "service_exposure": {"protocols": [], "summary": "No service exposure observed", "protocol_confidence": {}},
        "camera_detection": {
            "detected": False,
            "score": 25.0,
            "confidence": 0.25,
            "classification": "Vendor-family device",
            "vendor_role_state": "vendor_family_only",
            "family_match": "tp_link_tapo_lab",
            "family_match_confidence": "MEDIUM",
            "vendor_family": "tp_link_tapo_lab",
            "matched_families": ["tp_link_tapo_lab"],
        },
        "role_duel": {
            "winner_role": "router",
            "runner_up_role": "camera",
            "margin": 6.0,
        },
    }

    results = controller.build_results([network], [])

    assert results["leads"] == []
    assert results["near_misses"] == []
    assert results["possible_cloud_cameras"] == []


def test_camera_hunt_surfaces_xiaomi_family_as_possible_cloud_camera(tmp_path):
    controller = WiFiCameraPipelineController(tmp_path)
    client = {
        "record_id": "78:8b:2a:64:60:b9",
        "mac": "78:8b:2a:64:60:b9",
        "associated_bssid": "aa:bb:cc:dd:ee:ff",
        "vendor": "Zhen Shi Information Technology (Shanghai) Co., Ltd.",
        "packet_count": 42,
        "traffic_pattern": "periodic",
        "service_exposure": {"protocols": [], "summary": "No service exposure observed", "protocol_confidence": {}},
        "camera_detection": {
            "detected": False,
            "score": 39.0,
            "confidence": 0.39,
            "classification": "Vendor-family device",
            "vendor_role_state": "vendor_family_only",
            "family_match": "xiaomi_mi_imilab_mijia",
            "family_match_confidence": "MEDIUM",
            "vendor_family": "xiaomi_mi_imilab_mijia",
            "matched_families": ["xiaomi_mi_imilab_mijia"],
        },
        "role_duel": {"winner_role": "iot", "runner_up_role": "camera", "margin": 3.0},
    }

    results = controller.build_results([], [client])

    assert results["leads"] == []
    assert results["possible_cloud_camera_count"] == 1
    possible = results["possible_cloud_cameras"][0]
    evidence = possible["cloud_camera_evidence"]
    assert evidence["bucket"] == "possible_cloud_camera"
    assert evidence["proof_status"] == "missing"
    assert evidence["proof_level"] == "NO_PROOF"
    assert "gateway DNS/TLS-SNI/QUIC metadata during idle, app-open, and live-view stages" in evidence["required_evidence"]
    assert evidence["cloud_camera_candidate"] is True


def test_camera_hunt_does_not_promote_xiaomi_family_network_to_possible_cloud(tmp_path):
    controller = WiFiCameraPipelineController(tmp_path)
    network = {
        "record_id": "aa:bb:cc:dd:ee:ff",
        "bssid": "aa:bb:cc:dd:ee:ff",
        "ssid": "Lab Router",
        "vendor": "Zhen Shi Information Technology (Shanghai) Co., Ltd.",
        "traffic_pattern": "periodic",
        "fingerprint": {"device_family": "router", "device_type": "Router"},
        "service_exposure": {"protocols": [], "summary": "No service exposure observed", "protocol_confidence": {}},
        "camera_detection": {
            "detected": False,
            "score": 39.0,
            "confidence": 0.39,
            "classification": "Vendor-family device",
            "vendor_role_state": "vendor_family_only",
            "family_match": "xiaomi_mi_imilab_mijia",
            "family_match_confidence": "MEDIUM",
            "vendor_family": "xiaomi_mi_imilab_mijia",
            "matched_families": ["xiaomi_mi_imilab_mijia"],
        },
        "role_duel": {"winner_role": "router", "runner_up_role": "camera", "margin": 10.0},
    }

    results = controller.build_results([network], [])

    assert results["leads"] == []
    assert results["near_misses"] == []
    assert results["possible_cloud_cameras"] == []


def test_active_probe_summary_distinguishes_visual_proof_from_service_hits(tmp_path):
    engine = ActiveFingerprintEngine(root_dir=tmp_path)

    service_only = engine._summarize(
        [
            {
                "ip": "192.168.1.50",
                "rtsp": {"camera_hint": True},
                "snapshot": {"image_hint": False, "findings": []},
                "http": {},
                "onvif": {},
            }
        ]
    )

    assert service_only["camera_positive"] is True
    assert service_only["video_or_image_proof"] is False
    assert service_only["visual_artifact_count"] == 0
    assert service_only["proof_level"] == "SERVICE_HINT_ONLY"

    visual = engine._summarize(
        [
            {
                "ip": "192.168.1.50",
                "rtsp": {
                    "camera_hint": True,
                    "frame_capture_path": "/tmp/frame.jpg",
                    "frame_capture_url": "rtsp://192.168.1.50:554/stream1",
                },
                "snapshot": {
                    "image_hint": True,
                    "findings": [
                        {
                            "saved_path": "/tmp/snapshot.jpg",
                            "scheme": "http",
                            "port": 80,
                            "path": "/snapshot.jpg",
                            "payload_sha256": "abc",
                        }
                    ],
                },
                "http": {},
                "onvif": {},
            }
        ]
    )

    assert visual["video_or_image_proof"] is True
    assert visual["proof_level"] == "VISUAL_ARTIFACT"
    assert visual["rtsp_frame_hits"] == 1
    assert visual["visual_artifact_count"] == 2


def test_video_evidence_reports_cloud_leakage_metadata(tmp_path):
    engine = WiFiIntelligenceEngine(history_path=tmp_path / "history.json")
    services = {
        "protocols": ["TLS", "QUIC", "DNS"],
        "cloud_endpoints": ["stream.vendorcloud.example"],
        "protocol_confidence": {"TLS": 45, "QUIC": 30},
    }
    item = {
        "tls_server_names": ["stream.vendorcloud.example"],
        "quic_server_names": ["media.vendorcloud.example"],
        "dns_query_names": ["stream.vendorcloud.example"],
        "http_hosts": ["api.vendorcloud.example"],
        "http_uris": ["/camera/live"],
        "scenario_history": {
            "current_scenario": "live_view",
            "available_scenarios": ["idle", "live_view"],
            "idle": {"bytes": 1024, "packets": 10, "packet_rate_pps": 0.5, "endpoints": ["stream.vendorcloud.example"]},
            "live_view": {"bytes": 1048576, "packets": 200, "packet_rate_pps": 12, "duration_seconds": 30, "endpoints": ["stream.vendorcloud.example", "media.vendorcloud.example"]},
        },
    }

    evidence = engine._video_evidence(
        item,
        fingerprint={"device_family": "camera"},
        services=services,
        behavior={},
        stream_state={"metrics": {"long_lived_flow": True}},
        scenario_delta={"comparisons": {"idle_vs_live_view": {"status": "STRONGER_TARGET"}}},
        camera_confirmation={"level": "likely"},
    )

    cloud_audit = evidence["cloud_leakage_audit"]
    assert cloud_audit["status"] == "observed"
    assert cloud_audit["risk_level"] == "HIGH"
    assert cloud_audit["metadata_exposed"] is True
    assert cloud_audit["content_exposed"] is False
    assert "api.vendorcloud.example" in cloud_audit["http_hosts"]
