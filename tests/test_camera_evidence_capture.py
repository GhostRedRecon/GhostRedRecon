import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from backend.integrations.wifi_mk7.active_fingerprint_engine import ActiveFingerprintEngine
from backend.integrations.wifi_mk7.mk7_controller import WiFiMK7Controller


def test_active_fingerprint_candidate_ips_include_direct_lead_fields(monkeypatch, tmp_path):
    engine = ActiveFingerprintEngine(root_dir=tmp_path, preferred_interface="wlan0")
    monkeypatch.setattr(engine, "_neighbor_cache_candidates", lambda lead: [])

    candidate_ips = engine._candidate_ips(
        {
            "ip_addresses": ["192.168.0.29"],
            "candidate_ip_addresses": ["192.168.0.30"],
        }
    )

    assert "192.168.0.29" in candidate_ips[:2]
    assert "192.168.0.30" in candidate_ips[:2]


def test_collect_target_candidate_ips_includes_explicit_ip_lists(monkeypatch):
    controller = WiFiMK7Controller.__new__(WiFiMK7Controller)
    monkeypatch.setattr(controller, "_neighbor_ips_for_macs", lambda macs: [])
    monkeypatch.setattr(controller, "_lead_mac_candidates", lambda target: [])
    monkeypatch.setattr(controller, "_extract_mac_flows_from_pcaps", lambda target, inventory: {})
    monkeypatch.setattr(controller, "get_pcap_inventory", lambda: [])

    candidate_ips = controller._collect_target_candidate_ips(
        {
            "ip_addresses": ["192.168.0.29"],
            "candidate_ip_addresses": ["192.168.0.30"],
            "active_fingerprint": {"candidate_ips": ["192.168.0.31"]},
        }
    )

    assert candidate_ips[:3] == ["192.168.0.29", "192.168.0.30", "192.168.0.31"]


def test_capture_direct_target_ip_window_writes_evidence(monkeypatch, tmp_path):
    controller = WiFiMK7Controller.__new__(WiFiMK7Controller)
    controller.root_dir = tmp_path
    controller.capture = SimpleNamespace(
        dumpcap_path="/usr/bin/dumpcap",
        tcpdump_path="",
        tshark_path="/usr/bin/tshark",
    )
    controller.active_fingerprint = SimpleNamespace(
        _route_interface=lambda ip: "wlan0",
        _default_route_interface=lambda: "wlan0",
    )
    controller.CAMERA_PACKET_MAX_BYTES = 20 * 1024 * 1024

    def fake_run(command, capture_output, text, timeout, check):
        output_index = command.index("-w") + 1
        Path(command[output_index]).write_bytes(b"pcap-bytes")
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_extract(*, source_path, display_filter, destination_path, max_bytes):
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_bytes(b"filtered-pcapng")
        return {
            "ok": True,
            "path": str(destination_path),
            "packet_count": 5,
            "file_size_bytes": len(b"filtered-pcapng"),
            "truncated": False,
        }

    def fake_convert(*, source_path, destination_path):
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_bytes(b"pcap")
        return {"ok": True, "path": str(destination_path), "file_size_bytes": 4, "packet_count": 5}

    def fake_summary(*, pcap_path, target_ip):
        return {
            "target_ip": target_ip,
            "packet_count": 5,
            "total_bytes": 512,
            "assessment": "camera_ip_activity_observed",
            "protocols_seen": ["tcp", "tls"],
            "protocol_counts": {"tcp": 5, "tls": 5},
            "ports_seen": [443],
            "endpoint_ips": ["1.1.1.1"],
            "host_indicators": ["api.io.mi.com"],
            "stream_detected": False,
        }

    monkeypatch.setattr("backend.integrations.wifi_mk7.mk7_controller.subprocess.run", fake_run)
    monkeypatch.setattr(controller, "_extract_capped_filtered_pcap", fake_extract)
    monkeypatch.setattr(controller, "_convert_pcapng_to_pcap", fake_convert)
    monkeypatch.setattr(controller, "_summarize_camera_packet_pcap", fake_summary)

    result = controller._capture_direct_target_ip_window(
        lead_id="78:8b:2a:64:60:b9",
        target_ip="192.168.0.29",
        seconds=8,
        stage_id="trigger",
    )

    assert result["ok"] is True
    assert result["target_ip"] == "192.168.0.29"
    assert result["interface"] == "wlan0"
    assert result["packet_count"] == 5
    assert "evidence/camera_protocol" in result["pcapng_path"]
    assert Path(result["summary_path"]).exists()
    summary_payload = json.loads(Path(result["summary_path"]).read_text(encoding="utf-8"))
    assert summary_payload["target_ip"] == "192.168.0.29"
    assert summary_payload["assessment"] == "camera_ip_activity_observed"
