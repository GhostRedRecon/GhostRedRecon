from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.integrations.wifi_mk7.airodump_collector import AirodumpCollector
from backend.integrations.wifi_mk7.bettercap_collector import BettercapCollector
from backend.integrations.wifi_mk7.kismet_collector import KismetCollector
from backend.integrations.wifi_mk7.mk7_controller import WiFiMK7Controller


class FakeProcess:
    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid
        self._alive = True
        self.wait_calls = []

    def poll(self):
        return None if self._alive else 0

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        self._alive = False
        return 0

    def terminate(self):
        self._alive = False

    def kill(self):
        self._alive = False


@pytest.mark.parametrize(
    ("collector_cls", "module_path"),
    [
        (AirodumpCollector, "backend.integrations.wifi_mk7.airodump_collector"),
        (KismetCollector, "backend.integrations.wifi_mk7.kismet_collector"),
        (BettercapCollector, "backend.integrations.wifi_mk7.bettercap_collector"),
    ],
)
def test_collectors_stop_process_groups(monkeypatch, collector_cls, module_path):
    collector = collector_cls(Path("/tmp"))
    collector.process = FakeProcess()
    collector.started_at = 10.0
    kill_calls = []

    monkeypatch.setattr(f"{module_path}.os.getpgid", lambda pid: pid)
    monkeypatch.setattr(f"{module_path}.os.killpg", lambda pgid, sig: kill_calls.append((pgid, int(sig))))

    collector.stop()

    assert collector.process is None
    assert collector.stopped_at is not None
    assert kill_calls
    assert kill_calls[0][0] == 4242
    assert collector.last_stop_state == "terminated_process_group"


def test_toolchain_status_marks_packet_tools_idle_when_scan_is_idle():
    controller = WiFiMK7Controller.__new__(WiFiMK7Controller)
    controller.capture = SimpleNamespace(
        tool_status=lambda: {
            "iw": {"available": True, "path": "/usr/sbin/iw"},
            "dumpcap": {"available": True, "path": "/usr/bin/dumpcap"},
            "tshark": {"available": True, "path": "/usr/bin/tshark"},
        }
    )
    controller.pipeline = SimpleNamespace(
        status=lambda: {
            "collectors": [
                {"name": "airodump-ng", "available": True, "path": "/usr/sbin/airodump-ng", "active": False},
                {"name": "kismet", "available": True, "path": "/usr/bin/kismet", "active": False},
                {"name": "bettercap", "available": True, "path": "/usr/bin/bettercap", "active": False},
            ],
            "assignments": {},
            "summary": "pipeline idle",
        }
    )
    controller.processing_pipeline = SimpleNamespace(status=lambda: {"running": False, "limits": {"zeek_enabled": True}})
    controller.enricher = SimpleNamespace(status=lambda: {"zeek_available": True})
    controller.scan_selected_interfaces = ["wlan0mon"]
    controller.scan_camera_hunt = True
    controller.scan_blue_team_enrichment = False
    controller._effective_capture_active = lambda: False

    status = controller._toolchain_status()

    sensor_control = status["sensor_control"]
    packet_capture = status["packet_capture"]
    runtime_summary = status["runtime_summary"]

    assert sensor_control[0]["active"] is False
    assert packet_capture[0]["name"] == "dumpcap"
    assert packet_capture[0]["active"] is False
    assert packet_capture[1]["name"] == "tshark"
    assert packet_capture[1]["active"] is False
    assert packet_capture[2]["name"] == "zeek"
    assert packet_capture[2]["active"] is False
    assert runtime_summary["all_stopped"] is True
    assert runtime_summary["cleanup_state"] == "idle"
