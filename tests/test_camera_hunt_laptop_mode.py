from backend.integrations.wifi_mk7.mk7_controller import WiFiMK7Controller
from backend.integrations.wifi_mk7.staged_pipeline import StagedWiFiScanPipeline
from types import SimpleNamespace


def test_auto_resource_policy_keeps_balanced_for_powerful_laptop(monkeypatch):
    controller = WiFiMK7Controller.__new__(WiFiMK7Controller)
    monkeypatch.setattr("backend.integrations.wifi_mk7.mk7_controller.get_project_config", lambda: {"wifiMk7": {"resourceProfile": "auto"}})
    monkeypatch.setattr("backend.integrations.wifi_mk7.mk7_controller.os.cpu_count", lambda: 12)
    monkeypatch.setattr(controller, "_system_memory_mb", lambda: 16384)

    profile = controller._resolve_resource_policy()

    assert profile["name"] == "balanced"
    assert profile["enable_kismet"] is True
    assert profile["enable_bettercap"] is True
    assert profile["enable_zeek"] is True
    assert profile["camera_hunt_auto_probe_leads"] == 5


def test_staged_pipeline_uses_slower_camera_hunt_refresh_and_sampling():
    pipeline = StagedWiFiScanPipeline(
        tracker=None,
        enricher=None,
        get_networks=lambda: [],
        get_clients=lambda: [],
    )

    pipeline.start(
        enrichment_enabled=False,
        camera_hunt=True,
        enable_zeek=False,
        enrichment_sample_rate=1,
        max_enrichment_pcap_bytes=0,
    )
    try:
        assert pipeline.detection_refresh_interval_sec == pipeline.CAMERA_HUNT_DETECTION_REFRESH_INTERVAL_SEC
        assert pipeline.enrichment_sample_rate == 1
        status = pipeline.status()
        assert status["limits"]["detection_refresh_interval_seconds"] == pipeline.CAMERA_HUNT_DETECTION_REFRESH_INTERVAL_SEC
    finally:
        pipeline.stop()


def test_get_camera_hunt_results_uses_idle_cache(monkeypatch):
    controller = WiFiMK7Controller.__new__(WiFiMK7Controller)
    controller.camera_hunt_results_cache = {"built_at": 100.0, "results": {"count": 1, "leads": [{"lead_id": "cached"}]}}
    controller.resource_policy = {
        "camera_hunt_results_cache_ttl_active": 10.0,
        "camera_hunt_results_cache_ttl_idle": 6.0,
    }

    monkeypatch.setattr(controller, "_effective_capture_active", lambda: False)
    monkeypatch.setattr("backend.integrations.wifi_mk7.mk7_controller.time.time", lambda: 104.0)
    monkeypatch.setattr(controller, "get_networks", lambda: (_ for _ in ()).throw(AssertionError("cache should avoid recompute")))
    monkeypatch.setattr(controller, "get_clients", lambda: (_ for _ in ()).throw(AssertionError("cache should avoid recompute")))

    result = controller.get_camera_hunt_results()

    assert result["leads"][0]["lead_id"] == "cached"


def test_auto_probe_top_camera_leads_reuses_cached_camera_hunt_results(monkeypatch):
    controller = WiFiMK7Controller.__new__(WiFiMK7Controller)
    controller.active_probe_cache = {}
    controller.auto_probe_summary = {}
    controller.resource_policy = {"camera_hunt_auto_probe_leads": 2}
    controller.active_fingerprint = SimpleNamespace(
        _candidate_ips=lambda lead: ["192.168.0.29"],
        probe_lead=lambda lead: {"ok": True, "candidate_ips": ["192.168.0.29"], "summary": {"camera_positive": False}},
    )
    cached_results = {
        "leads": [
            {
                "mac": "78:8b:2a:64:60:b9",
                "camera_detection": {"score": 42.0},
                "target_score": {"score": 50},
            }
        ],
        "near_misses": [],
    }

    monkeypatch.setattr(controller, "get_camera_hunt_results", lambda: cached_results)
    monkeypatch.setattr(controller, "_camera_lead_id", lambda lead: "client:788b2a6460b9")

    summary = controller._auto_probe_top_camera_leads(max_leads=2)

    assert summary["attempted"] == 1
    assert summary["probed_leads"][0]["lead_id"] == "client:788b2a6460b9"
