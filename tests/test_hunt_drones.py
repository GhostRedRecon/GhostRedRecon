from __future__ import annotations

import json
import time
from pathlib import Path

from backend.integrations.dji_droneid_adapter import DJIDroneIDAdapter
from backend.integrations.hunt_drones.assurance import DetectionAssuranceEngine
from backend.integrations.hunt_drones.dji_features import AdditiveUAVEnrichmentService, SDRBurstLockEngine
from backend.integrations.hunt_drones_controller import HuntDronesController
from backend.integrations.hunt_drones.policy import ReceiveOnlyGuard
from backend.integrations.hunt_drones.replay import ReplayManager
from backend.integrations.hunt_drones.scoring import ConfidenceScoringEngine, ProofTierEngine


def test_receive_only_guard_blocks_offensive_capabilities():
    guard = ReceiveOnlyGuard()
    decision = guard.enforce("deauth")
    assert decision.allowed is False
    assert decision.reason == "The feature has been disabled on the backend."


def test_proof_tier_and_confidence_promote_decoder_backed_multi_sensor_evidence():
    proof_engine = ProofTierEngine()
    confidence_engine = ConfidenceScoringEngine()
    features = {
        "wifi_signature_score": 12,
        "vendor_score": 8,
        "remote_id_score": 18,
        "dji_score": 0,
        "sdr_score": 8,
        "recurrence_score": 8,
        "stability_score": 6,
        "band_consistency_score": 4,
        "sensor_score": 8,
        "baseline_anomaly_score": 4,
        "decoder_backed": True,
        "multi_sensor": True,
        "replayable": True,
        "raw_evidence_complete": True,
        "recurrence_count": 5,
        "temporal_stability": 0.8,
        "rationale": ["decoder-backed observation retained"],
    }
    proof = proof_engine.assign(features)
    score = confidence_engine.score(features, {"penalties": [], "total_penalty": 0}, proof)
    assert proof["tier"] == 4
    assert score["score"] >= 85
    assert score["label"] in {"high", "very high"}


def test_replay_manager_loads_retained_session(tmp_path: Path):
    evidence_root = tmp_path / "evidence"
    session_dir = evidence_root / "SESSION_2026_04_23_120000_demo"
    (session_dir / "targets").mkdir(parents=True)
    (session_dir / "topology").mkdir(parents=True)
    (session_dir / "reports").mkdir(parents=True)
    (session_dir / "dji").mkdir(parents=True)
    (session_dir / "remote_id").mkdir(parents=True)
    (session_dir / "leads").mkdir(parents=True)
    (session_dir / "replay").mkdir(parents=True)
    session = {"session_id": session_dir.name, "session_name": "Demo Session", "created_at": 1, "scan_profile": "dji_focus"}
    (session_dir / "session.json").write_text(json.dumps(session), encoding="utf-8")
    (session_dir / "targets" / "index.json").write_text(json.dumps({"count": 1, "targets": [{"target_id": "t1", "label": "demo"}]}), encoding="utf-8")
    (session_dir / "topology" / "graph.json").write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")
    (session_dir / "reports" / "summary.json").write_text(json.dumps({"session_name": "Demo Session", "score_model_version": "hunt_drones_v2"}), encoding="utf-8")
    (session_dir / "environment_baseline.json").write_text(json.dumps({"summary": "baseline"}), encoding="utf-8")
    (session_dir / "dji" / "decode_manifest.json").write_text(json.dumps({"matched_count": 1, "sample_windows": [{"reference": "sdr/iq_snippets/demo.json"}]}), encoding="utf-8")
    (session_dir / "remote_id" / "parsed_entities.json").write_text(json.dumps({"items": [{"identifier": "rid-1"}]}), encoding="utf-8")
    (session_dir / "remote_id" / "parsed_objects.json").write_text(json.dumps({"items": [{"object_type": "remote_id_candidate"}]}), encoding="utf-8")
    (session_dir / "leads" / "index.json").write_text(json.dumps({"items": [{"lead_id": "lead-1"}]}), encoding="utf-8")
    (session_dir / "replay" / "session_trace.json").write_text(json.dumps({"phase": "audit"}), encoding="utf-8")

    replay = ReplayManager(evidence_root)
    loaded = replay.load_session(session_dir.name)

    assert loaded["ok"] is True
    assert loaded["session"]["session_name"] == "Demo Session"
    assert loaded["detections"][0]["target_id"] == "t1"
    assert loaded["dji_manifest"]["matched_count"] == 1
    assert loaded["remote_id_objects"][0]["object_type"] == "remote_id_candidate"


def test_live_detection_returns_cached_leads_without_forcing_audit(monkeypatch, tmp_path: Path):
    class FakeRuntime:
        wifi_mk7 = None
        hackrf_sweep = None
        ble_nr5 = None

    controller = HuntDronesController(runtime=FakeRuntime())
    controller.evidence_root = tmp_path / "evidence"
    controller.evidence_root.mkdir(parents=True, exist_ok=True)
    started = controller.start_session(
        session_name="Live Demo",
        operator="",
        location="",
        notes="",
        scan_profile="dji_focus",
        evidence_path=str(tmp_path / "evidence" / "SESSION_TEST"),
    )
    assert started["ok"] is True

    lead = {
        "target_id": "drone-lead",
        "label": "DJI Lead",
        "family_label": "DJI Family",
        "model_family": "Wi-Fi broadcast source",
        "target_type": "probable_drone",
        "sensor_sources": ["wifi"],
        "channel": 149,
        "packet_count": 12,
        "rssi_dbm": -55,
        "reasons": ["DJI-family Wi-Fi identity evidence retained."],
    }

    monkeypatch.setattr(controller, "_wifi_runtime_snapshot", lambda: {
        "capture_active": True,
        "target_seconds": 86400,
        "progress_percent": 1.0,
        "elapsed_seconds": 1.0,
        "scan_mode": "adaptive_residential_dfs",
        "current_channel": 149,
        "channels_state": "active",
        "coverage_summary": "focused",
        "coverage_level": "STRONG",
        "network_count": 1,
        "client_count": 1,
        "pcap_count": 0,
    })
    monkeypatch.setattr(controller, "_advance_sdr_pipeline", lambda: {"running": True, "status_detail": "sweeping"})
    monkeypatch.setattr(controller, "_harvest_sdr_candidates", lambda: [])
    monkeypatch.setattr(controller, "_wifi_observations", lambda: [{"ssid": "", "vendor": "", "channel": 149, "packet_count": 12, "rssi_dbm": -55}])
    monkeypatch.setattr(controller, "_base_detection_set", lambda observations, sdr_candidates: [lead])

    audit_requests: list[str] = []

    def fake_start_background_audit():
        audit_requests.append("started")
        controller.scan_state["audit_started"] = True

    monkeypatch.setattr(controller, "_start_background_audit", fake_start_background_audit)

    first = controller.get_live_detection_state()
    second = controller.get_live_detection_state()

    assert first["ok"] is True
    assert first["live_lead_count"] == 1
    assert first["lead_detected"] is True
    assert audit_requests == ["started"]
    assert second["live_lead_count"] == 1
    assert audit_requests == ["started"]


def test_detection_assurance_engine_promotes_multi_sensor_leads():
    engine = DetectionAssuranceEngine()
    snapshot = engine.evaluate(
        wifi_rows=[
            {
                "timestamp": 10.0,
                "ssid": "",
                "vendor": "",
                "channel": 149,
                "packet_count": 9,
                "rssi_dbm": -56,
                "associated_bssid": "aa:bb:cc:dd:ee:ff",
            }
        ],
        sdr_rows=[
            {
                "timestamp": 10.2,
                "profile_key": "drone_58",
                "peak_mhz": 5785.0,
                "peak_db": -54.0,
                "noise_floor_db": -92.0,
                "burst_density": 0.8,
                "burst_recurrence": 2.5,
                "rolling_persistence": 0.7,
                "row_id": "rf-1",
            }
        ],
        baseline={"common_ssids": [], "noise_floor_hint_db": -92},
        scan_profile="dji_focus",
        now=11.0,
    )

    assert snapshot.leads
    assert snapshot.band_attention
    assert snapshot.scheduler_actions
    assert snapshot.raw_filtered_counts["active_leads"] >= 1
    assert snapshot.sensor_sync["status"] in {"tracking", "correlated"}


def test_dji_adapter_promotes_recurring_near_matches():
    adapter = DJIDroneIDAdapter()
    manifest = adapter.decode(
        [
            {
                "peak_mhz": 5770.0,
                "peak_db": -57.0,
                "burst_recurrence": 3,
                "rolling_persistence": 0.22,
                "timestamp": 11.0,
            }
        ]
    )
    assert manifest["matched_count"] == 1
    assert manifest["targets"]
    assert manifest["targets"][0]["manufacturer"] == "DJI"


def test_dji_burst_lock_engine_builds_replayable_sample_windows():
    engine = SDRBurstLockEngine()
    locks = engine.build_locks(
        [
            {
                "row_id": "rf-a",
                "timestamp": 11.0,
                "peak_mhz": 5776.0,
                "peak_db": -56.0,
                "burst_density": 0.7,
                "burst_recurrence": 5,
                "rolling_persistence": 0.6,
            },
            {
                "row_id": "rf-b",
                "timestamp": 11.2,
                "peak_mhz": 5779.0,
                "peak_db": -58.0,
                "burst_density": 0.6,
                "burst_recurrence": 4,
                "rolling_persistence": 0.5,
            },
        ],
        now=12.0,
    )
    assert locks
    assert locks[0]["lock_state"] in {"candidate_lock", "burst_locked"}
    assert locks[0]["sample_window"]["reference"].startswith("sdr/iq_snippets/")


def test_additive_uav_enrichment_preserves_hidden_high_band_candidates():
    service = AdditiveUAVEnrichmentService()
    enriched = service.enrich({"ssid": "", "vendor": "", "channel": 149, "packet_count": 7})
    assert enriched["uav_enrichment"]["score"] >= 18
    assert enriched["uav_enrichment"]["hints"]


def test_dji_adapter_emits_structured_lock_and_sample_window_manifest():
    adapter = DJIDroneIDAdapter()
    manifest = adapter.decode(
        [
            {
                "peak_mhz": 5776.0,
                "peak_db": -56.0,
                "burst_recurrence": 5,
                "rolling_persistence": 0.6,
                "timestamp": 11.0,
                "row_id": "rf-a",
            }
        ],
        burst_locks=[
            {
                "lock_id": "lock-1",
                "lock_state": "burst_locked",
                "lock_strength": 88,
                "nearest_center_mhz": 5776.5,
                "band": "5.8 GHz",
                "peak_list_mhz": [5776.0, 5779.0],
                "burst_recurrence": 5,
                "rolling_persistence": 0.6,
                "sample_window": {"reference": "sdr/iq_snippets/lock-1.json"},
            }
        ],
    )
    assert manifest["burst_locks"][0]["lock_state"] == "burst_locked"
    assert manifest["sample_windows"][0]["reference"] == "sdr/iq_snippets/lock-1.json"
    assert manifest["parsed_objects"][0]["object_type"] == "dji_burst_lock"


def test_hunt_drones_sdr_pipeline_cycles_profiles():
    class FakeSweep:
        def __init__(self):
            self.profile_key = ""
            self.running = False
            self.completed = False
            self.started = []

        def get_state(self):
            return {
                "running": self.running,
                "completed": self.completed,
                "profile_key": self.profile_key,
                "status_detail": "running" if self.running else "completed" if self.completed else "idle",
            }

        def start(self, profile_key):
            self.profile_key = profile_key
            self.running = True
            self.completed = False
            self.started.append(profile_key)
            return {"status": "started", "profile_key": profile_key}

    class FakeRuntime:
        def __init__(self):
            self.hackrf_sweep = FakeSweep()
            self.wifi_mk7 = None
            self.ble_nr5 = None

    controller = HuntDronesController(runtime=FakeRuntime())
    controller.session_metadata = {"scan_profile": "dji_focus"}
    controller.scan_state["active"] = True

    first = controller._advance_sdr_pipeline()
    assert first["profile_key"] == "drone_58"

    controller.runtime.hackrf_sweep.running = False
    controller.runtime.hackrf_sweep.completed = True
    second = controller._advance_sdr_pipeline()
    assert second["profile_key"] == "drone_24"

    controller.runtime.hackrf_sweep.running = False
    controller.runtime.hackrf_sweep.completed = True
    third = controller._advance_sdr_pipeline()
    assert third["profile_key"] == "drone_58"


def test_hunt_drones_preserves_completed_sdr_leads_before_restarting_sweep():
    now = time.time()

    class FakeSweep:
        def __init__(self):
            self.profile_key = "drone_58"
            self.running = False
            self.completed = True
            self.started = []

        def get_state(self):
            target_leads = []
            if self.completed and self.profile_key == "drone_58":
                target_leads = [
                    {
                        "row_id": "neo-58-1",
                        "timestamp": now,
                        "peak_mhz": 5785.0,
                        "peak_db": -57.0,
                        "family": "5.8 GHz Drone / WiFi Link",
                        "recommended_tab": "Hunt Drones",
                        "burst_density": 0.7,
                        "burst_recurrence": 3,
                        "rolling_persistence": 0.6,
                    }
                ]
            return {
                "running": self.running,
                "completed": self.completed,
                "profile_key": self.profile_key,
                "status_detail": "completed_with_detections" if self.completed else "running",
                "target_leads": target_leads,
            }

        def start(self, profile_key):
            self.started.append(profile_key)
            self.profile_key = profile_key
            self.running = True
            self.completed = False
            return {"status": "started", "profile_key": profile_key}

    class FakeRuntime:
        def __init__(self):
            self.hackrf_sweep = FakeSweep()
            self.wifi_mk7 = None
            self.ble_nr5 = None

    controller = HuntDronesController(runtime=FakeRuntime())
    controller.started_at = now - 1.0
    controller.session_metadata = {"scan_profile": "dji_focus"}
    controller.scan_state["active"] = True
    controller.scan_state["current_sdr_profile"] = "drone_58"

    state = controller._advance_sdr_pipeline()

    assert state["profile_key"] == "drone_24"
    assert controller.runtime.hackrf_sweep.started == ["drone_24"]
    assert controller.scan_state["sdr_candidates"]
    assert controller.scan_state["sdr_candidates"][0]["row_id"] == "neo-58-1"
    assert controller.scan_state["sdr_candidates"][0]["profile_key"] == "drone_58"


def test_hunt_drones_watchdog_restarts_wifi_capture_when_session_is_armed(tmp_path: Path):
    class FakeWiFi:
        def __init__(self):
            self.started = 0

        def _effective_capture_active(self):
            return False

        def start(self, **kwargs):
            self.started += 1
            return {"status": "started_and_scanning", "kwargs": kwargs}

    class FakeRuntime:
        def __init__(self):
            self.wifi_mk7 = FakeWiFi()
            self.hackrf_sweep = None
            self.ble_nr5 = None

    controller = HuntDronesController(runtime=FakeRuntime())
    controller.evidence_root = tmp_path / "evidence"
    controller.evidence_root.mkdir(parents=True, exist_ok=True)
    started = controller.start_session(
        session_name="Watchdog Demo",
        operator="",
        location="",
        notes="",
        scan_profile="dji_focus",
        evidence_path=str(tmp_path / "evidence" / "SESSION_WATCHDOG"),
    )
    assert started["ok"] is True
    controller.active = False

    live = controller.get_live_detection_state()

    assert controller.runtime.wifi_mk7.started == 1
    assert live["ok"] is True


def test_hunt_drones_ephemeral_test_mode_skips_evidence_writes(tmp_path: Path):
    class FakeRuntime:
        wifi_mk7 = None
        hackrf_sweep = None
        ble_nr5 = None

    controller = HuntDronesController(runtime=FakeRuntime())
    controller.evidence_root = tmp_path / "evidence"
    controller.evidence_root.mkdir(parents=True, exist_ok=True)
    started = controller.start_session(
        session_name="Ephemeral Demo",
        operator="",
        location="",
        notes="",
        scan_profile="dji_focus",
        evidence_path=str(tmp_path / "evidence" / "SESSION_EPHEMERAL"),
    )
    assert started["ok"] is True
    assert controller.retention_mode == "ephemeral_test"
    assert not (tmp_path / "evidence" / "SESSION_EPHEMERAL" / "session.json").exists()
    status = controller.get_status()
    assert status["retention_mode"] == "ephemeral_test"
    assert status["evidence_dir"] == ""


def test_hunt_drones_prunes_stale_sdr_only_detections_in_ephemeral_mode():
    class FakeRuntime:
        wifi_mk7 = None
        hackrf_sweep = None
        ble_nr5 = None

    controller = HuntDronesController(runtime=FakeRuntime())
    stale_time = time.time() - (controller.SDR_TARGET_STALE_SECONDS + 2.0)
    controller.detections = [
        {
            "target_id": "stale-dji",
            "sensor_sources": ["sdr"],
            "last_seen": stale_time,
            "confidence_score": {"score": 46},
        }
    ]
    controller.live_leads = list(controller.detections)

    detections = controller.get_detections()

    assert detections == []
    assert controller.live_leads == []
