from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

from backend.integrations.dji_droneid_adapter import DJIDroneIDAdapter
from backend.integrations.opendroneid_adapter import OpenDroneIDAdapter
from backend.integrations.hunt_drones import (
    AdditiveUAVEnrichmentService,
    ConfidenceScoringEngine,
    DetectionAssuranceEngine,
    DisruptionSusceptibilityEngine,
    EvidenceRetentionManager,
    FalsePositiveSuppressionEngine,
    ProofTierEngine,
    ReceiveOnlyGuard,
    ReplayManager,
    ReportBuilder,
    ResearchFeatureGate,
    SDRBurstLockEngine,
    SettingsSafetyEnforcer,
    SwarmGroupingEngine,
    TargetFusionEngine,
    ToolCapabilityPolicy,
    TopologyGraphBuilder,
    build_environment_baseline,
)


class HuntDronesController:
    VERSION = "2.0.0"
    DEFAULT_RETENTION_MODE = "ephemeral_test"
    SDR_TARGET_STALE_SECONDS = 8.0
    GENERAL_TARGET_STALE_SECONDS = 15.0
    LIVE_STATE_TTL_SECONDS = 0.1
    FAST_ACQUIRE_WINDOW_SECONDS = 20.0
    DJI_FAST_ACQUIRE_WIFI_CHANNELS = [149, 153, 157, 161]
    DJI_FOCUSED_WIFI_CHANNELS = [149, 153, 157, 161, 165, 36, 40, 44, 48, 1, 6, 11]
    SCAN_PROFILES = {
        "passive_quick": {"label": "Passive Quick", "duration_seconds": 45},
        "passive_standard": {"label": "Passive Standard", "duration_seconds": 90},
        "passive_deep": {"label": "Passive Deep", "duration_seconds": 180},
        "dji_focus": {"label": "DJI Focus", "duration_seconds": 120},
    }
    DJI_SSID_TOKENS = ("dji", "neo", "avic", "mavic", "mini", "phantom", "inspire", "air ")
    REMOTE_ID_TOKENS = ("rid", "remote id", "opendroneid", "uas", "uav", "drone", "astm")
    NON_DRONE_WIFI_TOKENS = ("movistar", "vodafone", "orange", "router", "ap", "iphone", "android", "samsung", "galaxy", "printer", "tv", "chromecast", "laptop", "windows")
    VENDOR_TOKENS = {
        "dji": "DJI Family",
        "parrot": "Parrot Family",
        "autel": "Autel Family",
        "skydio": "Skydio Family",
    }

    def __init__(self, runtime=None) -> None:
        self.runtime = runtime
        self.root_dir = Path(__file__).resolve().parents[2]
        self.evidence_root = self.root_dir / "evidence" / "hunt_drones"
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.signature_memory_path = self.root_dir / "logs" / "hunt_drones" / "signature_memory.json"

        self.active = False
        self.session_id = ""
        self.session_name = ""
        self.session_metadata: Dict[str, Any] = {}
        self.session_dir: Path | None = None
        self.started_at: float | None = None
        self.last_scan_at: float | None = None
        self.last_error = ""
        self.retention_mode = self.DEFAULT_RETENTION_MODE
        self.events: List[Dict[str, Any]] = []
        self.operator_log: List[Dict[str, Any]] = []
        self.detections: List[Dict[str, Any]] = []
        self.topology: Dict[str, Any] = {"nodes": [], "edges": []}
        self.reports: List[Dict[str, Any]] = []
        self.evidence_summary: Dict[str, Any] = {"bundles": [], "counts": {}}
        self.environment_baseline: Dict[str, Any] = {}
        self.replay_state: Dict[str, Any] = {}
        self.live_leads: List[Dict[str, Any]] = []
        self.assurance_state: Dict[str, Any] = {
            "leads": [],
            "anomalies_wifi": [],
            "anomalies_sdr": [],
            "band_attention": [],
            "scheduler_actions": [],
            "fusion_windows": [],
            "raw_filtered_counts": {},
            "sensor_sync": {"status": "idle"},
        }
        self._hardware_cache: Dict[str, Any] = {"timestamp": 0.0, "value": {}}
        self._live_state_cache: Dict[str, Any] = {"timestamp": 0.0, "value": {}}
        self._audit_thread: threading.Thread | None = None
        self._audit_lock = threading.Lock()
        self._audit_requested_at: float | None = None

        self.receive_only_guard = ReceiveOnlyGuard()
        self.tool_policy = ToolCapabilityPolicy(self.receive_only_guard)
        self.research_gate = ResearchFeatureGate()
        self.settings_enforcer = SettingsSafetyEnforcer(self.receive_only_guard, self.tool_policy, self.research_gate)

        self.proof_tier_engine = ProofTierEngine()
        self.confidence_engine = ConfidenceScoringEngine()
        self.dss_engine = DisruptionSusceptibilityEngine()
        self.suppression_engine = FalsePositiveSuppressionEngine()
        self.fusion_engine = TargetFusionEngine()
        self.swarm_engine = SwarmGroupingEngine()
        self.topology_builder = TopologyGraphBuilder()
        self.report_builder = ReportBuilder()
        self.assurance_engine = DetectionAssuranceEngine()
        self.burst_lock_engine = SDRBurstLockEngine()
        self.uav_enrichment = AdditiveUAVEnrichmentService()

        self.opendroneid = OpenDroneIDAdapter(self.root_dir)
        self.dji_droneid = DJIDroneIDAdapter()
        self.replay_manager = ReplayManager(self.evidence_root)
        self.settings = self.settings_enforcer.build_settings(self.SCAN_PROFILES)
        self.scan_state = self._blank_scan_state()
        self.signature_memory = self._load_signature_memory()

    def _blank_scan_state(self) -> Dict[str, Any]:
        return {
            "active": False,
            "started_at": None,
            "target_seconds": 300,
            "phase": "idle",
            "profile": "passive_standard",
            "sdr_profiles_started": [],
            "sdr_profiles_completed": [],
            "sdr_candidates": [],
            "current_sdr_profile": "",
            "last_sdr_profile": "",
            "correlation_runs": 0,
            "finalized": False,
            "lead_detected": False,
            "audit_started": False,
            "stopped_by_operator": False,
        }

    def _retention_enabled(self) -> bool:
        return self.retention_mode == "persistent"

    def _load_signature_memory(self) -> Dict[str, Dict[str, Any]]:
        try:
            if self.signature_memory_path.exists():
                loaded = json.loads(self.signature_memory_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    return {str(key): dict(value or {}) for key, value in loaded.items()}
        except Exception:
            pass
        return {}

    def _save_signature_memory(self) -> None:
        try:
            self.signature_memory_path.parent.mkdir(parents=True, exist_ok=True)
            self.signature_memory_path.write_text(json.dumps(self.signature_memory, indent=2, sort_keys=True), encoding="utf-8")
        except Exception:
            pass

    def _sdr_signature_key(self, item: Dict[str, Any], profile_key: str = "") -> str:
        peak_mhz = float(item.get("peak_mhz") or 0.0)
        rounded_bucket = int(round(peak_mhz / 5.0) * 5.0) if peak_mhz else 0
        band = "5.8" if peak_mhz >= 5000.0 else "2.4"
        family = str(item.get("family") or "unknown").strip().lower().replace(" ", "_")
        profile = str(profile_key or item.get("profile_key") or "unknown").strip().lower()
        return f"{band}|{rounded_bucket}|{profile}|{family}"

    def _remember_sdr_signature(self, item: Dict[str, Any], profile_key: str = "") -> Dict[str, Any]:
        key = self._sdr_signature_key(item, profile_key)
        now = self._now()
        bucket = dict(self.signature_memory.get(key) or {})
        bucket["sightings"] = int(bucket.get("sightings") or 0) + 1
        bucket["last_seen"] = now
        bucket["peak_db"] = max(float(bucket.get("peak_db") or -120.0), float(item.get("peak_db") or -120.0))
        bucket["peak_mhz"] = float(item.get("peak_mhz") or bucket.get("peak_mhz") or 0.0)
        bucket["profile_key"] = str(profile_key or item.get("profile_key") or bucket.get("profile_key") or "")
        bucket["family"] = str(item.get("family") or bucket.get("family") or "Unknown Family")
        self.signature_memory[key] = bucket
        self._save_signature_memory()
        return bucket

    def _sdr_signature_profile(self, item: Dict[str, Any]) -> Dict[str, Any]:
        key = self._sdr_signature_key(item, str(item.get("profile_key") or ""))
        bucket = dict(self.signature_memory.get(key) or {})
        if not bucket:
            return {"sightings": 0, "recent": False, "confidence_boost": 0}
        age_seconds = max(0.0, self._now() - float(bucket.get("last_seen") or 0.0))
        sightings = int(bucket.get("sightings") or 0)
        recent = age_seconds <= 900.0
        confidence_boost = 0
        if recent and sightings >= 2:
            confidence_boost = 6
        if recent and sightings >= 4:
            confidence_boost = 10
        return {
            **bucket,
            "sightings": sightings,
            "recent": recent,
            "confidence_boost": confidence_boost,
        }

    def _detection_last_seen(self, item: Dict[str, Any]) -> float:
        last_seen = float(item.get("last_seen") or 0.0)
        if last_seen:
            return last_seen
        evidence = list(item.get("evidence") or [])
        timestamps = [float(entry.get("timestamp") or 0.0) for entry in evidence if entry.get("timestamp")]
        return max(timestamps) if timestamps else 0.0

    def _is_detection_fresh(self, item: Dict[str, Any]) -> bool:
        if self._retention_enabled():
            return True
        last_seen = self._detection_last_seen(item)
        if not last_seen:
            return False
        age = max(0.0, self._now() - last_seen)
        sensors = set(item.get("sensor_sources") or item.get("evidence_sensors") or [])
        if sensors == {"sdr"}:
            return age <= self.SDR_TARGET_STALE_SECONDS
        return age <= self.GENERAL_TARGET_STALE_SECONDS

    def _prune_runtime_truth(self) -> None:
        if self._retention_enabled():
            return
        self.detections = [item for item in self.detections if self._is_detection_fresh(item)]
        self.live_leads = [item for item in self.live_leads if self._is_detection_fresh(item)]
        self.scan_state["sdr_candidates"] = [
            item for item in (self.scan_state.get("sdr_candidates") or [])
            if self._is_current_sdr_candidate(item)
        ]
        fresh_assurance_leads = []
        for lead in self.assurance_state.get("leads") or []:
            last_seen = float(lead.get("last_seen") or 0.0)
            if last_seen and (self._now() - last_seen) <= self.SDR_TARGET_STALE_SECONDS:
                fresh_assurance_leads.append(lead)
        self.assurance_state["leads"] = fresh_assurance_leads

    def _now(self) -> float:
        return time.time()

    def _session_armed(self) -> bool:
        return bool(self.session_id and self.session_dir and not bool(self.scan_state.get("stopped_by_operator")))

    def _fast_acquire_active(self) -> bool:
        if self.scan_state.get("lead_detected"):
            return False
        started_at = float(self.scan_state.get("started_at") or self.started_at or 0.0)
        if not started_at:
            return True
        return (self._now() - started_at) <= self.FAST_ACQUIRE_WINDOW_SECONDS

    def _preferred_dji_wifi_channels(self) -> List[int]:
        channel_pool = self.DJI_FAST_ACQUIRE_WIFI_CHANNELS if self._fast_acquire_active() else self.DJI_FOCUSED_WIFI_CHANNELS
        scores: Dict[int, float] = {int(channel): 0.0 for channel in channel_pool}
        for channel, count in dict(self.environment_baseline.get("common_channel_occupancy") or {}).items():
            try:
                normalized = int(channel)
            except Exception:
                continue
            if normalized in scores:
                scores[normalized] += float(count or 0) * 10.0
        for item in [*(self.detections or []), *(self.live_leads or [])]:
            try:
                normalized = int(item.get("channel") or 0)
            except Exception:
                normalized = 0
            if normalized in scores:
                scores[normalized] += 50.0
        ranked = sorted(
            channel_pool,
            key=lambda channel: (-scores.get(int(channel), 0.0), channel_pool.index(int(channel))),
        )
        return [int(channel) for channel in ranked]

    def _ensure_detection_runtime(self) -> None:
        if not self._session_armed():
            return
        self.active = True
        wifi_manager = getattr(self.runtime, "wifi_mk7", None) if self.runtime else None
        if wifi_manager is not None:
            try:
                preferred_channels = self._preferred_dji_wifi_channels()
                fast_acquire = self._fast_acquire_active()
                current_mode = str(getattr(wifi_manager, "scan_mode", "") or "")
                current_locked = [int(channel) for channel in (getattr(wifi_manager, "scan_locked_channels", []) or [])]
                focused_profile = str(self.session_metadata.get("scan_profile") or "") == "dji_focus"
                needs_focus_realign = focused_profile and (
                    current_mode != "adaptive"
                    or current_locked != preferred_channels
                )
                if bool(wifi_manager._effective_capture_active()) and not needs_focus_realign:
                    return
                if bool(wifi_manager._effective_capture_active()) and needs_focus_realign:
                    try:
                        wifi_manager.stop()
                    except Exception:
                        pass
                result = wifi_manager.start(
                    auto_scan=True,
                    bands=["5ghz"] if fast_acquire else ["2.4ghz", "5ghz"],
                    dwell_ms=100 if fast_acquire else 160,
                    duration_seconds=86400,
                    scan_mode="adaptive",
                    scan_scenario="passive_observation",
                    locked_channels=preferred_channels,
                    deep_packet_enrichment=False,
                    camera_hunt=False,
                    processing_enabled=False,
                )
                if str(result.get("status") or "") in {"started", "started_and_scanning", "armed"}:
                    self._append_event(
                        "scan",
                        "Hunt Drones watchdog aligned MK7AC passive capture to the DJI-focused plan.",
                        {"status": result.get("status"), "locked_channels": preferred_channels, "fast_acquire": fast_acquire},
                    )
                    self._append_operator_log(
                        "Watchdog aligned MK7AC passive capture to DJI-focused channels."
                        if not fast_acquire else
                        "Watchdog switched MK7AC into DJI fast-acquire on 5 GHz channels.",
                        action="scan",
                    )
            except Exception as exc:
                self.last_error = str(exc)

    def _safe_session_slug(self, value: str) -> str:
        text = "".join(ch.lower() if ch.isalnum() else "_" for ch in str(value or "").strip())
        text = "_".join(part for part in text.split("_") if part)
        return text[:48] or "hunt_drones_session"

    def _append_event(self, category: str, message: str, details: Dict[str, Any] | None = None, severity: str = "info") -> None:
        event = {"timestamp": self._now(), "category": category, "message": message, "severity": severity, "details": details or {}}
        self.events.append(event)
        self.events = self.events[-300:]

    def _append_operator_log(self, message: str, action: str = "system") -> None:
        item = {"timestamp": self._now(), "action": action, "message": message}
        self.operator_log.append(item)
        self.operator_log = self.operator_log[-200:]

    def _hardware_status(self) -> Dict[str, Any]:
        cache_age = self._now() - float(self._hardware_cache.get("timestamp") or 0.0)
        if cache_age < 5.0 and self._hardware_cache.get("value"):
            return dict(self._hardware_cache["value"])
        hackrf_connected = False
        hackrf_detail = "HackRF unavailable."
        try:
            result = subprocess.run(["hackrf_info"], capture_output=True, text=True, timeout=4, check=False)
            hackrf_connected = result.returncode == 0
            hackrf_detail = "HackRF detected." if hackrf_connected else (result.stderr.strip() or hackrf_detail)
        except Exception as exc:
            hackrf_detail = str(exc)

        wifi_adapter = {"detected": False, "detail": "WiFi hunt adapter unavailable.", "interface": ""}
        wifi_manager = getattr(self.runtime, "wifi_mk7", None) if self.runtime else None
        if wifi_manager is not None:
            try:
                wifi_status = wifi_manager.get_status(prepare=True)
                adapter = (wifi_status or {}).get("adapter") or {}
                wifi_adapter = {
                    "detected": bool(adapter.get("detected")),
                    "detail": adapter.get("detail") or "WiFi monitor path unknown.",
                    "interface": adapter.get("monitor_interface") or adapter.get("base_interface") or "",
                    "bands": adapter.get("bands") or [],
                }
            except Exception as exc:
                wifi_adapter = {"detected": False, "detail": str(exc), "interface": ""}

        ble_ready = False
        ble_detail = "BLE NR5 controller unavailable."
        ble_manager = getattr(self.runtime, "ble_nr5", None) if self.runtime else None
        if ble_manager is not None:
            try:
                ble_status = ble_manager.get_status()
                ble_ready = bool(ble_status.get("sensor_ready"))
                ble_detail = ble_status.get("status") or ble_status.get("last_error") or "BLE sensor status available."
            except Exception as exc:
                ble_detail = str(exc)
        status = {
            "hackrf": {"connected": hackrf_connected, "detail": hackrf_detail},
            "mk7ac": wifi_adapter,
            "ble_nr5": {"connected": ble_ready, "detail": ble_detail},
            "passive_only_locked": True,
        }
        self._hardware_cache = {"timestamp": self._now(), "value": status}
        return status

    def _wifi_runtime_snapshot(self) -> Dict[str, Any]:
        wifi_manager = getattr(self.runtime, "wifi_mk7", None) if self.runtime else None
        if wifi_manager is None:
            return {
                "capture_active": False,
                "armed": False,
                "current_channel": None,
                "channels_state": "idle",
                "coverage_summary": "Wi-Fi MK7 unavailable.",
                "coverage_level": "UNKNOWN",
                "network_count": 0,
                "client_count": 0,
                "pcap_count": 0,
                "progress_percent": 0.0,
                "elapsed_seconds": 0.0,
                "target_seconds": 0,
                "scan_mode": "idle",
            }
        tracker = getattr(wifi_manager, "tracker", None)
        channels = wifi_manager.get_channels() if hasattr(wifi_manager, "get_channels") else {}
        audit = tracker.get_observation_audit() if tracker and hasattr(tracker, "get_observation_audit") else {}
        scan_payload = wifi_manager._scan_status_payload() if hasattr(wifi_manager, "_scan_status_payload") else {}
        pcap_inventory = wifi_manager.get_pcap_inventory() if hasattr(wifi_manager, "get_pcap_inventory") else []
        networks = tracker.get_networks() if tracker and hasattr(tracker, "get_networks") else []
        clients = tracker.get_clients() if tracker and hasattr(tracker, "get_clients") else []
        coverage_confidence = (channels or {}).get("coverage_confidence") or {}
        return {
            "capture_active": bool(wifi_manager._effective_capture_active()) if hasattr(wifi_manager, "_effective_capture_active") else False,
            "armed": bool(getattr(wifi_manager, "armed", False)),
            "current_channel": (channels or {}).get("current_channel"),
            "channels_state": (channels or {}).get("state") or "idle",
            "locked_channels": list((channels or {}).get("locked_channels") or []),
            "coverage_summary": coverage_confidence.get("summary") or "Coverage summary unavailable.",
            "coverage_level": coverage_confidence.get("level") or "UNKNOWN",
            "network_count": len(networks),
            "client_count": len(clients),
            "pcap_count": len(pcap_inventory),
            "progress_percent": float((scan_payload or {}).get("progress_percent") or 0.0),
            "elapsed_seconds": float((scan_payload or {}).get("elapsed_seconds") or 0.0),
            "target_seconds": int((scan_payload or {}).get("target_seconds") or 0),
            "scan_mode": str((scan_payload or {}).get("mode") or "broad"),
            "top_ssids": [entry.get("ssid") for entry in (audit.get("top_ssids") or [])[:4] if entry.get("ssid")],
        }

    def _family_label(self, ssid: str, vendor: str, identifier: str) -> str:
        lowered = f"{ssid} {vendor} {identifier}".lower()
        for token, label in self.VENDOR_TOKENS.items():
            if token in lowered:
                return label
        if any(token in lowered for token in self.REMOTE_ID_TOKENS):
            return "Remote ID Family"
        return "Unknown Family"

    def _classify_target_class(self, item: Dict[str, Any], proof_tier: int) -> str:
        family = str(item.get("family_label") or "").lower()
        model = str(item.get("model_family") or "").lower()
        if "remote id" in model and proof_tier >= 3:
            return "Confirmed Remote ID Drone"
        if "remote id" in model:
            return "Probable Remote ID Drone"
        if "dji" in family and proof_tier >= 2:
            return "DJI-family Decoder-backed Candidate"
        if "dji" in family:
            return "DJI-family RF Candidate"
        if str(item.get("target_type") or "") == "controller":
            return "Controller / Ground Station Candidate"
        if str(item.get("target_type") or "") == "non_drone":
            return "Baseline Environmental Device"
        if proof_tier == 0:
            return "Unknown Aerial RF Source"
        return "Wi-Fi Drone Candidate"

    def _rf_candidate_surface(self, channel: Any, profile: str) -> Dict[str, Any]:
        channel_int = int(channel or 0) if str(channel or "").isdigit() else 0
        high_band = channel_int in {36, 40, 44, 48, 149, 153, 157, 161, 165}
        if profile == "dji_focus" and high_band:
            return {"band_hint": "5.8 GHz", "rf_visibility": "Candidate DJI-family band activity window", "sensors": ["wifi"]}
        if channel_int in {1, 6, 11}:
            return {"band_hint": "2.4 GHz", "rf_visibility": "2.4 GHz passive Wi-Fi detection surface", "sensors": ["wifi"]}
        return {"band_hint": "2.4/5 GHz", "rf_visibility": "Pending SDR sweep correlation", "sensors": ["wifi"]}

    def _classify_wifi_observation(self, item: Dict[str, Any], profile: str) -> Dict[str, Any]:
        ssid = str(item.get("ssid") or "").strip()
        vendor = str(item.get("vendor") or item.get("oui_vendor") or "").strip()
        mac = str(item.get("bssid") or item.get("mac") or item.get("associated_bssid") or "").strip().lower()
        rssi = int(item.get("rssi_dbm") or -95)
        channel = item.get("channel")
        packet_count = int(item.get("packet_count") or 0)
        reasons: List[str] = []
        classification = "Unknown Aerial RF Source"
        target_type = "unknown_aerial"
        if any(token in ssid.lower() for token in self.DJI_SSID_TOKENS) or "dji" in vendor.lower():
            classification = "Probable Drone"
            target_type = "probable_drone"
            reasons.append("DJI-family Wi-Fi identity evidence retained.")
        if any(token in ssid.lower() for token in self.REMOTE_ID_TOKENS):
            classification = "Probable Drone"
            target_type = "probable_drone"
            reasons.append("SSID or naming indicates standards-based identity markers.")
        if item.get("inventory_kind") == "client" and item.get("associated_bssid"):
            classification = "Controller / Ground Station"
            target_type = "controller"
            reasons.append("Client-side control relationship candidate.")
        if packet_count >= 3:
            reasons.append("Repeated Wi-Fi management recurrence retained.")
        if rssi >= -62:
            reasons.append("Strong local RSSI retained.")
        if profile == "dji_focus" and channel in {36, 40, 44, 48, 149, 153, 157, 161}:
            reasons.append("Observed inside DJI-focused passive band windows.")
        rf_surface = self._rf_candidate_surface(channel, profile)
        target_id = hashlib.sha1(f"{ssid}|{vendor}|{mac}|{channel}".encode("utf-8")).hexdigest()[:12]
        return {
            "target_id": f"drone-{target_id}",
            "label": ssid or vendor or mac or "Observed Wi-Fi Source",
            "classification": classification,
            "target_type": target_type,
            "manufacturer": vendor or "Unknown",
            "model_family": "Wi-Fi broadcast source",
            "identifier": mac or "--",
            "family_label": self._family_label(ssid, vendor, mac),
            "band": rf_surface["band_hint"],
            "channel": channel or "--",
            "rssi_dbm": rssi,
            "packet_count": packet_count,
            "sensor_sources": ["wifi"],
            "evidence_sensors": ["wifi"],
            "reasons": reasons or ["Passive Wi-Fi observation retained."],
            "wifi": {"ssid": ssid or "<hidden>", "bssid": mac or "--", "channel": channel or "--", "rssi_dbm": rssi, "security": item.get("security") or "--"},
            "rf": {"sweep_status": rf_surface["rf_visibility"], "bands_seen": [rf_surface["band_hint"]]},
            "evidence": [{"artifact_type": "wifi_observation", "sensor": "wifi", "reference": "wifi/management_frames.jsonl", "timestamp": self._now()}],
            "first_seen": self._now(),
            "last_seen": self._now(),
        }

    def _is_drone_wifi_observation(self, item: Dict[str, Any]) -> bool:
        ssid = str(item.get("ssid") or "").strip().lower()
        vendor = str(item.get("vendor") or item.get("oui_vendor") or item.get("manufacturer") or "").strip().lower()
        channel = int(item.get("channel") or 0) if str(item.get("channel") or "").isdigit() else 0
        packet_count = int(item.get("packet_count") or 0)
        rssi = int(item.get("rssi_dbm") or -95)
        enrichment_score = float(((item.get("uav_enrichment") or {}).get("score") or 0.0))
        controller_like = bool(item.get("associated_bssid"))
        ssid_has_dji_hint = any(token in ssid for token in self.DJI_SSID_TOKENS)
        vendor_has_dji_hint = "dji" in vendor
        has_remote_id_hint = any(token in ssid or token in vendor for token in self.REMOTE_ID_TOKENS)
        high_band_candidate = channel in {36, 40, 44, 48, 149, 153, 157, 161, 165}
        combined = f"{ssid} {vendor}".strip()
        if not combined:
            return enrichment_score >= 14 or (high_band_candidate and packet_count >= 8 and rssi >= -78)
        if has_remote_id_hint:
            return True
        if ssid_has_dji_hint:
            return True
        if vendor_has_dji_hint:
            return controller_like or enrichment_score >= 22 or (high_band_candidate and packet_count >= 6 and rssi >= -72)
        if any(token in combined for token in self.NON_DRONE_WIFI_TOKENS):
            return enrichment_score >= 28
        # Permit strong, non-infrastructure 5 GHz control/video observations as live leads.
        if high_band_candidate and packet_count >= 8 and rssi >= -78:
            return True
        return enrichment_score >= 20

    def _is_current_sdr_candidate(self, item: Dict[str, Any]) -> bool:
        if not self.started_at:
            return False
        timestamp = float(item.get("timestamp") or 0.0)
        if timestamp and timestamp < float(self.started_at):
            return False
        age_seconds = max(0.0, self._now() - timestamp) if timestamp else 9999.0
        return age_seconds <= self.SDR_TARGET_STALE_SECONDS

    def _classify_sdr_observation(self, item: Dict[str, Any]) -> Dict[str, Any]:
        peak_mhz = float(item.get("peak_mhz") or 0.0)
        peak_db = float(item.get("peak_db") or -110.0)
        recurrence = float(item.get("burst_recurrence") or 0.0)
        density = float(item.get("burst_density") or 0.0)
        persistence = float(item.get("rolling_persistence") or 0.0)
        band = "5.8 GHz" if peak_mhz >= 5000.0 else "2.4 GHz"
        family = str(item.get("family") or "Unknown Family")
        profile_key = str(item.get("profile_key") or "")
        memory = self._sdr_signature_profile(item)
        memory_boost = int(memory.get("confidence_boost") or 0)
        repeated_signature = bool(memory.get("recent")) and int(memory.get("sightings") or 0) >= 2
        probable_drone = (
            (peak_db >= -58 and "dji" in family.lower())
            or (profile_key == "drone_58" and peak_db >= -62)
            or (profile_key == "drone_24" and peak_db >= -56)
            or (profile_key in {"drone_58", "drone_24"} and recurrence >= 2 and density >= 0.18)
            or ("5.8" in band and persistence >= 0.18 and peak_db >= -70)
            or (repeated_signature and profile_key == "drone_58" and peak_db >= -68)
            or (repeated_signature and "dji" in family.lower() and peak_db >= -70)
        )
        reasons = ["HackRF retained a drone-band peak cluster."]
        if recurrence >= 2:
            reasons.append("Repeated SDR recurrence retained in the rolling window.")
        if density >= 0.18:
            reasons.append("Burst density elevated above local baseline.")
        if persistence >= 0.18:
            reasons.append("Cluster persistence retained across sweep windows.")
        if repeated_signature:
            reasons.append("Repeated SDR signature retained from prior hunts.")
        return {
            "target_id": f"rf-{str(item.get('row_id') or int(peak_mhz * 10))}",
            "label": f"{band} RF Cluster",
            "classification": "DJI-family RF Candidate" if probable_drone else "Unknown Aerial RF Source",
            "target_type": "probable_drone" if probable_drone else "unknown_aerial",
            "manufacturer": "Unknown",
            "model_family": "Passive RF cluster",
            "identifier": str(item.get("row_id") or f"{peak_mhz:.1f}"),
            "family_label": family,
            "band": band,
            "channel": "--",
            "rssi_dbm": None,
            "packet_count": int(recurrence),
            "sensor_sources": ["sdr"],
            "evidence_sensors": ["sdr"],
            "reasons": reasons,
            "rf": {
                "sweep_status": f"HackRF peak {peak_mhz:.1f} MHz @ {peak_db:.1f} dB",
                "peak_mhz": peak_mhz,
                "peak_db": peak_db,
                "bands_seen": [band],
                "burst_density": density,
                "burst_recurrence": recurrence,
                "rolling_persistence": persistence,
            },
            "evidence": [{"artifact_type": "sdr_peak", "sensor": "sdr", "reference": "sdr/events.jsonl", "timestamp": float(item.get("timestamp") or self._now())}],
            "first_seen": float(item.get("timestamp") or self._now()),
            "last_seen": float(item.get("timestamp") or self._now()),
            "signature_memory": memory,
            "signature_memory_boost": memory_boost,
        }

    def _wifi_observations(self) -> List[Dict[str, Any]]:
        wifi_manager = getattr(self.runtime, "wifi_mk7", None) if self.runtime else None
        if wifi_manager is None:
            return []
        tracker = getattr(wifi_manager, "tracker", None)
        if tracker is None:
            return []
        observations: List[Dict[str, Any]] = []
        try:
            for entry in tracker.get_networks():
                row = self.uav_enrichment.enrich(dict(entry))
                row["inventory_kind"] = "network"
                if self._is_drone_wifi_observation(row):
                    observations.append(row)
            for entry in tracker.get_clients():
                row = self.uav_enrichment.enrich(dict(entry))
                row["inventory_kind"] = "client"
                if self._is_drone_wifi_observation(row):
                    observations.append(row)
        except Exception as exc:
            self.last_error = str(exc)
        return observations

    def _build_sdr_burst_locks(self, sdr_candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self.burst_lock_engine.build_locks(sdr_candidates, now=self._now())

    def _ingest_sdr_state_candidates(self, state: Dict[str, Any], *, profile_key: str = "") -> List[Dict[str, Any]]:
        existing_ids = {str(item.get("row_id") or "") for item in self.scan_state.get("sdr_candidates", [])}
        harvested = list(self.scan_state.get("sdr_candidates") or [])
        current_profile = str(profile_key or state.get("profile_key") or self.scan_state.get("current_sdr_profile") or self.scan_state.get("last_sdr_profile") or "")
        for row in state.get("target_leads") or []:
            row_id = str(row.get("row_id") or "")
            if not row_id or row_id in existing_ids:
                continue
            if not self._is_current_sdr_candidate(row):
                continue
            memory = self._remember_sdr_signature(row, current_profile)
            harvested.append({**row, "profile_key": current_profile, "signature_memory": memory})
            existing_ids.add(row_id)
        self.scan_state["sdr_candidates"] = [item for item in harvested[-32:] if self._is_current_sdr_candidate(item)]
        return list(self.scan_state["sdr_candidates"])

    def _harvest_sdr_candidates(self, state: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        sdr_manager = getattr(self.runtime, "hackrf_sweep", None) if self.runtime else None
        if sdr_manager is None:
            return []
        try:
            state = state or sdr_manager.get_state()
        except Exception as exc:
            self.last_error = str(exc)
            return []
        return self._ingest_sdr_state_candidates(state)

    def _advance_sdr_pipeline(self) -> Dict[str, Any]:
        sdr_manager = getattr(self.runtime, "hackrf_sweep", None) if self.runtime else None
        if sdr_manager is None:
            return {"installed": False, "running": False, "status_detail": "unavailable"}
        try:
            state = sdr_manager.get_state()
        except Exception as exc:
            self.last_error = str(exc)
            return {"installed": True, "running": False, "status_detail": "error", "last_error": str(exc)}
        current_profile = str(self.scan_state.get("current_sdr_profile") or "")
        self._ingest_sdr_state_candidates(state, profile_key=current_profile or str(state.get("profile_key") or ""))
        if current_profile and state.get("completed") and current_profile not in self.scan_state["sdr_profiles_completed"]:
            self.scan_state["sdr_profiles_completed"].append(current_profile)
            self.scan_state["current_sdr_profile"] = ""
        if not state.get("running"):
            profile_order = ("drone_58", "drone_24") if str(self.session_metadata.get("scan_profile") or "") == "dji_focus" else ("drone_24", "drone_58")
            completed = list(self.scan_state.get("sdr_profiles_completed") or [])
            next_profile = ""
            for profile_key in profile_order:
                if profile_key not in completed:
                    next_profile = profile_key
                    break
            if not next_profile:
                last_profile = str(self.scan_state.get("last_sdr_profile") or "")
                if last_profile in profile_order and len(profile_order) > 1:
                    last_index = profile_order.index(last_profile)
                    next_profile = profile_order[(last_index + 1) % len(profile_order)]
                else:
                    next_profile = profile_order[0]
                self.scan_state["sdr_profiles_completed"] = []
            result = sdr_manager.start(next_profile)
            if result.get("status") == "started":
                if next_profile not in self.scan_state["sdr_profiles_started"]:
                    self.scan_state["sdr_profiles_started"].append(next_profile)
                self.scan_state["current_sdr_profile"] = next_profile
                self.scan_state["last_sdr_profile"] = next_profile
                state = sdr_manager.get_state()
        return state

    def _collect_decoder_manifests(self, observations: List[Dict[str, Any]], sdr_candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        wifi_manager = getattr(self.runtime, "wifi_mk7", None) if self.runtime else None
        tshark_path = ""
        pcap_inventory: List[Dict[str, Any]] = []
        if wifi_manager is not None:
            tshark_path = str(getattr(getattr(wifi_manager, "capture", None), "tshark_path", "") or "")
            try:
                pcap_inventory = wifi_manager.get_pcap_inventory()
            except Exception:
                pcap_inventory = []
        burst_locks = self._build_sdr_burst_locks(sdr_candidates)
        return {
            "remote_id": self.opendroneid.decode(observations, pcap_inventory, tshark_path=tshark_path),
            "dji": self.dji_droneid.decode(sdr_candidates, burst_locks=burst_locks),
            "kismet_like_enrichment": {
                "items": [
                    {
                        "identifier": str(item.get("bssid") or item.get("mac") or ""),
                        "family_label": ((item.get("uav_enrichment") or {}).get("family_label") or ""),
                        "score": ((item.get("uav_enrichment") or {}).get("score") or 0),
                        "hints": ((item.get("uav_enrichment") or {}).get("hints") or []),
                        "source": "additive_uav_enrichment",
                    }
                    for item in observations
                    if (item.get("uav_enrichment") or {}).get("score")
                ][:64],
            },
        }

    def _base_detection_set(self, observations: List[Dict[str, Any]], sdr_candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        profile = str(self.session_metadata.get("scan_profile") or "passive_standard")
        detections = [self._classify_wifi_observation(item, profile) for item in observations]
        detections.extend(
            self._classify_sdr_observation(item)
            for item in sdr_candidates
            if self._is_current_sdr_candidate(item)
        )
        return detections

    def _apply_decoder_manifests(self, detections: List[Dict[str, Any]], manifests: Dict[str, Any]) -> List[Dict[str, Any]]:
        merged = list(detections)
        by_identifier = {str(item.get("identifier") or ""): item for item in merged}
        for target in manifests.get("remote_id", {}).get("targets") or []:
            identifier = str(target.get("identifier") or "")
            existing = by_identifier.get(identifier)
            if existing:
                existing["model_family"] = target.get("model_family") or existing.get("model_family")
                existing["manufacturer"] = target.get("manufacturer") or existing.get("manufacturer")
                existing["family_label"] = target.get("family_label") or existing.get("family_label")
                existing["decoder"] = target.get("decoder")
                existing["reasons"] = list(dict.fromkeys([*(existing.get("reasons") or []), *(target.get("reasons") or [])]))
                existing["evidence"].extend(target.get("evidence") or [])
            else:
                merged.append({**target, "band": "2.4/5 GHz", "channel": "--", "sensor_sources": ["wifi"], "evidence_sensors": ["wifi"], "rf": {"sweep_status": "Awaiting SDR correlation", "bands_seen": ["2.4 GHz", "5 GHz"]}, "first_seen": self._now(), "last_seen": self._now()})
        dji_targets = list(manifests.get("dji", {}).get("targets") or [])
        if dji_targets:
            for item in merged:
                if "sdr" not in (item.get("sensor_sources") or []) and str(item.get("band") or "").startswith("5.8"):
                    item["sensor_sources"] = list(dict.fromkeys([*(item.get("sensor_sources") or []), "sdr"]))
                    item["evidence_sensors"] = list(dict.fromkeys([*(item.get("evidence_sensors") or []), "sdr"]))
                    item["reasons"] = list(dict.fromkeys([*(item.get("reasons") or []), "Cross-sensor band alignment retained."]))
        merged.extend(dji_targets)
        for enrichment in manifests.get("kismet_like_enrichment", {}).get("items") or []:
            identifier = str(enrichment.get("identifier") or "")
            if not identifier:
                continue
            existing = by_identifier.get(identifier)
            if not existing:
                continue
            if enrichment.get("family_label") and not existing.get("family_label"):
                existing["family_label"] = enrichment.get("family_label")
            hints = list(enrichment.get("hints") or [])
            if hints:
                existing["reasons"] = list(dict.fromkeys([*(existing.get("reasons") or []), *hints]))
                existing["evidence"] = list(existing.get("evidence") or [])
                existing["evidence"].append(
                    {
                        "artifact_type": "uav_enrichment",
                        "sensor": "wifi",
                        "reference": "wifi/oui_enrichment.json",
                        "timestamp": self._now(),
                    }
                )
        return merged

    def _score_detection(self, item: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        evidence = list(item.get("evidence") or [])
        reasons = list(item.get("reasons") or [])
        sensor_sources = list(dict.fromkeys(item.get("sensor_sources") or item.get("evidence_sensors") or []))
        remote_id_hits = any("remote_id" in str(entry.get("artifact_type") or "") for entry in evidence) or "remote id" in str(item.get("model_family") or "").lower()
        dji_hits = "dji" in str(item.get("family_label") or "").lower() or "dji" in str(item.get("manufacturer") or "").lower()
        features = {
            "wifi_signature_score": 12 if "wifi" in sensor_sources else 0,
            "vendor_score": 8 if item.get("manufacturer") and item.get("manufacturer") != "Unknown" else 0,
            "remote_id_score": 18 if remote_id_hits else 0,
            "dji_score": 14 if dji_hits else 0,
            "sdr_score": 8 if "sdr" in sensor_sources else 0,
            "signature_memory_score": int(item.get("signature_memory_boost") or 0),
            "recurrence_score": min(8, int(item.get("packet_count") or 0)),
            "stability_score": 6 if int(item.get("packet_count") or 0) >= 3 else 2,
            "band_consistency_score": 4 if len(set(item.get("rf", {}).get("bands_seen") or [])) <= 1 else 6,
            "sensor_score": 8 if len(sensor_sources) >= 2 else 2,
            "baseline_anomaly_score": 4 if str(item.get("classification") or "").lower() != "non-drone wi-fi / non-drone rf" else 0,
            "decoder_backed": bool(remote_id_hits or (item.get("decoder") or {}).get("name") in {"OpenDroneID Adapter", "DJI DroneID RF Adapter"}),
            "multi_sensor": len(sensor_sources) >= 2,
            "replayable": bool(evidence),
            "raw_evidence_complete": any(str(entry.get("reference") or "").endswith(".jsonl") or "/" in str(entry.get("reference") or "") for entry in evidence),
            "recurrence_count": int(item.get("packet_count") or 0),
            "temporal_stability": 0.7 if int(item.get("packet_count") or 0) >= 3 else 0.25,
            "rationale": reasons,
            "enough_audit_evidence": bool(evidence),
            "multi_band": len(set(item.get("rf", {}).get("bands_seen") or [])) > 1,
            "signal_margin_db": max(0.0, float((item.get("rssi_dbm") or -85) - baseline.get("noise_floor_hint_db", -92))),
            "dropout_ratio": 0.05 if int(item.get("packet_count") or 0) >= 4 else 0.2,
            "fallback_observed": remote_id_hits or len(sensor_sources) >= 2,
        }
        suppression = self.suppression_engine.evaluate(item, baseline)
        proof_tier = self.proof_tier_engine.assign(features)
        confidence = self.confidence_engine.score(features, suppression, proof_tier)
        dss = self.dss_engine.score(features)
        return {
            **item,
            "sensor_sources": sensor_sources,
            "proof_tier": proof_tier,
            "proof_level": proof_tier["label"],
            "confidence": confidence["score"],
            "confidence_score": confidence,
            "disruption_susceptibility": dss,
            "suppression": suppression,
            "target_class": self._classify_target_class(item, int(proof_tier["tier"])),
            "decoder_diagnostics": {"name": (item.get("decoder") or {}).get("name") or "Heuristic Classifier", "status": (item.get("decoder") or {}).get("status") or ("decoded" if proof_tier["tier"] >= 2 else "candidate"), "rationale": (item.get("decoder") or {}).get("rationale") or []},
            "rationale_graph": {"evidence": [entry.get("artifact_type") for entry in evidence], "confidence_rationale": confidence["rationale"], "dss_rationale": dss["rationale"]},
            "evidence_bundle": {"first_seen": item.get("first_seen"), "last_seen": item.get("last_seen"), "sensor_sources": sensor_sources, "raw_wifi_observation_rows": len([entry for entry in evidence if entry.get("sensor") == "wifi"]), "raw_sdr_sweep_rows": len([entry for entry in evidence if entry.get("sensor") == "sdr"]), "decoder_outputs": [entry.get("artifact_type") for entry in evidence if "decoder" in str(entry.get("artifact_type") or "") or "remote_id" in str(entry.get("artifact_type") or "")], "replay_pointers": [entry.get("reference") for entry in evidence]},
        }

    def _retainable_drone_detection(self, item: Dict[str, Any]) -> bool:
        proof_tier = int((item.get("proof_tier") or {}).get("tier", 0))
        confidence = int((item.get("confidence_score") or {}).get("score", 0))
        family = str(item.get("family_label") or "").lower()
        model = str(item.get("model_family") or "").lower()
        target_type = str(item.get("target_type") or "").lower()
        sensor_sources = set(item.get("sensor_sources") or [])
        has_remote_id = "remote id" in model
        has_dji_family = "dji" in family
        has_sdr = "sdr" in sensor_sources
        has_wifi = "wifi" in sensor_sources
        if has_remote_id and confidence >= 35:
            return True
        if has_dji_family and has_sdr and confidence >= 40:
            return True
        if target_type == "controller" and proof_tier >= 2 and has_wifi and confidence >= 45:
            return True
        return False

    def _build_live_leads(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        live_rows: List[Dict[str, Any]] = []
        for item in detections:
            family = str(item.get("family_label") or "").lower()
            classification = str(item.get("classification") or item.get("target_class") or "").lower()
            model = str(item.get("model_family") or "").lower()
            target_type = str(item.get("target_type") or "").lower()
            sensors = set(item.get("sensor_sources") or [])
            packet_count = int(item.get("packet_count") or 0)
            memory_boost = int(((item.get("signature_memory") or {}).get("confidence_boost")) or item.get("signature_memory_boost") or 0)
            rssi = int(item.get("rssi_dbm") or -95) if item.get("rssi_dbm") is not None else -95
            channel = int(item.get("channel") or 0) if str(item.get("channel") or "").isdigit() else 0
            high_band_candidate = channel in {36, 40, 44, 48, 149, 153, 157, 161, 165}
            has_remote_id = "remote id" in model
            dji_rf_correlated = "dji" in family and "sdr" in sensors
            strong_wifi_controller = target_type == "controller" and packet_count >= 6 and rssi >= -72 and high_band_candidate
            strong_wifi_drone = target_type == "probable_drone" and packet_count >= 8 and rssi >= -68 and high_band_candidate
            strong_sdr_drone = (
                target_type == "probable_drone"
                and "sdr" in sensors
                and (
                    "dji-family" in classification
                    or "dji" in family
                    or str(item.get("band") or "").startswith("5.8")
                    or packet_count >= 2
                    or memory_boost >= 6
                )
            )
            is_drone_lead = has_remote_id or dji_rf_correlated or strong_wifi_controller or strong_wifi_drone or strong_sdr_drone
            if not is_drone_lead:
                continue
            clone = dict(item)
            clone["target_class"] = clone.get("target_class") or clone.get("classification") or "Drone Lead"
            clone["proof_tier"] = clone.get("proof_tier") or {"tier": 0, "label": "Heuristic Lead"}
            live_score = 48 if has_remote_id else (46 if strong_sdr_drone else (44 if dji_rf_correlated else 40))
            live_score = min(72, live_score + memory_boost)
            if memory_boost >= 6:
                clone["reasons"] = list(dict.fromkeys([*(clone.get("reasons") or []), "Prior signature memory accelerated lead promotion."]))
            clone["confidence_score"] = clone.get("confidence_score") or {"score": live_score, "label": "low", "rationale": clone.get("reasons") or ["Live drone lead observed."]}
            clone["disruption_susceptibility"] = clone.get("disruption_susceptibility") or {"label": "Unknown", "rationale": ["Audit pending after initial detection."]}
            clone["live_state"] = "probable_drone" if strong_sdr_drone else "detected"
            live_rows.append(clone)
        return live_rows[:24]

    def _evaluate_assurance(
        self,
        observations: List[Dict[str, Any]],
        sdr_candidates: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        snapshot = self.assurance_engine.evaluate(
            wifi_rows=observations,
            sdr_rows=sdr_candidates,
            baseline=self.environment_baseline or {"noise_floor_hint_db": -92, "common_ssids": []},
            scan_profile=str(self.session_metadata.get("scan_profile") or "passive_standard"),
            now=self._now(),
        )
        self.assurance_state = {
            "leads": snapshot.leads,
            "anomalies_wifi": snapshot.anomalies_wifi,
            "anomalies_sdr": snapshot.anomalies_sdr,
            "band_attention": snapshot.band_attention,
            "scheduler_actions": snapshot.scheduler_actions,
            "fusion_windows": snapshot.fusion_windows,
            "raw_filtered_counts": snapshot.raw_filtered_counts,
            "sensor_sync": snapshot.sensor_sync,
        }
        return self.assurance_state

    def _assurance_leads_to_live_rows(self, assurance: Dict[str, Any]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for lead in assurance.get("leads") or []:
            state = str(lead.get("current_state") or "wifi_anomaly")
            band_focus = str(lead.get("band_focus") or "unknown")
            sensors = list(lead.get("sensor_sources") or [])
            sensor_set = set(sensors)
            decoder_evidence = bool(lead.get("decoder_evidence"))
            correlated = len(sensor_set) >= 2
            promotable_state = state in {"probable_drone", "confirmed_drone_evidence"}
            if not (decoder_evidence or correlated or promotable_state):
                continue
            target_class = {
                "rf_anomaly": "Unknown Aerial RF Source",
                "wifi_anomaly": "Wi-Fi Drone Candidate",
                "weak_drone_candidate": "Wi-Fi Drone Candidate",
                "correlated_drone_candidate": "Probable Drone",
                "probable_drone": "Probable Drone",
                "confirmed_drone_evidence": "Confirmed Drone Evidence",
            }.get(state, "Drone Lead")
            label = {
                "rf_anomaly": f"{band_focus} RF Anomaly",
                "wifi_anomaly": f"{band_focus} Wi-Fi Anomaly",
                "weak_drone_candidate": f"{band_focus} Weak Drone Candidate",
                "correlated_drone_candidate": f"{band_focus} Correlated Drone Candidate",
                "probable_drone": f"{band_focus} Probable Drone",
                "confirmed_drone_evidence": f"{band_focus} Confirmed Drone Evidence",
            }.get(state, "Drone Lead")
            proof_tier = {"tier": 0, "label": "Heuristic Lead"}
            if state == "correlated_drone_candidate":
                proof_tier = {"tier": 1, "label": "Multi-observation Heuristic"}
            elif state == "probable_drone":
                proof_tier = {"tier": 2, "label": "Decoder-backed Candidate" if lead.get("decoder_evidence") else "Correlated Candidate"}
            elif state == "confirmed_drone_evidence":
                proof_tier = {"tier": 3, "label": "Multi-sensor Corroborated"}
            rows.append(
                {
                    "target_id": f"lead-{lead.get('lead_id')}",
                    "label": label,
                    "classification": target_class,
                    "target_class": target_class,
                    "target_type": "probable_drone" if "drone" in state else "unknown_aerial",
                    "family_label": "DJI Family" if "5.8" in band_focus and "sdr" in sensors else "Unknown Family",
                    "manufacturer": "Unknown",
                    "model_family": state.replace("_", " "),
                    "identifier": lead.get("lead_id"),
                    "band": band_focus,
                    "channel": "--",
                    "sensor_sources": sensors,
                    "evidence_sensors": sensors,
                    "reasons": list(lead.get("rationale") or []),
                    "confidence_score": {
                        "score": int(lead.get("confidence") or 0),
                        "label": "medium" if int(lead.get("confidence") or 0) >= 50 else "low",
                        "rationale": list(lead.get("rationale") or []),
                    },
                    "proof_tier": proof_tier,
                    "disruption_susceptibility": {"label": "Unknown", "rationale": ["Audit pending after provisional lead promotion."]},
                    "live_state": state,
                    "scheduler_hints": list(lead.get("scheduler_hints") or []),
                    "assurance_lead": dict(lead),
                    "evidence": [{"artifact_type": "assurance_lead", "sensor": ",".join(sensors), "reference": path, "timestamp": lead.get("last_seen")} for path in (lead.get("evidence_paths") or [])],
                    "first_seen": lead.get("created_at"),
                    "last_seen": lead.get("last_seen"),
                }
            )
        return rows[:24]

    def _compute_live_detection_payload(self) -> Dict[str, Any]:
        wifi_runtime = self._wifi_runtime_snapshot()
        wifi_active = bool(wifi_runtime.get("capture_active"))
        if wifi_active and not self.scan_state.get("active"):
            self.scan_state.update(
                {
                    "active": True,
                    "started_at": self.scan_state.get("started_at") or self._now(),
                    "target_seconds": wifi_runtime.get("target_seconds") or self.SCAN_PROFILES[self.scan_state["profile"]]["duration_seconds"],
                    "phase": "detection",
                }
            )

        sdr_state = self._advance_sdr_pipeline() if self.scan_state.get("active") else {"running": False, "status_detail": "idle"}
        sdr_candidates = self._harvest_sdr_candidates() if self.scan_state.get("active") else []
        observations = self._wifi_observations()
        self.environment_baseline = build_environment_baseline(observations) if observations else (self.environment_baseline or {})
        assurance = self._evaluate_assurance(observations, sdr_candidates)
        base_detections = self._base_detection_set(observations, sdr_candidates)
        assurance_leads = self._assurance_leads_to_live_rows(assurance)
        heuristic_leads = self._build_live_leads(base_detections)
        self.live_leads = (assurance_leads or heuristic_leads)[:24]
        if self.live_leads and not self.scan_state.get("lead_detected"):
            self.scan_state["lead_detected"] = True
            self.scan_state["phase"] = "audit"
            self._append_event("detection", "Live drone lead detected.", {"lead_count": len(self.live_leads)})
            self._append_operator_log(f"Live drone lead detected with {len(self.live_leads)} candidate targets.", action="detect")
            self._audit_requested_at = self._now()
            self._start_background_audit()

        hardware = self._hardware_status()
        payload = {
            "ok": True,
            "active": bool(wifi_active or self.scan_state.get("active")),
            "phase": self.scan_state.get("phase") or "idle",
            "lead_detected": bool(self.scan_state.get("lead_detected")),
            "audit_started": bool(self.scan_state.get("audit_started")),
            "live_leads": list(self.live_leads),
            "live_lead_count": len(self.live_leads),
            "assurance": {
                "band_attention": assurance.get("band_attention") or [],
                "sensor_sync": assurance.get("sensor_sync") or {"status": "idle"},
                "scheduler_actions": assurance.get("scheduler_actions") or [],
                "fusion_windows": assurance.get("fusion_windows") or [],
                "raw_filtered_counts": assurance.get("raw_filtered_counts") or {},
                "anomaly_counts": {
                    "wifi": len(assurance.get("anomalies_wifi") or []),
                    "sdr": len(assurance.get("anomalies_sdr") or []),
                },
            },
            "wifi_active": wifi_active,
            "wifi_runtime": wifi_runtime,
            "sdr_state": {
                "running": bool(sdr_state.get("running")),
                "status_detail": sdr_state.get("status_detail") or "idle",
            },
            "scanning_devices": [
                {
                    "name": "Wi-Fi MK7 Adapter",
                    "device": str((((hardware.get("mk7ac") or {}).get("interface")) or "unavailable")),
                    "active": bool(wifi_active),
                    "role": "Drone-only passive Wi-Fi detection",
                },
                {
                    "name": "HackRF SDR",
                    "device": "HackRF One" if (hardware.get("hackrf") or {}).get("connected") else "unavailable",
                    "active": bool(sdr_state.get("running")),
                    "role": "Passive RF sweep and burst lead detection",
                },
            ],
        }
        self._live_state_cache = {"timestamp": self._now(), "value": payload}
        return payload

    def _start_background_audit(self) -> None:
        if self._audit_thread is not None and self._audit_thread.is_alive():
            return

        def _runner() -> None:
            with self._audit_lock:
                try:
                    self.run_passive_scan()
                except Exception as exc:
                    self.last_error = str(exc)
                finally:
                    self._live_state_cache = {"timestamp": 0.0, "value": {}}

        self._audit_thread = threading.Thread(target=_runner, daemon=True)
        self._audit_thread.start()

    def _graph_points(self) -> List[Dict[str, Any]]:
        points: List[Dict[str, Any]] = []
        for item in (self.scan_state.get("sdr_candidates") or [])[-12:]:
            if not self._is_current_sdr_candidate(item):
                continue
            peak_db = float(item.get("peak_db") or -110.0)
            points.append({"row_id": item.get("row_id"), "height": max(12, min(100, int((peak_db + 110.0) * 2.2))), "band": "5.8 GHz" if float(item.get("peak_mhz") or 0.0) >= 5000.0 else "2.4 GHz"})
        return points

    def _scan_phases(self, wifi_active: bool, sdr_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        completed = set(self.scan_state.get("sdr_profiles_completed") or [])
        active_phase = str(self.scan_state.get("phase") or "idle")
        phases: List[Dict[str, Any]] = []
        for key, label in [
            ("initialize", "Initialize Sensors"),
            ("wifi_capture", "MK7AC Passive Capture"),
            ("detection", "Live Drone Detection"),
            ("sdr_24", "HackRF 2.4 GHz Sweep"),
            ("sdr_58", "HackRF 5.8 GHz Sweep"),
            ("audit", "Audit & Scoring"),
            ("finalize", "Evidence Finalize"),
        ]:
            status = "pending"
            if key == "initialize" and self.scan_state.get("active"):
                status = "completed"
            elif key == "wifi_capture":
                status = "active" if wifi_active else ("completed" if self.scan_state.get("correlation_runs") else "pending")
            elif key == "detection":
                status = "completed" if self.scan_state.get("lead_detected") else ("active" if wifi_active else "pending")
            elif key == "sdr_24":
                status = "completed" if "drone_24" in completed else ("active" if sdr_state.get("running") and self.scan_state.get("current_sdr_profile") == "drone_24" else "pending")
            elif key == "sdr_58":
                status = "completed" if "drone_58" in completed else ("active" if sdr_state.get("running") and self.scan_state.get("current_sdr_profile") == "drone_58" else "pending")
            elif key == "audit":
                status = "active" if active_phase == "audit" else ("completed" if self.scan_state.get("audit_started") else "pending")
            elif key == "finalize":
                status = "completed" if self.scan_state.get("finalized") else ("active" if active_phase == "finalize" else "pending")
            phases.append({"key": key, "label": label, "status": status})
        return phases

    def start_session(self, *, session_name: str, operator: str, location: str, notes: str, scan_profile: str, evidence_path: str = "") -> Dict[str, Any]:
        profile_key = scan_profile if scan_profile in self.SCAN_PROFILES else "passive_standard"
        started = int(self._now())
        session_id = f"SESSION_{time.strftime('%Y_%m_%d_%H%M%S', time.localtime(started))}_{self._safe_session_slug(session_name)}"
        base_dir = Path(evidence_path).expanduser() if evidence_path else self.evidence_root / session_id
        if not base_dir.is_absolute():
            base_dir = (self.root_dir / base_dir).resolve()
        self.active = True
        self.session_id = session_id
        self.session_name = session_name or session_id
        self.session_dir = base_dir
        self.started_at = self._now()
        self.last_scan_at = None
        self.last_error = ""
        self.events = []
        self.operator_log = []
        self.detections = []
        self.topology = {"nodes": [], "edges": []}
        self.reports = []
        self.evidence_summary = {"bundles": [], "counts": {}}
        self.environment_baseline = {"captured_at": self._now(), "common_ssids": [], "stationary_ap_count_estimate": 0, "common_channel_occupancy": {}, "noise_floor_hint_db": -92, "summary": "Baseline will be learned during the first passive scan."}
        self.replay_state = {}
        self.live_leads = []
        self.assurance_state = {
            "leads": [],
            "anomalies_wifi": [],
            "anomalies_sdr": [],
            "band_attention": [],
            "scheduler_actions": [],
            "fusion_windows": [],
            "raw_filtered_counts": {},
            "sensor_sync": {"status": "idle"},
        }
        self.scan_state = self._blank_scan_state()
        self.scan_state["profile"] = profile_key
        self.scan_state["stopped_by_operator"] = False
        self.session_metadata = {"session_id": session_id, "session_name": self.session_name, "operator": operator, "location": location, "notes": notes, "scan_profile": profile_key, "profile_label": self.SCAN_PROFILES[profile_key]["label"], "passive_only_locked": True, "created_at": self.started_at}
        self.session_metadata["retention_mode"] = self.retention_mode
        if self._retention_enabled():
            retention = EvidenceRetentionManager(base_dir)
            retention.persist_session_shell(self.session_metadata, self.receive_only_guard.status(), self.environment_baseline)
        self._append_event("session", "Hunt Drones session started.", {"session_id": session_id, "scan_profile": profile_key})
        self._append_operator_log(
            f"Passive-only Hunt Drones session started for {self.session_name}. "
            f"Retention mode: {'persistent evidence' if self._retention_enabled() else 'ephemeral test'}."
        )
        self._live_state_cache = {"timestamp": 0.0, "value": {}}
        self._audit_requested_at = None
        return {"ok": True, "status": "started", "session": self.session_metadata, "evidence_dir": str(base_dir), "hardware": self._hardware_status()}

    def stop_session(self) -> Dict[str, Any]:
        wifi_manager = getattr(self.runtime, "wifi_mk7", None) if self.runtime else None
        sdr_manager = getattr(self.runtime, "hackrf_sweep", None) if self.runtime else None
        if wifi_manager is not None:
            try:
                wifi_manager.stop()
            except Exception:
                pass
        if sdr_manager is not None:
            try:
                sdr_manager.stop()
            except Exception:
                pass
        target_seconds = int(self.scan_state.get("target_seconds") or self.SCAN_PROFILES[self.scan_state.get("profile") or "passive_standard"]["duration_seconds"])
        profile = str(self.scan_state.get("profile") or "passive_standard")
        self.scan_state = self._blank_scan_state()
        self.scan_state["target_seconds"] = target_seconds
        self.scan_state["profile"] = profile
        self.scan_state["stopped_by_operator"] = True
        self.active = False
        self._live_state_cache = {"timestamp": 0.0, "value": {}}
        self._audit_requested_at = None
        self._append_event("session", "Hunt Drones session stopped.", {"session_id": self.session_id})
        self._append_operator_log(
            f"Hunt Drones session stopped. Retained {len(self.detections)} investigated targets and {len(self.live_leads)} live leads for operator review."
        )
        return {"ok": True, "status": "stopped", "session_id": self.session_id}

    def clear_session(self) -> Dict[str, Any]:
        wifi_manager = getattr(self.runtime, "wifi_mk7", None) if self.runtime else None
        sdr_manager = getattr(self.runtime, "hackrf_sweep", None) if self.runtime else None
        if wifi_manager is not None:
            try:
                wifi_manager.stop()
            except Exception:
                pass
        if sdr_manager is not None:
            try:
                sdr_manager.stop()
            except Exception:
                pass
        self.active = False
        self.detections = []
        self.topology = {"nodes": [], "edges": []}
        self.events = []
        self.operator_log = []
        self.reports = []
        self.evidence_summary = {"bundles": [], "counts": {}}
        self.scan_state = self._blank_scan_state()
        self.scan_state["stopped_by_operator"] = True
        self.last_scan_at = None
        self.live_leads = []
        self.assurance_state = {
            "leads": [],
            "anomalies_wifi": [],
            "anomalies_sdr": [],
            "band_attention": [],
            "scheduler_actions": [],
            "fusion_windows": [],
            "raw_filtered_counts": {},
            "sensor_sync": {"status": "idle"},
        }
        self._live_state_cache = {"timestamp": 0.0, "value": {}}
        self._audit_requested_at = None
        self._append_event("session", "Hunt Drones session reset.", {"session_id": self.session_id})
        self._append_operator_log("Hunt Drones session reset.", action="reset")
        return {"ok": True, "status": "cleared"}

    def delete_all_data(self) -> Dict[str, Any]:
        wifi_manager = getattr(self.runtime, "wifi_mk7", None) if self.runtime else None
        sdr_manager = getattr(self.runtime, "hackrf_sweep", None) if self.runtime else None
        if wifi_manager is not None:
            try:
                wifi_manager.stop()
            except Exception:
                pass
        if sdr_manager is not None:
            try:
                sdr_manager.stop()
            except Exception:
                pass

        deleted_paths: List[str] = []
        if self.evidence_root.exists():
            for child in self.evidence_root.iterdir():
                try:
                    if child.is_dir():
                        shutil.rmtree(child)
                    else:
                        child.unlink()
                    deleted_paths.append(str(child))
                except Exception as exc:
                    self.last_error = str(exc)
                    return {"ok": False, "status": "delete_failed", "error": str(exc), "deleted_paths": deleted_paths}

        self.active = False
        self.session_id = ""
        self.session_name = ""
        self.session_metadata = {}
        self.session_dir = None
        self.started_at = None
        self.last_scan_at = None
        self.last_error = ""
        self.events = []
        self.operator_log = []
        self.detections = []
        self.topology = {"nodes": [], "edges": []}
        self.reports = []
        self.evidence_summary = {"bundles": [], "counts": {}}
        self.environment_baseline = {}
        self.replay_state = {}
        self.live_leads = []
        self.scan_state = self._blank_scan_state()
        self.scan_state["stopped_by_operator"] = True
        self.assurance_state = {
            "leads": [],
            "anomalies_wifi": [],
            "anomalies_sdr": [],
            "band_attention": [],
            "scheduler_actions": [],
            "fusion_windows": [],
            "raw_filtered_counts": {},
            "sensor_sync": {"status": "idle"},
        }
        self._live_state_cache = {"timestamp": 0.0, "value": {}}
        self._audit_requested_at = None
        return {"ok": True, "status": "deleted", "deleted_count": len(deleted_paths), "deleted_paths": deleted_paths}

    def run_passive_scan(self) -> Dict[str, Any]:
        if not self._session_armed():
            return {"ok": False, "error": "Start a Hunt Drones session first."}
        self._ensure_detection_runtime()
        wifi_runtime = self._wifi_runtime_snapshot()
        wifi_scan = {
            "started_at": self.scan_state.get("started_at"),
            "target_seconds": wifi_runtime.get("target_seconds"),
            "progress_percent": wifi_runtime.get("progress_percent"),
        }
        wifi_active = bool(wifi_runtime.get("capture_active"))
        if wifi_active and not self.scan_state.get("active"):
            self.scan_state.update({"active": True, "started_at": wifi_scan.get("started_at") or self._now(), "target_seconds": wifi_scan.get("target_seconds") or self.SCAN_PROFILES[self.scan_state['profile']]["duration_seconds"], "phase": "initialize"})
            self._append_event("scan", "Dual-sensor passive cycle initialized.", {"profile": self.scan_state["profile"]})
            self._append_operator_log("Hunt Drones initialized MK7AC + HackRF passive collection.", action="scan")
        if wifi_active:
            self._append_event(
                "passive_observation",
                "Passive collection window updated.",
                {
                    "channel": wifi_runtime.get("current_channel"),
                    "coverage": wifi_runtime.get("coverage_level") or "UNKNOWN",
                    "networks": int(wifi_runtime.get("network_count") or 0),
                    "clients": int(wifi_runtime.get("client_count") or 0),
                    "pcaps": int(wifi_runtime.get("pcap_count") or 0),
                    "progress_percent": float(wifi_scan.get("progress_percent") or 0.0),
                },
            )
            self._append_operator_log(
                "Passive sensors observing "
                f"{int(wifi_runtime.get('network_count') or 0)} networks, "
                f"{int(wifi_runtime.get('client_count') or 0)} clients on channel "
                f"{wifi_runtime.get('current_channel') or '--'}.",
                action="observe",
            )
        sdr_state = self._advance_sdr_pipeline() if self.scan_state.get("active") else {"running": False}
        sdr_candidates = self._harvest_sdr_candidates() if self.scan_state.get("active") else []
        observations = self._wifi_observations()
        self.environment_baseline = build_environment_baseline(observations)
        assurance = self._evaluate_assurance(observations, sdr_candidates)
        base_detections = self._base_detection_set(observations, sdr_candidates)
        live_leads = self._assurance_leads_to_live_rows(assurance) or self._build_live_leads(base_detections)
        if live_leads and not self.scan_state.get("lead_detected"):
            self.scan_state["lead_detected"] = True
            self.scan_state["phase"] = "detection"
            self._append_event("detection", "Drone lead detected. Audit pipeline queued.", {"lead_count": len(live_leads)})
        self.live_leads = live_leads
        manifests = {"remote_id": {"targets": []}, "dji": {"targets": []}}
        report_targets: List[Dict[str, Any]] = list(self.live_leads)
        if self.scan_state.get("lead_detected"):
            self.scan_state["audit_started"] = True
            self.scan_state["phase"] = "audit"
            manifests = self._collect_decoder_manifests(observations, sdr_candidates)
            detections = self._apply_decoder_manifests(base_detections, manifests)
            detections = self.fusion_engine.fuse(detections)
            detections = [self._score_detection(item, self.environment_baseline) for item in detections]
            detections = [item for item in detections if self._retainable_drone_detection(item)]
            detections = self.swarm_engine.group(detections)
            detections.sort(key=lambda item: (int(item.get("proof_tier", {}).get("tier", 0)), int(item.get("confidence_score", {}).get("score", 0))), reverse=True)
            if detections:
                report_targets = detections[:48]
        self.detections = report_targets[:48]
        self.topology = self.topology_builder.build(self.session_id, self.session_name, self.detections)
        report = self.report_builder.build(self.session_metadata, self.detections, self.environment_baseline)
        operator_md = self.report_builder.build_operator_markdown(report, self.detections)
        self.reports = [report]
        self.last_scan_at = self._now()
        if self._retention_enabled() and self.session_dir is not None:
            retention = EvidenceRetentionManager(self.session_dir)
            retention.persist_session_shell(self.session_metadata, self.receive_only_guard.status(), self.environment_baseline)
            retention.persist_observations(observations, sdr_candidates, manifests.get("remote_id", {}).get("targets") or [], manifests.get("dji", {}))
            retention.persist_targets(self.detections)
            retention.persist_assurance(
                {
                    **assurance,
                    "runtime_baseline": self.environment_baseline,
                    "session_trace": {
                        "phase": self.scan_state.get("phase"),
                        "lead_detected": bool(self.scan_state.get("lead_detected")),
                        "audit_started": bool(self.scan_state.get("audit_started")),
                        "detection_count": len(self.detections),
                    },
                }
            )
            retention.write_json("topology/graph.json", self.topology)
            retention.write_json("topology/graph_metrics.json", {"node_count": len(self.topology.get("nodes") or []), "edge_count": len(self.topology.get("edges") or [])})
            retention.persist_timeline(self.events, self.operator_log)
            retention.persist_reports(report, report, operator_md)
        self.evidence_summary = {
            "bundles": [{"target_id": item.get("target_id"), "label": item.get("label"), "proof_tier": item.get("proof_tier"), "confidence": item.get("confidence_score", {}).get("score"), "evidence_bundle": item.get("evidence_bundle")} for item in self.detections],
            "counts": {
                "wifi_rows": len(observations),
                "sdr_rows": len(sdr_candidates),
                "targets": len(self.detections),
                "live_leads": len(self.live_leads),
                "assurance_wifi_anomalies": len(assurance.get("anomalies_wifi") or []),
                "assurance_sdr_anomalies": len(assurance.get("anomalies_sdr") or []),
                "retention_enabled": self._retention_enabled(),
            },
        }
        if self.scan_state.get("active"):
            self.scan_state["correlation_runs"] = int(self.scan_state.get("correlation_runs") or 0) + 1
            if wifi_active:
                if not self.scan_state.get("lead_detected"):
                    self.scan_state["phase"] = "detection"
                elif "drone_24" not in (self.scan_state.get("sdr_profiles_completed") or []):
                    self.scan_state["phase"] = "sdr_24"
                elif "drone_58" not in (self.scan_state.get("sdr_profiles_completed") or []):
                    self.scan_state["phase"] = "sdr_58"
                else:
                    self.scan_state["phase"] = "audit"
            else:
                self.scan_state["phase"] = "finalize"
                self.scan_state["finalized"] = True
                self.scan_state["active"] = False
        if not wifi_active and not sdr_state.get("running") and self.scan_state.get("active"):
            self.scan_state["phase"] = "finalize"
            self.scan_state["finalized"] = True
            self.scan_state["active"] = False
        if self.detections:
            top_target = self.detections[0]
            self._append_operator_log(
                f"Top retained target {top_target.get('label') or top_target.get('target_id')} at "
                f"confidence {top_target.get('confidence_score', {}).get('score', 0)} "
                f"with proof tier {top_target.get('proof_tier', {}).get('tier', 0)}.",
                action="retain",
            )
        else:
            self._append_operator_log(
                "No evidence-backed targets retained yet. Passive evidence is still being collected.",
                action="observe",
            )
        self._append_event("scan", "Passive Hunt Drones scan completed.", {"detections": len(self.detections), "profile": self.scan_state["profile"]})
        self._append_operator_log(f"Passive scan completed with {len(self.detections)} retained targets.")
        return {"ok": True, "status": "completed", "detections": self.detections, "topology": self.topology, "report": report}

    def get_live_detection_state(self) -> Dict[str, Any]:
        if not self._session_armed():
            self._prune_runtime_truth()
            return {
                "ok": False,
                "active": False,
                "phase": "idle",
                "lead_detected": False,
                "audit_started": False,
                "live_leads": [],
            }
        self._ensure_detection_runtime()
        self._prune_runtime_truth()
        cache_age = self._now() - float(self._live_state_cache.get("timestamp") or 0.0)
        cached = self._live_state_cache.get("value") or {}
        if cache_age <= self.LIVE_STATE_TTL_SECONDS and cached:
            return dict(cached)
        return self._compute_live_detection_payload()

    def list_replay_sessions(self) -> List[Dict[str, Any]]:
        return self.replay_manager.list_sessions()

    def load_replay_session(self, session_id: str) -> Dict[str, Any]:
        loaded = self.replay_manager.load_session(session_id)
        if not loaded.get("ok"):
            return loaded
        self.replay_state = loaded
        self.detections = list(loaded.get("detections") or [])
        self.topology = dict(loaded.get("topology") or {"nodes": [], "edges": []})
        self.reports = [loaded.get("report") or {}]
        self.environment_baseline = dict(loaded.get("baseline") or {})
        self._append_event("replay", "Replay session loaded.", {"session_id": session_id})
        self._append_operator_log(f"Replay session loaded for {session_id}.", action="replay")
        return loaded

    def request_disabled_capability(self, capability: str) -> Dict[str, Any]:
        decision = self.receive_only_guard.enforce(capability)
        return {"ok": decision.allowed, "capability": capability, "message": decision.reason}

    def get_status(self) -> Dict[str, Any]:
        self._prune_runtime_truth()
        hardware = self._hardware_status()
        sdr_manager = getattr(self.runtime, "hackrf_sweep", None) if self.runtime else None
        live_cache = self._live_state_cache.get("value") or {}
        wifi_runtime = dict(live_cache.get("wifi_runtime") or self._wifi_runtime_snapshot())
        sdr_state = dict(live_cache.get("sdr_state") or {"running": False, "status_detail": "idle"})
        if not live_cache and sdr_manager is not None:
            try:
                sdr_state = sdr_manager.get_state()
            except Exception:
                sdr_state = {"running": False, "status_detail": "error"}
        return {
            "service": "hunt_drones",
            "version": self.VERSION,
            "active": self._session_armed(),
            "retention_mode": self.retention_mode,
            "passive_only_locked": True,
            "session_id": self.session_id,
            "session_name": self.session_name,
            "started_at": self.started_at,
            "last_scan_at": self.last_scan_at,
            "hardware": hardware,
            "evidence_dir": str(self.session_dir) if (self.session_dir and self._retention_enabled()) else "",
            "detection_count": len(self.detections),
            "live_lead_count": len(self.live_leads),
            "scan_profiles": self.SCAN_PROFILES,
            "wifi_runtime": wifi_runtime,
            "assurance": {
                "band_attention": self.assurance_state.get("band_attention") or [],
                "sensor_sync": self.assurance_state.get("sensor_sync") or {"status": "idle"},
                "scheduler_actions": self.assurance_state.get("scheduler_actions") or [],
                "fusion_windows": self.assurance_state.get("fusion_windows") or [],
                "raw_filtered_counts": self.assurance_state.get("raw_filtered_counts") or {},
                "anomaly_counts": {
                    "wifi": len(self.assurance_state.get("anomalies_wifi") or []),
                    "sdr": len(self.assurance_state.get("anomalies_sdr") or []),
                },
            },
            "scan": {
                "active": bool(wifi_runtime.get("capture_active")) or bool(self.scan_state.get("active")),
                "started_at": self.scan_state.get("started_at"),
                "target_seconds": wifi_runtime.get("target_seconds") or self.scan_state.get("target_seconds"),
                "elapsed_seconds": wifi_runtime.get("elapsed_seconds") or 0.0,
                "progress_percent": wifi_runtime.get("progress_percent") or 0.0,
                "phase": self.scan_state.get("phase") or "idle",
                "lead_detected": bool(self.scan_state.get("lead_detected")),
                "audit_started": bool(self.scan_state.get("audit_started")),
                "toolchain": [
                    {"name": "wifi_mk7", "active": bool(wifi_runtime.get("capture_active")), "role": "Passive Wi-Fi capture", "integration_state": "active" if wifi_runtime.get("capture_active") else "ready", "progress_label": "capture"},
                    {"name": "hackrf_sweep", "active": bool(sdr_state.get("running")), "role": "Passive spectrum sweep", "integration_state": sdr_state.get("status_detail") or "idle", "progress_label": self.scan_state.get("current_sdr_profile") or "ready"},
                    {"name": "remote_id_parser", "active": True, "role": "Decoder-backed observation", "integration_state": "passive", "progress_label": "decode"},
                ],
                "scanning_devices": [
                    {
                        "name": "Wi-Fi MK7 Adapter",
                        "device": (((hardware.get("mk7ac") or {}).get("interface")) or "unavailable"),
                        "active": bool(wifi_runtime.get("capture_active")),
                        "role": "Drone-only passive Wi-Fi detection",
                    },
                    {
                        "name": "HackRF SDR",
                        "device": "HackRF One" if (hardware.get("hackrf") or {}).get("connected") else "unavailable",
                        "active": bool(sdr_state.get("running")),
                        "role": "Passive RF sweep and burst lead detection",
                    },
                ],
                "phases": self._scan_phases(bool(wifi_runtime.get("capture_active")), sdr_state),
                "graph_points": self._graph_points(),
            },
            "topology": {"node_count": len(self.topology.get("nodes") or []), "edge_count": len(self.topology.get("edges") or [])},
            "environment_baseline": self.environment_baseline,
            "last_error": self.last_error,
            "replay_state": self.replay_state.get("replay_status") or "idle",
        }

    def get_detections(self) -> List[Dict[str, Any]]:
        self._prune_runtime_truth()
        return list(self.detections)

    def get_target_detail(self, target_id: str) -> Dict[str, Any]:
        self._prune_runtime_truth()
        for item in self.detections:
            if item.get("target_id") == target_id:
                return dict(item)
        return {}

    def get_timeline(self) -> List[Dict[str, Any]]:
        return list(self.events)

    def get_operator_log(self) -> List[Dict[str, Any]]:
        return list(self.operator_log)

    def get_topology(self) -> Dict[str, Any]:
        return dict(self.topology)

    def get_reports(self) -> List[Dict[str, Any]]:
        return list(self.reports)

    def get_settings(self) -> Dict[str, Any]:
        return dict(self.settings)

    def get_evidence_summary(self) -> Dict[str, Any]:
        return dict(self.evidence_summary)
