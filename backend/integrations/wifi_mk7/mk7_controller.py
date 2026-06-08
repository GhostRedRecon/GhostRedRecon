from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import tempfile
import threading
import time
import traceback
from pathlib import Path
from shutil import which
from typing import Any, Dict, List

from backend.config.project_config import get_project_config
from backend.integrations.wifi_mk7.active_fingerprint_engine import ActiveFingerprintEngine
from backend.integrations.wifi_mk7.camera_validation_engine import CameraValidationEngine
from backend.integrations.wifi_mk7.channel_hopper import ChannelHopper
from backend.integrations.wifi_mk7.ddi_engine import WiFiDDIEngine
from backend.integrations.wifi_mk7.evidence_retention import WiFiEvidenceRetentionEngine
from backend.integrations.wifi_mk7.external_destination_analysis import ExternalDestinationAnalysisEngine
from backend.integrations.wifi_mk7.imported_capture_analyzer import ImportedCaptureAnalyzer
from backend.integrations.wifi_mk7.identity_enricher import WiFiIdentityEnricher
from backend.integrations.wifi_mk7.monitor_manager import MonitorManager
from backend.integrations.wifi_mk7.packet_capture import PacketCaptureEngine
from backend.integrations.wifi_mk7.pipeline_controller import WiFiCameraPipelineController
from backend.integrations.wifi_mk7.service_exposure_audit_engine import ServiceExposureAuditEngine
from backend.integrations.wifi_mk7.staged_pipeline import StagedWiFiScanPipeline
from backend.integrations.wifi_mk7.visual_acquisition_engine import VisualAcquisitionEngine
from backend.integrations.wifi_mk7.wifi_intelligence_engine import WiFiIntelligenceEngine
from backend.integrations.wifi_mk7.wifi_device_tracker import WiFiDeviceTracker


class WiFiMK7Controller:
    VERSION = "4.0.0"
    CAMERA_PACKET_MAX_BYTES = 20 * 1024 * 1024
    WIFI_HARD_AUDIT_SCOPE = [
        "ddi_resolution",
        "safe_port_discovery",
        "service_identification",
        "access_posture",
        "destination_analysis",
        "evidence_trace",
    ]
    HARD_AUDIT_STAGE_LABELS = {
        "passive_probe": "Passive + Probe",
        "xiaomi_firmware": "Xiaomi Firmware",
        "xiaomi_cloud": "Xiaomi Cloud",
        "xiaomi_local_api": "Xiaomi Local API",
        "network_reality": "Network Reality",
        "ip_materialization": "IP Materialization",
        "baseline": "Baseline",
        "trigger": "Trigger",
        "post_trigger": "Post Trigger",
        "direct_ip_capture": "Direct IP Capture",
        "traffic_intel": "Traffic Intel",
        "live_view": "Live-View Correlation",
        "stream_detection": "Stream Detection",
        "vendor_profile": "Vendor Profile",
        "visual_acquisition": "Visual Acquisition",
        "owner_assisted": "Owner Assisted",
        "recorder_replay": "Recorder Replay",
        "endpoint_attribution": "Endpoint Attribution",
        "artifact_decision": "Artifact Decision",
        "negative_proof": "Negative Proof",
        "finalize": "Finalize",
    }

    def __init__(self) -> None:
        self.root_dir = Path(__file__).resolve().parents[3]
        self.monitor = MonitorManager()
        self.hopper = ChannelHopper()
        self.capture = PacketCaptureEngine(self.root_dir)
        self.tracker = WiFiDeviceTracker(self.root_dir / "logs" / "wifi_mk7" / "tracker_history.json")
        self.enricher = WiFiIdentityEnricher(self.root_dir, self.capture.tshark_path)
        self.intelligence = WiFiIntelligenceEngine(self.root_dir / "logs" / "wifi_mk7" / "scenario_history.json")
        self.evidence = WiFiEvidenceRetentionEngine(self.root_dir, self.capture.tshark_path)
        self.ddi = WiFiDDIEngine(self.capture.tshark_path)
        self.destination_analysis = ExternalDestinationAnalysisEngine(self.root_dir, self.capture.tshark_path)
        self.active_fingerprint = ActiveFingerprintEngine(root_dir=self.root_dir, preferred_interface=self.monitor.PREFERRED_INTERFACE)
        self.camera_validation = CameraValidationEngine(self.root_dir)
        self.service_audit = ServiceExposureAuditEngine()
        self.imported_capture_analyzer = ImportedCaptureAnalyzer(self.root_dir)
        self.pipeline = WiFiCameraPipelineController(self.root_dir)
        self.visual_acquisition = VisualAcquisitionEngine()
        self.processing_pipeline = StagedWiFiScanPipeline(
            self.tracker,
            self.enricher,
            lambda: self.get_networks(lightweight=True),
            lambda: self.get_clients(lightweight=True),
            error_callback=self._record_error,
        )
        self.armed = False
        self.capture_active = False
        self.current_channel = None
        self.last_error = ""
        self.last_started_at = None
        self.last_sweep_at = None
        self.last_pps = 0.0
        self.sensor_snapshot: Dict[str, Any] = {}
        self.last_scan_summary: Dict[str, Any] = {}
        self.active_probe_cache: Dict[str, Dict[str, Any]] = {}
        self.hard_audit_cache: Dict[str, Dict[str, Any]] = {}
        self.service_audit_cache: Dict[str, Dict[str, Any]] = {}
        self.destination_analysis_cache: Dict[str, Dict[str, Any]] = {}
        self.auto_probe_summary: Dict[str, Any] = {"enabled": True, "attempted": 0, "positive": 0, "probed_leads": []}
        self.scan_thread: threading.Thread | None = None
        self.scan_lock = threading.Lock()
        self.tracker_lock = threading.Lock()
        self.stop_requested = False
        self.scan_started_at: float | None = None
        self.scan_target_seconds: int = 0
        self.scan_elapsed_seconds: float = 0.0
        self.scan_progress_percent: float = 0.0
        self.scan_completed_channels: int = 0
        self.scan_total_channels: int = 0
        self.scan_cycle: int = 0
        self.scan_mode: str = "broad"
        self.scan_scenario: str = "passive_observation"
        self.scan_locked_channels: List[int] = []
        self.scan_selected_interfaces: List[str] = []
        self.scan_deep_packet_enrichment: bool = False
        self.scan_camera_hunt: bool = False
        self.scan_processing_enabled: bool = True
        self.channel_statistics: Dict[int, Dict[str, Any]] = {}
        self.single_adapter_policy = True
        self.ddi_cache: Dict[str, Dict[str, Any]] = {}
        self.camera_hunt_results_cache: Dict[str, Any] = {"built_at": 0.0, "results": None}
        self.artifact_materialization_thread: threading.Thread | None = None
        self.artifact_materialization_started_at: float | None = None
        self.artifact_materialization_finished_at: float | None = None
        self.artifact_materialization_last_error: str = ""
        self.resource_policy = self._resolve_resource_policy()
        self.target_snapshot_cache: Dict[str, Dict[str, Any]] = {
            "networks": {"built_at": 0.0, "signature": "", "items": []},
            "clients": {"built_at": 0.0, "signature": "", "items": []},
            "networks_light": {"built_at": 0.0, "signature": "", "items": []},
            "clients_light": {"built_at": 0.0, "signature": "", "items": []},
        }
        self.fallback_ingest_count: int = 0
        self.last_fallback_ingest: Dict[str, Any] = {}
        self.redteam_validation_state: Dict[str, Any] = {"state": "IDLE", "updated_at": int(time.time()), "last_run": {}, "last_preflight": {}}
        self.adversary_replay_state: Dict[str, Any] = {"state": "IDLE", "updated_at": int(time.time()), "last_run": {}}

    @staticmethod
    def _system_memory_mb() -> int:
        try:
            meminfo = Path("/proc/meminfo")
            if meminfo.exists():
                for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("MemAvailable:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return max(0, int(parts[1]) // 1024)
        except Exception:
            pass
        return 0

    def _resolve_resource_policy(self) -> Dict[str, Any]:
        config = get_project_config()
        wifi_config = dict(config.get("wifiMk7") or {})
        profile_name = str(
            os.environ.get("GHOSTRECON_WIFI_MK7_PROFILE")
            or wifi_config.get("resourceProfile")
            or "auto"
        ).strip().lower()
        cpu_count = max(1, int(os.cpu_count() or 1))
        memory_mb = self._system_memory_mb()
        if profile_name == "auto":
            profile_name = "low_resource_linux" if cpu_count <= 4 or (memory_mb and memory_mb <= 6144) else "balanced"
        profiles = {
            "balanced": {
                "name": "balanced",
                "label": "Balanced",
                "enable_kismet": True,
                "enable_bettercap": True,
                "enable_zeek": True,
                "enrichment_sample_rate": 1,
                "camera_hunt_results_cache_ttl_active": 4.0,
                "camera_hunt_results_cache_ttl_idle": 2.0,
                "camera_hunt_auto_probe_leads": 5,
                "target_snapshot_cache_ttl_active": 2.5,
                "target_snapshot_cache_ttl_idle": 1.0,
                "max_enrichment_pcap_bytes": 0,
                "airodump_write_interval_seconds": 1,
            },
            "low_resource_linux": {
                "name": "low_resource_linux",
                "label": "Low Resource Linux",
                "enable_kismet": False,
                "enable_bettercap": False,
                "enable_zeek": False,
                "enrichment_sample_rate": 3,
                "camera_hunt_results_cache_ttl_active": 10.0,
                "camera_hunt_results_cache_ttl_idle": 6.0,
                "camera_hunt_auto_probe_leads": 2,
                "target_snapshot_cache_ttl_active": 6.0,
                "target_snapshot_cache_ttl_idle": 3.0,
                "max_enrichment_pcap_bytes": 4 * 1024 * 1024,
                "airodump_write_interval_seconds": 3,
            },
        }
        selected = dict(profiles.get(profile_name) or profiles["balanced"])
        selected["detected_cpu_count"] = cpu_count
        selected["detected_available_memory_mb"] = memory_mb
        selected["selected_by"] = "config/env" if profile_name != "auto" else "auto"
        selected["requested_profile"] = profile_name
        return selected

    def _enabled_pipeline_collectors(self) -> List[str]:
        enabled = ["airodump-ng"]
        if bool(self.resource_policy.get("enable_kismet")):
            enabled.append("kismet")
        if bool(self.resource_policy.get("enable_bettercap")):
            enabled.append("bettercap")
        return enabled

    def _invalidate_target_snapshot_cache(self) -> None:
        self.target_snapshot_cache = {
            "networks": {"built_at": 0.0, "signature": "", "items": []},
            "clients": {"built_at": 0.0, "signature": "", "items": []},
            "networks_light": {"built_at": 0.0, "signature": "", "items": []},
            "clients_light": {"built_at": 0.0, "signature": "", "items": []},
        }

    def _target_snapshot_signature(self) -> str:
        raw_networks = self.tracker.get_networks()
        raw_clients = self.tracker.get_clients()
        latest_network_seen = max((float(item.get("last_seen") or 0.0) for item in raw_networks), default=0.0)
        latest_client_seen = max((float(item.get("last_seen") or 0.0) for item in raw_clients), default=0.0)
        total_network_packets = sum(int(item.get("packet_count") or 0) for item in raw_networks)
        total_client_packets = sum(int(item.get("packet_count") or 0) for item in raw_clients)
        latest_pcap_seen = max((float(item.get("captured_at") or 0.0) for item in self.tracker.recent_pcaps), default=0.0)
        return "|".join(
            [
                str(len(raw_networks)),
                str(len(raw_clients)),
                str(total_network_packets),
                str(total_client_packets),
                f"{latest_network_seen:.3f}",
                f"{latest_client_seen:.3f}",
                str(len(self.tracker.recent_pcaps)),
                f"{latest_pcap_seen:.3f}",
                str(len(self.service_audit_cache)),
                str(len(self.destination_analysis_cache)),
            ]
        )

    def _artifact_materialization_active(self) -> bool:
        thread = self.artifact_materialization_thread
        return bool(thread and thread.is_alive())

    def _get_enriched_targets(self, kind: str, *, lightweight: bool = False) -> List[Dict[str, Any]]:
        base_cache_key = "clients" if kind == "clients" else "networks"
        cache_key = f"{base_cache_key}_light" if lightweight or self._artifact_materialization_active() else base_cache_key
        signature = self._target_snapshot_signature()
        cache = self.target_snapshot_cache.get(cache_key) or {}
        cache_age = time.time() - float(cache.get("built_at") or 0.0)
        ttl_seconds = float(
            self.resource_policy.get("target_snapshot_cache_ttl_active")
            if self._effective_capture_active()
            else self.resource_policy.get("target_snapshot_cache_ttl_idle")
            or (2.5 if self._effective_capture_active() else 1.0)
        )
        if (
            cache.get("items") is not None
            and str(cache.get("signature") or "") == signature
            and cache_age <= ttl_seconds
        ):
            return list(cache.get("items") or [])

        raw_networks = self.tracker.get_networks()
        raw_clients = self.tracker.get_clients()
        if base_cache_key == "networks":
            base_items = self.intelligence.enrich_networks(raw_networks, raw_clients)
        else:
            base_items = self.intelligence.enrich_clients(raw_clients)
        items = [self._merge_service_audit_into_target(item) for item in base_items]
        if not (lightweight or self._artifact_materialization_active()):
            items = [self._merge_runtime_context_into_target(item) for item in base_items]
        self.target_snapshot_cache[cache_key] = {
            "built_at": time.time(),
            "signature": signature,
            "items": items,
        }
        return list(items)

    @staticmethod
    def _hard_audit_stage_template() -> List[Dict[str, Any]]:
        return [
            {"id": "passive_probe", "label": "Passive + Probe", "status": "pending", "detail": "Awaiting audit start."},
            {"id": "network_reality", "label": "Network Reality", "status": "pending", "detail": "IP ↔ MAC validation not started."},
            {"id": "ip_materialization", "label": "IP Materialization", "status": "pending", "detail": "Candidate IP escalation not started."},
            {"id": "baseline", "label": "Baseline", "status": "pending", "detail": "Idle baseline window not started."},
            {"id": "trigger", "label": "Trigger", "status": "pending", "detail": "Awaiting operator live-view trigger."},
            {"id": "post_trigger", "label": "Post Trigger", "status": "pending", "detail": "Post-trigger capture window not started."},
            {"id": "traffic_intel", "label": "Traffic Intel", "status": "pending", "detail": "Endpoint extraction not started."},
            {"id": "live_view", "label": "Live-View Correlation", "status": "pending", "detail": "Correlation not attempted."},
            {"id": "stream_detection", "label": "Stream Detection", "status": "pending", "detail": "No stream classification yet."},
            {"id": "vendor_profile", "label": "Vendor Profile", "status": "pending", "detail": "Vendor family workflow not classified."},
            {"id": "visual_acquisition", "label": "Visual Acquisition", "status": "pending", "detail": "No visual acquisition path has been synthesized yet."},
            {"id": "owner_assisted", "label": "Owner Assisted", "status": "pending", "detail": "Owner-assisted fallback not evaluated."},
            {"id": "recorder_replay", "label": "Recorder Replay", "status": "pending", "detail": "Recorder or replay path not evaluated."},
            {"id": "endpoint_attribution", "label": "Endpoint Attribution", "status": "pending", "detail": "Endpoint roles not classified."},
            {"id": "artifact_decision", "label": "Artifact Decision", "status": "pending", "detail": "Artifact eligibility not decided."},
            {"id": "negative_proof", "label": "Negative Proof", "status": "pending", "detail": "Negative evidence review not started."},
            {"id": "finalize", "label": "Finalize", "status": "pending", "detail": "Awaiting final verdict."},
        ]

    def _seed_hard_audit_state(self, lead_id: str) -> Dict[str, Any]:
        audit = {
            "lead_id": lead_id,
            "status": "running",
            "tested_at": int(time.time()),
            "classification": "in_progress",
            "evidence_quality": "partial",
            "error": "",
            "pipeline": {
                "status": "running",
                "current_stage": "passive_probe",
                "summary": "Hard audit started.",
                "stages": self._hard_audit_stage_template(),
                "network_reality": {},
                "traffic_intelligence": {},
                "visual_acquisition": {},
                "artifact_decision": {},
            },
        }
        self.hard_audit_cache[lead_id] = audit
        return audit

    def _ensure_hard_audit_stage(
        self,
        lead_id: str,
        stage_id: str,
        *,
        label: str = "",
        detail: str = "",
        insert_after: str = "passive_probe",
    ) -> None:
        audit = dict(self.hard_audit_cache.get(lead_id) or {})
        pipeline = dict(audit.get("pipeline") or {})
        stages = [dict(item) for item in (pipeline.get("stages") or self._hard_audit_stage_template())]
        if any(str(stage.get("id") or "") == stage_id for stage in stages):
            return
        next_stage = {
            "id": stage_id,
            "label": label or self.HARD_AUDIT_STAGE_LABELS.get(stage_id, stage_id.replace("_", " ").title()),
            "status": "pending",
            "detail": detail or "Awaiting evaluation.",
        }
        insert_index = 1
        for index, stage in enumerate(stages):
            if str(stage.get("id") or "") == insert_after:
                insert_index = index + 1
                break
        stages.insert(insert_index, next_stage)
        pipeline["stages"] = stages
        audit["pipeline"] = pipeline
        self.hard_audit_cache[lead_id] = audit

    def _update_hard_audit_stage(
        self,
        lead_id: str,
        stage_id: str,
        *,
        status: str,
        detail: str,
        summary: str = "",
        extra: Dict[str, Any] | None = None,
    ) -> None:
        audit = dict(self.hard_audit_cache.get(lead_id) or {})
        pipeline = dict(audit.get("pipeline") or {})
        stages = [dict(item) for item in (pipeline.get("stages") or self._hard_audit_stage_template())]
        found = False
        for stage in stages:
            if str(stage.get("id") or "") == stage_id:
                stage["status"] = status
                stage["detail"] = detail
                stage["updated_at"] = int(time.time())
                found = True
                break
        if not found:
            stages.append(
                {
                    "id": stage_id,
                    "label": self.HARD_AUDIT_STAGE_LABELS.get(stage_id, stage_id.replace("_", " ").title()),
                    "status": status,
                    "detail": detail,
                    "updated_at": int(time.time()),
                }
            )
        pipeline["stages"] = stages
        pipeline["current_stage"] = stage_id
        if summary:
            pipeline["summary"] = summary
        if extra:
            pipeline.update(extra)
        audit["pipeline"] = pipeline
        self.hard_audit_cache[lead_id] = audit

    @staticmethod
    def _lead_mac_candidates(lead: Dict[str, Any]) -> List[str]:
        values = {
            str(lead.get("mac") or "").strip().lower(),
            str(lead.get("bssid") or "").strip().lower(),
            str(lead.get("associated_bssid") or "").strip().lower(),
            str(((lead.get("associated_network") or {}).get("bssid") or "")).strip().lower(),
        }
        return [value for value in values if value and ":" in value]

    @staticmethod
    def _gateway_ips() -> List[str]:
        try:
            result = subprocess.run(
                ["/usr/sbin/ip", "route"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except Exception:
            return []
        gateways: List[str] = []
        for raw in (result.stdout or "").splitlines():
            line = raw.strip()
            if not line.startswith("default via "):
                continue
            parts = line.split()
            if len(parts) >= 3:
                gateways.append(str(parts[2]).strip())
        return gateways

    @staticmethod
    def _neighbor_mac_for_ip(ip_value: str) -> str:
        arp_path = Path("/proc/net/arp")
        try:
            if arp_path.exists():
                for raw in arp_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                    parts = raw.split()
                    if len(parts) >= 4 and str(parts[0]).strip() == ip_value:
                        return str(parts[3]).strip().lower()
        except Exception:
            pass
        try:
            result = subprocess.run(
                ["/usr/sbin/ip", "neigh", "show", ip_value],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except Exception:
            return ""
        for raw in (result.stdout or "").splitlines():
            parts = raw.split()
            if "lladdr" in parts:
                index = parts.index("lladdr")
                if index + 1 < len(parts):
                    return str(parts[index + 1]).strip().lower()
        return ""

    def _validate_candidate_ips(self, lead: Dict[str, Any], candidate_ips: List[str]) -> Dict[str, Any]:
        gateways = set(self._gateway_ips())
        known_macs = set(self._lead_mac_candidates(lead))
        validated: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        for ip_value in [str(item).strip() for item in candidate_ips if str(item).strip()]:
            if ip_value in gateways:
                rejected.append({"ip": ip_value, "status": "invalid_target_ip", "confidence": 0.0, "reason": "gateway_ip", "neighbor_mac": ""})
                continue
            neighbor_mac = self._neighbor_mac_for_ip(ip_value)
            if neighbor_mac and known_macs and neighbor_mac not in known_macs:
                rejected.append({"ip": ip_value, "status": "rejected", "confidence": 0.1, "reason": f"mac_mismatch:{neighbor_mac}", "neighbor_mac": neighbor_mac})
                continue
            if neighbor_mac and known_macs and neighbor_mac in known_macs:
                validated.append({"ip": ip_value, "status": "validated", "confidence": 0.96, "reason": "mac_ip_match", "neighbor_mac": neighbor_mac})
                continue
            validated.append({"ip": ip_value, "status": "candidate", "confidence": 0.55, "reason": "routable_private_ip_without_neighbor_match", "neighbor_mac": neighbor_mac})
        return {"gateway_ips": sorted(gateways), "validated_candidates": validated, "rejected_candidates": rejected}

    @staticmethod
    def _extract_endpoint_set(lead: Dict[str, Any], analysis: Dict[str, Any] | None = None) -> Dict[str, Any]:
        video_evidence = dict(lead.get("video_evidence") or {})
        service_exposure = dict(lead.get("service_exposure") or {})
        stable = dict(lead.get("stable_fingerprint") or {})
        scenario = dict(lead.get("scenario_delta") or {})
        traffic_profile = dict(video_evidence.get("traffic_profile") or {})
        endpoints: List[str] = []
        for bucket in (
            list(traffic_profile.get("endpoints") or []),
            list(traffic_profile.get("new_endpoints") or []),
            list(service_exposure.get("cloud_endpoints") or []),
            list(stable.get("tls_server_names") or []),
            list(stable.get("quic_server_names") or []),
            list(stable.get("dns_query_names") or []),
            list(stable.get("related_domains") or []),
            list(scenario.get("cloud_endpoints") or []),
            list(((analysis or {}).get("analysis") or {}).get("cloud_endpoints") or []),
        ):
            for value in bucket:
                normalized = str(value or "").strip()
                if normalized and normalized not in endpoints:
                    endpoints.append(normalized)
        flow_duration = (
            float(traffic_profile.get("duration_seconds") or 0.0)
            or float((((lead.get("stream_state") or {}).get("metrics") or {}).get("duration_seconds") or 0.0))
            or float((((lead.get("behavior_analysis") or {}).get("flow_summary") or {}).get("duration_seconds") or 0.0))
        )
        byte_count = (
            int(traffic_profile.get("live_bytes") or 0)
            or int((((lead.get("stream_state") or {}).get("metrics") or {}).get("total_bytes") or 0))
            or int((((lead.get("behavior_analysis") or {}).get("flow_summary") or {}).get("total_bytes") or 0))
        )
        protocols: List[str] = []
        for value in list(service_exposure.get("protocols") or []) + list(((lead.get("stream_state") or {}).get("protocols") or [])):
            normalized = str(value or "").strip()
            if normalized and normalized not in protocols:
                protocols.append(normalized)
        return {
            "endpoints": endpoints[:12],
            "flow_duration_seconds": flow_duration,
            "byte_count": byte_count,
            "protocols": protocols[:8],
        }

    @staticmethod
    def _artifact_decision_from_evidence(lead: Dict[str, Any], probe: Dict[str, Any]) -> Dict[str, Any]:
        video_evidence = dict(lead.get("video_evidence") or {})
        local_stream = str(video_evidence.get("local_stream_available") or "no") == "yes"
        cloud_stream = str(video_evidence.get("cloud_stream_detected") or "no") == "yes"
        snapshot_hits = int(((probe.get("summary") or {}).get("snapshot_hits") or 0))
        rtsp_hits = int(((probe.get("summary") or {}).get("rtsp_hits") or 0))
        artifact_possible = local_stream or snapshot_hits > 0 or rtsp_hits > 0
        reason = str(video_evidence.get("artifact_reason") or "").strip()
        if artifact_possible:
            if snapshot_hits > 0:
                reason = "HTTP snapshot available"
            elif rtsp_hits > 0:
                reason = "RTSP available"
            else:
                reason = reason or "Local stream path available"
        elif cloud_stream:
            reason = reason or "ENCRYPTED_CLOUD_TRANSPORT"
        else:
            reason = reason or "No justified artifact path"
        return {
            "artifact_possible": artifact_possible,
            "reason": reason,
            "local_stream_available": local_stream,
            "cloud_stream_detected": cloud_stream,
        }

    @staticmethod
    def _xiaomi_family_profile(lead: Dict[str, Any], analysis: Dict[str, Any] | None = None) -> Dict[str, Any]:
        lead_blob = " ".join(
            [
                str(lead.get("vendor") or ""),
                str(lead.get("historical_identity_hint") or ""),
                " ".join(str(item) for item in (lead.get("related_identity_hints") or [])),
                str(((lead.get("camera_detection") or {}).get("family_match") or "")),
                str(((lead.get("stable_fingerprint") or {}).get("associated_network_ssid") or "")),
            ]
        ).lower()
        xiaomi_family = any(token in lead_blob for token in ("xiaomi", "mijia", "imilab", "chuangmi", "miap", "miio", "zhen shi"))
        model_hints = []
        for hint in [str(lead.get("historical_identity_hint") or "").strip(), *[str(item).strip() for item in (lead.get("related_identity_hints") or []) if str(item).strip()]]:
            lowered = hint.lower()
            if any(token in lowered for token in ("chuangmi", "camera", "miap", "ipc")) and hint not in model_hints:
                model_hints.append(hint)
        family_match = str(((lead.get("camera_detection") or {}).get("family_match") or "")).strip()
        if family_match and family_match not in model_hints:
            model_hints.append(family_match)
        endpoints = [
            *list(((lead.get("service_exposure") or {}).get("cloud_endpoints") or [])),
            *list((((analysis or {}).get("analysis") or {}).get("cloud_endpoints") or [])),
            *list(((lead.get("scenario_delta") or {}).get("cloud_endpoints") or [])),
        ]
        endpoint_blob = " ".join(str(item) for item in endpoints).lower()
        cloud_markers = []
        for marker in ("livestreaming.io.mi.com", "api.io.mi.com", "miio", "miiot", "xiaomi"):
            if marker in endpoint_blob and marker not in cloud_markers:
                cloud_markers.append(marker)
        if xiaomi_family and "api.io.mi.com" not in cloud_markers:
            cloud_markers.append("api.io.mi.com")
        expected_cloud_stack = []
        if xiaomi_family:
            expected_cloud_stack.extend(["Mi Home / Xiaomi Home app", "MIoT / miio control plane", "ephemeral cloud HLS or relay stream"])
        expected_local_paths = []
        if xiaomi_family:
            expected_local_paths.extend(["miio token / LAN API (model dependent)", "HTTP snapshot (conditional)", "RTSP usually absent unless firmware/custom model enables it"])
        firmware_notes = []
        if xiaomi_family:
            firmware_notes.extend(
                [
                    "Xiaomi cameras typically update through the Mi Home / Xiaomi Home app.",
                    "Older Chuangmi-family cameras are widely described as cloud-first and may expose no RTSP server in stock firmware.",
                    "Custom firmware exists for some Xiaomi camera families, but chipset and model support vary.",
                ]
            )
        return {
            "matched": xiaomi_family,
            "vendor_family": "xiaomi_chuangmi_imilab" if xiaomi_family else "",
            "model_hints": model_hints[:6],
            "cloud_markers": cloud_markers[:6],
            "expected_cloud_stack": expected_cloud_stack[:4],
            "expected_local_paths": expected_local_paths[:4],
            "firmware_notes": firmware_notes[:4],
            "recommended_next_steps": (
                [
                    "Look for Xiaomi token / Miio-style LAN control before assuming pure cloud lock-in.",
                    "Capture app-assisted live view and retain any Xiaomi cloud hostnames or HLS playlist references.",
                    "Treat absence of ONVIF/RTSP as expected for stock cloud-first firmware on this family.",
                ]
                if xiaomi_family
                else []
            ),
        }

    @staticmethod
    def _python_module_available(name: str) -> bool:
        try:
            return bool(importlib.util.find_spec(name))
        except Exception:
            return False

    def _xiaomi_local_api_test(self, target_ips: List[str]) -> Dict[str, Any]:
        ips = [str(item).strip() for item in target_ips if str(item).strip()][:2]
        dependencies = {
            "python_miio": self._python_module_available("miio"),
            "zeroconf": self._python_module_available("zeroconf"),
            "aiohttp": self._python_module_available("aiohttp"),
        }
        if not ips:
            return {
                "ok": False,
                "error": "no_target_ip",
                "dependencies": dependencies,
                "ports": {},
                "summary": "No target IP available for Xiaomi-family local API test.",
            }
        port_rows: Dict[str, Dict[str, Any]] = {}
        for ip_value in ips:
            try:
                result = subprocess.run(
                    ["nmap", "-Pn", "-sU", "-p", "54321,1900,3702,5353", ip_value],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except Exception as exc:
                port_rows[ip_value] = {"error": str(exc), "ports": {}}
                continue
            ports: Dict[str, Dict[str, str]] = {}
            for raw in (result.stdout or "").splitlines():
                line = raw.strip()
                if "/udp" not in line:
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                port_proto = parts[0]
                state = parts[1]
                service = parts[2]
                port = port_proto.split("/", 1)[0]
                ports[port] = {"state": state, "service": service}
            port_rows[ip_value] = {
                "ports": ports,
                "ok": result.returncode in {0, 1},
                "stdout_tail": (result.stdout or "").splitlines()[-20:],
                "stderr_tail": (result.stderr or "").splitlines()[-20:],
            }
        miio_surface = any(
            str(((entry.get("ports") or {}).get("54321") or {}).get("state") or "") in {"open", "open|filtered"}
            for entry in port_rows.values()
        )
        discovery_surface = any(
            str(((entry.get("ports") or {}).get(port) or {}).get("state") or "") in {"open", "open|filtered"}
            for entry in port_rows.values()
            for port in ("1900", "3702", "5353")
        )
        if miio_surface and dependencies["python_miio"]:
            summary = "UDP 54321 suggests MIIO / MIoT local transport is reachable."
        elif miio_surface:
            summary = "UDP 54321 suggests MIIO / MIoT local transport may be reachable, but python-miio is not installed locally."
        elif discovery_surface:
            summary = "Discovery ports are exposed, but MIIO transport was not confirmed."
        else:
            summary = "No Xiaomi-family local discovery surface was confirmed beyond normal host reachability."
        return {
            "ok": bool(miio_surface or discovery_surface),
            "dependencies": dependencies,
            "ports": port_rows,
            "miio_surface": miio_surface,
            "discovery_surface": discovery_surface,
            "summary": summary,
            "recommended_next_steps": (
                ["Install python-miio or equivalent tooling and test token-backed miIO.info against UDP 54321."]
                if miio_surface and not dependencies["python_miio"]
                else (
                    ["Attempt MIIO / MIoT token-backed local queries before assuming the device is cloud-only."]
                    if miio_surface
                    else ["Prioritize cloud/app-assisted capture because Xiaomi local discovery was not visible."]
                )
            ),
        }

    @staticmethod
    def _xiaomi_cloud_capture_plan(
        lead: Dict[str, Any],
        xiaomi_profile: Dict[str, Any],
        video_evidence: Dict[str, Any],
        traffic_intelligence: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not bool(xiaomi_profile.get("matched")):
            return {"matched": False, "summary": "No Xiaomi-family cloud capture plan was inferred."}

        correlation = dict(video_evidence.get("correlation") or {})
        flow_debug = dict(traffic_intelligence.get("debug") or {})
        endpoint_count = len(list(traffic_intelligence.get("endpoints") or []))
        phone_visible_stream = bool(correlation.get("flow_triggered_by_live_view"))
        likely_cloud_relay = bool(phone_visible_stream and endpoint_count <= 0)
        model_hints = list(xiaomi_profile.get("model_hints") or [])
        model_blob = " ".join(model_hints).lower()
        camera_model = (
            "chuangmi.camera.ipc019"
            if "ipc019" in model_blob
            else "chuangmi.camera.ipc009"
            if "ipc009" in model_blob
            else "chuangmi-family-camera"
        )
        host_patterns = [
            "livestreaming.io.mi.com",
            "processor.smartcamera.api.io.mi.com",
            "api.io.mi.com",
        ]
        stream_patterns = [
            "hlstranscoder/.../playlist.m3u8",
            "miot/camera/app/play/v1/video/file.mp4",
        ]
        return {
            "matched": True,
            "likely_cloud_relay": likely_cloud_relay,
            "camera_model_hint": camera_model,
            "phone_visible_stream": phone_visible_stream,
            "attributed_endpoint_count": endpoint_count,
            "packets_from_mac": int(flow_debug.get("packets_from_mac") or 0),
            "cloud_host_patterns": host_patterns,
            "cloud_stream_patterns": stream_patterns,
            "miot_action_hints": [
                {"siid": 4, "aiid": 1, "label": "camera-stream-for-google-home / stream start"},
            ],
            "required_artifacts": [
                "short-lived livestreaming.io.mi.com playlist URL",
                "service token / session-bound cloud auth context",
                "optional crypto+https segment URL, decryption key, and IV when Xiaomi returns encrypted media segments",
            ],
            "operator_capture_targets": [
                "Mi Home / Xiaomi Home app request that starts live view",
                "returned stream URL or media playlist",
                "follow-on media segment requests during active live view",
            ],
            "summary": (
                "Xiaomi-family live view is likely cloud-relayed. Recover the app-side cloud stream URL or token path; passive Wi-Fi capture of the camera alone is not enough."
                if likely_cloud_relay
                else "Xiaomi-family cloud stream path should still be validated from app-side evidence."
            ),
            "next_steps": [
                "Capture the phone-side Mi Home / Xiaomi Home traffic while live view is open.",
                "Look for livestreaming.io.mi.com or processor.smartcamera.api.io.mi.com responses.",
                "Retain the temporary playlist or file URL and any associated token or crypto parameters before they expire.",
            ],
        }

    @staticmethod
    def _build_video_truth(
        lead: Dict[str, Any],
        traffic_intelligence: Dict[str, Any],
        trigger_timestamp: float,
    ) -> Dict[str, Any]:
        video_evidence = dict(lead.get("video_evidence") or {})
        traffic_profile = dict(video_evidence.get("traffic_profile") or {})
        correlation = dict(video_evidence.get("correlation") or {})
        endpoints = list(traffic_intelligence.get("endpoints") or [])
        flows = list(traffic_intelligence.get("flows") or [])
        stream_flows = [flow for flow in flows if bool(flow.get("stream_candidate"))]
        truth_windows = dict(traffic_intelligence.get("truth_windows") or {})
        baseline_window = dict(truth_windows.get("baseline") or {})
        trigger_window = dict(truth_windows.get("trigger") or {})
        post_window = dict(truth_windows.get("post_trigger") or {})
        baseline_bytes = int((baseline_window.get("debug") or {}).get("bytes_total") or traffic_profile.get("baseline_bytes") or 0)
        live_bytes = int((trigger_window.get("debug") or {}).get("bytes_total") or 0) + int((post_window.get("debug") or {}).get("bytes_total") or 0)
        if live_bytes <= 0:
            live_bytes = int(traffic_profile.get("live_bytes") or 0)
        delta_bytes = max(0, live_bytes - baseline_bytes)
        baseline_duration = float(baseline_window.get("capture_window_seconds") or 0.0)
        live_duration = float(trigger_window.get("capture_window_seconds") or 0.0) + float(post_window.get("capture_window_seconds") or 0.0)
        if live_duration <= 0:
            live_duration = float(traffic_profile.get("duration_seconds") or 0.0)
        baseline_rate = (
            float((baseline_window.get("debug") or {}).get("packets_from_mac") or 0) / baseline_duration
            if baseline_duration > 0
            else float(traffic_profile.get("baseline_packet_rate_pps") or 0.0)
        )
        live_mac_packets = int((trigger_window.get("debug") or {}).get("packets_from_mac") or 0) + int((post_window.get("debug") or {}).get("packets_from_mac") or 0)
        live_rate = (float(live_mac_packets) / live_duration) if live_duration > 0 else float(traffic_profile.get("live_packet_rate_pps") or 0.0)
        baseline_bytes_per_sec = round((baseline_bytes / baseline_duration), 2) if baseline_duration > 0 else 0.0
        live_bytes_per_sec = round((live_bytes / live_duration), 2) if live_duration > 0 else 0.0
        top_flow = stream_flows[0] if stream_flows else (flows[0] if flows else {})
        flow_start = float(top_flow.get("first_seen") or 0.0)
        correlation_delay = round(max(0.0, flow_start - float(trigger_timestamp or 0.0)), 2) if flow_start and trigger_timestamp else None
        temporal_valid = bool(correlation_delay is not None and correlation_delay <= 5.0)
        delta_valid = bool(delta_bytes >= 300 * 1024 or live_bytes_per_sec >= max(32768.0, baseline_bytes_per_sec * 1.8))
        flow_valid = bool(stream_flows)
        endpoint_valid = bool(endpoints)
        mac_valid = bool((traffic_intelligence.get("debug") or {}).get("packets_from_mac") or 0)
        if delta_valid and flow_valid and endpoint_valid and temporal_valid and bool(correlation.get("flow_triggered_by_live_view")):
            video_confirmed = "YES"
        elif not mac_valid:
            video_confirmed = "INCONCLUSIVE"
        else:
            video_confirmed = "NO" if not delta_valid and not flow_valid else "INCONCLUSIVE"
        failure_reasons: List[str] = []
        if not delta_valid:
            failure_reasons.append("No significant traffic increase observed")
        if not mac_valid:
            failure_reasons.append("Unable to attribute flows to device MAC")
        if not temporal_valid:
            failure_reasons.append("No temporal correlation with live-view event")
        if not endpoint_valid:
            failure_reasons.append("No endpoint set retained")
        if not flow_valid:
            failure_reasons.append("No stream-like flow detected")
        return {
            "video_confirmed": video_confirmed,
            "correlation_confidence": float(correlation.get("correlation_confidence") or 0.0),
            "metrics": {
                "baseline_bytes_per_sec": baseline_bytes_per_sec,
                "live_bytes_per_sec": live_bytes_per_sec,
                "delta_bytes": delta_bytes,
                "flow_count": len(flows),
                "stream_flows_detected": len(stream_flows),
                "baseline_packet_rate_pps": round(baseline_rate, 2),
                "live_packet_rate_pps": round(live_rate, 2),
            },
            "flow_evidence": endpoints[:4],
            "timing": {
                "trigger_timestamp": float(trigger_timestamp or 0.0),
                "flow_start_timestamp": flow_start or 0.0,
                "correlation_delay_seconds": correlation_delay,
            },
            "truth_windows": {
                "baseline_packets_from_mac": int((baseline_window.get("debug") or {}).get("packets_from_mac") or 0),
                "trigger_packets_from_mac": int((trigger_window.get("debug") or {}).get("packets_from_mac") or 0),
                "post_trigger_packets_from_mac": int((post_window.get("debug") or {}).get("packets_from_mac") or 0),
            },
            "status_reason": (
                "Live-view correlation, MAC-attributed stream flow, and traffic delta confirm video."
                if video_confirmed == "YES"
                else (" · ".join(failure_reasons[:3]) if failure_reasons else "Video truth not established.")
            ),
        }

    def _extract_mac_flows_from_pcaps(self, lead: Dict[str, Any], pcap_inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
        tshark_path = self.capture.tshark_path
        if not tshark_path:
            return {
                "ok": False,
                "error": "tshark unavailable",
                "debug": {"total_packets": 0, "packets_from_mac": 0, "flows_built": 0, "bytes_total": 0},
                "flows": [],
                "endpoints": [],
                "capture_window_sufficient": False,
                "explanation": "Traffic analysis unavailable because tshark is not installed.",
            }
        macs = set(self._lead_mac_candidates(lead))
        if not macs:
            return {
                "ok": False,
                "error": "no_target_mac",
                "debug": {"total_packets": 0, "packets_from_mac": 0, "flows_built": 0, "bytes_total": 0},
                "flows": [],
                "endpoints": [],
                "capture_window_sufficient": False,
                "explanation": "No stable MAC was available for traffic analysis.",
            }
        pcap_paths = [
            str(entry.get("path") or "").strip()
            for entry in (pcap_inventory or [])[:8]
            if str(entry.get("path") or "").strip()
        ]
        total_packets = 0
        packets_from_mac = 0
        bytes_total = 0
        first_seen = None
        last_seen = None
        flows: Dict[str, Dict[str, Any]] = {}
        dns_map: Dict[str, str] = {}
        tls_map: Dict[str, str] = {}
        protocol_hits = {"broadcast_only": 0, "ip_packets": 0, "arp_packets": 0}
        arp_map: Dict[str, str] = {}

        for pcap_path in pcap_paths:
            try:
                total_result = subprocess.run(
                    [tshark_path, "-r", pcap_path, "-Y", "wlan", "-T", "fields", "-e", "frame.number"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except Exception:
                continue
            if total_result.returncode == 0:
                total_packets += len([line for line in (total_result.stdout or "").splitlines() if line.strip()])
            for mac_value in macs:
                try:
                    result = subprocess.run(
                        [
                            tshark_path,
                            "-r",
                            pcap_path,
                            "-Y",
                            f"(wlan.addr == {mac_value} or eth.addr == {mac_value}) and (ip or ipv6 or arp)",
                            "-T",
                            "fields",
                            "-E",
                            "header=n",
                            "-E",
                            "separator=\t",
                            "-e",
                            "frame.time_epoch",
                            "-e",
                            "wlan.sa",
                            "-e",
                            "wlan.da",
                            "-e",
                            "eth.src",
                            "-e",
                            "eth.dst",
                            "-e",
                            "ip.src",
                            "-e",
                            "ip.dst",
                            "-e",
                            "arp.src.proto_ipv4",
                            "-e",
                            "arp.dst.proto_ipv4",
                            "-e",
                            "tcp.srcport",
                            "-e",
                            "tcp.dstport",
                            "-e",
                            "udp.srcport",
                            "-e",
                            "udp.dstport",
                            "-e",
                            "frame.len",
                            "-e",
                            "frame.protocols",
                            "-e",
                            "dns.qry.name",
                            "-e",
                            "tls.handshake.extensions_server_name",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=25,
                        check=False,
                    )
                except Exception:
                    continue
                if result.returncode != 0:
                    continue
                for raw in (result.stdout or "").splitlines():
                    if not raw.strip():
                        continue
                    parts = raw.split("\t")
                    while len(parts) < 17:
                        parts.append("")
                    (
                        ts_text,
                        wlan_sa,
                        wlan_da,
                        eth_src,
                        eth_dst,
                        ip_src,
                        ip_dst,
                        arp_src_ip,
                        arp_dst_ip,
                        tcp_src,
                        tcp_dst,
                        udp_src,
                        udp_dst,
                        frame_len,
                        frame_protocols,
                        dns_name,
                        tls_sni,
                    ) = parts[:17]
                    packet_macs = {
                        str(wlan_sa or "").strip().lower(),
                        str(wlan_da or "").strip().lower(),
                        str(eth_src or "").strip().lower(),
                        str(eth_dst or "").strip().lower(),
                    }
                    if not (packet_macs & macs):
                        continue
                    packets_from_mac += 1
                    try:
                        ts_value = float(ts_text or 0.0)
                    except ValueError:
                        ts_value = 0.0
                    if ts_value > 0:
                        first_seen = ts_value if first_seen is None else min(first_seen, ts_value)
                        last_seen = ts_value if last_seen is None else max(last_seen, ts_value)
                    length_value = int(float(frame_len or 0))
                    bytes_total += max(0, length_value)
                    src_ip = str(ip_src or "").strip()
                    dst_ip = str(ip_dst or "").strip()
                    if not src_ip and str(arp_src_ip or "").strip():
                        src_ip = str(arp_src_ip).strip()
                    if not dst_ip and str(arp_dst_ip or "").strip():
                        dst_ip = str(arp_dst_ip).strip()
                    if str(arp_src_ip or "").strip() or str(arp_dst_ip or "").strip():
                        protocol_hits["arp_packets"] += 1
                        if self._is_routable_ip(src_ip):
                            sender_mac = str(wlan_sa or eth_src or "").strip().lower()
                            if sender_mac in macs:
                                arp_map["validated_ip"] = src_ip
                        if self._is_routable_ip(dst_ip):
                            receiver_mac = str(wlan_da or eth_dst or "").strip().lower()
                            if receiver_mac in macs and "validated_ip" not in arp_map:
                                arp_map["validated_ip"] = dst_ip
                    if not src_ip or not dst_ip:
                        protocol_hits["broadcast_only"] += 1
                        continue
                    protocol_hits["ip_packets"] += 1
                    src_port = str(tcp_src or udp_src or "").strip()
                    dst_port = str(tcp_dst or udp_dst or "").strip()
                    transport = "TCP" if (tcp_src or tcp_dst) else ("UDP" if (udp_src or udp_dst) else "IP")
                    frame_protocols_text = str(frame_protocols or "").lower()
                    if str(dst_port) == "443" or str(src_port) == "443" or str(tls_sni or "").strip() or "tls" in frame_protocols_text:
                        protocol = "TLS"
                    elif "quic" in frame_protocols_text:
                        protocol = "QUIC"
                    elif "dns" in frame_protocols_text:
                        protocol = "DNS"
                    elif "arp" in frame_protocols_text:
                        protocol = "ARP"
                    else:
                        protocol = transport
                    outbound = src_ip and (str(wlan_sa or eth_src or "").strip().lower() in macs)
                    endpoint_ip = dst_ip if outbound else src_ip
                    if dns_name and endpoint_ip:
                        dns_map[endpoint_ip] = str(dns_name).strip()
                    if tls_sni and endpoint_ip:
                        tls_map[endpoint_ip] = str(tls_sni).strip()
                    flow_key = "|".join([src_ip, dst_ip, src_port, dst_port, protocol])
                    flow = flows.setdefault(
                        flow_key,
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": protocol,
                            "transport": transport,
                            "direction": "outbound" if outbound else "inbound",
                            "packet_count": 0,
                            "total_bytes": 0,
                            "first_seen": ts_value or 0.0,
                            "last_seen": ts_value or 0.0,
                        },
                    )
                    flow["packet_count"] = int(flow.get("packet_count") or 0) + 1
                    flow["total_bytes"] = int(flow.get("total_bytes") or 0) + max(0, length_value)
                    flow["first_seen"] = min(float(flow.get("first_seen") or ts_value or 0.0), ts_value or float(flow.get("first_seen") or 0.0))
                    flow["last_seen"] = max(float(flow.get("last_seen") or ts_value or 0.0), ts_value or float(flow.get("last_seen") or 0.0))

        flow_list: List[Dict[str, Any]] = []
        endpoints: List[Dict[str, Any]] = []
        endpoint_index: Dict[str, Dict[str, Any]] = {}
        for flow in flows.values():
            duration = max(0.0, float(flow.get("last_seen") or 0.0) - float(flow.get("first_seen") or 0.0))
            packet_count = int(flow.get("packet_count") or 0)
            total_bytes_flow = int(flow.get("total_bytes") or 0)
            packet_rate = (packet_count / duration) if duration > 0 else float(packet_count)
            stream_candidate = bool(duration > 5.0 and total_bytes_flow >= 500 * 1024 and packet_rate >= 2.0)
            endpoint_ip = str(flow.get("dst_ip") if flow.get("direction") == "outbound" else flow.get("src_ip") or "").strip()
            endpoint_domain = tls_map.get(endpoint_ip) or dns_map.get(endpoint_ip) or ""
            rendered = {
                **flow,
                "duration_seconds": round(duration, 2),
                "packet_rate_pps": round(packet_rate, 2),
                "stream_candidate": stream_candidate,
                "endpoint_ip": endpoint_ip,
                "domain": endpoint_domain,
                "port": int(flow.get("dst_port") or flow.get("src_port") or 0) if str(flow.get("direction") or "") == "outbound" else int(flow.get("src_port") or flow.get("dst_port") or 0),
            }
            flow_list.append(rendered)
            if endpoint_ip:
                key = f"{endpoint_ip}|{rendered['port']}|{rendered['protocol']}"
                endpoint = endpoint_index.setdefault(
                    key,
                    {
                        "endpoint_ip": endpoint_ip,
                        "domain": endpoint_domain,
                        "port": rendered["port"],
                        "protocol": rendered["protocol"],
                        "total_bytes": 0,
                        "packet_count": 0,
                        "duration_seconds": 0.0,
                        "direction": rendered["direction"],
                        "stream_candidate": False,
                    },
                )
                endpoint["total_bytes"] = int(endpoint.get("total_bytes") or 0) + total_bytes_flow
                endpoint["packet_count"] = int(endpoint.get("packet_count") or 0) + packet_count
                endpoint["duration_seconds"] = max(float(endpoint.get("duration_seconds") or 0.0), duration)
                endpoint["stream_candidate"] = bool(endpoint.get("stream_candidate") or stream_candidate)
                if endpoint_domain and not endpoint.get("domain"):
                    endpoint["domain"] = endpoint_domain
        endpoints = sorted(endpoint_index.values(), key=lambda item: (int(item.get("total_bytes") or 0), float(item.get("duration_seconds") or 0.0)), reverse=True)
        validated_ip = str(arp_map.get("validated_ip") or "").strip()
        capture_window = max(0.0, (last_seen or 0.0) - (first_seen or 0.0)) if first_seen is not None and last_seen is not None else 0.0
        explanation = ""
        if packets_from_mac <= 0:
            explanation = "No traffic observed for target MAC during capture window."
        elif not flow_list:
            explanation = "Traffic was seen for target MAC but no IP flows were built."
        elif not endpoints and bytes_total < 1024:
            explanation = "Only minimal traffic was observed; endpoint extraction was not justified."
        elif not endpoints:
            explanation = "Traffic exists but endpoint extraction failed."
        else:
            explanation = f"{len(endpoints)} endpoints extracted from {len(flow_list)} flows."
        return {
            "ok": bool(endpoints) or packets_from_mac <= 0 or not flow_list,
            "flows": flow_list[:24],
            "endpoints": endpoints[:16],
            "validated_ip": validated_ip,
            "capture_window_sufficient": capture_window >= 20.0,
            "capture_window_seconds": round(capture_window, 2),
            "debug": {
                "total_packets": total_packets,
                "packets_from_mac": packets_from_mac,
                "flows_built": len(flow_list),
                "bytes_total": bytes_total,
                "broadcast_only_packets": int(protocol_hits.get("broadcast_only") or 0),
                "ip_packets": int(protocol_hits.get("ip_packets") or 0),
                "arp_packets": int(protocol_hits.get("arp_packets") or 0),
            },
            "explanation": explanation,
            "dns_map": dns_map,
            "tls_map": tls_map,
        }

    def _run_targeted_truth_capture(self, lead: Dict[str, Any], stage_id: str, seconds: int) -> Dict[str, Any]:
        bounded_seconds = max(4, min(20, int(seconds or 8)))
        channel = int(
            lead.get("channel")
            or ((lead.get("associated_network") or {}).get("channel") or 0)
            or 0
        )
        if channel <= 0:
            return {"ok": False, "error": "No stable channel available for targeted truth capture.", "stage": stage_id}
        sensor = self.prepare_sensor(self.scan_selected_interfaces)
        interface = str(sensor.get("monitor_interface") or "")
        if not interface:
            return {"ok": False, "error": "Monitor interface unavailable for targeted truth capture.", "stage": stage_id, "channel": channel}
        capture_result = self.capture.capture_channel(interface, channel, bounded_seconds * 1000)
        return {
            "ok": bool(capture_result.get("ok")),
            "stage": stage_id,
            "seconds": bounded_seconds,
            "interface": interface,
            "channel": channel,
            "pcap_path": str(capture_result.get("pcap_path") or ""),
            "frame_count": int(capture_result.get("frame_count") or 0),
            "error": str(capture_result.get("error") or ""),
        }

    def _persist_behavioral_video_proof_artifact(
        self,
        lead_id: str,
        lead: Dict[str, Any],
        video_truth: Dict[str, Any],
        traffic_intelligence: Dict[str, Any],
        targeted_truth_captures: List[Dict[str, Any]],
    ) -> str:
        artifact_dir = self.root_dir / "evidence" / "camera_protocol"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        safe_id = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in str(lead_id or "lead")).strip("_") or "lead"
        artifact_path = artifact_dir / f"{int(time.time())}_{safe_id}_behavioral_video_proof.json"
        payload = {
            "lead_id": lead_id,
            "identity": str(lead.get("ssid") or lead.get("mac") or lead.get("bssid") or lead.get("record_id") or "<unknown>"),
            "mac": str(lead.get("mac") or ""),
            "associated_bssid": str(lead.get("associated_bssid") or ""),
            "associated_ssid": str(lead.get("associated_ssid") or ""),
            "historical_identity_hint": str(lead.get("historical_identity_hint") or ""),
            "video_evidence": dict(lead.get("video_evidence") or {}),
            "video_truth": video_truth,
            "traffic_intelligence": {
                "explanation": str(traffic_intelligence.get("explanation") or ""),
                "validated_ip": str(traffic_intelligence.get("validated_ip") or ""),
                "endpoint_count": len(list(traffic_intelligence.get("endpoints") or [])),
                "flow_count": len(list(traffic_intelligence.get("flows") or [])),
                "debug": dict(traffic_intelligence.get("debug") or {}),
            },
            "targeted_truth_captures": [
                {
                    "stage": str(item.get("stage") or ""),
                    "seconds": int(item.get("seconds") or 0),
                    "channel": int(item.get("channel") or 0),
                    "interface": str(item.get("interface") or ""),
                    "pcap_path": str(item.get("pcap_path") or ""),
                    "frame_count": int(item.get("frame_count") or 0),
                    "ok": bool(item.get("ok")),
                    "error": str(item.get("error") or ""),
                }
                for item in targeted_truth_captures
            ],
        }
        artifact_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return str(artifact_path)

    def _run_decrypt_followup(self, pcaps: List[str]) -> Dict[str, Any]:
        selected = []
        for raw in pcaps:
            path = str(raw or "").strip()
            if not path or path in selected:
                continue
            if Path(path).exists():
                selected.append(path)
        if not selected:
            return {
                "ok": False,
                "error": "no_pcaps",
                "pcap_count": 0,
                "saved_image_count": 0,
                "saved_images": [],
            }
        script_path = self.root_dir / "scripts" / "ghostrecon_decrypt_test.py"
        if not script_path.exists():
            return {
                "ok": False,
                "error": "decrypt_script_missing",
                "pcap_count": len(selected),
                "saved_image_count": 0,
                "saved_images": [],
            }
        started = time.time()
        cmd = ["python3", str(script_path), "--timeout", "90"]
        for path in selected:
            cmd.extend(["--pcap", path])
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        decrypt_root = self.root_dir / "evidence" / "decrypt_test_runs"
        run_dir = None
        if decrypt_root.exists():
            candidates = []
            for candidate in decrypt_root.iterdir():
                if not candidate.is_dir():
                    continue
                try:
                    if candidate.stat().st_mtime >= started - 2:
                        candidates.append(candidate)
                except OSError:
                    continue
            if candidates:
                run_dir = max(candidates, key=lambda item: item.stat().st_mtime)
        summary: Dict[str, Any] = {
            "ok": result.returncode == 0,
            "returncode": int(result.returncode),
            "pcap_count": len(selected),
            "saved_image_count": 0,
            "saved_images": [],
            "run_dir": str(run_dir) if run_dir else "",
            "stdout_tail": (result.stdout or "").splitlines()[-20:],
            "stderr_tail": (result.stderr or "").splitlines()[-20:],
        }
        if run_dir:
            report_path = run_dir / "decrypt_report.json"
            summary["report_path"] = str(report_path)
            if report_path.exists():
                try:
                    payload = json.loads(report_path.read_text(encoding="utf-8"))
                except Exception:
                    payload = {}
                saved_images = [str(item).strip() for item in (payload.get("saved_images") or []) if str(item).strip()]
                summary["saved_images"] = saved_images
                summary["saved_image_count"] = len(saved_images)
        return summary

    def _effective_capture_active(self) -> bool:
        pipeline_active = bool((self.pipeline.status() or {}).get("active"))
        processing_running = bool((self.processing_pipeline.status() or {}).get("running"))
        scan_thread_alive = bool(self.scan_thread and self.scan_thread.is_alive())
        effective = bool(self.capture_active and (pipeline_active or processing_running or scan_thread_alive))
        if not effective and self.capture_active:
            self.capture_active = False
            self.current_channel = None
            if not processing_running and not pipeline_active and not scan_thread_alive:
                self.armed = False
        return effective

    def _offline_evidence_feature(self) -> Dict[str, Any]:
        gui_config = (get_project_config().get("gui") or {})
        raw = ((gui_config.get("wifiMk7Features") or {}).get("offlineEvidenceAnalysis") or {})
        enabled = bool(raw.get("enabled"))
        warning = str(
            raw.get("warning")
            or "Offline authentication-evidence analysis is limited to approved .pcap/.pcapng files."
        )
        audit_log = str(raw.get("auditLog") or "logs/wifi_mk7/imported_capture_audit.jsonl")
        return {
            "enabled": enabled,
            "warning": warning,
            "audit_log": audit_log,
        }

    def _external_destination_feature(self) -> Dict[str, Any]:
        return self.destination_analysis.feature_status()

    def _record_error(self, message: str) -> None:
        if message:
            self.last_error = str(message)

    def _toolchain_status(self) -> Dict[str, Any]:
        capture_tools = self.capture.tool_status()
        pipeline_status = self.pipeline.status()
        processing_status = self.processing_pipeline.status()
        effective_capture_active = self._effective_capture_active()
        processing_running = bool(processing_status.get("running"))
        zeek_enabled = bool(processing_status.get("limits", {}).get("zeek_enabled"))
        collector_status = {item["name"]: item for item in pipeline_status.get("collectors", [])}
        assignments = pipeline_status.get("assignments") or {}
        sensor_control = [
            {
                "name": "iw",
                "available": capture_tools["iw"]["available"],
                "path": capture_tools["iw"]["path"],
                "active": effective_capture_active,
                "role": "channel control",
            },
        ]
        packet_capture = [
            {
                "name": "dumpcap",
                "available": capture_tools["dumpcap"]["available"],
                "path": capture_tools["dumpcap"]["path"],
                "active": effective_capture_active,
                "role": "rolling pcap capture",
                "interfaces": self.scan_selected_interfaces or [],
            },
            {
                "name": "tshark",
                "available": capture_tools["tshark"]["available"],
                "path": capture_tools["tshark"]["path"],
                "active": processing_running or effective_capture_active,
                "role": "packet decode and field extraction",
            },
            {
                "name": "zeek",
                "available": bool(self.enricher.status().get("zeek_available")),
                "path": "zeek",
                "active": processing_running and zeek_enabled and bool(self.scan_camera_hunt or self.scan_deep_packet_enrichment),
                "role": "pcap enrichment and service inventory",
            },
        ]
        external_tools = [
            {
                "name": "airodump-ng",
                "available": bool((collector_status.get("airodump-ng") or {}).get("available")),
                "path": (collector_status.get("airodump-ng") or {}).get("path", ""),
                "active": bool((collector_status.get("airodump-ng") or {}).get("active")),
                "pid": (collector_status.get("airodump-ng") or {}).get("pid"),
                "started_at": (collector_status.get("airodump-ng") or {}).get("started_at"),
                "stopped_at": (collector_status.get("airodump-ng") or {}).get("stopped_at"),
                "last_stop_state": (collector_status.get("airodump-ng") or {}).get("last_stop_state", "idle"),
                "role": "RF scanner",
                "integration_state": "active" if bool((collector_status.get("airodump-ng") or {}).get("active")) else "additive_pipeline_ready",
                "interface": assignments.get("airodump-ng", ""),
            },
            {
                "name": "kismet",
                "available": bool((collector_status.get("kismet") or {}).get("available")),
                "path": (collector_status.get("kismet") or {}).get("path", ""),
                "active": bool((collector_status.get("kismet") or {}).get("active")),
                "pid": (collector_status.get("kismet") or {}).get("pid"),
                "started_at": (collector_status.get("kismet") or {}).get("started_at"),
                "stopped_at": (collector_status.get("kismet") or {}).get("stopped_at"),
                "last_stop_state": (collector_status.get("kismet") or {}).get("last_stop_state", "idle"),
                "role": "device intelligence",
                "integration_state": "active" if bool((collector_status.get("kismet") or {}).get("active")) else "additive_pipeline_ready",
                "interface": assignments.get("kismet", ""),
            },
            {
                "name": "bettercap",
                "available": bool((collector_status.get("bettercap") or {}).get("available")),
                "path": (collector_status.get("bettercap") or {}).get("path", ""),
                "active": bool((collector_status.get("bettercap") or {}).get("active")),
                "pid": (collector_status.get("bettercap") or {}).get("pid"),
                "started_at": (collector_status.get("bettercap") or {}).get("started_at"),
                "stopped_at": (collector_status.get("bettercap") or {}).get("stopped_at"),
                "last_stop_state": (collector_status.get("bettercap") or {}).get("last_stop_state", "idle"),
                "role": "live recon/events",
                "integration_state": "active" if bool((collector_status.get("bettercap") or {}).get("active")) else "additive_pipeline_ready",
                "interface": assignments.get("bettercap", ""),
            },
        ]
        runtime_apps = [*sensor_control, *packet_capture, *external_tools]
        active_runtime_apps = [tool for tool in runtime_apps if tool.get("active")]
        return {
            "sensor_control": sensor_control,
            "packet_capture": packet_capture,
            "external_tools": external_tools,
            "analysis_pipeline": [
                {"name": "frame_parser", "active": True, "role": "802.11 frame normalization"},
                {"name": "wifi_device_tracker", "active": True, "role": "device memory and flow tracking"},
                {"name": "camera_intelligence_engine", "active": True, "role": "camera scoring"},
            ],
            "processing_pipeline": processing_status,
            "runtime_summary": {
                "active_count": len(active_runtime_apps),
                "active_names": [str(tool.get("name") or "") for tool in active_runtime_apps],
                "all_stopped": not active_runtime_apps and not effective_capture_active and not processing_running,
                "cleanup_state": "idle"
                if not active_runtime_apps and not effective_capture_active and not processing_running
                else ("capture_active" if effective_capture_active else "runtime_drain"),
            },
            "summary": pipeline_status.get("summary") or "Automated path uses iw + dumpcap + tshark and additive camera-hunt collectors when enabled.",
        }

    def prepare_sensor(self, interfaces: List[str] | None = None) -> Dict[str, Any]:
        self.sensor_snapshot = self.monitor.ensure_monitor_interfaces(interfaces)
        if not self.sensor_snapshot.get("monitor_interface") and not self.sensor_snapshot.get("monitor_interfaces"):
            self.last_error = self.sensor_snapshot.get("detail") or "Failed to prepare monitor interface."
        return self.sensor_snapshot

    def start(
        self,
        auto_scan: bool = True,
        bands: List[str] | None = None,
        dwell_ms: int = 250,
        duration_seconds: int = 60,
        scan_mode: str = "broad",
        scan_scenario: str = "passive_observation",
        locked_channels: List[int] | None = None,
        interfaces: List[str] | None = None,
        deep_packet_enrichment: bool = False,
        camera_hunt: bool = False,
        processing_enabled: bool = True,
    ) -> Dict[str, Any]:
        sensor = self.prepare_sensor(interfaces)
        if not sensor.get("monitor_interface") and not sensor.get("monitor_interfaces"):
            return {"status": "unavailable", "error": sensor.get("detail") or "Monitor interface unavailable.", "sensor": sensor}
        if self._effective_capture_active():
            return {
                "status": "scan_in_progress",
                "sensor": sensor,
                "error": "A WiFi MK7 scan is already running.",
                "scan": self._scan_status_payload(),
            }
        self.armed = True
        self.capture_active = False
        self.last_started_at = time.time()
        self.last_error = ""
        self.scan_mode = str(scan_mode or "broad")
        self.scan_scenario = str(scan_scenario or "passive_observation")
        self.scan_locked_channels = [int(channel) for channel in (locked_channels or [])]
        self.scan_selected_interfaces = [str(item).strip() for item in (interfaces or []) if str(item).strip()]
        self.scan_deep_packet_enrichment = bool(deep_packet_enrichment)
        self.scan_camera_hunt = bool(camera_hunt)
        self.scan_processing_enabled = bool(processing_enabled)
        self.clear_results()
        self.scan_mode = str(scan_mode or "broad")
        self.scan_scenario = str(scan_scenario or "passive_observation")
        self.scan_locked_channels = [int(channel) for channel in (locked_channels or [])]
        self.scan_selected_interfaces = [str(item).strip() for item in (interfaces or []) if str(item).strip()]
        self.scan_deep_packet_enrichment = bool(deep_packet_enrichment)
        self.scan_camera_hunt = bool(camera_hunt)
        self.scan_processing_enabled = bool(processing_enabled)
        if auto_scan:
            self.start_background_scan(
                bands=bands or ["2.4ghz", "5ghz"],
                dwell_ms=dwell_ms,
                duration_seconds=duration_seconds,
                scan_mode=self.scan_mode,
                scan_scenario=self.scan_scenario,
                locked_channels=self.scan_locked_channels,
                interfaces=self.scan_selected_interfaces,
                deep_packet_enrichment=self.scan_deep_packet_enrichment,
                camera_hunt=self.scan_camera_hunt,
                processing_enabled=self.scan_processing_enabled,
            )
            return {
                "status": "started_and_scanning",
                "sensor": sensor,
                "auto_scan": True,
                "scan": self._scan_status_payload(),
            }
        return {"status": "armed", "sensor": sensor, "auto_scan": False}

    def stop(self) -> Dict[str, Any]:
        if self._effective_capture_active():
            self.stop_requested = True
            self.armed = False
            self.capture_active = False
            self.current_channel = None
            self.pipeline.stop()
            self.processing_pipeline.stop()
            self.tracker.flush_history(force=True)
            return {"status": "stopping", "scan": self._scan_status_payload()}
        self.armed = False
        self.capture_active = False
        self.current_channel = None
        self.pipeline.stop()
        self.processing_pipeline.stop()
        self.tracker.flush_history(force=True)
        return {"status": "stopped"}

    def clear_results(self) -> Dict[str, Any]:
        with self.scan_lock:
            self.tracker.flush_history(force=True)
            self.tracker.reset()
            self.pipeline.clear()
            self.processing_pipeline.stop()
            self.last_scan_summary = {}
            self.active_probe_cache = {}
            self.hard_audit_cache = {}
            self.service_audit_cache = {}
            self.destination_analysis_cache = {}
            self.auto_probe_summary = {"enabled": True, "attempted": 0, "positive": 0, "probed_leads": []}
            self.last_pps = 0.0
            self.last_error = ""
            self.stop_requested = False
            self.capture_active = False
            self.current_channel = None
            self.scan_thread = None
            self.scan_started_at = None
            self.scan_target_seconds = 0
            self.scan_elapsed_seconds = 0.0
            self.scan_progress_percent = 0.0
            self.scan_completed_channels = 0
            self.scan_total_channels = 0
            self.scan_cycle = 0
            self.channel_statistics = {}
            self.scan_scenario = "passive_observation"
            self.scan_camera_hunt = False
            self.ddi_cache = {}
            self.camera_hunt_results_cache = {"built_at": 0.0, "results": None}
            self.fallback_ingest_count = 0
            self.last_fallback_ingest = {}
            self._invalidate_target_snapshot_cache()
            self.evidence.reset()
        return {"status": "cleared"}

    def start_background_scan(
        self,
        bands: List[str] | None = None,
        dwell_ms: int = 250,
        duration_seconds: int = 60,
        scan_mode: str = "broad",
        scan_scenario: str = "passive_observation",
        locked_channels: List[int] | None = None,
        interfaces: List[str] | None = None,
        deep_packet_enrichment: bool = False,
        camera_hunt: bool = False,
        processing_enabled: bool = True,
    ) -> Dict[str, Any]:
        if self._effective_capture_active():
            return {"status": "scan_in_progress", "scan": self._scan_status_payload()}

        self.stop_requested = False
        self.capture_active = True
        self.scan_processing_enabled = bool(processing_enabled)
        if self.scan_processing_enabled:
            self.processing_pipeline.start(
                enrichment_enabled=bool(self.scan_deep_packet_enrichment),
                camera_hunt=bool(self.scan_camera_hunt),
                enable_zeek=bool(self.resource_policy.get("enable_zeek", True)),
                enrichment_sample_rate=int(self.resource_policy.get("enrichment_sample_rate") or 1),
                max_enrichment_pcap_bytes=int(self.resource_policy.get("max_enrichment_pcap_bytes") or 0),
            )
        self.scan_started_at = time.time()
        self.scan_target_seconds = max(60, int(duration_seconds))
        self.scan_elapsed_seconds = 0.0
        self.scan_progress_percent = 0.0
        self.scan_completed_channels = 0
        self.scan_cycle = 0
        self.scan_mode = scan_mode
        self.scan_scenario = str(scan_scenario or "passive_observation")
        self.scan_locked_channels = [int(channel) for channel in (locked_channels or [])]
        self.scan_selected_interfaces = [str(item).strip() for item in (interfaces or []) if str(item).strip()]
        self.scan_deep_packet_enrichment = bool(deep_packet_enrichment)
        self.scan_camera_hunt = bool(camera_hunt)
        self.scan_processing_enabled = bool(processing_enabled)
        self.intelligence.set_scan_context(
            scenario=self.scan_scenario,
            camera_hunt=self.scan_camera_hunt,
            scan_mode=self.scan_mode,
            started_at=self.scan_started_at,
        )
        self.ddi_cache = {}
        plan = self.hopper.build_plan(
            bands=bands,
            dwell_ms=dwell_ms,
            locked_channels=self.scan_locked_channels,
            scan_mode=self.scan_mode,
        )
        self.scan_total_channels = len(plan)

        self.scan_thread = threading.Thread(
            target=self._run_background_scan,
            kwargs={
                "bands": bands or ["2.4ghz", "5ghz"],
                "dwell_ms": dwell_ms,
                "duration_seconds": self.scan_target_seconds,
                "scan_mode": self.scan_mode,
                "scan_scenario": self.scan_scenario,
                "locked_channels": self.scan_locked_channels,
                "interfaces": self.scan_selected_interfaces,
                "deep_packet_enrichment": self.scan_deep_packet_enrichment,
                "camera_hunt": self.scan_camera_hunt,
                "processing_enabled": self.scan_processing_enabled,
            },
            daemon=True,
        )
        self.scan_thread.start()
        return {"status": "started", "scan": self._scan_status_payload()}

    def _scan_status_payload(self) -> Dict[str, Any]:
        return {
            "started_at": self.scan_started_at,
            "target_seconds": self.scan_target_seconds,
            "elapsed_seconds": round(self.scan_elapsed_seconds, 1),
            "progress_percent": round(self.scan_progress_percent, 1),
            "completed_channels": self.scan_completed_channels,
            "total_channels": self.scan_total_channels,
            "cycle": self.scan_cycle,
            "stop_requested": self.stop_requested,
            "mode": self.scan_mode,
            "scenario": self.scan_scenario,
            "locked_channels": self.scan_locked_channels,
            "interfaces": self.scan_selected_interfaces,
            "deep_packet_enrichment": self.scan_deep_packet_enrichment,
            "camera_hunt": self.scan_camera_hunt,
            "processing_enabled": self.scan_processing_enabled,
        }

    def _finalize_scan(self, result: Dict[str, Any]) -> Dict[str, Any]:
        self.pipeline.stop()
        self.processing_pipeline.stop()
        self.tracker.flush_history(force=True)
        self._normalize_evidence_session()
        self.evidence.finalize_session(handshake_session_count=int((self.tracker.get_authentication_evidence() or {}).get("session_count") or 0))
        self.last_scan_summary = result
        self.last_sweep_at = time.time()
        self.capture_active = False
        self.current_channel = None
        self.armed = False
        self.scan_thread = None
        self.scan_elapsed_seconds = min(self.scan_elapsed_seconds, float(self.scan_target_seconds or self.scan_elapsed_seconds))
        self.scan_progress_percent = min(100.0, self.scan_progress_percent or 100.0)
        self.camera_hunt_results_cache = {"built_at": 0.0, "results": None}
        self._invalidate_target_snapshot_cache()
        return result

    def _run_background_scan(
        self,
        bands: List[str],
        dwell_ms: int,
        duration_seconds: int,
        scan_mode: str,
        scan_scenario: str,
        locked_channels: List[int],
        interfaces: List[str],
        deep_packet_enrichment: bool,
        camera_hunt: bool,
        processing_enabled: bool,
    ) -> None:
        try:
            result = self.sweep(
                bands=bands,
                dwell_ms=dwell_ms,
                duration_seconds=duration_seconds,
                scan_mode=scan_mode,
                scan_scenario=scan_scenario,
                locked_channels=locked_channels,
                interfaces=interfaces,
                deep_packet_enrichment=deep_packet_enrichment,
                camera_hunt=camera_hunt,
                processing_enabled=processing_enabled,
            )
        except Exception as exc:
            detail = f"{exc.__class__.__name__}: {exc}"
            self.last_error = detail
            result = {
                "status": "scan_failed",
                "error": detail,
                "traceback": traceback.format_exc(limit=12),
                "scan": self._scan_status_payload(),
                "camera_hunt": bool(camera_hunt),
                "processing_pipeline": self.processing_pipeline.status(),
                "camera_hunt_results": self.get_camera_hunt_results() if camera_hunt else {"count": 0, "leads": []},
            }
        self._finalize_scan(result)

    @staticmethod
    def _partition_plan(plan: List[Dict[str, Any]], monitor_interfaces: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        assignments = {interface: [] for interface in monitor_interfaces}
        if not monitor_interfaces:
            return assignments
        for index, entry in enumerate(plan):
            assignments[monitor_interfaces[index % len(monitor_interfaces)]].append(entry)
        return assignments

    def _hot_channels(self) -> List[int]:
        ranked = sorted(
            self.channel_statistics.items(),
            key=lambda item: (int((item[1] or {}).get("frames") or 0), int((item[1] or {}).get("hits") or 0)),
            reverse=True,
        )
        return [int(channel) for channel, stats in ranked if int((stats or {}).get("frames") or 0) > 0][:6]

    def _build_cycle_plan(
        self,
        bands: List[str],
        dwell_ms: int,
        scan_mode: str,
        locked_channels: List[int] | None,
    ) -> List[Dict[str, Any]]:
        hot_channels = self._hot_channels() if scan_mode in {"adaptive", "adaptive_residential_dfs", "adaptive_handshake_hunt"} and self.scan_cycle >= 1 else []
        return self.hopper.build_plan(
            bands=bands,
            dwell_ms=dwell_ms,
            locked_channels=locked_channels,
            hot_channels=hot_channels,
            channel_activity=self.tracker.get_channel_activity(),
            scan_mode=scan_mode,
        )

    def _ingest_capture_without_pipeline(self, entry: Dict[str, Any], result: Dict[str, Any]) -> None:
        channel = int(entry.get("channel") or 0)
        band = str(entry.get("band") or "")
        pcap_path = str(result.get("pcap_path") or "")
        frames = list(result.get("frames") or [])
        with self.tracker_lock:
            self.tracker.ingest_capture(channel, band, pcap_path, frames)
        self.fallback_ingest_count += 1
        self.last_fallback_ingest = {
            "channel": channel,
            "band": band,
            "pcap_path": pcap_path,
            "frame_count": len(frames),
            "captured_at": time.time(),
        }

    def _normalize_evidence_session(self) -> None:
        session = self.evidence.current_session or {}
        if not session:
            return
        if str(session.get("session_dir") or "").strip():
            return
        session_id = str(session.get("session_id") or "").strip()
        if not session_id:
            return
        session["session_dir"] = str(self.evidence.evidence_root / session_id)
        notes = list(session.get("notes") or [])
        notes.append("session_dir_missing: recovered in mk7_controller")
        session["notes"] = notes[-8:]
        self.evidence.current_session = session

    def _ensure_evidence_session_started(self) -> Dict[str, Any]:
        session_manifest = self.evidence.session_manifest()
        if session_manifest.get("session_id") or (self.evidence.current_session or {}).get("session_id"):
            return session_manifest or dict(self.evidence.current_session or {})
        if not (self._effective_capture_active() or self.armed):
            return {}
        monitor_interfaces = list((self.sensor_snapshot or {}).get("monitor_interfaces") or [])
        monitor_interface = str((self.sensor_snapshot or {}).get("monitor_interface") or "").strip()
        if monitor_interface and monitor_interface not in monitor_interfaces:
            monitor_interfaces.append(monitor_interface)
        self.evidence.start_session(
            adapter_identifier=",".join(monitor_interfaces),
            bands=list(self.scan_selected_interfaces or []) or ["2.4ghz", "5ghz"],
            dwell_ms=0,
            duration_seconds=int(self.scan_target_seconds or 0),
            scan_mode=str(self.scan_mode or "broad"),
            scan_scenario=str(self.scan_scenario or "passive_observation"),
            locked_channels=[int(channel) for channel in (self.scan_locked_channels or [])],
            interfaces=monitor_interfaces,
            deep_packet_enrichment=bool(self.scan_deep_packet_enrichment),
            camera_hunt=bool(self.scan_camera_hunt),
        )
        return self.evidence.session_manifest()

    def sweep(
        self,
        bands: List[str] | None = None,
        dwell_ms: int = 250,
        duration_seconds: int | None = None,
        scan_mode: str = "broad",
        scan_scenario: str = "passive_observation",
        locked_channels: List[int] | None = None,
        interfaces: List[str] | None = None,
        deep_packet_enrichment: bool = False,
        camera_hunt: bool = False,
        processing_enabled: bool = True,
    ) -> Dict[str, Any]:
        if not self.armed:
            return {"status": "idle", "error": "Start Session first to arm the WiFi capture pipeline."}

        band_selection = bands or ["2.4ghz", "5ghz"]
        self.scan_scenario = str(scan_scenario or self.scan_scenario or "passive_observation")
        self.intelligence.set_scan_context(
            scenario=self.scan_scenario,
            camera_hunt=bool(camera_hunt),
            scan_mode=scan_mode,
            started_at=self.scan_started_at or time.time(),
        )
        sensor = self.prepare_sensor(interfaces)
        monitor_interfaces = [item for item in (sensor.get("monitor_interfaces") or []) if item]
        if sensor.get("monitor_interface") and sensor.get("monitor_interface") not in monitor_interfaces:
            monitor_interfaces.insert(0, sensor.get("monitor_interface"))
        if not monitor_interfaces:
            return {"status": "unavailable", "error": sensor.get("detail") or "Monitor interface unavailable.", "sensor": sensor}
        core_interfaces = [monitor_interfaces[0]]
        pipeline_interfaces: List[str] = []
        if camera_hunt and not self.single_adapter_policy and len(monitor_interfaces) > 1:
            pipeline_interfaces = monitor_interfaces[1:]
        if self.single_adapter_policy and processing_enabled:
            if camera_hunt:
                self.pipeline.begin_single_adapter_session(
                    core_interfaces[0],
                    band_selection,
                    int(duration_seconds or self.scan_target_seconds or 60),
                    enabled_collectors=self._enabled_pipeline_collectors(),
                    airodump_write_interval_seconds=int(self.resource_policy.get("airodump_write_interval_seconds") or 1),
                )
            else:
                self.pipeline.begin_single_adapter_recon(
                    core_interfaces[0],
                    band_selection,
                    int(duration_seconds or self.scan_target_seconds or 60),
                    enabled_collectors=self._enabled_pipeline_collectors(),
                    airodump_write_interval_seconds=int(self.resource_policy.get("airodump_write_interval_seconds") or 1),
                )
            phase_result = self.pipeline.run_single_adapter_phase("airodump-ng")
            if phase_result.get("error"):
                self.last_error = str(phase_result.get("error"))
            self.pipeline.mark_core_capture_phase(True, 0.0)
        elif processing_enabled and camera_hunt and pipeline_interfaces and not self.pipeline.status().get("active"):
            pipeline_result = self.pipeline.start(
                pipeline_interfaces,
                band_selection,
                enabled_collectors=self._enabled_pipeline_collectors(),
                airodump_write_interval_seconds=int(self.resource_policy.get("airodump_write_interval_seconds") or 1),
            )
            if pipeline_result.get("errors"):
                self.last_error = "; ".join(pipeline_result["errors"])

        plan = self._build_cycle_plan(band_selection, dwell_ms, scan_mode, locked_channels)
        if not plan:
            return {"status": "invalid", "error": "No WiFi channel plan selected."}

        self.capture_active = True
        self.evidence.start_session(
            adapter_identifier=",".join(core_interfaces),
            bands=band_selection,
            dwell_ms=int(dwell_ms or 0),
            duration_seconds=int(duration_seconds or self.scan_target_seconds or 0),
            scan_mode=str(scan_mode or "broad"),
            scan_scenario=self.scan_scenario,
            locked_channels=[int(channel) for channel in (locked_channels or [])],
            interfaces=monitor_interfaces,
            deep_packet_enrichment=bool(deep_packet_enrichment),
            camera_hunt=bool(camera_hunt),
        )
        self.last_error = ""
        started = time.time()
        total_frames = 0
        completed: List[Dict[str, Any]] = []
        success_count = 0
        successful_channels: set[int] = set()
        failed_count = 0
        deadline = started + max(1, int(duration_seconds or 0)) if duration_seconds else None

        while True:
            self.scan_cycle += 1
            cycle_plan = self._build_cycle_plan(band_selection, dwell_ms, scan_mode, locked_channels)
            assignments = self._partition_plan(cycle_plan, core_interfaces)
            max_steps = max((len(entries) for entries in assignments.values()), default=0)

            for step_index in range(max_steps):
                if self.stop_requested:
                    break
                if deadline and time.time() >= deadline:
                    break

                batch_results: List[Dict[str, Any]] = []
                workers: List[threading.Thread] = []

                def capture_one(interface_name: str, plan_entry: Dict[str, Any]) -> None:
                    result = self.capture.capture_channel(interface_name, int(plan_entry["channel"]), int(plan_entry["dwell_ms"]))
                    batch_results.append({"interface": interface_name, "entry": plan_entry, "result": result})

                for interface_name, entries in assignments.items():
                    if step_index >= len(entries):
                        continue
                    worker = threading.Thread(target=capture_one, args=(interface_name, entries[step_index]), daemon=True)
                    worker.start()
                    workers.append(worker)

                for worker in workers:
                    worker.join()

                for batch in batch_results:
                    entry = batch["entry"]
                    result = batch["result"]
                    channel = int(entry["channel"])
                    self.current_channel = channel
                    self.scan_completed_channels += 1
                    self.scan_elapsed_seconds = max(0.0, time.time() - started)
                    if duration_seconds:
                        self.scan_progress_percent = min(100.0, (self.scan_elapsed_seconds / float(duration_seconds)) * 100.0)
                    if camera_hunt and self.single_adapter_policy:
                        self.pipeline.mark_core_capture_phase(True, self.scan_elapsed_seconds)

                    stats = self.channel_statistics.setdefault(channel, {"frames": 0, "hits": 0, "visits": 0})
                    stats["visits"] = int(stats.get("visits") or 0) + 1

                    if result.get("ok"):
                        frames = result.get("frames", [])
                        total_frames += len(frames)
                        success_count += 1
                        successful_channels.add(channel)
                        stats["frames"] = int(stats.get("frames") or 0) + len(frames)
                        stats["hits"] = int(stats.get("hits") or 0) + (1 if len(frames) > 0 else 0)
                        self._normalize_evidence_session()
                        self.evidence.record_channel_capture(
                            source_pcap_path=str(result.get("pcap_path") or ""),
                            channel=channel,
                            band=str(entry.get("band") or ""),
                            interface=str(batch.get("interface") or ""),
                            frame_count=len(frames),
                        )
                        if self.scan_processing_enabled and self.processing_pipeline.running:
                            self.processing_pipeline.submit({"interface": batch["interface"], "entry": entry, "result": result})
                        else:
                            self._ingest_capture_without_pipeline(entry, result)
                        completed.append(
                            {
                                "channel": channel,
                                "band": entry["band"],
                                "interface": batch["interface"],
                                "priority": entry.get("priority"),
                                "frame_count": len(frames),
                                "pcap_path": result.get("pcap_path"),
                            }
                        )
                    else:
                        failed_count += 1
                        self.last_error = result.get("error") or ""
                        completed.append(
                            {
                                "channel": channel,
                                "band": entry["band"],
                                "interface": batch["interface"],
                                "priority": entry.get("priority"),
                                "frame_count": 0,
                                "error": self.last_error,
                                "pcap_path": result.get("pcap_path"),
                            }
                        )

                    if self.stop_requested:
                        break
                    if deadline and time.time() >= deadline:
                        break

                if self.stop_requested:
                    break
                if deadline and time.time() >= deadline:
                    break

            if self.stop_requested:
                break
            if not deadline:
                break
            if deadline and time.time() >= deadline:
                break

        elapsed = max(0.001, time.time() - started)
        self.processing_pipeline.wait_idle(timeout=15.0)
        if self.single_adapter_policy:
            self.pipeline.finish_core_capture_phase(elapsed)
            for phase_name in [name for name in ("kismet", "bettercap") if name in self._enabled_pipeline_collectors()]:
                phase_result = self.pipeline.run_single_adapter_phase(phase_name)
                if phase_result.get("error"):
                    self.last_error = str(phase_result.get("error"))
            self.pipeline.complete_single_adapter_session()
            elapsed = max(0.001, time.time() - started)
        self.scan_elapsed_seconds = elapsed
        if duration_seconds:
            self.scan_progress_percent = min(100.0, (elapsed / float(duration_seconds)) * 100.0)

        self.last_pps = round(total_frames / elapsed, 2)
        hunt_results: Dict[str, Any] = {"count": 0, "leads": []}
        if camera_hunt:
            hunt_results = self.get_camera_hunt_results()
        result = {
            "status": "completed" if success_count > 0 else ("stopped" if self.stop_requested else "scan_failed"),
            "channel_count": len(plan),
            "channel_visit_count": self.scan_completed_channels,
            "successful_channel_count": len(successful_channels),
            "successful_channel_visit_count": success_count,
            "failed_channel_count": failed_count,
            "frame_count": total_frames,
            "packet_rate_pps": self.last_pps,
            "scan_mode": scan_mode,
            "scan_scenario": self.scan_scenario,
            "locked_channels": [int(channel) for channel in (locked_channels or [])],
            "monitor_interfaces": monitor_interfaces,
            "core_capture_interfaces": core_interfaces,
            "pipeline_interfaces": pipeline_interfaces,
            "channel_statistics": self.channel_statistics,
            "deep_packet_enrichment": {
                "enabled": bool(deep_packet_enrichment),
                **self.enricher.status(),
            },
            "camera_hunt": bool(camera_hunt),
            "channels": completed,
            "networks": self.get_networks(lightweight=True),
            "clients": self.get_clients(lightweight=True),
            "camera_hunt_results": hunt_results,
            "processing_pipeline": self.processing_pipeline.status(),
            "resource_policy": self.resource_policy,
            "scan": self._scan_status_payload(),
        }
        if camera_hunt:
            auto_probe_leads = int(self.resource_policy.get("camera_hunt_auto_probe_leads") or 5)
            result["auto_probe_summary"] = self._auto_probe_top_camera_leads(max_leads=auto_probe_leads)
        self._start_artifact_materialization_async()
        result["artifact_materialization"] = self._artifact_materialization_status()
        result["networks"] = self.get_networks(lightweight=True)
        result["clients"] = self.get_clients(lightweight=True)
        self.intelligence.record_scan_snapshot(result["networks"], result["clients"])
        return result

    def get_networks(self, *, lightweight: bool = False) -> List[Dict[str, Any]]:
        return self._get_enriched_targets("networks", lightweight=lightweight)

    def get_clients(self, *, lightweight: bool = False) -> List[Dict[str, Any]]:
        return self._get_enriched_targets("clients", lightweight=lightweight)

    def get_pcap_inventory(self) -> List[Dict[str, Any]]:
        inventory = list(self.tracker.recent_pcaps)
        session_manifest = self.evidence.session_manifest()
        if session_manifest:
            for entry in inventory:
                entry["session_id"] = session_manifest.get("session_id") or ""
            return inventory
        return inventory

    def get_operator_snapshot(
        self,
        *,
        prepare: bool = False,
        light: bool = False,
        include_data: bool = True,
        include_redteam: bool = False,
    ) -> Dict[str, Any]:
        status = self.get_status(prepare=prepare, light=light)
        snapshot: Dict[str, Any] = {
            "status": status,
            "channels": status.get("channels") or self.get_channels(light=light),
        }
        if include_data:
            lightweight_targets = bool(light or self._effective_capture_active() or self._artifact_materialization_active())
            snapshot["networks"] = self.get_networks(lightweight=lightweight_targets)
            snapshot["clients"] = self.get_clients(lightweight=lightweight_targets)
            snapshot["pcaps"] = self.get_pcap_inventory()
        else:
            snapshot["networks"] = []
            snapshot["clients"] = []
            snapshot["pcaps"] = []
        if include_redteam:
            snapshot["redteam"] = self.get_redteam_validation_status()
            snapshot["adversary_replay"] = self.get_adversary_replay_status()
        return snapshot

    def get_channels(self, light: bool = False) -> Dict[str, Any]:
        observation_audit = {} if light else self.tracker.get_observation_audit()
        return {
            "current_channel": self.current_channel,
            "state": "Scanning" if self.capture_active else ("Idle" if not self.armed else "Armed"),
            "bands": ["2.4 GHz", "5 GHz"],
            "plan_24": ChannelHopper.CHANNELS_24,
            "plan_5": ChannelHopper.CHANNELS_5,
            "mode": self.scan_mode,
            "scenario": self.scan_scenario,
            "locked_channels": self.scan_locked_channels,
            "selected_interfaces": self.scan_selected_interfaces,
            "hot_channels": self._hot_channels(),
            "channel_statistics": self.channel_statistics,
            "observation_activity": self.tracker.get_channel_activity(),
            "coverage_confidence": observation_audit.get("coverage_confidence") or {},
        }

    def get_camera_hunt_results(self) -> Dict[str, Any]:
        cache_age = time.time() - float(self.camera_hunt_results_cache.get("built_at") or 0.0)
        active_ttl = float(self.resource_policy.get("camera_hunt_results_cache_ttl_active") or 4.0)
        idle_ttl = float(self.resource_policy.get("camera_hunt_results_cache_ttl_idle") or 2.0)
        ttl = active_ttl if self._effective_capture_active() else idle_ttl
        if cache_age <= ttl and self.camera_hunt_results_cache.get("results") is not None:
            return self.camera_hunt_results_cache["results"]
        lightweight_targets = bool(self._effective_capture_active() or self._artifact_materialization_active())
        networks = self.get_networks(lightweight=lightweight_targets)
        clients = self.get_clients(lightweight=lightweight_targets)
        results = self.pipeline.build_results(networks, clients)
        network_lookup = {
            str(network.get("bssid") or "").strip().lower(): network
            for network in networks
            if str(network.get("bssid") or "").strip()
        }
        results["leads"] = [self._merge_probe_cache_into_lead(self._attach_association_context(lead, network_lookup)) for lead in (results.get("leads") or [])]
        results["near_misses"] = [self._merge_probe_cache_into_lead(self._attach_association_context(lead, network_lookup)) for lead in (results.get("near_misses") or [])]
        results["possible_cloud_cameras"] = [
            self._merge_probe_cache_into_lead(self._attach_association_context(lead, network_lookup))
            for lead in (results.get("possible_cloud_cameras") or [])
        ]
        self.camera_hunt_results_cache = {"built_at": time.time(), "results": results}
        return results

    @staticmethod
    def _camera_lead_id(lead: Dict[str, Any]) -> str:
        kind = str(lead.get("leadKind") or ("client" if lead.get("mac") else "network")).lower()
        if kind == "client":
            return f"client:{str(lead.get('mac') or lead.get('record_id') or '').lower()}"
        return f"network:{str(lead.get('bssid') or lead.get('record_id') or '').lower()}"

    @staticmethod
    def _wifi_target_id(target: Dict[str, Any]) -> str:
        if str(target.get("mac") or "").strip():
            return f"client:{str(target.get('mac') or '').strip().lower()}"
        return f"network:{str(target.get('bssid') or target.get('record_id') or '').strip().lower()}"

    @staticmethod
    def _stable_wifi_target_key(kind: str, mac_value: str) -> str:
        normalized = str(mac_value or "").strip().lower().replace(":", "")
        return f"{kind}_{normalized}" if normalized else ""

    @staticmethod
    def _parse_airodump_timestamp(value: Any) -> float:
        raw = str(value or "").strip()
        if not raw:
            return 0.0
        try:
            return time.mktime(time.strptime(raw, "%Y-%m-%d %H:%M:%S"))
        except Exception:
            return 0.0

    def _active_airodump_targets(self) -> List[Dict[str, Any]]:
        try:
            snapshot = self.pipeline.snapshot().get("airodump") or {}
        except Exception:
            return []
        now = time.time()
        targets: List[Dict[str, Any]] = []
        for ap in list(snapshot.get("aps") or []):
            bssid = str(ap.get("bssid") or "").strip().lower()
            if not bssid:
                continue
            ssid = str(ap.get("essid") or "").strip()
            last_seen = self._parse_airodump_timestamp(ap.get("last_seen")) or now
            channel_text = str(ap.get("channel") or "").strip()
            channel = int(channel_text) if channel_text.isdigit() else 0
            targets.append(
                {
                    "record_id": bssid,
                    "target_id": self._wifi_target_id({"bssid": bssid}),
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": channel,
                    "band": "2.4 GHz" if 1 <= channel <= 14 else ("5 GHz" if channel else ""),
                    "security": str(ap.get("privacy") or "").strip(),
                    "rssi_dbm": float(ap.get("power") or 0.0) if str(ap.get("power") or "").strip().lstrip("-").isdigit() else 0.0,
                    "packet_count": int(ap.get("beacons") or 0) if str(ap.get("beacons") or "").strip().isdigit() else 0,
                    "last_seen": last_seen,
                    "first_seen": self._parse_airodump_timestamp(ap.get("first_seen")) or last_seen,
                    "evidence_tier": "Observed",
                    "evidence_reason": "Live airodump-ng AP observation",
                    "observation_source": "airodump-ng",
                    "synthetic_identity": False,
                }
            )
        for station in list(snapshot.get("stations") or []):
            mac = str(station.get("mac") or "").strip().lower()
            if not mac:
                continue
            associated_bssid = str(station.get("bssid") or "").strip().lower()
            if associated_bssid == "(not associated)":
                associated_bssid = ""
            probed_essids = str(station.get("probed_essids") or "").strip()
            last_seen = self._parse_airodump_timestamp(station.get("last_seen")) or now
            targets.append(
                {
                    "record_id": mac,
                    "target_id": self._wifi_target_id({"mac": mac}),
                    "mac": mac,
                    "associated_bssid": associated_bssid,
                    "ssid": probed_essids.split(",")[0].strip() if probed_essids else "",
                    "channel": 0,
                    "band": "",
                    "packet_count": int(station.get("packets") or 0) if str(station.get("packets") or "").strip().isdigit() else 0,
                    "rssi_dbm": float(station.get("power") or 0.0) if str(station.get("power") or "").strip().lstrip("-").isdigit() else 0.0,
                    "last_seen": last_seen,
                    "first_seen": self._parse_airodump_timestamp(station.get("first_seen")) or last_seen,
                    "probed_essids": probed_essids,
                    "evidence_tier": "Observed",
                    "evidence_reason": "Live airodump-ng station observation",
                    "observation_source": "airodump-ng",
                    "synthetic_identity": False,
                }
            )
        return targets

    def _wifi_target_aliases(self, target: Dict[str, Any]) -> set[str]:
        bssid = str(target.get("bssid") or "").strip().lower()
        mac = str(target.get("mac") or "").strip().lower()
        record_id = str(target.get("record_id") or "").strip().lower()
        target_id = str(target.get("target_id") or self._wifi_target_id(target) or "").strip().lower()
        aliases = {
            target_id,
            bssid,
            mac,
            record_id,
        }
        if bssid:
            aliases.add(self._stable_wifi_target_key("network", bssid))
        if mac:
            aliases.add(self._stable_wifi_target_key("client", mac))
        return {value for value in aliases if value}

    def _redteam_session_id(self) -> str:
        session_manifest = self.evidence.session_manifest()
        session_id = str(session_manifest.get("session_id") or "").strip()
        if session_id:
            return session_id
        current = self.evidence.current_session or {}
        session_id = str(current.get("session_id") or "").strip()
        if session_id:
            return session_id
        return f"adhoc_{int(time.time())}"

    def _redteam_run_id(self) -> str:
        return f"rt_{int(time.time())}"

    def _redteam_root(self, session_id: str, run_id: str) -> Path:
        return self.root_dir / "evidence" / "wifi_hunt" / "sessions" / session_id / "redteam" / run_id

    def _adversary_replay_run_id(self) -> str:
        return f"replay_{int(time.time())}"

    def _adversary_replay_root(self, session_id: str, run_id: str) -> Path:
        return self.root_dir / "evidence" / "wifi_hunt" / "sessions" / session_id / "adversary_replay" / run_id

    def _pcap_inventory_for_redteam(self) -> List[Dict[str, Any]]:
        session_manifest = self.evidence.session_manifest()
        inventory: List[Dict[str, Any]] = []
        full_session_pcap = str(((session_manifest.get("artifacts") or {}).get("full_session_pcap") or "")).strip()
        if full_session_pcap:
            inventory.append({"path": full_session_pcap, "frame_count": int((session_manifest.get("artifacts") or {}).get("full_session_packet_count") or 0), "stage": "full_session"})
        inventory.extend(self.get_pcap_inventory())
        seen: set[str] = set()
        unique: List[Dict[str, Any]] = []
        for entry in inventory:
            path = str(entry.get("path") or "").strip()
            if not path or path in seen or not Path(path).exists():
                continue
            seen.add(path)
            unique.append(dict(entry))
        return unique[:10]

    def _count_pcap_packets(self, pcap_path: str) -> int:
        tshark_path = str(self.capture.tshark_path or "")
        if not tshark_path or not pcap_path or not Path(pcap_path).exists():
            return 0
        try:
            result = subprocess.run(
                [tshark_path, "-r", pcap_path, "-T", "fields", "-e", "frame.number"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if result.returncode != 0:
                return 0
            return len([line for line in (result.stdout or "").splitlines() if line.strip()])
        except Exception:
            return 0

    @staticmethod
    def _camera_packet_limit(packet_count: int, file_size_bytes: int, max_bytes: int) -> int:
        packets = max(0, int(packet_count or 0))
        size_bytes = max(0, int(file_size_bytes or 0))
        cap = max(1, int(max_bytes or 1))
        if packets <= 0 or size_bytes <= 0 or size_bytes <= cap:
            return 0
        ratio = min(1.0, cap / float(size_bytes))
        return max(1, int(packets * ratio * 0.95))

    @staticmethod
    def _camera_ip_filter(target_ip: str) -> str:
        ip_value = str(target_ip or "").strip()
        if ":" in ip_value:
            return f"ipv6.addr == {ip_value}"
        return f"ip.addr == {ip_value}"

    def _extract_filtered_pcap_with_limit(
        self,
        *,
        source_path: str,
        display_filter: str,
        destination_path: Path,
        packet_limit: int = 0,
    ) -> Dict[str, Any]:
        tshark_path = str(self.capture.tshark_path or "")
        if not tshark_path or not source_path or not Path(source_path).exists():
            return {"ok": False, "error": "tshark unavailable"}
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        command = [tshark_path, "-r", source_path, "-Y", display_filter]
        if int(packet_limit or 0) > 0:
            command.extend(["-c", str(int(packet_limit))])
        command.extend(["-w", str(destination_path)])
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0 or not destination_path.exists():
            return {"ok": False, "error": (result.stderr or result.stdout or "tshark filter extraction failed").strip()}
        packet_count = self._count_pcap_packets(str(destination_path))
        file_size_bytes = int(destination_path.stat().st_size) if destination_path.exists() else 0
        if packet_count <= 0:
            try:
                destination_path.unlink(missing_ok=True)
            except Exception:
                pass
            return {"ok": False, "error": "no_matching_packets"}
        return {
            "ok": True,
            "path": str(destination_path),
            "packet_count": packet_count,
            "file_size_bytes": file_size_bytes,
            "packet_limit": int(packet_limit or 0),
        }

    def _extract_capped_filtered_pcap(
        self,
        *,
        source_path: str,
        display_filter: str,
        destination_path: Path,
        max_bytes: int,
    ) -> Dict[str, Any]:
        extract = self._extract_filtered_pcap_with_limit(
            source_path=source_path,
            display_filter=display_filter,
            destination_path=destination_path,
        )
        if not extract.get("ok"):
            return extract
        if int(extract.get("file_size_bytes") or 0) <= int(max_bytes or 0):
            return {**extract, "truncated": False}

        packet_limit = self._camera_packet_limit(
            int(extract.get("packet_count") or 0),
            int(extract.get("file_size_bytes") or 0),
            int(max_bytes or 0),
        )
        for _attempt in range(4):
            if packet_limit <= 0:
                break
            try:
                destination_path.unlink(missing_ok=True)
            except Exception:
                pass
            limited = self._extract_filtered_pcap_with_limit(
                source_path=source_path,
                display_filter=display_filter,
                destination_path=destination_path,
                packet_limit=packet_limit,
            )
            if not limited.get("ok"):
                return limited
            if int(limited.get("file_size_bytes") or 0) <= int(max_bytes or 0):
                return {**limited, "truncated": True}
            next_limit = self._camera_packet_limit(
                int(limited.get("packet_count") or 0),
                int(limited.get("file_size_bytes") or 0),
                int(max_bytes or 0),
            )
            if next_limit >= packet_limit:
                break
            packet_limit = next_limit
        return {**extract, "truncated": True, "warning": "max_size_not_fully_met"}

    def _convert_pcapng_to_pcap(self, *, source_path: str, destination_path: Path) -> Dict[str, Any]:
        tshark_path = str(self.capture.tshark_path or "")
        if not tshark_path or not source_path or not Path(source_path).exists():
            return {"ok": False, "error": "tshark unavailable"}
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [tshark_path, "-r", source_path, "-F", "pcap", "-w", str(destination_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0 or not destination_path.exists():
            return {"ok": False, "error": (result.stderr or result.stdout or "pcap conversion failed").strip()}
        return {
            "ok": True,
            "path": str(destination_path),
            "file_size_bytes": int(destination_path.stat().st_size),
            "packet_count": self._count_pcap_packets(str(destination_path)),
        }

    @staticmethod
    def _camera_packet_summary_from_rows(rows: List[Dict[str, Any]], target_ip: str) -> Dict[str, Any]:
        total_bytes = 0
        first_seen = 0.0
        last_seen = 0.0
        protocols_seen: set[str] = set()
        ports_seen: set[int] = set()
        endpoint_ips: set[str] = set()
        host_indicators: set[str] = set()
        uplink_packets = 0
        downlink_packets = 0
        uplink_bytes = 0
        downlink_bytes = 0
        protocol_counts = {
            "tcp": 0,
            "udp": 0,
            "dns": 0,
            "http": 0,
            "tls": 0,
            "rtsp": 0,
            "rtp": 0,
            "rtcp": 0,
            "h264": 0,
        }

        for row in rows:
            timestamp = float(row.get("timestamp") or 0.0)
            frame_len = int(row.get("frame_len") or 0)
            ip_src = str(row.get("ip_src") or "").strip()
            ip_dst = str(row.get("ip_dst") or "").strip()
            protocol_blob = str(row.get("protocols") or "").strip().lower()
            tokens = [token.strip() for token in protocol_blob.split(":") if token.strip()]
            for token in tokens:
                protocols_seen.add(token)
                if token in protocol_counts:
                    protocol_counts[token] += 1
                if token in {"h264", "h265", "hevc"}:
                    protocol_counts["h264"] += 1
            for raw_port in (
                row.get("tcp_srcport"),
                row.get("tcp_dstport"),
                row.get("udp_srcport"),
                row.get("udp_dstport"),
            ):
                value = str(raw_port or "").strip()
                if value.isdigit():
                    ports_seen.add(int(value))
            for raw_host in (row.get("dns_name"), row.get("tls_sni"), row.get("http_host"), row.get("rtsp_url")):
                value = str(raw_host or "").strip()
                if value:
                    host_indicators.add(value)
            if ip_src == str(target_ip):
                uplink_packets += 1
                uplink_bytes += frame_len
                if ip_dst:
                    endpoint_ips.add(ip_dst)
            elif ip_dst == str(target_ip):
                downlink_packets += 1
                downlink_bytes += frame_len
                if ip_src:
                    endpoint_ips.add(ip_src)
            total_bytes += frame_len
            if timestamp > 0:
                if first_seen <= 0 or timestamp < first_seen:
                    first_seen = timestamp
                if timestamp > last_seen:
                    last_seen = timestamp

        packet_count = len(rows)
        duration_seconds = round(max(0.0, last_seen - first_seen), 3) if first_seen and last_seen else 0.0
        stream_detected = bool(
            protocol_counts["rtsp"]
            or protocol_counts["rtp"]
            or protocol_counts["rtcp"]
            or protocol_counts["h264"]
            or (total_bytes >= 262144 and packet_count >= 20)
        )
        if protocol_counts["rtp"] or protocol_counts["h264"]:
            assessment = "stream_like_media_detected"
        elif protocol_counts["rtsp"]:
            assessment = "camera_control_plane_detected"
        elif protocol_counts["tls"] and total_bytes >= 131072 and packet_count >= 12:
            assessment = "encrypted_camera_relay_likely"
        elif packet_count > 0:
            assessment = "camera_ip_activity_observed"
        else:
            assessment = "no_camera_ip_packets_retained"
        return {
            "target_ip": str(target_ip or ""),
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "first_seen_epoch": round(first_seen, 6) if first_seen else 0.0,
            "last_seen_epoch": round(last_seen, 6) if last_seen else 0.0,
            "duration_seconds": duration_seconds,
            "protocols_seen": sorted(protocols_seen)[:20],
            "protocol_counts": protocol_counts,
            "ports_seen": sorted(ports_seen)[:20],
            "endpoint_ips": sorted(endpoint_ips)[:12],
            "host_indicators": sorted(host_indicators)[:12],
            "uplink_packets": uplink_packets,
            "downlink_packets": downlink_packets,
            "uplink_bytes": uplink_bytes,
            "downlink_bytes": downlink_bytes,
            "stream_detected": stream_detected,
            "assessment": assessment,
        }

    def _summarize_camera_packet_pcap(self, *, pcap_path: str, target_ip: str) -> Dict[str, Any]:
        tshark_path = str(self.capture.tshark_path or "")
        if not tshark_path or not pcap_path or not Path(pcap_path).exists():
            return {
                "target_ip": str(target_ip or ""),
                "packet_count": 0,
                "total_bytes": 0,
                "assessment": "tshark_unavailable",
                "protocols_seen": [],
                "protocol_counts": {},
                "ports_seen": [],
                "endpoint_ips": [],
                "host_indicators": [],
                "stream_detected": False,
            }
        result = subprocess.run(
            [
                tshark_path,
                "-r",
                pcap_path,
                "-T",
                "fields",
                "-E",
                "header=n",
                "-E",
                "separator=\t",
                "-e",
                "frame.time_epoch",
                "-e",
                "frame.len",
                "-e",
                "frame.protocols",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
                "-e",
                "udp.srcport",
                "-e",
                "udp.dstport",
                "-e",
                "dns.qry.name",
                "-e",
                "tls.handshake.extensions_server_name",
                "-e",
                "http.host",
                "-e",
                "rtsp.url",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            return {
                "target_ip": str(target_ip or ""),
                "packet_count": 0,
                "total_bytes": 0,
                "assessment": "summary_parse_failed",
                "error": (result.stderr or result.stdout or "tshark summary parse failed").strip(),
                "protocols_seen": [],
                "protocol_counts": {},
                "ports_seen": [],
                "endpoint_ips": [],
                "host_indicators": [],
                "stream_detected": False,
            }
        rows: List[Dict[str, Any]] = []
        for line in (result.stdout or "").splitlines():
            parts = line.split("\t")
            while len(parts) < 13:
                parts.append("")
            rows.append(
                {
                    "timestamp": parts[0],
                    "frame_len": parts[1],
                    "protocols": parts[2],
                    "ip_src": parts[3],
                    "ip_dst": parts[4],
                    "tcp_srcport": parts[5],
                    "tcp_dstport": parts[6],
                    "udp_srcport": parts[7],
                    "udp_dstport": parts[8],
                    "dns_name": parts[9],
                    "tls_sni": parts[10],
                    "http_host": parts[11],
                    "rtsp_url": parts[12],
                }
            )
        summary = self._camera_packet_summary_from_rows(rows, target_ip)
        summary["pcap_path"] = str(pcap_path)
        return summary

    def _build_camera_packet_evidence(self, *, lead_id: str, target_ips: List[str], source_paths: List[str]) -> Dict[str, Any]:
        tshark_path = str(self.capture.tshark_path or "")
        normalized_ips = [str(item or "").strip() for item in target_ips if str(item or "").strip()]
        valid_sources = []
        for raw in source_paths:
            candidate = str(raw or "").strip()
            if candidate and candidate not in valid_sources and Path(candidate).exists():
                valid_sources.append(candidate)
        if not tshark_path:
            return {"ok": False, "error": "tshark unavailable"}
        if not normalized_ips:
            return {"ok": False, "error": "no_target_ip"}
        if not valid_sources:
            return {"ok": False, "error": "no_source_pcaps"}

        target_ip = normalized_ips[0]
        safe_id = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in str(lead_id or "camera"))
        safe_ip = target_ip.replace(":", "_").replace(".", "_")
        artifact_dir = self.root_dir / "evidence" / "camera_protocol"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        stamp = int(time.time())
        raw_pcapng_path = artifact_dir / f"{stamp}_{safe_id}_{safe_ip}_camera_ip_raw.pcapng"
        raw_pcap_path = artifact_dir / f"{stamp}_{safe_id}_{safe_ip}_camera_ip_raw.pcap"
        summary_path = artifact_dir / f"{stamp}_{safe_id}_{safe_ip}_camera_media_summary.json"
        with tempfile.TemporaryDirectory(prefix="ghostredrecon_camera_") as temp_dir:
            merged_path = Path(temp_dir) / f"{safe_id}_merged.pcapng"
            merged = self._merge_pcaps(valid_sources[:8], merged_path)
            if not merged.get("ok"):
                return merged
            extract = self._extract_capped_filtered_pcap(
                source_path=str(merged.get("path") or ""),
                display_filter=self._camera_ip_filter(target_ip),
                destination_path=raw_pcapng_path,
                max_bytes=self.CAMERA_PACKET_MAX_BYTES,
            )
            if not extract.get("ok"):
                return extract
        converted = self._convert_pcapng_to_pcap(source_path=str(raw_pcapng_path), destination_path=raw_pcap_path)
        summary = self._summarize_camera_packet_pcap(pcap_path=str(raw_pcapng_path), target_ip=target_ip)
        summary.update(
            {
                "target_ip": target_ip,
                "capture_file": str(raw_pcapng_path),
                "pcap_path": str(raw_pcap_path) if converted.get("ok") else "",
                "file_size_bytes": int(extract.get("file_size_bytes") or 0),
                "max_file_size_bytes": int(self.CAMERA_PACKET_MAX_BYTES),
                "truncated": bool(extract.get("truncated")),
                "source_pcap_count": len(valid_sources[:8]),
            }
        )
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        return {
            "ok": True,
            "target_ip": target_ip,
            "pcapng_path": str(raw_pcapng_path),
            "pcap_path": str(raw_pcap_path) if converted.get("ok") else "",
            "summary_path": str(summary_path),
            "packet_count": int(extract.get("packet_count") or 0),
            "file_size_bytes": int(extract.get("file_size_bytes") or 0),
            "truncated": bool(extract.get("truncated")),
            "summary": summary,
        }

    def _capture_direct_target_ip_window(
        self,
        *,
        lead_id: str,
        target_ip: str,
        seconds: int,
        stage_id: str,
    ) -> Dict[str, Any]:
        target_ip = str(target_ip or "").strip()
        if not target_ip:
            return {"ok": False, "error": "no_target_ip", "target_ip": "", "stage": stage_id}
        route_interface = str(
            self.active_fingerprint._route_interface(target_ip)
            or self.active_fingerprint._default_route_interface()
            or ""
        ).strip()
        if not route_interface:
            return {"ok": False, "error": "no_route_interface", "target_ip": target_ip, "stage": stage_id}
        dumpcap_path = str(self.capture.dumpcap_path or "")
        tcpdump_path = str(self.capture.tcpdump_path or "")
        if not dumpcap_path and not tcpdump_path:
            return {"ok": False, "error": "no_capture_tool", "target_ip": target_ip, "stage": stage_id, "interface": route_interface}

        bounded_seconds = max(4, min(20, int(seconds or 8)))
        safe_id = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in str(lead_id or "camera"))
        safe_ip = target_ip.replace(":", "_").replace(".", "_")
        capture_filter = f"host {target_ip}"
        artifact_dir = self.root_dir / "evidence" / "camera_protocol"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        stamp = int(time.time())
        raw_pcapng_path = artifact_dir / f"{stamp}_{safe_id}_{safe_ip}_{stage_id}_direct_ip_raw.pcapng"
        raw_pcap_path = artifact_dir / f"{stamp}_{safe_id}_{safe_ip}_{stage_id}_direct_ip_raw.pcap"
        summary_path = artifact_dir / f"{stamp}_{safe_id}_{safe_ip}_{stage_id}_direct_media_summary.json"

        with tempfile.TemporaryDirectory(prefix="ghostredrecon_direct_ip_") as temp_dir:
            temp_dir_path = Path(temp_dir)
            temp_capture_path = temp_dir_path / f"{safe_id}_{stage_id}_{safe_ip}.pcapng"
            if dumpcap_path:
                result = subprocess.run(
                    [
                        dumpcap_path,
                        "-i",
                        route_interface,
                        "-a",
                        f"duration:{bounded_seconds}",
                        "-f",
                        capture_filter,
                        "-w",
                        str(temp_capture_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=max(10, bounded_seconds + 8),
                    check=False,
                )
                detail = (result.stderr or result.stdout or "").strip()
                if result.returncode != 0 and not temp_capture_path.exists():
                    return {
                        "ok": False,
                        "error": detail or "direct_dumpcap_failed",
                        "target_ip": target_ip,
                        "stage": stage_id,
                        "interface": route_interface,
                    }
            else:
                temp_capture_path = temp_dir_path / f"{safe_id}_{stage_id}_{safe_ip}.pcap"
                result = subprocess.run(
                    [
                        tcpdump_path,
                        "-i",
                        route_interface,
                        "-U",
                        "-G",
                        str(bounded_seconds),
                        "-W",
                        "1",
                        "-w",
                        str(temp_capture_path),
                        capture_filter,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=max(10, bounded_seconds + 8),
                    check=False,
                )
                detail = (result.stderr or result.stdout or "").strip()
                if result.returncode != 0 and not temp_capture_path.exists():
                    return {
                        "ok": False,
                        "error": detail or "direct_tcpdump_failed",
                        "target_ip": target_ip,
                        "stage": stage_id,
                        "interface": route_interface,
                    }

            extract = self._extract_capped_filtered_pcap(
                source_path=str(temp_capture_path),
                display_filter=self._camera_ip_filter(target_ip),
                destination_path=raw_pcapng_path,
                max_bytes=self.CAMERA_PACKET_MAX_BYTES,
            )
            if not extract.get("ok"):
                return {
                    **extract,
                    "target_ip": target_ip,
                    "stage": stage_id,
                    "interface": route_interface,
                }

        converted = self._convert_pcapng_to_pcap(source_path=str(raw_pcapng_path), destination_path=raw_pcap_path)
        summary = self._summarize_camera_packet_pcap(pcap_path=str(raw_pcapng_path), target_ip=target_ip)
        summary.update(
            {
                "target_ip": target_ip,
                "capture_file": str(raw_pcapng_path),
                "pcap_path": str(raw_pcap_path) if converted.get("ok") else "",
                "interface": route_interface,
                "stage": stage_id,
                "file_size_bytes": int(extract.get("file_size_bytes") or 0),
                "max_file_size_bytes": int(self.CAMERA_PACKET_MAX_BYTES),
                "truncated": bool(extract.get("truncated")),
                "capture_filter": capture_filter,
            }
        )
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        return {
            "ok": True,
            "target_ip": target_ip,
            "stage": stage_id,
            "interface": route_interface,
            "pcap_path": str(raw_pcap_path) if converted.get("ok") else "",
            "pcapng_path": str(raw_pcapng_path),
            "summary_path": str(summary_path),
            "packet_count": int(extract.get("packet_count") or 0),
            "file_size_bytes": int(extract.get("file_size_bytes") or 0),
            "truncated": bool(extract.get("truncated")),
            "summary": summary,
        }

    def _merge_pcaps(self, source_paths: List[str], destination_path: Path) -> Dict[str, Any]:
        valid = [str(Path(path).resolve()) for path in source_paths if str(path).strip() and Path(path).exists()]
        if not valid:
            return {"ok": False, "error": "no_source_pcaps"}
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        mergecap_path = str(getattr(self.evidence, "mergecap_path", "") or which("mergecap") or "")
        if mergecap_path and len(valid) > 1:
            result = subprocess.run(
                [mergecap_path, "-w", str(destination_path), *valid],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode == 0 and destination_path.exists():
                return {"ok": True, "path": str(destination_path), "packet_count": self._count_pcap_packets(str(destination_path))}
            return {"ok": False, "error": (result.stderr or result.stdout or "mergecap failed").strip()}
        source = Path(valid[0])
        destination_path.write_bytes(source.read_bytes())
        return {"ok": True, "path": str(destination_path), "packet_count": self._count_pcap_packets(str(destination_path))}

    def _extract_filtered_pcap_for_redteam(self, source_path: str, display_filter: str, destination_path: Path) -> Dict[str, Any]:
        tshark_path = str(self.capture.tshark_path or "")
        if not tshark_path or not source_path or not Path(source_path).exists():
            return {"ok": False, "error": "tshark unavailable"}
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [tshark_path, "-r", source_path, "-Y", display_filter, "-w", str(destination_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0 or not destination_path.exists():
            return {"ok": False, "error": (result.stderr or result.stdout or "tshark filter extraction failed").strip()}
        packet_count = self._count_pcap_packets(str(destination_path))
        if packet_count <= 0:
            try:
                destination_path.unlink(missing_ok=True)
            except Exception:
                pass
            return {"ok": False, "error": "no_matching_packets"}
        return {"ok": True, "path": str(destination_path), "packet_count": packet_count}

    def _redteam_detection_mapping(self, action_type: str) -> Dict[str, Any]:
        mappings = {
            "deauth_evidence_probe": {
                "wireshark_filter": "wlan.fc.type_subtype == 0x0c",
                "expected_detection": "unusual deauthentication frames for selected BSSID/client pair",
                "defensive_control": "Protected Management Frames / 802.11w",
                "evidence_hint": "pcap/deauth_frames.pcapng · detection_mapping.json",
            },
            "disassociation_evidence_probe": {
                "wireshark_filter": "wlan.fc.type_subtype == 0x0a",
                "expected_detection": "unusual disassociation frames for selected BSSID/client pair",
                "defensive_control": "Protected Management Frames / 802.11w",
                "evidence_hint": "pcap/disassoc_frames.pcapng · detection_mapping.json",
            },
            "handshake_visibility_trigger": {
                "wireshark_filter": "eapol",
                "expected_detection": "EAPOL sequence associated with selected AP/client pair",
                "defensive_control": "Protected Management Frames / 802.11w may suppress spoofed disconnect effects",
                "evidence_hint": "pcap/eapol_after_effect.pcapng · observed_effects.json",
            },
        }
        return dict(mappings.get(action_type) or {})

    def get_redteam_validation_status(self) -> Dict[str, Any]:
        state = dict(self.redteam_validation_state or {})
        if "updated_at" not in state:
            state["updated_at"] = int(time.time())
        return state

    def get_adversary_replay_status(self) -> Dict[str, Any]:
        state = dict(self.adversary_replay_state or {})
        if "updated_at" not in state:
            state["updated_at"] = int(time.time())
        return state

    @staticmethod
    def _adversary_replay_detection_mapping(counters: Dict[str, int], rogue_ssids: List[str]) -> List[Dict[str, Any]]:
        mapping: List[Dict[str, Any]] = []
        if int(counters.get("deauthentication") or 0) > 0:
            mapping.append({
                "signal": "Deauthentication Activity",
                "wireshark_filter": "wlan.fc.type_subtype == 0x0c",
                "expected_detection": "deauthentication frame spike affecting observed AP/client pairs",
                "evidence_type": "pcap_replay",
            })
        if int(counters.get("disassociation") or 0) > 0:
            mapping.append({
                "signal": "Disassociation Activity",
                "wireshark_filter": "wlan.fc.type_subtype == 0x0a",
                "expected_detection": "disassociation frame spike affecting observed AP/client pairs",
                "evidence_type": "pcap_replay",
            })
        if int(counters.get("eapol") or 0) > 0:
            mapping.append({
                "signal": "EAPOL / Handshake Visibility",
                "wireshark_filter": "eapol",
                "expected_detection": "EAPOL sequence visible after replayed disconnect/reconnect behavior",
                "evidence_type": "pcap_replay",
            })
        if rogue_ssids:
            mapping.append({
                "signal": "Rogue Beacon Advertisement",
                "wireshark_filter": 'wlan.fc.type_subtype == 0x08 && wlan.ssid contains "GRR-LAB-ROGUE"',
                "expected_detection": "rogue or unauthorized beacon SSID advertisement",
                "evidence_type": "pcap_replay",
            })
        return mapping

    def run_adversary_replay(
        self,
        *,
        capture_path: str,
        confirm_authorized_lab: bool,
        replay_label: str = "",
        reset_before_replay: bool = True,
    ) -> Dict[str, Any]:
        feature = self._offline_evidence_feature()
        if not feature.get("enabled"):
            result = {
                "ok": False,
                "state": "BLOCKED_FEATURE_DISABLED",
                "error": feature.get("warning") or "Offline replay is disabled by project configuration.",
            }
            self.adversary_replay_state = {"state": result["state"], "updated_at": int(time.time()), "last_run": result}
            return result
        if not confirm_authorized_lab:
            result = {
                "ok": False,
                "state": "BLOCKED_SCOPE_REQUIRED",
                "error": "CONFIRM_AUTHORIZED_LAB is required for adversary replay.",
            }
            self.adversary_replay_state = {"state": result["state"], "updated_at": int(time.time()), "last_run": result}
            return result
        if self._effective_capture_active():
            result = {
                "ok": False,
                "state": "BLOCKED_CAPTURE_ACTIVE",
                "error": "Stop the live WiFi MK7 capture before replaying offline adversary PCAP evidence.",
            }
            self.adversary_replay_state = {"state": result["state"], "updated_at": int(time.time()), "last_run": result}
            return result

        source = Path(str(capture_path or "").strip()).expanduser()
        if not source.exists() or not source.is_file():
            result = {"ok": False, "state": "FAILED_PARSE", "error": "Replay capture file not found.", "path": str(source)}
            self.adversary_replay_state = {"state": result["state"], "updated_at": int(time.time()), "last_run": result}
            return result
        if source.suffix.lower() not in {".pcap", ".pcapng"}:
            result = {"ok": False, "state": "FAILED_PARSE", "error": "Only .pcap and .pcapng files are supported.", "path": str(source)}
            self.adversary_replay_state = {"state": result["state"], "updated_at": int(time.time()), "last_run": result}
            return result

        self.adversary_replay_state = {"state": "RUNNING", "updated_at": int(time.time()), "last_run": {"path": str(source)}}
        parsed = self.capture.parse_capture_file(str(source))
        if not parsed.get("ok"):
            result = {"ok": False, "state": "FAILED_PARSE", "error": parsed.get("error") or "Unable to parse replay capture.", "path": str(source)}
            self.adversary_replay_state = {"state": result["state"], "updated_at": int(time.time()), "last_run": result}
            return result

        frames = list(parsed.get("frames") or [])
        if reset_before_replay:
            self.clear_results()
        self.scan_mode = "pcap_replay"
        self.scan_scenario = "adversary_replay"
        self.scan_camera_hunt = False
        self.scan_processing_enabled = False
        self.last_error = ""
        self.intelligence.set_scan_context(
            scenario="adversary_replay",
            camera_hunt=False,
            scan_mode="pcap_replay",
            started_at=time.time(),
        )

        self.evidence.start_session(
            adapter_identifier="pcap_replay",
            bands=["Imported Replay"],
            dwell_ms=0,
            duration_seconds=0,
            scan_mode="pcap_replay",
            scan_scenario="adversary_replay",
            locked_channels=[],
            interfaces=[],
            deep_packet_enrichment=False,
            camera_hunt=False,
        )
        session_id = self._redteam_session_id()
        run_id = self._adversary_replay_run_id()
        run_root = self._adversary_replay_root(session_id, run_id)
        source_dir = run_root / "source"
        source_dir.mkdir(parents=True, exist_ok=True)
        replay_capture_path = source_dir / f"replay_capture{source.suffix.lower()}"
        replay_capture_path.write_bytes(source.read_bytes())

        current_session = dict(self.evidence.current_session or {})
        capture_files = list(current_session.get("capture_files") or [])
        capture_files.append(
            {
                "artifact_type": "pcap_adversary_replay_source",
                "session_id": current_session.get("session_id") or session_id,
                "path": str(replay_capture_path),
                "source_path": str(source.resolve()),
                "integrity_hash": self.evidence._sha256(replay_capture_path),
                "packet_count": len(frames),
                "reason_for_retention": "Real captured Wi-Fi adversary traffic replayed through WiFi MK7 decode/tracking pipeline.",
            }
        )
        current_session["capture_files"] = capture_files
        self.evidence.current_session = current_session
        self.evidence._write_session_manifest()

        with self.tracker_lock:
            self.tracker.ingest_capture(channel=0, band="Imported Replay", pcap_path=str(replay_capture_path), frames=frames)
        self.ddi_cache = {}
        self.camera_hunt_results_cache = {"built_at": 0.0, "results": None}
        self._invalidate_target_snapshot_cache()

        networks = self.get_networks()
        clients = self.get_clients()
        self.intelligence.record_scan_snapshot(networks, clients)
        self._materialize_all_target_artifacts()
        auth_evidence = dict(self.tracker.get_authentication_evidence() or {})
        observation_audit = dict(self.tracker.get_observation_audit() or {})
        self.evidence.finalize_session(handshake_session_count=int(auth_evidence.get("session_count") or 0))

        subtype_counts: Dict[str, int] = {}
        rogue_ssids: List[str] = []
        channels_seen: set[int] = set()
        for frame in frames:
            subtype = str(frame.get("subtype_label") or "other")
            subtype_counts[subtype] = subtype_counts.get(subtype, 0) + 1
            if frame.get("channel") is not None:
                channels_seen.add(int(frame.get("channel") or 0))
            ssid = str(frame.get("ssid") or "").strip()
            if subtype == "beacon" and ssid.startswith("GRR-LAB-ROGUE-") and ssid not in rogue_ssids:
                rogue_ssids.append(ssid)

        counters = {
            "deauthentication": int(subtype_counts.get("deauthentication") or 0),
            "disassociation": int(subtype_counts.get("disassociation") or 0),
            "beacon": int(subtype_counts.get("beacon") or 0),
            "authentication": int(subtype_counts.get("authentication") or 0),
            "association_request": int(subtype_counts.get("association_request") or 0),
            "reassociation_request": int(subtype_counts.get("reassociation_request") or 0),
            "eapol": int(auth_evidence.get("total_frame_count") or 0),
        }
        detection_mapping = self._adversary_replay_detection_mapping(counters, rogue_ssids)
        top_networks = [
            {
                "ssid": item.get("ssid") or "<hidden>",
                "bssid": item.get("bssid") or "",
                "channel": item.get("channel"),
                "security": item.get("security") or "--",
                "pmf": item.get("pmf") or "",
                "handshake_status": item.get("handshake_status") or "",
                "eapol_count": int(item.get("handshake_eapol_count") or item.get("eapol_count") or 0),
            }
            for item in networks[:8]
        ]
        top_clients = [
            {
                "mac": item.get("mac") or "",
                "associated_bssid": item.get("associated_bssid") or "",
                "eapol_count": int(item.get("eapol_count") or 0),
                "packet_count": int(item.get("packet_count") or 0),
            }
            for item in clients[:10]
        ]
        trace = {
            "run_id": run_id,
            "session_id": session_id,
            "replay_label": str(replay_label or source.name),
            "source_capture": str(source.resolve()),
            "retained_capture": str(replay_capture_path),
            "frame_count": len(frames),
            "channels_seen": sorted(channel for channel in channels_seen if channel > 0),
            "subtype_counts": subtype_counts,
            "authentication_evidence": auth_evidence,
            "observation_audit": observation_audit,
        }
        (run_root / "replay_manifest.json").write_text(json.dumps({
            "run_id": run_id,
            "session_id": session_id,
            "capture_path": str(source.resolve()),
            "replay_label": str(replay_label or source.name),
            "confirm_authorized_lab": True,
            "reset_before_replay": bool(reset_before_replay),
            "replay_mode": "pcap_adversary_replay",
            "frame_count": len(frames),
            "network_count": len(networks),
            "client_count": len(clients),
            "counters": counters,
            "artifact_hashes": {
                "retained_capture": self.evidence._sha256(replay_capture_path),
            },
        }, indent=2), encoding="utf-8")
        (run_root / "replay_trace.json").write_text(json.dumps(trace, indent=2), encoding="utf-8")
        (run_root / "detection_mapping.json").write_text(json.dumps({"mapping": detection_mapping, "counters": counters, "rogue_ssids": rogue_ssids}, indent=2), encoding="utf-8")
        summary_lines = [
            "# WiFi MK7 Adversary Replay Summary",
            f"- Run ID: `{run_id}`",
            f"- Session ID: `{session_id}`",
            f"- Source Capture: `{source.resolve()}`",
            f"- Replay Label: `{replay_label or source.name}`",
            f"- Real Frames Parsed: `{len(frames)}`",
            f"- Networks Materialized: `{len(networks)}`",
            f"- Clients Materialized: `{len(clients)}`",
            f"- Deauth Frames: `{counters['deauthentication']}`",
            f"- Disassoc Frames: `{counters['disassociation']}`",
            f"- EAPOL Frames: `{counters['eapol']}`",
            f"- Rogue Beacon SSIDs: `{', '.join(rogue_ssids) if rogue_ssids else '--'}`",
        ]
        (run_root / "replay_summary.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

        state = "COMPLETED"
        result = {
            "ok": True,
            "state": state,
            "run_id": run_id,
            "session_id": session_id,
            "replay_label": str(replay_label or source.name),
            "capture_path": str(source.resolve()),
            "retained_capture": str(replay_capture_path),
            "frame_count": len(frames),
            "network_count": len(networks),
            "client_count": len(clients),
            "counters": counters,
            "top_networks": top_networks,
            "top_clients": top_clients,
            "authentication_evidence": auth_evidence,
            "detection_mapping": detection_mapping,
            "rogue_ssids": rogue_ssids,
            "evidence_files": {
                "manifest": str(run_root / "replay_manifest.json"),
                "trace": str(run_root / "replay_trace.json"),
                "detection_mapping": str(run_root / "detection_mapping.json"),
                "summary_markdown": str(run_root / "replay_summary.md"),
                "retained_capture": str(replay_capture_path),
            },
            "message": "Real captured Wi-Fi adversary traffic was replayed through the live WiFi MK7 decode, tracking, DDI, and evidence pipeline.",
        }
        self.adversary_replay_state = {"state": state, "updated_at": int(time.time()), "last_run": result}
        return result

    def run_redteam_preflight(
        self,
        *,
        target_id: str,
        action_type: str,
        confirm_authorized_lab: bool,
        channel: int,
    ) -> Dict[str, Any]:
        target = self._find_wifi_target(target_id)
        effective_capture_active = self._effective_capture_active()
        if effective_capture_active:
            self._ensure_evidence_session_started()
        session_manifest = self.evidence.session_manifest()
        channel_locked = bool(self.scan_mode == "lock" and self.scan_locked_channels)
        locked_channel = int(self.scan_locked_channels[0]) if self.scan_locked_channels else 0
        target_channel = int(target.get("channel") or 0) if target else 0
        target_recent = bool(target and float(target.get("last_seen") or 0) > 0 and (time.time() - float(target.get("last_seen") or 0)) <= 300)
        evidence_ready = bool(session_manifest.get("session_id") or (self.evidence.current_session or {}).get("session_id"))
        resource_compatible = str((self.resource_policy or {}).get("name") or "") != "low_resource_linux"
        interface_ready = bool((self.sensor_snapshot or {}).get("monitor_interface") or ((self.sensor_snapshot or {}).get("monitor_interfaces") or []))
        supported_action = action_type in {"deauth_evidence_probe", "disassociation_evidence_probe", "handshake_visibility_trigger"}
        channel_match = bool(channel_locked and ((channel and locked_channel == int(channel)) or (target_channel and locked_channel == target_channel)))
        checks = [
            {"id": "authorized_scope", "label": "Owned-lab authorization confirmed", "ok": bool(confirm_authorized_lab), "detail": "Required before any red-team validation can run."},
            {"id": "supported_action", "label": "Supported receive-only validation action", "ok": supported_action, "detail": "This build validates packet evidence only; transmit/injection workflows are not available."},
            {"id": "target_selected", "label": "Observed target selected", "ok": bool(target), "detail": str(target_id or "No target id provided.")},
            {"id": "target_recent", "label": "Target recently observed", "ok": target_recent, "detail": f"last seen {int(time.time() - float(target.get('last_seen') or 0))}s ago" if target_recent and target else "Target must be observed within the last 5 minutes."},
            {"id": "capture_running", "label": "Capture running", "ok": effective_capture_active, "detail": "An active MK7 capture session is required to retain real evidence."},
            {"id": "interface_ready", "label": "Monitor interface ready", "ok": interface_ready, "detail": (self.sensor_snapshot or {}).get("monitor_interface") or "No monitor interface cached."},
            {"id": "channel_lock", "label": "Channel locked", "ok": channel_locked, "detail": f"scan mode {self.scan_mode} · locked {self.scan_locked_channels or []}"},
            {"id": "channel_match", "label": "Locked channel matches target scope", "ok": channel_match, "detail": f"target {target_channel or '--'} · requested {channel or '--'} · locked {locked_channel or '--'}"},
            {"id": "evidence_ready", "label": "Evidence session initialized", "ok": evidence_ready, "detail": session_manifest.get("session_id") or (self.evidence.current_session or {}).get("session_id") or "No active session manifest."},
            {"id": "resource_profile", "label": "Resource profile compatible", "ok": resource_compatible, "detail": str((self.resource_policy or {}).get("label") or (self.resource_policy or {}).get("name") or "unknown")},
        ]
        failing = [item for item in checks if not item.get("ok")]
        if not confirm_authorized_lab:
            state = "BLOCKED_SCOPE_REQUIRED"
        elif not supported_action:
            state = "BLOCKED_UNSAFE_SCOPE"
        elif not target:
            state = "BLOCKED_TARGET_NOT_OBSERVED"
        elif not effective_capture_active:
            state = "BLOCKED_CAPTURE_NOT_RUNNING"
        elif not interface_ready:
            state = "BLOCKED_INTERFACE_NOT_READY"
        elif not channel_locked or not channel_match:
            state = "BLOCKED_TARGET_NOT_OBSERVED"
        elif not evidence_ready:
            state = "BLOCKED_CAPTURE_NOT_RUNNING"
        else:
            state = "READY"
        preflight = {
            "state": state,
            "action_type": action_type,
            "target_id": target_id,
            "checks": checks,
            "target": target or {},
            "supported_actions": ["deauth_evidence_probe", "disassociation_evidence_probe", "handshake_visibility_trigger"],
            "failing_count": len(failing),
            "updated_at": int(time.time()),
        }
        self.redteam_validation_state = {**self.redteam_validation_state, "state": state, "updated_at": int(time.time()), "last_preflight": preflight}
        return preflight

    def run_redteam_validation(
        self,
        *,
        target_id: str,
        action_type: str,
        confirm_authorized_lab: bool,
        channel: int,
        max_duration: int,
        max_frame_count: int,
        reason_code: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        preflight = self.run_redteam_preflight(
            target_id=target_id,
            action_type=action_type,
            confirm_authorized_lab=confirm_authorized_lab,
            channel=channel,
        )
        if preflight.get("state") != "READY":
            return {
                "ok": False,
                "state": preflight.get("state") or "FAILED_CAPTURE_ERROR",
                "preflight": preflight,
                "message": "Red Team Validation is blocked until all preflight checks pass.",
                "receive_only": True,
            }
        target = dict(preflight.get("target") or {})
        requested_duration = max(5, min(120, int(max_duration or 30)))
        requested_frames = max(1, min(10, int(max_frame_count or 3)))
        session_id = self._redteam_session_id()
        run_id = self._redteam_run_id()
        run_root = self._redteam_root(session_id, run_id)
        pcap_dir = run_root / "pcap"
        pcap_dir.mkdir(parents=True, exist_ok=True)
        source_inventory = self._pcap_inventory_for_redteam()
        source_paths = [str(item.get("path") or "").strip() for item in source_inventory if str(item.get("path") or "").strip()]
        window_build = self._merge_pcaps(source_paths, pcap_dir / "redteam_window.pcapng")
        if not window_build.get("ok"):
            state = "FAILED_CAPTURE_ERROR"
            result = {
                "ok": False,
                "state": state,
                "preflight": preflight,
                "message": window_build.get("error") or "Unable to build red-team evidence window.",
                "receive_only": True,
            }
            self.redteam_validation_state = {**self.redteam_validation_state, "state": state, "updated_at": int(time.time()), "last_run": result}
            return result

        bssid = str(target.get("bssid") or target.get("associated_bssid") or "").strip().lower()
        client_mac = str(target.get("mac") or "").strip().lower()
        address_terms: List[str] = []
        if bssid:
            address_terms.append(f"wlan.addr == {bssid}")
        if client_mac:
            address_terms.append(f"wlan.addr == {client_mac}")
        address_filter = " && ".join(address_terms)
        base_filters = {
            "deauth_evidence_probe": "wlan.fc.type_subtype == 0x0c",
            "disassociation_evidence_probe": "wlan.fc.type_subtype == 0x0a",
            "handshake_visibility_trigger": "eapol",
        }
        display_filter = base_filters.get(action_type, "eapol")
        if address_filter:
            display_filter = f"({display_filter}) && {address_filter}"
        artifact_names = {
            "deauth_evidence_probe": "deauth_frames.pcapng",
            "disassociation_evidence_probe": "disassoc_frames.pcapng",
            "handshake_visibility_trigger": "eapol_after_effect.pcapng",
        }
        artifact_extract = self._extract_filtered_pcap_for_redteam(
            str(window_build.get("path") or ""),
            display_filter,
            pcap_dir / artifact_names.get(action_type, "redteam_effect.pcapng"),
        )
        observed_count = int(artifact_extract.get("packet_count") or 0) if artifact_extract.get("ok") else 0
        pmf_enabled = str(target.get("pmf") or "").lower() in {"true", "1", "required", "capable"}
        detection_mapping = self._redteam_detection_mapping(action_type)
        handshake_summary = self._handshake_artifact_summary(target)
        eapol_observed = int(handshake_summary.get("frame_count") or 0) > 0
        effect_observed = observed_count > 0 or (action_type == "handshake_visibility_trigger" and eapol_observed)
        if effect_observed:
            state = "COMPLETED_EFFECT_OBSERVED"
        elif pmf_enabled and action_type in {"deauth_evidence_probe", "disassociation_evidence_probe", "handshake_visibility_trigger"}:
            state = "COMPLETED_DEFENSE_EFFECTIVE"
        else:
            state = "COMPLETED_NO_EFFECT_OBSERVED"
        badges = []
        if observed_count > 0:
            badges.extend(["REAL_FRAMES_OBSERVED", "BLUE_TEAM_SIGNAL_PRESENT"])
        if eapol_observed:
            badges.append("EAPOL_OBSERVED")
        if effect_observed:
            badges.append("EFFECT_OBSERVED")
        else:
            badges.append("NO_EFFECT_OBSERVED")
        if pmf_enabled and not effect_observed:
            badges.append("PMF_LIKELY_EFFECTIVE")

        authorization_scope = {
            "confirm_authorized_lab": bool(confirm_authorized_lab),
            "target_ssid": str(target.get("ssid") or ""),
            "bssid": bssid,
            "client_mac": client_mac,
            "channel": int(channel or target.get("channel") or 0),
            "max_duration": requested_duration,
            "max_frame_count": requested_frames,
            "reason_code": str(reason_code or ""),
            "notes": str(notes or ""),
            "receive_only": True,
        }
        observed_effects = {
            "frames_confirmed_observed": observed_count,
            "effect_observed": bool(effect_observed),
            "pmf_likely_effective": bool(pmf_enabled and not effect_observed),
            "handshake_eapol_frames": int(handshake_summary.get("frame_count") or 0),
            "handshake_sessions": int(handshake_summary.get("session_count") or 0),
            "involved_clients": list(handshake_summary.get("involved_clients") or []),
        }
        timeline = [
            {"at": int(time.time()), "state": "PREFLIGHT_RUNNING", "detail": f"Preflight passed for {target_id}."},
            {"at": int(time.time()), "state": "RUNNING", "detail": f"Built red-team evidence window from {len(source_paths)} retained PCAP source(s)."},
            {"at": int(time.time()), "state": state, "detail": f"Observed {observed_count} matching packet(s). EAPOL {int(handshake_summary.get('frame_count') or 0)}."},
        ]
        evidence_files = {
            "redteam_window_pcap": str(window_build.get("path") or ""),
            "action_pcap": str(artifact_extract.get("path") or ""),
        }
        detection_payload = {
            "action_type": action_type,
            "mapping": detection_mapping,
            "result_badges": badges,
            "wireshark_filter": detection_mapping.get("wireshark_filter") or display_filter,
        }
        trace_payload = {
            "run_id": run_id,
            "session_id": session_id,
            "target_id": target_id,
            "action_type": action_type,
            "receive_only": True,
            "source_pcaps": source_inventory,
            "timeline": timeline,
            "filter_used": display_filter,
        }
        manifest = {
            "run_id": run_id,
            "session_id": session_id,
            "operator_scope": authorization_scope,
            "target_identifiers": {
                "target_id": target_id,
                "ssid": str(target.get("ssid") or ""),
                "bssid": bssid,
                "client_mac": client_mac,
            },
            "interface": (self.sensor_snapshot or {}).get("monitor_interface") or "",
            "channel": int(channel or target.get("channel") or 0),
            "start_time": int(time.time()),
            "end_time": int(time.time()),
            "action_type": action_type,
            "command_or_tool": "receive_only_validation:tshark+mergecap",
            "exact_safety_limits": {
                "max_duration": requested_duration,
                "max_frame_count": requested_frames,
                "transmit_disabled": True,
            },
            "frames_requested": requested_frames,
            "frames_confirmed_observed": observed_count,
            "effect_observed": bool(effect_observed),
            "pmf_likely_effective": bool(pmf_enabled and not effect_observed),
            "evidence_files": evidence_files,
        }
        file_payloads = {
            run_root / "authorization_scope.json": authorization_scope,
            run_root / "preflight.json": preflight,
            run_root / "observed_effects.json": observed_effects,
            run_root / "detection_mapping.json": detection_payload,
            run_root / "redteam_trace.json": trace_payload,
            run_root / "redteam_manifest.json": manifest,
        }
        for path, payload in file_payloads.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        (run_root / "injected_frames.jsonl").write_text("", encoding="utf-8")
        summary_lines = [
            "# WiFi MK7 Red Team Validation Summary",
            f"- Run ID: `{run_id}`",
            f"- Session ID: `{session_id}`",
            f"- Action: `{action_type}`",
            f"- Receive-only: `true`",
            f"- Target: `{target.get('ssid') or target_id}`",
            f"- Result State: `{state}`",
            f"- Matching Frames Observed: `{observed_count}`",
            f"- EAPOL Frames Observed: `{int(handshake_summary.get('frame_count') or 0)}`",
            f"- PMF Likely Effective: `{str(bool(pmf_enabled and not effect_observed)).lower()}`",
            f"- Wireshark Filter: `{detection_mapping.get('wireshark_filter') or display_filter}`",
        ]
        (run_root / "redteam_summary.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

        artifact_hashes = {}
        for label, raw_path in {
            "redteam_window_pcap": str(window_build.get("path") or ""),
            "action_pcap": str(artifact_extract.get("path") or ""),
            "manifest": str(run_root / "redteam_manifest.json"),
            "observed_effects": str(run_root / "observed_effects.json"),
        }.items():
            if raw_path and Path(raw_path).exists():
                artifact_hashes[label] = self.evidence._sha256(Path(raw_path))

        result = {
            "ok": True,
            "state": state,
            "receive_only": True,
            "preflight": preflight,
            "run_id": run_id,
            "session_id": session_id,
            "target": target,
            "authorization_scope": authorization_scope,
            "result_badges": badges,
            "packet_counters": {
                "window_packets": int(window_build.get("packet_count") or 0),
                "matching_packets": observed_count,
                "eapol_packets": int(handshake_summary.get("frame_count") or 0),
            },
            "observed_effects": observed_effects,
            "detection_mapping": detection_payload,
            "timeline": timeline,
            "evidence_files": {
                **evidence_files,
                "summary_markdown": str(run_root / "redteam_summary.md"),
                "manifest": str(run_root / "redteam_manifest.json"),
                "preflight": str(run_root / "preflight.json"),
                "observed_effects": str(run_root / "observed_effects.json"),
                "detection_mapping": str(run_root / "detection_mapping.json"),
                "redteam_trace": str(run_root / "redteam_trace.json"),
            },
            "artifact_hashes": artifact_hashes,
            "message": "Real packet evidence was analyzed and retained from the active owned-lab capture session. No transmit or injection tooling was executed.",
        }
        self.redteam_validation_state = {"state": state, "updated_at": int(time.time()), "last_run": result, "last_preflight": preflight}
        return result

    def _handshake_artifact_summary(self, target: Dict[str, Any]) -> Dict[str, Any]:
        auth_summary = dict(self.tracker.get_authentication_evidence() or {})
        sessions = list(auth_summary.get("sessions") or [])
        target_mac = str(target.get("mac") or "").strip().lower()
        target_bssid = str(target.get("bssid") or target.get("associated_bssid") or ((target.get("associated_network") or {}).get("bssid") or "")).strip().lower()
        matched = []
        for session in sessions:
            session_bssid = str(session.get("bssid") or "").strip().lower()
            session_client = str(session.get("client_mac") or "").strip().lower()
            if target_mac and session_client == target_mac:
                matched.append(session)
            elif target_bssid and session_bssid == target_bssid:
                matched.append(session)
        evidence_refs = []
        involved_clients = []
        for session in matched:
            client_mac = str(session.get("client_mac") or "").strip().lower()
            if client_mac and client_mac not in involved_clients:
                involved_clients.append(client_mac)
            for ref in list(session.get("evidence_refs") or []):
                if len(evidence_refs) >= 24:
                    break
                evidence_refs.append(
                    {
                        "pcap_file": str(ref.get("pcap_file") or "").strip(),
                        "frame_number": int(ref.get("frame_number") or 0),
                        "timestamp": float(ref.get("timestamp") or 0.0),
                        "message_number": ref.get("message_number"),
                        "bssid": session_bssid or target_bssid,
                        "client_mac": client_mac,
                    }
                )
        quality = "NO_HANDSHAKE_OBSERVED"
        if matched:
            session_quality = str(matched[0].get("quality") or "NONE").upper()
            quality = (
                "HANDSHAKE_CONFIRMED"
                if session_quality == "CONFIRMED"
                else "HANDSHAKE_CANDIDATE"
                if session_quality == "LIKELY"
                else "EAPOL_OBSERVED_PARTIAL"
                if session_quality == "PARTIAL"
                else "NO_HANDSHAKE_OBSERVED"
            )
        return {
            "state": quality,
            "session_count": len(matched),
            "frame_count": sum(int(item.get("frame_count") or 0) for item in matched),
            "involved_clients": involved_clients[:16],
            "evidence_refs": evidence_refs,
            "sessions": matched[:8],
            "explanation": (
                "No EAPOL/authentication evidence attributable to this target was retained."
                if not matched
                else (
                    "Full handshake criteria met based on internal completeness rules; artifact retained for manual review."
                    if quality == "HANDSHAKE_CONFIRMED"
                    else "EAPOL frames were observed for this target, but full handshake completeness could not be confirmed."
                )
            ),
        }

    def _resolve_ddi_for_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        target_id = self._wifi_target_id(target)
        cached = self.ddi_cache.get(target_id) or {}
        inventory = self.get_pcap_inventory()
        signature = self.ddi._inventory_signature(inventory)
        if cached and str(cached.get("_signature") or "") == signature:
            return cached
        ddi_result = self.ddi.resolve_target(target, inventory)
        handshake_summary = self._handshake_artifact_summary(target)
        self._normalize_evidence_session()
        evidence_artifacts = self.evidence.write_target_artifacts(
            target=target,
            ddi_resolution=ddi_result,
            handshake_summary=handshake_summary,
        )
        ddi_result["handshake_evidence"] = handshake_summary
        ddi_result["evidence_artifacts"] = evidence_artifacts
        ddi_result["_signature"] = signature
        self.ddi_cache[target_id] = ddi_result
        return ddi_result

    def _artifact_materialization_status(self) -> Dict[str, Any]:
        return {
            "active": self._artifact_materialization_active(),
            "started_at": self.artifact_materialization_started_at,
            "finished_at": self.artifact_materialization_finished_at,
            "last_error": self.artifact_materialization_last_error,
        }

    def _start_artifact_materialization_async(self) -> None:
        if self._artifact_materialization_active():
            return

        def worker() -> None:
            self.artifact_materialization_started_at = time.time()
            self.artifact_materialization_finished_at = None
            self.artifact_materialization_last_error = ""
            try:
                self._materialize_all_target_artifacts()
                self._invalidate_target_snapshot_cache()
            except Exception as exc:
                self.artifact_materialization_last_error = f"{exc.__class__.__name__}: {exc}"
            finally:
                self.artifact_materialization_finished_at = time.time()

        self.artifact_materialization_thread = threading.Thread(
            target=worker,
            daemon=True,
            name="wifi-mk7-artifacts",
        )
        self.artifact_materialization_thread.start()

    def _materialize_all_target_artifacts(self) -> None:
        if not self.evidence.current_session:
            return
        networks = self.intelligence.enrich_networks(self.tracker.get_networks(), self.tracker.get_clients())
        clients = self.intelligence.enrich_clients(self.tracker.get_clients())
        for target in [*networks, *clients]:
            self._resolve_ddi_for_target(target)

    def _merge_runtime_context_into_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        merged = self._merge_service_audit_into_target(target)
        ddi_result = self._resolve_ddi_for_target(merged)
        merged["ddi_resolution"] = {key: value for key, value in ddi_result.items() if key != "_signature"}
        merged["evidence_artifacts"] = dict(ddi_result.get("evidence_artifacts") or {})
        merged["handshake_evidence"] = dict(ddi_result.get("handshake_evidence") or {})
        self._ensure_destination_analysis_for_target(
            target_key=self._wifi_target_id(merged),
            ddi_resolution=ddi_result,
        )
        return self._merge_destination_analysis_into_target(merged)

    def _merge_service_audit_into_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(target)
        target_id = self._wifi_target_id(target)
        cached = self.service_audit_cache.get(target_id) or {}
        if cached:
            merged["service_audit"] = cached
        return merged

    def _load_retained_destination_analysis(self, target_id: str) -> Dict[str, Any]:
        target_record = dict(self.evidence.current_targets.get(target_id) or {})
        analysis_path = str(target_record.get("destination_analysis") or "").strip()
        if not analysis_path:
            return {}
        path = Path(analysis_path)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _artifact_signature(path_value: str) -> str:
        path = Path(str(path_value or "").strip())
        if not path.exists():
            return ""
        try:
            stat = path.stat()
            return f"{path}:{int(stat.st_mtime)}:{int(stat.st_size)}"
        except Exception:
            return str(path)

    def _destination_analysis_signature(self, ddi_resolution: Dict[str, Any]) -> str:
        evidence_artifacts = dict(ddi_resolution.get("evidence_artifacts") or {})
        validated = list(ddi_resolution.get("validated_candidates") or [])
        target_ip = str(next(iter(validated), {}).get("candidate_ip") or "").strip()
        parts = [
            str(ddi_resolution.get("_signature") or ""),
            str(ddi_resolution.get("resolution_state") or ""),
            target_ip,
            self._artifact_signature(str(evidence_artifacts.get("target_filtered_pcap") or "")),
            self._artifact_signature(str(evidence_artifacts.get("ddi_resolution_path") or "")),
        ]
        return "|".join(parts)

    def _destination_analysis_ready(self, ddi_resolution: Dict[str, Any]) -> bool:
        state = str(ddi_resolution.get("resolution_state") or "").strip().upper()
        if state not in {"VALIDATED_IP", "VALIDATED_MULTI_IP"}:
            return False
        evidence_artifacts = dict(ddi_resolution.get("evidence_artifacts") or {})
        return bool(
            str(evidence_artifacts.get("target_filtered_pcap") or "").strip()
            and str(evidence_artifacts.get("ddi_resolution_path") or "").strip()
        )

    def _ensure_destination_analysis_for_target(
        self,
        *,
        target_key: str,
        ddi_resolution: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not self._destination_analysis_ready(ddi_resolution):
            return {}
        source_signature = self._destination_analysis_signature(ddi_resolution)
        cached = dict(self.destination_analysis_cache.get(target_key) or {})
        if cached and str(cached.get("_source_signature") or "") == source_signature:
            return cached
        retained = self._load_retained_destination_analysis(target_key)
        if retained and str(retained.get("_source_signature") or "") == source_signature:
            self.destination_analysis_cache[target_key] = retained
            return retained
        return self._run_external_destination_analysis(
            target_key=target_key,
            ddi_resolution=ddi_resolution,
            source_signature=source_signature,
        )

    def _merge_destination_analysis_into_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(target)
        target_id = self._wifi_target_id(target)
        analysis = dict(self.destination_analysis_cache.get(target_id) or {})
        if not analysis:
            analysis = self._load_retained_destination_analysis(target_id)
            if analysis:
                self.destination_analysis_cache[target_id] = analysis
        if not analysis:
            return merged
        merged["destination_analysis"] = analysis
        evidence_artifacts = dict(merged.get("evidence_artifacts") or {})
        evidence_artifacts.update({key: value for key, value in (analysis.get("evidence_artifacts") or {}).items() if str(value or "").strip()})
        target_record = dict(self.evidence.current_targets.get(target_id) or {})
        for key in ("destination_analysis", "external_ips", "dns_records", "tls_metadata"):
            value = str(target_record.get(key) or "").strip()
            if value:
                evidence_artifacts[key] = value
        if evidence_artifacts:
            merged["evidence_artifacts"] = evidence_artifacts
        service_audit = dict(merged.get("service_audit") or {})
        if service_audit and not service_audit.get("destination_analysis"):
            service_audit["destination_analysis"] = analysis
            service_audit["evidence_artifacts"] = {
                **dict(service_audit.get("evidence_artifacts") or {}),
                **{key: value for key, value in evidence_artifacts.items() if key in {"destination_analysis", "external_ips", "dns_records", "tls_metadata"}},
            }
            merged["service_audit"] = service_audit
        return merged

    def _find_wifi_target(self, target_id: str) -> Dict[str, Any] | None:
        needle = str(target_id or "").strip().lower()
        if not needle:
            return None
        for target in [*self.get_networks(), *self.get_clients()]:
            if needle in self._wifi_target_aliases(target):
                return target
        for target in self._active_airodump_targets():
            if needle in self._wifi_target_aliases(target):
                return target
        return None

    @staticmethod
    def _neighbor_ips_for_macs(macs: List[str]) -> List[str]:
        known = {str(item or "").strip().lower() for item in macs if str(item or "").strip()}
        if not known:
            return []
        candidates: List[str] = []
        arp_path = Path("/proc/net/arp")
        try:
            if arp_path.exists():
                for raw in arp_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                    parts = raw.split()
                    if len(parts) >= 4 and str(parts[3]).strip().lower() in known:
                        ip_value = str(parts[0]).strip()
                        if ip_value and ip_value not in candidates:
                            candidates.append(ip_value)
        except Exception:
            pass
        try:
            result = subprocess.run(
                ["/usr/sbin/ip", "neigh"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            for raw in (result.stdout or "").splitlines():
                parts = raw.split()
                if "lladdr" in parts:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts) and str(parts[idx + 1]).strip().lower() in known:
                        ip_value = str(parts[0]).strip()
                        if ip_value and ip_value not in candidates:
                            candidates.append(ip_value)
        except Exception:
            pass
        return candidates

    def _collect_target_candidate_ips(self, target: Dict[str, Any]) -> List[str]:
        candidate_ips: List[str] = []
        ddi_resolution = dict(target.get("ddi_resolution") or {})
        for value in (
            target.get("ip"),
            target.get("ip_address"),
            target.get("local_ip"),
            ((target.get("service_audit") or {}).get("target_validation") or {}).get("target_ip"),
        ):
            normalized = str(value or "").strip()
            if normalized and normalized not in candidate_ips:
                candidate_ips.append(normalized)
        for bucket in (
            list(target.get("ip_addresses") or []),
            list(target.get("candidate_ip_addresses") or []),
        ):
            for value in bucket:
                normalized = str(value or "").strip()
                if normalized and normalized not in candidate_ips:
                    candidate_ips.append(normalized)
        for value in self._neighbor_ips_for_macs(self._lead_mac_candidates(target)):
            if value not in candidate_ips:
                candidate_ips.append(value)
        stable = dict(target.get("stable_fingerprint") or {})
        for bucket in (
            list((stable.get("dhcp_assigned_ips") or [])),
            list((stable.get("related_ips") or [])),
            list((stable.get("recurring_destination_ips") or {}).keys()),
            list((stable.get("associated_network_recurring_ips") or {}).keys()),
            list(((target.get("active_fingerprint") or {}).get("candidate_ips") or [])),
        ):
            for value in bucket:
                normalized = str(value or "").strip()
                if normalized and normalized not in candidate_ips:
                    candidate_ips.append(normalized)
        for candidate in list(ddi_resolution.get("validated_candidates") or []) + list(ddi_resolution.get("candidate_ips") or []):
            normalized = str(candidate.get("candidate_ip") or "").strip()
            if normalized and normalized not in candidate_ips:
                candidate_ips.append(normalized)
        flow_intel = self._extract_mac_flows_from_pcaps(target, self.get_pcap_inventory())
        validated_ip = str(flow_intel.get("validated_ip") or "").strip()
        if validated_ip and validated_ip not in candidate_ips:
            candidate_ips.insert(0, validated_ip)
        return candidate_ips[:12]

    def _find_camera_lead(self, lead_id: str, leads: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        needle = str(lead_id or "").strip().lower()
        if not needle:
            return None
        for lead in leads or []:
            aliases = {
                self._camera_lead_id(lead),
                str(lead.get("mac") or "").strip().lower(),
                str(lead.get("bssid") or "").strip().lower(),
                str(lead.get("record_id") or "").strip().lower(),
            }
            aliases = {value for value in aliases if value}
            if needle in aliases:
                return lead
        return None

    def _camera_lead_pool(self) -> List[Dict[str, Any]]:
        results = self.get_camera_hunt_results()
        pooled: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for lead in (results.get("leads") or []) + (results.get("near_misses") or []) + self.get_clients() + self.get_networks():
            lead_key = self._camera_lead_id(lead)
            if not lead_key or lead_key in seen:
                continue
            pooled.append(self._merge_probe_cache_into_lead(lead))
            seen.add(lead_key)
        return pooled

    def _merge_probe_cache_into_lead(self, lead: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(lead)
        lead_key = self._camera_lead_id(lead)
        cache = self.active_probe_cache.get(lead_key) or {}
        if cache:
            merged["active_fingerprint"] = cache
        hard_audit = self.hard_audit_cache.get(lead_key) or {}
        if hard_audit:
            merged["hard_audit"] = hard_audit
            if hard_audit.get("active_fingerprint"):
                merged["active_fingerprint"] = hard_audit.get("active_fingerprint")
        if merged.get("active_fingerprint") and merged.get("cloud_camera_evidence"):
            evidence = dict(merged.get("cloud_camera_evidence") or {})
            active = dict(merged.get("active_fingerprint") or {})
            summary = dict(active.get("summary") or {})
            if not evidence.get("target_ips"):
                evidence["target_ips"] = list(active.get("candidate_ips") or [])
            if summary.get("video_or_image_proof"):
                evidence["proof_status"] = "visual_artifact"
                evidence["proof_level"] = str(summary.get("proof_level") or "VISUAL_ARTIFACT")
            elif summary.get("camera_positive"):
                evidence["proof_status"] = "service_hint"
                evidence["proof_level"] = str(summary.get("proof_level") or "SERVICE_HINT_ONLY")
            merged["cloud_camera_evidence"] = evidence
        return merged

    @staticmethod
    def _attach_association_context(lead: Dict[str, Any], network_lookup: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        merged = dict(lead)
        if str(merged.get("leadKind") or "").lower() != "client":
            merged["associated_ssid"] = str(merged.get("associated_ssid") or merged.get("ssid") or "")
            return merged
        associated_bssid = str(merged.get("associated_bssid") or "").strip().lower()
        associated_network = network_lookup.get(associated_bssid) or {}
        merged["associated_ssid"] = str(
            merged.get("associated_ssid")
            or associated_network.get("ssid")
            or ""
        ).strip()
        if associated_network:
            merged["associated_network"] = {
                "bssid": str(associated_network.get("bssid") or ""),
                "ssid": str(associated_network.get("ssid") or ""),
                "service_exposure": dict(associated_network.get("service_exposure") or {}),
                "stable_fingerprint": dict(associated_network.get("stable_fingerprint") or {}),
                "camera_detection": dict(associated_network.get("camera_detection") or {}),
                "evidence_provenance": list(associated_network.get("evidence_provenance") or []),
            }
        return merged

    def _lead_with_association_context(self, lead: Dict[str, Any]) -> Dict[str, Any]:
        if str(lead.get("leadKind") or "").lower() != "client":
            return dict(lead)
        associated_bssid = str(lead.get("associated_bssid") or "").strip().lower()
        if not associated_bssid:
            return dict(lead)
        associated_network = next(
            (
                network for network in self.get_networks()
                if str(network.get("bssid") or "").strip().lower() == associated_bssid
            ),
            None,
        )
        if not associated_network:
            return dict(lead)
        merged = dict(lead)
        merged["associated_ssid"] = str(associated_network.get("ssid") or merged.get("associated_ssid") or "").strip()
        merged["associated_network"] = {
            "bssid": str(associated_network.get("bssid") or ""),
            "ssid": str(associated_network.get("ssid") or ""),
            "service_exposure": dict(associated_network.get("service_exposure") or {}),
            "stable_fingerprint": dict(associated_network.get("stable_fingerprint") or {}),
            "camera_detection": dict(associated_network.get("camera_detection") or {}),
            "evidence_provenance": list(associated_network.get("evidence_provenance") or []),
        }
        merged_service_exposure = dict(merged.get("service_exposure") or {})
        associated_service_exposure = dict((associated_network.get("service_exposure") or {}))
        if associated_service_exposure:
            merged_service_exposure["associated_network_summary"] = str(associated_service_exposure.get("summary") or "")
            merged_service_exposure["associated_network_protocols"] = list(associated_service_exposure.get("protocols") or [])
            merged_service_exposure["associated_network_services"] = list(associated_service_exposure.get("services") or [])
            merged["service_exposure"] = merged_service_exposure
        merged_stable = dict(merged.get("stable_fingerprint") or {})
        associated_stable = dict(associated_network.get("stable_fingerprint") or {})
        if associated_stable:
            merged_stable["associated_network_ssid"] = str(associated_network.get("ssid") or "")
            merged_stable["associated_network_bssid"] = str(associated_network.get("bssid") or "")
            merged_stable["associated_network_recurring_ips"] = dict(associated_stable.get("recurring_destination_ips") or {})
            merged["stable_fingerprint"] = merged_stable
        merged_evidence = list(merged.get("evidence_provenance") or [])
        merged_evidence.extend(list(associated_network.get("evidence_provenance") or [])[:8])
        merged["evidence_provenance"] = merged_evidence
        return merged

    def _auto_probe_top_camera_leads(self, max_leads: int = 3) -> Dict[str, Any]:
        results = self.get_camera_hunt_results()
        retained_leads = list(results.get("leads") or [])
        if not retained_leads:
            retained_leads = list(results.get("near_misses") or [])
        retained_leads.sort(
            key=lambda lead: (
                len(self.active_fingerprint._candidate_ips(lead)),
                float((lead.get("camera_detection") or {}).get("score") or 0.0),
                float((lead.get("target_score") or {}).get("score") or 0.0),
            ),
            reverse=True,
        )
        retained_leads = retained_leads[: max(1, int(max_leads or 5))]
        probed_leads: List[Dict[str, Any]] = []
        attempted = 0
        positive = 0

        for lead in retained_leads:
            lead_id = self._camera_lead_id(lead)
            if not lead_id:
                continue

            cached = self.active_probe_cache.get(lead_id)
            if cached:
                summary = cached.get("summary") or {}
                is_positive = bool(summary.get("camera_positive"))
                attempted += 1
                positive += 1 if is_positive else 0
                probed_leads.append(
                    {
                        "lead_id": lead_id,
                        "identity": str(lead.get("ssid") or lead.get("mac") or lead.get("bssid") or lead.get("record_id") or "<unknown>"),
                        "cached": True,
                        "camera_positive": is_positive,
                        "candidate_ips": list(cached.get("candidate_ips") or [])[:4],
                    }
                )
                continue

            probe = self.active_fingerprint.probe_lead(lead)
            attempted += 1
            self.active_probe_cache[lead_id] = probe
            summary = probe.get("summary") or {}
            is_positive = bool(summary.get("camera_positive"))
            positive += 1 if is_positive else 0
            probed_leads.append(
                {
                    "lead_id": lead_id,
                    "identity": str(lead.get("ssid") or lead.get("mac") or lead.get("bssid") or lead.get("record_id") or "<unknown>"),
                    "cached": False,
                    "ok": bool(probe.get("ok")),
                    "camera_positive": is_positive,
                    "candidate_ips": list(probe.get("candidate_ips") or [])[:4],
                    "error": str(probe.get("error") or ""),
                }
            )

        self.auto_probe_summary = {
            "enabled": True,
            "attempted": attempted,
            "positive": positive,
            "probed_leads": probed_leads,
            "updated_at": time.time(),
        }
        return self.auto_probe_summary

    @staticmethod
    def _camera_lead_sample(lead: Dict[str, Any]) -> Dict[str, Any]:
        service_exposure = lead.get("service_exposure") or {}
        camera_detection = lead.get("camera_detection") or {}
        return {
            "timestamp": int(time.time()),
            "classification": str(camera_detection.get("classification") or "Unknown"),
            "score": float(camera_detection.get("score") or 0.0),
            "confidence": float(camera_detection.get("confidence") or 0.0),
            "protocols": list(service_exposure.get("protocols") or []),
            "services": list(service_exposure.get("services") or []),
            "cloud_endpoints": list(service_exposure.get("cloud_endpoints") or []),
            "summary": str(service_exposure.get("summary") or lead.get("behavior_analysis", {}).get("summary") or "Limited passive evidence"),
            "indicators": list(camera_detection.get("indicators") or []),
            "matched_families": list(camera_detection.get("matched_families") or []),
            "packet_count": int(lead.get("packet_count") or 0),
            "rssi_dbm": float(lead.get("rssi_dbm") or 0.0),
        }

    @staticmethod
    def _xiaomi_decode_constraints(
        lead: Dict[str, Any],
        xiaomi_profile: Dict[str, Any],
        xiaomi_local_api: Dict[str, Any],
        active_probe: Dict[str, Any],
        traffic_intelligence: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not bool(xiaomi_profile.get("matched")):
            return {"matched": False, "summary": "No Xiaomi-family decode constraint was inferred."}

        probe_summary = dict(active_probe.get("summary") or {})
        flow_debug = dict(traffic_intelligence.get("debug") or {})
        endpoint_count = len(list(traffic_intelligence.get("endpoints") or []))
        local_hits = int(probe_summary.get("http_hits") or 0) + int(probe_summary.get("onvif_hits") or 0) + int(probe_summary.get("rtsp_hits") or 0) + int(probe_summary.get("snapshot_hits") or 0)
        miio_surface = bool((xiaomi_local_api.get("surface") or {}).get("miio_surface"))
        phone_visible_stream = bool((((lead.get("video_evidence") or {}).get("correlation") or {}).get("flow_triggered_by_live_view")))
        blocked = local_hits <= 0 and endpoint_count <= 0
        summary = (
            "Phone-visible live view is likely cloud-relayed for this Xiaomi-family device; passive Wi-Fi capture alone is not enough to decode media."
            if blocked and phone_visible_stream
            else "Xiaomi-family stream path constraints were evaluated."
        )
        return {
            "matched": True,
            "likely_cloud_relay": bool(blocked and phone_visible_stream),
            "miio_surface": miio_surface,
            "passive_wifi_decode_blocked": bool(blocked),
            "phone_visible_stream": phone_visible_stream,
            "local_media_hits": local_hits,
            "attributed_endpoint_count": endpoint_count,
            "packets_from_mac": int(flow_debug.get("packets_from_mac") or 0),
            "ip_packets_from_mac": int(flow_debug.get("ip_packets_from_mac") or 0),
            "summary": summary,
            "reason": (
                "The camera can be continuously streaming to the vendor cloud while monitor-mode Wi-Fi capture still only retains encrypted 802.11 payloads or non-attributable traffic."
                if blocked
                else "Some locally attributable media indicators were retained."
            ),
            "requirements_for_decode": [
                "WPA session keys or decryptable IP payloads",
                "Mi Home / Xiaomi cloud stream URL or token path",
                "A locally exposed snapshot, HTTP, ONVIF, or RTSP service",
            ],
            "next_steps": [
                "Capture the app-side Mi Home / Xiaomi Home cloud request path during live view.",
                "Test Xiaomi token / miIO control viability on UDP 54321.",
                "Treat packet volume alone as insufficient unless IP payloads or cloud stream URLs are recovered.",
            ],
        }

    def analyze_camera_lead(self, lead_id: str, seconds: int = 30) -> Dict[str, Any]:
        bounded_seconds = max(5, min(30, int(seconds or 30)))
        lead = self._find_camera_lead(lead_id, self._camera_lead_pool())
        if lead is None:
            return {"ok": False, "error": "Camera lead not found in hunt results.", "lead_id": lead_id}

        active_collection = bool(self.capture_active and self.scan_camera_hunt)
        sample_interval = 5
        deadline = time.time() + bounded_seconds
        samples: List[Dict[str, Any]] = []

        while True:
            current = self._find_camera_lead(lead_id, self._camera_lead_pool())
            if current is not None:
                lead = current
                samples.append(self._camera_lead_sample(current))

            remaining = deadline - time.time()
            if remaining <= 0 or not active_collection:
                break
            time.sleep(min(sample_interval, max(1.0, remaining)))

        if not samples:
            samples.append(self._camera_lead_sample(lead))

        protocols = sorted({value for sample in samples for value in (sample.get("protocols") or [])})
        services = sorted({value for sample in samples for value in (sample.get("services") or [])})
        indicators = []
        for sample in samples:
            for indicator in sample.get("indicators") or []:
                if indicator not in indicators:
                    indicators.append(indicator)
        matched_families = []
        for sample in samples:
            for family in sample.get("matched_families") or []:
                if family not in matched_families:
                    matched_families.append(family)

        confidences = [float(sample.get("confidence") or 0.0) for sample in samples]
        scores = [float(sample.get("score") or 0.0) for sample in samples]
        packet_counts = [int(sample.get("packet_count") or 0) for sample in samples]
        classifications = [str(sample.get("classification") or "Unknown") for sample in samples]
        camera_detection = lead.get("camera_detection") or {}
        service_exposure = lead.get("service_exposure") or {}
        fingerprint = lead.get("fingerprint") or {}

        avg_confidence = round(sum(confidences) / max(1, len(confidences)), 2)
        max_confidence = round(max(confidences, default=0.0), 2)
        avg_score = round(sum(scores) / max(1, len(scores)), 1)
        max_score = round(max(scores, default=0.0), 1)
        latest_summary = next((str(sample.get("summary") or "").strip() for sample in reversed(samples) if str(sample.get("summary") or "").strip()), "")
        observation_status = (
            f"Tracked {len(samples)} sample windows during active camera hunt."
            if active_collection
            else "No active camera hunt session; analysis used retained passive evidence only."
        )
        recommendation = (
            "Retain this lead and continue passive collection for stronger protocol and vendor confirmation."
            if max_confidence >= 0.6
            else "Treat as tentative; gather more passive metadata before escalating classification."
        )

        return {
            "ok": True,
            "lead_id": lead_id,
            "seconds_requested": bounded_seconds,
            "seconds_observed": bounded_seconds if active_collection else 0,
            "active_collection": active_collection,
            "observation_status": observation_status,
            "lead": lead,
            "analysis": {
                "label": str(camera_detection.get("classification") or "Camera Lead"),
                "device_type": str(camera_detection.get("device_type") or fingerprint.get("device_type") or "Unknown"),
                "confidence_tier": str(camera_detection.get("confidence_tier") or "LOW"),
                "avg_confidence": avg_confidence,
                "max_confidence": max_confidence,
                "avg_score": avg_score,
                "max_score": max_score,
                "sample_count": len(samples),
                "classifications": classifications,
                "protocols": protocols,
                "services": services,
                "cloud_endpoints": list(service_exposure.get("cloud_endpoints") or [])[:6],
                "indicators": indicators[:8],
                "matched_families": matched_families[:6],
                "latest_summary": latest_summary or str(service_exposure.get("summary") or "Limited passive evidence"),
                "recommendation": recommendation,
                "packet_span": {
                    "min": min(packet_counts) if packet_counts else 0,
                    "max": max(packet_counts) if packet_counts else 0,
                },
            },
            "samples": samples,
        }

    def probe_camera_lead(self, lead_id: str) -> Dict[str, Any]:
        lead = self._find_camera_lead(lead_id, self._camera_lead_pool())
        if lead is None:
            return {"ok": False, "error": "Camera lead not found in hunt results.", "lead_id": lead_id}
        lead = self._lead_with_association_context(lead)
        lead_key = self._camera_lead_id(lead)
        probe = self.active_fingerprint.probe_lead(lead)
        self.active_probe_cache[lead_key] = probe
        self.active_probe_cache[lead_id] = probe
        if not probe.get("ok"):
            return {
                "ok": False,
                "error": probe.get("error") or "Active fingerprinting failed.",
                "lead_id": lead_id,
                "lead": lead,
                "active_fingerprint": probe,
            }
        validation = self.camera_validation.validate_lead(
            lead={**lead, "lead_id": lead_id},
            active_probe=probe,
            analysis=None,
            pcap_inventory=self.get_pcap_inventory(),
            run_type="camera_probe_validation",
        )
        recommendation = (
            "Treat active probe evidence as a strong discriminator and merge with passive role scoring."
            if bool(((probe.get("summary") or {}).get("camera_positive")))
            else "No strong ONVIF/RTSP/HTTP camera fingerprint returned; keep this as vendor-family or unresolved."
        )
        return {
            "ok": True,
            "lead_id": lead_id,
            "lead": lead,
            "active_fingerprint": probe,
            "validation_report": validation,
            "recommendation": recommendation,
        }

    def probe_camera_ip(self, ip: str) -> Dict[str, Any]:
        probe = self.active_fingerprint.probe_ip(ip)
        if not probe.get("ok"):
            return {"ok": False, "error": probe.get("error") or "Active fingerprinting failed.", "ip": ip}
        validation = self.camera_validation.validate_lead(
            lead={"lead_id": f"ip:{ip}", "record_id": ip, "device_type": "camera_or_video_iot"},
            active_probe=probe,
            analysis=None,
            pcap_inventory=self.get_pcap_inventory(),
            run_type="camera_ip_validation",
        )
        recommendation = (
            "Treat active probe evidence as a strong discriminator and merge with passive role scoring."
            if bool(((probe.get("summary") or {}).get("camera_positive")))
            else "No strong ONVIF/RTSP/HTTP/snapshot camera fingerprint returned; treat this target as router, hub, or unresolved unless more evidence appears."
        )
        return {
            "ok": True,
            "ip": ip,
            "active_fingerprint": probe,
            "validation_report": validation,
            "recommendation": recommendation,
        }

    def validate_camera_lead(self, lead_id: str, seconds: int = 30) -> Dict[str, Any]:
        lead = self._find_camera_lead(lead_id, self._camera_lead_pool())
        if lead is None:
            return {"ok": False, "error": "Camera lead not found in hunt results.", "lead_id": lead_id}
        lead = self._lead_with_association_context(lead)

        analysis = self.analyze_camera_lead(lead_id, seconds=seconds)
        if not analysis.get("ok"):
            analysis = {
                "ok": True,
                "lead_id": lead_id,
                "seconds_requested": int(seconds or 30),
                "seconds_observed": 0,
                "active_collection": False,
                "observation_status": "No retained active analysis; validation fell back to current hunt snapshot.",
                "lead": lead,
                "analysis": {},
                "samples": [],
            }
        probe_result = self.probe_camera_lead(lead_id)
        if not probe_result.get("ok"):
            report = self.camera_validation.validate_lead(
                lead={**lead, "lead_id": lead_id},
                active_probe={"ok": False, "error": probe_result.get("error") or "Active probe failed", "candidate_ip_reason": "probe_failure"},
                analysis=analysis,
                pcap_inventory=self.get_pcap_inventory(),
                run_type="camera_lead_validation",
            )
            return {
                "ok": False,
                "lead_id": lead_id,
                "analysis": analysis,
                "active_fingerprint": probe_result.get("active_fingerprint") or {},
                "validation_report": report,
                "error": probe_result.get("error") or "Active validation failed.",
            }
        report = self.camera_validation.validate_lead(
            lead={**lead, "lead_id": lead_id},
            active_probe=probe_result.get("active_fingerprint") or {},
            analysis=analysis,
            pcap_inventory=self.get_pcap_inventory(),
            run_type="camera_lead_validation",
        )
        return {
            "ok": True,
            "lead_id": lead_id,
            "analysis": analysis,
            "active_fingerprint": probe_result.get("active_fingerprint") or {},
            "validation_report": report,
        }

    def hard_audit_camera_lead(self, lead_id: str, seconds: int = 30) -> Dict[str, Any]:
        lead = self._find_camera_lead(lead_id, self._camera_lead_pool())
        if lead is None:
            return {"ok": False, "error": "Camera lead not found in hunt results.", "lead_id": lead_id}
        lead = self._lead_with_association_context(lead)
        hard_audit_start = time.time()
        self._seed_hard_audit_state(lead_id)
        analysis = self.analyze_camera_lead(lead_id, seconds=seconds)

        self._update_hard_audit_stage(
            lead_id,
            "passive_probe",
            status="active",
            detail="Running initial passive-backed probe.",
            summary="Hard audit: passive evidence and initial probe running.",
        )
        initial_probe = self.active_fingerprint.probe_lead(lead, aggressive=False)
        candidate_pool = list(initial_probe.get("candidate_ips") or [])
        self._update_hard_audit_stage(
            lead_id,
            "passive_probe",
            status="completed" if initial_probe.get("ok") else "partial",
            detail=(
                f"{len(candidate_pool)} candidate IPs from initial probe."
                if candidate_pool
                else str(initial_probe.get("candidate_ip_reason") or initial_probe.get("error") or "Initial probe produced no candidate path.")
            ),
            extra={"initial_probe": initial_probe},
        )

        xiaomi_profile = self._xiaomi_family_profile(lead, analysis)
        if xiaomi_profile.get("matched"):
            self._ensure_hard_audit_stage(
                lead_id,
                "xiaomi_firmware",
                detail="Family-specific firmware and model profile not evaluated.",
            )
            self._ensure_hard_audit_stage(
                lead_id,
                "xiaomi_cloud",
                detail="Mi Home / cloud relay path not evaluated.",
                insert_after="xiaomi_firmware",
            )
            self._ensure_hard_audit_stage(
                lead_id,
                "xiaomi_local_api",
                detail="MIIO / MIoT local transport not evaluated.",
                insert_after="xiaomi_cloud",
            )
            self._update_hard_audit_stage(
                lead_id,
                "xiaomi_firmware",
                status="completed",
                detail=(
                    ", ".join(xiaomi_profile.get("model_hints") or ["Xiaomi / Chuangmi family"])
                    + " · stock firmware is likely app-managed and cloud-first."
                ),
                summary="Hard audit: Xiaomi-family firmware profile recognized.",
                extra={"xiaomi_family_profile": xiaomi_profile},
            )
            self._update_hard_audit_stage(
                lead_id,
                "xiaomi_cloud",
                status="completed",
                detail=(
                    ", ".join(xiaomi_profile.get("cloud_markers") or ["Mi Home / MIoT relay expected"])
                    + " · local RTSP/ONVIF absence may be normal for this family."
                ),
                summary="Hard audit: Xiaomi-family cloud relay pattern recognized.",
                extra={"xiaomi_family_profile": xiaomi_profile},
            )
        else:
            hard_audit = dict(self.hard_audit_cache.get(lead_id) or {})
            pipeline = dict(hard_audit.get("pipeline") or {})
            stages = [
                stage
                for stage in list(pipeline.get("stages") or [])
                if str((stage or {}).get("id") or "") not in {"xiaomi_firmware", "xiaomi_cloud", "xiaomi_local_api"}
            ]
            pipeline["stages"] = stages
            pipeline["xiaomi_family_profile"] = xiaomi_profile
            hard_audit["pipeline"] = pipeline
            self.hard_audit_cache[lead_id] = hard_audit

        self._update_hard_audit_stage(
            lead_id,
            "network_reality",
            status="active",
            detail="Validating candidate IPs against gateway and ARP reality.",
            summary="Hard audit: verifying target IP reality.",
        )
        network_reality = self._validate_candidate_ips(lead, candidate_pool)
        validated_candidates = list(network_reality.get("validated_candidates") or [])
        rejected_candidates = list(network_reality.get("rejected_candidates") or [])
        validated_ips = [str(item.get("ip") or "").strip() for item in validated_candidates if str(item.get("ip") or "").strip()]
        self._update_hard_audit_stage(
            lead_id,
            "network_reality",
            status="completed" if validated_ips else "partial",
            detail=(
                f"{len(validated_ips)} validated IPs · {len(rejected_candidates)} rejected."
                if validated_candidates or rejected_candidates
                else "No gateway-safe IP candidate was validated yet."
            ),
            extra={"network_reality": network_reality},
        )

        self._update_hard_audit_stage(
            lead_id,
            "ip_materialization",
            status="active",
            detail="Escalating IP materialization using subnet and discovery evidence.",
            summary="Hard audit: escalating IP materialization.",
        )
        aggressive_probe = initial_probe
        if not validated_ips:
            aggressive_probe = self.active_fingerprint.probe_lead(lead, aggressive=True)
            aggressive_candidates = list(aggressive_probe.get("candidate_ips") or [])
            candidate_pool = list(dict.fromkeys([*candidate_pool, *aggressive_candidates]))
            network_reality = self._validate_candidate_ips(lead, candidate_pool)
            validated_candidates = list(network_reality.get("validated_candidates") or [])
            rejected_candidates = list(network_reality.get("rejected_candidates") or [])
            validated_ips = [str(item.get("ip") or "").strip() for item in validated_candidates if str(item.get("ip") or "").strip()]
        materialization_detail = (
            f"{len(validated_ips)} validated IPs retained."
            if validated_ips
            else str(aggressive_probe.get("candidate_ip_reason") or aggressive_probe.get("error") or "IP materialization remained unresolved.")
        )
        self._update_hard_audit_stage(
            lead_id,
            "ip_materialization",
            status="completed" if validated_ips else "blocked",
            detail=materialization_detail,
            extra={"network_reality": network_reality, "aggressive_probe": aggressive_probe},
        )

        xiaomi_local_api = {}
        if xiaomi_profile.get("matched"):
            self._update_hard_audit_stage(
                lead_id,
                "xiaomi_local_api",
                status="active",
                detail="Testing Xiaomi-family local transport exposure.",
                summary="Hard audit: checking MIIO / MIoT local API surface.",
            )
            xiaomi_local_api = self._xiaomi_local_api_test(validated_ips or candidate_pool)
            self._update_hard_audit_stage(
                lead_id,
                "xiaomi_local_api",
                status="completed" if xiaomi_local_api.get("ok") else "partial",
                detail=str(xiaomi_local_api.get("summary") or "No Xiaomi-family local API result."),
                extra={"xiaomi_local_api": xiaomi_local_api},
            )
        else:
            pass

        final_probe = aggressive_probe
        if validated_ips:
            final_probe = self.active_fingerprint.probe_ips(validated_ips[:4], source="hard_audit_validated_ip")
            final_probe["candidate_ip_reason"] = "validated_target_ip"
            final_probe["validated_candidates"] = validated_candidates[:4]
            final_probe["rejected_candidates"] = rejected_candidates[:8]

        self.active_probe_cache[lead_id] = final_probe
        direct_capture_target_ip = ""
        for ip_value in validated_ips + [str(item).strip() for item in list(final_probe.get("candidate_ips") or []) if str(item).strip()]:
            if ip_value:
                direct_capture_target_ip = ip_value
                break

        baseline_seconds = max(5, min(10, int(max(24, int(seconds or 30)) * 0.25)))
        trigger_seconds = max(8, min(16, int(max(24, int(seconds or 30)) * 0.4)))
        post_trigger_seconds = max(5, min(10, int(max(24, int(seconds or 30)) * 0.25)))
        targeted_truth_captures: List[Dict[str, Any]] = []
        direct_truth_captures: List[Dict[str, Any]] = []
        if direct_capture_target_ip:
            self._update_hard_audit_stage(
                lead_id,
                "direct_ip_capture",
                status="active",
                detail=f"Capturing routed traffic for {direct_capture_target_ip} during live-view windows.",
                summary="Hard audit: collecting direct target-IP packet evidence.",
            )

        self._update_hard_audit_stage(
            lead_id,
            "baseline",
            status="active",
            detail=f"Capturing idle baseline on channel {int(lead.get('channel') or 0) or int(((lead.get('associated_network') or {}).get('channel') or 0))} for {baseline_seconds}s.",
            summary="Hard audit: establishing baseline window.",
        )
        baseline_capture = self._run_targeted_truth_capture(lead, "baseline", baseline_seconds)
        targeted_truth_captures.append(baseline_capture)
        self._update_hard_audit_stage(
            lead_id,
            "baseline",
            status="completed",
            detail=(
                f"Baseline capture retained {int(baseline_capture.get('frame_count') or 0)} frames."
                if baseline_capture.get("ok")
                else str(baseline_capture.get("error") or "Baseline capture failed.")
            ),
            extra={
                "operator_prompt": {"state": "baseline_complete", "message": "Baseline retained. Open the device live view now."},
                "truth_captures": {"baseline": baseline_capture},
            },
        )
        self._update_hard_audit_stage(
            lead_id,
            "trigger",
            status="active",
            detail=f"Operator trigger window active for {trigger_seconds}s. Open app live view / camera session now.",
            summary="Hard audit: waiting for live-view trigger.",
        )
        trigger_capture = self._run_targeted_truth_capture(lead, "trigger", trigger_seconds)
        targeted_truth_captures.append(trigger_capture)
        if direct_capture_target_ip:
            direct_trigger_capture = self._capture_direct_target_ip_window(
                lead_id=lead_id,
                target_ip=direct_capture_target_ip,
                seconds=trigger_seconds,
                stage_id="trigger",
            )
            direct_truth_captures.append(direct_trigger_capture)
        self._update_hard_audit_stage(
            lead_id,
            "trigger",
            status="completed",
            detail=(
                f"Trigger capture retained {int(trigger_capture.get('frame_count') or 0)} frames."
                if trigger_capture.get("ok")
                else str(trigger_capture.get("error") or "Trigger capture failed.")
            ),
            extra={
                "operator_prompt": {"state": "trigger_complete", "message": "Trigger recorded. Hold live view open through the post-trigger window."},
                "truth_captures": {
                    "baseline": baseline_capture,
                    "trigger": trigger_capture,
                    "trigger_direct_ip": direct_truth_captures[-1] if direct_truth_captures else {},
                },
            },
        )
        self._update_hard_audit_stage(
            lead_id,
            "post_trigger",
            status="active",
            detail=f"Capturing post-trigger traffic and sustained flow evidence for {post_trigger_seconds}s.",
            summary="Hard audit: collecting post-trigger evidence.",
        )
        post_trigger_capture = self._run_targeted_truth_capture(lead, "post_trigger", post_trigger_seconds)
        targeted_truth_captures.append(post_trigger_capture)
        if direct_capture_target_ip:
            direct_post_trigger_capture = self._capture_direct_target_ip_window(
                lead_id=lead_id,
                target_ip=direct_capture_target_ip,
                seconds=post_trigger_seconds,
                stage_id="post_trigger",
            )
            direct_truth_captures.append(direct_post_trigger_capture)
        self._update_hard_audit_stage(
            lead_id,
            "post_trigger",
            status="completed",
            detail=(
                f"Post-trigger capture retained {int(post_trigger_capture.get('frame_count') or 0)} frames."
                if post_trigger_capture.get("ok")
                else str(post_trigger_capture.get("error") or "Post-trigger capture failed.")
            ),
            extra={
                "operator_prompt": {"state": "post_trigger_complete", "message": "Post-trigger capture complete. Correlating truth evidence now."},
                "truth_captures": {
                    "baseline": baseline_capture,
                    "trigger": trigger_capture,
                    "post_trigger": post_trigger_capture,
                    "direct_truth_captures": direct_truth_captures,
                },
            },
        )
        if direct_capture_target_ip:
            direct_ok = [capture for capture in direct_truth_captures if capture.get("ok")]
            direct_packets = sum(int(capture.get("packet_count") or 0) for capture in direct_ok)
            self._update_hard_audit_stage(
                lead_id,
                "direct_ip_capture",
                status="completed" if direct_ok else "blocked",
                detail=(
                    f"{len(direct_ok)} routed capture windows retained for {direct_capture_target_ip} · {direct_packets} packets saved."
                    if direct_ok
                    else "No routed target-IP packets were retained during the live-view windows."
                ),
                extra={"direct_truth_captures": direct_truth_captures, "target_ip": direct_capture_target_ip},
            )

        truth_pcap_inventory = [
            {"path": str(capture.get("pcap_path") or ""), "stage": str(capture.get("stage") or "")}
            for capture in targeted_truth_captures
            if str(capture.get("pcap_path") or "").strip()
        ]
        merged_pcap_inventory = truth_pcap_inventory + self.get_pcap_inventory()
        baseline_inventory = [item for item in truth_pcap_inventory if str(item.get("stage") or "") == "baseline"]
        trigger_inventory = [item for item in truth_pcap_inventory if str(item.get("stage") or "") == "trigger"]
        post_inventory = [item for item in truth_pcap_inventory if str(item.get("stage") or "") == "post_trigger"]

        self._update_hard_audit_stage(
            lead_id,
            "traffic_intel",
            status="active",
            detail="Extracting MAC-scoped flows and endpoint set from targeted truth windows and retained PCAPs.",
            summary="Hard audit: building traffic intelligence evidence.",
        )
        baseline_intel = self._extract_mac_flows_from_pcaps(lead, baseline_inventory) if baseline_inventory else {"debug": {}, "flows": [], "endpoints": []}
        trigger_intel = self._extract_mac_flows_from_pcaps(lead, trigger_inventory) if trigger_inventory else {"debug": {}, "flows": [], "endpoints": []}
        post_trigger_intel = self._extract_mac_flows_from_pcaps(lead, post_inventory) if post_inventory else {"debug": {}, "flows": [], "endpoints": []}
        flow_intel = self._extract_mac_flows_from_pcaps(lead, merged_pcap_inventory)
        if not validated_ips and str(flow_intel.get("validated_ip") or "").strip():
            validated_ips = [str(flow_intel.get("validated_ip") or "").strip()]
        hint_intel = self._extract_endpoint_set(lead, analysis)
        endpoint_set = list(flow_intel.get("endpoints") or [])
        traffic_intelligence = {
            **hint_intel,
            **flow_intel,
            "hint_endpoints": list(hint_intel.get("endpoints") or []),
            "truth_windows": {
                "baseline": baseline_intel,
                "trigger": trigger_intel,
                "post_trigger": post_trigger_intel,
            },
            "targeted_truth_captures": targeted_truth_captures,
        }
        flow_debug = dict(flow_intel.get("debug") or {})
        traffic_detail = (
            f"{len(endpoint_set)} endpoints · {flow_debug.get('flows_built') or 0} flows · {flow_debug.get('packets_from_mac') or 0} MAC packets."
            if endpoint_set
            else (
                flow_intel.get("explanation")
                or f"total packets {flow_debug.get('total_packets') or 0} · packets from MAC {flow_debug.get('packets_from_mac') or 0} · flows built {flow_debug.get('flows_built') or 0}"
            )
        )
        self._update_hard_audit_stage(
            lead_id,
            "traffic_intel",
            status="completed" if endpoint_set else ("partial" if (flow_debug.get("packets_from_mac") or 0) <= 0 else "blocked"),
            detail=traffic_detail,
            extra={"traffic_intelligence": traffic_intelligence},
        )

        decode_constraints = self._xiaomi_decode_constraints(
            lead,
            xiaomi_profile,
            xiaomi_local_api,
            final_probe,
            traffic_intelligence,
        )
        xiaomi_cloud_capture = self._xiaomi_cloud_capture_plan(
            lead,
            xiaomi_profile,
            dict(lead.get("video_evidence") or {}),
            traffic_intelligence,
        )
        if bool(decode_constraints.get("matched")) and bool(decode_constraints.get("likely_cloud_relay")):
            self._update_hard_audit_stage(
                lead_id,
                "xiaomi_cloud",
                status="completed",
                detail=str(decode_constraints.get("summary") or "Xiaomi-family cloud relay constraints recognized."),
                summary="Hard audit: Xiaomi-family cloud relay path likely blocks passive media decoding.",
                extra={"decode_constraints": decode_constraints, "xiaomi_cloud_capture": xiaomi_cloud_capture},
            )
        elif bool(xiaomi_cloud_capture.get("matched")):
            self._update_hard_audit_stage(
                lead_id,
                "xiaomi_cloud",
                status="completed",
                detail=str(xiaomi_cloud_capture.get("summary") or "Xiaomi-family cloud stream path profiled."),
                summary="Hard audit: Xiaomi-family cloud stream path profiled.",
                extra={"decode_constraints": decode_constraints, "xiaomi_cloud_capture": xiaomi_cloud_capture},
            )

        video_evidence = dict(lead.get("video_evidence") or {})
        correlation = dict(video_evidence.get("correlation") or {})
        self._update_hard_audit_stage(
            lead_id,
            "live_view",
            status="completed" if correlation else "blocked",
            detail=(
                f"{correlation.get('summary') or 'Correlation retained.'} · {round(float(correlation.get('correlation_confidence') or 0.0) * 100)}%."
                if correlation
                else "No live-view correlation retained; operator-triggered live view is still required."
            ),
            summary="Hard audit: correlating app/live-view behavior.",
        )

        traffic_profile = dict(video_evidence.get("traffic_profile") or {})
        sustained = bool(traffic_profile.get("sustained_flow"))
        bandwidth = str(traffic_profile.get("bandwidth_classification") or "none")
        self._update_hard_audit_stage(
            lead_id,
            "stream_detection",
            status="completed" if str(video_evidence.get("video_capable") or "") == "confirmed" else "partial",
            detail=(
                f"{str(video_evidence.get('video_device_class') or 'UNKNOWN').replace('_', ' ')} · {bandwidth} bandwidth · sustained {str(sustained).upper()}."
            ),
            summary="Hard audit: evaluating stream-like behavior.",
        )

        self._update_hard_audit_stage(
            lead_id,
            "vendor_profile",
            status="active",
            detail="Synthesizing vendor-family workflow and acquisition priorities.",
            summary="Hard audit: classifying vendor-family acquisition path.",
        )

        endpoint_roles = {
            "stream_endpoints": endpoint_set[:4],
            "control_endpoints": list(dict.fromkeys((video_evidence.get("traffic_profile") or {}).get("new_endpoints") or []))[:4],
        }
        self._update_hard_audit_stage(
            lead_id,
            "endpoint_attribution",
            status="completed" if endpoint_set else ("partial" if (flow_debug.get("packets_from_mac") or 0) <= 0 else "blocked"),
            detail=(
                f"{len(endpoint_set)} endpoints attributed."
                if endpoint_set
                else f"total packets {flow_debug.get('total_packets') or 0} · packets from MAC {flow_debug.get('packets_from_mac') or 0} · flows {flow_debug.get('flows_built') or 0}"
            ),
            summary="Hard audit: attributing endpoint roles.",
            extra={"endpoint_attribution": endpoint_roles},
        )

        artifact_decision = self._artifact_decision_from_evidence(lead, final_probe)
        self._update_hard_audit_stage(
            lead_id,
            "artifact_decision",
            status="completed",
            detail=(
                "Visual artifact extraction justified."
                if artifact_decision.get("artifact_possible")
                else f"Visual artifact not locally recoverable due to {artifact_decision.get('reason') or 'missing protocol evidence'}."
            ),
            summary="Hard audit: deciding artifact eligibility.",
            extra={"artifact_decision": artifact_decision},
        )

        negative_proof_detail = []
        if not endpoint_set:
            negative_proof_detail.append("no endpoints")
        if int(((final_probe.get("summary") or {}).get("http_hits") or 0)) <= 0:
            negative_proof_detail.append("no http")
        if int(((final_probe.get("summary") or {}).get("onvif_hits") or 0)) <= 0:
            negative_proof_detail.append("no onvif")
        if int(((final_probe.get("summary") or {}).get("rtsp_hits") or 0)) <= 0:
            negative_proof_detail.append("no rtsp")
        self._update_hard_audit_stage(
            lead_id,
            "negative_proof",
            status="completed",
            detail=" · ".join(negative_proof_detail) if negative_proof_detail else "Direct negative evidence retained.",
            summary="Hard audit: negative evidence reviewed.",
        )

        video_truth = self._build_video_truth(lead, traffic_intelligence, hard_audit_start)
        behavioral_video_proof_artifact = ""
        if (
            str(video_truth.get("video_confirmed") or "").upper() in {"YES", "INCONCLUSIVE"}
            or str(video_evidence.get("video_capable") or "") == "confirmed"
        ):
            try:
                behavioral_video_proof_artifact = self._persist_behavioral_video_proof_artifact(
                    lead_id,
                    lead,
                    video_truth,
                    traffic_intelligence,
                    targeted_truth_captures,
                )
            except Exception:
                behavioral_video_proof_artifact = ""

        decrypt_followup = self._run_decrypt_followup(
            [str(item.get("pcap_path") or "").strip() for item in targeted_truth_captures]
            + [str(item.get("path") or "").strip() for item in merged_pcap_inventory[:8]]
        )
        camera_packet_evidence = self._build_camera_packet_evidence(
            lead_id=lead_id,
            target_ips=validated_ips + [str(item).strip() for item in list(final_probe.get("candidate_ips") or []) if str(item).strip()],
            source_paths=[str(item.get("pcap_path") or "").strip() for item in targeted_truth_captures]
            + [str(item.get("pcapng_path") or "").strip() for item in direct_truth_captures]
            + [str(item.get("pcap_path") or "").strip() for item in direct_truth_captures]
            + [str(item.get("path") or "").strip() for item in merged_pcap_inventory[:8]],
        )

        validation_report = self.camera_validation.validate_lead(
            lead={**lead, "lead_id": lead_id},
            active_probe=final_probe,
            analysis=analysis,
            pcap_inventory=merged_pcap_inventory,
            run_type="camera_hard_audit",
        )
        if behavioral_video_proof_artifact:
            protocol_evidence = list(((validation_report.get("evidence") or {}).get("protocol")) or [])
            protocol_evidence.append(
                {
                    "evidence_type": "behavioral_video_proof",
                    "capture_file": behavioral_video_proof_artifact,
                    "flow_identifier": lead_id,
                    "protocol": "behavioral",
                    "timestamps": {"observed_at": int(time.time())},
                    "summary": str(video_truth.get("status_reason") or video_evidence.get("summary") or "Behavioral video proof retained."),
                    "run_id": str(validation_report.get("run_id") or ""),
                    "quality": "corroborated" if str(video_truth.get("video_confirmed") or "").upper() == "YES" else "partial",
                }
            )
            if bool(decode_constraints.get("matched")):
                protocol_evidence.append(
                    {
                        "evidence_type": "decode_constraint",
                        "protocol": "xiaomi_cloud_relay",
                        "summary": str(decode_constraints.get("summary") or "Xiaomi-family decode constraint retained."),
                        "reason": str(decode_constraints.get("reason") or ""),
                        "run_id": str(validation_report.get("run_id") or ""),
                        "quality": "partial",
                    }
                )
            if bool(xiaomi_cloud_capture.get("matched")):
                protocol_evidence.append(
                    {
                        "evidence_type": "cloud_capture_plan",
                        "protocol": "xiaomi_miot_cloud_stream",
                        "summary": str(xiaomi_cloud_capture.get("summary") or "Xiaomi-family cloud capture plan retained."),
                        "host_patterns": list(xiaomi_cloud_capture.get("cloud_host_patterns") or []),
                        "required_artifacts": list(xiaomi_cloud_capture.get("required_artifacts") or []),
                        "run_id": str(validation_report.get("run_id") or ""),
                        "quality": "partial",
                    }
                )
            validation_report.setdefault("evidence", {})["protocol"] = protocol_evidence
        if int(decrypt_followup.get("saved_image_count") or 0) > 0:
            exposure_evidence = list(((validation_report.get("evidence") or {}).get("exposure")) or [])
            for image_path in list(decrypt_followup.get("saved_images") or [])[:8]:
                exposure_evidence.append(
                    {
                        "evidence_type": "snapshot_artifact",
                        "capture_file": str(image_path),
                        "path": Path(str(image_path)).name,
                        "summary": "Image artifact extracted automatically from Camera Hunt truth captures.",
                        "run_id": str(validation_report.get("run_id") or ""),
                        "quality": "corroborated",
                    }
                )
            validation_report.setdefault("evidence", {})["exposure"] = exposure_evidence
        if camera_packet_evidence.get("ok"):
            protocol_evidence = list(((validation_report.get("evidence") or {}).get("protocol")) or [])
            protocol_evidence.append(
                {
                    "evidence_type": "camera_ip_raw_capture",
                    "capture_file": str(camera_packet_evidence.get("pcapng_path") or ""),
                    "flow_identifier": str(camera_packet_evidence.get("target_ip") or ""),
                    "protocol": "ip",
                    "timestamps": {"observed_at": int(time.time())},
                    "summary": str((camera_packet_evidence.get("summary") or {}).get("assessment") or "camera_ip_activity_observed"),
                    "run_id": str(validation_report.get("run_id") or ""),
                    "quality": "corroborated",
                }
            )
            if str(camera_packet_evidence.get("pcap_path") or "").strip():
                protocol_evidence.append(
                    {
                        "evidence_type": "camera_ip_raw_pcap",
                        "capture_file": str(camera_packet_evidence.get("pcap_path") or ""),
                        "flow_identifier": str(camera_packet_evidence.get("target_ip") or ""),
                        "protocol": "ip",
                        "timestamps": {"observed_at": int(time.time())},
                        "summary": "pcap conversion for offline review",
                        "run_id": str(validation_report.get("run_id") or ""),
                        "quality": "corroborated",
                    }
                )
            protocol_evidence.append(
                {
                    "evidence_type": "camera_media_summary",
                    "capture_file": str(camera_packet_evidence.get("summary_path") or ""),
                    "flow_identifier": str(camera_packet_evidence.get("target_ip") or ""),
                    "protocol": "ip",
                    "timestamps": {"observed_at": int(time.time())},
                    "summary": str((camera_packet_evidence.get("summary") or {}).get("assessment") or "camera_ip_activity_observed"),
                    "run_id": str(validation_report.get("run_id") or ""),
                    "quality": "corroborated",
                }
            )
            validation_report.setdefault("evidence", {})["protocol"] = protocol_evidence
        visual_context = {
            "camera_packet_evidence": camera_packet_evidence,
            "decrypt_followup": decrypt_followup,
            "behavioral_video_proof_artifact": behavioral_video_proof_artifact,
            "video_truth": video_truth,
            "decode_constraints": decode_constraints,
            "xiaomi_cloud_capture": xiaomi_cloud_capture,
        }
        visual_acquisition = self.visual_acquisition.run(
            lead=lead,
            active_probe=final_probe,
            hard_audit=visual_context,
            validation_report=validation_report,
            analysis=analysis,
        )
        evidence_policy = dict(visual_acquisition.get("evidence_policy") or {})
        vendor_profile = dict(visual_acquisition.get("vendor_profile") or {})
        outcome_class = str(visual_acquisition.get("outcome_class") or "network_proof_only")
        self._update_hard_audit_stage(
            lead_id,
            "vendor_profile",
            status="completed" if vendor_profile.get("matched") else "partial",
            detail=(
                f"{vendor_profile.get('label') or 'Generic Camera'} · {vendor_profile.get('plugin_id') or 'generic'}."
                if vendor_profile
                else "No vendor-family plugin matched; using generic acquisition policy."
            ),
            extra={"vendor_profile": vendor_profile},
        )
        self._update_hard_audit_stage(
            lead_id,
            "visual_acquisition",
            status="completed" if str(outcome_class) == "visual_proof_recovered" else ("partial" if evidence_policy else "blocked"),
            detail=str(visual_acquisition.get("summary") or "No visual acquisition summary retained."),
            summary="Hard audit: evaluating visual acquisition paths.",
            extra={"visual_acquisition": visual_acquisition},
        )
        owner_assisted_items = list(evidence_policy.get("owner_assisted_evidence") or [])
        self._update_hard_audit_stage(
            lead_id,
            "owner_assisted",
            status="completed" if owner_assisted_items else "partial",
            detail=(
                str(owner_assisted_items[0].get("step") or "")
                if owner_assisted_items
                else "No owner-assisted visual acquisition plan was retained."
            ),
        )
        recorder_detail = str(((vendor_profile.get("recorder_replay") or {}).get("detail")) or "No recorder replay guidance retained.")
        self._update_hard_audit_stage(
            lead_id,
            "recorder_replay",
            status="completed" if bool((vendor_profile.get("recorder_replay") or {}).get("supported")) else "partial",
            detail=recorder_detail,
        )
        verdict = dict(validation_report.get("verdict") or {})
        verdict_classification = str(verdict.get("classification") or "").strip().lower()
        verdict_guidance = str(verdict.get("operator_guidance") or "").strip()
        classification = str(verdict.get("classification") or "inconclusive").lower()
        evidence_quality = str(verdict.get("evidence_quality") or "inconclusive").lower()
        parser_failure = bool(
            (flow_debug.get("packets_from_mac") or 0) > 0
            and (flow_debug.get("flows_built") or 0) > 0
            and not endpoint_set
        )
        success = bool(
            classification in {"weak_enforcement", "unsafe", "secure"}
            or endpoint_set
            or validated_ips
            or str(video_evidence.get("video_capable") or "") == "confirmed"
        )
        final_summary = (
            str(verdict.get("reasoning") or "").strip()
            or str(visual_acquisition.get("summary") or "").strip()
            or ("Cloud video behavior confirmed – no local access." if str(video_evidence.get("video_device_class") or "") == "CLOUD_STREAM_DEVICE" else "Hard audit complete.")
        )
        self._update_hard_audit_stage(
            lead_id,
            "finalize",
            status="completed",
            detail=f"{classification.replace('_', ' ')} · {evidence_quality.replace('_', ' ')} · {outcome_class.replace('_', ' ')}",
            summary=final_summary,
            extra={"operator_prompt": {"state": "complete", "message": "Hard audit complete. Review truth correlation, endpoints, and artifact eligibility."}},
        )

        hard_audit = dict(self.hard_audit_cache.get(lead_id) or {})
        pipeline = dict(hard_audit.get("pipeline") or {})
        pipeline["status"] = "completed"
        hard_audit.update(
            {
                "status": "completed",
                "tested_at": int(time.time()),
                "analysis": analysis,
                "active_fingerprint": final_probe,
                "validation_report": validation_report,
                "video_truth": video_truth,
                "behavioral_video_proof_artifact": behavioral_video_proof_artifact,
                "decrypt_followup": decrypt_followup,
                "camera_packet_evidence": camera_packet_evidence,
                "visual_acquisition": visual_acquisition,
                "evidence_policy": evidence_policy,
                "xiaomi_family_profile": xiaomi_profile,
                "xiaomi_local_api": xiaomi_local_api,
                "xiaomi_cloud_capture": xiaomi_cloud_capture,
                "decode_constraints": decode_constraints,
                "targeted_truth_captures": targeted_truth_captures,
                "direct_truth_captures": direct_truth_captures,
                "classification": classification,
                "evidence_quality": evidence_quality,
                "error": (
                    "Traffic exists but endpoint extraction failed."
                    if parser_failure
                    else ("" if success else str(final_probe.get("error") or flow_intel.get("explanation") or "Hard audit completed without enough evidence to classify the target."))
                ),
                "pipeline": pipeline,
            }
        )
        self.hard_audit_cache[lead_id] = hard_audit
        if hard_audit.get("active_fingerprint"):
            self.active_probe_cache[lead_id] = hard_audit.get("active_fingerprint") or {}
        return {
            "ok": True,
            "lead_id": lead_id,
            "lead": self._merge_probe_cache_into_lead(lead),
            "hard_audit": hard_audit,
            "analysis": analysis,
            "active_fingerprint": final_probe,
            "validation_report": validation_report,
            "error": hard_audit["error"],
        }

    def audit_camera_lead_layers(self, lead_id: str) -> Dict[str, Any]:
        lead = self._find_camera_lead(lead_id, self._camera_lead_pool())
        if lead is None:
            return {"ok": False, "error": "Camera lead not found in hunt results.", "lead_id": lead_id}
        hard_audit = dict(self.hard_audit_cache.get(lead_id) or {})
        if not hard_audit:
            return {
                "ok": False,
                "lead_id": lead_id,
                "error": "Run Hard Audit first. Layered audit synthesizes the retained evidence planes from that run.",
            }

        lead = self._merge_probe_cache_into_lead(self._lead_with_association_context(lead))
        analysis = dict(hard_audit.get("analysis") or {})
        active_fingerprint = dict(hard_audit.get("active_fingerprint") or {})
        validation_report = dict(hard_audit.get("validation_report") or {})
        video_truth = dict(hard_audit.get("video_truth") or {})
        video_evidence = dict(lead.get("video_evidence") or {})
        decrypt_followup = dict(hard_audit.get("decrypt_followup") or {})
        xiaomi_profile = dict(hard_audit.get("xiaomi_family_profile") or {})
        xiaomi_local_api = dict(hard_audit.get("xiaomi_local_api") or {})
        xiaomi_cloud_capture = dict(hard_audit.get("xiaomi_cloud_capture") or {})
        decode_constraints = dict(hard_audit.get("decode_constraints") or {})
        camera_packet_evidence = dict(hard_audit.get("camera_packet_evidence") or {})
        traffic_intelligence = dict(((hard_audit.get("pipeline") or {}).get("traffic_intelligence")) or {})
        flow_debug = dict(traffic_intelligence.get("debug") or {})
        probe_summary = dict(active_fingerprint.get("summary") or {})
        verdict = dict(validation_report.get("verdict") or {})
        protocol_evidence = list(((validation_report.get("evidence") or {}).get("protocol")) or [])
        exposure_evidence = list(((validation_report.get("evidence") or {}).get("exposure")) or [])
        candidate_ips = list(active_fingerprint.get("candidate_ips") or [])
        validated_candidates = list(active_fingerprint.get("validated_candidates") or [])
        validated_ips = [
            str(item.get("ip") or item.get("candidate_ip") or "").strip()
            for item in validated_candidates
            if str(item.get("ip") or item.get("candidate_ip") or "").strip()
        ]
        artifact_paths = [
            str(item.get("capture_file") or item.get("saved_path") or "").strip()
            for item in [*protocol_evidence, *exposure_evidence]
            if str(item.get("capture_file") or item.get("saved_path") or "").strip()
        ]
        if str(hard_audit.get("behavioral_video_proof_artifact") or "").strip():
            artifact_paths.append(str(hard_audit.get("behavioral_video_proof_artifact") or "").strip())
        saved_images = [str(path).strip() for path in list(decrypt_followup.get("saved_images") or []) if str(path).strip()]

        def _layer_status(ok: bool, partial: bool = False) -> str:
            if ok:
                return "complete"
            if partial:
                return "partial"
            return "blocked"

        passive_confidence = float((lead.get("camera_detection") or {}).get("confidence") or 0.0)
        passive_complete = bool(
            passive_confidence >= 0.35
            or (lead.get("camera_detection") or {}).get("detected")
            or analysis
        )
        local_service_hits = int(probe_summary.get("http_hits") or 0) + int(probe_summary.get("onvif_hits") or 0) + int(probe_summary.get("rtsp_hits") or 0) + int(probe_summary.get("snapshot_hits") or 0)
        local_service_complete = local_service_hits > 0
        local_service_partial = bool(candidate_ips)
        local_api_complete = bool(xiaomi_local_api.get("ok"))
        local_api_partial = bool(xiaomi_local_api) or bool(validated_ips)
        cloud_relay_complete = bool(
            decode_constraints.get("likely_cloud_relay")
            or xiaomi_cloud_capture.get("matched")
            or video_evidence.get("cloud_stream_detected")
        )
        cloud_relay_partial = bool(xiaomi_profile.get("matched"))
        decrypt_complete = int(decrypt_followup.get("saved_image_count") or 0) > 0
        decrypt_partial = bool(
            int((decrypt_followup.get("report") or {}).get("eapol_frames") or 0) > 0
            or int(flow_debug.get("packets_from_mac") or 0) > 0
            or int(flow_debug.get("total_packets") or 0) > 0
        )
        packet_summary = dict(camera_packet_evidence.get("summary") or {})
        packet_capture_complete = bool(camera_packet_evidence.get("ok")) and int(camera_packet_evidence.get("packet_count") or 0) > 0
        packet_capture_partial = bool(camera_packet_evidence) or bool(packet_summary)
        artifact_complete = bool(saved_images) or any(path.lower().endswith((".jpg", ".jpeg", ".png", ".bmp", ".webp")) for path in artifact_paths)
        artifact_partial = bool(artifact_paths)

        layers = [
            {
                "id": "passive_identity",
                "label": "Passive Identity",
                "status": _layer_status(passive_complete),
                "detail": (
                    f"{lead.get('vendor') or '--'} · {(lead.get('camera_detection') or {}).get('family_match') or 'unclassified'} · {round(passive_confidence * 100)}% passive confidence"
                    if passive_complete
                    else "Passive camera identity did not retain enough confidence."
                ),
                "signals": [
                    str((lead.get("camera_detection") or {}).get("classification") or ""),
                    str((lead.get("camera_detection") or {}).get("family_match") or ""),
                    str((lead.get("camera_detection") or {}).get("vendor_explainer") or ""),
                ],
            },
            {
                "id": "local_services",
                "label": "Local Services",
                "status": _layer_status(local_service_complete, partial=local_service_partial),
                "detail": (
                    f"{local_service_hits} local media/service hits across HTTP, ONVIF, RTSP, or snapshot probing."
                    if local_service_complete
                    else (
                        f"{len(candidate_ips)} candidate IPs retained, but no local media/service hit confirmed."
                        if local_service_partial
                        else "No candidate IP or local media/service surface was retained."
                    )
                ),
                "signals": [
                    f"http {int(probe_summary.get('http_hits') or 0)}",
                    f"onvif {int(probe_summary.get('onvif_hits') or 0)}",
                    f"rtsp {int(probe_summary.get('rtsp_hits') or 0)}",
                    f"snapshot {int(probe_summary.get('snapshot_hits') or 0)}",
                ],
            },
            {
                "id": "local_authenticated_api",
                "label": "Local Auth API",
                "status": _layer_status(local_api_complete, partial=local_api_partial),
                "detail": (
                    str(xiaomi_local_api.get("summary") or "Local authenticated API path retained.")
                    if local_api_partial
                    else "No local authenticated API path was retained."
                ),
                "signals": [
                    ", ".join(validated_ips[:2]) if validated_ips else "",
                    str(xiaomi_local_api.get("transport") or ""),
                    str(xiaomi_local_api.get("reason") or ""),
                ],
            },
            {
                "id": "cloud_relay",
                "label": "Cloud Relay",
                "status": _layer_status(cloud_relay_complete, partial=cloud_relay_partial),
                "detail": (
                    str(decode_constraints.get("summary") or xiaomi_cloud_capture.get("summary") or "Cloud/app relay path retained.")
                    if (cloud_relay_complete or cloud_relay_partial)
                    else "No cloud relay path was inferred from retained evidence."
                ),
                "signals": list(xiaomi_cloud_capture.get("cloud_host_patterns") or []),
            },
            {
                "id": "decryption_decode",
                "label": "Decryption / Decode",
                "status": _layer_status(decrypt_complete, partial=decrypt_partial),
                "detail": (
                    f"{len(saved_images)} recovered image artifacts from retained truth captures."
                    if decrypt_complete
                    else (
                        f"saved images {int(decrypt_followup.get('saved_image_count') or 0)} · eapol {int((decrypt_followup.get('report') or {}).get('eapol_frames') or 0)} · mac packets {int(flow_debug.get('packets_from_mac') or 0)}"
                        if decrypt_partial
                        else "No decryption material or decodable media payload was retained."
                    )
                ),
                "signals": [
                    f"saved images {int(decrypt_followup.get('saved_image_count') or 0)}",
                    f"eapol {int((decrypt_followup.get('report') or {}).get('eapol_frames') or 0)}",
                    f"flows {int(flow_debug.get('flows_built') or 0)}",
                ],
            },
            {
                "id": "camera_ip_packets",
                "label": "Camera IP Packets",
                "status": _layer_status(packet_capture_complete, partial=packet_capture_partial),
                "detail": (
                    f"{int(camera_packet_evidence.get('packet_count') or 0)} IP packets retained · {int(camera_packet_evidence.get('file_size_bytes') or 0)} bytes · {str(packet_summary.get('assessment') or 'camera_ip_activity_observed').replace('_', ' ')}."
                    if packet_capture_complete
                    else "No camera-scoped IP packet artifact was retained."
                ),
                "signals": [
                    f"target {str(camera_packet_evidence.get('target_ip') or '')}",
                    f"stream {str(bool(packet_summary.get('stream_detected'))).lower()}",
                    ", ".join([str(port) for port in list(packet_summary.get("ports_seen") or [])[:4]]),
                ],
            },
            {
                "id": "artifact_recovery",
                "label": "Artifact Recovery",
                "status": _layer_status(artifact_complete, partial=artifact_partial),
                "detail": (
                    f"{len(saved_images) or len(artifact_paths)} retained artifacts available for operator review."
                    if (artifact_complete or artifact_partial)
                    else "No retained artifact path was justified by the current evidence set."
                ),
                "signals": [
                    Path(saved_images[0]).name if saved_images else "",
                    Path(artifact_paths[0]).name if artifact_paths else "",
                    str(video_truth.get("video_confirmed") or ""),
                ],
            },
        ]

        media_plane_detected = "encrypted_unknown"
        evidence_recovery_path = "additional_validation_required"
        image_feasible_now = False
        blockers: List[str] = []
        next_actions: List[str] = []

        if artifact_complete or decrypt_complete:
            media_plane_detected = "local_open" if local_service_complete else "local_auth"
            evidence_recovery_path = "artifact_ready"
            image_feasible_now = True
            next_actions.append("Open the retained artifact and export it into the case evidence bundle.")
        elif packet_capture_complete:
            media_plane_detected = "ip_packet_evidence"
            evidence_recovery_path = "review_camera_ip_packets"
            blockers.append("No direct image artifact was retained, but camera-emitted IP packet evidence is available for offline analysis.")
            next_actions.append("Review the retained camera_ip_raw capture and camera_media_summary to confirm stream behavior, endpoints, and timing.")
        elif local_service_complete:
            media_plane_detected = "local_open"
            evidence_recovery_path = "probe_local_media_path"
            blockers.append("Local surface exists, but no retained image payload was carved yet.")
            next_actions.append("Retry focused snapshot/RTSP retrieval on the validated local service path.")
        elif local_api_complete or local_api_partial:
            media_plane_detected = "local_auth"
            evidence_recovery_path = "authenticate_local_api"
            blockers.append("The device likely needs local app/API authorization before media retrieval.")
            next_actions.append("Use the vendor-authenticated LAN path for still capture instead of passive RF decoding.")
        elif cloud_relay_complete or cloud_relay_partial:
            media_plane_detected = "cloud_relay"
            evidence_recovery_path = "capture_app_or_cloud_stream"
            blockers.append("Live view is likely app/cloud relayed rather than locally exposed.")
            next_actions.append("Capture the app/cloud stream-start path, playlist, segment, or relay URL as the evidence source.")
        else:
            blockers.append("No local or cloud media plane was retained strongly enough to recover an image.")
            next_actions.append("Re-run Hard Audit with a live-view trigger and preserve any protocol-positive path before decoding.")

        if not validated_ips and not candidate_ips:
            blockers.append("No validated device IP was retained.")
        if int(flow_debug.get("packets_from_mac") or 0) <= 0:
            blockers.append("No attributable MAC-scoped IP flow was retained in the truth windows.")
        if int((decrypt_followup.get("report") or {}).get("eapol_frames") or 0) <= 0 and not image_feasible_now:
            blockers.append("No decryption material was retained for passive decode.")

        if verdict_classification == "unsafe":
            next_actions.append("Treat the unauthenticated stream or control surface as direct audit evidence and recommend immediate isolation, shutdown, or replacement.")
        elif verdict_classification == "weak_enforcement":
            next_actions.append("Treat the pre-auth media or management exposure as an audit failure and recommend network isolation, service disablement, or replacement if hardening is not possible.")

        blocker_list = list(dict.fromkeys([item for item in blockers if str(item).strip()]))[:4]
        next_action_list = list(dict.fromkeys([item for item in next_actions if str(item).strip()]))[:4]
        summary = (
            verdict_guidance
            or (
                "Artifact-ready evidence is retained."
                if image_feasible_now
                else (
                    "Cloud/app relay is the dominant recovery plane for this target."
                    if media_plane_detected == "cloud_relay"
                    else (
                        "Camera-emitted IP packet evidence is retained for offline audit, even though no image artifact was recovered yet."
                        if media_plane_detected == "ip_packet_evidence"
                        else (
                        "Local authenticated access is the next viable recovery plane."
                        if media_plane_detected == "local_auth"
                        else (
                            "Local media services are present but artifact recovery still needs targeted extraction."
                            if media_plane_detected == "local_open"
                            else "The retained evidence set is still mostly passive/identity-level."
                        )
                        )
                    )
                )
            )
        )
        layer_audit = {
            "status": "completed",
            "tested_at": int(time.time()),
            "lead_id": lead_id,
            "summary": summary,
            "media_plane_detected": media_plane_detected,
            "evidence_recovery_path": evidence_recovery_path,
            "image_feasible_now": image_feasible_now,
            "layers": layers,
            "blockers": blocker_list,
            "next_actions": next_action_list,
        }
        hard_audit["layer_audit"] = layer_audit
        self.hard_audit_cache[lead_id] = hard_audit
        return {
            "ok": True,
            "lead_id": lead_id,
            "lead": self._merge_probe_cache_into_lead(lead),
            "layer_audit": layer_audit,
            "hard_audit": hard_audit,
            "validation_report": validation_report,
        }

    def video_truth_test_camera_lead(self, lead_id: str, seconds: int = 40) -> Dict[str, Any]:
        bounded_seconds = max(30, min(60, int(seconds or 40)))
        result = self.hard_audit_camera_lead(lead_id, seconds=bounded_seconds)
        if not result.get("hard_audit"):
            return {
                **result,
                "video_truth_test": {
                    "status": "failed",
                    "tested_at": int(time.time()),
                    "summary": result.get("error") or "Video truth test did not start.",
                },
            }
        hard_audit = dict(result.get("hard_audit") or {})
        video_truth = dict(hard_audit.get("video_truth") or {})
        summary = str(video_truth.get("status_reason") or hard_audit.get("pipeline", {}).get("summary") or "Video truth test completed.").strip()
        video_truth_test = {
            "status": "completed" if result.get("ok") else "partial",
            "tested_at": int(time.time()),
            "window_seconds": bounded_seconds,
            "summary": summary,
            "video_truth": video_truth,
        }
        hard_audit["video_truth_test"] = video_truth_test
        self.hard_audit_cache[lead_id] = hard_audit
        return {
            **result,
            "hard_audit": hard_audit,
            "video_truth_test": video_truth_test,
        }

    @staticmethod
    def _service_audit_stage_template() -> List[Dict[str, Any]]:
        return [
            {"id": "target_validation", "label": "Target Validate", "status": "active", "detail": "Resolving MAC ↔ IP and retained DDI evidence."},
            {"id": "port_discovery", "label": "Port Discovery", "status": "pending", "detail": "Awaiting validated target IP."},
            {"id": "service_id", "label": "Service ID", "status": "pending", "detail": "Awaiting open port confirmation."},
            {"id": "access_posture", "label": "Access Posture", "status": "pending", "detail": "Awaiting safe HTTP/TLS/banner checks."},
            {"id": "destination_analysis", "label": "External Destinations", "status": "pending", "detail": "Awaiting retained target PCAP and audit trace."},
            {"id": "trace", "label": "Trace", "status": "pending", "detail": "Awaiting retained audit evidence."},
        ]

    def _update_service_audit_stage(
        self,
        target_key: str,
        stage_id: str,
        *,
        label: str,
        status: str,
        detail: str,
    ) -> None:
        audit = dict(self.service_audit_cache.get(target_key) or {})
        pipeline = dict(audit.get("pipeline") or {})
        stages = [dict(item) for item in (pipeline.get("stages") or self._service_audit_stage_template())]
        found = False
        for stage in stages:
            if str(stage.get("id") or "") == stage_id:
                stage["label"] = label
                stage["status"] = status
                stage["detail"] = detail
                stage["updated_at"] = int(time.time())
                found = True
                break
        if not found:
            stages.append(
                {
                    "id": stage_id,
                    "label": label,
                    "status": status,
                    "detail": detail,
                    "updated_at": int(time.time()),
                }
            )
        pipeline["stages"] = stages
        pipeline["current_stage"] = stage_id
        pipeline["status"] = "running" if status in {"active", "pending"} else pipeline.get("status") or "running"
        audit["status"] = "running"
        audit["target_id"] = target_key
        audit["tested_at"] = int(time.time())
        audit["pipeline"] = pipeline
        self.service_audit_cache[target_key] = audit

    def _annotate_wifi_hard_audit(self, result: Dict[str, Any]) -> Dict[str, Any]:
        result["audit_kind"] = "wifi_hard_audit"
        result["audit_label"] = "WiFi Hard Audit"
        result["audit_scope"] = list(self.WIFI_HARD_AUDIT_SCOPE)
        return result

    @staticmethod
    def _upsert_pipeline_stage(pipeline: Dict[str, Any], *, stage_id: str, label: str, status: str, detail: str) -> Dict[str, Any]:
        stages = [dict(item) for item in (pipeline.get("stages") or [])]
        inserted = False
        for stage in stages:
            if str(stage.get("id") or "") == stage_id:
                stage["label"] = label
                stage["status"] = status
                stage["detail"] = detail
                inserted = True
                break
        if not inserted:
            stages.insert(max(0, len(stages) - 1), {"id": stage_id, "label": label, "status": status, "detail": detail})
        pipeline["stages"] = stages
        return pipeline

    def _run_external_destination_analysis(
        self,
        *,
        target_key: str,
        ddi_resolution: Dict[str, Any],
        source_signature: str,
    ) -> Dict[str, Any]:
        evidence_artifacts = dict(ddi_resolution.get("evidence_artifacts") or {})
        analysis = self.destination_analysis.analyze(
            target_id=target_key,
            target_filtered_pcap=str(evidence_artifacts.get("target_filtered_pcap") or ""),
            ddi_resolution_path=str(evidence_artifacts.get("ddi_resolution_path") or ""),
            service_audit_trace_path=str((dict(self.service_audit_cache.get(target_key) or {}).get("evidence_artifacts") or {}).get("service_audit_trace") or ""),
        )
        analysis["_source_signature"] = source_signature
        retained = self.evidence.write_destination_analysis_artifacts(
            target_id=target_key,
            analysis_payload=analysis,
            external_ips=list(analysis.get("external_ips") or []),
            dns_records=list(analysis.get("dns_records") or []),
            tls_metadata=list(analysis.get("tls_metadata") or []),
        )
        analysis["evidence_artifacts"] = retained
        self.destination_analysis_cache[target_key] = analysis
        return analysis

    def run_hard_audit(self, target_id: str, allow_infrastructure: bool = False) -> Dict[str, Any]:
        return self._annotate_wifi_hard_audit(
            self.run_service_audit(target_id, allow_infrastructure=allow_infrastructure)
        )

    def run_service_audit(self, target_id: str, allow_infrastructure: bool = False) -> Dict[str, Any]:
        target = self._find_wifi_target(target_id)
        if target is None:
            return {"ok": False, "error": "WiFi target not found.", "target_id": target_id}
        target_key = self._wifi_target_id(target)
        ddi_resolution = self._resolve_ddi_for_target(target)
        self.service_audit_cache[target_key] = {
            "status": "running",
            "target_id": target_key,
            "tested_at": int(time.time()),
            "pipeline": {
                "status": "running",
                "current_stage": "target_validation",
                "stages": self._service_audit_stage_template(),
            },
        }
        candidate_ips = self._collect_target_candidate_ips({**target, "ddi_resolution": ddi_resolution})
        validated_candidates = list(ddi_resolution.get("validated_candidates") or [])
        rejected_candidates = list(ddi_resolution.get("rejected_candidates") or [])
        best = next(iter(validated_candidates), None)
        if not best:
            result = {
                "ok": False,
                "target_id": target_key,
                "target": target,
                "target_validation": {
                    "target_ip_valid": False,
                    "validation_method": "ddi_evidence_policy",
                    "confidence_score": 0.0,
                    "candidate_ips": candidate_ips,
                    "validated_candidates": validated_candidates,
                    "rejected_candidates": rejected_candidates,
                    "ddi_resolution": ddi_resolution,
                    "resolution_state": ddi_resolution.get("resolution_state") or "NO_IP_EVIDENCE",
                    "explanation": ddi_resolution.get("explanation") or "No validated IP for this device.",
                },
                "ddi_resolution": ddi_resolution,
                "negative_evidence": list(ddi_resolution.get("negative_evidence") or []),
                "final_verdict": {"classification": "UNKNOWN", "explanation": ddi_resolution.get("explanation") or "Target IP was not validated; service audit did not start."},
                "pipeline": {
                    "status": "blocked",
                    "current_stage": "target_validation",
                    "stages": [
                        {"id": "target_validation", "label": "Target Validate", "status": "blocked", "detail": ddi_resolution.get("resolution_state") or "No validated IP for this device."},
                        {"id": "port_discovery", "label": "Port Discovery", "status": "pending", "detail": "Awaiting validated target IP."},
                        {"id": "service_id", "label": "Service ID", "status": "pending", "detail": "Awaiting validated target IP."},
                        {"id": "access_posture", "label": "Access Posture", "status": "pending", "detail": "Awaiting validated target IP."},
                        {"id": "destination_analysis", "label": "External Destinations", "status": "pending", "detail": "Awaiting validated target IP."},
                        {"id": "trace", "label": "Trace", "status": "pending", "detail": "Awaiting validated target IP."},
                    ],
                },
                "evidence_artifacts": dict(ddi_resolution.get("evidence_artifacts") or {}),
            }
            trace_path = self.evidence.write_service_audit_trace(target_id=target_key, audit_payload=result)
            if trace_path:
                result["evidence_artifacts"] = {
                    **dict(result.get("evidence_artifacts") or {}),
                    "service_audit_trace": trace_path,
                }
            self.service_audit_cache[target_key] = result
            return self._annotate_wifi_hard_audit(result)

        target_mac = str(target.get("mac") or "").strip().lower()
        if not target_mac:
            mac_candidates = self._lead_mac_candidates(target)
            target_mac = mac_candidates[0] if mac_candidates else ""

        def progress_callback(stage: Dict[str, Any]) -> None:
            self._update_service_audit_stage(
                target_key,
                str(stage.get("id") or ""),
                label=str(stage.get("label") or "stage"),
                status=str(stage.get("status") or "pending"),
                detail=str(stage.get("detail") or "").strip() or "Processing.",
            )

        audit = self.service_audit.run(
            target_id=target_key,
            ip_value=str(best.get("candidate_ip") or ""),
            target_mac=target_mac,
            validation_method="ddi_evidence_policy",
            confidence_score=float(best.get("confidence_score") or 0.0),
            allow_infrastructure=allow_infrastructure,
            credential_mode=False,
            progress_callback=progress_callback,
        )
        result = {
            "ok": bool(audit.get("ok")),
            "target_id": target_key,
            "target": target,
            "ddi_resolution": ddi_resolution,
            "evidence_artifacts": dict(ddi_resolution.get("evidence_artifacts") or {}),
            **audit,
        }
        trace_path = self.evidence.write_service_audit_trace(target_id=target_key, audit_payload=result)
        if trace_path:
            result["evidence_artifacts"] = {
                **dict(result.get("evidence_artifacts") or {}),
                "service_audit_trace": trace_path,
            }
            destination_analysis = self._ensure_destination_analysis_for_target(
                target_key=target_key,
                ddi_resolution=ddi_resolution,
            )
            result["destination_analysis"] = destination_analysis
            result["evidence_artifacts"] = {
                **dict(result.get("evidence_artifacts") or {}),
                **dict(destination_analysis.get("evidence_artifacts") or {}),
            }
            pipeline = dict(result.get("pipeline") or {})
            endpoint_count = len(destination_analysis.get("external_endpoints") or [])
            analysis_state = str(destination_analysis.get("analysis_state") or "")
            stage_status = "completed" if analysis_state in {"ANALYZED", "NO_EXTERNAL_ENDPOINTS"} else "partial"
            stage_detail = (
                f"{endpoint_count} external endpoint{'s' if endpoint_count != 1 else ''} retained"
                if analysis_state == "ANALYZED"
                else (
                    "No external endpoints retained in target capture."
                    if analysis_state == "NO_EXTERNAL_ENDPOINTS"
                    else str(destination_analysis.get("assessment") or "External destination analysis unavailable.")
                )
            )
            result["pipeline"] = self._upsert_pipeline_stage(
                pipeline,
                stage_id="destination_analysis",
                label="External Destinations",
                status=stage_status,
                detail=stage_detail,
            )
            self.evidence.write_service_audit_trace(target_id=target_key, audit_payload=result)
        result["target_validation"] = {
            **dict(result.get("target_validation") or {}),
            "candidate_ips": candidate_ips,
            "validated_candidates": validated_candidates,
            "rejected_candidates": rejected_candidates,
            "ddi_resolution": ddi_resolution,
            "resolution_state": ddi_resolution.get("resolution_state") or "VALIDATED_IP",
            "explanation": ddi_resolution.get("explanation") or "",
        }
        self.service_audit_cache[target_key] = result
        return self._annotate_wifi_hard_audit(result)

    def analyze_imported_capture(self, capture_path: str, replay: bool = False) -> Dict[str, Any]:
        feature = self._offline_evidence_feature()
        if not feature.get("enabled"):
            return {
                "ok": False,
                "error": "Offline authentication-evidence analysis is disabled by project configuration.",
                "feature": feature,
            }
        return self.imported_capture_analyzer.analyze(capture_path, replay=replay)

    def get_status(self, prepare: bool = False, light: bool = False) -> Dict[str, Any]:
        sensor = self.prepare_sensor(self.scan_selected_interfaces) if prepare else (self.sensor_snapshot or self.monitor.ensure_monitor_interfaces(self.scan_selected_interfaces))
        monitor_interface = sensor.get("monitor_interface")
        monitor_interfaces = sensor.get("monitor_interfaces") or ([monitor_interface] if monitor_interface else [])
        auth_evidence = {} if light else self.tracker.get_authentication_evidence()
        observation_audit = {} if light else self.tracker.get_observation_audit()
        effective_capture_active = self._effective_capture_active()
        return {
            "service": "wifi_mk7",
            "version": self.VERSION,
            "sensor_ready": bool(monitor_interface or monitor_interfaces),
            "armed": self.armed,
            "capture_active": effective_capture_active,
            "packet_rate_pps": self.last_pps,
            "last_started_at": self.last_started_at,
            "last_sweep_at": self.last_sweep_at,
            "last_error": self.last_error or ("" if (monitor_interface or monitor_interfaces) else sensor.get("detail", "")),
            "adapter": {
                "detected": bool(sensor.get("available")),
                "base_interface": sensor.get("base_interface"),
                "preferred_interface": sensor.get("preferred_interface") or self.monitor.PREFERRED_INTERFACE,
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
            "channels": self.get_channels(light=light),
            "capture": {
                "state": "Active" if effective_capture_active else ("Idle" if not self.armed else "Ready"),
            },
            "inventory": {
                "network_count": len(self.tracker.networks),
                "client_count": len(self.tracker.clients),
                "pcap_count": len(self.get_pcap_inventory()),
            },
            "feature_flags": {
                "offlineEvidenceAnalysis": self._offline_evidence_feature(),
                "externalDestinationAnalysis": self._external_destination_feature(),
                "adversaryReplay": {
                    "enabled": bool(self._offline_evidence_feature().get("enabled")),
                    "warning": "Adversary replay reprocesses approved .pcap/.pcapng evidence through the live WiFi MK7 decode and tracker pipeline without RF transmission.",
                    "receive_only": True,
                },
            },
            "authentication_evidence": auth_evidence,
            "observation_audit": observation_audit,
            "last_scan_summary": self.last_scan_summary,
            "scan": self._scan_status_payload(),
            "deep_packet_enrichment": self.enricher.status(),
            "camera_hunt": self.scan_camera_hunt,
            "camera_hunt_pipeline": self.pipeline.status(),
            "camera_hunt_auto_probe": self.auto_probe_summary,
            "processing_pipeline": self.processing_pipeline.status(),
            "fallback_ingest": {
                "count": int(self.fallback_ingest_count or 0),
                "last": dict(self.last_fallback_ingest or {}),
            },
            "artifact_materialization": self._artifact_materialization_status(),
            "resource_policy": self.resource_policy,
            "toolchain": self._toolchain_status(),
        }
