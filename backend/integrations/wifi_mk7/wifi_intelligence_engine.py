from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from backend.core.device_classifier import DeviceClassifier
from backend.integrations.wifi_mk7.camera_intelligence_engine import CameraIntelligenceEngine
from backend.integrations.wifi_mk7.device_assessment_builder import DeviceAssessmentBuilder
from backend.integrations.wifi_mk7.password_risk_engine import WiFiPasswordRiskEngine
from backend.integrations.wifi_mk7.passive_event_engine import PassiveEventEngine
from backend.integrations.wifi_mk7.wifi_intelligence_profiles import (
    CAMERA_HINTS,
    DEVICE_VALUE_SCORES,
    HIGH_RISK_IMPORT_COUNTRIES,
    HUB_HINTS,
    ISP_ROUTER_HINTS,
    EXTENDER_HINTS,
    ONBOARDING_HINTS,
    PHONE_VENDORS,
    PRINTER_HINTS,
    PRIORITY_THRESHOLDS,
    ROUTER_HINTS,
    TV_HINTS,
    VACUUM_HINTS,
)


class WiFiIntelligenceEngine:
    DEFAULT_SCENARIO = "passive_observation"
    SCENARIO_LABELS = {
        "passive_observation": "Passive Observation",
        "idle": "Idle",
        "app_open": "App Open",
        "live_view": "Live View",
        "motion": "Motion",
        "doorbell": "Doorbell",
        "reboot": "Post-Reboot",
    }
    STRICT_CAMERA_VENDOR_HINTS = (
        "hikvision",
        "dahua",
        "axis",
        "ezviz",
        "reolink",
        "arlo",
        "ring",
        "amcrest",
        "imou",
        "lorex",
        "annke",
        "foscam",
        "vstarcam",
        "uniview",
        "xiongmai",
        "xmeye",
        "netatmo",
        "vivotek",
        "mobotix",
        "bosch",
        "wisenet",
        "hanwha",
    )
    CONDITIONAL_CAMERA_VENDOR_HINTS = (
        "tp-link",
        "tplink",
        "tapo",
        "xiaomi",
        "imilab",
        "mijia",
        "tuya",
        "smart life",
        "wyze",
        "eufy",
        "aqara",
        "google",
        "nest",
        "amazon",
        "ring",
        "arlo",
        "ubiquiti",
        "unifi",
    )
    VENDOR_FAMILY_HINTS = {
        "xiaomi_mi_imilab_mijia": ("xiaomi", "mijia", "imilab", "chuangmi", "miap", "miio", "miiot", "zhen shi"),
        "tplink_tapo_kasa": ("tp-link", "tplink", "tapo", "kasa"),
        "hikvision_ezviz": ("hikvision", "ezviz"),
        "dahua_imou": ("dahua", "imou"),
        "google_nest": ("google", "nest"),
        "amazon_ring_blink": ("amazon", "ring", "blink"),
        "anker_eufy": ("anker", "eufy"),
        "arlo": ("arlo",),
        "wyze": ("wyze",),
        "ubiquiti_unifi": ("ubiquiti", "unifi"),
        "aqara": ("aqara",),
        "tuya_smart_life": ("tuya", "smart life"),
        "roborock": ("roborock",),
        "ecovacs": ("ecovacs", "deebot"),
        "apple": ("apple", "airplay", "homepod"),
        "samsung_smartthings": ("samsung", "smartthings"),
        "lg_thinq": ("lg", "thinq"),
        "hp_printer": ("hp", "hewlett packard"),
        "canon_printer": ("canon",),
        "brother_printer": ("brother",),
    }
    PRODUCT_CATEGORY_HINTS = {
        "doorbell_camera": ("doorbell", "video doorbell"),
        "baby_monitor": ("baby", "monitor", "infant"),
        "pet_camera": ("pet", "furbo"),
        "camera": ("camera", "cam", "ipc", "ipcam", "webcam", "surveillance"),
        "router_ap": ("router", "gateway", "cpe"),
        "mesh_extender": ("mesh", "extender", "repeater"),
        "iot_hub": ("hub", "bridge", "gateway"),
        "vacuum": ("vacuum", "roborock", "deebot"),
        "printer": ("printer", "print", "officejet", "deskjet", "laserjet"),
        "tv_media": ("tv", "roku", "chromecast", "appletv", "firetv", "media"),
        "phone": ("iphone", "android", "phone", "galaxy", "pixel"),
    }

    def __init__(self, history_path: Path | None = None) -> None:
        self.camera_engine = CameraIntelligenceEngine()
        self.device_classifier = DeviceClassifier()
        self.assessment_builder = DeviceAssessmentBuilder()
        self.password_risk_engine = WiFiPasswordRiskEngine()
        self.passive_event_engine = PassiveEventEngine()
        self.history_path = history_path
        self.scenario_history: Dict[str, Dict[str, Dict[str, Any]]] = {"networks": {}, "clients": {}}
        self.current_scan_context: Dict[str, Any] = {
            "scenario": self.DEFAULT_SCENARIO,
            "camera_hunt": False,
            "scan_mode": "broad",
            "started_at": None,
        }
        self._load_scenario_history()

    def _load_scenario_history(self) -> None:
        if not self.history_path or not self.history_path.exists():
            return
        try:
            loaded = json.loads(self.history_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if isinstance(loaded, dict):
            self.scenario_history["networks"] = dict(loaded.get("networks") or {})
            self.scenario_history["clients"] = dict(loaded.get("clients") or {})

    def _save_scenario_history(self) -> None:
        if not self.history_path:
            return
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            self.history_path.write_text(json.dumps(self.scenario_history, indent=2, sort_keys=True), encoding="utf-8")
        except Exception:
            pass

    def set_scan_context(
        self,
        *,
        scenario: str = DEFAULT_SCENARIO,
        camera_hunt: bool = False,
        scan_mode: str = "broad",
        started_at: float | None = None,
    ) -> None:
        normalized = str(scenario or self.DEFAULT_SCENARIO).strip().lower().replace(" ", "_")
        if normalized not in self.SCENARIO_LABELS:
            normalized = self.DEFAULT_SCENARIO
        self.current_scan_context = {
            "scenario": normalized,
            "camera_hunt": bool(camera_hunt),
            "scan_mode": str(scan_mode or "broad"),
            "started_at": started_at,
        }

    def _entity_key(self, item: Dict[str, Any]) -> str:
        return str(item.get("mac") or item.get("bssid") or item.get("record_id") or "").strip().lower()

    def _scenario_history_for(self, group: str, item: Dict[str, Any]) -> Dict[str, Any]:
        key = self._entity_key(item)
        if not key:
            return {"current_scenario": self.current_scan_context.get("scenario") or self.DEFAULT_SCENARIO, "available_scenarios": [], "scenarios": {}}
        stored = ((self.scenario_history.get(group) or {}).get(key) or {}).get("scenarios") or {}
        available = sorted({*stored.keys(), str(self.current_scan_context.get("scenario") or self.DEFAULT_SCENARIO)})
        return {
            "current_scenario": self.current_scan_context.get("scenario") or self.DEFAULT_SCENARIO,
            "available_scenarios": available,
            "scenarios": stored,
        }

    @staticmethod
    def _scenario_observation_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
        services = dict(item.get("service_exposure") or {})
        protocol_conf = dict(services.get("protocol_confidence") or {})
        flow_metrics = dict(item.get("flow_metrics") or {})
        stream_state = dict(item.get("stream_state") or {})
        endpoints = sorted(
            {
                *[str(value).strip().lower() for value in (services.get("cloud_endpoints") or []) if str(value).strip()],
                *[str(value).strip().lower() for value in (item.get("tls_server_names") or []) if str(value).strip()],
                *[str(value).strip().lower() for value in (item.get("quic_server_names") or []) if str(value).strip()],
                *[str(value).strip().lower() for value in (item.get("dns_query_names") or []) if str(value).strip()],
                *[str(value).strip().lower() for value in (item.get("related_domains") or []) if str(value).strip()],
            }
        )[:10]
        return {
            "timestamp": int(time.time()),
            "bytes": int(flow_metrics.get("total_bytes") or item.get("frame_bytes_total") or 0),
            "packets": int(flow_metrics.get("total_packets") or item.get("packet_count") or 0),
            "eapol": int((item.get("authentication_evidence") or {}).get("eapol_frame_count") or item.get("eapol_count") or 0),
            "http_confidence": float(protocol_conf.get("HTTP") or 0.0),
            "rtsp_confidence": float(protocol_conf.get("RTSP") or 0.0),
            "tls_confidence": float(protocol_conf.get("TLS") or 0.0),
            "quic_confidence": float(protocol_conf.get("QUIC") or 0.0),
            "object_hits": int(stream_state.get("metrics", {}).get("object_hits") or item.get("saved_image_count") or item.get("http_object_count") or 0),
            "state": str(stream_state.get("state") or "no_session"),
            "transport": str(stream_state.get("transport") or "unknown"),
            "traffic_pattern": str(item.get("traffic_pattern") or "mixed"),
            "camera_score": float((item.get("camera_detection") or {}).get("score") or 0.0),
            "duration_seconds": float(flow_metrics.get("duration_seconds") or 0.0),
            "packet_rate_pps": float(flow_metrics.get("packet_rate_pps") or 0.0),
            "endpoints": endpoints,
        }

    def record_scan_snapshot(self, networks: List[Dict[str, Any]], clients: List[Dict[str, Any]]) -> None:
        scenario = str(self.current_scan_context.get("scenario") or self.DEFAULT_SCENARIO)
        for group, items in (("networks", networks), ("clients", clients)):
            group_history = self.scenario_history.setdefault(group, {})
            for item in items or []:
                key = self._entity_key(item)
                if not key:
                    continue
                bucket = group_history.setdefault(key, {"scenarios": {}})
                scenario_bucket = bucket.setdefault("scenarios", {}).setdefault(scenario, {"observations": [], "summary": {}})
                observation = self._scenario_observation_from_item(item)
                observations = list(scenario_bucket.get("observations") or [])
                observations.insert(0, observation)
                scenario_bucket["observations"] = observations[:6]
                scenario_bucket["summary"] = {
                    "last_seen": observation["timestamp"],
                    "observation_count": len(scenario_bucket["observations"]),
                    "max_bytes": max(int(obs.get("bytes") or 0) for obs in scenario_bucket["observations"]),
                    "max_packets": max(int(obs.get("packets") or 0) for obs in scenario_bucket["observations"]),
                    "max_eapol": max(int(obs.get("eapol") or 0) for obs in scenario_bucket["observations"]),
                    "max_http_confidence": max(float(obs.get("http_confidence") or 0.0) for obs in scenario_bucket["observations"]),
                    "max_rtsp_confidence": max(float(obs.get("rtsp_confidence") or 0.0) for obs in scenario_bucket["observations"]),
                    "max_tls_confidence": max(float(obs.get("tls_confidence") or 0.0) for obs in scenario_bucket["observations"]),
                    "max_object_hits": max(int(obs.get("object_hits") or 0) for obs in scenario_bucket["observations"]),
                    "max_duration_seconds": max(float(obs.get("duration_seconds") or 0.0) for obs in scenario_bucket["observations"]),
                    "max_packet_rate_pps": max(float(obs.get("packet_rate_pps") or 0.0) for obs in scenario_bucket["observations"]),
                    "strongest_state": max(
                        (str(obs.get("state") or "no_session") for obs in scenario_bucket["observations"]),
                        key=self._stream_state_rank,
                    ),
                    "last_transport": observation["transport"],
                    "endpoints": sorted({endpoint for obs in scenario_bucket["observations"] for endpoint in list(obs.get("endpoints") or [])})[:10],
                }
        self._save_scenario_history()

    @staticmethod
    def _stream_state_rank(state: str) -> int:
        ranks = {
            "no_session": 0,
            "background_telemetry": 1,
            "possible_encrypted_media": 2,
            "media_path_confirmed": 3,
            "artifact_recovered": 4,
        }
        return ranks.get(str(state or "no_session"), 0)

    @classmethod
    def _scenario_label(cls, scenario: str) -> str:
        return cls.SCENARIO_LABELS.get(str(scenario or cls.DEFAULT_SCENARIO), "Passive Observation")

    def _scenario_view(
        self,
        scenario: str,
        current_scenario: str,
        current_observation: Dict[str, Any],
        scenario_history: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        if scenario == current_scenario:
            return current_observation
        history_bucket = (((scenario_history.get("scenarios") or {}).get(scenario) or {}).get("summary") or {})
        if not history_bucket:
            return None
        return {
            "bytes": int(history_bucket.get("max_bytes") or 0),
            "packets": int(history_bucket.get("max_packets") or 0),
            "eapol": int(history_bucket.get("max_eapol") or 0),
            "http_confidence": float(history_bucket.get("max_http_confidence") or 0.0),
            "rtsp_confidence": float(history_bucket.get("max_rtsp_confidence") or 0.0),
            "tls_confidence": float(history_bucket.get("max_tls_confidence") or 0.0),
            "object_hits": int(history_bucket.get("max_object_hits") or 0),
            "state": str(history_bucket.get("strongest_state") or "no_session"),
            "transport": str(history_bucket.get("last_transport") or "unknown"),
            "duration_seconds": float(history_bucket.get("max_duration_seconds") or 0.0),
            "packet_rate_pps": float(history_bucket.get("max_packet_rate_pps") or 0.0),
            "endpoints": list(history_bucket.get("endpoints") or []),
        }

    def _compare_scenarios(
        self,
        baseline_name: str,
        baseline_view: Dict[str, Any] | None,
        target_name: str,
        target_view: Dict[str, Any] | None,
    ) -> Dict[str, Any]:
        if not baseline_view or not target_view:
            return {
                "status": "UNKNOWN",
                "summary": f"{self._scenario_label(baseline_name)} vs {self._scenario_label(target_name)} requires retained observations for both scenarios.",
            }
        baseline_state_rank = self._stream_state_rank(str(baseline_view.get("state") or "no_session"))
        target_state_rank = self._stream_state_rank(str(target_view.get("state") or "no_session"))
        baseline_bytes = int(baseline_view.get("bytes") or 0)
        target_bytes = int(target_view.get("bytes") or 0)
        baseline_protocol = max(
            float(baseline_view.get("http_confidence") or 0.0),
            float(baseline_view.get("rtsp_confidence") or 0.0),
            float(baseline_view.get("tls_confidence") or 0.0),
        )
        target_protocol = max(
            float(target_view.get("http_confidence") or 0.0),
            float(target_view.get("rtsp_confidence") or 0.0),
            float(target_view.get("tls_confidence") or 0.0),
        )
        if target_state_rank > baseline_state_rank and target_protocol >= max(25.0, baseline_protocol):
            return {
                "status": "STRONGER_TARGET",
                "summary": f"{self._scenario_label(target_name)} shows a stronger media path than {self._scenario_label(baseline_name)}.",
            }
        if target_bytes >= max(65536, baseline_bytes * 2) and target_protocol > baseline_protocol:
            return {
                "status": "HIGHER_PAYLOAD",
                "summary": f"{self._scenario_label(target_name)} carries materially more payload and stronger protocol evidence than {self._scenario_label(baseline_name)}.",
            }
        if target_state_rank == baseline_state_rank and abs(target_bytes - baseline_bytes) <= max(8192, baseline_bytes * 0.25):
            return {
                "status": "NO_SIGNIFICANT_DELTA",
                "summary": f"{self._scenario_label(target_name)} currently resembles {self._scenario_label(baseline_name)}.",
            }
        return {
            "status": "MIXED_DELTA",
            "summary": f"{self._scenario_label(target_name)} differs from {self._scenario_label(baseline_name)}, but the retained evidence is not yet decisive.",
        }

    def enrich_networks(self, networks: List[Dict[str, Any]], clients: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        client_counts = {}
        for client in clients:
            bssid = str(client.get("associated_bssid") or "").lower()
            if bssid and bssid != "ff:ff:ff:ff:ff:ff":
                client_counts[bssid] = client_counts.get(bssid, 0) + 1

        enriched = []
        for network in networks:
            item = dict(network)
            bssid = str(item.get("bssid") or "").lower()
            item["client_count"] = client_counts.get(bssid, item.get("client_count") or 0) if bssid else 0
            item["scenario_history"] = self._scenario_history_for("networks", item)
            fingerprint = self._fingerprint_network(item)
            services = self._service_exposure(item)
            item["service_exposure"] = services
            camera = self._camera_detection(item, fingerprint)
            role_duel = self._role_duel(item, fingerprint, camera, services)
            camera = self._adjudicate_camera(item, fingerprint, camera, services, role_duel)
            score = self._target_score(item, fingerprint, camera)
            behavior = self._behavior_analysis(item, fingerprint)
            security_posture = self._security_posture(item)
            password_risk = self.password_risk_engine.assess_network(
                {
                    **item,
                    "fingerprint": fingerprint,
                    "security_posture": security_posture,
                }
            )
            auth_evidence = self._authentication_evidence(item)
            observation_opportunity = self.passive_event_engine.observation_opportunity(item)
            anomalies = self._anomaly_profile(item, fingerprint, services)
            risk = self._risk_profile(item, fingerprint, camera, score, services, anomalies)
            evidence_model = self._evidence_model(item, fingerprint, camera, services)
            stable_fingerprint = self._stable_fingerprint(item, fingerprint)
            stream_state = self._stream_state(item, services, behavior, auth_evidence, camera)
            scenario_delta = self._scenario_delta(item, services, behavior, stream_state)
            camera_confirmation = self._camera_confirmation(item, fingerprint, services, camera, stream_state, scenario_delta)
            video_evidence = self._video_evidence(item, fingerprint, services, behavior, stream_state, scenario_delta, camera_confirmation)
            item["fingerprint"] = fingerprint
            item["camera_detection"] = camera
            item["role_duel"] = role_duel
            item["target_score"] = score
            item["behavior_analysis"] = behavior
            item["security_posture"] = security_posture
            item["password_risk"] = password_risk
            item["authentication_evidence"] = auth_evidence
            item["observation_opportunity"] = observation_opportunity
            item["anomaly_profile"] = anomalies
            item["risk_profile"] = risk
            item["evidence_model"] = evidence_model
            item["stable_fingerprint"] = stable_fingerprint
            item["stream_state"] = stream_state
            item["scenario_delta"] = scenario_delta
            item["camera_confirmation"] = camera_confirmation
            item["video_evidence"] = video_evidence
            classification = self.device_classifier.classify_device(
                item,
                fingerprint=fingerprint,
                services=services,
                camera=camera,
                behavior=behavior,
                role_duel=role_duel,
                stream_state=stream_state,
                camera_confirmation=camera_confirmation,
            )
            item["device_classification"] = classification
            item["device_group"] = classification.get("device_group")
            item["device_group_color"] = classification.get("color")
            item["device_group_confidence"] = classification.get("confidence")
            item["classification_signals"] = classification.get("classification_signals") or []
            item["classification_explanation"] = classification.get("explanation") or ""
            item["device_assessment"] = self.assessment_builder.build(
                item,
                fingerprint=fingerprint,
                services=services,
                camera=camera,
                behavior=behavior,
                auth_evidence=auth_evidence,
                risk=risk,
                stable_fingerprint=stable_fingerprint,
            )
            enriched.append(item)
        return enriched

    def enrich_clients(self, clients: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched = []
        for client in clients:
            item = dict(client)
            item["scenario_history"] = self._scenario_history_for("clients", item)
            fingerprint = self._fingerprint_client(item)
            services = self._service_exposure(item)
            item["service_exposure"] = services
            camera = self._camera_detection(item, fingerprint)
            role_duel = self._role_duel(item, fingerprint, camera, services)
            camera = self._adjudicate_camera(item, fingerprint, camera, services, role_duel)
            score = self._target_score(item, fingerprint, camera)
            behavior = self._behavior_analysis(item, fingerprint)
            auth_evidence = self._authentication_evidence(item)
            anomalies = self._anomaly_profile(item, fingerprint, services)
            risk = self._risk_profile(item, fingerprint, camera, score, services, anomalies)
            evidence_model = self._evidence_model(item, fingerprint, camera, services)
            stable_fingerprint = self._stable_fingerprint(item, fingerprint)
            stream_state = self._stream_state(item, services, behavior, auth_evidence, camera)
            scenario_delta = self._scenario_delta(item, services, behavior, stream_state)
            camera_confirmation = self._camera_confirmation(item, fingerprint, services, camera, stream_state, scenario_delta)
            video_evidence = self._video_evidence(item, fingerprint, services, behavior, stream_state, scenario_delta, camera_confirmation)
            item["fingerprint"] = fingerprint
            item["camera_detection"] = camera
            item["role_duel"] = role_duel
            item["target_score"] = score
            item["behavior_analysis"] = behavior
            item["authentication_evidence"] = auth_evidence
            item["anomaly_profile"] = anomalies
            item["risk_profile"] = risk
            item["evidence_model"] = evidence_model
            item["stable_fingerprint"] = stable_fingerprint
            item["stream_state"] = stream_state
            item["scenario_delta"] = scenario_delta
            item["camera_confirmation"] = camera_confirmation
            item["video_evidence"] = video_evidence
            classification = self.device_classifier.classify_device(
                item,
                fingerprint=fingerprint,
                services=services,
                camera=camera,
                behavior=behavior,
                role_duel=role_duel,
                stream_state=stream_state,
                camera_confirmation=camera_confirmation,
            )
            item["device_classification"] = classification
            item["device_group"] = classification.get("device_group")
            item["device_group_color"] = classification.get("color")
            item["device_group_confidence"] = classification.get("confidence")
            item["classification_signals"] = classification.get("classification_signals") or []
            item["classification_explanation"] = classification.get("explanation") or ""
            item["device_assessment"] = self.assessment_builder.build(
                item,
                fingerprint=fingerprint,
                services=services,
                camera=camera,
                behavior=behavior,
                auth_evidence=item.get("authentication_evidence") or {},
                risk=risk,
                stable_fingerprint=stable_fingerprint,
            )
            enriched.append(item)
        return enriched

    def _behavior_analysis(self, item: Dict[str, Any], fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        traffic_pattern = str(item.get("traffic_pattern") or "mixed")
        mobility_class = str(item.get("mobility_class") or "static")
        packet_count = int(item.get("packet_count") or 0)
        avg_gap = float(item.get("avg_interarrival_seconds") or 0.0)
        uptime_span = float(item.get("activity_span_seconds") or 0.0)
        variance = float(item.get("rssi_variance_db") or 0.0)

        if traffic_pattern == "steady-stream":
            summary = "Continuous"
        elif traffic_pattern == "probe-bursty":
            summary = "Bursty"
        elif traffic_pattern == "periodic":
            summary = "Periodic"
        else:
            summary = "Mixed"

        if mobility_class == "high-mobility":
            mobility_score = 0.9
        elif mobility_class == "low-mobility":
            mobility_score = 0.45
        else:
            mobility_score = 0.1

        if uptime_span >= 45 or int(item.get("historical_captures") or 0) >= 3:
            activity_pattern = "Persistent"
        elif packet_count >= 8:
            activity_pattern = "Active"
        else:
            activity_pattern = "Intermittent"

        reasons: List[str] = []
        if summary == "Continuous":
            reasons.append("steady packet cadence")
        if summary == "Periodic":
            reasons.append("repeating interval behavior")
        if summary == "Bursty":
            reasons.append("probe-heavy burst pattern")
        if mobility_class != "static":
            reasons.append(mobility_class)
        if variance:
            reasons.append(f"RSSI variance {round(variance, 1)} dB")
        if avg_gap:
            reasons.append(f"avg gap {round(avg_gap, 2)}s")

        return {
            "summary": summary,
            "traffic_pattern": traffic_pattern,
            "mobility_class": mobility_class,
            "mobility_score": round(mobility_score, 2),
            "activity_pattern": activity_pattern,
            "uptime_behavior": "Always-on" if activity_pattern == "Persistent" else ("Active burst" if activity_pattern == "Active" else "Intermittent"),
            "flow_summary": self._flow_summary(item),
            "reasons": reasons or [str(fingerprint.get("behavior_profile") or "limited passive behavior evidence")],
        }

    def _service_exposure(self, item: Dict[str, Any]) -> Dict[str, Any]:
        raw_services = [
            *list(item.get("related_services") or []),
            *list(item.get("mdns_ptr_names") or []),
            *list(item.get("tls_server_names") or []),
            *list(item.get("dns_query_names") or []),
            *list(item.get("related_domains") or []),
            *list(item.get("http_user_agents") or []),
            *list(item.get("http_server_headers") or []),
            *list(item.get("related_hostnames") or []),
            *list(item.get("dhcp_hostnames") or []),
            *list(item.get("dhcp_vendor_class_ids") or []),
            *list(item.get("mdns_service_instances") or []),
            *list(item.get("quic_server_names") or []),
            *list(item.get("tls_subject_alt_names") or []),
        ]
        text = " ".join(str(value or "") for value in raw_services).lower()

        protocols: List[str] = []
        services: List[str] = []
        exposures: List[str] = []
        cloud_endpoints: List[str] = []

        if "rtsp" in text or "_rtsp._tcp" in text:
            protocols.append("RTSP")
            services.append("Video Stream")
            exposures.append("RTSP detected")
        if "onvif" in text:
            protocols.append("ONVIF")
            services.append("Camera Discovery")
            exposures.append("ONVIF exposure")
        if "mqtt" in text or "_mqtt" in text:
            protocols.append("MQTT")
            services.append("IoT Messaging")
            exposures.append("MQTT active")
        if "ssdp" in text or "upnp" in text or "_upnp" in text:
            protocols.append("SSDP/UPnP")
            services.append("Service Advertisement")
            exposures.append("UPnP service exposure")
        if "http" in text or len(item.get("http_user_agents") or []) > 0:
            protocols.append("HTTP")
            services.append("HTTP Application")
            exposures.append("HTTP admin/API surface")
        if len(item.get("quic_server_names") or []) > 0 or len(item.get("http3_authorities") or []) > 0:
            protocols.append("QUIC")
            services.append("QUIC Application")
            exposures.append("QUIC cloud endpoint identified")
        if len(item.get("dhcp_hostnames") or []) > 0:
            services.append("DHCP Identity")
        if len(item.get("mdns_ptr_names") or []) > 0:
            protocols.append("mDNS")
            services.append("mDNS Identity")
        if len(item.get("dns_query_names") or []) > 0 or len(item.get("related_domains") or []) > 0:
            protocols.append("DNS")
        if len(item.get("tls_server_names") or []) > 0:
            protocols.append("TLS")
            for endpoint in list(item.get("tls_server_names") or [])[:6]:
                if "." in str(endpoint):
                    cloud_endpoints.append(str(endpoint))
            if cloud_endpoints:
                exposures.append("Cloud endpoints identified")
        for endpoint in list(item.get("quic_server_names") or [])[:6]:
            if "." in str(endpoint):
                cloud_endpoints.append(str(endpoint))
        if (item.get("flow_metrics") or {}).get("long_lived_flow"):
            exposures.append("Long-lived encrypted stream observed")

        service_inventory_entries = list(item.get("service_inventory") or [])
        normalized_inventory = []
        for entry in service_inventory_entries:
            if not isinstance(entry, dict):
                continue
            service_name = str(entry.get("service_name") or "").strip()
            service_port = int(entry.get("service_port") or 0)
            transport = str(entry.get("transport") or "").strip().lower()
            protocol_source = str(entry.get("protocol_source") or "").strip()
            evidence_detail = str(entry.get("evidence_detail") or "").strip()
            if not any((service_name, service_port, evidence_detail)):
                continue
            normalized_inventory.append(
                {
                    "service": service_name or "--",
                    "port": service_port,
                    "transport": transport or "--",
                    "source": protocol_source or "passive",
                    "detail": evidence_detail or "--",
                }
            )

        mdns_dns_score = 0
        if len(item.get("mdns_ptr_names") or []) > 0:
            mdns_dns_score += min(40, len(item.get("mdns_ptr_names") or []) * 12)
        if len(item.get("dns_query_names") or []) > 0 or len(item.get("related_domains") or []) > 0:
            mdns_dns_score += min(25, (len(item.get("dns_query_names") or []) + len(item.get("related_domains") or [])) * 5)
        if len(item.get("dhcp_hostnames") or []) > 0:
            mdns_dns_score += 10

        http_score = 0
        if len(item.get("http_hosts") or []) > 0:
            http_score += min(35, len(item.get("http_hosts") or []) * 10)
        if len(item.get("http_uris") or []) > 0:
            http_score += min(25, len(item.get("http_uris") or []) * 8)
        if len(item.get("http_user_agents") or []) > 0:
            http_score += min(20, len(item.get("http_user_agents") or []) * 6)

        tls_score = min(60, len(item.get("tls_server_names") or []) * 15)
        tls_score += min(20, len(item.get("tls_subject_alt_names") or []) * 5)
        rtsp_score = min(80, (len(item.get("rtsp_urls") or []) * 20) + (len(item.get("rtsp_requests") or []) * 12))
        quic_score = min(50, len(item.get("quic_server_names") or []) * 15)
        vendor_wps_score = 0
        if any(
            str(item.get(field) or "").strip()
            for field in ("wps_manufacturer", "wps_model_name", "wps_device_name", "wps_model_number")
        ):
            vendor_wps_score += 35
        if bool(item.get("wps_primary_device_camera")):
            vendor_wps_score += 30
        if str(item.get("vendor") or "").strip() not in {"", "--", "Unknown"}:
            vendor_wps_score += 10

        protocol_confidence = {
            "mDNS/DNS": min(100, mdns_dns_score),
            "HTTP": min(100, http_score),
            "TLS": min(100, tls_score),
            "RTSP": min(100, rtsp_score),
            "QUIC": min(100, quic_score),
            "vendor/WPS": min(100, vendor_wps_score),
        }

        return {
            "protocols": sorted(set(protocols)),
            "services": sorted(set(services)),
            "exposures": exposures[:6],
            "cloud_endpoints": cloud_endpoints[:6],
            "identity_hints": [*list(item.get("dhcp_hostnames") or [])[:4], *list(item.get("mdns_ptr_names") or [])[:4]],
            "service_inventory": normalized_inventory[:10],
            "protocol_confidence": protocol_confidence,
            "summary": ", ".join(exposures[:3]) if exposures else ("Passive identity only" if raw_services else "No service exposure observed"),
        }

    def _evidence_model(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        camera: Dict[str, Any],
        services: Dict[str, Any],
    ) -> Dict[str, Any]:
        vendor = self._normalize_vendor(item)
        family = str(camera.get("family_match") or fingerprint.get("device_family") or "unknown")
        probable_model = self._probable_model(item)
        local_services = [
            entry.get("service")
            for entry in list(services.get("service_inventory") or [])
            if str(entry.get("service") or "").strip() not in {"", "--"}
        ]
        cloud_provider = self._cloud_provider(item, services)
        identity_sources = sorted(
            {
                *[str(source).strip() for source in (item.get("enrichment_sources") or []) if str(source).strip()],
                *["wps" for field in ("wps_manufacturer", "wps_model_name", "wps_device_name") if str(item.get(field) or "").strip()],
                *["dhcp" for field in ("dhcp_hostnames", "dhcp_vendor_class_ids", "dhcp_parameter_request_lists") if list(item.get(field) or [])],
                *["tls" for field in ("tls_server_names", "tls_certificate_subjects", "tls_subject_alt_names") if list(item.get(field) or [])],
            }
        )
        camera_mode = str(camera.get("detection_mode") or "unknown")
        missing_evidence: List[str] = []
        if camera_mode == "local_camera":
            if "RTSP" not in list(services.get("protocols") or []) and "ONVIF" not in list(services.get("protocols") or []):
                missing_evidence.append("local protocol evidence")
        if camera_mode == "cloud_camera":
            if not cloud_provider and not list(services.get("cloud_endpoints") or []):
                missing_evidence.append("cloud provider evidence")
        if not probable_model:
            missing_evidence.append("probable model")
        if not list(item.get("evidence_provenance") or []):
            missing_evidence.append("provenance-backed identity evidence")
        return {
            "vendor": vendor,
            "product_family": family,
            "probable_model": probable_model,
            "camera_mode": camera_mode,
            "cloud_provider": cloud_provider,
            "local_services": sorted(set(local_services))[:8],
            "identity_sources": identity_sources[:8],
            "missing_evidence": missing_evidence[:6],
        }

    def _stable_fingerprint(self, item: Dict[str, Any], fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        oui = self._normalize_vendor(item)
        wps_model = self._normalize_wps_model(item)
        tls_client = sorted(set([*list(item.get("tls_ja3_fingerprints") or []), *list(item.get("tls_ja4_fingerprints") or [])]))[:6]
        tls_server = sorted(set(list(item.get("tls_ja3s_fingerprints") or [])))[:6]
        dhcp_buckets = sorted(set(list((item.get("dhcp_fingerprint_buckets") or {}).keys())))[:8]
        return {
            "oui_vendor": oui,
            "normalized_wps_model": wps_model,
            "tls_client_fingerprints": tls_client,
            "tls_server_fingerprints": tls_server,
            "dhcp_fingerprint_buckets": dhcp_buckets,
            "recurring_domains": dict(item.get("recurring_domain_profiles") or {}),
            "recurring_destination_ips": dict(item.get("recurring_destination_profiles") or {}),
            "recurring_services": dict(item.get("recurring_service_profiles") or {}),
            "role": str(fingerprint.get("role") or ""),
        }

    def _role_duel(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        camera: Dict[str, Any],
        services: Dict[str, Any],
    ) -> Dict[str, Any]:
        protocols = set(services.get("protocols") or [])
        vendor_text = self._normalize_vendor(item)
        family = str(camera.get("family_match") or "")
        client_count = int(item.get("client_count") or 0)
        associated_bssids = len(item.get("associated_bssids") or [])
        traffic_pattern = str(item.get("traffic_pattern") or "")
        uplink_ratio = float(((item.get("flow_metrics") or {}).get("uplink_ratio") or 0.0))
        long_lived = bool((item.get("flow_metrics") or {}).get("long_lived_flow"))
        probe_count = int(item.get("probe_request_count") or 0)
        mobility = str(item.get("mobility_class") or "static")
        cloud_provider = self._cloud_provider(item, services)

        role_scores = {
            "camera": 0.0,
            "router": 0.0,
            "hub": 0.0,
            "speaker": 0.0,
            "nvr": 0.0,
            "generic_iot": 0.0,
        }
        arguments: Dict[str, List[str]] = {role: [] for role in role_scores}
        strong_camera_protocol = bool(protocols.intersection({"RTSP", "ONVIF"}))
        cloud_camera_signal = bool(family and cloud_provider and protocols.intersection({"TLS", "QUIC", "HTTP"}))
        camera_behavior_signal = bool(long_lived and uplink_ratio >= 0.60 and traffic_pattern in {"steady-stream", "periodic"})

        if family:
            role_scores["camera"] += 12.0
            arguments["camera"].append(f"vendor family {family}")
        if bool(item.get("wps_primary_device_camera")):
            role_scores["camera"] += 24.0
            arguments["camera"].append("WPS camera type")
        if strong_camera_protocol:
            role_scores["camera"] += 26.0
            arguments["camera"].append("camera local protocol")
        if cloud_camera_signal:
            role_scores["camera"] += 12.0
            arguments["camera"].append(f"camera cloud ecosystem {cloud_provider}")
        if camera_behavior_signal:
            role_scores["camera"] += 14.0
            arguments["camera"].append("upload-biased persistent flow")
        if mobility == "static" and probe_count == 0:
            role_scores["camera"] += 6.0
            arguments["camera"].append("static quiet profile")
        if not family and not strong_camera_protocol and not cloud_camera_signal:
            role_scores["camera"] -= 10.0
            arguments["camera"].append("no vendor or protocol discriminator")

        if str(fingerprint.get("role") or "") == "AP":
            role_scores["router"] += 14.0
            arguments["router"].append("AP role")
        if client_count >= 2:
            role_scores["router"] += min(24.0, 8.0 + (client_count * 4.0))
            arguments["router"].append("multiple attached clients")
        if traffic_pattern == "broadcast-heavy":
            role_scores["router"] += 16.0
            arguments["router"].append("broadcast-heavy AP pattern")
        if any(token in vendor_text for token in ("tp-link", "tplink", "ubiquiti", "unifi", "sercomm", "arcadyan")) and str(fingerprint.get("role") or "") == "AP":
            role_scores["router"] += 10.0
            arguments["router"].append("infrastructure vendor profile")

        if any(token in vendor_text for token in ("amazon", "google", "nest", "eufy", "aqara", "xiaomi")):
            role_scores["hub"] += 8.0
            arguments["hub"].append("hub-capable ecosystem vendor")
        if "MQTT" in protocols or "SSDP/UPnP" in protocols:
            role_scores["hub"] += 10.0
            arguments["hub"].append("hub-style service advertisement")
        if associated_bssids >= 2:
            role_scores["hub"] += 6.0
            arguments["hub"].append("multi-AP / bridge behavior")

        if any(token in vendor_text for token in ("amazon", "google", "nest")) and not ("RTSP" in protocols or "ONVIF" in protocols):
            role_scores["speaker"] += 12.0
            arguments["speaker"].append("speaker/display ecosystem")
        if probe_count > 0 and mobility != "static":
            role_scores["speaker"] += 4.0
            arguments["speaker"].append("mobile assistant behavior")

        if any(token in vendor_text for token in ("reolink", "hikvision", "dahua", "uniview", "annke")) and client_count >= 2:
            role_scores["nvr"] += 20.0
            arguments["nvr"].append("camera vendor with aggregator topology")
        if any(token in str(entry.get("service") or "").lower() for entry in (services.get("service_inventory") or []) for token in ("nvr", "cgi", "protect")):
            role_scores["nvr"] += 12.0
            arguments["nvr"].append("aggregator service indicator")

        role_scores["generic_iot"] += 8.0
        arguments["generic_iot"].append("baseline passive IoT")
        if cloud_provider:
            role_scores["generic_iot"] += 6.0
            arguments["generic_iot"].append("cloud-connected device")
        if family and not ("RTSP" in protocols or "ONVIF" in protocols or cloud_provider):
            role_scores["generic_iot"] += 8.0
            arguments["generic_iot"].append("vendor family without camera discriminator")
        if not family and not strong_camera_protocol and not cloud_camera_signal and camera_behavior_signal:
            role_scores["generic_iot"] += 14.0
            arguments["generic_iot"].append("behavior-only device without camera identity")

        ranked = sorted(role_scores.items(), key=lambda item: item[1], reverse=True)
        winner_role, winner_score = ranked[0]
        runner_role, runner_score = ranked[1]
        return {
            "winner_role": winner_role,
            "winner_score": round(winner_score, 1),
            "runner_up_role": runner_role,
            "runner_up_score": round(runner_score, 1),
            "margin": round(winner_score - runner_score, 1),
            "role_scores": {role: round(score, 1) for role, score in ranked},
            "arguments": {role: reasons[:4] for role, reasons in arguments.items()},
        }

    def _adjudicate_camera(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        camera: Dict[str, Any],
        services: Dict[str, Any],
        role_duel: Dict[str, Any],
    ) -> Dict[str, Any]:
        updated = dict(camera)
        protocols = set(services.get("protocols") or [])
        cloud_provider = self._cloud_provider(item, services)
        strong_camera_protocol = bool(protocols.intersection({"RTSP", "ONVIF"}))
        cloud_camera_signal = bool(
            cloud_provider
            and str(camera.get("family_match") or "")
            and protocols.intersection({"TLS", "QUIC", "HTTP"})
        )
        behavior_camera_signal = bool(
            str(item.get("traffic_pattern") or "") in {"steady-stream", "periodic"}
            and bool((item.get("flow_metrics") or {}).get("long_lived_flow"))
            and float(((item.get("flow_metrics") or {}).get("uplink_ratio") or 0.0)) >= 0.55
        )
        historical_identity_hints = [
            str(item.get("historical_identity_hint") or "").strip().lower(),
            *[str(value).strip().lower() for value in (item.get("related_identity_hints") or []) if str(value).strip()],
        ]
        historical_camera_identity = any(
            any(token in hint for token in ("camera", "chuangmi", "miap", "ipcam"))
            for hint in historical_identity_hints
        )
        evidence_classes = {
            "identity": bool(
                camera.get("family_match")
                or historical_camera_identity
                or bool(item.get("wps_primary_device_camera"))
                or any(list(item.get(field) or []) for field in ("dhcp_hostnames", "dhcp_vendor_class_ids", "tls_certificate_subjects"))
            ),
            "protocol": bool(strong_camera_protocol or cloud_camera_signal),
            "behavior": bool(behavior_camera_signal),
            "topology": bool(
                role_duel.get("winner_role") == "camera"
                or (
                    role_duel.get("winner_role") == "nvr"
                    and int(item.get("client_count") or 0) > 1
                )
            ),
        }
        quorum_count = sum(1 for present in evidence_classes.values() if present)
        winner_role = str(role_duel.get("winner_role") or "")
        runner_up_role = str(role_duel.get("runner_up_role") or "")
        margin = float(role_duel.get("margin") or 0.0)
        family_match = str(camera.get("family_match") or "")
        vendor_family = family_match or self._normalize_vendor(item)

        why_not_camera: List[str] = []
        if family_match and not strong_camera_protocol:
            why_not_camera.append("no local camera protocol")
        if family_match and str(camera.get("detection_mode") or "") == "cloud_camera" and not cloud_provider:
            why_not_camera.append("no cloud camera endpoint")
        if quorum_count < 2:
            why_not_camera.append("insufficient evidence quorum")
        if winner_role != "camera":
            why_not_camera.append(f"competing role {winner_role} outranks camera")
        elif runner_up_role and margin < 8.0:
            why_not_camera.append(f"weak margin over {runner_up_role}")

        if family_match and protocols.intersection({"RTSP", "ONVIF"}):
            updated["vendor_role_state"] = "vendor_family_plus_local_camera"
        elif family_match and cloud_camera_signal:
            updated["vendor_role_state"] = "vendor_family_plus_cloud_camera"
        elif family_match and historical_camera_identity:
            updated["vendor_role_state"] = "vendor_family_plus_historical_camera_identity"
        elif historical_camera_identity:
            updated["vendor_role_state"] = "historical_camera_identity"
        elif family_match:
            updated["vendor_role_state"] = "vendor_family_only"
        else:
            updated["vendor_role_state"] = "unresolved"

        updated["vendor_family"] = vendor_family
        updated["role_winner"] = winner_role
        updated["role_runner_up"] = runner_up_role
        updated["role_margin"] = round(margin, 1)
        updated["camera_evidence_quorum"] = {
            "count": quorum_count,
            "classes": evidence_classes,
        }
        updated["why_not_camera"] = why_not_camera[:6]

        should_retain_as_camera = (
            float(updated.get("score") or 0.0) >= 60.0
            and winner_role == "camera"
            and margin >= 8.0
            and quorum_count >= 2
            and (strong_camera_protocol or cloud_camera_signal or bool(item.get("wps_primary_device_camera")))
        )
        history_backed_camera = bool(
            historical_camera_identity
            and winner_role == "camera"
            and margin >= 12.0
            and quorum_count >= 3
            and behavior_camera_signal
        )
        should_retain_as_camera = bool(should_retain_as_camera or history_backed_camera)
        if not should_retain_as_camera:
            updated["detected"] = False
            if not family_match and not strong_camera_protocol and not cloud_camera_signal:
                updated["classification"] = "Unresolved device"
                updated["ui_label"] = "non_camera_static_device"
                updated["device_type"] = None
                updated["score"] = round(min(float(updated.get("score") or 0.0), 34.0), 1)
            elif family_match and updated["vendor_role_state"] == "vendor_family_only":
                updated["classification"] = "Vendor-family device"
                updated["ui_label"] = "non_camera_static_device"
                updated["device_type"] = updated.get("device_type") if float(updated.get("score") or 0.0) >= 40.0 else None
                updated["score"] = round(min(float(updated.get("score") or 0.0), 39.0), 1)
            elif family_match and not strong_camera_protocol and not cloud_camera_signal:
                updated["classification"] = "Vendor-family device"
                updated["ui_label"] = "non_camera_static_device"
                updated["score"] = round(min(float(updated.get("score") or 0.0), 39.0), 1)
        else:
            updated["detected"] = True
            if history_backed_camera and not strong_camera_protocol and not cloud_camera_signal:
                updated["classification"] = "History-backed behavioral camera"
                updated["ui_label"] = "camera_behavioral_history"
        return updated
    
    @staticmethod
    def _normalize_vendor(item: Dict[str, Any]) -> str:
        for field in ("wps_manufacturer", "vendor"):
            value = str(item.get(field) or "").strip()
            if value:
                return value.lower().replace(" systems", "").replace(" communications", "").strip()
        return "unknown"

    def _probable_model(self, item: Dict[str, Any]) -> str:
        for field in ("wps_model_name", "wps_device_name", "wps_model_number"):
            value = str(item.get(field) or "").strip()
            if value:
                return self._normalize_token(value)
        for field in ("dhcp_hostnames", "related_hostnames"):
            values = list(item.get(field) or [])
            if values:
                return self._normalize_token(str(values[0]))
        return ""

    def _cloud_provider(self, item: Dict[str, Any], services: Dict[str, Any]) -> str:
        endpoints = " ".join([*list(item.get("tls_server_names") or []), *list(item.get("quic_server_names") or []), *list(services.get("cloud_endpoints") or [])]).lower()
        providers = {
            "amazon": ("amazon", "aws", "ring"),
            "google": ("google", "gvt1", "nest", "googlevideo"),
            "tuya": ("tuya", "smartlife"),
            "eufy": ("eufylife", "anker"),
            "tp-link": ("tplinkcloud", "nbu.iot", "tapo"),
            "reolink": ("reolink",),
            "arlo": ("arlo", "myarlo"),
            "xiaomi": ("xiaomi", "miio", "miiot"),
        }
        for provider, hints in providers.items():
            if any(hint in endpoints for hint in hints):
                return provider
        return ""

    @staticmethod
    def _normalize_wps_model(item: Dict[str, Any]) -> str:
        for field in ("wps_model_name", "wps_device_name", "wps_model_number"):
            value = str(item.get(field) or "").strip()
            if value:
                return value.lower().replace("_", "-").replace(" ", "-")
        return ""

    @staticmethod
    def _normalize_token(value: str) -> str:
        return str(value or "").strip().lower().replace("_", "-")

    def _security_posture(self, item: Dict[str, Any]) -> Dict[str, Any]:
        security = str(item.get("security") or "Unknown")
        pmf_enabled = str(item.get("pmf") or "").lower() in {"true", "1"}
        ssid = str(item.get("ssid") or "").lower()
        wps_present = any(
            str(item.get(field) or "").strip()
            for field in (
                "wps_manufacturer",
                "wps_model_name",
                "wps_device_name",
                "wps_model_number",
                "wps_config_methods",
            )
        )
        segmentation = "Guest/Inferred" if "guest" in ssid else "Internal/Unknown"
        findings: List[str] = []
        if "open" in security.lower():
            findings.append("Open network")
        if "wpa2" in security.lower() and "wpa3" not in security.lower():
            findings.append("WPA2 only")
        if not pmf_enabled:
            findings.append("No PMF")
        if wps_present:
            findings.append("WPS observable")
        if "guest" in ssid:
            findings.append("Guest network inference")
        return {
            "security": security,
            "pmf_enabled": pmf_enabled,
            "wps_present": wps_present,
            "segmentation": segmentation,
            "findings": findings,
            "summary": " · ".join(findings[:3]) if findings else security,
        }

    def _authentication_evidence(self, item: Dict[str, Any]) -> Dict[str, Any]:
        handshake_count = int(item.get("handshake_eapol_count") or item.get("eapol_count") or 0)
        session_count = int(item.get("authentication_evidence_session_count") or 0)
        session_quality = str(item.get("authentication_evidence_quality") or "")
        if session_quality == "CONFIRMED":
            quality = "CONFIRMED"
            summary = "Confirmed authentication exchange"
        elif session_quality == "LIKELY":
            quality = "LIKELY"
            summary = "Likely authentication exchange"
        elif session_quality == "PARTIAL":
            quality = "PARTIAL"
            summary = "Partial EAPOL evidence"
        elif handshake_count >= 4:
            quality = "CONFIRMED"
            summary = "Confirmed authentication exchange"
        elif handshake_count == 3:
            quality = "LIKELY"
            summary = "Likely authentication exchange"
        elif handshake_count >= 1:
            quality = "PARTIAL"
            summary = "Partial EAPOL evidence"
        else:
            quality = "NONE"
            summary = "No authentication evidence"
        return {
            "quality": quality,
            "eapol_frame_count": handshake_count,
            "session_count": session_count,
            "handshake_status": str(item.get("handshake_status") or "Not Captured"),
            "summary": summary,
        }

    def _stream_state(
        self,
        item: Dict[str, Any],
        services: Dict[str, Any],
        behavior: Dict[str, Any],
        auth_evidence: Dict[str, Any],
        camera: Dict[str, Any],
    ) -> Dict[str, Any]:
        protocol_conf = dict(services.get("protocol_confidence") or {})
        http_conf = float(protocol_conf.get("HTTP") or 0.0)
        rtsp_conf = float(protocol_conf.get("RTSP") or 0.0)
        tls_conf = float(protocol_conf.get("TLS") or 0.0)
        quic_conf = float(protocol_conf.get("QUIC") or 0.0)
        mdns_dns_conf = float(protocol_conf.get("mDNS/DNS") or 0.0)
        cloud_endpoints = list(services.get("cloud_endpoints") or [])
        protocols = set(services.get("protocols") or [])
        flow_metrics = dict(item.get("flow_metrics") or {})
        total_bytes = int(flow_metrics.get("total_bytes") or item.get("frame_bytes_total") or 0)
        total_packets = int(flow_metrics.get("total_packets") or item.get("packet_count") or 0)
        long_lived = bool(flow_metrics.get("long_lived_flow"))
        uplink_ratio = float(flow_metrics.get("uplink_ratio") or 0.0)
        traffic_pattern = str(item.get("traffic_pattern") or "")
        object_hits = int(item.get("saved_image_count") or 0) + int(item.get("http_object_count") or 0)
        local_media = rtsp_conf >= 20 or "RTSP" in protocols or "ONVIF" in protocols or http_conf >= 35
        encrypted_media = (
            (tls_conf >= 20 or quic_conf >= 20 or "TLS" in protocols or "QUIC" in protocols)
            and (long_lived or total_bytes >= 65536 or total_packets >= 32 or uplink_ratio >= 0.55)
        )
        telemetry_like = (
            traffic_pattern in {"periodic", "mixed"}
            and total_bytes > 0
            and not local_media
            and not encrypted_media
        )
        if object_hits > 0:
            state = "artifact_recovered"
            confidence = "HIGH"
            summary = "Exportable object or image artifacts were recovered from passive evidence."
        elif local_media:
            state = "media_path_confirmed"
            confidence = "HIGH" if rtsp_conf >= 40 or http_conf >= 50 else "MEDIUM"
            summary = "A local media path is visible through RTSP, ONVIF, or strong HTTP evidence."
        elif encrypted_media:
            state = "possible_encrypted_media"
            confidence = "MEDIUM"
            summary = "Traffic shape suggests media may be present, but only encrypted application evidence is visible."
        elif telemetry_like:
            state = "background_telemetry"
            confidence = "MEDIUM"
            summary = "Observed traffic looks like background telemetry rather than a confirmed media session."
        else:
            state = "no_session"
            confidence = "LOW"
            summary = "No credible media session is currently visible in passive evidence."
        return {
            "state": state,
            "confidence": confidence,
            "summary": summary,
            "transport": (
                "local"
                if local_media and not cloud_endpoints
                else ("cloud" if cloud_endpoints and not local_media else ("hybrid" if local_media and cloud_endpoints else "unknown"))
            ),
            "protocols": sorted(protocols),
            "metrics": {
                "http_confidence": round(http_conf, 1),
                "rtsp_confidence": round(rtsp_conf, 1),
                "tls_confidence": round(tls_conf, 1),
                "quic_confidence": round(quic_conf, 1),
                "mdns_dns_confidence": round(mdns_dns_conf, 1),
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "uplink_ratio": round(uplink_ratio, 2),
                "long_lived_flow": long_lived,
                "eapol_frame_count": int(auth_evidence.get("eapol_frame_count") or 0),
                "object_hits": object_hits,
            },
        }

    def _scenario_delta(
        self,
        item: Dict[str, Any],
        services: Dict[str, Any],
        behavior: Dict[str, Any],
        stream_state: Dict[str, Any],
    ) -> Dict[str, Any]:
        current_state = str(stream_state.get("state") or "no_session")
        scenario_history = dict(item.get("scenario_history") or {})
        current_mode = str(scenario_history.get("current_scenario") or self.DEFAULT_SCENARIO)
        current_observation = self._scenario_observation_from_item(
            {
                **item,
                "service_exposure": services,
                "stream_state": stream_state,
            }
        )
        idle_view = self._scenario_view("idle", current_mode, current_observation, scenario_history)
        live_view = self._scenario_view("live_view", current_mode, current_observation, scenario_history)
        motion_view = self._scenario_view("motion", current_mode, current_observation, scenario_history)
        passive_view = self._scenario_view(self.DEFAULT_SCENARIO, current_mode, current_observation, scenario_history)
        app_open_view = self._scenario_view("app_open", current_mode, current_observation, scenario_history)

        live_baseline_name = "idle" if idle_view else self.DEFAULT_SCENARIO
        live_baseline_view = idle_view or passive_view
        idle_vs_live = self._compare_scenarios(live_baseline_name, live_baseline_view, "live_view", live_view)
        motion_vs_idle = self._compare_scenarios("idle", idle_view or passive_view, "motion", motion_view)
        app_open_delta = self._compare_scenarios(self.DEFAULT_SCENARIO, passive_view, "app_open", app_open_view)
        supports_comparison = len(list(scenario_history.get("available_scenarios") or [])) >= 2

        if current_state == "artifact_recovered":
            next_step = "Verify whether the recovered artifact appears only during live-view or event-driven scenarios."
        elif idle_vs_live.get("status") == "STRONGER_TARGET":
            next_step = "Re-run idle and live-view captures back to back to confirm the media-path transition."
        elif motion_vs_idle.get("status") == "STRONGER_TARGET":
            next_step = "Trigger motion again and preserve the highest-byte slices for artifact extraction."
        elif current_state == "possible_encrypted_media":
            next_step = "Capture the same device during app live view and compare encrypted session growth, continuity, and EAPOL evidence."
        elif current_state == "background_telemetry":
            next_step = "Trigger a known live-view or motion event and look for a transition from telemetry to sustained media."
        else:
            next_step = "Start controlled scenario captures for idle, app open, live view, and motion to build a real delta model."
        return {
            "supports_comparison": supports_comparison,
            "current_mode": current_mode,
            "current_mode_label": self._scenario_label(current_mode),
            "available_scenarios": list(scenario_history.get("available_scenarios") or []),
            "idle_vs_live_view": idle_vs_live.get("status") or "UNKNOWN",
            "motion_vs_idle": motion_vs_idle.get("status") or "UNKNOWN",
            "app_open_delta": app_open_delta.get("status") or "UNKNOWN",
            "summary": (
                f"Current evidence is {current_state.replace('_', ' ')} under {self._scenario_label(current_mode)}. "
                f"{idle_vs_live.get('summary') or ''}".strip()
            ),
            "next_step": next_step,
            "observed_behavior": behavior.get("summary") or str(item.get("traffic_pattern") or "unknown"),
            "cloud_endpoints": list(services.get("cloud_endpoints") or [])[:4],
            "comparisons": {
                "idle_vs_live_view": idle_vs_live,
                "motion_vs_idle": motion_vs_idle,
                "app_open_delta": app_open_delta,
            },
        }

    def _camera_confirmation(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        camera: Dict[str, Any],
        stream_state: Dict[str, Any],
        scenario_delta: Dict[str, Any],
    ) -> Dict[str, Any]:
        protocols = set(services.get("protocols") or [])
        protocol_conf = dict(services.get("protocol_confidence") or {})
        identity_reasons: List[str] = []
        service_reasons: List[str] = []
        behavior_reasons: List[str] = []
        artifact_reasons: List[str] = []
        blockers: List[str] = []
        historical_identity_hints = [
            str(item.get("historical_identity_hint") or "").strip().lower(),
            *[str(value).strip().lower() for value in (item.get("related_identity_hints") or []) if str(value).strip()],
        ]
        historical_camera_identity = any(
            any(token in hint for token in ("camera", "chuangmi", "miap", "ipcam"))
            for hint in historical_identity_hints
        )

        family_match = str(camera.get("family_match") or "")
        classification = str(camera.get("classification") or "")
        vendor_state = str(camera.get("vendor_role_state") or "")
        stream_transport = str(stream_state.get("transport") or "unknown")
        object_hits = int(stream_state.get("metrics", {}).get("object_hits") or 0)
        rtsp_conf = float(protocol_conf.get("RTSP") or 0.0)
        http_conf = float(protocol_conf.get("HTTP") or 0.0)
        tls_conf = float(protocol_conf.get("TLS") or 0.0)
        local_protocols = [label for label, present in (("RTSP", "RTSP" in protocols or rtsp_conf >= 20), ("ONVIF", "ONVIF" in protocols), ("HTTP", "HTTP" in protocols or http_conf >= 35)) if present]
        cloud_protocols = [label for label, present in (("TLS", "TLS" in protocols or tls_conf >= 20), ("QUIC", "QUIC" in protocols)) if present]
        idle_vs_live = dict((scenario_delta.get("comparisons") or {}).get("idle_vs_live_view") or {})
        motion_vs_idle = dict((scenario_delta.get("comparisons") or {}).get("motion_vs_idle") or {})
        app_open_delta = dict((scenario_delta.get("comparisons") or {}).get("app_open_delta") or {})
        stream_state_name = str(stream_state.get("state") or "no_session")
        has_live_delta = str(idle_vs_live.get("status") or "") in {"STRONGER_TARGET", "HIGHER_PAYLOAD"}
        has_motion_delta = str(motion_vs_idle.get("status") or "") in {"STRONGER_TARGET", "HIGHER_PAYLOAD"}
        has_app_delta = str(app_open_delta.get("status") or "") in {"STRONGER_TARGET", "HIGHER_PAYLOAD"}
        transport_path = "local" if local_protocols and not cloud_protocols else ("cloud" if cloud_protocols and not local_protocols else ("hybrid" if local_protocols and cloud_protocols else stream_transport))

        if family_match:
            identity_reasons.append(f"family match {family_match}")
        if historical_camera_identity:
            identity_reasons.append("historical camera identity")
        if bool(item.get("wps_primary_device_camera")):
            identity_reasons.append("WPS camera type")
        if str(fingerprint.get("device_type") or "").lower().find("camera") >= 0:
            identity_reasons.append(f"fingerprint {fingerprint.get('device_type')}")
        if local_protocols:
            service_reasons.append(f"local media protocols {', '.join(local_protocols)}")
        if transport_path in {"cloud", "hybrid"} and list(services.get("cloud_endpoints") or []):
            service_reasons.append("camera cloud endpoints retained")
        if stream_state_name in {"media_path_confirmed", "artifact_recovered"}:
            behavior_reasons.append(stream_state.get("summary") or "media path retained")
        if has_live_delta:
            behavior_reasons.append("idle vs live-view delta retained")
        if has_motion_delta:
            behavior_reasons.append("motion vs idle delta retained")
        if has_app_delta:
            behavior_reasons.append("app-open delta retained")
        if object_hits > 0:
            artifact_reasons.append(f"{object_hits} recovered object or image artifacts")

        identity_score = 30 if identity_reasons else 0
        service_score = 35 if service_reasons else 0
        behavior_score = 20 if behavior_reasons else 0
        artifact_score = 15 if artifact_reasons else 0
        confidence_score = identity_score + service_score + behavior_score + artifact_score

        if not identity_reasons:
            blockers.append("no camera-specific identity evidence")
        if not service_reasons:
            blockers.append("no RTSP/ONVIF/HTTP or cloud media-path evidence")
        if not behavior_reasons:
            blockers.append("no retained scenario delta proving camera behavior")
        if not artifact_reasons:
            blockers.append("no exported object or image artifact")

        if artifact_reasons:
            level = "artifact_confirmed"
            summary = "Artifact-confirmed camera evidence retained."
            sensor_verdict = "artifact_confirmed_cmos_device"
        elif identity_reasons and service_reasons and behavior_reasons:
            level = "confirmed"
            summary = "Camera confirmation is supported by identity, media-path, and scenario behavior evidence."
            sensor_verdict = "confirmed_imaging_capable_device"
        elif identity_reasons and service_reasons:
            level = "likely"
            summary = "Camera confirmation is likely: camera identity aligns with a visible media path."
            sensor_verdict = "likely_cmos_capable_device"
        elif identity_reasons:
            level = "possible"
            summary = "Camera evidence is still identity-led; protocol or scenario proof is missing."
            sensor_verdict = "possible_cmos_capable_device"
        else:
            level = "unconfirmed"
            summary = "The lead is not camera-confirmed yet."
            sensor_verdict = "unconfirmed_sensor_use"

        if transport_path == "local" and not local_protocols:
            transport_path = "unknown"
        next_step = (
            "Preserve artifact-producing slices and validate recovered images manually."
            if level == "artifact_confirmed"
            else (
                "Repeat idle and live-view runs against this same lead; a stable live-view delta is the fastest confirmation path."
                if local_protocols and not has_live_delta
                else (
                    "Focus on RTSP/ONVIF/HTTP discovery first, then rerun live-view and motion scenario captures."
                    if transport_path in {"local", "hybrid"}
                    else "Use tagged idle, app-open, and live-view runs to separate cloud telemetry from true camera sessions."
                )
            )
        )
        return {
            "level": level,
            "summary": summary,
            "transport_path": transport_path,
            "sensor_verdict": sensor_verdict,
            "confidence_score": min(100, confidence_score),
            "identity_reasons": identity_reasons[:4],
            "service_reasons": service_reasons[:4],
            "behavior_reasons": behavior_reasons[:4],
            "artifact_reasons": artifact_reasons[:4],
            "local_protocols": local_protocols,
            "cloud_protocols": cloud_protocols,
            "blockers": blockers[:4],
            "next_step": next_step,
            "vendor_role_state": vendor_state,
            "camera_classification": classification,
        }

    def _video_evidence(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        services: Dict[str, Any],
        behavior: Dict[str, Any],
        stream_state: Dict[str, Any],
        scenario_delta: Dict[str, Any],
        camera_confirmation: Dict[str, Any],
    ) -> Dict[str, Any]:
        protocols = set(services.get("protocols") or [])
        protocol_conf = dict(services.get("protocol_confidence") or {})
        historical_identity_hints = [
            str(item.get("historical_identity_hint") or "").strip().lower(),
            *[str(value).strip().lower() for value in (item.get("related_identity_hints") or []) if str(value).strip()],
        ]
        historical_camera_identity = any(
            any(token in hint for token in ("camera", "chuangmi", "miap", "ipcam"))
            for hint in historical_identity_hints
        )
        local_stream_available = bool(
            "RTSP" in protocols
            or "ONVIF" in protocols
            or float(protocol_conf.get("RTSP") or 0.0) >= 20.0
            or float(protocol_conf.get("HTTP") or 0.0) >= 35.0
        )
        explicit_cloud_stream_detected = bool(
            list(services.get("cloud_endpoints") or [])
            and (
                "TLS" in protocols
                or "QUIC" in protocols
                or float(protocol_conf.get("TLS") or 0.0) >= 20.0
                or float(protocol_conf.get("QUIC") or 0.0) >= 20.0
            )
        )
        current_observation = self._scenario_observation_from_item(
            {
                **item,
                "service_exposure": services,
                "stream_state": stream_state,
            }
        )
        scenario_history = dict(item.get("scenario_history") or {})
        current_mode = str(scenario_history.get("current_scenario") or self.DEFAULT_SCENARIO)
        idle_view = self._scenario_view("idle", current_mode, current_observation, scenario_history)
        app_open_view = self._scenario_view("app_open", current_mode, current_observation, scenario_history)
        live_view = self._scenario_view("live_view", current_mode, current_observation, scenario_history)
        passive_view = self._scenario_view(self.DEFAULT_SCENARIO, current_mode, current_observation, scenario_history)
        baseline_view = idle_view or passive_view or app_open_view or current_observation
        live_target_view = live_view or (current_observation if current_mode == "live_view" else None)

        baseline_bytes = int((baseline_view or {}).get("bytes") or 0)
        live_bytes = int((live_target_view or {}).get("bytes") or 0)
        baseline_packets = int((baseline_view or {}).get("packets") or 0)
        live_packets = int((live_target_view or {}).get("packets") or 0)
        baseline_rate = float((baseline_view or {}).get("packet_rate_pps") or 0.0)
        live_rate = float((live_target_view or {}).get("packet_rate_pps") or 0.0)
        live_duration = float((live_target_view or {}).get("duration_seconds") or 0.0)
        baseline_endpoints = set((baseline_view or {}).get("endpoints") or [])
        live_endpoints = set((live_target_view or {}).get("endpoints") or [])
        new_endpoints = sorted(live_endpoints - baseline_endpoints)
        idle_vs_live = dict((scenario_delta.get("comparisons") or {}).get("idle_vs_live_view") or {})
        app_open_delta = dict((scenario_delta.get("comparisons") or {}).get("app_open_delta") or {})
        live_delta_status = str(idle_vs_live.get("status") or "")
        app_delta_status = str(app_open_delta.get("status") or "")

        sustained_flow = bool(
            live_duration >= 20.0
            or bool((stream_state.get("metrics") or {}).get("long_lived_flow"))
        )
        stream_like = bool(
            live_bytes >= max(524288, baseline_bytes * 2)
            or live_packets >= max(48, baseline_packets * 2)
            or live_rate >= max(8.0, baseline_rate * 1.8)
            or live_delta_status in {"STRONGER_TARGET", "HIGHER_PAYLOAD"}
        )
        history_backed_live_uplift = bool(
            historical_camera_identity
            and live_target_view is not None
            and (
                live_bytes >= max(8192, baseline_bytes * 4)
                or live_packets >= max(40, baseline_packets * 4)
                or live_rate >= max(1.5, baseline_rate * 4)
            )
        )
        inferred_cloud_stream = bool(
            not local_stream_available
            and not explicit_cloud_stream_detected
            and historical_camera_identity
            and stream_like
            and sustained_flow
            and history_backed_live_uplift
        )
        cloud_stream_detected = bool(explicit_cloud_stream_detected or inferred_cloud_stream)
        flow_triggered = bool(
            stream_like
            and live_target_view is not None
            and (
                current_mode == "live_view"
                or live_delta_status in {"STRONGER_TARGET", "HIGHER_PAYLOAD"}
                or app_delta_status in {"STRONGER_TARGET", "HIGHER_PAYLOAD"}
                or history_backed_live_uplift
            )
        )
        correlation_confidence = 0.0
        if flow_triggered:
            correlation_confidence += 0.45
        if sustained_flow:
            correlation_confidence += 0.2
        if new_endpoints:
            correlation_confidence += 0.15
        if cloud_stream_detected:
            correlation_confidence += 0.1
        if inferred_cloud_stream:
            correlation_confidence += 0.1
        if str(item.get("traffic_pattern") or "") == "steady-stream":
            correlation_confidence += 0.1
        correlation_confidence = min(1.0, round(correlation_confidence, 2))

        camera_level = str(camera_confirmation.get("level") or "unconfirmed")
        winner_role = str((item.get("role_duel") or {}).get("winner_role") or "")
        if local_stream_available and cloud_stream_detected:
            video_device_class = "HYBRID_STREAM_DEVICE"
        elif local_stream_available and int(item.get("client_count") or 0) >= 2 and winner_role == "nvr":
            video_device_class = "RECORDER_SYSTEM"
        elif local_stream_available:
            video_device_class = "LOCAL_STREAM_DEVICE"
        elif cloud_stream_detected and (flow_triggered or camera_level in {"confirmed", "likely", "artifact_confirmed"}):
            video_device_class = "CLOUD_STREAM_DEVICE"
        elif camera_level in {"confirmed", "likely", "possible"} or str(fingerprint.get("device_family") or "") == "camera":
            video_device_class = "EMBEDDED_CAMERA_DEVICE"
        else:
            video_device_class = "NON_VIDEO_DEVICE"

        if local_stream_available and cloud_stream_detected:
            evidence_type = "hybrid"
        elif local_stream_available:
            evidence_type = "protocol"
        elif flow_triggered or cloud_stream_detected:
            evidence_type = "behavioral"
        else:
            evidence_type = "partial"

        if video_device_class == "NON_VIDEO_DEVICE":
            video_capable = "not_confirmed"
        elif local_stream_available or (cloud_stream_detected and flow_triggered):
            video_capable = "confirmed"
        else:
            video_capable = "inconclusive"

        artifact_possible = bool(local_stream_available)
        if "RTSP" in protocols or float(protocol_conf.get("RTSP") or 0.0) >= 20.0:
            artifact_reason = "RTSP available"
        elif float(protocol_conf.get("HTTP") or 0.0) >= 35.0 or "HTTP" in protocols:
            artifact_reason = "HTTP snapshot candidate"
        elif inferred_cloud_stream:
            artifact_reason = "behavioral live-view proof only"
        elif cloud_stream_detected:
            artifact_reason = "cloud encrypted transport"
        else:
            artifact_reason = "no justified artifact path"

        traffic_profile = {
            "baseline_scenario": self._scenario_label("idle" if idle_view else (self.DEFAULT_SCENARIO if passive_view else current_mode)),
            "live_scenario": self._scenario_label("live_view" if live_view else current_mode),
            "baseline_bytes": baseline_bytes,
            "live_bytes": live_bytes,
            "baseline_packets": baseline_packets,
            "live_packets": live_packets,
            "baseline_packet_rate_pps": round(baseline_rate, 2),
            "live_packet_rate_pps": round(live_rate, 2),
            "delta_bytes": max(0, live_bytes - baseline_bytes),
            "delta_packets": max(0, live_packets - baseline_packets),
            "duration_seconds": round(live_duration, 2),
            "sustained_flow": sustained_flow,
            "bandwidth_classification": (
                "stream_like"
                if stream_like and sustained_flow
                else ("medium" if stream_like else ("low" if live_bytes > 0 else "none"))
            ),
            "endpoint_count": len(live_endpoints),
            "new_endpoints": new_endpoints[:6],
            "endpoints": sorted(live_endpoints)[:8],
        }

        summary_parts = []
        if local_stream_available:
            summary_parts.append("Local stream evidence retained")
        if explicit_cloud_stream_detected:
            summary_parts.append("Cloud stream path detected")
        elif inferred_cloud_stream:
            summary_parts.append("Cloud-like live-view behavior inferred from retained history and traffic uplift")
        if flow_triggered:
            summary_parts.append("Live-view action correlates with device-side flow growth")
        if not artifact_possible and cloud_stream_detected:
            summary_parts.append("Visual artifact not locally recoverable")

        cloud_endpoint_names = sorted(
            {
                *[str(value).strip() for value in (services.get("cloud_endpoints") or []) if str(value).strip()],
                *[str(value).strip() for value in (item.get("tls_server_names") or []) if str(value).strip()],
                *[str(value).strip() for value in (item.get("quic_server_names") or []) if str(value).strip()],
                *[str(value).strip() for value in (item.get("dns_query_names") or []) if str(value).strip()],
                *[str(value).strip() for value in (item.get("related_domains") or []) if str(value).strip()],
            }
        )[:12]
        plaintext_http_hosts = sorted({str(value).strip() for value in (item.get("http_hosts") or []) if str(value).strip()})[:8]
        plaintext_http_uris = sorted({str(value).strip() for value in (item.get("http_uris") or []) if str(value).strip()})[:8]
        cloud_metadata_observed = bool(cloud_endpoint_names or explicit_cloud_stream_detected or cloud_stream_detected)
        plaintext_http_observed = bool(plaintext_http_hosts or plaintext_http_uris)
        if not cloud_metadata_observed:
            cloud_risk = "NONE"
            leakage_verdict = "no_cloud_camera_leakage_observed"
        elif plaintext_http_observed and (cloud_stream_detected or cloud_endpoint_names):
            cloud_risk = "HIGH"
            leakage_verdict = "possible_plaintext_cloud_metadata_or_api_leakage"
        elif cloud_stream_detected and flow_triggered:
            cloud_risk = "MEDIUM"
            leakage_verdict = "live_view_correlated_cloud_egress_observed"
        elif cloud_endpoint_names:
            cloud_risk = "LOW"
            leakage_verdict = "encrypted_cloud_metadata_observed"
        else:
            cloud_risk = "UNKNOWN"
            leakage_verdict = "cloud_behavior_inconclusive"
        cloud_leakage_audit = {
            "status": "observed" if cloud_metadata_observed else "not_observed",
            "risk_level": cloud_risk,
            "leakage_verdict": leakage_verdict,
            "cloud_endpoints": cloud_endpoint_names[:8],
            "new_live_view_endpoints": new_endpoints[:6],
            "dns_names": list(item.get("dns_query_names") or [])[:8],
            "tls_sni": list(item.get("tls_server_names") or [])[:8],
            "quic_sni": list(item.get("quic_server_names") or [])[:8],
            "http_hosts": plaintext_http_hosts,
            "http_uris": plaintext_http_uris,
            "metadata_exposed": cloud_metadata_observed,
            "content_exposed": False,
            "content_exposure_basis": "No decrypted video/image content was recovered from cloud transport." if cloud_metadata_observed else "No cloud media path observed.",
            "privacy_exposure": [
                value
                for value in [
                    "DNS/SNI cloud endpoint metadata" if cloud_endpoint_names else "",
                    "traffic timing and volume correlation" if cloud_stream_detected or flow_triggered else "",
                    "plaintext HTTP host/path metadata" if plaintext_http_observed else "",
                    "new endpoints during live-view scenario" if new_endpoints else "",
                ]
                if value
            ],
            "operator_next_steps": [
                "Run tagged idle, app-open, and live-view captures against the same lead.",
                "Review DNS/SNI/QUIC endpoint artifacts and compare against the owner-approved vendor region.",
                "Use firewall egress logs or a controlled gateway to validate whether cloud endpoints are expected.",
            ],
        }

        return {
            "video_capable": video_capable,
            "video_device_class": video_device_class,
            "evidence_type": evidence_type,
            "local_stream_available": "yes" if local_stream_available else "no",
            "cloud_stream_detected": "yes" if cloud_stream_detected else "no",
            "artifact_possible": "yes" if artifact_possible else "no",
            "artifact_reason": artifact_reason,
            "traffic_profile": traffic_profile,
            "correlation": {
                "flow_triggered_by_live_view": flow_triggered,
                "correlation_confidence": correlation_confidence,
                "timing_status": live_delta_status or "UNKNOWN",
                "app_open_status": app_delta_status or "UNKNOWN",
                "historical_camera_identity": historical_camera_identity,
                "inferred_cloud_stream": inferred_cloud_stream,
                "summary": (
                    "live view action triggered flow from this device"
                    if flow_triggered
                    else "device-side live-view correlation not yet proven"
                ),
            },
            "cloud_leakage_audit": cloud_leakage_audit,
            "summary": " · ".join(summary_parts) if summary_parts else "Video capability not confirmed by retained evidence.",
        }

    def _anomaly_profile(self, item: Dict[str, Any], fingerprint: Dict[str, Any], services: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[str] = []
        if int(item.get("historical_captures") or 0) <= 1:
            findings.append("Newly observed device")
        if int(item.get("packet_count") or 0) >= 80 and str(item.get("traffic_pattern") or "") in {"steady-stream", "broadcast-heavy"}:
            findings.append("High traffic spike")
        if len(item.get("associated_bssids") or []) >= 3:
            findings.append("Multi-AP roaming behavior")
        if bool(item.get("hidden_ssid")):
            findings.append("Hidden SSID activity")
        if "UPnP service exposure" in (services.get("exposures") or []):
            findings.append("Broadcast service exposure")
        if "Cloud endpoints identified" in (services.get("exposures") or []):
            findings.append("Cloud communication observed")
        return {
            "findings": findings[:6],
            "has_anomaly": bool(findings),
            "summary": findings[0] if findings else "No strong anomaly detected",
        }

    def _risk_profile(
        self,
        item: Dict[str, Any],
        fingerprint: Dict[str, Any],
        camera: Dict[str, Any],
        target_score: Dict[str, Any],
        services: Dict[str, Any],
        anomalies: Dict[str, Any],
    ) -> Dict[str, Any]:
        reasons: List[str] = []
        score = float(target_score.get("score") or 0.0)

        exposures = list(services.get("exposures") or [])
        if exposures:
            score += min(12, len(exposures) * 3)
            reasons.extend(exposures[:2])
        if camera.get("detected"):
            score += 8
            reasons.append("surveillance-capable profile")
        if int(item.get("historical_captures") or 0) <= 1:
            score += 4
            reasons.append("new observation")
        if str(item.get("vendor") or "").strip() in {"", "--", "Unknown"}:
            score += 4
            reasons.append("unknown vendor")
        vendor_country = str(item.get("vendor_country") or "").lower()
        if vendor_country in HIGH_RISK_IMPORT_COUNTRIES:
            score += 6
            reasons.append("high-risk import geography")
        reasons.extend((anomalies.get("findings") or [])[:2])

        risk_score = min(100, int(round(score)))
        if risk_score >= 85:
            risk = "HIGH"
        elif risk_score >= 65:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        return {
            "risk": risk,
            "risk_score": risk_score,
            "exposure_score": min(100, len(exposures) * 18 + (18 if "open" in str(item.get("security") or "").lower() else 0)),
            "behavior_score": min(100, int(round(float(target_score.get("confidence") or 0.0) * 100))),
            "confidence_level": self._confidence_tier(float(target_score.get("confidence") or 0.0)),
            "reasons": reasons[:6],
            "summary": " · ".join(reasons[:3]) if reasons else "baseline passive risk profile",
        }

    def _fingerprint_network(self, item: Dict[str, Any]) -> Dict[str, Any]:
        ssid = str(item.get("ssid") or "").lower()
        vendor = str(item.get("vendor") or "").lower()
        security = str(item.get("security") or "")
        packet_count = int(item.get("packet_count") or 0)
        client_count = int(item.get("client_count") or 0)
        rssi = float(item.get("rssi_dbm") or -95)
        history_captures = int(item.get("historical_captures") or 0)
        history_days = int(item.get("historical_days_seen") or 0)
        wps_text = self._identity_text(item)
        traffic_pattern = str(item.get("traffic_pattern") or "mixed")
        mobility_class = str(item.get("mobility_class") or "static")
        beacon_count = int(item.get("beacon_count") or 0)
        probe_response_count = int(item.get("probe_response_count") or 0)
        wps_camera = bool(item.get("wps_primary_device_camera"))
        reasons: List[str] = []

        device_type = "WiFi Network"
        confidence = 0.45
        role = "AP" if beacon_count > 0 or probe_response_count > 0 or not item.get("synthetic_identity") else "Observed"

        family = "Unknown"
        identity_profile = self._identity_profile(item, network_role=True)
        vendor_family = str(identity_profile.get("vendor_family") or "")
        product_category = str(identity_profile.get("product_category") or "")

        if wps_camera or self._contains_any(wps_text, CAMERA_HINTS):
            device_type = "WiFi Camera"
            family = "camera"
            confidence = 0.93 if wps_camera else 0.82
            reasons.append("WPS camera identity or camera-specific model string")
        elif self._contains_strict_camera_vendor(vendor) or self._contains_any(ssid, CAMERA_HINTS):
            device_type = "WiFi Camera"
            family = "camera"
            confidence = 0.78 if self._contains_strict_camera_vendor(vendor) else 0.68
            reasons.append("camera vendor or SSID signature")
        elif self._contains_conditional_camera_vendor(vendor) and self._contains_any(wps_text, CAMERA_HINTS):
            device_type = "WiFi Camera"
            family = "camera"
            confidence = 0.72
            reasons.append("conditional vendor with camera-specific identity")
        elif self._contains_any(ssid, ONBOARDING_HINTS) or self._contains_any(wps_text, ONBOARDING_HINTS):
            device_type = "IoT Onboarding"
            family = "onboarding"
            confidence = 0.83
            reasons.append("setup or provisioning SSID pattern")
        elif self._contains_any(ssid, VACUUM_HINTS) or self._contains_any(wps_text, VACUUM_HINTS):
            device_type = "Robot Vacuum"
            family = "vacuum"
            confidence = 0.86
            reasons.append("vacuum device signature")
        elif self._contains_any(ssid, ISP_ROUTER_HINTS):
            device_type = "ISP Router / CPE"
            family = "isp-cpe"
            confidence = 0.88 if client_count >= 1 else 0.8
            reasons.append("ISP router / CPE naming pattern")
        elif self._contains_any(ssid, EXTENDER_HINTS):
            device_type = "Mesh / Extender"
            family = "extender"
            confidence = 0.76
            reasons.append("mesh or extender naming pattern")
        elif self._contains_any(ssid, ROUTER_HINTS) or client_count >= 2:
            device_type = "Router / AP"
            family = "router"
            confidence = 0.84 if client_count >= 2 else 0.72
            reasons.append("infrastructure naming or attached clients")
        elif self._contains_any(ssid, HUB_HINTS):
            device_type = "IoT Hub"
            family = "iot-hub"
            confidence = 0.78
            reasons.append("hub or gateway SSID pattern")
        elif self._contains_any(ssid, PRINTER_HINTS):
            device_type = "Printer"
            family = "printer"
            confidence = 0.75
            reasons.append("printer naming pattern")
        elif self._contains_any(ssid, TV_HINTS):
            device_type = "Smart TV"
            family = "tv-media"
            confidence = 0.7
            reasons.append("TV/streaming naming pattern")

        if product_category == "doorbell_camera":
            device_type = "Video Doorbell"
            family = "camera"
            confidence = max(confidence, 0.88)
            reasons.append("doorbell camera identity profile")
        elif product_category == "baby_monitor":
            device_type = "Baby Monitor"
            family = "camera"
            confidence = max(confidence, 0.84)
            reasons.append("baby monitor identity profile")
        elif product_category == "pet_camera":
            device_type = "Pet Camera"
            family = "camera"
            confidence = max(confidence, 0.82)
            reasons.append("pet camera identity profile")
        elif product_category == "mesh_extender" and family not in {"camera", "router"}:
            device_type = "Mesh / Extender"
            family = "extender"
            confidence = max(confidence, 0.78)
            reasons.append("mesh/extender identity profile")
        elif product_category == "router_ap" and family not in {"camera", "extender"}:
            device_type = "Router / AP"
            family = "router"
            confidence = max(confidence, 0.8)
            reasons.append("router/ap identity profile")
        elif product_category == "printer":
            device_type = "Printer"
            family = "printer"
            confidence = max(confidence, 0.74)
            reasons.append("printer identity profile")
        elif product_category == "tv_media":
            device_type = "Smart TV"
            family = "tv-media"
            confidence = max(confidence, 0.72)
            reasons.append("TV/media identity profile")

        if item.get("wps_model_name") or item.get("wps_device_name") or item.get("wps_model_number"):
            confidence = min(0.98, confidence + 0.08)
            reasons.append("WPS model/device identity present")
        if traffic_pattern == "broadcast-heavy" and role == "AP":
            confidence = min(0.98, confidence + 0.04)
            reasons.append("infrastructure broadcast pattern")
        if mobility_class == "static" and rssi >= -60:
            reasons.append("stable location profile")
        if history_captures >= 3 or history_days >= 2:
            confidence = min(0.98, confidence + 0.05)
            reasons.append("persistent observation across captures")
        if item.get("he_capable") or item.get("vht_capable"):
            reasons.append("modern 802.11 capability advertisement")

        behavior = []
        if packet_count >= 40:
            behavior.append("high packet rate")
        if client_count >= 3:
            behavior.append("multiple attached clients")
        if "open" in security.lower():
            behavior.append("open security posture")
        if rssi >= -55:
            behavior.append("close proximity")

        final_confidence = round(min(0.98, confidence + (0.04 if packet_count >= 40 else 0.0)), 2)
        return {
            "role": role,
            "device_type": device_type,
            "device_family": family,
            "vendor_family": vendor_family,
            "product_category": product_category or family,
            "confidence": final_confidence,
            "confidence_tier": self._confidence_tier(final_confidence),
            "behavior_profile": ", ".join(behavior) if behavior else "limited passive fingerprint",
            "identity_profile": identity_profile,
            "reasons": reasons or ["passive WiFi infrastructure observation"],
        }

    def _fingerprint_client(self, item: Dict[str, Any]) -> Dict[str, Any]:
        vendor = str(item.get("vendor") or "").lower()
        joined_ssids = " ".join(item.get("last_ssids") or []).lower()
        packet_count = int(item.get("packet_count") or 0)
        probe_count = int(item.get("probe_request_count") or 0)
        assoc_count = int(item.get("association_count") or 0)
        history_captures = int(item.get("historical_captures") or 0)
        history_days = int(item.get("historical_days_seen") or 0)
        avg_frame_len = float(item.get("avg_frame_len") or 0.0)
        associated_bssids = len(item.get("associated_bssids") or [])
        wps_text = self._identity_text(item)
        traffic_pattern = str(item.get("traffic_pattern") or "mixed")
        mobility_class = str(item.get("mobility_class") or "static")
        reasons: List[str] = []

        device_type = "Client Device"
        confidence = 0.45
        role = "Client"

        family = "client"
        identity_profile = self._identity_profile(item, network_role=False)
        vendor_family = str(identity_profile.get("vendor_family") or "")
        product_category = str(identity_profile.get("product_category") or "")

        if bool(item.get("wps_primary_device_camera")) or self._contains_any(wps_text, CAMERA_HINTS):
            device_type = "WiFi Camera"
            family = "camera"
            confidence = 0.94 if bool(item.get("wps_primary_device_camera")) else 0.84
            reasons.append("WPS camera device typing")
        elif self._contains_strict_camera_vendor(vendor) or self._contains_any(joined_ssids, CAMERA_HINTS):
            device_type = "WiFi Camera"
            family = "camera"
            confidence = 0.8 if self._contains_strict_camera_vendor(vendor) else 0.69
            reasons.append("camera vendor or SSID behavior")
        elif self._contains_conditional_camera_vendor(vendor) and self._contains_any(wps_text, CAMERA_HINTS):
            device_type = "WiFi Camera"
            family = "camera"
            confidence = 0.74
            reasons.append("conditional vendor with camera-specific identity")
        elif self._contains_any(joined_ssids, VACUUM_HINTS) or self._contains_any(wps_text, VACUUM_HINTS):
            device_type = "Robot Vacuum"
            family = "vacuum"
            confidence = 0.88
            reasons.append("vacuum device signature")
        elif self._contains_any(joined_ssids, ONBOARDING_HINTS):
            device_type = "IoT Onboarding"
            family = "onboarding"
            confidence = 0.78
            reasons.append("setup or provisioning SSID behavior")
        elif self._contains_any(joined_ssids, TV_HINTS):
            device_type = "Smart TV"
            family = "tv-media"
            confidence = 0.76
            reasons.append("streaming/media naming pattern")
        elif self._contains_any(joined_ssids, HUB_HINTS):
            device_type = "IoT Hub"
            family = "iot-hub"
            confidence = 0.74
            reasons.append("gateway or hub naming pattern")
        elif self._contains_any(joined_ssids, PRINTER_HINTS):
            device_type = "Printer"
            family = "printer"
            confidence = 0.72
            reasons.append("printer naming pattern")
        elif self._contains_any(vendor, PHONE_VENDORS) and probe_count >= 2:
            device_type = "Phone"
            family = "phone"
            confidence = 0.68
            reasons.append("mobile vendor with active probing")

        if product_category == "doorbell_camera":
            device_type = "Video Doorbell"
            family = "camera"
            confidence = max(confidence, 0.88)
            reasons.append("doorbell camera identity profile")
        elif product_category == "baby_monitor":
            device_type = "Baby Monitor"
            family = "camera"
            confidence = max(confidence, 0.84)
            reasons.append("baby monitor identity profile")
        elif product_category == "pet_camera":
            device_type = "Pet Camera"
            family = "camera"
            confidence = max(confidence, 0.82)
            reasons.append("pet camera identity profile")
        elif product_category == "vacuum":
            device_type = "Robot Vacuum"
            family = "vacuum"
            confidence = max(confidence, 0.86)
            reasons.append("vacuum identity profile")
        elif product_category == "printer":
            device_type = "Printer"
            family = "printer"
            confidence = max(confidence, 0.74)
            reasons.append("printer identity profile")
        elif product_category == "tv_media":
            device_type = "Smart TV"
            family = "tv-media"
            confidence = max(confidence, 0.74)
            reasons.append("TV/media identity profile")
        elif product_category == "phone":
            device_type = "Phone"
            family = "phone"
            confidence = max(confidence, 0.7)
            reasons.append("phone identity profile")

        if item.get("wps_model_name") or item.get("wps_device_name") or item.get("wps_model_number"):
            confidence = min(0.98, confidence + 0.08)
            reasons.append("WPS model/device identity present")
        if mobility_class == "high-mobility" and probe_count >= 2 and device_type == "Client Device":
            device_type = "Phone"
            confidence = max(confidence, 0.66)
            reasons.append("high RSSI variance with active probing")
        if traffic_pattern == "periodic" and device_type == "Client Device":
            device_type = "IoT Sensor"
            family = "iot-sensor"
            confidence = max(confidence, 0.64)
            reasons.append("periodic endpoint behavior")
        if traffic_pattern == "steady-stream" and mobility_class == "static" and probe_count == 0 and associated_bssids <= 1:
            if device_type == "Client Device":
                device_type = "WiFi Camera"
                family = "camera"
                confidence = max(confidence, 0.72)
            reasons.append("static steady-stream endpoint profile")
        if avg_frame_len >= 700 and traffic_pattern == "steady-stream":
            confidence = min(0.98, confidence + 0.05)
            reasons.append("large-frame streaming profile")
        if history_captures >= 3 or history_days >= 2:
            confidence = min(0.98, confidence + 0.05)
            reasons.append("persistent observation across captures")
        if len(item.get("dhcp_hostnames") or []) > 0:
            reasons.append("hostname metadata present")

        behavior = []
        if packet_count >= 12 and probe_count == 0:
            behavior.append("steady client traffic")
        if probe_count >= 3:
            behavior.append("bursty probe activity")
        if assoc_count > 0:
            behavior.append("explicit association behavior")
        if mobility_class != "static":
            behavior.append(mobility_class)
        if not behavior:
            behavior.append("limited passive endpoint fingerprint")

        final_confidence = round(min(0.98, confidence + (0.06 if assoc_count > 0 else 0.0)), 2)
        return {
            "role": role,
            "device_type": device_type,
            "device_family": family,
            "vendor_family": vendor_family,
            "product_category": product_category or family,
            "confidence": final_confidence,
            "confidence_tier": self._confidence_tier(final_confidence),
            "behavior_profile": ", ".join(behavior),
            "identity_profile": identity_profile,
            "reasons": reasons or ["passive WiFi endpoint observation"],
        }

    def _identity_profile(self, item: Dict[str, Any], *, network_role: bool) -> Dict[str, Any]:
        identity_blob = self._identity_text(item, include_vendor=True)
        vendor_family = ""
        vendor_terms: List[str] = []
        for family_name, terms in self.VENDOR_FAMILY_HINTS.items():
            matched = [term for term in terms if term in identity_blob]
            if matched:
                vendor_family = family_name
                vendor_terms = matched[:4]
                break

        product_category = ""
        category_terms: List[str] = []
        for category_name, terms in self.PRODUCT_CATEGORY_HINTS.items():
            matched = [term for term in terms if term in identity_blob]
            if matched:
                product_category = category_name
                category_terms = matched[:4]
                break

        confidence = 0.0
        if vendor_family:
            confidence += 0.35
        if product_category:
            confidence += 0.35
        if str(item.get("wps_model_name") or "").strip() or str(item.get("wps_device_name") or "").strip():
            confidence += 0.15
        if str(item.get("historical_identity_hint") or "").strip():
            confidence += 0.1
        if list(item.get("related_identity_hints") or []):
            confidence += 0.05

        normalized_category = product_category
        if not normalized_category and vendor_family in {
            "xiaomi_mi_imilab_mijia",
            "tplink_tapo_kasa",
            "hikvision_ezviz",
            "dahua_imou",
            "google_nest",
            "amazon_ring_blink",
            "anker_eufy",
            "arlo",
            "wyze",
        }:
            normalized_category = "camera" if not network_role else ""

        return {
            "vendor_family": vendor_family,
            "product_category": normalized_category,
            "vendor_terms": vendor_terms,
            "category_terms": category_terms,
            "confidence": round(min(0.95, confidence), 2),
            "confidence_tier": self._confidence_tier(min(0.95, confidence) if confidence > 0 else 0.0),
        }

    def _camera_detection(self, item: Dict[str, Any], fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        return self.camera_engine.score(item, fingerprint)

    def _target_score(self, item: Dict[str, Any], fingerprint: Dict[str, Any], camera: Dict[str, Any]) -> Dict[str, Any]:
        device_type = str(camera.get("device_type") or fingerprint.get("device_type") or "WiFi Device")
        security = str(item.get("security") or "")
        pmf = str(item.get("pmf") or "").lower()
        hidden = bool(item.get("hidden_ssid"))
        rssi = float(item.get("rssi_dbm") or -95)
        packet_count = int(item.get("packet_count") or 0)
        confidence = float(camera.get("confidence") or fingerprint.get("confidence") or 0.0)
        traffic_pattern = str(item.get("traffic_pattern") or "mixed")
        activity_span = float(item.get("activity_span_seconds") or 0.0)
        history_captures = int(item.get("historical_captures") or 0)
        history_days = int(item.get("historical_days_seen") or 0)
        reasons: List[str] = []
        role = str((fingerprint or {}).get("role") or "")
        client_count = int(item.get("client_count") or 0)
        exposure_score = 0
        device_value_score = 0
        proximity_score = 0
        behavior_score = 0
        persistence_score = 0
        noise_penalty = 0

        if "open" in security.lower():
            exposure_score += 50
            reasons.append("open network")
        elif "wpa2" in security.lower():
            exposure_score += 15
            reasons.append("WPA2 exposure")
        elif "wpa3" in security.lower():
            exposure_score += 4
        if hidden:
            exposure_score += 5
            reasons.append("hidden SSID")
        if pmf not in {"true", "1"}:
            exposure_score += 8
            reasons.append("no PMF")
        exposure_score = min(50, exposure_score)

        if device_type == "WiFi Camera":
            device_value_score = 40
            reasons.append("camera value")
        elif device_type in {"Router / AP", "ISP Router / CPE"}:
            device_value_score = 25
            reasons.append("router value")
        elif device_type in {"IoT Hub", "IoT Onboarding", "IoT Sensor"}:
            device_value_score = 20
            reasons.append("IoT value")
        else:
            device_value_score = 10
            reasons.append("unknown/general device value")

        if rssi >= -55:
            proximity_score = 25
            reasons.append("strong proximity")
        elif rssi >= -70:
            proximity_score = 15
            reasons.append("usable proximity")
        else:
            proximity_score = 5
            reasons.append("weak proximity")

        if traffic_pattern == "steady-stream":
            behavior_score = 25
            reasons.append("constant stream")
        elif traffic_pattern == "periodic":
            behavior_score = 10
            reasons.append("periodic behavior")
        else:
            behavior_score = 5
            reasons.append("mixed behavior")
        if confidence >= 0.8:
            behavior_score = min(25, behavior_score + 5)
            reasons.append("strong behavior confidence")

        if activity_span >= 1200 or history_days >= 2 or history_captures >= 10:
            persistence_score = 20
            reasons.append("seen over 20 minutes / persistent history")
        elif activity_span >= 300 or history_captures >= 3:
            persistence_score = 10
            reasons.append("seen over 5 minutes")

        if rssi < -80:
            noise_penalty -= 15
            reasons.append("weak RSSI noise penalty")
        if int(item.get("beacon_count") or 0) >= 12 and packet_count <= int(item.get("beacon_count") or 0) + int(item.get("probe_response_count") or 0) and client_count == 0:
            noise_penalty -= 20
            reasons.append("broadcast-only penalty")
        if bool(item.get("synthetic_identity")):
            noise_penalty -= 10
            reasons.append("unresolved identity penalty")

        score = exposure_score + device_value_score + proximity_score + behavior_score + persistence_score + noise_penalty

        return {
            "score": max(0, min(100, int(round(score)))),
            "priority": self._priority_tier(score),
            "device_type": device_type,
            "confidence": round(confidence, 2),
            "confidence_tier": self._confidence_tier(confidence),
            "reasons": reasons,
            "components": {
                "exposure": exposure_score,
                "device_value": device_value_score,
                "proximity": proximity_score,
                "behavior_confidence": behavior_score,
                "persistence": persistence_score,
                "noise_penalty": noise_penalty,
            },
        }

    @staticmethod
    def _contains_any(text: str, hints: tuple[str, ...]) -> bool:
        haystack = str(text or "").lower()
        return any(hint in haystack for hint in hints)

    @classmethod
    def _contains_strict_camera_vendor(cls, text: str) -> bool:
        return cls._contains_any(text, cls.STRICT_CAMERA_VENDOR_HINTS)

    @classmethod
    def _contains_conditional_camera_vendor(cls, text: str) -> bool:
        return cls._contains_any(text, cls.CONDITIONAL_CAMERA_VENDOR_HINTS)

    @staticmethod
    def _identity_text(item: Dict[str, Any], include_vendor: bool = True) -> str:
        parts = [
            str(item.get("ssid") or ""),
            " ".join(item.get("last_ssids") or []),
            str(item.get("wps_manufacturer") or ""),
            str(item.get("wps_model_name") or ""),
            str(item.get("wps_model_number") or ""),
            str(item.get("wps_device_name") or ""),
            " ".join(item.get("dhcp_hostnames") or []),
        ]
        if include_vendor:
            parts.append(str(item.get("vendor") or ""))
        return " ".join(filter(None, parts)).lower()

    @staticmethod
    def _flow_summary(item: Dict[str, Any]) -> Dict[str, Any]:
        flow = dict(item.get("flow_metrics") or {})
        return {
            "uplink_ratio": round(float(flow.get("uplink_ratio") or 0.0), 3),
            "packet_rate_pps": round(float(flow.get("packet_rate_pps") or 0.0), 3),
            "duration_seconds": round(float(flow.get("duration_seconds") or 0.0), 3),
            "constant_bitrate": bool(flow.get("constant_bitrate")),
            "long_lived_flow": bool(flow.get("long_lived_flow")),
            "bitrate_variance": round(float(flow.get("bitrate_variance") or 0.0), 3),
        }

    @staticmethod
    def _confidence_tier(confidence: float) -> str:
        if confidence >= 0.8:
            return "HIGH"
        if confidence >= 0.55:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _priority_tier(score: float) -> str:
        if score >= PRIORITY_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        if score >= PRIORITY_THRESHOLDS["HIGH"]:
            return "HIGH"
        if score >= PRIORITY_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        return "LOW"
