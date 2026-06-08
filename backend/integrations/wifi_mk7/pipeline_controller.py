from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from backend.intel.identity.mac_oui_resolver import MacOUIResolver
from backend.integrations.wifi_mk7.airodump_collector import AirodumpCollector
from backend.integrations.wifi_mk7.bettercap_collector import BettercapCollector
from backend.integrations.wifi_mk7.camera_signature_database import NEGATIVE_VENDOR_BIAS
from backend.integrations.wifi_mk7.kismet_collector import KismetCollector


CAMERA_KEYWORDS = (
    "camera",
    "cam",
    "ipc",
    "ipcam",
    "onvif",
    "rtsp",
    "hikvision",
    "ezviz",
    "reolink",
    "imou",
    "dahua",
    "arlo",
    "ring",
    "nest",
    "tapo",
    "tuya",
    "netatmo",
    "xiaomi",
    "mijia",
    "imilab",
    "miiot",
    "mi home",
    "miio",
    "chuangmi",
    "zhen shi",
)

CLOUD_CAMERA_FAMILY_TOKENS = (
    "xiaomi",
    "mijia",
    "imilab",
    "chuangmi",
    "miio",
    "miiot",
    "zhen shi",
    "tuya",
    "tapo",
    "ezviz",
    "imou",
    "yi",
    "wyze",
    "ring",
    "arlo",
    "nest",
    "google_nest",
    "eufy",
    "wansview",
    "ajcloud",
    "hikvision",
    "dahua",
    "reolink",
)


class WiFiCameraPipelineController:
    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir
        self.oui = MacOUIResolver()
        self.tracker_history_path = self.root_dir / "logs" / "wifi_mk7" / "tracker_history.json"
        self.airodump = AirodumpCollector(root_dir)
        self.kismet = KismetCollector(root_dir)
        self.bettercap = BettercapCollector(root_dir)
        self.active = False
        self.started_at: float | None = None
        self.interfaces: List[str] = []
        self.bands: List[str] = []
        self.last_errors: List[str] = []
        self.last_snapshot: Dict[str, Any] = {}
        self.assignments: Dict[str, str] = {}
        self.mode = "inactive"
        self.current_phase = "idle"
        self.phase_plan: List[Dict[str, Any]] = []
        self.phase_state: Dict[str, Dict[str, Any]] = {}
        self.session_label = "WiFi Recon 4.0"
        self.airodump_write_interval_seconds = 1

    def start(
        self,
        interfaces: List[str],
        bands: List[str] | None = None,
        *,
        enabled_collectors: List[str] | None = None,
        airodump_write_interval_seconds: int = 1,
    ) -> Dict[str, Any]:
        self.stop()
        self.interfaces = [item for item in interfaces if item]
        self.bands = list(bands or [])
        self.started_at = time.time()
        self.last_errors = []
        self.assignments = {}
        self.mode = "parallel_collectors"
        self.current_phase = "collector_start"
        self.phase_plan = []
        self.phase_state = {}
        allowed = set(enabled_collectors or ["airodump-ng", "kismet", "bettercap"])
        spare = list(self.interfaces)
        results: Dict[str, Dict[str, Any]] = {}

        airodump_iface = spare.pop(0) if spare else ""
        if "airodump-ng" not in allowed:
            results["airodump"] = {"ok": False, "error": "Collector disabled by runtime resource policy"}
        elif airodump_iface:
            self.assignments["airodump-ng"] = airodump_iface
            results["airodump"] = self.airodump.start([airodump_iface], self.bands, write_interval_seconds=airodump_write_interval_seconds)
        else:
            results["airodump"] = {"ok": False, "error": "No dedicated spare interface available for airodump-ng"}

        kismet_iface = spare.pop(0) if spare else ""
        if "kismet" not in allowed:
            results["kismet"] = {"ok": False, "error": "Collector disabled by runtime resource policy"}
        elif kismet_iface:
            self.assignments["kismet"] = kismet_iface
            results["kismet"] = self.kismet.start([kismet_iface])
        else:
            results["kismet"] = {"ok": False, "error": "No dedicated spare interface available for kismet"}

        bettercap_iface = spare.pop(0) if spare else ""
        if "bettercap" not in allowed:
            results["bettercap"] = {"ok": False, "error": "Collector disabled by runtime resource policy"}
        elif bettercap_iface:
            self.assignments["bettercap"] = bettercap_iface
            results["bettercap"] = self.bettercap.start(bettercap_iface)
        else:
            results["bettercap"] = {"ok": False, "error": "No dedicated spare interface available for bettercap"}

        for result in results.values():
            if not result.get("ok") and result.get("error"):
                self.last_errors.append(str(result.get("error")))
        self.active = any(result.get("ok") for result in results.values())
        self.current_phase = "idle" if not self.active else "external_collection"
        return {"active": self.active, "results": results, "errors": self.last_errors}

    def begin_single_adapter_session(
        self,
        interface: str,
        bands: List[str] | None,
        total_duration: int,
        *,
        enabled_collectors: List[str] | None = None,
        airodump_write_interval_seconds: int = 1,
    ) -> Dict[str, Any]:
        return self._begin_staged_session(
            interface,
            bands,
            total_duration,
            session_label="Camera Hunt 2.0",
            enabled_collectors=enabled_collectors,
            airodump_write_interval_seconds=airodump_write_interval_seconds,
        )

    def begin_single_adapter_recon(
        self,
        interface: str,
        bands: List[str] | None,
        total_duration: int,
        *,
        enabled_collectors: List[str] | None = None,
        airodump_write_interval_seconds: int = 1,
    ) -> Dict[str, Any]:
        return self._begin_staged_session(
            interface,
            bands,
            total_duration,
            session_label="WiFi Recon 4.0",
            enabled_collectors=enabled_collectors,
            airodump_write_interval_seconds=airodump_write_interval_seconds,
        )

    def _begin_staged_session(
        self,
        interface: str,
        bands: List[str] | None,
        total_duration: int,
        session_label: str,
        *,
        enabled_collectors: List[str] | None = None,
        airodump_write_interval_seconds: int = 1,
    ) -> Dict[str, Any]:
        self.stop()
        self.interfaces = [interface] if interface else []
        self.bands = list(bands or [])
        self.started_at = time.time()
        self.last_errors = []
        self.assignments = {}
        self.mode = "single_adapter_phased"
        self.session_label = session_label
        self.airodump_write_interval_seconds = max(1, int(airodump_write_interval_seconds or 1))
        self.current_phase = "planning"
        self.phase_state = {}
        allowed = set(enabled_collectors or ["airodump-ng", "kismet", "bettercap"])
        total_seconds = max(60, int(total_duration or 60))
        kismet_allowed = "kismet" in allowed
        bettercap_allowed = "bettercap" in allowed
        rf_seconds = min(45, max(10, int(total_seconds * 0.15)))
        kismet_seconds = min(35, max(6, int(total_seconds * 0.1))) if kismet_allowed else 0
        bettercap_seconds = min(25, max(5, int(total_seconds * 0.08))) if bettercap_allowed else 0
        packet_seconds = total_seconds - rf_seconds - kismet_seconds - bettercap_seconds
        if packet_seconds < 20:
            overflow = 20 - packet_seconds
            reduce_by = min(bettercap_seconds, overflow)
            bettercap_seconds -= reduce_by
            overflow -= reduce_by
            reduce_by = min(kismet_seconds, overflow)
            kismet_seconds -= reduce_by
            overflow -= reduce_by
            reduce_by = min(max(0, rf_seconds - 5), overflow)
            rf_seconds -= reduce_by
            packet_seconds = total_seconds - rf_seconds - kismet_seconds - bettercap_seconds
        self.phase_plan = [{"name": "airodump-ng", "seconds": rf_seconds, "role": "RF discovery"}]
        self.phase_plan.append({"name": "dumpcap/tshark", "seconds": max(20, packet_seconds), "role": "core packet truth"})
        if kismet_allowed and kismet_seconds > 0:
            self.phase_plan.append({"name": "kismet", "seconds": kismet_seconds, "role": "device intelligence"})
        if bettercap_allowed and bettercap_seconds > 0:
            self.phase_plan.append({"name": "bettercap", "seconds": bettercap_seconds, "role": "live recon events"})
        self.phase_state = {
            phase["name"]: {
                "planned_seconds": int(phase["seconds"]),
                "elapsed_seconds": 0,
                "percent": 0,
                "status": "pending",
                "role": phase["role"],
            }
            for phase in self.phase_plan
        }
        self.assignments = {
            "core_capture": interface,
            "airodump-ng": interface,
            "kismet": interface,
            "bettercap": interface,
        }
        self.active = True
        self.current_phase = "airodump-ng"
        self._mark_phase_status("airodump-ng", "active")
        return {"active": True, "mode": self.mode, "phase_plan": self.phase_plan, "interface": interface}

    def run_single_adapter_phase(self, name: str) -> Dict[str, Any]:
        phase = next((item for item in self.phase_plan if item.get("name") == name), None)
        if not phase or not self.interfaces:
            return {"ok": False, "error": f"Phase {name} unavailable"}
        seconds = int(phase.get("seconds") or 0)
        interface = self.interfaces[0]
        self.current_phase = name
        self._mark_phase_status(name, "active")
        if name == "airodump-ng":
            result = self._run_collector_for_duration(self.airodump, [interface], self.bands, seconds)
            self._mark_phase_complete(name, seconds, result.get("ok", False))
            return result
        if name == "kismet":
            result = self._run_collector_for_duration(self.kismet, [interface], self.bands, seconds)
            self._mark_phase_complete(name, seconds, result.get("ok", False))
            return result
        if name == "bettercap":
            result = self._run_collector_for_duration(self.bettercap, [interface], self.bands, seconds)
            self._mark_phase_complete(name, seconds, result.get("ok", False))
            return result
        return {"ok": False, "error": f"Unsupported phase {name}"}

    def complete_single_adapter_session(self) -> None:
        self.current_phase = "idle"
        self.active = False

    def stop(self) -> None:
        self.airodump.stop()
        self.kismet.stop()
        self.bettercap.stop()
        self.active = False
        self.current_phase = "idle"

    def clear(self) -> None:
        self.stop()
        self.airodump.clear()
        self.kismet.clear()
        self.bettercap.clear()
        self.started_at = None
        self.interfaces = []
        self.bands = []
        self.last_errors = []
        self.last_snapshot = {}
        self.assignments = {}
        self.mode = "inactive"
        self.phase_plan = []
        self.phase_state = {}

    def status(self) -> Dict[str, Any]:
        collectors = [self.airodump.status(), self.kismet.status(), self.bettercap.status()]
        active_names = [collector["name"] for collector in collectors if collector.get("active")]
        available_names = [collector["name"] for collector in collectors if collector.get("available")]
        return {
            "active": any(collector.get("active") for collector in collectors),
            "started_at": self.started_at,
            "interfaces": self.interfaces,
            "assignments": self.assignments,
            "bands": self.bands,
            "mode": self.mode,
            "current_phase": self.current_phase,
            "phase_plan": self.phase_plan,
            "phase_state": self.phase_state,
            "session_label": self.session_label,
            "collectors": collectors,
            "active_collectors": active_names,
            "available_collectors": available_names,
            "errors": self.last_errors,
            "summary": (
                f"{self.session_label} uses a phased single-adapter pipeline on the MK7AC: "
                "airodump-ng -> dumpcap/tshark -> kismet -> bettercap."
                if self.mode == "single_adapter_phased"
                else
                f"Camera Hunt 2.0 runs dumpcap/tshark plus Zeek enrichment on dedicated core interfaces and additive collectors on spare interfaces: "
                f"{', '.join(f'{name}={iface}' for name, iface in self.assignments.items()) if self.assignments else 'no spare interfaces for external collectors'}."
            ),
        }

    def _run_collector_for_duration(self, collector: Any, interfaces: List[str], bands: List[str], seconds: int) -> Dict[str, Any]:
        if collector is self.airodump:
            start = collector.start(interfaces, bands, write_interval_seconds=getattr(self, "airodump_write_interval_seconds", 1))
        elif collector is self.kismet:
            start = collector.start(interfaces)
        else:
            start = collector.start(interfaces[0] if interfaces else "")
        if not start.get("ok"):
            if start.get("error"):
                self.last_errors.append(str(start.get("error")))
            return start
        phase_name = str(collector.status().get("name") or "")
        total_seconds = max(1, int(seconds))
        started_at = time.time()
        while True:
          elapsed = min(total_seconds, int(time.time() - started_at))
          if phase_name:
              state = self.phase_state.setdefault(
                  phase_name,
                  {
                      "planned_seconds": total_seconds,
                      "elapsed_seconds": 0,
                      "percent": 0,
                      "status": "pending",
                      "role": "",
                  },
              )
              state["elapsed_seconds"] = elapsed
              state["percent"] = round((elapsed / max(1, total_seconds)) * 100, 1)
              state["status"] = "active" if elapsed < total_seconds else "completed"
              self.phase_state[phase_name] = state
          if elapsed >= total_seconds:
              break
          time.sleep(1)
        collector.stop()
        return {"ok": True, "phase": collector.status().get("name"), "seconds": seconds}

    def mark_core_capture_phase(self, active: bool, elapsed_seconds: float = 0.0) -> None:
        state = self.phase_state.setdefault(
            "dumpcap/tshark",
            {"planned_seconds": 0, "elapsed_seconds": 0, "percent": 0, "status": "pending", "role": "core packet truth"},
        )
        planned = max(1, int(state.get("planned_seconds") or 1))
        elapsed = max(0, min(int(elapsed_seconds), planned))
        state["elapsed_seconds"] = elapsed
        state["percent"] = round((elapsed / planned) * 100, 1)
        state["status"] = "active" if active else ("completed" if elapsed >= planned else "pending")
        self.phase_state["dumpcap/tshark"] = state
        if active:
            self.current_phase = "dumpcap/tshark"

    def finish_core_capture_phase(self, elapsed_seconds: float) -> None:
        self.mark_core_capture_phase(False, elapsed_seconds)
        state = self.phase_state.get("dumpcap/tshark") or {}
        state["status"] = "completed"
        state["percent"] = 100.0
        self.phase_state["dumpcap/tshark"] = state

    def _mark_phase_status(self, name: str, status: str) -> None:
        state = self.phase_state.setdefault(
            name,
            {"planned_seconds": 0, "elapsed_seconds": 0, "percent": 0, "status": "pending", "role": ""},
        )
        state["status"] = status
        self.phase_state[name] = state

    def _mark_phase_complete(self, name: str, elapsed_seconds: int, ok: bool) -> None:
        state = self.phase_state.setdefault(
            name,
            {"planned_seconds": elapsed_seconds, "elapsed_seconds": 0, "percent": 0, "status": "pending", "role": ""},
        )
        planned = max(1, int(state.get("planned_seconds") or elapsed_seconds or 1))
        state["elapsed_seconds"] = int(elapsed_seconds)
        state["percent"] = 100.0 if ok else round((min(elapsed_seconds, planned) / planned) * 100, 1)
        state["status"] = "completed" if ok else "error"
        self.phase_state[name] = state

    def snapshot(self) -> Dict[str, Any]:
        snapshot = {
            "airodump": self.airodump.snapshot(),
            "kismet": self.kismet.snapshot(),
            "bettercap": self.bettercap.snapshot(),
        }
        self.last_snapshot = snapshot
        return snapshot

    def build_results(self, networks: List[Dict[str, Any]], clients: List[Dict[str, Any]]) -> Dict[str, Any]:
        snapshot = self.snapshot()
        airodump_aps = {str(item.get("bssid") or "").lower(): item for item in snapshot["airodump"].get("aps", []) if item.get("bssid")}
        airodump_clients = {str(item.get("mac") or "").lower(): item for item in snapshot["airodump"].get("stations", []) if item.get("mac")}
        kismet_devices = {str(item.get("mac") or "").lower(): item for item in snapshot["kismet"].get("devices", []) if item.get("mac")}
        bettercap_events: Dict[str, List[Dict[str, Any]]] = {}
        for event in snapshot["bettercap"].get("events", []):
            for mac in event.get("macs", []):
                bettercap_events.setdefault(mac, []).append(event)
        camera_client_context: Dict[str, Dict[str, Any]] = {}
        for client in clients or []:
            bssid = str(client.get("associated_bssid") or "").lower()
            if not bssid:
                continue
            bucket = camera_client_context.setdefault(bssid, {"count": 0, "families": set(), "scores": []})
            client_score = float(((client.get("camera_detection") or {}).get("score") or 0.0))
            client_family = str(((client.get("fingerprint") or {}).get("device_family") or "")).lower()
            if client_score >= 30.0 or client_family == "camera":
                bucket["count"] += 1
                if client_family:
                    bucket["families"].add(client_family)
                bucket["scores"].append(client_score)
        network_context: Dict[str, Dict[str, Any]] = {}
        for network in networks or []:
            bssid = str(network.get("bssid") or "").lower()
            if not bssid:
                continue
            network_context[bssid] = {
                "camera_score": float(((network.get("camera_detection") or {}).get("score") or 0.0)),
                "camera_mode": str(((network.get("camera_detection") or {}).get("detection_mode") or "")),
                "matched_families": list((network.get("camera_detection") or {}).get("matched_families") or []),
            }

        fused_all = []
        for network in networks or []:
            fused_lead = self._fuse_item(dict(network), "network", airodump_aps, airodump_clients, kismet_devices, bettercap_events, camera_client_context, network_context)
            if fused_lead:
                fused_all.append(fused_lead)
        for client in clients or []:
            fused_lead = self._fuse_item(dict(client), "client", airodump_aps, airodump_clients, kismet_devices, bettercap_events, camera_client_context, network_context)
            if fused_lead:
                fused_all.append(fused_lead)
        existing_client_macs = {
            str(item.get("mac") or "").lower()
            for item in fused_all
            if str(item.get("leadKind") or "").lower() == "client" and item.get("mac")
        }
        for supplemental in self._supplemental_airodump_clients(
            airodump_clients=airodump_clients,
            airodump_aps=airodump_aps,
            existing_client_macs=existing_client_macs,
        ):
            fused_lead = self._fuse_item(supplemental, "client", airodump_aps, airodump_clients, kismet_devices, bettercap_events, camera_client_context, network_context)
            if fused_lead:
                fused_all.append(fused_lead)
        existing_client_macs.update(
            str(item.get("mac") or "").lower()
            for item in fused_all
            if str(item.get("leadKind") or "").lower() == "client" and item.get("mac")
        )
        for supplemental in self._supplemental_neighbor_clients(existing_client_macs=existing_client_macs):
            fused_lead = self._fuse_item(supplemental, "client", airodump_aps, airodump_clients, kismet_devices, bettercap_events, camera_client_context, network_context)
            if fused_lead:
                fused_all.append(fused_lead)

        fused_all.sort(
            key=lambda item: (
                float(item.get("pipeline_score") or 0.0),
                float((item.get("camera_detection") or {}).get("score") or 0.0),
                float(item.get("rssi_dbm") or -999.0),
            ),
            reverse=True,
        )
        fused = [item for item in fused_all if bool((item.get("camera_detection") or {}).get("retained", False))]
        near_misses = [
            item for item in fused_all
            if not bool((item.get("camera_detection") or {}).get("retained", False))
            and self._allow_camera_near_miss(item)
            and float(item.get("pipeline_score") or 0.0) >= 25.0
        ][:12]
        possible_cloud_cameras = [
            item for item in fused_all
            if not bool((item.get("camera_detection") or {}).get("retained", False))
            and self._allow_possible_cloud_camera(item)
        ][:12]
        no_proof_count = sum(
            1
            for item in possible_cloud_cameras
            if str((item.get("cloud_camera_evidence") or {}).get("proof_status") or "") == "missing"
        )
        return {
            "count": len(fused),
            "leads": fused,
            "near_miss_count": len(near_misses),
            "near_misses": near_misses,
            "possible_cloud_camera_count": len(possible_cloud_cameras),
            "possible_cloud_cameras": possible_cloud_cameras,
            "evidence_buckets": {
                "confirmed_count": len(fused),
                "near_miss_count": len(near_misses),
                "possible_cloud_count": len(possible_cloud_cameras),
                "no_proof_count": no_proof_count,
            },
            "snapshot": snapshot,
            "pipeline": self.status(),
        }

    def _fuse_item(
        self,
        item: Dict[str, Any],
        lead_kind: str,
        airodump_aps: Dict[str, Dict[str, Any]],
        airodump_clients: Dict[str, Dict[str, Any]],
        kismet_devices: Dict[str, Dict[str, Any]],
        bettercap_events: Dict[str, List[Dict[str, Any]]],
        camera_client_context: Dict[str, Dict[str, Any]],
        network_context: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any] | None:
        mac = str(item.get("mac") or item.get("bssid") or "").lower()
        support_id = str(item.get("associated_bssid") or item.get("bssid") or "").lower()
        camera = dict(item.get("camera_detection") or {})
        role_duel = dict(item.get("role_duel") or {})
        score = float(camera.get("score") or 0.0)
        confidence_basis: List[str] = []
        sources: List[str] = ["dumpcap/tshark"]
        contributing_sources: List[str] = []
        evidence = list(camera.get("indicators") or [])
        suppression_reasons: List[str] = []
        vendor_text = str(item.get("vendor") or "").lower()
        traffic_pattern = str(item.get("traffic_pattern") or "").lower()
        flow = dict(item.get("flow_metrics") or {})
        service_exposure = dict(item.get("service_exposure") or {})
        protocol_confidence = dict(service_exposure.get("protocol_confidence") or {})
        service_inventory = list(service_exposure.get("service_inventory") or [])
        matched_families = list((camera.get("matched_families") or []))
        uplink_ratio = float(flow.get("uplink_ratio") or 0.0)
        long_lived_flow = bool(flow.get("long_lived_flow"))
        total_packets = int(flow.get("total_packets") or 0)
        correlation_context = {}
        if lead_kind == "network":
            correlation_context = camera_client_context.get(mac, {})
        else:
            correlation_context = network_context.get(support_id, {})

        airodump_match = airodump_clients.get(mac) if lead_kind == "client" else airodump_aps.get(mac)
        if airodump_match:
            sources.append("airodump-ng")
            if self._has_camera_keywords(" ".join(str(value) for value in airodump_match.values())):
                confidence_basis.append("RF scan")
                contributing_sources.append("airodump-ng")
                score += 12
                evidence.append("airodump signature match")

        kismet_match = kismet_devices.get(mac)
        if kismet_match:
            sources.append("kismet")
            kismet_text = " ".join(str(value) for value in kismet_match.values())
            if self._has_camera_keywords(kismet_text):
                confidence_basis.append("Kismet")
                contributing_sources.append("kismet")
                score += 15
                evidence.append("kismet camera identity")

        bettercap_match = bettercap_events.get(mac)
        if bettercap_match:
            sources.append("bettercap")
            if any(bool(event.get("camera_hint")) for event in bettercap_match):
                confidence_basis.append("Bettercap")
                contributing_sources.append("bettercap")
                score += 10
                evidence.append("bettercap camera event")

        identity_blob = " ".join(
            [
                str(item.get("ssid") or ""),
                " ".join(item.get("last_ssids") or []),
                str(item.get("historical_identity_hint") or ""),
                " ".join(item.get("related_identity_hints") or []),
                str(item.get("vendor") or ""),
                " ".join(str(event.get("message") or "") for event in (bettercap_match or [])),
            ]
        )
        if self._has_camera_keywords(identity_blob):
            confidence_basis.append("Identity")
            score += 14
            evidence.append("camera-oriented identity history")
        exposures = {str(value or "").strip().lower() for value in (service_exposure.get("exposures") or []) if str(value or "").strip()}
        if "local_neighbor_observed" in exposures and matched_families:
            confidence_basis.append("Neighbor")
            score += 6
            evidence.append("local neighbor table corroboration")

        if (item.get("service_exposure") or {}).get("summary"):
            summary = str((item.get("service_exposure") or {}).get("summary") or "").lower()
            if any(token in summary for token in ("rtsp", "onvif", "camera", "ipc", "cloud")):
                confidence_basis.append("Protocol")
                score += 12
                evidence.append("protocol summary match")
        if (item.get("tls_server_names") or []):
            confidence_basis.append("Cloud TLS")
            score += 10
            evidence.append("tls identity evidence")
        if item.get("wps_primary_device_camera"):
            confidence_basis.append("WPS Identity")
            score += 10
            evidence.append("wps camera type")

        if matched_families:
            confidence_basis.append("Signature DB")
            score += min(16.0, 6.0 + (len(matched_families) * 2.0))
            evidence.append("camera family signature match")
        if str(role_duel.get("winner_role") or "") == "camera":
            confidence_basis.append("Role Duel")
            score += min(10.0, max(0.0, float(role_duel.get("margin") or 0.0)))
            evidence.append("camera role won adversarial scoring")

        mdns_dns_conf = float(protocol_confidence.get("mDNS/DNS") or 0.0)
        http_conf = float(protocol_confidence.get("HTTP") or 0.0)
        tls_conf = float(protocol_confidence.get("TLS") or 0.0)
        rtsp_conf = float(protocol_confidence.get("RTSP") or 0.0)
        vendor_wps_conf = float(protocol_confidence.get("vendor/WPS") or 0.0)
        if mdns_dns_conf >= 25:
            confidence_basis.append("mDNS/DNS")
            score += min(10.0, mdns_dns_conf / 8.0)
            evidence.append("mdns/dns service evidence")
        if http_conf >= 20:
            confidence_basis.append("HTTP")
            score += min(8.0, http_conf / 10.0)
            evidence.append("http service evidence")
        if tls_conf >= 20 and "Cloud TLS" not in confidence_basis:
            confidence_basis.append("Cloud TLS")
            score += min(10.0, tls_conf / 8.0)
            evidence.append("tls cloud evidence")
        if rtsp_conf >= 20:
            confidence_basis.append("RTSP")
            score += min(14.0, rtsp_conf / 6.0)
            evidence.append("rtsp service evidence")
        if vendor_wps_conf >= 20 and "WPS Identity" not in confidence_basis:
            confidence_basis.append("Vendor/WPS")
            score += min(8.0, vendor_wps_conf / 10.0)
            evidence.append("vendor or wps evidence")

        for service in service_inventory:
            service_name = str((service or {}).get("service") or "").lower()
            detail = str((service or {}).get("detail") or "").lower()
            source = str((service or {}).get("source") or "").lower()
            if any(token in service_name for token in ("rtsp", "onvif", "vapix", "ipcamera")) or any(token in detail for token in ("rtsp", "onvif", "camera", "ipc")):
                confidence_basis.append("Service Inventory")
                score += 8
                evidence.append(f"service inventory {service_name or detail}")
                break
            if any(token in source for token in ("zeek", "tshark")) and any(token in detail for token in ("google", "nest", "ring", "arlo", "reolink", "hikvision", "ezviz", "imou", "tapo", "camera")):
                confidence_basis.append("Inventory Detail")
                score += 6
                evidence.append("inventory vendor detail")
                break

        if lead_kind == "client":
            if uplink_ratio >= 0.6 and long_lived_flow and total_packets >= 12:
                confidence_basis.append("Behavior")
                score += 10
                evidence.append("persistent upload-biased flow")
            if float(correlation_context.get("camera_score") or 0.0) >= 30.0:
                confidence_basis.append("AP Context")
                score += 8
                evidence.append("associated AP has camera-like evidence")
        else:
            correlated_clients = int(correlation_context.get("count") or 0)
            if correlated_clients > 0:
                confidence_basis.append("Client Correlation")
                score += min(12.0, 4.0 + (correlated_clients * 3.0))
                evidence.append(f"{correlated_clients} associated client(s) show camera-like behavior")

        has_protocol_basis = any(basis in confidence_basis for basis in ("Protocol", "Cloud TLS", "WPS Identity"))
        has_external_basis = bool(contributing_sources)
        has_behavior_basis = "Behavior" in confidence_basis
        winner_role = str(role_duel.get("winner_role") or "")
        role_margin = float(role_duel.get("margin") or 0.0)
        strong_camera_discriminator = bool(
            has_protocol_basis
            or matched_families
            or bool(item.get("wps_primary_device_camera"))
            or str(camera.get("vendor_role_state") or "") in {"vendor_family_plus_local_camera", "vendor_family_plus_cloud_camera"}
        )

        if any(bias in vendor_text for bias in NEGATIVE_VENDOR_BIAS) and not has_protocol_basis and not matched_families:
            score -= 12
            evidence.append("negative vendor suppression")
            suppression_reasons.append("negative vendor bias without protocol evidence")

        if lead_kind == "network" and not has_protocol_basis and not has_external_basis and not matched_families and vendor_wps_conf < 25:
            score -= 8
            evidence.append("network-only passive suppression")
            suppression_reasons.append("network lead without protocol or external corroboration")

        if lead_kind == "client" and not has_protocol_basis and not has_external_basis and not has_behavior_basis and not matched_families:
            score -= 8
            evidence.append("weak client passive suppression")
            suppression_reasons.append("client lead without protocol, behavior, or signature corroboration")

        if traffic_pattern not in {"steady-stream", "periodic"} and not has_protocol_basis and not matched_families:
            score -= 4
            suppression_reasons.append("traffic pattern not stream-like")
        if str(camera.get("vendor_role_state") or "") == "vendor_family_only":
            score = min(score, 39.0)
            suppression_reasons.append("vendor family only without camera discriminator")
        if str(camera.get("classification") or "") == "Unresolved device":
            score = min(score, 34.0)
            suppression_reasons.append("behavior-only unresolved device")
        if winner_role in {"router", "hub", "speaker"} and role_margin >= 8.0 and not strong_camera_discriminator:
            score = min(score, 18.0)
            evidence.append(f"{winner_role} role suppression")
            suppression_reasons.append(f"{winner_role} role outranks camera without camera discriminator")

        fused_label = camera.get("classification") or "Possible stream device"
        if not bool(camera.get("detected")) and str(camera.get("vendor_role_state") or "") == "vendor_family_only":
            fused_label = "Vendor-family device"
        elif str(camera.get("classification") or "") == "Unresolved device":
            fused_label = "Unresolved device"
        elif score >= 80:
            fused_label = "Confirmed camera"
        elif score >= 60:
            fused_label = "Likely camera"
        elif score >= 40:
            fused_label = "Possible stream device"
        elif score >= 25:
            fused_label = "Camera near miss"

        item["leadKind"] = lead_kind
        item["pipeline_score"] = round(min(100.0, score), 1)
        item["pipeline_sources"] = sorted(set(sources))
        item["pipeline_confidence_basis"] = sorted(set(confidence_basis)) or ["Passive"]
        item["pipeline_evidence"] = evidence[:8]
        item["pipeline_suppression_reasons"] = suppression_reasons[:6]
        retained = self._should_retain_camera_lead(
            lead_kind=lead_kind,
            score=score,
            camera=camera,
            item=item,
            role_duel=role_duel,
        )
        item["camera_detection"] = {
            **camera,
            "score": round(min(100.0, score), 1),
            "classification": fused_label,
            "ui_label": camera.get("ui_label") or ("likely_camera_cloud" if score >= 60 else "possible_stream_device"),
            "indicators": evidence[:8],
            "suppression_reasons": suppression_reasons[:6],
            "retained": retained,
        }
        item["cloud_camera_evidence"] = self._build_cloud_camera_evidence(item)
        return item

    @staticmethod
    def _should_retain_camera_lead(
        *,
        lead_kind: str,
        score: float,
        camera: Dict[str, Any],
        item: Dict[str, Any],
        role_duel: Dict[str, Any],
    ) -> bool:
        protocols = {str(value or "").strip().upper() for value in ((item.get("service_exposure") or {}).get("protocols") or []) if str(value or "").strip()}
        vendor_state = str(camera.get("vendor_role_state") or "")
        winner_role = str(role_duel.get("winner_role") or "")
        margin = float(role_duel.get("margin") or 0.0)
        family = str(camera.get("family_match") or camera.get("vendor_family") or "").strip()
        local_camera_discriminator = bool(
            family
            and (
                protocols.intersection({"RTSP", "ONVIF"})
                or vendor_state == "vendor_family_plus_local_camera"
                or bool(item.get("wps_primary_device_camera"))
            )
        )
        if lead_kind == "network" and winner_role in {"router", "hub", "speaker"} and margin >= 8.0 and not local_camera_discriminator:
            return False
        if bool(camera.get("detected")):
            return True
        if (
            lead_kind == "client"
            and score >= 40.0
            and winner_role in {"camera", "nvr"}
            and vendor_state in {"vendor_family_plus_cloud_camera", "vendor_family_plus_historical_camera_identity", "historical_camera_identity"}
            and family
        ):
            return True
        if (
            lead_kind == "client"
            and score >= 32.0
            and vendor_state == "vendor_family_plus_cloud_camera"
            and family
            and protocols.intersection({"TLS", "HTTP", "QUIC", "DNS", "MDNS", "MDNS/DNS", "SSDP"})
        ):
            return True
        if (
            lead_kind == "client"
            and score >= 28.0
            and vendor_state in {"vendor_family_plus_cloud_camera", "vendor_family_plus_historical_camera_identity", "historical_camera_identity"}
            and family
            and bool(str(item.get("associated_bssid") or "").strip())
            and protocols.intersection({"TLS", "HTTP", "QUIC", "DNS", "MDNS", "MDNS/DNS", "SSDP"})
        ):
            return True
        return False

    @staticmethod
    def _allow_camera_near_miss(item: Dict[str, Any]) -> bool:
        camera = dict(item.get("camera_detection") or {})
        role_duel = dict(item.get("role_duel") or {})
        winner_role = str(role_duel.get("winner_role") or "").lower()
        protocols = {str(value or "").strip().upper() for value in ((item.get("service_exposure") or {}).get("protocols") or [])}
        vendor_state = str(camera.get("vendor_role_state") or "")
        family = str(camera.get("family_match") or camera.get("vendor_family") or "").strip()
        lead_kind = str(item.get("leadKind") or ("client" if item.get("mac") else "network")).lower()
        local_or_media_protocol = bool(protocols.intersection({"RTSP", "ONVIF", "SSDP", "MDNS", "MDNS/DNS"}))
        cloud_or_identity_state = vendor_state in {
            "vendor_family_plus_local_camera",
            "vendor_family_plus_cloud_camera",
            "vendor_family_plus_historical_camera_identity",
            "historical_camera_identity",
        }
        explicit_camera_identity = bool(item.get("wps_primary_device_camera") or str(camera.get("family_match_confidence") or "").upper() == "HIGH")
        client_camera_context = bool(lead_kind == "client" and winner_role in {"camera", "nvr"} and family)
        has_camera_discriminator = bool(local_or_media_protocol or cloud_or_identity_state or explicit_camera_identity or client_camera_context)
        if winner_role in {"router", "hub", "speaker"} and not has_camera_discriminator:
            return False
        if str(camera.get("classification") or "").lower() in {"unresolved device", "vendor-family device"} and not has_camera_discriminator:
            return False
        return has_camera_discriminator

    @staticmethod
    def _allow_possible_cloud_camera(item: Dict[str, Any]) -> bool:
        evidence = dict(item.get("cloud_camera_evidence") or {})
        if evidence.get("bucket") != "possible_cloud_camera":
            return False
        role_duel = dict(item.get("role_duel") or {})
        winner_role = str(role_duel.get("winner_role") or "").lower()
        lead_kind = str(item.get("leadKind") or ("client" if item.get("mac") else "network")).lower()
        family = str((item.get("camera_detection") or {}).get("family_match") or (item.get("camera_detection") or {}).get("vendor_family") or "").strip()
        if lead_kind != "client":
            return False
        if not str(item.get("associated_bssid") or "").strip():
            return False
        if winner_role in {"router", "hub", "speaker", "access_point"}:
            return False
        return bool(family)

    @staticmethod
    def _build_cloud_camera_evidence(item: Dict[str, Any]) -> Dict[str, Any]:
        camera = dict(item.get("camera_detection") or {})
        service_exposure = dict(item.get("service_exposure") or {})
        active_fingerprint = dict(item.get("active_fingerprint") or {})
        active_summary = dict(active_fingerprint.get("summary") or {})
        role_duel = dict(item.get("role_duel") or {})
        lead_kind = str(item.get("leadKind") or ("client" if item.get("mac") else "network")).lower()
        protocols = sorted({str(value or "").strip().upper() for value in (service_exposure.get("protocols") or []) if str(value or "").strip()})
        family = str(camera.get("family_match") or camera.get("vendor_family") or "").strip()
        family_blob = " ".join(
            [
                family,
                " ".join(str(value or "") for value in (camera.get("matched_families") or [])),
                str(item.get("vendor") or ""),
                str(item.get("historical_identity_hint") or ""),
                " ".join(str(value or "") for value in (item.get("related_identity_hints") or [])),
            ]
        ).lower()
        known_cloud_family = any(token in family_blob for token in CLOUD_CAMERA_FAMILY_TOKENS)
        local_protocol = bool(set(protocols).intersection({"RTSP", "ONVIF"}))
        cloud_metadata = bool(
            set(protocols).intersection({"TLS", "QUIC", "DNS", "MDNS", "MDNS/DNS", "SSDP"})
            or service_exposure.get("cloud_endpoints")
            or item.get("tls_server_names")
            or item.get("quic_server_names")
            or item.get("dns_query_names")
        )
        retained = bool(camera.get("retained"))
        video_or_image_proof = bool(active_summary.get("video_or_image_proof"))
        service_positive = bool(active_summary.get("camera_positive") or local_protocol)
        if video_or_image_proof:
            proof_status = "visual_artifact"
        elif service_positive:
            proof_status = "service_hint"
        elif cloud_metadata:
            proof_status = "cloud_metadata"
        else:
            proof_status = "missing"

        winner_role = str(role_duel.get("winner_role") or "").lower()
        possible_cloud = bool(
            not retained
            and lead_kind == "client"
            and known_cloud_family
            and family
            and bool(str(item.get("associated_bssid") or "").strip())
            and winner_role not in {"router", "hub", "speaker", "access_point"}
        )
        if retained:
            bucket = "confirmed_camera"
        elif possible_cloud:
            bucket = "possible_cloud_camera"
        elif known_cloud_family:
            bucket = "cloud_camera_family_device"
        else:
            bucket = "not_camera"

        required_evidence = []
        if proof_status == "missing":
            required_evidence.extend(
                [
                    "gateway DNS/TLS-SNI/QUIC metadata during idle, app-open, and live-view stages",
                    "owner-assisted live-view traffic delta with packet and byte increase",
                    "local discovery proof from ONVIF, RTSP, SSDP, mDNS, miio/54321, or vendor LAN API where supported",
                    "visual artifact from RTSP frame capture or HTTP snapshot when a local path exists",
                ]
            )
        elif proof_status == "cloud_metadata":
            required_evidence.extend(
                [
                    "correlate cloud endpoint burst to owner-assisted live view",
                    "retain DNS/SNI/QUIC endpoint list and flow deltas as cloud-leakage evidence",
                    "attempt local visual artifact only if RTSP/ONVIF/HTTP snapshot appears",
                ]
            )
        elif proof_status == "service_hint":
            required_evidence.append("capture visual frame or image artifact before calling this proof-complete")

        return {
            "bucket": bucket,
            "cloud_camera_candidate": bucket == "possible_cloud_camera",
            "candidate_reason": (
                "Known cloud-camera vendor family seen as a WiFi client, but no video/image or cloud endpoint proof was retained."
                if bucket == "possible_cloud_camera" and proof_status == "missing"
                else "Camera evidence retained by primary detector."
                if retained
                else "No cloud-camera evidence bucket matched."
            ),
            "proof_status": proof_status,
            "proof_level": str(active_summary.get("proof_level") or ("NO_PROOF" if proof_status == "missing" else proof_status.upper())),
            "required_evidence": required_evidence[:6],
            "proof_blockers": (
                ["no visual artifact", "no local camera protocol", "no cloud endpoint metadata"]
                if proof_status == "missing"
                else []
            ),
            "safe_probe_plan": [
                "Run passive gateway capture first; do not assume the camera exposes local media services.",
                "Use owner-assisted idle -> app-open -> live-view stages to create a defensible traffic delta.",
                "Probe RTSP/ONVIF/HTTP snapshot paths only against validated private IP candidates.",
                "For Xiaomi-family devices, include miio UDP/54321 and Xiaomi cloud hostname review.",
                "For Tuya/AJCloud-style devices, retain DNS/SNI/QUIC evidence and review vendor cloud domains.",
            ],
            "operator_next_steps": [
                "Keep the device in Possible Cloud Camera until proof is retained.",
                "Ask the owner to open live view, then compare new endpoints, packet rate, and upload bytes against idle.",
                "If endpoints or visual proof remain absent, report as camera-family device without proof, not confirmed camera.",
            ],
            "audit_methods": [
                "ONVIF probe",
                "RTSP DESCRIBE/frame capture",
                "HTTP snapshot path probe",
                "mDNS/SSDP service discovery",
                "DNS query capture",
                "TLS SNI capture",
                "QUIC SNI capture",
                "JA3/JA4-style TLS handshake fingerprinting",
                "idle/app-open/live-view traffic delta",
                "vendor LAN API probe such as Xiaomi miio/54321 or Tuya local discovery",
            ],
            "target_ips": list(active_fingerprint.get("candidate_ips") or []),
            "source_context": {
                "lead_kind": lead_kind,
                "family": family,
                "vendor_role_state": str(camera.get("vendor_role_state") or ""),
                "protocols": protocols,
                "winner_role": winner_role,
            },
        }

    def _supplemental_airodump_clients(
        self,
        *,
        airodump_clients: Dict[str, Dict[str, Any]],
        airodump_aps: Dict[str, Dict[str, Any]],
        existing_client_macs: set[str],
    ) -> List[Dict[str, Any]]:
        tracker_history = self._load_tracker_history()
        clients_history = (tracker_history.get("clients") or {}) if isinstance(tracker_history, dict) else {}
        networks_history = (tracker_history.get("networks") or {}) if isinstance(tracker_history, dict) else {}
        supplemental: List[Dict[str, Any]] = []
        for mac, station in airodump_clients.items():
            if not mac or mac in existing_client_macs:
                continue
            station_text = " ".join(str(value or "") for value in station.values())
            vendor_profile = self.oui.resolve(mac)
            vendor = str(vendor_profile.get("vendor") or "")
            client_bucket = dict(clients_history.get(mac) or {})
            network_bucket = dict(networks_history.get(mac) or {})
            historical_identity_hint = str(network_bucket.get("last_device_type") or client_bucket.get("last_device_type") or "").strip()
            if historical_identity_hint.lower() in {"client", "<hidden>", "unknown"}:
                historical_identity_hint = ""
            identity_blob = " ".join([station_text, vendor, historical_identity_hint])
            if not self._has_camera_keywords(identity_blob):
                continue
            associated_bssid = str(station.get("bssid") or "").strip().lower()
            ap_context = airodump_aps.get(associated_bssid) or {}
            try:
                channel = int(str(ap_context.get("channel") or "").strip())
            except ValueError:
                channel = 0
            try:
                rssi = float(str(station.get("power") or "").strip())
            except ValueError:
                rssi = None
            try:
                packet_count = int(str(station.get("packets") or "").strip())
            except ValueError:
                packet_count = 0
            related_hints = [historical_identity_hint] if historical_identity_hint else []
            seed = self._supplemental_camera_seed(" ".join([identity_blob, associated_bssid]))
            supplemental.append(
                {
                    "mac": mac,
                    "vendor": vendor,
                    "vendor_country": vendor_profile.get("country"),
                    "vendor_country_code": vendor_profile.get("country_code"),
                    "vendor_country_source": vendor_profile.get("country_source"),
                    "associated_bssid": associated_bssid,
                    "last_ssids": [],
                    "packet_count": packet_count,
                    "probe_request_count": 0,
                    "association_count": 0,
                    "rssi_dbm": rssi,
                    "channel": channel,
                    "band": "2.4 GHz" if channel and channel <= 14 else ("5 GHz" if channel else ""),
                    "dhcp_hostnames": [],
                    "frame_type_counts": {"data": packet_count} if packet_count else {},
                    "frame_count_total": packet_count,
                    "frame_bytes_total": 0,
                    "avg_frame_len": 0.0,
                    "max_frame_len": 0,
                    "retry_count": 0,
                    "eapol_count": 0,
                    "handshake_captured": False,
                    "handshake_status": "Not Captured",
                    "qos_frame_count": 0,
                    "associated_bssids": [associated_bssid] if associated_bssid else [],
                    "rssi_samples": [rssi] if isinstance(rssi, (int, float)) else [],
                    "rssi_min_dbm": rssi,
                    "rssi_max_dbm": rssi,
                    "rssi_variance_db": 0.0,
                    "packet_timestamps": [],
                    "avg_interarrival_seconds": 0.0,
                    "activity_span_seconds": 0.0,
                    "flow_metrics": {},
                    "authentication_evidence_quality": "NONE",
                    "mobility_class": "static",
                    "traffic_pattern": "mixed",
                    "historical_captures": int(client_bucket.get("captures") or 0),
                    "historical_days_seen": int(client_bucket.get("days_seen") or 0),
                    "historical_first_seen": client_bucket.get("first_seen"),
                    "historical_last_seen": client_bucket.get("last_seen"),
                    "historical_identity_hint": historical_identity_hint,
                    "related_identity_hints": related_hints,
                    "service_exposure": {"protocols": [], "services": [], "exposures": [], "cloud_endpoints": [], "identity_hints": [], "service_inventory": [], "protocol_confidence": {}},
                    "camera_detection": seed["camera_detection"],
                    "fingerprint": {
                        "role": "Client",
                        "device_type": historical_identity_hint or seed["device_type"] or "Client Device",
                        "device_family": seed["device_family"],
                    },
                }
            )
        return supplemental

    def _supplemental_neighbor_clients(self, *, existing_client_macs: set[str]) -> List[Dict[str, Any]]:
        tracker_history = self._load_tracker_history()
        clients_history = (tracker_history.get("clients") or {}) if isinstance(tracker_history, dict) else {}
        networks_history = (tracker_history.get("networks") or {}) if isinstance(tracker_history, dict) else {}
        supplemental: List[Dict[str, Any]] = []
        for row in self._neighbor_table_rows():
            mac = str(row.get("mac") or "").strip().lower()
            ip_value = str(row.get("ip") or "").strip()
            if not mac or mac in existing_client_macs or not ip_value:
                continue
            vendor_profile = self.oui.resolve(mac)
            vendor = str(vendor_profile.get("vendor") or "")
            client_bucket = dict(clients_history.get(mac) or {})
            network_bucket = dict(networks_history.get(mac) or {})
            historical_identity_hint = str(network_bucket.get("last_device_type") or client_bucket.get("last_device_type") or "").strip()
            if historical_identity_hint.lower() in {"client", "<hidden>", "unknown"}:
                historical_identity_hint = ""
            identity_blob = " ".join([vendor, historical_identity_hint, ip_value])
            if not self._has_camera_keywords(identity_blob):
                continue
            related_hints = [historical_identity_hint] if historical_identity_hint else []
            seed = self._supplemental_camera_seed(identity_blob)
            supplemental.append(
                {
                    "mac": mac,
                    "vendor": vendor,
                    "vendor_country": vendor_profile.get("country"),
                    "vendor_country_code": vendor_profile.get("country_code"),
                    "vendor_country_source": vendor_profile.get("country_source"),
                    "ip_addresses": [ip_value],
                    "candidate_ip_addresses": [ip_value],
                    "last_ssids": [],
                    "packet_count": 0,
                    "probe_request_count": 0,
                    "association_count": 0,
                    "rssi_dbm": None,
                    "channel": 0,
                    "band": "",
                    "dhcp_hostnames": [],
                    "frame_type_counts": {},
                    "frame_count_total": 0,
                    "frame_bytes_total": 0,
                    "avg_frame_len": 0.0,
                    "max_frame_len": 0,
                    "retry_count": 0,
                    "eapol_count": 0,
                    "handshake_captured": False,
                    "handshake_status": "Not Captured",
                    "qos_frame_count": 0,
                    "associated_bssids": [],
                    "rssi_samples": [],
                    "rssi_min_dbm": None,
                    "rssi_max_dbm": None,
                    "rssi_variance_db": 0.0,
                    "packet_timestamps": [],
                    "avg_interarrival_seconds": 0.0,
                    "activity_span_seconds": 0.0,
                    "flow_metrics": {},
                    "authentication_evidence_quality": "NONE",
                    "mobility_class": "static",
                    "traffic_pattern": "mixed",
                    "historical_captures": int(client_bucket.get("captures") or 0),
                    "historical_days_seen": int(client_bucket.get("days_seen") or 0),
                    "historical_first_seen": client_bucket.get("first_seen"),
                    "historical_last_seen": client_bucket.get("last_seen"),
                    "historical_identity_hint": historical_identity_hint,
                    "related_identity_hints": related_hints,
                    "service_exposure": {
                        "protocols": ["ARP"],
                        "services": [],
                        "exposures": ["local_neighbor_observed"],
                        "cloud_endpoints": [],
                        "identity_hints": [f"neighbor_ip:{ip_value}"],
                        "service_inventory": [],
                        "protocol_confidence": {"ARP": 25},
                        "summary": f"Host neighbor table observed {mac} at {ip_value}",
                    },
                    "camera_detection": seed["camera_detection"],
                    "fingerprint": {
                        "role": "Client",
                        "device_type": historical_identity_hint or seed["device_type"] or "Client Device",
                        "device_family": seed["device_family"],
                    },
                }
            )
        return supplemental

    @staticmethod
    def _neighbor_table_rows() -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        arp_path = Path("/proc/net/arp")
        try:
            if arp_path.exists():
                for raw in arp_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                    parts = raw.split()
                    if len(parts) >= 4:
                        ip_value = str(parts[0]).strip()
                        mac_value = str(parts[3]).strip().lower()
                        if ip_value and mac_value:
                            rows.append({"ip": ip_value, "mac": mac_value, "source": "/proc/net/arp"})
        except Exception:
            return []
        return rows

    @staticmethod
    def _supplemental_camera_seed(identity_blob: str) -> Dict[str, Any]:
        lowered = str(identity_blob or "").lower()
        family = ""
        classification = "Unresolved device"
        device_type = "Client Device"
        device_family = "client"
        if any(token in lowered for token in ("xiaomi", "mijia", "imilab", "chuangmi", "miio", "miiot", "zhen shi")):
            family = "xiaomi_mi_imilab_mijia"
            classification = "Vendor-family device"
            device_type = "Xiaomi / Mijia Camera Family"
            device_family = "camera"
        elif any(token in lowered for token in ("tapo", "kasa", "tp-link")):
            family = "tp_link_tapo"
            classification = "Vendor-family device"
            device_type = "TP-Link / Tapo Camera Family"
            device_family = "camera"
        return {
            "device_type": device_type,
            "device_family": device_family,
            "camera_detection": {
                "detected": False,
                "score": 0.0,
                "classification": classification,
                "matched_families": [family] if family else [],
                "family_match": family,
                "family_match_confidence": "LOW" if family else "NONE",
                "vendor_family": family,
                "vendor_role_state": "vendor_family_only" if family else "unresolved",
            },
        }

    def _load_tracker_history(self) -> Dict[str, Any]:
        if not self.tracker_history_path.exists():
            return {}
        try:
            return json.loads(self.tracker_history_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _has_camera_keywords(text: str) -> bool:
        lowered = str(text or "").lower()
        return any(keyword in lowered for keyword in CAMERA_KEYWORDS)
