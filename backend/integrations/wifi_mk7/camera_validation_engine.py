from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List


class CameraValidationEngine:
    def __init__(self, root_dir: Path) -> None:
        self.root_dir = Path(root_dir)
        self.run_dir = self.root_dir / "logs" / "wifi_mk7" / "camera_validation_runs"
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def validate_lead(
        self,
        *,
        lead: Dict[str, Any],
        active_probe: Dict[str, Any],
        analysis: Dict[str, Any] | None = None,
        pcap_inventory: List[Dict[str, Any]] | None = None,
        run_type: str = "camera_lead_validation",
    ) -> Dict[str, Any]:
        ts = int(time.time())
        lead_id = str(lead.get("lead_id") or lead.get("leadId") or lead.get("record_id") or lead.get("bssid") or lead.get("mac") or f"lead-{ts}")
        run_id = f"camval-{ts}-{lead_id.replace(':', '').replace('/', '_')[:24]}"
        pcap_inventory = list(pcap_inventory or [])
        evidence = self._build_evidence(lead, active_probe, analysis, pcap_inventory, run_id)
        verdict = self._build_verdict(evidence)
        report = {
            "run_id": run_id,
            "run_type": run_type,
            "target": {
                "lead_id": lead_id,
                "identity": str(lead.get("ssid") or lead.get("mac") or lead.get("bssid") or lead.get("record_id") or "<unknown>"),
                "device_type": str(((lead.get("camera_detection") or {}).get("device_type") or (lead.get("fingerprint") or {}).get("device_type") or "unknown")),
                "vendor": str((lead.get("vendor") or (lead.get("fingerprint") or {}).get("vendor") or "unknown")),
            },
            "timestamp": ts,
            "analysis": analysis or {},
            "active_probe_summary": active_probe.get("summary") or {},
            "evidence": evidence,
            "verdict": verdict,
            "reproducibility": {
                "status": "reproducible",
                "steps": self._repro_steps(active_probe),
            },
        }
        self._persist_run(report)
        return report

    def _build_evidence(
        self,
        lead: Dict[str, Any],
        active_probe: Dict[str, Any],
        analysis: Dict[str, Any] | None,
        pcap_inventory: List[Dict[str, Any]],
        run_id: str,
    ) -> Dict[str, Any]:
        evidence: Dict[str, List[Dict[str, Any]]] = {
            "exposure": [],
            "authentication": [],
            "stream": [],
            "control_surface": [],
            "firmware": [],
            "protocol": [],
            "behavior": [],
            "sequence": [],
            "stress": [],
            "negative": [],
            "inconclusive": [],
        }
        candidate_ips = list(active_probe.get("candidate_ips") or [])
        probes = list(active_probe.get("probes") or [])
        discovery_fallback = dict(active_probe.get("discovery_fallback") or {})
        ts = int(time.time())
        video_evidence = dict(lead.get("video_evidence") or {})

        if discovery_fallback:
            for response in discovery_fallback.get("responses") or []:
                evidence["exposure"].append(
                    {
                        "evidence_type": "onvif_multicast_discovery",
                        "target_ip": str(response.get("from_ip") or ""),
                        "protocol": "udp",
                        "port": 3702,
                        "request": {"method": "Probe", "transport": "WS-Discovery"},
                        "response": {
                            "xaddrs": list(response.get("xaddrs") or []),
                            "scopes": list(response.get("scopes") or []),
                            "matched_tokens": list(response.get("matched_tokens") or []),
                        },
                        "timestamp": ts,
                        "run_id": run_id,
                        "quality": "corroborated" if response.get("xaddrs") else "direct_confirmed",
                    }
                )

        for probe in probes:
            ip = str(probe.get("ip") or "")
            http = probe.get("http") or {}
            onvif = probe.get("onvif") or {}
            rtsp = probe.get("rtsp") or {}
            snapshot = probe.get("snapshot") or {}

            for finding in http.get("findings") or []:
                record = {
                    "evidence_type": "http_endpoint",
                    "target_ip": ip,
                    "protocol": str(finding.get("scheme") or "http"),
                    "port": int(finding.get("port") or 0),
                    "path": str(finding.get("path") or ""),
                    "request": {"method": "GET", "path": str(finding.get("path") or "")},
                    "response": {
                        "status": int(finding.get("status") or 0),
                        "reason": str(finding.get("reason") or ""),
                        "server": str(finding.get("server") or ""),
                        "www_authenticate": str(finding.get("www_authenticate") or ""),
                    },
                    "timestamp": ts,
                    "run_id": run_id,
                    "quality": self._evidence_quality(True, bool(http.get("camera_hint"))),
                }
                evidence["exposure"].append(record)
                if record["response"]["status"] in {401, 403}:
                    evidence["negative"].append(
                        {
                            "evidence_type": "http_auth_enforced",
                            "target_ip": ip,
                            "path": record["path"],
                            "status": record["response"]["status"],
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "direct_confirmed",
                        }
                    )
                elif record["response"]["status"] in {200, 204} and self._is_sensitive_http_path(record["path"]):
                    evidence["authentication"].append(
                        {
                            "evidence_type": "unauthenticated_http_access",
                            "target_ip": ip,
                            "path": record["path"],
                            "status": record["response"]["status"],
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "direct_confirmed",
                        }
                    )
                    evidence["control_surface"].append(
                        {
                            "evidence_type": "http_control_surface",
                            "target_ip": ip,
                            "path": record["path"],
                            "classification": self._control_classification(record["path"]),
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "direct_confirmed",
                        }
                    )

            onvif_http = onvif.get("http_service") or {}
            if onvif_http.get("ok"):
                evidence["exposure"].append(
                    {
                        "evidence_type": "onvif_http_service",
                        "target_ip": ip,
                        "protocol": "http",
                        "port": 80,
                        "path": "/onvif/device_service",
                        "request": {"method": "POST", "action": "Probe"},
                        "response": {
                            "status": int(onvif_http.get("status") or 0),
                            "reason": str(onvif_http.get("reason") or ""),
                            "matched_tokens": list(onvif_http.get("matched_tokens") or []),
                        },
                        "timestamp": ts,
                        "run_id": run_id,
                        "quality": self._evidence_quality(True, bool(onvif.get("camera_hint"))),
                    }
                )
                if int(onvif_http.get("status") or 0) in {401, 403}:
                    evidence["negative"].append(
                        {
                            "evidence_type": "onvif_auth_enforced",
                            "target_ip": ip,
                            "status": int(onvif_http.get("status") or 0),
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "direct_confirmed",
                        }
                    )
                elif int(onvif_http.get("status") or 0) in {200, 400}:
                    evidence["authentication"].append(
                        {
                            "evidence_type": "onvif_pre_auth_response",
                            "target_ip": ip,
                            "status": int(onvif_http.get("status") or 0),
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "direct_confirmed",
                        }
                    )
                    evidence["control_surface"].append(
                        {
                            "evidence_type": "onvif_control_surface",
                            "target_ip": ip,
                            "action": "device_service_probe",
                            "classification": "configuration",
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "direct_confirmed",
                        }
                    )

            onvif_ws = onvif.get("ws_discovery") or {}
            if onvif_ws.get("ok"):
                evidence["exposure"].append(
                    {
                        "evidence_type": "onvif_ws_discovery",
                        "target_ip": ip,
                        "protocol": "udp",
                        "port": 3702,
                        "request": {"method": "Probe", "transport": "WS-Discovery"},
                        "response": {
                            "status": str(onvif_ws.get("status") or ""),
                            "matched_tokens": list(onvif_ws.get("matched_tokens") or []),
                            "xaddrs": list(onvif_ws.get("xaddrs") or []),
                            "scopes": list(onvif_ws.get("scopes") or []),
                        },
                        "timestamp": ts,
                        "run_id": run_id,
                        "quality": self._evidence_quality(True, bool(onvif.get("camera_hint"))),
                    }
                )

            if rtsp.get("ok"):
                status_line = str(rtsp.get("status_line") or "")
                status_code = self._rtsp_status_code(status_line)
                evidence["stream"].append(
                    {
                        "evidence_type": "rtsp_options",
                        "target_ip": ip,
                        "protocol": "rtsp",
                        "port": int(rtsp.get("port") or 0),
                        "request_sequence": ["OPTIONS", "DESCRIBE"],
                        "status_line": status_line,
                        "describe_status_line": str(rtsp.get("describe_status_line") or ""),
                        "supported_methods": list(rtsp.get("supported_methods") or []),
                        "transcript_path": str(rtsp.get("transcript_path") or ""),
                        "media_session_established": status_code == 200,
                        "timestamp": ts,
                        "run_id": run_id,
                        "quality": self._evidence_quality(True, bool(rtsp.get("camera_hint"))),
                    }
                )
                if rtsp.get("transcript_path"):
                    evidence["protocol"].append(
                        {
                            "evidence_type": "rtsp_transcript",
                            "capture_file": str(rtsp.get("transcript_path") or ""),
                            "flow_identifier": f"rtsp://{ip}:{int(rtsp.get('port') or 0)}",
                            "protocol": "rtsp",
                            "timestamps": {"observed_at": ts},
                            "summary": str(rtsp.get("status_line") or ""),
                            "run_id": run_id,
                            "quality": "corroborated" if status_code in {200, 401} else "partial",
                        }
                    )
                if rtsp.get("frame_capture_path"):
                    evidence["protocol"].append(
                        {
                            "evidence_type": "rtsp_frame_artifact",
                            "capture_file": str(rtsp.get("frame_capture_path") or ""),
                            "flow_identifier": str(rtsp.get("frame_capture_url") or f"rtsp://{ip}:{int(rtsp.get('port') or 0)}/"),
                            "protocol": "rtsp",
                            "timestamps": {"observed_at": ts},
                            "summary": str(rtsp.get("status_line") or "RTSP frame recovered."),
                            "run_id": run_id,
                            "quality": "corroborated",
                        }
                    )
                if status_code == 401:
                    evidence["negative"].append(
                        {
                            "evidence_type": "rtsp_auth_enforced",
                            "target_ip": ip,
                            "port": int(rtsp.get("port") or 0),
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "direct_confirmed",
                        }
                    )
                elif status_code == 200:
                    evidence["authentication"].append(
                        {
                            "evidence_type": "unauthenticated_rtsp_access",
                            "target_ip": ip,
                            "port": int(rtsp.get("port") or 0),
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "direct_confirmed",
                        }
                    )

            if snapshot.get("ok"):
                for finding in snapshot.get("findings") or []:
                    record = {
                        "evidence_type": "snapshot_endpoint",
                        "target_ip": ip,
                        "protocol": str(finding.get("scheme") or "http"),
                        "port": int(finding.get("port") or 0),
                        "path": str(finding.get("path") or ""),
                        "status": int(finding.get("status") or 0),
                        "image_hint": bool(finding.get("image_hint")),
                        "saved_path": str(finding.get("saved_path") or ""),
                        "payload_sha256": str(finding.get("payload_sha256") or ""),
                        "timestamp": ts,
                        "run_id": run_id,
                        "quality": self._evidence_quality(True, bool(finding.get("image_hint"))),
                    }
                    evidence["stream"].append(record)
                    if record["saved_path"]:
                        evidence["protocol"].append(
                            {
                                "evidence_type": "snapshot_artifact",
                                "capture_file": record["saved_path"],
                                "flow_identifier": f"{record['protocol']}://{ip}:{record['port']}{record['path']}",
                                "protocol": record["protocol"],
                                "timestamps": {"observed_at": ts},
                                "summary": record["payload_sha256"],
                                "run_id": run_id,
                                "quality": "corroborated" if record["image_hint"] else "partial",
                            }
                        )
                    if record["status"] == 200 and record["image_hint"]:
                        evidence["authentication"].append(
                            {
                                "evidence_type": "unauthenticated_snapshot_access",
                                "target_ip": ip,
                                "path": record["path"],
                                "timestamp": ts,
                                "run_id": run_id,
                                "quality": "direct_confirmed",
                            }
                        )

        for pcap in pcap_inventory[:20]:
            evidence["protocol"].append(
                {
                    "evidence_type": "pcap_capture",
                    "capture_file": str(pcap.get("path") or ""),
                    "channel": int(pcap.get("channel") or 0),
                    "band": str(pcap.get("band") or ""),
                    "frame_count": int(pcap.get("frame_count") or 0),
                    "timestamp": int(pcap.get("captured_at") or ts),
                    "run_id": run_id,
                    "quality": "corroborated" if int(pcap.get("frame_count") or 0) > 0 else "partial",
                }
            )

        if analysis:
            evidence["sequence"].append(
                {
                    "evidence_type": "lead_observation_sequence",
                    "sample_count": int((analysis.get("analysis") or {}).get("sample_count") or 0),
                    "observation_status": str(analysis.get("observation_status") or ""),
                    "timestamp": ts,
                    "run_id": run_id,
                    "quality": "partial" if not analysis.get("active_collection") else "direct_confirmed",
                }
            )

        if video_evidence:
            traffic_profile = dict(video_evidence.get("traffic_profile") or {})
            correlation = dict(video_evidence.get("correlation") or {})
            cloud_leakage = dict(video_evidence.get("cloud_leakage_audit") or {})
            evidence["behavior"].append(
                {
                    "evidence_type": "video_behavior_profile",
                    "video_capable": str(video_evidence.get("video_capable") or "inconclusive"),
                    "video_device_class": str(video_evidence.get("video_device_class") or "UNKNOWN"),
                    "evidence_type_label": str(video_evidence.get("evidence_type") or "partial"),
                    "local_stream_available": str(video_evidence.get("local_stream_available") or "no"),
                    "cloud_stream_detected": str(video_evidence.get("cloud_stream_detected") or "no"),
                    "artifact_possible": str(video_evidence.get("artifact_possible") or "no"),
                    "artifact_reason": str(video_evidence.get("artifact_reason") or ""),
                    "traffic_profile": traffic_profile,
                    "correlation": correlation,
                    "timestamp": ts,
                    "run_id": run_id,
                    "quality": (
                        "direct_confirmed"
                        if str(video_evidence.get("video_capable") or "") == "confirmed"
                        else ("partial" if str(video_evidence.get("video_capable") or "") == "inconclusive" else "negative")
                    ),
                }
            )
            if cloud_leakage:
                risk_level = str(cloud_leakage.get("risk_level") or "UNKNOWN").upper()
                evidence["behavior"].append(
                    {
                        "evidence_type": "cloud_leakage_audit",
                        "risk_level": risk_level,
                        "leakage_verdict": str(cloud_leakage.get("leakage_verdict") or ""),
                        "metadata_exposed": bool(cloud_leakage.get("metadata_exposed")),
                        "content_exposed": bool(cloud_leakage.get("content_exposed")),
                        "cloud_endpoints": list(cloud_leakage.get("cloud_endpoints") or []),
                        "new_live_view_endpoints": list(cloud_leakage.get("new_live_view_endpoints") or []),
                        "privacy_exposure": list(cloud_leakage.get("privacy_exposure") or []),
                        "timestamp": ts,
                        "run_id": run_id,
                        "quality": "corroborated" if risk_level in {"HIGH", "MEDIUM"} else "partial",
                    }
                )
                if list(cloud_leakage.get("cloud_endpoints") or []):
                    evidence["protocol"].append(
                        {
                            "evidence_type": "cloud_endpoint_metadata",
                            "protocol": "dns_tls_quic",
                            "flow_identifier": str(lead.get("lead_id") or lead.get("mac") or lead.get("bssid") or ""),
                            "cloud_endpoints": list(cloud_leakage.get("cloud_endpoints") or [])[:8],
                            "dns_names": list(cloud_leakage.get("dns_names") or [])[:8],
                            "tls_sni": list(cloud_leakage.get("tls_sni") or [])[:8],
                            "quic_sni": list(cloud_leakage.get("quic_sni") or [])[:8],
                            "summary": str(cloud_leakage.get("leakage_verdict") or "Cloud endpoint metadata retained."),
                            "run_id": run_id,
                            "quality": "corroborated" if risk_level in {"HIGH", "MEDIUM"} else "partial",
                        }
                    )
                if risk_level == "HIGH":
                    evidence["exposure"].append(
                        {
                            "evidence_type": "cloud_metadata_or_api_leakage",
                            "risk_level": risk_level,
                            "http_hosts": list(cloud_leakage.get("http_hosts") or []),
                            "http_uris": list(cloud_leakage.get("http_uris") or []),
                            "summary": str(cloud_leakage.get("leakage_verdict") or "Potential cloud leakage retained."),
                            "timestamp": ts,
                            "run_id": run_id,
                            "quality": "corroborated",
                        }
                    )
            if str(video_evidence.get("artifact_possible") or "no") == "no" and str(video_evidence.get("cloud_stream_detected") or "no") == "yes":
                evidence["negative"].append(
                    {
                        "evidence_type": "visual_artifact_not_locally_recoverable",
                        "reason": str(video_evidence.get("artifact_reason") or "cloud encrypted transport"),
                        "timestamp": ts,
                        "run_id": run_id,
                        "quality": "direct_confirmed",
                    }
                )

        handshake_frames = int(
            lead.get("authentication_evidence_frame_count")
            or ((lead.get("authentication_evidence") or {}).get("eapol_frame_count") or 0)
            or lead.get("eapol_count")
            or 0
        )
        handshake_quality = str(
            lead.get("authentication_evidence_quality")
            or ((lead.get("authentication_evidence") or {}).get("quality") or "NONE")
        )
        evidence["sequence"].append(
            {
                "evidence_type": "handshake_observation",
                "auth_state": "passive_handshake_observed" if handshake_frames > 0 else "no_handshake_observed",
                "quality_state": handshake_quality,
                "frame_count": handshake_frames,
                "timestamp": ts,
                "run_id": run_id,
                "quality": "direct_confirmed" if handshake_frames > 0 else "negative",
            }
        )
        if handshake_frames > 0:
            evidence["protocol"].append(
                {
                    "evidence_type": "passive_handshake_evidence",
                    "protocol": "eapol",
                    "flow_identifier": str(lead.get("associated_bssid") or lead.get("bssid") or lead.get("mac") or ""),
                    "timestamps": {"observed_at": ts},
                    "summary": f"{handshake_frames} EAPOL frames · quality {handshake_quality}",
                    "run_id": run_id,
                    "quality": "direct_confirmed",
                }
            )

        if not candidate_ips:
            evidence["inconclusive"].append(
                {
                    "evidence_type": "no_candidate_ip",
                    "reason": str(active_probe.get("candidate_ip_reason") or active_probe.get("error") or "No candidate IPs available"),
                    "timestamp": ts,
                    "run_id": run_id,
                    "quality": "inconclusive",
                }
            )

        return evidence

    def _build_verdict(self, evidence: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        auth = evidence.get("authentication") or []
        control = evidence.get("control_surface") or []
        stream = evidence.get("stream") or []
        behavior = evidence.get("behavior") or []
        negative = evidence.get("negative") or []
        inconclusive = evidence.get("inconclusive") or []

        if any(item.get("evidence_type") in {"unauthenticated_snapshot_access", "unauthenticated_rtsp_access", "unauthenticated_http_access"} for item in auth):
            return {
                "classification": "unsafe",
                "recommended_action": "isolate_shutdown_or_replace",
                "reasoning": "Direct confirmed unauthenticated access was observed on a stream or control-related surface.",
                "evidence_quality": "direct_confirmed",
                "audit_basis": "non_authenticated_exposure",
                "operator_guidance": "Treat this target as failed for audit. No login is required to justify remediation; recommend immediate isolation, shutdown, or replacement.",
            }
        if control or any(item.get("evidence_type") == "onvif_pre_auth_response" for item in auth):
            return {
                "classification": "weak_enforcement",
                "recommended_action": "segment_disable_services_or_replace",
                "reasoning": "Control-capable or service-management surfaces are exposed pre-auth or respond inconsistently under validation.",
                "evidence_quality": "direct_confirmed",
                "audit_basis": "pre_auth_management_exposure",
                "operator_guidance": "Treat exposed ONVIF, RTSP, or management surfaces as an audit failure unless the owner can harden them immediately. Recommend isolation, service disablement, or replacement.",
            }
        cloud_leak = next(
            (
                item for item in behavior
                if item.get("evidence_type") == "cloud_leakage_audit"
                and str(item.get("risk_level") or "").upper() == "HIGH"
            ),
            None,
        )
        if cloud_leak:
            return {
                "classification": "privacy_risk",
                "recommended_action": "segment_restrict_cloud_egress_or_replace",
                "reasoning": "Cloud-camera traffic exposed plaintext host/path metadata or API-like cloud metadata during validation.",
                "evidence_quality": str(cloud_leak.get("quality") or "corroborated"),
                "audit_basis": "cloud_metadata_or_plaintext_leakage",
                "operator_guidance": "Treat this as a privacy audit failure. Restrict egress to approved vendor endpoints, isolate the camera VLAN, disable cloud features where possible, or replace the device.",
            }
        cloud_video = next(
            (
                item for item in behavior
                if str(item.get("video_capable") or "") == "confirmed"
                and str(item.get("video_device_class") or "") == "CLOUD_STREAM_DEVICE"
            ),
            None,
        )
        if cloud_video and not auth and not control:
            return {
                "classification": "secure",
                "recommended_action": "safe_for_deployment",
                "reasoning": "Cloud-mediated video streaming was confirmed behaviorally and no local unauthenticated stream or control surface was observed during validation.",
                "evidence_quality": str(cloud_video.get("quality") or "direct_confirmed"),
                "audit_basis": "no_non_authenticated_local_exposure_observed",
                "operator_guidance": "No non-authenticated local media or management exposure was proven during this audit window.",
            }
        if negative and not auth and not inconclusive:
            return {
                "classification": "secure",
                "recommended_action": "safe_for_deployment",
                "reasoning": "Observed services enforced authentication during direct validation and no unauthenticated control or stream access was confirmed.",
                "evidence_quality": "direct_confirmed",
                "audit_basis": "authentication_enforced",
                "operator_guidance": "Authentication was enforced on observed local services. This audit did not prove an exposure severe enough to justify replacement.",
            }
        return {
            "classification": "inconclusive",
            "recommended_action": "requires_additional_validation",
            "reasoning": "Validation did not produce enough direct evidence to support a security conclusion.",
            "evidence_quality": "inconclusive",
            "audit_basis": "insufficient_non_authenticated_evidence",
            "operator_guidance": "No non-authenticated exposure was proven. Do not recommend shutdown or replacement unless a later audit produces direct evidence.",
        }

    @staticmethod
    def _evidence_quality(direct: bool, corroborated: bool) -> str:
        if direct and corroborated:
            return "corroborated"
        if direct:
            return "direct_confirmed"
        return "partial"

    @staticmethod
    def _is_sensitive_http_path(path: str) -> bool:
        lowered = str(path or "").lower()
        return any(token in lowered for token in ("device_service", "isapi", "magicbox", "webapi", "admin", "cgi-bin"))

    @staticmethod
    def _control_classification(path: str) -> str:
        lowered = str(path or "").lower()
        if any(token in lowered for token in ("device_service", "isapi", "webapi", "magicbox")):
            return "configuration"
        if "snapshot" in lowered:
            return "stream_interface"
        return "control_surface"

    @staticmethod
    def _rtsp_status_code(status_line: str) -> int:
        parts = str(status_line or "").split()
        for token in parts:
            if token.isdigit():
                return int(token)
        return 0

    @staticmethod
    def _repro_steps(active_probe: Dict[str, Any]) -> List[Dict[str, Any]]:
        steps: List[Dict[str, Any]] = []
        for probe in active_probe.get("probes") or []:
            ip = str(probe.get("ip") or "")
            steps.append({"step": "http_probe", "target_ip": ip, "paths": list((probe.get("http") or {}).get("findings") or [])[:4]})
            steps.append({"step": "onvif_probe", "target_ip": ip, "service": (probe.get("onvif") or {}).get("http_service") or {}})
            steps.append({"step": "rtsp_probe", "target_ip": ip, "attempts": list((probe.get("rtsp") or {}).get("attempts") or [])[:4]})
            steps.append({"step": "snapshot_probe", "target_ip": ip, "findings": list((probe.get("snapshot") or {}).get("findings") or [])[:4]})
        return steps

    def _persist_run(self, report: Dict[str, Any]) -> None:
        run_id = str(report.get("run_id") or f"camval-{int(time.time())}")
        target = self.run_dir / f"{run_id}.json"
        target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
