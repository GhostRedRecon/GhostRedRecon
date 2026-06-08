from __future__ import annotations

from typing import Any, Dict, List

from backend.integrations.wifi_mk7.camera_evidence_policy import (
    OUTCOME_ENCRYPTED_CLOUD_RELAY_ONLY,
    OUTCOME_NETWORK_PROOF_ONLY,
    OUTCOME_STREAM_PATH_RECOVERED_BUT_DECODE_BLOCKED,
    OUTCOME_VISUAL_PROOF_RECOVERED,
    build_camera_evidence_policy,
)
from backend.integrations.wifi_mk7.camera_vendor_sdk import CameraVendorPluginRegistry


class VisualAcquisitionEngine:
    def __init__(self) -> None:
        self.registry = CameraVendorPluginRegistry()

    def run(
        self,
        *,
        lead: Dict[str, Any],
        active_probe: Dict[str, Any],
        hard_audit: Dict[str, Any],
        validation_report: Dict[str, Any],
        analysis: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        vendor_matches = self.registry.match(lead, analysis=analysis)
        vendor_profile = dict(vendor_matches.get("primary") or {})
        probe_summary = dict(active_probe.get("summary") or {})
        video_evidence = dict(lead.get("video_evidence") or {})
        camera_packet = dict(hard_audit.get("camera_packet_evidence") or {})
        decode_constraints = dict(hard_audit.get("decode_constraints") or {})
        xiaomi_cloud_capture = dict(hard_audit.get("xiaomi_cloud_capture") or {})

        evidence_policy = build_camera_evidence_policy(
            lead=lead,
            active_probe=active_probe,
            hard_audit=hard_audit,
            validation_report=validation_report,
            vendor_profile=vendor_profile,
        )
        outcome_class = str(evidence_policy.get("outcome_class") or OUTCOME_NETWORK_PROOF_ONLY)
        visual_items = list(evidence_policy.get("visual_evidence") or [])
        packet_items = list(evidence_policy.get("packet_evidence") or [])

        onvif_snapshot_status = "recovered" if any(item.get("source") == "snapshot_probe" for item in visual_items) else ("available" if int(probe_summary.get("onvif_hits") or 0) > 0 or int(probe_summary.get("snapshot_hits") or 0) > 0 else "unavailable")
        rtsp_status = "recovered" if any(item.get("source") == "rtsp_probe" for item in visual_items) else ("available" if int(probe_summary.get("rtsp_hits") or 0) > 0 else "unavailable")
        mjpeg_status = "recovered" if any("mjpg" in str(item.get("detail") or "").lower() or "mjpeg" in str(item.get("detail") or "").lower() for item in visual_items) else ("available" if self._has_mjpeg_candidate(active_probe) else "unavailable")
        bridge_status = "candidate" if outcome_class in {OUTCOME_ENCRYPTED_CLOUD_RELAY_ONLY, OUTCOME_STREAM_PATH_RECOVERED_BUT_DECODE_BLOCKED} or bool(vendor_profile.get("bridge_targets")) else "unavailable"
        vendor_status = "matched" if vendor_profile.get("matched") else "generic"
        recorder_status = "candidate" if bool((vendor_profile.get("recorder_replay") or {}).get("supported")) else "unavailable"

        inputs = {
            "onvif_snapshot": {
                "status": onvif_snapshot_status,
                "detail": "Snapshot or ONVIF media path exposed." if onvif_snapshot_status != "unavailable" else "No ONVIF or snapshot path retained.",
            },
            "rtsp": {
                "status": rtsp_status,
                "detail": "RTSP path exposed." if rtsp_status != "unavailable" else "No RTSP path retained.",
            },
            "mjpeg": {
                "status": mjpeg_status,
                "detail": "Multipart MJPEG or HTTP image path was retained." if mjpeg_status != "unavailable" else "No MJPEG path retained.",
            },
            "webrtc_hls_bridge": {
                "status": bridge_status,
                "detail": self._bridge_detail(outcome_class=outcome_class, xiaomi_cloud_capture=xiaomi_cloud_capture, vendor_profile=vendor_profile),
            },
            "vendor_plugin": {
                "status": vendor_status,
                "detail": str(vendor_profile.get("label") or "Generic camera workflow"),
                "plugin_id": str(vendor_profile.get("plugin_id") or ""),
                "notes": list(vendor_profile.get("notes") or []),
            },
            "recorder_replay": {
                "status": recorder_status,
                "detail": str(((vendor_profile.get("recorder_replay") or {}).get("detail")) or "No recorder replay plan retained."),
            },
        }

        return {
            "outcome_class": outcome_class,
            "summary": str(evidence_policy.get("summary") or ""),
            "vendor_profile": vendor_profile,
            "vendor_matches": list(vendor_matches.get("matches") or []),
            "inputs": inputs,
            "evidence_policy": evidence_policy,
            "packet_capture_present": bool(packet_items),
            "cloud_relay_detected": bool(
                str(video_evidence.get("cloud_stream_detected") or "").strip().lower() == "yes"
                or decode_constraints.get("likely_cloud_relay")
                or xiaomi_cloud_capture.get("likely_cloud_relay")
            ),
            "local_visual_present": bool(visual_items),
            "bridge_targets": list(vendor_profile.get("bridge_targets") or []),
            "owner_assisted_workflow": list(vendor_profile.get("owner_assisted_workflow") or []),
            "local_capture_paths": list(vendor_profile.get("local_capture_paths") or []),
        }

    @staticmethod
    def _has_mjpeg_candidate(active_probe: Dict[str, Any]) -> bool:
        for probe in active_probe.get("probes") or []:
            for finding in ((probe.get("snapshot") or {}).get("findings") or []):
                blob = " ".join(
                    [
                        str(finding.get("path") or ""),
                        str(finding.get("content_type") or ""),
                    ]
                ).lower()
                if "mjpg" in blob or "mjpeg" in blob or "multipart" in blob:
                    return True
        return False

    @staticmethod
    def _bridge_detail(*, outcome_class: str, xiaomi_cloud_capture: Dict[str, Any], vendor_profile: Dict[str, Any]) -> str:
        if outcome_class == OUTCOME_VISUAL_PROOF_RECOVERED:
            return "Bridge not required because a visual artifact was already retained."
        if outcome_class == OUTCOME_STREAM_PATH_RECOVERED_BUT_DECODE_BLOCKED:
            return "A local or proxied stream path exists, but decode or artifact retention failed."
        if outcome_class == OUTCOME_ENCRYPTED_CLOUD_RELAY_ONLY:
            return str(
                xiaomi_cloud_capture.get("summary")
                or "Encrypted cloud relay behavior suggests an owner-assisted bridge or app-side capture is required."
            )
        if vendor_profile.get("bridge_targets"):
            return "Owner-assisted relay or bridge remains the best visual-acquisition path for this family."
        return "No bridge target retained."
