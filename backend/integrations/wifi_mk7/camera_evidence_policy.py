from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


OUTCOME_VISUAL_PROOF_RECOVERED = "visual_proof_recovered"
OUTCOME_STREAM_PATH_RECOVERED_BUT_DECODE_BLOCKED = "stream_path_recovered_but_decode_blocked"
OUTCOME_ENCRYPTED_CLOUD_RELAY_ONLY = "encrypted_cloud_relay_only"
OUTCOME_NETWORK_PROOF_ONLY = "network_proof_only"


def build_camera_evidence_policy(
    *,
    lead: Dict[str, Any],
    active_probe: Dict[str, Any],
    hard_audit: Dict[str, Any],
    validation_report: Dict[str, Any],
    vendor_profile: Dict[str, Any],
) -> Dict[str, Any]:
    visual_evidence = _collect_visual_evidence(active_probe=active_probe, hard_audit=hard_audit, validation_report=validation_report)
    packet_evidence = _collect_packet_evidence(hard_audit=hard_audit, validation_report=validation_report)
    protocol_evidence = _collect_protocol_evidence(active_probe=active_probe, hard_audit=hard_audit, validation_report=validation_report)
    owner_assisted_evidence = _collect_owner_assisted_evidence(lead=lead, hard_audit=hard_audit, vendor_profile=vendor_profile)

    video_evidence = dict(lead.get("video_evidence") or {})
    artifact_decision = dict(((hard_audit.get("pipeline") or {}).get("artifact_decision")) or {})
    decode_constraints = dict(hard_audit.get("decode_constraints") or {})
    local_stream_available = str(video_evidence.get("local_stream_available") or "").strip().lower() == "yes"
    cloud_stream_detected = str(video_evidence.get("cloud_stream_detected") or "").strip().lower() == "yes"
    artifact_possible = bool(artifact_decision.get("artifact_possible")) or str(video_evidence.get("artifact_possible") or "").strip().lower() == "yes"

    if visual_evidence:
        outcome_class = OUTCOME_VISUAL_PROOF_RECOVERED
        summary = f"{len(visual_evidence)} visual artifact{'s' if len(visual_evidence) != 1 else ''} retained."
    elif artifact_possible or local_stream_available:
        outcome_class = OUTCOME_STREAM_PATH_RECOVERED_BUT_DECODE_BLOCKED
        summary = str(artifact_decision.get("reason") or video_evidence.get("artifact_reason") or "Stream path recovered but no visual artifact was retained.")
    elif cloud_stream_detected or bool(decode_constraints.get("likely_cloud_relay")):
        outcome_class = OUTCOME_ENCRYPTED_CLOUD_RELAY_ONLY
        summary = str(decode_constraints.get("summary") or video_evidence.get("artifact_reason") or "Behavior suggests encrypted cloud relay only.")
    else:
        outcome_class = OUTCOME_NETWORK_PROOF_ONLY
        summary = "Protocol or packet evidence retained without visual recovery."

    return {
        "outcome_class": outcome_class,
        "summary": summary,
        "counts": {
            "visual_evidence": len(visual_evidence),
            "packet_evidence": len(packet_evidence),
            "protocol_evidence": len(protocol_evidence),
            "owner_assisted_evidence": len(owner_assisted_evidence),
        },
        "visual_evidence": visual_evidence,
        "packet_evidence": packet_evidence,
        "protocol_evidence": protocol_evidence,
        "owner_assisted_evidence": owner_assisted_evidence,
    }


def _collect_visual_evidence(
    *,
    active_probe: Dict[str, Any],
    hard_audit: Dict[str, Any],
    validation_report: Dict[str, Any],
) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    seen: set[str] = set()

    def append(path: str, *, source: str, label: str, protocol: str = "", detail: str = "") -> None:
        normalized = str(path or "").strip()
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        suffix = normalized.lower()
        if not suffix.endswith((".jpg", ".jpeg", ".png", ".bmp", ".webp", ".mp4", ".mov", ".webm", ".m4v")):
            return
        collected.append(
            {
                "path": normalized,
                "source": source,
                "label": label,
                "protocol": protocol,
                "detail": detail,
                "file_name": Path(normalized).name,
            }
        )

    for probe in active_probe.get("probes") or []:
        ip = str(probe.get("ip") or "").strip()
        for finding in ((probe.get("snapshot") or {}).get("findings") or []):
            append(
                str(finding.get("saved_path") or ""),
                source="snapshot_probe",
                label="Snapshot Artifact",
                protocol=str(finding.get("scheme") or "http"),
                detail=f"{ip} {finding.get('path') or ''}".strip(),
            )
        rtsp = probe.get("rtsp") or {}
        append(
            str(rtsp.get("frame_capture_path") or ""),
            source="rtsp_probe",
            label="RTSP Frame Artifact",
            protocol="rtsp",
            detail=str(rtsp.get("frame_capture_url") or ip),
        )

    for bucket_name in ("protocol", "exposure"):
        for entry in ((validation_report.get("evidence") or {}).get(bucket_name) or []):
            append(
                str(entry.get("capture_file") or entry.get("saved_path") or ""),
                source="validation_report",
                label=str(entry.get("evidence_type") or "artifact").replace("_", " "),
                protocol=str(entry.get("protocol") or ""),
                detail=str(entry.get("summary") or ""),
            )

    for path in list((hard_audit.get("decrypt_followup") or {}).get("saved_images") or []):
        append(str(path), source="decrypt_followup", label="Recovered Image", protocol="offline", detail="Recovered from retained truth capture.")
    append(
        str(hard_audit.get("behavioral_video_proof_artifact") or ""),
        source="behavioral_video_proof",
        label="Behavioral Video Proof",
        protocol="behavioral",
        detail=str(((hard_audit.get("video_truth") or {}).get("status_reason")) or ""),
    )
    return collected


def _collect_packet_evidence(*, hard_audit: Dict[str, Any], validation_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    camera_packet = dict(hard_audit.get("camera_packet_evidence") or {})
    if camera_packet.get("ok"):
        collected.append(
            {
                "target_ip": str(camera_packet.get("target_ip") or ""),
                "pcapng_path": str(camera_packet.get("pcapng_path") or ""),
                "pcap_path": str(camera_packet.get("pcap_path") or ""),
                "summary_path": str(camera_packet.get("summary_path") or ""),
                "packet_count": int(camera_packet.get("packet_count") or 0),
                "file_size_bytes": int(camera_packet.get("file_size_bytes") or 0),
                "summary": dict(camera_packet.get("summary") or {}),
                "source": "camera_packet_evidence",
            }
        )
    for capture in list(hard_audit.get("direct_truth_captures") or []):
        if not capture.get("ok"):
            continue
        collected.append(
            {
                "target_ip": str(capture.get("target_ip") or ""),
                "pcapng_path": str(capture.get("pcapng_path") or ""),
                "pcap_path": str(capture.get("pcap_path") or ""),
                "summary_path": str(capture.get("summary_path") or ""),
                "packet_count": int(capture.get("packet_count") or 0),
                "file_size_bytes": int(capture.get("file_size_bytes") or 0),
                "summary": dict(capture.get("summary") or {}),
                "source": f"direct_truth_{capture.get('stage') or 'window'}",
            }
        )
    if not collected:
        for entry in ((validation_report.get("evidence") or {}).get("protocol") or []):
            if str(entry.get("evidence_type") or "") in {"camera_ip_raw_capture", "camera_ip_raw_pcap", "camera_media_summary"}:
                collected.append(
                    {
                        "target_ip": str(entry.get("flow_identifier") or ""),
                        "pcapng_path": str(entry.get("capture_file") or ""),
                        "pcap_path": str(entry.get("capture_file") or ""),
                        "summary_path": str(entry.get("capture_file") or ""),
                        "packet_count": 0,
                        "file_size_bytes": 0,
                        "summary": {"assessment": str(entry.get("summary") or "")},
                        "source": "validation_report",
                    }
                )
    return collected


def _collect_protocol_evidence(
    *,
    active_probe: Dict[str, Any],
    hard_audit: Dict[str, Any],
    validation_report: Dict[str, Any],
) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    for probe in active_probe.get("probes") or []:
        ip = str(probe.get("ip") or "").strip()
        for finding in ((probe.get("http") or {}).get("findings") or []):
            if int(finding.get("status") or 0) <= 0:
                continue
            collected.append(
                {
                    "source": "http_probe",
                    "target_ip": ip,
                    "protocol": str(finding.get("scheme") or "http"),
                    "path": str(finding.get("path") or ""),
                    "detail": f"{finding.get('status') or 0} {finding.get('server') or ''}".strip(),
                }
            )
        rtsp = probe.get("rtsp") or {}
        if rtsp.get("ok"):
            collected.append(
                {
                    "source": "rtsp_probe",
                    "target_ip": ip,
                    "protocol": "rtsp",
                    "path": str(rtsp.get("transcript_path") or ""),
                    "detail": str(rtsp.get("status_line") or ""),
                }
            )
        onvif = probe.get("onvif") or {}
        if (onvif.get("http_service") or {}).get("ok") or (onvif.get("ws_discovery") or {}).get("ok"):
            collected.append(
                {
                    "source": "onvif_probe",
                    "target_ip": ip,
                    "protocol": "onvif",
                    "path": "/onvif/device_service",
                    "detail": str(((onvif.get("http_service") or {}).get("status")) or ((onvif.get("ws_discovery") or {}).get("status")) or ""),
                }
            )
    for entry in ((validation_report.get("evidence") or {}).get("protocol") or []):
        collected.append(
            {
                "source": "validation_report",
                "target_ip": str(entry.get("flow_identifier") or ""),
                "protocol": str(entry.get("protocol") or ""),
                "path": str(entry.get("capture_file") or ""),
                "detail": str(entry.get("summary") or ""),
            }
        )
    for note in list((((hard_audit.get("xiaomi_cloud_capture") or {}).get("required_artifacts")) or [])):
        collected.append(
            {
                "source": "cloud_capture_plan",
                "target_ip": "",
                "protocol": "cloud",
                "path": "",
                "detail": str(note),
            }
        )
    return collected[:24]


def _collect_owner_assisted_evidence(
    *,
    lead: Dict[str, Any],
    hard_audit: Dict[str, Any],
    vendor_profile: Dict[str, Any],
) -> List[Dict[str, Any]]:
    workflow = list(vendor_profile.get("owner_assisted_workflow") or [])
    correlation = dict(((lead.get("video_evidence") or {}).get("correlation")) or {})
    items: List[Dict[str, Any]] = []
    for index, step in enumerate(workflow):
        items.append(
            {
                "id": f"owner-assisted-{index + 1}",
                "step": str(step),
                "status": "correlated" if bool(correlation) else "recommended",
                "detail": str(correlation.get("summary") or "Owner-assisted app-side visual proof is recommended when local media is unavailable."),
            }
        )
    if not items and bool((hard_audit.get("xiaomi_cloud_capture") or {}).get("matched")):
        items.append(
            {
                "id": "owner-assisted-cloud",
                "step": "Retain owner-consented live-view screenshot or screen recording during the audit.",
                "status": "recommended",
                "detail": "Cloud relay behavior was detected and no local visual artifact was retained.",
            }
        )
    return items
