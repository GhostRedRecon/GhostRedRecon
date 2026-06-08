from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List


def build_environment_baseline(observations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    common_ssids: List[str] = []
    channel_counts: Dict[str, int] = {}
    for item in observations:
        ssid = str(item.get("ssid") or "").strip()
        if ssid:
            common_ssids.append(ssid)
        channel = str(item.get("channel") or "--")
        channel_counts[channel] = channel_counts.get(channel, 0) + 1
    return {
        "captured_at": time.time(),
        "common_ssids": sorted({ssid for ssid in common_ssids if ssid})[:32],
        "stationary_ap_count_estimate": len({ssid for ssid in common_ssids if ssid}),
        "common_channel_occupancy": channel_counts,
        "noise_floor_hint_db": -92,
        "summary": "Session baseline learned from passive Wi-Fi observations.",
    }


class EvidenceRetentionManager:
    STRUCTURE = [
        "targets",
        "leads",
        "timeline",
        "logs",
        "fusion",
        "scheduler",
        "anomalies",
        "wifi/raw",
        "sdr/iq_snippets",
        "sdr/spectrograms",
        "remote_id",
        "dji",
        "topology",
        "reports",
        "calibration",
        "replay",
    ]

    def __init__(self, session_dir: Path) -> None:
        self.session_dir = Path(session_dir)

    def ensure_structure(self) -> None:
        for relative in self.STRUCTURE:
            (self.session_dir / relative).mkdir(parents=True, exist_ok=True)

    def write_json(self, relative_path: str, payload: Any) -> str:
        path = self.session_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(path)

    def write_jsonl(self, relative_path: str, rows: Iterable[Dict[str, Any]]) -> str:
        path = self.session_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        return str(path)

    def persist_session_shell(self, session_metadata: Dict[str, Any], policy_state: Dict[str, Any], baseline: Dict[str, Any]) -> None:
        self.ensure_structure()
        self.write_json("session.json", session_metadata)
        self.write_json("policy_state.json", policy_state)
        self.write_json("environment_baseline.json", baseline)
        self.write_json("calibration/reference_profiles.json", self._reference_profiles())
        self.write_json("calibration/thresholds_resolved.json", self._thresholds())

    def persist_observations(
        self,
        wifi_rows: List[Dict[str, Any]],
        sdr_rows: List[Dict[str, Any]],
        remote_id_rows: List[Dict[str, Any]],
        dji_rows: Dict[str, Any],
    ) -> None:
        self.write_jsonl("wifi/beacons.jsonl", wifi_rows)
        self.write_jsonl("wifi/management_frames.jsonl", wifi_rows)
        self.write_json("wifi/wifi_candidates.json", {"count": len(wifi_rows), "items": wifi_rows[:100]})
        self.write_json(
            "wifi/oui_enrichment.json",
            {
                "count": len([row for row in wifi_rows if row.get("uav_enrichment")]),
                "items": [
                    {
                        "identifier": str(row.get("bssid") or row.get("mac") or row.get("associated_bssid") or ""),
                        "enrichment": row.get("uav_enrichment") or {},
                    }
                    for row in wifi_rows
                    if row.get("uav_enrichment")
                ][:100],
            },
        )
        self.write_jsonl("sdr/events.jsonl", sdr_rows)
        self.write_json("sdr/clusters.json", {"count": len(sdr_rows), "items": sdr_rows[:100]})
        self.write_json("remote_id/messages.jsonl", remote_id_rows)
        self.write_json("remote_id/parsed_entities.json", {"count": len(remote_id_rows), "items": remote_id_rows[:100]})
        self.write_json(
            "remote_id/parsed_objects.json",
            {
                "count": len([row for row in remote_id_rows if (row.get("decoder") or {}).get("parsed_object")]),
                "items": [
                    (row.get("decoder") or {}).get("parsed_object")
                    for row in remote_id_rows
                    if (row.get("decoder") or {}).get("parsed_object")
                ][:100],
            },
        )
        self.write_json("remote_id/transport_summary.json", {"sources": sorted({str(item.get('transport') or 'wifi') for item in remote_id_rows})})
        self.write_json("remote_id/parser_diagnostics.json", {"status": "passive", "message_count": len(remote_id_rows)})
        self.write_json("dji/rf_profile.json", {"matched_count": len(dji_rows.get("matched_peaks") or []), "targets": dji_rows.get("targets") or []})
        self.write_json("dji/decode_manifest.json", dji_rows)
        self.write_json("dji/decoder_diagnostics.json", dji_rows.get("decoder_diagnostics") or {"status": "best_effort_passive_decode", "target_count": len(dji_rows.get("targets") or [])})
        self.write_json("dji/burst_groups.json", {"matched_peaks": dji_rows.get("matched_peaks") or [], "burst_locks": dji_rows.get("burst_locks") or []})
        self.write_json("dji/parsed_entities.json", {"count": len(dji_rows.get("parsed_objects") or []), "items": dji_rows.get("parsed_objects") or []})
        self.write_json("dji/sample_windows.json", {"count": len(dji_rows.get("sample_windows") or []), "items": dji_rows.get("sample_windows") or []})
        for window in dji_rows.get("sample_windows") or []:
            reference = str(window.get("reference") or "").strip()
            if not reference:
                continue
            self.write_json(
                reference,
                {
                    "window_id": window.get("window_id"),
                    "relative_start_sec": window.get("relative_start_sec"),
                    "duration_ms": window.get("duration_ms"),
                    "row_ids": window.get("row_ids") or [],
                },
            )

    def persist_targets(self, detections: List[Dict[str, Any]]) -> None:
        manifest = {"count": len(detections), "targets": detections}
        self.write_json("targets/index.json", manifest)

    def persist_timeline(self, events: List[Dict[str, Any]], operator_log: List[Dict[str, Any]]) -> None:
        self.write_jsonl("timeline/events.jsonl", events)
        self.write_jsonl("logs/operator.jsonl", operator_log)
        self.write_jsonl("logs/system.jsonl", events)

    def persist_reports(self, summary: Dict[str, Any], audit_report: Dict[str, Any], operator_report_md: str) -> None:
        self.write_json("reports/summary.json", summary)
        self.write_json("reports/audit_report.json", audit_report)
        self.write_json("reports/evidence_manifest.json", audit_report.get("evidence_manifest") or {})
        path = self.session_dir / "reports" / "operator_report.md"
        path.write_text(operator_report_md, encoding="utf-8")

    def persist_assurance(self, assurance: Dict[str, Any]) -> None:
        self.write_json("leads/index.json", {"count": len(assurance.get("leads") or []), "items": assurance.get("leads") or []})
        self.write_jsonl("fusion/windows.jsonl", assurance.get("fusion_windows") or [])
        self.write_jsonl("scheduler/actions.jsonl", assurance.get("scheduler_actions") or [])
        self.write_jsonl("anomalies/wifi.jsonl", assurance.get("anomalies_wifi") or [])
        self.write_jsonl("anomalies/sdr.jsonl", assurance.get("anomalies_sdr") or [])
        self.write_json("calibration/runtime_baseline.json", assurance.get("runtime_baseline") or {})
        self.write_json("replay/session_trace.json", assurance.get("session_trace") or {})

    @staticmethod
    def _reference_profiles() -> Dict[str, Any]:
        return {
            "indoor_lab": {"noise_floor_hint_db": -88, "robustness_class": "reference"},
            "urban_outdoor": {"noise_floor_hint_db": -84, "robustness_class": "mixed"},
            "suburban_outdoor": {"noise_floor_hint_db": -89, "robustness_class": "mixed"},
            "rf_quiet_test_field": {"noise_floor_hint_db": -96, "robustness_class": "reference"},
            "dense_wifi_environment": {"noise_floor_hint_db": -80, "robustness_class": "noisy"},
        }

    @staticmethod
    def _thresholds() -> Dict[str, Any]:
        return {
            "probable_drone_confidence": 65,
            "confirmed_drone_confidence": 85,
            "audit_grade_confidence": 90,
            "one_off_decay_penalty": -8,
            "stationary_ap_penalty": -15,
        }
