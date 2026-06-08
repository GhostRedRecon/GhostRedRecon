#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[1]


def now_ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def log(message: str) -> None:
    print(f"[targeted-capture] {message}", flush=True)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def api_request(base_url: str, method: str, path: str, *, timeout: int = 30, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    query_parts: List[str] = []
    for key, value in (params or {}).items():
        if isinstance(value, (list, tuple)):
            for item in value:
                query_parts.append(f"{key}={str(item)}")
        else:
            query_parts.append(f"{key}={str(value)}")
    query = "&".join(query_parts)
    url = f"{base_url.rstrip('/')}{path}"
    if query:
        url = f"{url}?{query}"
    try:
        result = subprocess.run(
            ["curl", "-fsS", "-X", method.upper(), url],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            return {"ok": False, "error": (result.stderr or result.stdout or "").strip(), "url": url}
        return json.loads((result.stdout or "{}").strip() or "{}")
    except Exception as exc:
        return {"ok": False, "error": str(exc), "url": url}


def unique_ints(values: Iterable[int]) -> List[int]:
    return sorted({int(value) for value in values if int(value) > 0})


def channel_to_band(channel: int) -> str:
    return "5ghz" if int(channel) > 14 else "2.4ghz"


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class GhostReconTargetedCapture:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root_dir = REPO_ROOT
        self.run_dir = self.root_dir / "evidence" / "targeted_capture_runs" / now_ts()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.base_url = args.base_url.rstrip("/")
        self.started_at = time.time()
        self.selected_targets: List[Dict[str, Any]] = []
        self.selected_channels: List[int] = []
        self.initial_pcap_count = 0
        self.final_pcap_inventory: List[Dict[str, Any]] = []
        self.poll_samples: List[Dict[str, Any]] = []
        self.logs_dir = self.root_dir / "logs" / "wifi_mk7"

    def run(self) -> int:
        initial_status = api_request(self.base_url, "GET", "/api/wifi_mk7/status", params={"prepare": "true"})
        if initial_status.get("service") != "wifi_mk7":
            raise SystemExit(f"WiFi MK7 unavailable: {initial_status}")

        if bool(initial_status.get("capture_active")):
            raise SystemExit("WiFi MK7 scan already active; stop it before running a targeted capture.")

        self.initial_pcap_count = int(((initial_status.get("inventory") or {}).get("pcap_count") or 0))
        initial_survey = self._collect_candidate_survey(initial_status, label="initial")
        write_json(self.run_dir / "initial_candidate_survey.json", initial_survey)
        write_text(self.run_dir / "initial_candidate_survey.txt", self._render_candidate_survey(initial_survey))
        self.selected_targets = self._select_targets(initial_status)
        self.selected_channels = self._select_channels(initial_status)
        if not self.selected_channels:
            raise SystemExit("No target channels resolved from explicit channels, SSIDs, or observation history.")

        if self.args.survey_only:
            log("survey-only mode enabled; no new capture started")
            log(f"run directory: {self.run_dir}")
            log(f"top candidate: {self._top_candidate_label(initial_survey)}")
            return 0

        start_payload = self._start_capture()
        log(f"locked channels: {','.join(str(item) for item in self.selected_channels)}")
        if self.selected_targets:
            log(f"target SSIDs: {', '.join(str(item.get('ssid') or '--') for item in self.selected_targets[:8])}")

        stop_reason = self._poll_until_complete()
        final_status = api_request(self.base_url, "GET", "/api/wifi_mk7/status")
        final_survey = self._collect_candidate_survey(final_status, label="final")
        pcap_inventory = api_request(self.base_url, "GET", "/api/wifi_mk7/pcap")
        self.final_pcap_inventory = list(pcap_inventory.get("pcaps") or [])
        fresh_pcaps = self._fresh_pcaps()

        report = {
            "generated_at": int(time.time()),
            "run_dir": str(self.run_dir),
            "base_url": self.base_url,
            "args": vars(self.args),
            "selected_channels": self.selected_channels,
            "selected_targets": self.selected_targets,
            "initial_pcap_count": self.initial_pcap_count,
            "initial_candidate_survey": initial_survey,
            "start_payload": start_payload,
            "stop_reason": stop_reason,
            "poll_samples": self.poll_samples,
            "final_status": final_status,
            "final_candidate_survey": final_survey,
            "fresh_pcap_count": len(fresh_pcaps),
            "fresh_pcaps": fresh_pcaps,
        }
        write_json(self.run_dir / "targeted_capture_report.json", report)
        write_text(self.run_dir / "targeted_capture_summary.txt", self._render_summary(report))
        write_json(self.run_dir / "final_candidate_survey.json", final_survey)
        write_text(self.run_dir / "final_candidate_survey.txt", self._render_candidate_survey(final_survey))
        log(f"run directory: {self.run_dir}")
        log(f"fresh pcaps: {len(fresh_pcaps)}")
        log(f"stop reason: {stop_reason}")
        log(f"top candidate: {self._top_candidate_label(final_survey)}")
        return 0

    def _select_targets(self, status: Dict[str, Any]) -> List[Dict[str, Any]]:
        requested_ssids = {item.strip() for item in self.args.ssid if item.strip()}
        survey = self._collect_candidate_survey(status, label="selection")
        secured_networks = [
            item.get("source_network") or {}
            for item in survey.get("candidates") or []
            if item.get("lead_kind") == "network"
            and (self.args.include_open or not item.get("is_open"))
        ]

        chosen: List[Dict[str, Any]] = []
        if requested_ssids:
            for item in secured_networks:
                if str(item.get("ssid") or "").strip() in requested_ssids:
                    chosen.append(item)
        else:
            scored = sorted(
                secured_networks,
                key=lambda item: (
                    int(item.get("historical_captures") or 0),
                    float(item.get("rssi_dbm") or -1000.0),
                    float(item.get("packet_count") or 0.0),
                ),
                reverse=True,
            )
            chosen = scored[: max(1, int(self.args.auto_ssids))]

        if not chosen:
            top_ssids = list((((status.get("observation_audit") or {}).get("top_ssids")) or []))
            for row in top_ssids:
                if requested_ssids and str(row.get("ssid") or "").strip() not in requested_ssids:
                    continue
                if str(row.get("ssid") or "").strip():
                    chosen.append(row)
            chosen = chosen[: max(1, int(self.args.auto_ssids))]
        return chosen

    def _select_channels(self, status: Dict[str, Any]) -> List[int]:
        explicit_channels = [int(item) for item in self.args.channel]
        if explicit_channels:
            return unique_ints(explicit_channels)

        target_channels = [int(item.get("channel") or 0) for item in self.selected_targets if int(item.get("channel") or 0) > 0]
        if target_channels:
            return unique_ints(target_channels)

        top_ssids = list((((status.get("observation_audit") or {}).get("top_ssids")) or []))
        fallback = [int(item.get("channel") or 0) for item in top_ssids[: max(1, int(self.args.auto_ssids))] if int(item.get("channel") or 0) > 0]
        if fallback:
            return unique_ints(fallback)

        hot_channels = [int(item) for item in (((status.get("channels") or {}).get("hot_channels")) or []) if int(item) > 0]
        return unique_ints(hot_channels[: max(1, int(self.args.auto_channels))])

    def _start_capture(self) -> Dict[str, Any]:
        bands = unique_ints(self.selected_channels)
        band_names = ",".join(sorted({channel_to_band(item) for item in bands}))
        params = {
            "bands": band_names or "2.4ghz,5ghz",
            "dwell_ms": int(self.args.dwell_ms),
            "duration_seconds": int(self.args.duration_seconds),
            "scan_mode": self.args.scan_mode,
            "locked_channels": ",".join(str(item) for item in self.selected_channels),
            "camera_hunt": "false",
            "blue_team_enrichment": "false",
        }
        payload = api_request(self.base_url, "POST", "/api/wifi_mk7/start", params=params, timeout=60)
        if str(payload.get("status") or "").startswith("unavailable") or payload.get("error"):
            raise SystemExit(f"Failed to start targeted capture: {payload}")
        return payload

    def _poll_until_complete(self) -> str:
        deadline = time.time() + int(self.args.duration_seconds) + int(self.args.grace_seconds)
        stop_reason = "duration_elapsed"
        while time.time() < deadline:
            status = api_request(self.base_url, "GET", "/api/wifi_mk7/status")
            sample = self._sample_status(status)
            self.poll_samples.append(sample)
            log(
                "elapsed=%ss pcaps=%s raw_eapol=%s quality=%s"
                % (
                    sample["elapsed_seconds"],
                    sample["pcap_count"],
                    sample["raw_eapol_frame_count"],
                    sample["quality_counts"],
                )
            )
            if not bool(status.get("capture_active")) and sample["elapsed_seconds"] >= int(self.args.duration_seconds) - 5:
                stop_reason = "scan_completed"
                break
            if self.args.stop_on_eapol and sample["raw_eapol_frame_count"] > 0:
                api_request(self.base_url, "POST", "/api/wifi_mk7/stop")
                stop_reason = "raw_eapol_detected"
                break
            if self.args.stop_on_quality:
                quality_counts = sample["quality_counts"]
                if any(int(quality_counts.get(level) or 0) > 0 for level in ("PARTIAL", "LIKELY", "CONFIRMED")):
                    api_request(self.base_url, "POST", "/api/wifi_mk7/stop")
                    stop_reason = "authentication_quality_detected"
                    break
            time.sleep(float(self.args.poll_seconds))
        else:
            status = api_request(self.base_url, "GET", "/api/wifi_mk7/status")
            if bool(status.get("capture_active")):
                api_request(self.base_url, "POST", "/api/wifi_mk7/stop")
                stop_reason = "deadline_reached"
            else:
                stop_reason = "scan_completed"
        return stop_reason

    def _sample_status(self, status: Dict[str, Any]) -> Dict[str, Any]:
        scan = status.get("scan") or {}
        inventory = status.get("inventory") or {}
        auth = status.get("authentication_evidence") or {}
        auth_debug = auth.get("debug") or {}
        processing = status.get("processing_pipeline") or {}
        summary = processing.get("summary") or {}
        return {
            "timestamp": time.time(),
            "capture_active": bool(status.get("capture_active")),
            "elapsed_seconds": round(float(scan.get("elapsed_seconds") or 0.0), 1),
            "progress_percent": round(float(scan.get("progress_percent") or 0.0), 1),
            "pcap_count": int(inventory.get("pcap_count") or 0),
            "network_count": int(inventory.get("network_count") or 0),
            "client_count": int(inventory.get("client_count") or 0),
            "raw_eapol_frame_count": int(auth_debug.get("raw_eapol_frame_count") or 0),
            "quality_counts": dict(auth.get("quality_counts") or {}),
            "handshake_network_count": int(summary.get("handshake_network_count") or 0),
            "handshake_client_count": int(summary.get("handshake_client_count") or 0),
            "coverage_confidence_level": str(((status.get("observation_audit") or {}).get("coverage_confidence") or {}).get("level") or ""),
        }

    def _collect_candidate_survey(self, status: Dict[str, Any], *, label: str) -> Dict[str, Any]:
        networks = list((api_request(self.base_url, "GET", "/api/wifi_mk7/networks").get("networks") or []))
        clients = list((api_request(self.base_url, "GET", "/api/wifi_mk7/clients").get("clients") or []))
        camera_results = api_request(self.base_url, "GET", "/api/wifi_mk7/camera_hunt/results")
        candidates = self._build_candidate_rows(
            networks=networks,
            clients=clients,
            camera_results=camera_results,
            status=status,
        )
        return {
            "label": label,
            "generated_at": int(time.time()),
            "run_dir": str(self.run_dir),
            "count": len(candidates),
            "networks_count": len(networks),
            "clients_count": len(clients),
            "camera_lead_count": as_int(camera_results.get("count")),
            "camera_near_miss_count": as_int(camera_results.get("near_miss_count")),
            "coverage_confidence": ((status.get("observation_audit") or {}).get("coverage_confidence") or {}),
            "channels": status.get("channels") or {},
            "candidates": candidates[: max(1, int(self.args.candidate_limit))],
        }

    def _build_candidate_rows(
        self,
        *,
        networks: List[Dict[str, Any]],
        clients: List[Dict[str, Any]],
        camera_results: Dict[str, Any],
        status: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        fused_map: Dict[str, Dict[str, Any]] = {}
        for bucket_name, bonus in (("leads", 30.0), ("near_misses", 18.0)):
            for item in camera_results.get(bucket_name) or []:
                key = self._candidate_key(item)
                fused_map[key] = {
                    "lead": item,
                    "pipeline_bonus": bonus,
                    "bucket": bucket_name,
                }

        top_ssids = list((((status.get("observation_audit") or {}).get("top_ssids")) or []))
        top_ssid_map = {str(item.get("ssid") or "").strip(): item for item in top_ssids if str(item.get("ssid") or "").strip()}

        rows: List[Dict[str, Any]] = []
        for network in networks:
            key = self._candidate_key(network)
            fused_entry = fused_map.get(key, {})
            lead = dict(fused_entry.get("lead") or {})
            security = str(network.get("security") or "").strip()
            camera_detection = dict(network.get("camera_detection") or {})
            target_score = dict(network.get("target_score") or {})
            observation = dict(network.get("observation_opportunity") or {})
            top_ssid = top_ssid_map.get(str(network.get("ssid") or "").strip(), {})
            score = 0.0
            score += min(35.0, as_float(target_score.get("score")) * 0.35)
            score += min(20.0, as_float(camera_detection.get("score")) * 0.25)
            score += min(12.0, max(0.0, as_float(network.get("rssi_dbm"), -100.0) + 100.0) * 0.2)
            score += min(10.0, as_float(network.get("packet_count")) / 12.0)
            score += min(8.0, as_float(network.get("historical_captures")) * 1.5)
            score += min(7.0, as_float(observation.get("score")) / 15.0)
            score += min(6.0, as_float(network.get("client_count")) * 1.5)
            score += min(6.0, as_float(top_ssid.get("frames")) / 30.0)
            score += as_float(fused_entry.get("pipeline_bonus"))
            if security and security.lower() not in {"open", ""}:
                score += 5.0
            if bool(camera_detection.get("retained")):
                score += 8.0
            rows.append(
                {
                    "rank_score": round(score, 1),
                    "lead_kind": "network",
                    "identity": str(network.get("ssid") or "<hidden>"),
                    "ssid": str(network.get("ssid") or ""),
                    "bssid": str(network.get("bssid") or ""),
                    "channel": as_int(network.get("channel")),
                    "band": str(network.get("band") or ""),
                    "security": security,
                    "is_open": security.lower() in {"", "open"},
                    "rssi_dbm": as_int(network.get("rssi_dbm"), -999),
                    "packet_count": as_int(network.get("packet_count")),
                    "historical_captures": as_int(network.get("historical_captures")),
                    "client_count": as_int(network.get("client_count")),
                    "target_score": round(as_float(target_score.get("score")), 1),
                    "camera_score": round(as_float(camera_detection.get("score")), 1),
                    "camera_confidence": round(as_float(camera_detection.get("confidence")), 3),
                    "camera_retained": bool(camera_detection.get("retained")),
                    "classification": str(camera_detection.get("classification") or ""),
                    "matched_families": list(camera_detection.get("matched_families") or []),
                    "pipeline_bucket": str(fused_entry.get("bucket") or ""),
                    "pipeline_score": round(as_float(lead.get("pipeline_score")), 1),
                    "observation_score": round(as_float(observation.get("score")), 1),
                    "frames_seen": as_int(top_ssid.get("frames")),
                    "why": self._candidate_reasons(network, lead, top_ssid),
                    "source_network": network,
                }
            )

        for client in clients:
            camera_detection = dict(client.get("camera_detection") or {})
            if as_float(camera_detection.get("score")) < float(self.args.client_floor):
                continue
            key = self._candidate_key(client)
            fused_entry = fused_map.get(key, {})
            lead = dict(fused_entry.get("lead") or {})
            target_score = dict(client.get("target_score") or {})
            score = 0.0
            score += min(30.0, as_float(target_score.get("score")) * 0.35)
            score += min(22.0, as_float(camera_detection.get("score")) * 0.25)
            score += min(10.0, max(0.0, as_float(client.get("rssi_dbm"), -100.0) + 100.0) * 0.2)
            score += min(8.0, as_float(client.get("packet_count")) / 10.0)
            score += min(8.0, as_float(client.get("historical_captures")) * 1.5)
            score += as_float(fused_entry.get("pipeline_bonus"))
            rows.append(
                {
                    "rank_score": round(score, 1),
                    "lead_kind": "client",
                    "identity": str(client.get("mac") or ""),
                    "ssid": "",
                    "bssid": str(client.get("associated_bssid") or ""),
                    "channel": as_int(client.get("channel")),
                    "band": str(client.get("band") or ""),
                    "security": "",
                    "is_open": False,
                    "rssi_dbm": as_int(client.get("rssi_dbm"), -999),
                    "packet_count": as_int(client.get("packet_count")),
                    "historical_captures": as_int(client.get("historical_captures")),
                    "client_count": 0,
                    "target_score": round(as_float(target_score.get("score")), 1),
                    "camera_score": round(as_float(camera_detection.get("score")), 1),
                    "camera_confidence": round(as_float(camera_detection.get("confidence")), 3),
                    "camera_retained": bool(camera_detection.get("retained")),
                    "classification": str(camera_detection.get("classification") or ""),
                    "matched_families": list(camera_detection.get("matched_families") or []),
                    "pipeline_bucket": str(fused_entry.get("bucket") or ""),
                    "pipeline_score": round(as_float(lead.get("pipeline_score")), 1),
                    "observation_score": 0.0,
                    "frames_seen": 0,
                    "why": self._candidate_reasons(client, lead, {}),
                }
            )

        rows.sort(
            key=lambda item: (
                as_float(item.get("rank_score")),
                as_float(item.get("pipeline_score")),
                as_float(item.get("camera_score")),
                as_float(item.get("target_score")),
                as_int(item.get("packet_count")),
                as_int(item.get("rssi_dbm"), -999),
            ),
            reverse=True,
        )
        return rows

    def _candidate_key(self, item: Dict[str, Any]) -> str:
        lead_kind = str(item.get("leadKind") or ("network" if item.get("bssid") else "client")).lower()
        identity = str(item.get("bssid") or item.get("mac") or item.get("associated_bssid") or item.get("ssid") or "").lower()
        return f"{lead_kind}:{identity}"

    def _candidate_reasons(self, item: Dict[str, Any], lead: Dict[str, Any], top_ssid: Dict[str, Any]) -> List[str]:
        reasons: List[str] = []
        camera_detection = dict(item.get("camera_detection") or {})
        if bool(camera_detection.get("retained")):
            reasons.append("retained camera lead")
        elif lead:
            reasons.append(str(lead.get("pipeline_bucket") or "camera pipeline hit"))
        if as_float(camera_detection.get("score")) >= 20.0:
            reasons.append(f"camera score {round(as_float(camera_detection.get('score')), 1)}")
        if as_float((item.get("target_score") or {}).get("score")) >= 40.0:
            reasons.append(f"target score {round(as_float((item.get('target_score') or {}).get('score')), 1)}")
        if as_int(item.get("historical_captures")) > 0:
            reasons.append(f"{as_int(item.get('historical_captures'))} retained captures")
        if as_int(item.get("packet_count")) > 0:
            reasons.append(f"{as_int(item.get('packet_count'))} packets")
        if as_int(top_ssid.get("frames")) > 0:
            reasons.append(f"{as_int(top_ssid.get('frames'))} recent frames")
        security = str(item.get("security") or "").strip()
        if security and security.lower() not in {"", "open"}:
            reasons.append(security)
        return reasons[:5]

    def _top_candidate_label(self, survey: Dict[str, Any]) -> str:
        candidates = list(survey.get("candidates") or [])
        if not candidates:
            return "none"
        top = candidates[0]
        identity = str(top.get("identity") or top.get("bssid") or "--")
        return f"{identity} score={top.get('rank_score')}"

    def _fresh_pcaps(self) -> List[str]:
        fresh: set[str] = set()
        for item in self.final_pcap_inventory:
            path = str(item.get("path") or "").strip()
            timestamp = float(item.get("timestamp") or 0.0)
            if path and timestamp >= self.started_at - 2:
                fresh.add(path)

        status = api_request(self.base_url, "GET", "/api/wifi_mk7/status")
        recent_captures = list((((status.get("observation_audit") or {}).get("recent_captures")) or []))
        for item in recent_captures:
            path = str(item.get("pcap_path") or "").strip()
            timestamp = float(item.get("timestamp") or 0.0)
            if path and timestamp >= self.started_at - 2:
                fresh.add(path)

        for path in self.logs_dir.glob("wifi_mk7_*_*.pcapng"):
            try:
                if path.stat().st_mtime >= self.started_at - 2:
                    fresh.add(str(path))
            except OSError:
                continue
        return sorted(fresh)

    def _render_summary(self, report: Dict[str, Any]) -> str:
        lines = [
            "GhostRecon Targeted Capture Summary",
            f"Generated: {report.get('generated_at', 0)}",
            f"Run dir: {report.get('run_dir', '')}",
            f"Selected channels: {','.join(str(item) for item in report.get('selected_channels', []))}",
            f"Fresh pcaps: {report.get('fresh_pcap_count', 0)}",
            f"Stop reason: {report.get('stop_reason', '')}",
            "",
            "Initial top candidates:",
            self._render_candidate_lines((report.get("initial_candidate_survey") or {}).get("candidates") or [], limit=8),
            "",
            "Final top candidates:",
            self._render_candidate_lines((report.get("final_candidate_survey") or {}).get("candidates") or [], limit=8),
            "",
            "Selected targets:",
            json.dumps(report.get("selected_targets", []), indent=2, ensure_ascii=True),
            "",
            "Recent status samples:",
            json.dumps(report.get("poll_samples", [])[-10:], indent=2, ensure_ascii=True),
            "",
            "Fresh PCAPs:",
            json.dumps(report.get("fresh_pcaps", []), indent=2, ensure_ascii=True),
        ]
        return "\n".join(lines).strip() + "\n"

    def _render_candidate_survey(self, survey: Dict[str, Any]) -> str:
        lines = [
            "GhostRecon Candidate Survey",
            f"Label: {survey.get('label', '')}",
            f"Generated: {survey.get('generated_at', 0)}",
            f"Run dir: {survey.get('run_dir', '')}",
            f"Coverage confidence: {((survey.get('coverage_confidence') or {}).get('level') or '--')}",
            f"Networks: {survey.get('networks_count', 0)}",
            f"Clients: {survey.get('clients_count', 0)}",
            f"Camera leads: {survey.get('camera_lead_count', 0)}",
            f"Camera near misses: {survey.get('camera_near_miss_count', 0)}",
            "",
            self._render_candidate_lines(survey.get("candidates") or [], limit=max(1, int(self.args.candidate_limit))),
        ]
        return "\n".join(lines).strip() + "\n"

    def _render_candidate_lines(self, candidates: List[Dict[str, Any]], *, limit: int) -> str:
        if not candidates:
            return "No ranked candidates."
        lines: List[str] = []
        for index, item in enumerate(candidates[:limit], start=1):
            identity = str(item.get("identity") or item.get("bssid") or "--")
            reason_text = ", ".join(item.get("why") or []) or "no corroborating detail"
            lines.append(
                f"{index}. {identity} | kind={item.get('lead_kind')} | ch={item.get('channel') or '--'} | "
                f"rssi={item.get('rssi_dbm')} | rank={item.get('rank_score')} | "
                f"camera={item.get('camera_score')} | target={item.get('target_score')} | {reason_text}"
            )
        return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Targeted WiFi MK7 capture helper focused on handshake and authentication evidence")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100", help="GhostRedRecon backend base URL")
    parser.add_argument("--ssid", action="append", default=[], help="Preferred SSID to lock onto; may be provided multiple times")
    parser.add_argument("--channel", action="append", type=int, default=[], help="Explicit channel to lock onto; may be provided multiple times")
    parser.add_argument("--auto-ssids", type=int, default=4, help="Auto-select up to this many secured SSIDs when none are supplied")
    parser.add_argument("--auto-channels", type=int, default=4, help="Fallback hot-channel count when SSIDs do not resolve channels")
    parser.add_argument("--duration-seconds", type=int, default=300, help="Targeted capture duration")
    parser.add_argument("--dwell-ms", type=int, default=500, help="Channel dwell time in milliseconds")
    parser.add_argument("--scan-mode", default="broad", help="WiFi MK7 scan mode")
    parser.add_argument("--poll-seconds", type=float, default=5.0, help="Polling interval while capture is running")
    parser.add_argument("--grace-seconds", type=int, default=45, help="Extra wait budget for backend shutdown/finalization")
    parser.add_argument("--candidate-limit", type=int, default=15, help="Number of ranked candidates to keep in the survey output")
    parser.add_argument("--client-floor", type=float, default=25.0, help="Minimum client camera score to include in surveys")
    parser.add_argument("--include-open", action="store_true", help="Allow open networks in auto-selection")
    parser.add_argument("--survey-only", action="store_true", help="Only write the ranked candidate survey; do not start a new capture")
    parser.add_argument("--stop-on-eapol", action="store_true", help="Stop early once raw EAPOL frames are observed")
    parser.add_argument("--stop-on-quality", action="store_true", help="Stop early once PARTIAL/LIKELY/CONFIRMED auth evidence appears")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return GhostReconTargetedCapture(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
