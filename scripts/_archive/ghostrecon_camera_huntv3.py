#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_TARGETS = [
    {"bssid": "44:48:b9:69:0b:d8", "channel": 1, "band": "2.4 GHz", "label": "target-01"},
    {"bssid": "5c:e9:31:5d:a5:78", "channel": 5, "band": "2.4 GHz", "label": "tp_link_tapo_lab-24"},
    {"bssid": "5c:e9:31:5d:44:42", "channel": 44, "band": "5 GHz", "label": "tp_link_tapo_lab-5a"},
    {"bssid": "5c:e9:31:5d:a5:7a", "channel": 44, "band": "5 GHz", "label": "tp_link_tapo_lab-5b"},
    {"bssid": "3c:98:72:49:e1:55", "channel": 56, "band": "5 GHz", "label": "reolink_lab"},
    {"bssid": "a0:95:7f:3b:87:b0", "channel": 13, "band": "2.4 GHz", "label": "sernet-13"},
]
DEFAULT_OWNED_CHANNELS = (1, 5)
OWNED_TARGET_PRESETS = {
    "xiaomi_owned": [
        {"bssid": "78:8b:2a:64:60:b9", "channel": 6, "band": "2.4 GHz", "label": "xiaomi-owned"},
    ],
}


def now_ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def log(message: str) -> None:
    print(f"[camera-hunt-v3] {message}", flush=True)


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


class GhostReconCameraHuntV3:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root_dir = REPO_ROOT
        self.run_dir = self.root_dir / "evidence" / "camera_hunt_runs" / f"{now_ts()}_v3"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir = self.root_dir / "logs" / "wifi_mk7"
        self.decrypt_runs_dir = self.root_dir / "evidence" / "decrypt_test_runs"
        self.base_url = args.base_url.rstrip("/")
        self.started_at = time.time()
        self.targets = self._resolve_targets()
        self.channels = unique_ints(item["channel"] for item in self.targets)
        self.evidence_channels = unique_ints(args.evidence_channel or DEFAULT_OWNED_CHANNELS)
        self.poll_samples: List[Dict[str, Any]] = []

    def _resolve_targets(self) -> List[Dict[str, Any]]:
        if self.args.preset:
            preset_targets = list(OWNED_TARGET_PRESETS.get(str(self.args.preset or "").strip().lower()) or [])
            if preset_targets:
                return preset_targets
        if not self.args.target:
            return list(DEFAULT_TARGETS)
        targets: List[Dict[str, Any]] = []
        for raw in self.args.target:
            parts = [part.strip() for part in str(raw or "").split(":")]
            if len(parts) < 7:
                continue
            bssid = ":".join(parts[:6]).lower()
            channel = int(parts[6]) if parts[6].isdigit() else 0
            label = parts[7] if len(parts) > 7 else bssid
            if channel > 0:
                targets.append({"bssid": bssid, "channel": channel, "band": "5 GHz" if channel > 14 else "2.4 GHz", "label": label})
        return targets or list(DEFAULT_TARGETS)

    def run(self) -> int:
        status = api_request(self.base_url, "GET", "/api/wifi_mk7/status", params={"prepare": "true"})
        if status.get("service") != "wifi_mk7":
            raise SystemExit(f"WiFi MK7 unavailable: {status}")
        if bool(status.get("capture_active")):
            if not self.args.force_reset:
                raise SystemExit("WiFi MK7 scan already active; stop it before running camera_huntv3.")
            api_request(self.base_url, "POST", "/api/wifi_mk7/stop")
            time.sleep(1.0)
            api_request(self.base_url, "POST", "/api/wifi_mk7/clear")
            time.sleep(1.0)
            status = api_request(self.base_url, "GET", "/api/wifi_mk7/status", params={"prepare": "true"})
            if bool(status.get("capture_active")):
                raise SystemExit("WiFi MK7 still reports an active scan after forced reset.")

        clear_payload = api_request(self.base_url, "POST", "/api/wifi_mk7/clear")
        start_payload = api_request(
            self.base_url,
            "POST",
            "/api/wifi_mk7/start",
            timeout=60,
            params={
                "bands": ",".join(sorted({channel_to_band(channel) for channel in self.channels})) or "2.4ghz,5ghz",
                "dwell_ms": int(self.args.dwell_ms),
                "duration_seconds": int(self.args.duration_seconds),
                "scan_mode": self.args.scan_mode,
                "scan_scenario": self.args.scan_scenario,
                "locked_channels": ",".join(str(channel) for channel in self.channels),
                "interfaces": self.args.interface,
                "camera_hunt": "true",
            },
        )
        if start_payload.get("error"):
            raise SystemExit(f"Failed to start hunt: {start_payload}")

        stop_reason = self._poll_until_complete()
        final_status = api_request(self.base_url, "GET", "/api/wifi_mk7/status")
        results = api_request(self.base_url, "GET", "/api/wifi_mk7/camera_hunt/results")
        networks = list((api_request(self.base_url, "GET", "/api/wifi_mk7/networks").get("networks") or []))
        clients = list((api_request(self.base_url, "GET", "/api/wifi_mk7/clients").get("clients") or []))
        pcap_inventory = list((api_request(self.base_url, "GET", "/api/wifi_mk7/pcap").get("pcaps") or []))

        target_lookup = {item["bssid"].lower(): item for item in self.targets}
        target_networks = [
            network for network in networks
            if str(network.get("bssid") or "").lower() in target_lookup
        ]
        target_clients = [
            client for client in clients
            if str(client.get("associated_bssid") or "").lower() in target_lookup
        ]
        result_items = [*(results.get("leads") or []), *(results.get("near_misses") or [])]
        target_results = [
            item for item in result_items
            if str(item.get("bssid") or item.get("associated_bssid") or item.get("mac") or "").lower() in target_lookup
        ]
        fresh_pcaps = self._fresh_pcaps(pcap_inventory)
        owned_fresh_pcaps = self._filter_pcaps_by_channels(fresh_pcaps, self.evidence_channels)
        decrypt_followup = self._run_decrypt_followup(owned_fresh_pcaps) if self.args.decrypt_followup and owned_fresh_pcaps else {}

        report = {
            "generated_at": int(time.time()),
            "run_dir": str(self.run_dir),
            "targets": self.targets,
            "channels": self.channels,
            "evidence_channels": self.evidence_channels,
            "scan_scenario": self.args.scan_scenario,
            "clear_payload": clear_payload,
            "start_payload": start_payload,
            "stop_reason": stop_reason,
            "poll_samples": self.poll_samples,
            "final_status": final_status,
            "target_results_count": len(target_results),
            "target_results": target_results,
            "target_network_count": len(target_networks),
            "target_networks": target_networks,
            "target_client_count": len(target_clients),
            "target_clients": target_clients,
            "fresh_pcap_count": len(fresh_pcaps),
            "fresh_pcaps": fresh_pcaps,
            "owned_fresh_pcap_count": len(owned_fresh_pcaps),
            "owned_fresh_pcaps": owned_fresh_pcaps,
            "decrypt_followup": decrypt_followup,
        }
        write_json(self.run_dir / "camera_hunt_v3_report.json", report)
        write_text(self.run_dir / "camera_hunt_v3_summary.txt", self._render_summary(report))
        log(f"run directory: {self.run_dir}")
        log(f"target results: {len(target_results)}")
        log(f"fresh pcaps: {len(fresh_pcaps)}")
        if owned_fresh_pcaps:
            log(f"owned-scope pcaps: {len(owned_fresh_pcaps)} on channels {', '.join(str(item) for item in self.evidence_channels)}")
        if decrypt_followup:
            log(f"decrypt follow-up images: {decrypt_followup.get('saved_image_count', 0)}")
        return 0

    def _poll_until_complete(self) -> str:
        deadline = time.time() + int(self.args.duration_seconds) + int(self.args.grace_seconds)
        stop_reason = "duration_elapsed"
        while time.time() < deadline:
            status = api_request(self.base_url, "GET", "/api/wifi_mk7/status")
            sample = {
                "timestamp": time.time(),
                "capture_active": bool(status.get("capture_active")),
                "elapsed_seconds": float((status.get("scan") or {}).get("elapsed_seconds") or 0.0),
                "progress_percent": float((status.get("scan") or {}).get("progress_percent") or 0.0),
                "network_count": int(((status.get("inventory") or {}).get("network_count") or 0)),
                "client_count": int(((status.get("inventory") or {}).get("client_count") or 0)),
                "raw_eapol_frame_count": int((((status.get("authentication_evidence") or {}).get("debug") or {}).get("raw_eapol_frame_count") or 0)),
                "current_phase": str(((status.get("camera_hunt_pipeline") or {}).get("current_phase") or "idle")),
                "hot_channels": list(((status.get("channels") or {}).get("hot_channels") or [])),
            }
            self.poll_samples.append(sample)
            log(
                "elapsed=%ss phase=%s nets=%s clients=%s raw_eapol=%s"
                % (
                    round(sample["elapsed_seconds"], 1),
                    sample["current_phase"],
                    sample["network_count"],
                    sample["client_count"],
                    sample["raw_eapol_frame_count"],
                )
            )
            if not sample["capture_active"] and sample["elapsed_seconds"] >= int(self.args.duration_seconds) - 5:
                stop_reason = "scan_completed"
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

    def _fresh_pcaps(self, pcap_inventory: List[Dict[str, Any]]) -> List[str]:
        fresh: List[str] = []
        for item in pcap_inventory:
            path = str(item.get("path") or "").strip()
            timestamp = float(item.get("timestamp") or 0.0)
            if path and timestamp >= self.started_at - 2:
                fresh.append(path)
        for path in sorted(self.logs_dir.glob("wifi_mk7_*_*.pcapng")):
            try:
                if path.stat().st_mtime >= self.started_at - 2 and str(path) not in fresh:
                    fresh.append(str(path))
            except OSError:
                continue
        return sorted(fresh)

    def _pcap_channel(self, path: str) -> int:
        name = Path(path).name
        marker = "wifi_mk7_ch"
        if marker not in name:
            return 0
        suffix = name.split(marker, 1)[1]
        channel_text = suffix.split("_", 1)[0]
        return int(channel_text) if channel_text.isdigit() else 0

    def _filter_pcaps_by_channels(self, pcaps: List[str], channels: List[int]) -> List[str]:
        allowed = set(int(item) for item in channels if int(item) > 0)
        if not allowed:
            return list(pcaps)
        return [path for path in pcaps if self._pcap_channel(path) in allowed]

    def _latest_decrypt_run_dir(self, *, started_after: float) -> Path | None:
        if not self.decrypt_runs_dir.exists():
            return None
        candidates = [
            path for path in self.decrypt_runs_dir.iterdir()
            if path.is_dir() and path.stat().st_mtime >= started_after
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda path: path.stat().st_mtime)

    def _run_decrypt_followup(self, pcaps: List[str]) -> Dict[str, Any]:
        started = time.time()
        cmd = [
            "python3",
            str(self.root_dir / "scripts" / "ghostrecon_decrypt_test.py"),
            "--timeout",
            str(int(self.args.decrypt_timeout)),
        ]
        for path in pcaps:
            cmd.extend(["--pcap", path])
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        run_dir = self._latest_decrypt_run_dir(started_after=started - 2)
        summary: Dict[str, Any] = {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "command": cmd,
            "stdout_tail": (result.stdout or "").splitlines()[-20:],
            "stderr_tail": (result.stderr or "").splitlines()[-20:],
            "pcap_count": len(pcaps),
            "run_dir": str(run_dir) if run_dir else "",
        }
        if run_dir:
            report_path = run_dir / "decrypt_report.json"
            summary_path = run_dir / "decrypt_summary.txt"
            summary["report_path"] = str(report_path)
            summary["summary_path"] = str(summary_path)
            if report_path.exists():
                try:
                    payload = json.loads(report_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    payload = {}
                summary["saved_image_count"] = len(payload.get("saved_images") or [])
                summary["saved_images"] = list(payload.get("saved_images") or [])
        return summary

    def _render_summary(self, report: Dict[str, Any]) -> str:
        lines = [
            "GhostRecon Camera Hunt V3 Summary",
            f"Run dir: {report.get('run_dir', '')}",
            f"Targets: {len(report.get('targets', []))}",
            f"Channels: {', '.join(str(channel) for channel in report.get('channels', []))}",
            f"Owned evidence channels: {', '.join(str(channel) for channel in report.get('evidence_channels', []))}",
            f"Scenario: {report.get('scan_scenario', 'passive_observation')}",
            f"Stop reason: {report.get('stop_reason', '')}",
            f"Target results: {report.get('target_results_count', 0)}",
            f"Target networks: {report.get('target_network_count', 0)}",
            f"Target clients: {report.get('target_client_count', 0)}",
            f"Fresh pcaps: {report.get('fresh_pcap_count', 0)}",
            f"Owned-scope pcaps: {report.get('owned_fresh_pcap_count', 0)}",
            "",
            "Targets:",
            json.dumps(report.get("targets", []), indent=2, ensure_ascii=True),
            "",
            "Matched results:",
            json.dumps(report.get("target_results", []), indent=2, ensure_ascii=True),
            "",
            "Owned-Scope PCAPs:",
            json.dumps(report.get("owned_fresh_pcaps", []), indent=2, ensure_ascii=True),
            "",
            "Decrypt Follow-Up:",
            json.dumps(report.get("decrypt_followup", {}), indent=2, ensure_ascii=True),
            "",
            "Fresh PCAPs:",
            json.dumps(report.get("fresh_pcaps", []), indent=2, ensure_ascii=True),
        ]
        return "\n".join(lines).strip() + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Focused Camera Hunt V3 for selected BSSIDs/channels")
    parser.add_argument("--base-url", default="http://127.0.0.1:8100", help="GhostRedRecon backend base URL")
    parser.add_argument("--interface", default="wlan1", help="Base WiFi interface")
    parser.add_argument("--duration-seconds", type=int, default=300, help="Targeted camera hunt duration")
    parser.add_argument("--dwell-ms", type=int, default=1200, help="Per-channel dwell time in milliseconds")
    parser.add_argument("--scan-mode", default="lock", help="WiFi MK7 scan mode")
    parser.add_argument("--poll-seconds", type=float, default=5.0, help="Polling interval during live capture")
    parser.add_argument("--grace-seconds", type=int, default=45, help="Extra wait budget for shutdown/finalization")
    parser.add_argument("--preset", default="", help="Owned target preset name, e.g. xiaomi_owned")
    parser.add_argument("--target", action="append", default=[], help="Override default target as BSSID:channel[:label]")
    parser.add_argument("--scan-scenario", default="passive_observation", help="Scenario tag, e.g. idle, app_open, live_view, motion")
    parser.add_argument("--evidence-channel", action="append", type=int, default=[], help="Authorized channels for evidence promotion and decrypt follow-up")
    parser.add_argument("--decrypt-followup", action="store_true", help="Run decrypt follow-up against the authorized evidence channels")
    parser.add_argument("--decrypt-timeout", type=int, default=120, help="Per-PCAP timeout for decrypt follow-up")
    parser.add_argument("--force-reset", action="store_true", help="Stop and clear MK7 state automatically if a stale active scan is reported")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return GhostReconCameraHuntV3(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
